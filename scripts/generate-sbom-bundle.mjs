#!/usr/bin/env node

import { execFile } from 'node:child_process';
import { constants } from 'node:fs';
import { mkdtemp, open, rm, unlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { validateDigest, validateRegion, validateRepository } from '../src/aws-cli.js';
import { validatePlatform } from '../src/trivy.js';

const execFileAsync = promisify(execFile);
const MAX_SBOM_BYTES = 16 * 1024 * 1024;
const REQUIRED = ['image', 'account', 'region', 'repository', 'digest', 'platform', 'output'];
const IMAGE_RE = /^[a-zA-Z0-9][a-zA-Z0-9._/:@-]{0,511}$/;
const SHA256_RE = /^sha256:[a-f0-9]{64}$/;
const USAGE = `Usage: node scripts/generate-sbom-bundle.mjs \\
  --image LOCAL_DOCKER_IMAGE --account AWS_ACCOUNT_ID --region AWS_REGION \\
  --repository ECR_REPOSITORY --digest sha256:IMAGE_MANIFEST_DIGEST \\
  --platform linux/amd64 --output /private/path/image.sentinel-sbom.json

Run on an authorized build host after pushing the image to ECR. Docker must
locally know the exact ECR repository digest. The helper reads the local Docker
image and never asks Trivy to pull an image from ECR.`;

function safeEnv() {
  const allowed = [
    'HOME', 'PATH', 'TMPDIR', 'LANG', 'LC_ALL',
    'DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CONFIG', 'DOCKER_CERT_PATH', 'DOCKER_TLS_VERIFY',
    'SSL_CERT_FILE', 'SSL_CERT_DIR',
    'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'http_proxy', 'https_proxy', 'no_proxy',
  ];
  const env = Object.fromEntries(allowed.filter((name) => process.env[name] !== undefined)
    .map((name) => [name, process.env[name]]));
  env.AWS_EC2_METADATA_DISABLED = 'true';
  env.AWS_SHARED_CREDENTIALS_FILE = '/dev/null';
  env.AWS_CONFIG_FILE = '/dev/null';
  return env;
}

export async function runCommand(command, args, { timeoutMs = 30_000, env = safeEnv(), maxOutputBytes = 512 * 1024 } = {}) {
  return execFileAsync(command, args, {
    env, timeout: timeoutMs, maxBuffer: maxOutputBytes, windowsHide: true,
  });
}

export function parseArgs(argv) {
  if (argv.includes('--help') || argv.includes('-h')) return { help: true };
  const values = {};
  for (let i = 0; i < argv.length; i += 1) {
    const argument = argv[i];
    if (!argument.startsWith('--')) throw new Error(`Unexpected argument: ${argument}`);
    const separator = argument.indexOf('=');
    const name = argument.slice(2, separator < 0 ? undefined : separator);
    if (!REQUIRED.includes(name)) throw new Error(`Unknown option: --${name}`);
    if (Object.hasOwn(values, name)) throw new Error(`Duplicate option: --${name}`);
    const value = separator < 0 ? argv[++i] : argument.slice(separator + 1);
    if (!value || value.startsWith('--')) throw new Error(`Provide a value for --${name}.`);
    values[name] = value;
  }
  for (const name of REQUIRED) {
    if (!Object.hasOwn(values, name)) throw new Error(`Missing required --${name}.`);
  }
  return validateOptions(values);
}

export function validateOptions(values) {
  if (!values || typeof values !== 'object' || Array.isArray(values)) throw new Error('Provide image and ECR target options.');
  if (typeof values.image !== 'string' || !IMAGE_RE.test(values.image)) throw new Error('Provide a valid local Docker image reference.');
  if (typeof values.account !== 'string' || !/^\d{12}$/.test(values.account)) throw new Error('AWS account must be 12 digits.');
  let region;
  let repository;
  let digest;
  let platform;
  try {
    region = validateRegion(values.region);
    repository = validateRepository(values.repository);
    digest = validateDigest(values.digest);
    platform = validatePlatform(values.platform);
  } catch (error) {
    throw new Error(error.message);
  }
  if (typeof values.output !== 'string' || values.output.length > 4096 || !values.output.trim() || /[\x00-\x1f\x7f]/.test(values.output)) {
    throw new Error('Provide a valid output file path.');
  }
  const suffix = region.startsWith('cn-') ? 'amazonaws.com.cn' : 'amazonaws.com';
  const repositoryUri = `${values.account}.dkr.ecr.${region}.${suffix}/${repository}`;
  return {
    image: values.image,
    account: values.account,
    region,
    repository,
    digest,
    platform,
    output: resolve(values.output),
    repositoryUri,
    repoDigest: `${repositoryUri}@${digest}`,
  };
}

export function parseDockerInspect(output, target) {
  const fields = String(output).trim().split('|');
  if (fields.length !== 5) throw new Error('Docker returned unreadable image metadata.');
  let repoDigests;
  let os;
  let architecture;
  let variant;
  let id;
  try {
    [repoDigests, os, architecture, variant, id] = fields.map((field) => JSON.parse(field));
  } catch {
    throw new Error('Docker returned unreadable image metadata.');
  }
  // Docker can omit Variant entirely for platforms such as linux/amd64.
  if (variant === null) variant = '';
  if (!Array.isArray(repoDigests) || !repoDigests.includes(target.repoDigest)) {
    throw new Error(`The local Docker image is not associated with ${target.repoDigest}. Push this exact image to ECR on the build host, then retry.`);
  }
  if (typeof os !== 'string' || typeof architecture !== 'string' || !/^[a-z0-9]+$/.test(os) || !/^[a-z0-9]+$/.test(architecture)
    || (variant !== '' && (typeof variant !== 'string' || !/^[a-z0-9._-]+$/.test(variant)))) {
    throw new Error('Docker returned an unsupported image platform.');
  }
  if (typeof id !== 'string' || !SHA256_RE.test(id)) throw new Error('Docker returned an invalid local image ID.');
  const parts = target.platform.split('/');
  if (parts[0] !== os || parts[1] !== architecture || (parts[2] && parts[2] !== variant)) {
    const actual = `${os}/${architecture}${variant ? `/${variant}` : ''}`;
    throw new Error(`The local image is ${actual}; --platform ${target.platform} does not match.`);
  }
  return { repoDigests, os, architecture, variant, id };
}

function inspectArgs(image) {
  return ['image', 'inspect',
    '--format={{json .RepoDigests}}|{{json .Os}}|{{json .Architecture}}|{{json .Variant}}|{{json .Id}}',
    image];
}

async function inspectLocalImage(target, run) {
  let result;
  try {
    result = await run('docker', inspectArgs(target.image), { timeoutMs: 30_000, env: safeEnv() });
  } catch {
    throw new Error('Docker could not inspect the local image. Confirm Docker is running and --image names an image on this build host.');
  }
  return parseDockerInspect(result.stdout, target);
}

function requireCycloneDx(sbom, target) {
  if (!sbom || typeof sbom !== 'object' || Array.isArray(sbom) || sbom.bomFormat !== 'CycloneDX'
    || typeof sbom.specVersion !== 'string' || !Array.isArray(sbom.components)
    || sbom.metadata?.component?.type !== 'container') {
    throw new Error('Trivy did not produce a valid container-image CycloneDX JSON SBOM.');
  }
  const properties = sbom.metadata.component.properties;
  if (Array.isArray(properties)) {
    const reported = properties.filter((item) => item?.name === 'aquasecurity:trivy:RepoDigest').map((item) => item.value);
    if (reported.length && !reported.includes(target.repoDigest)) {
      throw new Error('Trivy reported an SBOM repository digest that differs from the selected ECR image.');
    }
  }
}

export async function generateSbomBundle(options, { run = runCommand } = {}) {
  const target = validateOptions(options);
  const before = await inspectLocalImage(target, run);
  let version;
  try {
    const result = await run('trivy', ['version', '--format=json', '--config='], { timeoutMs: 8_000, env: safeEnv() });
    version = JSON.parse(result.stdout).Version;
  } catch {
    throw new Error('Trivy is unavailable on this build host. Install Trivy 0.71.1 or newer.');
  }
  const match = typeof version === 'string' ? /^(\d+)\.(\d+)\.(\d+)$/.exec(version) : null;
  if (!match || Number(match[1]) === 0 && (Number(match[2]) < 71 || Number(match[2]) === 71 && Number(match[3]) < 1)) {
    throw new Error('Trivy 0.71.1 or newer is required on the build host.');
  }
  const temporary = await mkdtemp(join(tmpdir(), 'ecr-sentinel-sbom-'));
  try {
    let result;
    try {
      result = await run('trivy', [
        'image', '--image-src=docker', '--format=cyclonedx', '--offline-scan',
        '--disable-telemetry', '--skip-version-check', '--config=', '--ignorefile=',
        '--no-progress', '--timeout=14m', `--platform=${target.platform}`,
        '--max-image-size=4GB', '--parallel=2', `--cache-dir=${join(temporary, 'cache')}`,
        before.id,
      ], { timeoutMs: 15 * 60 * 1000, maxOutputBytes: MAX_SBOM_BYTES, env: safeEnv() });
    } catch {
      throw new Error('Trivy could not generate a bounded SBOM from the verified local Docker image ID. Check Docker access, image size, and the 16 MiB SBOM limit.');
    }
    const after = await inspectLocalImage(target, run);
    if (after.id !== before.id) throw new Error('The local image changed while Trivy generated the SBOM. Retry with an immutable local image reference.');
    if (typeof result.stdout !== 'string' || Buffer.byteLength(result.stdout, 'utf8') > MAX_SBOM_BYTES) {
      throw new Error('The generated SBOM exceeds the 16 MiB bundle limit.');
    }
    let sbom;
    try {
      sbom = JSON.parse(result.stdout);
    } catch {
      throw new Error('Trivy returned unreadable CycloneDX JSON.');
    }
    requireCycloneDx(sbom, target);
    const bundle = {
      schemaVersion: 1,
      image: {
        account: target.account,
        region: target.region,
        repository: target.repository,
        digest: target.digest,
        platform: target.platform,
      },
      generatedAt: new Date().toISOString(),
      producer: { name: 'ECR Sentinel pipeline helper', trivyVersion: version },
      sbom,
    };
    const content = `${JSON.stringify(bundle)}\n`;
    if (Buffer.byteLength(content, 'utf8') > MAX_SBOM_BYTES) {
      throw new Error('The completed SBOM bundle exceeds the 16 MiB limit.');
    }
    let handle;
    try {
      handle = await open(target.output, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
      await handle.writeFile(content, 'utf8');
      await handle.sync();
    } catch (error) {
      if (handle) await unlink(target.output).catch(() => {});
      if (error?.code === 'EEXIST') throw new Error(`Output already exists: ${target.output}. Choose a new path to avoid replacing an SBOM.`);
      throw new Error(`Could not write the private SBOM bundle in ${dirname(target.output)}.`);
    } finally {
      await handle?.close();
    }
    return { output: target.output, repoDigest: target.repoDigest, platform: target.platform, bytes: Buffer.byteLength(content, 'utf8') };
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}

async function main(argv) {
  let options;
  try {
    options = parseArgs(argv);
  } catch (error) {
    process.stderr.write(`${error.message}\n\n${USAGE}\n`);
    process.exitCode = 2;
    return;
  }
  if (options.help) {
    process.stdout.write(`${USAGE}\n`);
    return;
  }
  try {
    const result = await generateSbomBundle(options);
    process.stdout.write(`Created ${result.output} (${result.bytes} bytes) for ${result.repoDigest} · ${result.platform}\n`);
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  await main(process.argv.slice(2));
}
