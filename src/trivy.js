import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { lstat, mkdir, open, readFile, readdir, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { AwsCliError, validateDigest, validateRegion, validateRepository } from './aws-cli.js';
import { InspectorDestinationStore } from './inspector-settings.js';

const PLATFORM_RE = /^[a-z0-9]+\/[a-z0-9]+(?:\/[a-z0-9._-]+)?$/;
const ACCOUNT_RE = /^\d{12}$/;
const MAX_OUTPUT = 64 * 1024 * 1024;
const MAX_SBOM_BYTES = 16 * 1024 * 1024;
const MAX_SBOM_NODES = 250_000;
const STALE_SBOM_MS = 60 * 60 * 1000;
const MAX_FINDINGS = 5_000;
const MAX_REPORT_CHARS = 5_000_000;
const MAX_JOBS = 40;
const MAX_REPORTS = 10;
const MAX_PENDING = 3;
const DB_REFRESH_MS = 6 * 60 * 60 * 1000;
const SCAN_TIMEOUT_MS = 15 * 60 * 1000;
const JOB_TIMEOUT_MS = 30 * 60 * 1000;
const STATUS_CACHE_MS = 30_000;
const INSPECTOR_POLL_MS = 5_000;
const INSPECTOR_EXPORT_TIMEOUT_MS = 12 * 60 * 1000;

export function validatePlatform(value) {
  const platform = value === undefined || value === null || value === '' ? 'linux/amd64' : value;
  if (typeof platform !== 'string' || platform.length > 64 || !PLATFORM_RE.test(platform)) {
    throw new AwsCliError(400, 'INVALID_INPUT', 'Select a valid image platform, such as linux/amd64.');
  }
  return platform;
}

function safeText(value, limit = 1200) {
  return typeof value === 'string' ? value.slice(0, limit) : '';
}

function safeUrl(value) {
  if (typeof value !== 'string') return null;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' ? url.href : null;
  } catch {
    return null;
  }
}

function scoreFrom(vulnerability) {
  const sources = Object.values(vulnerability.CVSS ?? {});
  for (const entry of sources) {
    for (const key of ['V4Score', 'V3Score', 'V2Score']) {
      const score = entry?.[key];
      if (typeof score === 'number' && score >= 0 && score <= 10) return score;
    }
  }
  return null;
}

function severity(value) {
  return ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(value) ? value : 'UNKNOWN';
}

function supportedVersion(version) {
  const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(version);
  if (!match) return false;
  const [major, minor, patch] = match.slice(1).map(Number);
  return major > 0 || minor > 71 || (minor === 71 && patch >= 1);
}

export function normalizeTrivyReport(raw, context) {
  const fromSbom = context.scanMode === 'sbom';
  if (!raw || raw.SchemaVersion !== 2
    || (fromSbom
      ? raw.ArtifactName !== context.sbomPath
        || raw.ArtifactType !== context.sbomFormat
        || (raw.Results !== undefined && !Array.isArray(raw.Results))
      : raw.ArtifactType !== 'container_image'
        || raw.ArtifactName !== context.imageRef || !Array.isArray(raw.Results))) {
    throw new AwsCliError(502, 'TRIVY_BAD_REPORT', fromSbom
      ? 'Trivy returned a report that did not match the imported SBOM.'
      : 'Trivy returned a report that did not match the selected image.');
  }
  let actualPlatform;
  if (fromSbom) {
    // The platform is declared by the bundle producer; no image configuration is
    // available to independently verify it in a Trivy SBOM scan.
    actualPlatform = context.platform;
  } else {
    const imageConfig = raw.Metadata?.ImageConfig;
    const actualOs = imageConfig?.os;
    const actualArch = imageConfig?.architecture;
    const actualVariant = imageConfig?.variant;
    if (typeof actualOs !== 'string' || typeof actualArch !== 'string'
      || !/^[a-z0-9]+$/.test(actualOs) || !/^[a-z0-9]+$/.test(actualArch)
      || (actualVariant !== undefined && (typeof actualVariant !== 'string' || !/^[a-z0-9._-]{1,32}$/.test(actualVariant)))) {
      throw new AwsCliError(502, 'PLATFORM_UNVERIFIED', 'Trivy did not identify the image platform, so this report cannot be attributed safely.');
    }
    actualPlatform = `${actualOs}/${actualArch}${actualVariant ? `/${actualVariant}` : ''}`;
    const requestedParts = context.platform.split('/');
    if (requestedParts[0] !== actualOs || requestedParts[1] !== actualArch
      || (requestedParts[2] && requestedParts[2] !== actualVariant)) {
      throw new AwsCliError(422, 'PLATFORM_MISMATCH', `The image is ${actualPlatform}; choose that platform and scan again.`);
    }
  }
  const findings = [];
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
  const packageTypes = new Set();
  let reportChars = 0;
  for (const result of raw.Results ?? []) {
    if (result?.Class === 'os-pkgs') packageTypes.add('os');
    if (result?.Class === 'lang-pkgs') packageTypes.add('library');
    if (!result || !Array.isArray(result.Vulnerabilities)) continue;
    const target = safeText(result.Target, 512);
    const type = safeText(result.Type, 100);
    for (const vuln of result.Vulnerabilities) {
      if (findings.length >= MAX_FINDINGS) {
        throw new AwsCliError(413, 'TRIVY_REPORT_TOO_LARGE', 'The image has too many findings for this local report. Narrow the image or increase the configured report limit.');
      }
      if (!vuln || typeof vuln.VulnerabilityID !== 'string' || typeof vuln.PkgName !== 'string') continue;
      const level = severity(vuln.Severity);
      counts[level] += 1;
      const finding = {
        id: safeText(vuln.VulnerabilityID, 128),
        severity: level,
        title: safeText(vuln.Title || vuln.VulnerabilityID, 300),
        description: typeof vuln.Description === 'string' && vuln.Description.length > 1200
          ? `${vuln.Description.slice(0, 1199)}…` : safeText(vuln.Description, 1200),
        descriptionTruncated: typeof vuln.Description === 'string' && vuln.Description.length > 1200,
        packageName: safeText(vuln.PkgName, 256),
        installedVersion: safeText(vuln.InstalledVersion, 128),
        fixedVersion: safeText(vuln.FixedVersion, 256) || null,
        score: scoreFrom(vuln),
        uri: safeUrl(vuln.PrimaryURL) ?? (Array.isArray(vuln.References) ? vuln.References.map(safeUrl).find(Boolean) : null) ?? null,
        target,
        type,
        source: 'Trivy',
        fixAvailable: vuln.FixedVersion ? 'YES' : 'NO',
        status: safeText(vuln.Status, 100) || null,
      };
      reportChars += Object.values(finding).reduce((size, value) => size + (typeof value === 'string' ? value.length : 0), 0);
      if (reportChars > MAX_REPORT_CHARS) {
        throw new AwsCliError(413, 'TRIVY_REPORT_TOO_LARGE', 'The image has too much finding detail for this local report.');
      }
      findings.push(finding);
    }
  }
  const scannedAt = new Date().toISOString();
  return {
    status: 'COMPLETE',
    source: fromSbom ? 'Trivy SBOM' : 'Trivy',
    scanMode: fromSbom ? 'sbom' : 'image',
    scannedAt,
    scannerVersion: context.scannerVersion,
    dbUpdatedAt: context.dbUpdatedAt,
    profile: context.profile,
    account: context.account,
    region: context.region,
    repository: context.repository,
    digest: context.digest,
    platform: actualPlatform,
    requestedPlatform: context.platform,
    imageRef: context.imageRef,
    ...(fromSbom ? { provenance: {
      sbomSha256: context.sbomSha256,
      ...(context.bundleSha256 ? { bundleSha256: context.bundleSha256 } : {}),
      association: context.sbomAssociation ?? 'unverified',
      ...(context.sbomSource ? { source: context.sbomSource } : {}),
      generatedAt: context.generatedAt,
      producer: context.producer,
      format: context.sbomFormat,
    } } : {}),
    counts,
    summary: { counts, completedAt: scannedAt, updatedAt: context.dbUpdatedAt },
    findings,
    coverage: {
      scanners: ['vuln'],
      packageTypes: [...packageTypes],
      noPackagesDetected: packageTypes.size === 0,
      limitedCoverage: packageTypes.size < 2,
      offlineDependencyResolution: true,
      note: fromSbom
        ? context.sbomSource === 'amazon-inspector'
          ? packageTypes.size === 0
            ? 'Trivy found no supported package targets in the Inspector SBOM. The export metadata matches this image, but zero findings do not establish image coverage.'
            : 'Findings cover packages listed in the Inspector SBOM. Export filters and SBOM metadata match this ECR digest and platform; the inventory is not cryptographically attested. Missing packages will not be scanned.'
          : packageTypes.size === 0
            ? 'Trivy found no supported package targets in this SBOM. The bundle\'s association with this image is unverified; zero findings do not establish image coverage.'
            : 'Findings cover packages listed in the imported SBOM. Its association with this ECR digest and platform is producer-asserted, not cryptographically verified. Missing packages will not be scanned.'
        : packageTypes.size === 0
          ? 'Trivy did not detect OS or language packages in this image. Zero findings do not establish that the image is vulnerability-free.'
          : 'Remote Maven dependency lookup is disabled; some Java dependencies may not be identified.',
    },
  };
}

function scannerEnv(credentials, region, dockerConfig) {
  // Keep proxy and CA settings required for enterprise VPNs, but strip inherited
  // Trivy, Docker and AWS settings that could redirect registries or scans.
  const allowed = [
    'HOME', 'PATH', 'TMPDIR', 'LANG', 'LC_ALL', 'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY',
    'http_proxy', 'https_proxy', 'no_proxy', 'SSL_CERT_FILE', 'SSL_CERT_DIR', 'AWS_CA_BUNDLE',
  ];
  const env = Object.fromEntries(allowed.filter((key) => process.env[key] !== undefined).map((key) => [key, process.env[key]]));
  env.DOCKER_CONFIG = dockerConfig;
  env.AWS_EC2_METADATA_DISABLED = 'true';
  env.AWS_IGNORE_CONFIGURED_ENDPOINT_URLS = 'true';
  env.AWS_SHARED_CREDENTIALS_FILE = '/dev/null';
  env.AWS_CONFIG_FILE = '/dev/null';
  if (credentials) {
    env.AWS_ACCESS_KEY_ID = credentials.accessKeyId;
    env.AWS_SECRET_ACCESS_KEY = credentials.secretAccessKey;
    if (credentials.sessionToken) env.AWS_SESSION_TOKEN = credentials.sessionToken;
    env.AWS_REGION = region;
    env.AWS_DEFAULT_REGION = region;
  }
  return env;
}

async function privateDirectory(path) {
  try {
    await mkdir(path, { mode: 0o700 });
  } catch (error) {
    if (error?.code !== 'EEXIST') throw error;
  }
  const details = await lstat(path);
  const owner = typeof process.getuid === 'function' ? process.getuid() : details.uid;
  if (!details.isDirectory() || details.isSymbolicLink() || details.uid !== owner || (details.mode & 0o077) !== 0) {
    throw new AwsCliError(500, 'UNSAFE_CACHE_DIRECTORY', 'The local scanner cache directory is not private. Remove or secure it before scanning.');
  }
}

export function runBounded(command, args, { env, timeoutMs = 30_000, maxOutputBytes = MAX_OUTPUT, signal } = {}) {
  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawn(command, args, {
        shell: false,
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'],
        env,
        signal,
      });
    } catch (error) {
      reject(error);
      return;
    }
    let stdoutSize = 0;
    let stderrSize = 0;
    let outputExceeded = false;
    let timedOut = false;
    const stdout = [];
    const stderr = [];
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, timeoutMs);
    child.stdout.on('data', (chunk) => {
      stdoutSize += chunk.length;
      if (stdoutSize > maxOutputBytes) {
        outputExceeded = true;
        child.kill('SIGKILL');
      } else stdout.push(chunk);
    });
    child.stderr.on('data', (chunk) => {
      stderrSize += chunk.length;
      if (stderrSize > 64 * 1024) {
        outputExceeded = true;
        child.kill('SIGKILL');
      } else stderr.push(chunk);
    });
    let spawnError = null;
    child.on('error', (error) => { spawnError = error; });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (spawnError) return reject(spawnError);
      if (signal?.aborted) return reject(Object.assign(new Error('Scan canceled'), { code: 'CANCELED' }));
      if (timedOut) return reject(Object.assign(new Error('Trivy timed out'), { code: 'TRIVY_TIMEOUT' }));
      if (outputExceeded) return reject(Object.assign(new Error('Trivy output too large'), { code: 'TRIVY_OUTPUT_TOO_LARGE' }));
      const result = { stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8') };
      if (code !== 0) return reject(Object.assign(new Error('Trivy failed'), { code: 'TRIVY_FAILED', ...result }));
      resolve(result);
    });
  });
}

function mapTrivyError(error, phase) {
  if (error instanceof AwsCliError) return error;
  if (error?.code === 'ENOENT') return new AwsCliError(503, 'TRIVY_MISSING', 'Trivy is not installed. Install it with brew install trivy, then retry.');
  if (error?.code === 'TRIVY_TIMEOUT') return new AwsCliError(504, 'TRIVY_TIMEOUT', 'The local scan took too long. Check VPN and image size, then retry.');
  if (error?.code === 'TRIVY_OUTPUT_TOO_LARGE') return new AwsCliError(413, 'TRIVY_REPORT_TOO_LARGE', 'Trivy produced more report data than this app can safely process.');
  const diagnostic = String(error?.stderr ?? '');
  if (/max(?:imum)? image size|exceeds maximum allowed size/i.test(diagnostic)) {
    return new AwsCliError(413, 'IMAGE_TOO_LARGE', 'This image exceeds the 4 GB local scan limit.');
  }
  if (/unauthorized|authentication required|denied|no basic auth credentials/i.test(diagnostic)) {
    return new AwsCliError(403, 'ECR_PULL_DENIED', 'The selected AWS profile cannot pull this image. Check ECR pull permissions and retry.');
  }
  if (/manifest unknown|not found|NAME_UNKNOWN/i.test(diagnostic)) {
    return new AwsCliError(404, 'IMAGE_NOT_FOUND', 'ECR could not provide this image digest. Refresh the repository and retry.');
  }
  if (/timeout|connection refused|no such host|network is unreachable|TLS handshake/i.test(diagnostic)) {
    return new AwsCliError(502, 'SCAN_NETWORK', 'The scanner could not reach ECR or its vulnerability database. Check VPN, DNS, and registry access.');
  }
  if (phase === 'updating-db') {
    return new AwsCliError(502, 'TRIVY_DB_UNAVAILABLE', 'Trivy could not update its vulnerability databases. Check access to the configured database registries and retry.');
  }
  return new AwsCliError(502, 'TRIVY_FAILED', 'Trivy could not scan this image. Check local scanner installation, VPN, and ECR pull permissions.');
}

function mapSbomError(error, phase) {
  if (error instanceof AwsCliError) return error;
  if (phase === 'updating-db') return mapTrivyError(error, phase);
  if (error?.code === 'ENOENT') return mapTrivyError(error, phase);
  if (error?.code === 'TRIVY_TIMEOUT') return new AwsCliError(504, 'TRIVY_TIMEOUT', 'The SBOM scan took too long. Try a smaller SBOM or check the local scanner.');
  if (error?.code === 'TRIVY_OUTPUT_TOO_LARGE') return new AwsCliError(413, 'TRIVY_REPORT_TOO_LARGE', 'Trivy produced more SBOM report data than this app can safely process.');
  const diagnostic = String(error?.stderr ?? '');
  if (/invalid (?:sbom|cyclonedx|spdx)|failed to decode|failed to parse|unsupported (?:format|sbom)/i.test(diagnostic)) {
    return new AwsCliError(422, 'SBOM_UNSUPPORTED', 'Trivy could not parse this SBOM. Generate a CycloneDX or SPDX JSON bundle from the final image and retry.');
  }
  return new AwsCliError(502, 'SBOM_SCAN_FAILED', 'Trivy could not scan the imported SBOM. Check the file format and local vulnerability database, then retry.');
}

function jobPublic(job, report = null) {
  return {
    id: job.id,
    mode: job.mode,
    status: job.status,
    phase: job.phase,
    createdAt: job.createdAt,
    startedAt: job.startedAt ?? null,
    completedAt: job.completedAt ?? null,
    ...(job.error ? { error: job.error } : {}),
    ...(report ? { report } : {}),
  };
}

function keyFor({ profile, account, region, repository, digest, platform }) {
  return createHash('sha256').update(JSON.stringify([profile, account, region, repository, digest, platform])).digest('hex');
}

function validateSbomDocument(sbom, target, account) {
  if (!sbom || typeof sbom !== 'object' || Array.isArray(sbom)) {
    throw new AwsCliError(422, 'SBOM_BUNDLE_INVALID', 'The bundle does not contain a JSON SBOM.');
  }
  const format = sbom.bomFormat === 'CycloneDX' && /^1\.[4-9]$/.test(sbom.specVersion) && Array.isArray(sbom.components)
    ? 'cyclonedx' : /^SPDX-2\.[23]$/.test(sbom.spdxVersion) && Array.isArray(sbom.packages)
      ? 'spdx' : null;
  if (!format) {
    throw new AwsCliError(422, 'SBOM_FORMAT_UNSUPPORTED', 'The bundle must contain a CycloneDX or SPDX JSON SBOM with a package list.');
  }
  if ((format === 'cyclonedx' ? sbom.components : sbom.packages).length > 100_000) {
    throw new AwsCliError(413, 'SBOM_TOO_LARGE', 'This SBOM has more package entries than the local scanner can safely process.');
  }
  if (format === 'cyclonedx' && Array.isArray(sbom.metadata?.component?.properties)) {
    const suffix = target.region.startsWith('cn-') ? 'amazonaws.com.cn' : 'amazonaws.com';
    const expectedRepoDigest = `${account}.dkr.ecr.${target.region}.${suffix}/${target.repository}@${target.digest}`;
    const reported = sbom.metadata.component.properties
      .filter((item) => item?.name === 'aquasecurity:trivy:RepoDigest')
      .map((item) => item.value);
    if (reported.length && !reported.includes(expectedRepoDigest)) {
      throw new AwsCliError(422, 'SBOM_TARGET_MISMATCH', 'The SBOM package inventory names a different ECR repository digest. Select the matching image or regenerate the bundle.');
    }
  }
  const stack = [{ value: sbom, depth: 0 }];
  let nodes = 0;
  while (stack.length) {
    const { value, depth } = stack.pop();
    if (++nodes > MAX_SBOM_NODES || depth > 64) {
      throw new AwsCliError(413, 'SBOM_TOO_COMPLEX', 'This SBOM is too deeply nested or complex to scan safely.');
    }
    if (value && typeof value === 'object') {
      for (const child of Object.values(value)) stack.push({ value: child, depth: depth + 1 });
    }
  }
  let sbomJson;
  try { sbomJson = JSON.stringify(sbom); } catch {
    throw new AwsCliError(422, 'SBOM_BUNDLE_INVALID', 'The SBOM could not be serialized.');
  }
  if (Buffer.byteLength(sbomJson) > MAX_SBOM_BYTES) {
    throw new AwsCliError(413, 'SBOM_TOO_LARGE', 'The SBOM exceeds the 16 MiB local import limit.');
  }
  return { sbomJson, format, sbomSha256: createHash('sha256').update(sbomJson).digest('hex') };
}

function validateSbomBundle(bundle, target, account) {
  if (!bundle || typeof bundle !== 'object' || Array.isArray(bundle) || bundle.schemaVersion !== 1) {
    throw new AwsCliError(422, 'SBOM_BUNDLE_INVALID', 'Select a version 1 ECR Sentinel SBOM bundle in JSON format.');
  }
  const image = bundle.image;
  if (!image || typeof image !== 'object' || Array.isArray(image)
    || image.account !== account || image.region !== target.region
    || image.repository !== target.repository || image.digest !== target.digest
    || image.platform !== target.platform) {
    throw new AwsCliError(422, 'SBOM_TARGET_MISMATCH', 'This SBOM bundle declares a different account, repository, digest, or platform. Select the matching image and platform.');
  }
  const { sbomJson, format, sbomSha256 } = validateSbomDocument(bundle.sbom, target, account);
  const generatedAt = typeof bundle.generatedAt === 'string' && bundle.generatedAt.length <= 64
    && Number.isFinite(Date.parse(bundle.generatedAt)) ? new Date(bundle.generatedAt).toISOString() : null;
  const producer = bundle.producer && typeof bundle.producer === 'object' && !Array.isArray(bundle.producer)
    ? { name: safeText(bundle.producer.name, 100), trivyVersion: safeText(bundle.producer.trivyVersion, 80) }
    : { name: '', trivyVersion: '' };
  if (!generatedAt || !producer.name.trim() || !producer.trivyVersion.trim()) {
    throw new AwsCliError(422, 'SBOM_BUNDLE_INVALID', 'The bundle needs a valid generation time and producer details. Generate it on the authorized build host.');
  }
  const bundleSha256 = createHash('sha256').update(JSON.stringify([
    account, target.region, target.repository, target.digest, target.platform,
    generatedAt, producer.name, producer.trivyVersion, sbomSha256,
  ])).digest('hex');
  return {
    sbomJson, format,
    sbomSha256, bundleSha256,
    generatedAt, producer,
  };
}

export function validateInspectorSbom(sbom, target, account) {
  if (!sbom || typeof sbom !== 'object' || Array.isArray(sbom)
    || sbom.bomFormat !== 'CycloneDX' || sbom.specVersion !== '1.4'
    || !Array.isArray(sbom.components)) {
    throw new AwsCliError(422, 'INSPECTOR_SBOM_INVALID', 'Inspector did not export a CycloneDX 1.4 JSON SBOM for one image.');
  }
  const metadata = sbom.metadata;
  const properties = metadata?.properties;
  if (!Array.isArray(properties) || properties.length > 128) {
    throw new AwsCliError(422, 'INSPECTOR_SBOM_UNBOUND', 'The Inspector SBOM is missing image identity metadata.');
  }
  const required = ['imageId', 'accountId', 'resourceType', 'architecture'];
  const values = {};
  for (const name of required) {
    const matches = properties.filter((item) => item?.name === name);
    if (matches.length !== 1 || typeof matches[0].value !== 'string') {
      throw new AwsCliError(422, 'INSPECTOR_SBOM_UNBOUND', 'The Inspector SBOM has missing or ambiguous image identity metadata.');
    }
    values[name] = matches[0].value;
  }
  const requestedArch = target.platform.split('/')[1];
  if (values.imageId !== target.digest || values.accountId !== account
    || values.resourceType !== 'AWS_ECR_CONTAINER_IMAGE' || values.architecture !== requestedArch) {
    throw new AwsCliError(422, 'INSPECTOR_SBOM_TARGET_MISMATCH',
      'The Inspector SBOM identifies a different account, image digest, resource type, or architecture. Select the exact image manifest and platform.');
  }
  // Inspector identifies architecture but does not attest OS or variant in its
  // published CycloneDX metadata. Reject variants rather than claiming a match.
  if (target.platform !== `linux/${requestedArch}`) {
    throw new AwsCliError(422, 'INSPECTOR_SBOM_PLATFORM_UNVERIFIED',
      'Inspector does not identify this OS or platform variant in its SBOM metadata. Choose the matching linux architecture without a variant.');
  }
  const timestamp = metadata.timestamp;
  if (typeof timestamp !== 'string' || timestamp.length > 64 || !Number.isFinite(Date.parse(timestamp))) {
    throw new AwsCliError(422, 'INSPECTOR_SBOM_INVALID', 'The Inspector SBOM is missing a valid generation time.');
  }
  const base = validateSbomDocument(sbom, target, account);
  const generatedAt = new Date(timestamp).toISOString();
  const producer = { name: 'Amazon Inspector SBOM Generator' };
  return { ...base, generatedAt, producer,
    association: 'metadata-verified', source: 'amazon-inspector' };
}

function verifyRepositoryUri(item, identity, repository, region) {
  const uri = item?.repositoryUri;
  const registryId = item?.registryId;
  if (!ACCOUNT_RE.test(identity.account) || registryId !== identity.account || typeof uri !== 'string') {
    throw new AwsCliError(502, 'ECR_BAD_REPOSITORY', 'ECR returned repository details inconsistent with the selected account.');
  }
  // Region is already limited to ASCII letters, digits, and hyphens.
  const host = new RegExp(`^${identity.account}\\.dkr\\.ecr\\.${region}\\.amazonaws\\.com(?:\\.cn)?/`);
  if (!host.test(uri) || uri !== uri.split('/')[0] + '/' + repository) {
    throw new AwsCliError(502, 'ECR_BAD_REPOSITORY', 'ECR returned an unexpected registry address for this repository.');
  }
  return uri;
}

export class TrivyScanService {
  constructor(aws, { run = runBounded, command = 'trivy', cacheRoot = join(tmpdir(), 'ecr-sentinel-trivy-cache'),
    settingsRoot, settingsStore } = {}) {
    this.aws = aws;
    this.run = run;
    this.command = command;
    this.cacheRoot = cacheRoot;
    this.settings = settingsStore ?? new InspectorDestinationStore(settingsRoot ? { root: settingsRoot } : {});
    this.cachePending = null;
    this.dbPreparedAt = null;
    this.scannerVersion = null;
    this.statusCache = null;
    this.statusCheckedAt = 0;
    this.statusPending = null;
    this.jobs = new Map();
    this.reports = new Map();
    this.pending = [];
    this.active = null;
  }

  async ensureCache() {
    if (!this.cachePending) this.cachePending = (async () => {
      await privateDirectory(this.cacheRoot);
      await privateDirectory(join(this.cacheRoot, 'cache'));
      await privateDirectory(join(this.cacheRoot, 'docker-empty'));
      const sbomDirectory = join(this.cacheRoot, 'sboms');
      await privateDirectory(sbomDirectory);
      const owner = typeof process.getuid === 'function' ? process.getuid() : null;
      for (const name of await readdir(sbomDirectory)) {
        if (!/^[a-f0-9-]{36}\.(?:cyclonedx|spdx)\.json$/.test(name)) continue;
        const path = join(sbomDirectory, name);
        try {
          const details = await lstat(path);
          if ((details.isFile() || details.isSymbolicLink())
            && (owner === null || details.uid === owner)
            && Date.now() - details.mtimeMs > STALE_SBOM_MS) await unlink(path);
        } catch (error) {
          if (error?.code !== 'ENOENT') throw error;
        }
      }
      return this.cacheRoot;
    })().catch((error) => {
      this.cachePending = null;
      throw error;
    });
    return this.cachePending;
  }

  async dbMetadata(cacheRoot, name = 'db') {
    try {
      const raw = await readFile(join(cacheRoot, 'cache', name, 'metadata.json'), 'utf8');
      const value = JSON.parse(raw);
      const updatedAt = value.UpdatedAt;
      return typeof updatedAt === 'string' && Number.isFinite(Date.parse(updatedAt))
        ? new Date(updatedAt).toISOString() : null;
    } catch {
      return null;
    }
  }

  async status() {
    if (this.statusCache && Date.now() - this.statusCheckedAt < STATUS_CACHE_MS) return this.statusCache;
    if (this.statusPending) return this.statusPending;
    this.statusPending = this.probeStatus().then((result) => {
      this.statusCache = result;
      this.statusCheckedAt = Date.now();
      return result;
    }).finally(() => {
      this.statusPending = null;
    });
    return this.statusPending;
  }

  async probeStatus() {
    try {
      const cacheRoot = await this.ensureCache();
      const { stdout } = await this.run(this.command,
        ['version', '--format=json', '--config=', `--cache-dir=${join(cacheRoot, 'cache')}`],
        { env: scannerEnv(null, null, join(cacheRoot, 'docker-empty')), timeoutMs: 8000, maxOutputBytes: 64 * 1024 });
      const value = JSON.parse(stdout);
      const version = safeText(value.Version ?? value.version, 80);
      if (!version) throw new Error('Version unavailable');
      if (!supportedVersion(version)) {
        return {
          available: false, version,
          error: { code: 'TRIVY_UNSAFE_VERSION', message: 'Trivy 0.71.1 or newer is required. Upgrade to a trusted stable release and retry.' },
        };
      }
      this.scannerVersion = version;
      return { available: true, version };
    } catch (error) {
      const mapped = mapTrivyError(error, 'preflight');
      return { available: false, version: null, error: { code: mapped.code, message: mapped.message } };
    }
  }

  validateContext(input) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
      throw new AwsCliError(400, 'INVALID_INPUT', 'Select an AWS profile and Region.');
    }
    if (typeof input.profile !== 'string' || !input.profile || input.profile.length > 128 || /[\x00-\x1f\x7f]/.test(input.profile)) {
      throw new AwsCliError(400, 'INVALID_INPUT', 'Select a configured AWS profile.');
    }
    return {
      profile: input.profile,
      region: validateRegion(input.region),
    };
  }

  validateTarget(input) {
    return {
      ...this.validateContext(input),
      repository: validateRepository(input.repository),
      digest: validateDigest(input.digest),
      platform: validatePlatform(input.platform),
    };
  }

  async verifiedInspectorContext(input) {
    const selected = this.validateContext(input);
    const identity = await this.aws.identity(selected.profile, selected.region);
    if (!ACCOUNT_RE.test(identity?.account ?? '')) {
      throw new AwsCliError(502, 'AWS_BAD_RESPONSE', 'AWS did not return a valid account identity.');
    }
    return { ...selected, account: identity.account };
  }

  async inspectorDestination(input) {
    const context = await this.verifiedInspectorContext(input);
    const destination = await this.settings.get(context);
    return { configured: Boolean(destination), destination };
  }

  async saveInspectorDestination(input) {
    const context = await this.verifiedInspectorContext(input);
    const destination = await this.settings.put(context, input.destination);
    return { configured: true, destination };
  }

  async deleteInspectorDestination(input) {
    const context = await this.verifiedInspectorContext(input);
    await this.settings.delete(context);
    return { configured: false, destination: null };
  }

  async start(input) {
    const target = this.validateTarget(input);
    const identity = await this.aws.identity(target.profile, target.region);
    return this.enqueue(target, identity.account, 'image');
  }

  async startSbom(input) {
    const target = this.validateTarget(input);
    const identity = await this.aws.identity(target.profile, target.region);
    const sbom = validateSbomBundle(input.bundle, target, identity.account);
    return this.enqueue(target, identity.account, 'sbom', sbom);
  }

  async startInspector(input) {
    const target = this.validateTarget(input);
    if (['bucketName', 'keyPrefix', 'kmsKeyArn', 's3Destination', 'destination']
      .some((key) => Object.hasOwn(input, key))) {
      throw new AwsCliError(400, 'INVALID_INPUT', 'Save the Inspector export destination in the app, then start the scan.');
    }
    if (target.platform.split('/').length !== 2 || !target.platform.startsWith('linux/')) {
      throw new AwsCliError(422, 'INSPECTOR_SBOM_PLATFORM_UNVERIFIED',
        'Inspector identifies image architecture but not OS or variant. Select a linux platform without a variant.');
    }
    const identity = await this.aws.identity(target.profile, target.region);
    if (!ACCOUNT_RE.test(identity?.account ?? '')) {
      throw new AwsCliError(502, 'AWS_BAD_RESPONSE', 'AWS did not return a valid account identity.');
    }
    const destination = await this.settings.get({ profile: target.profile, region: target.region, account: identity.account });
    if (!destination) {
      throw new AwsCliError(409, 'INSPECTOR_DESTINATION_NOT_CONFIGURED',
        'Set up the Inspector export destination for this AWS account and Region, then start the scan.');
    }
    return this.enqueue(target, identity.account, 'inspector-sbom', null, destination);
  }

  enqueue(target, account, mode, sbom = null, inspectorDestination = null) {
    const targetKey = keyFor({ ...target, account });
    const destinationKey = inspectorDestination
      ? createHash('sha256').update(JSON.stringify(inspectorDestination)).digest('hex') : null;
    const key = `${targetKey}:${mode}${sbom ? `:${sbom.bundleSha256}` : ''}${destinationKey ? `:${destinationKey}` : ''}`;
    const existing = [...this.jobs.values()].find((item) => item.key === key && ['PENDING', 'IN_PROGRESS'].includes(item.status));
    if (existing) return jobPublic(existing);
    if (this.pending.length >= MAX_PENDING) {
      throw new AwsCliError(429, 'SCAN_QUEUE_FULL', 'The local scan queue is full. Wait for a scan to finish before starting another.');
    }
    const requestedPrefix = inspectorDestination?.keyPrefix.replace(/\/+$/, '') ?? '';
    const job = {
      id: randomUUID(), key, targetKey, target, account, mode, sbom, status: 'PENDING', phase: 'queued',
      createdAt: new Date().toISOString(), controller: new AbortController(),
      ...(inspectorDestination ? { inspectorDestination: {
        ...inspectorDestination,
        keyPrefix: `${requestedPrefix ? `${requestedPrefix}/` : ''}ecr-sentinel/${randomUUID()}/`,
      } } : {}),
    };
    this.jobs.set(job.id, job);
    this.pending.push(job);
    while (this.jobs.size > MAX_JOBS) {
      const oldest = [...this.jobs.values()].find((item) => !['PENDING', 'IN_PROGRESS'].includes(item.status));
      if (!oldest) break;
      this.jobs.delete(oldest.id);
    }
    this.drain();
    return jobPublic(job);
  }

  get(id) {
    if (typeof id !== 'string' || !/^[a-f0-9-]{36}$/.test(id)) {
      throw new AwsCliError(400, 'INVALID_INPUT', 'The scan ID is invalid.');
    }
    const job = this.jobs.get(id);
    if (!job) throw new AwsCliError(404, 'SCAN_NOT_FOUND', 'This local scan is no longer available.');
    const stored = this.reports.get(job.key);
    return jobPublic(job, stored?.jobId === id ? stored.report : null);
  }

  cancel(id) {
    const job = this.jobs.get(id);
    if (!job) throw new AwsCliError(404, 'SCAN_NOT_FOUND', 'This local scan is no longer available.');
    if (job.status === 'PENDING') {
      this.pending = this.pending.filter((item) => item.id !== id);
      job.status = 'CANCELED';
      job.phase = 'canceled';
      job.completedAt = new Date().toISOString();
      job.sbom = null;
      job.inspectorDestination = null;
    } else if (job.status === 'IN_PROGRESS') {
      job.controller.abort();
    }
    return jobPublic(job);
  }

  async latest(input) {
    const target = this.validateTarget(input);
    const identity = await this.aws.identity(target.profile, target.region);
    const targetKey = keyFor({ ...target, account: identity.account });
    const stored = [...this.reports.values()].reverse().find((item) => item.targetKey === targetKey
      && item.report?.account === identity.account);
    const job = [...this.jobs.values()].reverse().find((item) => item.targetKey === targetKey
      && (!item.account || item.account === identity.account));
    return {
      report: stored?.report?.account === identity.account ? stored.report : null,
      job: job ? jobPublic(job) : null,
    };
  }

  drain() {
    if (this.active || !this.pending.length) return;
    const job = this.pending.shift();
    this.active = job;
    job.status = 'IN_PROGRESS';
    job.phase = 'preflight';
    job.startedAt = new Date().toISOString();
    const deadline = setTimeout(() => {
      job.timedOut = true;
      job.controller.abort();
    }, JOB_TIMEOUT_MS);
    (job.mode === 'sbom' ? this.runSbomJob(job)
      : job.mode === 'inspector-sbom' ? this.runInspectorJob(job) : this.runJob(job)).then((report) => {
      if (job.controller.signal.aborted) throw Object.assign(new Error('Canceled'), { code: 'CANCELED' });
      job.status = 'COMPLETE';
      job.phase = 'complete';
      this.reports.delete(job.key);
      this.reports.set(job.key, { jobId: job.id, targetKey: job.targetKey, report });
      while (this.reports.size > MAX_REPORTS) this.reports.delete(this.reports.keys().next().value);
    }).catch((error) => {
      if (job.timedOut) {
        job.status = 'FAILED';
        job.phase = 'failed';
        job.error = {
          code: 'SCAN_DEADLINE',
          message: job.mode !== 'image'
            ? 'The SBOM workflow exceeded its 30 minute deadline. Check Inspector export, S3 access, and scanner database access.'
            : 'The local scan exceeded its 30 minute deadline. Check image size, VPN, and scanner database access.',
        };
      } else if (job.controller.signal.aborted || error?.code === 'CANCELED') {
        job.status = 'CANCELED';
        job.phase = 'canceled';
      } else {
        const mapped = job.mode !== 'image' ? mapSbomError(error, job.phase) : mapTrivyError(error, job.phase);
        job.status = 'FAILED';
        job.phase = 'failed';
        job.error = { code: mapped.code, message: mapped.message };
      }
    }).finally(() => {
      clearTimeout(deadline);
      job.completedAt = new Date().toISOString();
      job.sbom = null;
      job.inspectorDestination = null;
      this.active = null;
      this.drain();
    });
  }

  async downloadJavaDb(cacheDir, dockerConfig, signal, mode = 'image') {
    const base = [mode, `--cache-dir=${cacheDir}`, '--config=', '--ignorefile=',
      '--disable-telemetry', '--skip-version-check', '--no-progress'];
    try {
      await this.run(this.command, [...base, '--download-java-db-only'], {
        env: scannerEnv(null, null, dockerConfig), timeoutMs: 5 * 60 * 1000,
        maxOutputBytes: 128 * 1024, signal,
      });
    } catch (error) {
      throw mapTrivyError(error, 'updating-db');
    }
  }

  async prepareDatabase(job, cacheRoot, mode = 'image') {
    const signal = job.controller.signal;
    const cacheDir = join(cacheRoot, 'cache');
    const dockerConfig = join(cacheRoot, 'docker-empty');
    if (!this.dbPreparedAt || Date.now() - Date.parse(this.dbPreparedAt) > DB_REFRESH_MS) {
      job.phase = 'updating-db';
      const base = [mode, `--cache-dir=${cacheDir}`, '--config=', '--ignorefile=',
        '--disable-telemetry', '--skip-version-check', '--no-progress'];
      try {
        await this.run(this.command, [...base, '--download-db-only'], {
          env: scannerEnv(null, null, dockerConfig), timeoutMs: 5 * 60 * 1000,
          maxOutputBytes: 128 * 1024, signal,
        });
        if (signal.aborted) throw Object.assign(new Error('Canceled'), { code: 'CANCELED' });
        this.dbPreparedAt = new Date().toISOString();
      } catch (error) {
        throw mapTrivyError(error, 'updating-db');
      }
    }
    const dbUpdatedAt = await this.dbMetadata(cacheRoot);
    if (!dbUpdatedAt) {
      throw new AwsCliError(502, 'TRIVY_DB_METADATA_MISSING', 'Trivy updated its database but did not provide a valid database timestamp.');
    }
    const javaDbUpdatedAt = await this.dbMetadata(cacheRoot, 'java-db');
    if (javaDbUpdatedAt && Date.now() - Date.parse(javaDbUpdatedAt) > DB_REFRESH_MS) {
      job.phase = 'updating-db';
      await this.downloadJavaDb(cacheDir, dockerConfig, signal, mode);
    }
    return dbUpdatedAt;
  }

  async runJob(job) {
    const { profile, region, repository, digest, platform } = job.target;
    const signal = job.controller.signal;
    const checkCanceled = () => {
      if (signal.aborted) throw Object.assign(new Error('Canceled'), { code: 'CANCELED' });
    };
    const scanner = await this.status();
    if (!scanner.available) throw new AwsCliError(503, scanner.error.code, scanner.error.message);
    checkCanceled();
    const identity = await this.aws.identity(profile, region);
    if (job.account !== identity.account) {
      throw new AwsCliError(409, 'AWS_ACCOUNT_CHANGED', 'The selected profile now resolves to a different AWS account. Reconnect and start a new scan.');
    }
    const [repo, image] = await Promise.all([
      this.aws.repository(profile, region, repository),
      this.aws.image(profile, region, repository, digest),
    ]);
    checkCanceled();
    if (image.imageStatus && image.imageStatus !== 'ACTIVE') {
      throw new AwsCliError(422, 'IMAGE_ARCHIVED', 'Restore this image in ECR before scanning it locally.');
    }
    const repositoryUri = verifyRepositoryUri(repo, identity, repository, region);
    const imageRef = `${repositoryUri}@${digest}`;
    const cacheRoot = await this.ensureCache();
    const cacheDir = join(cacheRoot, 'cache');
    const dockerConfig = join(cacheRoot, 'docker-empty');
    // Databases update without AWS credentials. The image scan then uses
    // short-lived role credentials only for ECR layer access.
    const dbUpdatedAt = await this.prepareDatabase(job, cacheRoot);
    checkCanceled();
    const args = [
      'image', `--cache-dir=${cacheDir}`, '--config=', '--ignorefile=',
      '--disable-telemetry', '--skip-version-check', '--no-progress',
      '--image-src=remote', '--scanners=vuln', '--format=json', '--exit-code=0',
      '--skip-db-update', '--skip-java-db-update', '--skip-check-update',
      '--offline-scan', '--max-image-size=4GB', '--parallel=2', '--timeout=14m',
      `--platform=${platform}`, imageRef,
    ];
    const scanOnce = async () => {
      job.phase = 'scanning';
      const credentials = await this.aws.exportCredentials(profile, region);
      checkCanceled();
      const credentialAccount = await this.aws.identityForCredentials(credentials, region);
      if (credentialAccount !== job.account) {
        throw new AwsCliError(409, 'AWS_ACCOUNT_CHANGED', 'The selected profile now resolves to a different AWS account. Reconnect and start a new scan.');
      }
      checkCanceled();
      return this.run(this.command, args, {
        env: scannerEnv(credentials, region, dockerConfig),
        timeoutMs: SCAN_TIMEOUT_MS,
        maxOutputBytes: MAX_OUTPUT,
        signal,
      });
    };
    let output;
    try {
      output = await scanOnce();
    } catch (error) {
      if (!signal.aborted && /(?:first run cannot skip downloading Java DB|Unable to initialize the Java DB|skip-java-db-update.*first run)/i.test(String(error?.stderr ?? ''))) {
        job.phase = 'updating-db';
        try {
          await this.downloadJavaDb(cacheDir, dockerConfig, signal);
          checkCanceled();
          output = await scanOnce();
        } catch (retryError) {
          throw mapTrivyError(retryError, job.phase);
        }
      } else {
        throw mapTrivyError(error, 'scanning');
      }
    }
    checkCanceled();
    job.phase = 'processing';
    let raw;
    try {
      raw = JSON.parse(output.stdout);
    } catch {
      throw new AwsCliError(502, 'TRIVY_BAD_REPORT', 'Trivy returned unreadable scan results.');
    }
    return normalizeTrivyReport(raw, {
      ...job.target, account: identity.account, imageRef,
      scannerVersion: scanner.version, dbUpdatedAt,
    });
  }

  async runSbomJob(job) {
    const { profile, region, repository, digest } = job.target;
    const signal = job.controller.signal;
    const checkCanceled = () => {
      if (signal.aborted) throw Object.assign(new Error('Canceled'), { code: 'CANCELED' });
    };
    const scanner = await this.status();
    if (!scanner.available) throw new AwsCliError(503, scanner.error.code, scanner.error.message);
    checkCanceled();
    const identity = await this.aws.identity(profile, region);
    if (identity.account !== job.account) {
      throw new AwsCliError(409, 'AWS_ACCOUNT_CHANGED', 'The selected profile now resolves to a different AWS account. Reconnect and start a new scan.');
    }
    // This is ECR metadata only. No layer or manifest bytes are requested.
    await this.aws.image(profile, region, repository, digest);
    checkCanceled();
    const cacheRoot = await this.ensureCache();
    const cacheDir = join(cacheRoot, 'cache');
    const dockerConfig = join(cacheRoot, 'docker-empty');
    const dbUpdatedAt = await this.prepareDatabase(job, cacheRoot);
    checkCanceled();
    const sbom = job.sbom;
    if (!sbom) throw Object.assign(new Error('Canceled'), { code: 'CANCELED' });
    const sbomPath = join(cacheRoot, 'sboms', `${randomUUID()}.${sbom.format}.json`);
    try {
      await writeFile(sbomPath, sbom.sbomJson, { flag: 'wx', mode: 0o600 });
      checkCanceled();
      const args = [
        'sbom', `--cache-dir=${cacheDir}`, '--config=', '--ignorefile=',
        '--disable-telemetry', '--skip-version-check', '--no-progress',
        '--scanners=vuln', '--format=json', '--exit-code=0',
        '--skip-db-update', '--skip-java-db-update', '--offline-scan',
        sbomPath,
      ];
      const scanOnce = async () => {
        job.phase = 'scanning-sbom';
        return this.run(this.command, args, {
          env: scannerEnv(null, null, dockerConfig),
          timeoutMs: SCAN_TIMEOUT_MS, maxOutputBytes: MAX_OUTPUT, signal,
        });
      };
      let output;
      try {
        output = await scanOnce();
      } catch (error) {
        if (!signal.aborted && /(?:first run cannot skip downloading Java DB|Unable to initialize the Java DB|skip-java-db-update.*first run)/i.test(String(error?.stderr ?? ''))) {
          job.phase = 'updating-db';
          await this.downloadJavaDb(cacheDir, dockerConfig, signal);
          checkCanceled();
          try { output = await scanOnce(); } catch (retryError) { throw mapSbomError(retryError, 'scanning-sbom'); }
        } else {
          throw mapSbomError(error, 'scanning-sbom');
        }
      }
      checkCanceled();
      job.phase = 'processing';
      let raw;
      try { raw = JSON.parse(output.stdout); } catch {
        throw new AwsCliError(502, 'TRIVY_BAD_REPORT', 'Trivy returned unreadable SBOM scan results.');
      }
      return normalizeTrivyReport(raw, {
        ...job.target, account: identity.account, scanMode: 'sbom',
        scannerVersion: scanner.version, dbUpdatedAt,
        sbomPath, sbomFormat: sbom.format, sbomSha256: sbom.sbomSha256,
        bundleSha256: sbom.bundleSha256,
        generatedAt: sbom.generatedAt, producer: sbom.producer,
        sbomSource: sbom.source, sbomAssociation: sbom.association,
      });
    } finally {
      await unlink(sbomPath).catch((error) => {
        if (error?.code !== 'ENOENT') throw error;
      });
    }
  }

  async runInspectorJob(job) {
    const { profile, region, repository, digest } = job.target;
    const signal = job.controller.signal;
    const checkCanceled = () => {
      if (signal.aborted) throw Object.assign(new Error('Canceled'), { code: 'CANCELED' });
    };
    const scanner = await this.status();
    if (!scanner.available) throw new AwsCliError(503, scanner.error.code, scanner.error.message);
    checkCanceled();
    const identity = await this.aws.identity(profile, region);
    if (identity.account !== job.account) {
      throw new AwsCliError(409, 'AWS_ACCOUNT_CHANGED', 'The selected profile now resolves to a different AWS account. Reconnect and start a new scan.');
    }
    // DescribeImages reads ECR inventory metadata. It does not fetch manifests or layers.
    const image = await this.aws.image(profile, region, repository, digest);
    if (image.imageStatus && image.imageStatus !== 'ACTIVE') {
      throw new AwsCliError(422, 'IMAGE_ARCHIVED', 'Restore this image in ECR before exporting its Inspector SBOM.');
    }
    checkCanceled();
    const destination = job.inspectorDestination;
    if (!destination) throw Object.assign(new Error('Canceled'), { code: 'CANCELED' });
    job.phase = 'requesting-sbom';
    const { reportId, resourceId } = await this.aws.createInspectorSbomExport(job.target, job.account, destination, signal);
    checkCanceled();
    job.phase = 'waiting-for-sbom';
    const expiresAt = Date.now() + INSPECTOR_EXPORT_TIMEOUT_MS;
    let exportStatus;
    while (Date.now() < expiresAt) {
      checkCanceled();
      exportStatus = await this.aws.getInspectorSbomExport(job.target, reportId, signal);
      checkCanceled();
      if (exportStatus.status !== 'IN_PROGRESS') break;
      await delay(INSPECTOR_POLL_MS, undefined, { signal });
    }
    if (!exportStatus || exportStatus.status === 'IN_PROGRESS') {
      throw new AwsCliError(504, 'INSPECTOR_EXPORT_TIMEOUT', 'Inspector did not finish the SBOM export within 12 minutes. Check export status in AWS and retry.');
    }
    if (exportStatus.status !== 'SUCCEEDED') {
      const code = exportStatus.errorCode;
      const message = code === 'NO_FINDINGS_FOUND'
        ? 'Inspector has no monitored SBOM for this exact image. Check enhanced scanning coverage and retry.'
        : code === 'INVALID_PERMISSIONS'
          ? 'Inspector cannot write this SBOM. Check the S3 bucket policy and KMS key policy for Inspector exports.'
          : code === 'BUCKET_NOT_FOUND' || code === 'INCOMPATIBLE_BUCKET_REGION' || code === 'MALFORMED_KMS_KEY'
            ? 'Inspector rejected the S3 bucket or KMS key. Check that both are configured for this Region.'
            : 'Inspector could not export this image SBOM. Check Inspector coverage and export configuration.';
      throw new AwsCliError(502, 'INSPECTOR_EXPORT_FAILED', message);
    }
    if (exportStatus.format !== 'CYCLONEDX_1_4'
      || exportStatus.s3Destination?.bucketName !== destination.bucketName
      || exportStatus.s3Destination?.keyPrefix !== destination.keyPrefix
      || exportStatus.s3Destination?.kmsKeyArn !== destination.kmsKeyArn) {
      throw new AwsCliError(502, 'INSPECTOR_EXPORT_MISMATCH', 'Inspector returned a different SBOM format or export destination. The object was not opened.');
    }
    const filters = exportStatus.filterCriteria;
    const expected = {
      accountId: job.account,
      resourceId,
      resourceType: 'AWS_ECR_CONTAINER_IMAGE',
    };
    if (!filters || Object.entries(expected).some(([name, value]) =>
      !Array.isArray(filters[name]) || filters[name].length !== 1
      || filters[name][0]?.comparison !== 'EQUALS' || filters[name][0]?.value !== value)) {
      throw new AwsCliError(502, 'INSPECTOR_EXPORT_MISMATCH', 'Inspector returned different resource filters. The object was not opened.');
    }
    checkCanceled();
    job.phase = 'retrieving-sbom';
    const object = await this.aws.listInspectorSbomObject(job.target, destination, signal);
    const cacheRoot = await this.ensureCache();
    const exportPath = join(cacheRoot, 'sboms', `${randomUUID()}.cyclonedx.json`);
    const file = await open(exportPath, 'wx', 0o600);
    await file.close();
    try {
      await this.aws.downloadInspectorSbomObject(job.target, destination, object, exportPath, signal);
      checkCanceled();
      const details = await lstat(exportPath);
      const owner = typeof process.getuid === 'function' ? process.getuid() : details.uid;
      if (!details.isFile() || details.isSymbolicLink() || details.uid !== owner
        || (details.mode & 0o077) !== 0 || details.size !== object.size || details.size > MAX_SBOM_BYTES) {
        throw new AwsCliError(422, 'INSPECTOR_EXPORT_INVALID', 'The downloaded Inspector SBOM changed size or is not a private local file.');
      }
      const bytes = await readFile(exportPath);
      checkCanceled();
      let sbom;
      try { sbom = JSON.parse(bytes.toString('utf8')); } catch {
        throw new AwsCliError(422, 'INSPECTOR_SBOM_INVALID', 'Inspector exported unreadable SBOM JSON.');
      }
      job.sbom = validateInspectorSbom(sbom, job.target, job.account);
    } finally {
      await unlink(exportPath).catch((error) => {
        if (error?.code !== 'ENOENT') throw error;
      });
    }
    checkCanceled();
    return this.runSbomJob(job);
  }

  async dispose() {
    for (const job of this.pending) {
      job.status = 'CANCELED';
      job.phase = 'canceled';
      job.completedAt = new Date().toISOString();
      job.sbom = null;
      job.inspectorDestination = null;
    }
    this.pending = [];
    this.active?.controller.abort();
  }
}
