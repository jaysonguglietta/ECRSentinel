import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, stat, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { generateSbomBundle, parseArgs, parseDockerInspect } from '../scripts/generate-sbom-bundle.mjs';

const DIGEST = `sha256:${'a'.repeat(64)}`;
const REPO_DIGEST = `123456789012.dkr.ecr.us-east-1.amazonaws.com/team/service@${DIGEST}`;

function options(output) {
  return {
    image: 'service:build-42', account: '123456789012', region: 'us-east-1',
    repository: 'team/service', digest: DIGEST, platform: 'linux/amd64', output,
  };
}

function dockerInspect(repoDigests = [REPO_DIGEST], os = 'linux', arch = 'amd64') {
  return [repoDigests, os, arch, '', `sha256:${'b'.repeat(64)}`].map(JSON.stringify).join('|');
}

function sbom(repoDigest = REPO_DIGEST) {
  return {
    bomFormat: 'CycloneDX', specVersion: '1.5', components: [],
    metadata: {
      component: {
        type: 'container', properties: [
          { name: 'aquasecurity:trivy:RepoDigest', value: repoDigest },
        ],
      },
    },
  };
}

function fakeRun(calls, { inspect = dockerInspect(), document = sbom() } = {}) {
  let inspectCount = 0;
  return async (command, args) => {
    calls.push({ command, args });
    if (command === 'docker') {
      const inspections = Array.isArray(inspect) ? inspect : [inspect];
      return { stdout: inspections[Math.min(inspectCount++, inspections.length - 1)], stderr: '' };
    }
    if (command === 'trivy' && args[0] === 'version') return { stdout: '{"Version":"0.76.0"}', stderr: '' };
    if (command === 'trivy' && args[0] === 'image') {
      return { stdout: JSON.stringify(document), stderr: '' };
    }
    throw new Error(`Unexpected command: ${command}`);
  };
}

test('requires complete, validated CLI arguments', () => {
  assert.throws(() => parseArgs(['--image', 'service:1']), /Missing required --account/);
  assert.throws(() => parseArgs([
    '--image', 'service:1', '--account', '123456789012', '--region', 'us-east-1',
    '--repository', 'team/service', '--digest', DIGEST, '--platform', 'linux/amd64',
    '--output', '/tmp/a', '--output', '/tmp/b',
  ]), /Duplicate option/);
  assert.throws(() => parseArgs([
    '--image', 'service:1', '--account', '123456789012', '--region', 'us-east-1',
    '--repository', 'team/service', '--digest', DIGEST, '--platform', 'linux/amd64',
    '--output', '/tmp/a', '--unknown', 'x',
  ]), /Unknown option/);
});

test('accepts Docker images without a platform variant', () => {
  const inspected = parseDockerInspect([
    JSON.stringify([REPO_DIGEST]), '"linux"', '"amd64"', 'null', JSON.stringify(`sha256:${'b'.repeat(64)}`),
  ].join('|'), {
    repoDigest: REPO_DIGEST, platform: 'linux/amd64',
  });
  assert.equal(inspected.variant, '');
});

test('generates a private digest-bound bundle only from local Docker', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'sentinel-bundle-test-'));
  try {
    const output = join(directory, 'bundle.json');
    const calls = [];
    const result = await generateSbomBundle(options(output), { run: fakeRun(calls) });
    const bundle = JSON.parse(await readFile(output, 'utf8'));
    assert.equal(result.repoDigest, REPO_DIGEST);
    assert.deepEqual(bundle.image, {
      account: '123456789012', region: 'us-east-1', repository: 'team/service',
      digest: DIGEST, platform: 'linux/amd64',
    });
    assert.equal(bundle.producer.trivyVersion, '0.76.0');
    assert.equal(bundle.sbom.bomFormat, 'CycloneDX');
    assert.equal((await stat(output)).mode & 0o777, 0o600);
    const imageCall = calls.find(({ command, args }) => command === 'trivy' && args[0] === 'image');
    assert.ok(imageCall);
    assert.ok(imageCall.args.includes('--image-src=docker'));
    assert.ok(imageCall.args.includes('--platform=linux/amd64'));
    assert.ok(imageCall.args.includes('--max-image-size=4GB'));
    assert.ok(imageCall.args.some((value) => value.startsWith('--cache-dir=')));
    assert.equal(imageCall.args.at(-1), `sha256:${'b'.repeat(64)}`);
    assert.equal(imageCall.args.some((value) => value.startsWith('--output=')), false);
    assert.equal(calls.filter(({ command }) => command === 'docker').length, 2);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('rejects a tag swap while Trivy stays pinned to the inspected image ID', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'sentinel-bundle-test-'));
  try {
    const output = join(directory, 'bundle.json');
    const calls = [];
    const after = [
      JSON.stringify([REPO_DIGEST]), '"linux"', '"amd64"', '""', JSON.stringify(`sha256:${'c'.repeat(64)}`),
    ].join('|');
    await assert.rejects(generateSbomBundle(options(output), {
      run: fakeRun(calls, { inspect: [dockerInspect(), after] }),
    }), /local image changed/);
    assert.equal(calls.find(({ command, args }) => command === 'trivy' && args[0] === 'image').args.at(-1),
      `sha256:${'b'.repeat(64)}`);
    assert.deepEqual(await readdir(directory), []);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('will not replace an existing bundle', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'sentinel-bundle-test-'));
  try {
    const output = join(directory, 'bundle.json');
    await writeFile(output, 'existing verified bundle');
    await assert.rejects(generateSbomBundle(options(output), { run: fakeRun([]) }), /Output already exists/);
    assert.equal(await readFile(output, 'utf8'), 'existing verified bundle');
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('rejects a local image without the exact ECR digest before Trivy runs', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'sentinel-bundle-test-'));
  try {
    const calls = [];
    const output = join(directory, 'bundle.json');
    await assert.rejects(generateSbomBundle(options(output), {
      run: fakeRun(calls, { inspect: dockerInspect([]) }),
    }), /not associated/);
    assert.equal(calls.some(({ command }) => command === 'trivy'), false);
    assert.deepEqual(await readdir(directory), []);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('rejects inconsistent CycloneDX provenance and does not leave an output file', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'sentinel-bundle-test-'));
  try {
    const output = join(directory, 'bundle.json');
    await assert.rejects(generateSbomBundle(options(output), {
      run: fakeRun([], { document: sbom(`wrong.example/service@${DIGEST}`) }),
    }), /SBOM repository digest/);
    assert.deepEqual(await readdir(directory), []);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('rejects an oversized Trivy SBOM before creating a bundle', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'sentinel-bundle-test-'));
  try {
    const output = join(directory, 'bundle.json');
    const document = sbom();
    document.components.push({ name: 'x'.repeat(16 * 1024 * 1024) });
    await assert.rejects(generateSbomBundle(options(output), {
      run: fakeRun([], { document }),
    }), /16 MiB bundle limit/);
    assert.deepEqual(await readdir(directory), []);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
