import assert from 'node:assert/strict';
import { test } from 'node:test';
import { access, chmod, mkdtemp, mkdir, readFile, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EventEmitter, once } from 'node:events';
import { AwsCliService } from '../src/aws-cli.js';
import { TrivyScanService, normalizeTrivyReport, validateInspectorSbom, validatePlatform } from '../src/trivy.js';
import { createAppServer } from '../server.js';

const digest = `sha256:${'a'.repeat(64)}`;
const account = '123456789012';
const imageRef = `${account}.dkr.ecr.us-east-1.amazonaws.com/team/api@${digest}`;
const validCredentials = {
  Version: 1, AccessKeyId: `ASIA${'A'.repeat(16)}`,
  SecretAccessKey: 'this-is-a-test-secret-key-1234567890', SessionToken: 'test-session-token',
};

function fakeRunner(responses) {
  const calls = [];
  return {
    calls,
    run: async (command, args, options) => {
      calls.push({ command, args, options });
      const key = args.slice(0, 2).join(' ');
      const response = responses[key];
      if (response instanceof Error) throw response;
      if (response === undefined && key === 'configure get') return { stdout: '', stderr: '' };
      if (response === undefined) throw new Error(`Unexpected command: ${key}`);
      return { stdout: typeof response === 'string' ? response : JSON.stringify(response), stderr: '' };
    },
  };
}

test('AWS inventory uses validated profiles, fixed arguments, and no ECR scanner calls', async () => {
  const fake = fakeRunner({
    'configure list-profiles': 'default\nengineering\n',
    'sts get-caller-identity': { Account: account, Arn: 'arn:aws:sts::123456789012:assumed-role/scan/operator' },
    'ecr describe-repositories': {
      repositories: [{ repositoryName: 'team/api', registryId: account, repositoryUri: `${account}.dkr.ecr.us-east-1.amazonaws.com/team/api` }],
      NextToken: 'next-page',
    },
    'ecr describe-images': { imageDetails: [{ imageDigest: digest, imageStatus: 'ACTIVE' }] },
  });
  const aws = new AwsCliService({ run: fake.run });
  assert.equal((await aws.identity('engineering', 'us-east-1')).account, account);
  assert.equal((await aws.repositories('engineering', 'us-east-1')).nextToken, 'next-page');
  assert.equal((await aws.image('engineering', 'us-east-1', 'team/api', digest)).imageDigest, digest);
  const calls = fake.calls.filter((item) => item.args[0] === 'ecr');
  assert.deepEqual(calls.map((item) => item.args[1]), ['describe-repositories', 'describe-images']);
  assert.ok(calls.every((item) => item.options.shell === false));
  assert.ok(calls.every((item) => item.options.env.AWS_IGNORE_CONFIGURED_ENDPOINT_URLS === 'true'));
  await assert.rejects(() => aws.images('engineering', 'us-east-1', '../secret'), { code: 'INVALID_INPUT' });
  await assert.rejects(() => aws.images('unknown', 'us-east-1', 'team/api'), { code: 'UNKNOWN_PROFILE' });
});

test('blocks CLI history before AWS calls, preserves MFA method and maps MFA errors safely', async () => {
  const history = fakeRunner({ 'configure list-profiles': 'role\n', 'configure get': 'enabled\n' });
  await assert.rejects(() => new AwsCliService({ run: history.run }).identity('role', 'us-east-1'), { code: 'CLI_HISTORY_ENABLED' });
  assert.equal(history.calls.some((item) => item.args[0] === 'sts'), false);

  const settings = { mfa_serial: 'arn:aws:iam::123456789012:mfa/operator', role_arn: 'arn:aws:iam::123456789012:role/scan' };
  const run = async (_cmd, args) => {
    if (args[1] === 'list-profiles') return { stdout: 'role\n' };
    if (args[1] === 'get') return { stdout: settings[args[2]] ?? '' };
    throw new Error('unexpected');
  };
  assert.equal(await new AwsCliService({ run }).authMethod('role'), 'role-mfa');
  const error = new Error('Command failed');
  error.stderr = 'Enter MFA code for arn:aws:iam::123456789012:mfa/operator: EOFError';
  const fake = fakeRunner({ 'configure list-profiles': 'role\n', 'sts get-caller-identity': error });
  await assert.rejects(() => new AwsCliService({ run: fake.run }).identity('role', 'us-east-1'),
    (mapped) => mapped.code === 'AWS_MFA_REQUIRED' && !mapped.message.includes('123456789012'));
});

test('AWS CLI exports short-lived role credentials without exposing them through the API', async () => {
  const fake = fakeRunner({
    'configure list-profiles': 'role\n',
    'configure export-credentials': validCredentials,
    'sts get-caller-identity': { Account: account },
  });
  const aws = new AwsCliService({ run: fake.run });
  const credentials = await aws.exportCredentials('role', 'us-east-1');
  assert.equal(credentials.sessionToken, 'test-session-token');
  assert.equal(await aws.identityForCredentials(credentials, 'us-east-1'), account);
  const exportCall = fake.calls.find((item) => item.args[1] === 'export-credentials');
  assert.ok(exportCall.args.includes('--format=process'));
  assert.equal(exportCall.options.maxBuffer, 8192);
  const stsCall = fake.calls.at(-1);
  assert.equal(stsCall.options.env.AWS_ACCESS_KEY_ID, validCredentials.AccessKeyId);
  assert.equal(stsCall.options.env.AWS_CONFIG_FILE, '/dev/null');
});

test('in-app MFA resolves the selected role and reuses only its in-memory session for AWS operations', async () => {
  const serial = 'arn:aws:iam::123456789012:mfa/operator';
  const roleArn = 'arn:aws:iam::123456789012:role/scan';
  const settings = {
    role: { role_arn: roleArn, mfa_serial: serial, source_profile: 'base', role_session_name: 'sentinel-test' },
    base: {},
  };
  const calls = [];
  let stamp = 'unchanged';
  let factoryOptions;
  let suppliedCode;
  const runner = async (command, args, options) => {
    calls.push({ command, args, options });
    if (args[0] === 'configure' && args[1] === 'list-profiles') return { stdout: 'role\nbase\n' };
    if (args[0] === 'configure' && args[1] === 'get') {
      const profile = args.find((part) => part.startsWith('--profile='))?.slice(10);
      return { stdout: settings[profile]?.[args[2]] ?? '' };
    }
    if (args[0] === 'sts' && args[1] === 'get-caller-identity') {
      return { stdout: JSON.stringify({ Account: account, Arn: `arn:aws:sts::${account}:assumed-role/scan/sentinel-test` }) };
    }
    if (args[0] === 'ecr' && args[1] === 'describe-repositories') {
      return { stdout: JSON.stringify({ repositories: [] }) };
    }
    throw new Error(`Unexpected command: ${args.join(' ')}`);
  };
  const aws = new AwsCliService({ run: runner, configStampProvider: async () => stamp,
    credentialProviderFactory: (options) => {
      factoryOptions = options;
      return async () => {
        suppliedCode = await options.mfaCodeProvider(serial);
        return {
          accessKeyId: validCredentials.AccessKeyId,
          secretAccessKey: validCredentials.SecretAccessKey,
          sessionToken: validCredentials.SessionToken,
          expiration: new Date(Date.now() + 3_600_000),
        };
      };
    },
  });
  const authenticated = await aws.authenticateRoleMfa('role', 'us-east-1', '123456');
  assert.equal(authenticated.account, account);
  assert.equal(authenticated.authMethod, 'role-mfa');
  assert.equal(Object.hasOwn(authenticated, 'credentials'), false);
  assert.equal(suppliedCode, '123456');
  assert.equal(factoryOptions.profile, 'role');
  assert.equal(factoryOptions.clientConfig.endpoint, 'https://sts.us-east-1.amazonaws.com');
  assert.equal((await aws.identity('role', 'us-east-1')).account, account);
  await aws.repositories('role', 'us-east-1');
  assert.equal((await aws.exportCredentials('role', 'us-east-1')).sessionToken, validCredentials.SessionToken);
  const stsAndEcr = calls.filter((call) => ['sts', 'ecr'].includes(call.args[0]));
  assert.equal(stsAndEcr.length, 3);
  assert.ok(stsAndEcr.every((call) => !call.args.some((arg) => arg.includes('123456') || arg.startsWith('--profile='))));
  assert.ok(stsAndEcr.every((call) => call.options.env.AWS_ACCESS_KEY_ID === validCredentials.AccessKeyId));
  assert.ok(stsAndEcr.every((call) => call.options.env.AWS_CONFIG_FILE === '/dev/null'));
  assert.ok(calls.every((call) => !call.args.some((arg) => arg.includes('123456'))));
  assert.ok(calls.every((call) => Object.values(call.options.env).every((value) => value !== '123456')));
  assert.equal(calls.some((call) => call.args[1] === 'export-credentials'), false);
  stamp = 'changed';
  await aws.identity('role', 'us-east-1');
  const afterChange = calls.at(-1);
  assert.ok(afterChange.args.includes('--profile=role'));
  assert.equal(afterChange.options.env.AWS_ACCESS_KEY_ID, undefined);
});

test('in-app MFA rejects unsupported role chains and extra MFA prompts', async () => {
  const serial = 'arn:aws:iam::123456789012:mfa/operator';
  const settings = {
    role: { role_arn: 'arn:aws:iam::123456789012:role/scan', mfa_serial: serial, source_profile: 'base' },
    base: { mfa_serial: 'arn:aws:iam::123456789012:mfa/other' },
  };
  const run = async (_command, args) => {
    if (args[1] === 'list-profiles') return { stdout: 'role\nbase\n' };
    if (args[1] === 'get') {
      const profile = args.find((part) => part.startsWith('--profile='))?.slice(10);
      return { stdout: settings[profile]?.[args[2]] ?? '' };
    }
    throw new Error('unexpected AWS operation');
  };
  let providerCalls = 0;
  const aws = new AwsCliService({ run, configStampProvider: async () => 'unchanged',
    credentialProviderFactory: (options) => {
      providerCalls += 1;
      return async () => {
        await options.mfaCodeProvider(serial);
        await options.mfaCodeProvider('arn:aws:iam::123456789012:mfa/other');
      };
    },
  });
  await assert.rejects(() => aws.authenticateRoleMfa('role', 'us-east-1', '123456'), { code: 'AWS_MFA_UNSUPPORTED' });
  assert.equal(providerCalls, 0);
  settings.base.mfa_serial = '';
  await assert.rejects(() => aws.authenticateRoleMfa('role', 'us-east-1', '123456'), { code: 'AWS_MFA_UNSUPPORTED' });
  assert.equal(providerCalls, 1);
  await assert.rejects(() => aws.authenticateRoleMfa('missing', 'us-east-1', '123456'), { code: 'UNKNOWN_PROFILE' });
  assert.equal(aws.mfaAttempts.has('missing'), false);
  await assert.rejects(() => aws.authenticateRoleMfa('role', 'us-east-1', 'not-a-code'), { code: 'INVALID_MFA_CODE' });
});

test('only one in-app MFA request can run across all profiles', async () => {
  const serial = 'arn:aws:iam::123456789012:mfa/operator';
  const settings = {
    role1: { role_arn: 'arn:aws:iam::123456789012:role/scan', mfa_serial: serial, source_profile: 'base' },
    role2: { role_arn: 'arn:aws:iam::123456789012:role/scan', mfa_serial: serial, source_profile: 'base' },
    base: {},
  };
  const run = async (_command, args) => {
    if (args[1] === 'list-profiles') return { stdout: 'role1\nrole2\nbase\n' };
    if (args[1] === 'get') {
      const profile = args.find((part) => part.startsWith('--profile='))?.slice(10);
      return { stdout: settings[profile]?.[args[2]] ?? '' };
    }
    if (args[0] === 'sts' && args[1] === 'get-caller-identity') {
      return { stdout: JSON.stringify({ Account: account, Arn: `arn:aws:sts::${account}:assumed-role/scan/test` }) };
    }
    throw new Error('unexpected AWS operation');
  };
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  let entered;
  const enteredPromise = new Promise((resolve) => { entered = resolve; });
  let providerCalls = 0;
  const aws = new AwsCliService({ run, configStampProvider: async () => 'unchanged',
    credentialProviderFactory: (options) => {
      providerCalls += 1;
      return async () => {
        entered();
        await gate;
        assert.equal(await options.mfaCodeProvider(serial), '123456');
        return {
          accessKeyId: validCredentials.AccessKeyId, secretAccessKey: validCredentials.SecretAccessKey,
          sessionToken: validCredentials.SessionToken, expiration: new Date(Date.now() + 3_600_000),
        };
      };
    },
  });
  const first = aws.authenticateRoleMfa('role1', 'us-east-1', '123456');
  await enteredPromise;
  await assert.rejects(() => aws.authenticateRoleMfa('role2', 'us-east-1', '654321'), { code: 'AWS_MFA_BUSY' });
  assert.equal(aws.mfaAttempts.has('role2'), false);
  assert.equal(providerCalls, 1);
  release();
  assert.equal((await first).account, account);
});

function trivyReport({ os = 'linux', architecture = 'amd64' } = {}) {
  return {
    SchemaVersion: 2,
    ArtifactName: imageRef,
    ArtifactType: 'container_image',
    Metadata: { ImageConfig: { os, architecture } },
    Results: [{
      Target: 'alpine:3.20 (alpine 3.20)',
      Class: 'os-pkgs',
      Type: 'alpine',
      Vulnerabilities: [{
        VulnerabilityID: 'CVE-2026-1234', PkgName: 'openssl', InstalledVersion: '3.0',
        FixedVersion: '3.1', Severity: 'HIGH', Title: 'OpenSSL vulnerability',
        PrimaryURL: 'https://example.org/advisory', CVSS: { nvd: { V3Score: 8.1 } },
      }],
    }],
  };
}

function context() {
  return {
    profile: 'role', account, region: 'us-east-1', repository: 'team/api', digest,
    platform: 'linux/amd64', imageRef, scannerVersion: '0.76.0',
    dbUpdatedAt: '2026-10-21T12:00:00.000Z',
  };
}

function sbomBundle(overrides = {}) {
  return {
    schemaVersion: 1,
    image: { account, region: 'us-east-1', repository: 'team/api', digest, platform: 'linux/amd64' },
    generatedAt: '2026-10-21T12:00:00Z',
    producer: { name: 'ECR Sentinel pipeline helper', trivyVersion: '0.76.0' },
    sbom: {
      bomFormat: 'CycloneDX', specVersion: '1.6', version: 1,
      components: [{ type: 'library', name: 'openssl', version: '3.0.0' }],
    },
    ...overrides,
  };
}

function inspectorSbom(overrides = {}) {
  return {
    bomFormat: 'CycloneDX', specVersion: '1.4', version: 1,
    metadata: { timestamp: '2026-10-21T12:00:00Z', properties: [
      { name: 'imageId', value: digest },
      { name: 'architecture', value: 'amd64' },
      { name: 'accountId', value: account },
      { name: 'resourceType', value: 'AWS_ECR_CONTAINER_IMAGE' },
    ] },
    components: [{ type: 'library', name: 'openssl', version: '3.0.0' }],
    ...overrides,
  };
}

test('Trivy report normalizes CVEs and verifies selected image and architecture', () => {
  const report = normalizeTrivyReport(trivyReport(), context());
  assert.equal(report.findings[0].id, 'CVE-2026-1234');
  assert.equal(report.findings[0].packageName, 'openssl');
  assert.equal(report.findings[0].score, 8.1);
  assert.equal(report.counts.HIGH, 1);
  assert.equal(report.counts.CRITICAL, 0);
  assert.equal(report.platform, 'linux/amd64');
  assert.equal(report.account, account);
  assert.deepEqual(report.coverage.packageTypes, ['os']);
  assert.equal(report.coverage.limitedCoverage, true);
  const empty = normalizeTrivyReport({ ...trivyReport(), Results: [] }, context());
  assert.equal(empty.coverage.noPackagesDetected, true);
  assert.deepEqual(empty.coverage.packageTypes, []);
  assert.throws(() => normalizeTrivyReport(trivyReport({ architecture: 'arm64' }), context()), { code: 'PLATFORM_MISMATCH' });
  assert.throws(() => normalizeTrivyReport({ ...trivyReport(), ArtifactName: 'evil.example/image' }, context()), { code: 'TRIVY_BAD_REPORT' });
  assert.throws(() => validatePlatform('../linux/amd64'), { code: 'INVALID_INPUT' });
});

async function waitForTerminal(scans, id) {
  for (let index = 0; index < 100; index += 1) {
    const job = scans.get(id);
    if (['COMPLETE', 'FAILED', 'CANCELED'].includes(job.status)) return job;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error('scan did not complete');
}

async function scanFixture(run) {
  const directory = await mkdtemp(join(tmpdir(), 'ecr-sentinel-test-'));
  const cacheRoot = join(directory, 'cache-root');
  await mkdir(join(cacheRoot, 'cache', 'db'), { recursive: true, mode: 0o700 });
  await writeFile(join(cacheRoot, 'cache', 'db', 'metadata.json'), JSON.stringify({ UpdatedAt: '2026-10-21T12:00:00Z' }));
  const aws = {
    identity: async () => ({ account }),
    repository: async () => ({ repositoryName: 'team/api', repositoryUri: `${account}.dkr.ecr.us-east-1.amazonaws.com/team/api`, registryId: account }),
    image: async () => ({ imageDigest: digest, imageStatus: 'ACTIVE' }),
    exportCredentials: async () => ({ accessKeyId: validCredentials.AccessKeyId, secretAccessKey: validCredentials.SecretAccessKey, sessionToken: validCredentials.SessionToken }),
    identityForCredentials: async () => account,
  };
  return { directory, aws, scans: new TrivyScanService(aws, { run, cacheRoot,
    settingsRoot: join(directory, 'settings') }) };
}

test('scan updates DB without credentials, scans exact digest with role credentials, and remembers report', async () => {
  const calls = [];
  const fixture = await scanFixture(async (_cmd, args, options) => {
    calls.push({ args, options });
    if (args[0] === 'version') return { stdout: '{"Version":"0.76.0"}' };
    if (args.includes('--download-db-only')) return { stdout: '' };
    if (args.includes('--format=json')) return { stdout: JSON.stringify(trivyReport()) };
    throw new Error('unexpected trivy invocation');
  });
  try {
    const target = { profile: 'role', region: 'us-east-1', repository: 'team/api', digest, platform: 'linux/amd64' };
    const started = await fixture.scans.start(target);
    const completed = await waitForTerminal(fixture.scans, started.id);
    assert.equal(completed.status, 'COMPLETE');
    assert.equal(completed.report.findings[0].id, 'CVE-2026-1234');
    assert.equal(completed.report.dbUpdatedAt, '2026-10-21T12:00:00.000Z');
    const dbCall = calls.find((item) => item.args.includes('--download-db-only'));
    assert.equal(dbCall.options.env.AWS_ACCESS_KEY_ID, undefined);
    const scanCall = calls.find((item) => item.args.includes('--image-src=remote'));
    assert.equal(scanCall.args.at(-1), imageRef);
    assert.ok(scanCall.args.includes('--skip-db-update'));
    assert.ok(scanCall.args.includes('--skip-java-db-update'));
    assert.ok(scanCall.args.includes('--offline-scan'));
    assert.equal(scanCall.options.env.AWS_ACCESS_KEY_ID, validCredentials.AccessKeyId);
    assert.equal(scanCall.options.env.TRIVY_USERNAME, undefined);
    assert.equal(scanCall.options.env.AWS_PROFILE, undefined);
    const latest = await fixture.scans.latest(target);
    assert.equal(latest.report.digest, digest);
    assert.equal(latest.job.status, 'COMPLETE');
    assert.ok(['PENDING', 'IN_PROGRESS'].includes((await fixture.scans.start(target)).status));
  } finally {
    await fixture.scans.dispose();
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test('SBOM import scans listed packages without ECR pull or AWS credentials and removes the temporary file', async () => {
  const calls = [];
  let sbomPath;
  const fixture = await scanFixture(async (_cmd, args, options) => {
    calls.push({ args, options });
    if (args[0] === 'version') return { stdout: '{"Version":"0.76.0"}' };
    if (args.includes('--download-db-only')) return { stdout: '' };
    if (args[0] === 'sbom') {
      sbomPath = args.at(-1);
      assert.equal(JSON.parse(await readFile(sbomPath, 'utf8')).bomFormat, 'CycloneDX');
      return { stdout: JSON.stringify({
        SchemaVersion: 2, ArtifactName: sbomPath, ArtifactType: 'cyclonedx',
        Results: trivyReport().Results,
      }) };
    }
    throw new Error('unexpected trivy invocation');
  });
  try {
    const target = { profile: 'role', region: 'us-east-1', repository: 'team/api', digest, platform: 'linux/amd64' };
    const started = await fixture.scans.startSbom({ ...target, bundle: sbomBundle() });
    const completed = await waitForTerminal(fixture.scans, started.id);
    assert.equal(completed.status, 'COMPLETE');
    assert.equal(completed.mode, 'sbom');
    assert.equal(completed.report.scanMode, 'sbom');
    assert.equal(completed.report.findings[0].id, 'CVE-2026-1234');
    assert.equal(completed.report.provenance.association, 'unverified');
    assert.match(completed.report.provenance.sbomSha256, /^[a-f0-9]{64}$/);
    assert.equal((await fixture.scans.latest(target)).report.scanMode, 'sbom');
    assert.ok(calls.every((call) => call.options.env.AWS_ACCESS_KEY_ID === undefined));
    assert.ok(calls.every((call) => !call.args.includes('--image-src=remote')));
    await assert.rejects(() => access(sbomPath), { code: 'ENOENT' });
  } finally {
    await fixture.scans.dispose();
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test('SBOM import rejects a mismatched target before invoking Trivy', async () => {
  let calls = 0;
  const fixture = await scanFixture(async () => { calls += 1; return { stdout: '' }; });
  try {
    const target = { profile: 'role', region: 'us-east-1', repository: 'team/api', digest, platform: 'linux/amd64' };
    await assert.rejects(() => fixture.scans.startSbom({ ...target, bundle: sbomBundle({
      image: { ...sbomBundle().image, digest: `sha256:${'b'.repeat(64)}` },
    }) }), { code: 'SBOM_TARGET_MISMATCH' });
    await assert.rejects(() => fixture.scans.startSbom({ ...target, bundle: sbomBundle({
      sbom: { ...sbomBundle().sbom, metadata: { component: { properties: [{
        name: 'aquasecurity:trivy:RepoDigest', value: `evil.example/team/api@${digest}`,
      }] } } },
    }) }), { code: 'SBOM_TARGET_MISMATCH' });
    assert.equal(calls, 0);
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test('Inspector SBOM requires one exact image, account, resource type, and architecture', () => {
  const target = { profile: 'role', region: 'us-east-1', repository: 'team/api', digest, platform: 'linux/amd64' };
  const valid = validateInspectorSbom(inspectorSbom(), target, account);
  assert.equal(valid.format, 'cyclonedx');
  assert.equal(valid.source, 'amazon-inspector');
  assert.equal(valid.association, 'metadata-verified');
  const replace = (name, value) => inspectorSbom({
    metadata: { ...inspectorSbom().metadata,
      properties: inspectorSbom().metadata.properties.map((item) => item.name === name ? { name, value } : item) },
  });
  for (const [name, value] of [
    ['imageId', `sha256:${'b'.repeat(64)}`], ['accountId', '999999999999'],
    ['resourceType', 'AWS_EC2_INSTANCE'], ['architecture', 'arm64'],
  ]) {
    assert.throws(() => validateInspectorSbom(replace(name, value), target, account),
      { code: 'INSPECTOR_SBOM_TARGET_MISMATCH' });
  }
  const duplicate = inspectorSbom({ metadata: { ...inspectorSbom().metadata,
    properties: [...inspectorSbom().metadata.properties, { name: 'imageId', value: digest }] } });
  assert.throws(() => validateInspectorSbom(duplicate, target, account), { code: 'INSPECTOR_SBOM_UNBOUND' });
  assert.throws(() => validateInspectorSbom(inspectorSbom(), { ...target, platform: 'linux/amd64/v3' }, account),
    { code: 'INSPECTOR_SBOM_PLATFORM_UNVERIFIED' });
  assert.throws(() => validateInspectorSbom([inspectorSbom(), inspectorSbom()], target, account),
    { code: 'INSPECTOR_SBOM_INVALID' });
});

test('AWS Inspector export uses exact filters and bounded single-object S3 retrieval', async () => {
  const reportId = '11111111-2222-3333-4444-555555555555';
  const prefix = 'team/ecr-sentinel/test-job/';
  const destination = { bucketName: 'security-sboms', keyPrefix: prefix,
    kmsKeyArn: `arn:aws:kms:us-east-1:${account}:key/12345678-1234-1234-1234-123456789abc` };
  const etag = `"${'a'.repeat(32)}"`;
  const fake = fakeRunner({
    'configure list-profiles': 'role\n',
    'inspector2 create-sbom-export': { reportId },
    'inspector2 get-sbom-export': { reportId, status: 'SUCCEEDED', format: 'CYCLONEDX_1_4', s3Destination: destination },
    's3api list-objects-v2': { Contents: [{ Key: `${prefix}${reportId}.json`, Size: 144, ETag: etag }] },
    's3api get-object': { ContentLength: 144, ETag: etag },
  });
  const aws = new AwsCliService({ run: fake.run });
  const target = { profile: 'role', region: 'us-east-1', repository: 'team/api', digest, platform: 'linux/amd64' };
  const created = await aws.createInspectorSbomExport(target, account, destination);
  assert.equal(created.reportId, reportId);
  const createCall = fake.calls.find((item) => item.args[1] === 'create-sbom-export');
  const filters = JSON.parse(createCall.args.find((arg) => arg.startsWith('--resource-filter-criteria=')).split('=', 2)[1]);
  const sentDestination = JSON.parse(createCall.args.find((arg) => arg.startsWith('--s3-destination=')).slice('--s3-destination='.length));
  assert.deepEqual(sentDestination, destination);
  assert.deepEqual(filters, {
    accountId: [{ comparison: 'EQUALS', value: account }],
    resourceId: [{ comparison: 'EQUALS', value: `arn:aws:ecr:us-east-1:${account}:repository/team/api/${digest}` }],
    resourceType: [{ comparison: 'EQUALS', value: 'AWS_ECR_CONTAINER_IMAGE' }],
  });
  assert.equal(createCall.options.shell, false);
  const status = await aws.getInspectorSbomExport(target, reportId);
  assert.equal(status.status, 'SUCCEEDED');
  assert.equal(status.s3Destination.keyPrefix, sentDestination.keyPrefix);
  const object = await aws.listInspectorSbomObject(target, destination);
  await aws.downloadInspectorSbomObject(target, destination, object, '/tmp/inspector-test.json');
  const listCall = fake.calls.find((item) => item.args[1] === 'list-objects-v2');
  assert.ok(listCall.args.includes('--max-keys=2'));
  assert.ok(listCall.args.includes('--no-paginate'));
  const getCall = fake.calls.find((item) => item.args[1] === 'get-object');
  assert.ok(getCall.args.includes('--range=bytes=0-16777216'));
  assert.ok(getCall.args.includes(`--if-match=${etag}`));
  assert.equal(getCall.options.maxBuffer, 64 * 1024);
  assert.equal(fake.calls.some((item) => ['batch-get-image', 'get-download-url-for-layer'].includes(item.args[1])), false);
  await assert.rejects(() => aws.createInspectorSbomExport(target, account,
    { ...destination, keyPrefix: '../other' }), { code: 'INVALID_INPUT' });
  fake.run = fakeRunner({
    'configure list-profiles': 'role\n',
    's3api list-objects-v2': { Contents: [
      { Key: `${prefix}one.json`, Size: 1, ETag: etag },
      { Key: `${prefix}two.json`, Size: 1, ETag: etag },
    ] },
  }).run;
  await assert.rejects(() => new AwsCliService({ run: fake.run }).listInspectorSbomObject(target, destination),
    { code: 'INSPECTOR_EXPORT_AMBIGUOUS' });
});

test('Inspector permission failures name the required action without exposing AWS stderr', async () => {
  const target = { profile: 'role', region: 'us-east-1', repository: 'team/api', digest, platform: 'linux/amd64' };
  const reportId = '11111111-2222-3333-4444-555555555555';
  const destination = { bucketName: 'security-sboms', keyPrefix: 'team/ecr-sentinel/test-job/',
    kmsKeyArn: `arn:aws:kms:us-east-1:${account}:key/12345678-1234-1234-1234-123456789abc` };
  const object = { key: `${destination.keyPrefix}${reportId}.json`, etag: `"${'a'.repeat(32)}"`, size: 144 };
  const cases = [
    ['inspector2 create-sbom-export', (aws) => aws.createInspectorSbomExport(target, account, destination),
      'INSPECTOR_CREATE_DENIED', 'inspector2:CreateSbomExport'],
    ['inspector2 get-sbom-export', (aws) => aws.getInspectorSbomExport(target, reportId),
      'INSPECTOR_STATUS_DENIED', 'inspector2:GetSbomExport'],
    ['s3api list-objects-v2', (aws) => aws.listInspectorSbomObject(target, destination),
      'INSPECTOR_S3_LIST_DENIED', 's3:ListBucket'],
    ['s3api get-object', (aws) => aws.downloadInspectorSbomObject(target, destination, object, '/tmp/inspector-test.json'),
      'INSPECTOR_S3_READ_DENIED', 'kms:Decrypt'],
  ];
  for (const [operation, invoke, code, action] of cases) {
    const denied = new Error('AWS command failed');
    denied.stderr = 'AccessDenied: sensitive account context from AWS';
    const fake = fakeRunner({ 'configure list-profiles': 'role\n', [operation]: denied });
    const aws = new AwsCliService({ run: fake.run });
    await assert.rejects(() => invoke(aws), (error) => error.code === code && error.status === 403
      && error.message.includes(action) && !error.message.includes('sensitive account context'));
  }
});

test('Inspector export flows into credential-free Trivy SBOM scan and deletes local export', async () => {
  const calls = [];
  let sbomPath;
  const fixture = await scanFixture(async (_cmd, args, options) => {
    calls.push({ args, options });
    if (args[0] === 'version') return { stdout: '{"Version":"0.76.0"}' };
    if (args.includes('--download-db-only')) return { stdout: '' };
    if (args[0] === 'sbom') {
      sbomPath = args.at(-1);
      return { stdout: JSON.stringify({ SchemaVersion: 2, ArtifactName: sbomPath,
        ArtifactType: 'cyclonedx', Results: trivyReport().Results }) };
    }
    throw new Error('unexpected trivy invocation');
  });
  const target = { profile: 'role', region: 'us-east-1', repository: 'team/api', digest, platform: 'linux/amd64' };
  const document = JSON.stringify(inspectorSbom());
  const destinations = [];
  fixture.aws.createInspectorSbomExport = async (_target, _account, destination) => {
    destinations.push(destination);
    return { reportId: '11111111-2222-3333-4444-555555555555',
      resourceId: `arn:aws:ecr:us-east-1:${account}:repository/team/api/${digest}` };
  };
  fixture.aws.getInspectorSbomExport = async () => ({
    status: 'SUCCEEDED', format: 'CYCLONEDX_1_4', s3Destination: destinations[0],
    filterCriteria: {
      accountId: [{ comparison: 'EQUALS', value: account }],
      resourceId: [{ comparison: 'EQUALS', value: `arn:aws:ecr:us-east-1:${account}:repository/team/api/${digest}` }],
      resourceType: [{ comparison: 'EQUALS', value: 'AWS_ECR_CONTAINER_IMAGE' }],
    },
  });
  fixture.aws.listInspectorSbomObject = async () => ({ key: `${destinations[0].keyPrefix}report.json`,
    etag: `"${'a'.repeat(32)}"`, size: Buffer.byteLength(document) });
  let exportedPath;
  fixture.aws.downloadInspectorSbomObject = async (_target, _destination, _object, path) => {
    exportedPath = path;
    await writeFile(path, document);
  };
  try {
    await fixture.scans.saveInspectorDestination({ profile: target.profile, region: target.region,
      destination: { bucketName: 'security-sboms', keyPrefix: 'team/',
        kmsKeyArn: `arn:aws:kms:us-east-1:${account}:key/12345678-1234-1234-1234-123456789abc` } });
    const started = await fixture.scans.startInspector(target);
    const completed = await waitForTerminal(fixture.scans, started.id);
    assert.equal(completed.status, 'COMPLETE');
    assert.equal(completed.mode, 'inspector-sbom');
    assert.equal(completed.report.scanMode, 'sbom');
    assert.equal(completed.report.provenance.source, 'amazon-inspector');
    assert.equal(completed.report.provenance.association, 'metadata-verified');
    assert.equal(completed.report.findings[0].id, 'CVE-2026-1234');
    assert.match(destinations[0].keyPrefix, /^team\/ecr-sentinel\/[a-f0-9-]{36}\/$/);
    assert.ok(calls.every((call) => call.options.env.AWS_ACCESS_KEY_ID === undefined));
    assert.ok(calls.every((call) => !call.args.includes('--image-src=remote')));
    await assert.rejects(() => access(exportedPath), { code: 'ENOENT' });
    await assert.rejects(() => access(sbomPath), { code: 'ENOENT' });
    await assert.rejects(() => fixture.scans.saveInspectorDestination({ ...target,
      destination: { bucketName: 'security-sboms', keyPrefix: 'a'.repeat(401),
        kmsKeyArn: `arn:aws:kms:us-east-1:${account}:key/12345678-1234-1234-1234-123456789abc` } }),
    { code: 'INVALID_INPUT' });
  } finally {
    await fixture.scans.dispose();
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test('Inspector export without exact returned filters is rejected before S3 access', async () => {
  const fixture = await scanFixture(async (_cmd, args) => {
    if (args[0] === 'version') return { stdout: '{"Version":"0.76.0"}' };
    throw new Error('unexpected scan invocation');
  });
  let destination;
  let listed = false;
  fixture.aws.createInspectorSbomExport = async (_target, _account, selected) => {
    destination = selected;
    return { reportId: '11111111-2222-3333-4444-555555555555',
      resourceId: `arn:aws:ecr:us-east-1:${account}:repository/team/api/${digest}` };
  };
  fixture.aws.getInspectorSbomExport = async () => ({
    status: 'SUCCEEDED', format: 'CYCLONEDX_1_4', s3Destination: destination,
  });
  fixture.aws.listInspectorSbomObject = async () => { listed = true; throw new Error('must not list'); };
  try {
    await fixture.scans.saveInspectorDestination({ profile: 'role', region: 'us-east-1', destination: {
      bucketName: 'security-sboms',
      kmsKeyArn: `arn:aws:kms:us-east-1:${account}:key/12345678-1234-1234-1234-123456789abc` } });
    const started = await fixture.scans.startInspector({ profile: 'role', region: 'us-east-1',
      repository: 'team/api', digest, platform: 'linux/amd64' });
    const completed = await waitForTerminal(fixture.scans, started.id);
    assert.equal(completed.status, 'FAILED');
    assert.equal(completed.error.code, 'INSPECTOR_EXPORT_MISMATCH');
    assert.equal(listed, false);
  } finally {
    await fixture.scans.dispose();
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test('Inspector destination is private, durable, and scoped to the verified account, Region, and profile', async () => {
  const fixture = await scanFixture(async () => { throw new Error('Scanner must not run'); });
  const target = { profile: 'role', region: 'us-east-1', repository: 'team/api', digest, platform: 'linux/amd64' };
  const destination = { bucketName: 'security-sboms', keyPrefix: 'team/',
    kmsKeyArn: `arn:aws:kms:us-east-1:${account}:key/12345678-1234-1234-1234-123456789abc` };
  let activeAccount = account;
  fixture.aws.identity = async () => ({ account: activeAccount });
  try {
    assert.deepEqual(await fixture.scans.inspectorDestination(target), { configured: false, destination: null });
    await assert.rejects(() => fixture.scans.startInspector(target), { code: 'INSPECTOR_DESTINATION_NOT_CONFIGURED', status: 409 });
    assert.deepEqual(await fixture.scans.saveInspectorDestination({ ...target, destination }), {
      configured: true, destination: { ...destination, keyPrefix: 'team' },
    });
    const root = join(fixture.directory, 'settings');
    assert.equal((await stat(root)).mode & 0o077, 0);
    assert.equal((await stat(join(root, 'inspector-destinations.json'))).mode & 0o077, 0);
    const reopened = new TrivyScanService(fixture.aws, { settingsRoot: root });
    assert.equal((await reopened.inspectorDestination(target)).destination.bucketName, destination.bucketName);
    const settingsPath = join(root, 'inspector-destinations.json');
    const savedSettings = await readFile(settingsPath, 'utf8');
    const editedSettings = JSON.parse(savedSettings);
    Object.values(editedSettings.destinations)[0].destination.keyPrefix = 'a'.repeat(401);
    await writeFile(settingsPath, JSON.stringify(editedSettings));
    await assert.rejects(() => reopened.inspectorDestination(target), { code: 'INSPECTOR_SETTINGS_INVALID' });
    await writeFile(settingsPath, savedSettings);
    assert.deepEqual(await reopened.inspectorDestination({ ...target, profile: 'other-role' }),
      { configured: false, destination: null });
    assert.deepEqual(await reopened.inspectorDestination({ ...target, region: 'us-west-2' }),
      { configured: false, destination: null });
    activeAccount = '210987654321';
    assert.deepEqual(await reopened.inspectorDestination(target), { configured: false, destination: null });
    activeAccount = account;
    await assert.rejects(() => reopened.startInspector({ ...target, ...destination }), { code: 'INVALID_INPUT' });
    assert.deepEqual(await reopened.deleteInspectorDestination(target), { configured: false, destination: null });
    assert.deepEqual(await reopened.inspectorDestination(target), { configured: false, destination: null });
    await chmod(settingsPath, 0o644);
    await assert.rejects(() => reopened.inspectorDestination(target), { code: 'INSPECTOR_SETTINGS_UNSAFE' });
    await chmod(settingsPath, 0o600);
    await writeFile(settingsPath, '{broken');
    await assert.rejects(() => reopened.inspectorDestination(target), { code: 'INSPECTOR_SETTINGS_INVALID' });
    await rm(settingsPath);
    const elsewhere = join(fixture.directory, 'elsewhere.json');
    await writeFile(elsewhere, '{}', { mode: 0o600 });
    await symlink(elsewhere, settingsPath);
    await assert.rejects(() => reopened.inspectorDestination(target), { code: 'INSPECTOR_SETTINGS_UNSAFE' });
  } finally {
    await fixture.scans.dispose();
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test('Java DB is downloaded without AWS credentials only when Java is detected', async () => {
  const calls = [];
  let scanAttempts = 0;
  const fixture = await scanFixture(async (_cmd, args, options) => {
    calls.push({ args, options });
    if (args[0] === 'version') return { stdout: '{"Version":"0.76.0"}' };
    if (args.includes('--download-db-only') || args.includes('--download-java-db-only')) return { stdout: '' };
    scanAttempts += 1;
    if (scanAttempts === 1) {
      const error = new Error('Java database missing');
      error.stderr = "Unable to initialize the Java DB: '--skip-java-db-update' cannot be specified on the first run";
      throw error;
    }
    return { stdout: JSON.stringify(trivyReport()) };
  });
  try {
    const started = await fixture.scans.start({ profile: 'role', region: 'us-east-1', repository: 'team/api', digest });
    assert.equal((await waitForTerminal(fixture.scans, started.id)).status, 'COMPLETE');
    assert.equal(scanAttempts, 2);
    const java = calls.find((call) => call.args.includes('--download-java-db-only'));
    assert.ok(java);
    assert.equal(java.options.env.AWS_ACCESS_KEY_ID, undefined);
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test('bounded history does not retain evicted full reports in old job objects', async () => {
  const fixture = await scanFixture(async (_cmd, args) => {
    if (args[0] === 'version') return { stdout: '{"Version":"0.76.0"}' };
    if (args.includes('--download-db-only')) return { stdout: '' };
    return { stdout: JSON.stringify(trivyReport()) };
  });
  try {
    const ids = [];
    for (let index = 0; index < 11; index += 1) {
      const started = await fixture.scans.start({
        profile: `role${index}`, region: 'us-east-1', repository: 'team/api', digest,
      });
      ids.push(started.id);
      assert.equal((await waitForTerminal(fixture.scans, started.id)).status, 'COMPLETE');
    }
    assert.equal(fixture.scans.reports.size, 10);
    assert.equal(fixture.scans.get(ids[0]).report, undefined);
    assert.equal(fixture.scans.get(ids.at(-1)).report.findings.length, 1);
    assert.ok([...fixture.scans.jobs.values()].every((job) => !Object.hasOwn(job, 'report')));
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test('queued and active scans can be canceled without starting the queued image', async () => {
  let scanStarts = 0;
  const fixture = await scanFixture(async (_cmd, args, options) => {
    if (args[0] === 'version') return { stdout: '{"Version":"0.76.0"}' };
    if (args.includes('--download-db-only')) return { stdout: '' };
    scanStarts += 1;
    if (options.signal.aborted) throw Object.assign(new Error('canceled'), { code: 'CANCELED' });
    return new Promise((_resolve, reject) => {
      options.signal.addEventListener('abort', () => reject(Object.assign(new Error('canceled'), { code: 'CANCELED' })), { once: true });
    });
  });
  try {
    const first = await fixture.scans.start({ profile: 'role1', region: 'us-east-1', repository: 'team/api', digest });
    const queued = await fixture.scans.start({ profile: 'role2', region: 'us-east-1', repository: 'team/api', digest });
    assert.equal(fixture.scans.cancel(queued.id).status, 'CANCELED');
    fixture.scans.cancel(first.id);
    assert.equal((await waitForTerminal(fixture.scans, first.id)).status, 'CANCELED');
    assert.equal(scanStarts <= 1, true);
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test('old reports and jobs cannot cross account changes', async () => {
  const fixture = await scanFixture(async (_cmd, args) => {
    if (args[0] === 'version') return { stdout: '{"Version":"0.76.0"}' };
    if (args.includes('--download-db-only')) return { stdout: '' };
    return { stdout: JSON.stringify(trivyReport()) };
  });
  const target = { profile: 'role', region: 'us-east-1', repository: 'team/api', digest, platform: 'linux/amd64' };
  try {
    const started = await fixture.scans.start(target);
    assert.equal((await waitForTerminal(fixture.scans, started.id)).status, 'COMPLETE');
    fixture.aws.identity = async () => ({ account: '999999999999' });
    assert.deepEqual(await fixture.scans.latest(target), { report: null, job: null });
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test('rejects an unexpected ECR registry address before any image pull', async () => {
  const calls = [];
  const fixture = await scanFixture(async (_cmd, args) => {
    calls.push(args);
    return { stdout: '{"Version":"0.76.0"}' };
  });
  fixture.aws.repository = async () => ({
    repositoryName: 'team/api', registryId: account,
    repositoryUri: 'attacker.example/team/api',
  });
  try {
    const started = await fixture.scans.start({
      profile: 'role', region: 'us-east-1', repository: 'team/api', digest,
    });
    const result = await waitForTerminal(fixture.scans, started.id);
    assert.equal(result.status, 'FAILED');
    assert.equal(result.error.code, 'ECR_BAD_REPOSITORY');
    assert.equal(calls.some((args) => args.includes('--image-src=remote')), false);
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test('rejects exported credentials for a different account before any image pull', async () => {
  const calls = [];
  const fixture = await scanFixture(async (_cmd, args) => {
    calls.push(args);
    if (args[0] === 'version') return { stdout: '{"Version":"0.76.0"}' };
    return { stdout: '' };
  });
  fixture.aws.identityForCredentials = async () => '999999999999';
  try {
    const started = await fixture.scans.start({
      profile: 'role', region: 'us-east-1', repository: 'team/api', digest,
    });
    const result = await waitForTerminal(fixture.scans, started.id);
    assert.equal(result.status, 'FAILED');
    assert.equal(result.error.code, 'AWS_ACCOUNT_CHANGED');
    assert.equal(calls.some((args) => args.includes('--image-src=remote')), false);
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test('unsafe and prerelease Trivy versions are rejected before scan', async () => {
  for (const version of ['0.51.1', '0.69.4', '0.71.0', '0.76.0-rc1', 'unknown']) {
    const fixture = await scanFixture(async () => ({ stdout: JSON.stringify({ Version: version }) }));
    try {
      const status = await fixture.scans.status();
      assert.equal(status.available, false, version);
      assert.equal(status.error.code, 'TRIVY_UNSAFE_VERSION', version);
    } finally {
      await rm(fixture.directory, { recursive: true, force: true });
    }
  }
});

test('concurrent scanner status requests share one bounded version check', async () => {
  let versionCalls = 0;
  const fixture = await scanFixture(async (_cmd, args) => {
    assert.equal(args[0], 'version');
    versionCalls += 1;
    await new Promise((resolve) => setTimeout(resolve, 20));
    return { stdout: '{"Version":"0.76.0"}' };
  });
  try {
    const results = await Promise.all(Array.from({ length: 12 }, () => fixture.scans.status()));
    assert.equal(versionCalls, 1);
    assert.ok(results.every((result) => result.available && result.version === '0.76.0'));
    await fixture.scans.status();
    assert.equal(versionCalls, 1);
    fixture.scans.statusCheckedAt -= 31_000;
    await fixture.scans.status();
    assert.equal(versionCalls, 2);
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

async function simulatedRequest(server, path, { method = 'GET', headers = {}, body } = {}) {
  const response = new EventEmitter();
  response.headers = {};
  response.headersSent = false;
  response.setHeader = (name, value) => { response.headers[name.toLowerCase()] = value; };
  response.writeHead = (status, outgoingHeaders) => {
    response.status = status;
    response.headersSent = true;
    for (const [name, value] of Object.entries(outgoingHeaders)) response.setHeader(name, value);
  };
  response.end = (value) => {
    response.body = Buffer.isBuffer(value) ? value.toString('utf8') : (value ?? '');
    response.emit('finish');
  };
  response.destroy = () => response.emit('finish');
  const request = {
    method, url: path, headers: { host: '127.0.0.1:4173', ...headers },
    async *[Symbol.asyncIterator]() { if (body) yield Buffer.from(body); },
  };
  const done = once(response, 'finish');
  server.emit('request', request, response);
  await done;
  return response;
}

test('plain loopback pages never reveal the launch token and API requires it', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'ecr-sentinel-http-test-'));
  const publicDirectory = join(directory, 'public');
  await mkdir(publicDirectory);
  await writeFile(join(publicDirectory, 'index.html'), '<!doctype html><h1>ECR Sentinel</h1>');
  const { server, token } = createAppServer({
    aws: { listProfiles: async () => ['role'], authMethod: async () => 'role-mfa' },
    publicDirectory, token: 'test-token',
  });
  server.address = () => ({ port: 4173 });
  try {
    const page = await simulatedRequest(server, '/');
    assert.equal(page.status, 200);
    assert.equal(page.body.includes(token), false);
    assert.equal(page.body.includes('ECR Sentinel'), true);
    const fragmentPage = await simulatedRequest(server, '/#token=attacker-controlled');
    assert.equal(fragmentPage.body, page.body);
    assert.equal((await simulatedRequest(server, '/api/profiles')).status, 403);
    const allowed = await simulatedRequest(server, '/api/profiles', { headers: { 'x-ecr-sentinel-token': token } });
    assert.deepEqual(JSON.parse(allowed.body), { profiles: ['role'] });
    const other = await simulatedRequest(server, '/api/profiles', { headers: { 'x-ecr-sentinel-token': token, origin: 'https://evil.example' } });
    assert.equal(other.status, 403);
    const wrongHost = await simulatedRequest(server, '/api/profiles', { headers: { 'x-ecr-sentinel-token': token, host: 'evil.example' } });
    assert.equal(wrongHost.status, 403);
    const removed = await simulatedRequest(server, '/api/scan', { method: 'POST', headers: { 'x-ecr-sentinel-token': token } });
    assert.equal(removed.status, 404);
    const tooBig = await simulatedRequest(server, '/api/scans', {
      method: 'POST', headers: { 'x-ecr-sentinel-token': token, 'content-type': 'application/json' },
      body: JSON.stringify({ payload: 'x'.repeat(20_000) }),
    });
    assert.equal(tooBig.status, 413);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('SBOM API accepts the dedicated upload route and rejects concurrent uploads before buffering', async () => {
  let release;
  let entered;
  const enteredPromise = new Promise((resolve) => { entered = resolve; });
  const hold = new Promise((resolve) => { release = resolve; });
  const scans = {
    startSbom: async () => {
      entered();
      await hold;
      return { id: 'test-job', status: 'PENDING', mode: 'sbom' };
    },
    dispose: async () => {},
  };
  const { server, token } = createAppServer({ aws: {}, scans, token: 'test-token' });
  server.address = () => ({ port: 4173 });
  const headers = { 'x-ecr-sentinel-token': token, 'content-type': 'application/json' };
  const first = simulatedRequest(server, '/api/scans/sbom', {
    method: 'POST', headers, body: JSON.stringify({ bundle: sbomBundle() }),
  });
  await enteredPromise;
  const second = await simulatedRequest(server, '/api/scans/sbom', {
    method: 'POST', headers, body: JSON.stringify({ bundle: sbomBundle() }),
  });
  assert.equal(second.status, 429);
  assert.equal(JSON.parse(second.body).error.code, 'SBOM_UPLOAD_BUSY');
  release();
  assert.equal((await first).status, 202);
  const oversized = await simulatedRequest(server, '/api/scans/sbom', {
    method: 'POST', headers: { ...headers, 'content-length': String(20 * 1024 * 1024 + 1) },
  });
  assert.equal(oversized.status, 413);
});

test('Inspector scan API accepts a protected JSON request and returns an existing scan job', async () => {
  const calls = [];
  const scans = {
    inspectorDestination: async (input) => {
      calls.push(['get', input]);
      return { configured: false, destination: null };
    },
    saveInspectorDestination: async (input) => {
      calls.push(['put', input]);
      return { configured: true, destination: input.destination };
    },
    deleteInspectorDestination: async (input) => {
      calls.push(['delete', input]);
      return { configured: false, destination: null };
    },
    startInspector: async (body) => {
      calls.push(['scan', body]);
      return { id: '11111111-2222-3333-4444-555555555555', status: 'PENDING', mode: 'inspector-sbom' };
    },
    dispose: async () => {},
  };
  const { server, token } = createAppServer({ aws: {}, scans, token: 'test-token' });
  server.address = () => ({ port: 4173 });
  const body = { profile: 'role', region: 'us-east-1', repository: 'team/api', digest,
    platform: 'linux/amd64' };
  const setting = { profile: 'role', region: 'us-east-1', destination: {
    bucketName: 'security-sboms', keyPrefix: 'team',
    kmsKeyArn: `arn:aws:kms:us-east-1:${account}:key/12345678-1234-1234-1234-123456789abc` } };
  const headers = { 'x-ecr-sentinel-token': token, 'content-type': 'application/json' };
  const settingsPath = '/api/inspector/destination?profile=role&region=us-east-1';
  assert.equal((await simulatedRequest(server, settingsPath)).status, 403);
  const before = await simulatedRequest(server, settingsPath, { headers });
  assert.equal(JSON.parse(before.body).configured, false);
  const saved = await simulatedRequest(server, '/api/inspector/destination', {
    method: 'PUT', headers, body: JSON.stringify(setting),
  });
  assert.equal(JSON.parse(saved.body).destination.bucketName, setting.destination.bucketName);
  const denied = await simulatedRequest(server, '/api/scans/inspector', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  });
  assert.equal(denied.status, 403);
  assert.equal(calls.filter(([operation]) => operation === 'scan').length, 0);
  const response = await simulatedRequest(server, '/api/scans/inspector', {
    method: 'POST', headers, body: JSON.stringify(body),
  });
  assert.equal(response.status, 202);
  assert.equal(JSON.parse(response.body).mode, 'inspector-sbom');
  assert.deepEqual(calls.find(([operation]) => operation === 'scan'), ['scan', body]);
  const removed = await simulatedRequest(server, settingsPath, { method: 'DELETE', headers });
  assert.equal(JSON.parse(removed.body).configured, false);
  assert.equal((await simulatedRequest(server, '/api/scans/inspector', { headers })).status, 405);
  assert.equal((await simulatedRequest(server, settingsPath, { method: 'POST', headers })).status, 405);
});

test('MFA API accepts a code only in a protected POST body and returns no secrets', async () => {
  const calls = [];
  const aws = {
    authenticateRoleMfa: async (...args) => {
      calls.push(args);
      return { account, arn: `arn:aws:sts::${account}:assumed-role/scan/sentinel-test`,
        region: 'us-east-1', authMethod: 'role-mfa', expiresAt: '2026-10-21T18:00:00.000Z' };
    },
  };
  const { server, token } = createAppServer({ aws, token: 'test-token' });
  server.address = () => ({ port: 4173 });
  const body = JSON.stringify({ profile: 'role', region: 'us-east-1', code: '123456' });
  const headers = { 'x-ecr-sentinel-token': token, 'content-type': 'application/json' };
  const blocked = await simulatedRequest(server, '/api/auth/mfa', { method: 'POST',
    headers: { 'content-type': 'application/json' }, body });
  assert.equal(blocked.status, 403);
  assert.equal(calls.length, 0);
  const response = await simulatedRequest(server, '/api/auth/mfa', { method: 'POST', headers, body });
  assert.equal(response.status, 200);
  assert.equal(response.headers['cache-control'], 'no-store');
  assert.deepEqual(calls, [['role', 'us-east-1', '123456']]);
  assert.equal(JSON.parse(response.body).account, account);
  assert.equal(Object.hasOwn(JSON.parse(response.body), 'code'), false);
  assert.equal((await simulatedRequest(server, '/api/auth/mfa', { headers })).status, 405);
});
