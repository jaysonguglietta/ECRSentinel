import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { stat } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { fromIni } from '@aws-sdk/credential-providers';
import { NodeHttpHandler } from '@smithy/node-http-handler';

const execFileAsync = promisify(execFile);
const REGION_RE = /^(?:[a-z0-9]+-){2,}[0-9]+$/;
const REPOSITORY_RE = /^[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*(\/[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*)*$/;
const DIGEST_RE = /^sha256:[a-f0-9]{64}$/;
const ROLE_ARN_RE = /^arn:(aws|aws-us-gov|aws-cn):iam::(\d{12}):role\/([A-Za-z0-9+=,.@_/-]{1,512})$/;
const MFA_ARN_RE = /^arn:(aws|aws-us-gov|aws-cn):iam::\d{12}:mfa\/[A-Za-z0-9+=,.@_/-]{1,256}$/;
const MFA_CODE_RE = /^[0-9]{6}$/;
const MFA_SESSION_MARGIN_MS = 60_000;
const INSPECTOR_REPORT_ID_RE = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const INSPECTOR_MAX_SBOM_BYTES = 16 * 1024 * 1024;

export class AwsCliError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = 'AwsCliError';
    this.status = status;
    this.code = code;
  }
}

function requireString(value, field, maximum, pattern) {
  if (typeof value !== 'string' || !value || value.length > maximum || !pattern.test(value)) {
    throw new AwsCliError(400, 'INVALID_INPUT', `Enter a valid ${field}.`);
  }
  return value;
}

export function validateRegion(value) {
  return requireString(value, 'AWS Region', 32, REGION_RE);
}

export function validateRepository(value) {
  return requireString(value, 'repository name', 256, REPOSITORY_RE);
}

export function validateDigest(value) {
  return requireString(value, 'SHA-256 image digest', 71, DIGEST_RE);
}

export function validateNextToken(value) {
  if (value === undefined || value === null || value === '') return undefined;
  if (typeof value !== 'string' || value.length > 8192 || /[\x00-\x1f\x7f]/.test(value)) {
    throw new AwsCliError(400, 'INVALID_INPUT', 'The page token is invalid. Refresh the list and try again.');
  }
  return value;
}

export function mapCliError(error) {
  if (error instanceof AwsCliError) return error;
  if (error?.code === 'ENOENT') {
    return new AwsCliError(503, 'AWS_CLI_MISSING', 'AWS CLI was not found. Install AWS CLI v2, then restart the app.');
  }
  const message = String(error?.stderr ?? error?.message ?? '');
  if (/SSO|UnauthorizedSSOToken/i.test(message)) {
    return new AwsCliError(401, 'AWS_SESSION_EXPIRED', 'Your AWS session has expired. Run aws sso login for this profile and retry.');
  }
  const mfaFailure = (/(?:\bMFA\b|multi[- ]?factor(?: authentication)?)/i.test(message)
    && /\b(?:code|token|prompt|required|requires|failed|invalid|expired|authentication|device)\b/i.test(message))
    || /\bTokenCode\b/i.test(message);
  if (mfaFailure) {
    return new AwsCliError(401, 'AWS_MFA_REQUIRED', 'This AWS profile needs an MFA sign-in. Enter a fresh code in the app, or sign in using Terminal, then retry.');
  }
  if (/Token has expired|ExpiredToken/i.test(message)) {
    return new AwsCliError(401, 'AWS_SESSION_EXPIRED', 'Your AWS session has expired. Sign in again using the app or Terminal, then retry.');
  }
  if (error?.killed || error?.signal === 'SIGTERM' || error?.code === 'ETIMEDOUT') {
    return new AwsCliError(504, 'AWS_TIMEOUT', 'AWS did not respond in time. Check the VPN and try again.');
  }
  if (error?.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER') {
    return new AwsCliError(502, 'AWS_RESPONSE_TOO_LARGE', 'AWS returned too much data for one page. Narrow the selection and try again.');
  }
  if (/Unable to locate credentials|NoCredentialsError|InvalidClientTokenId|UnrecognizedClientException/i.test(message)) {
    return new AwsCliError(401, 'AWS_CREDENTIALS', 'AWS credentials are unavailable or invalid for this profile. Check your CLI configuration.');
  }
  if (/AccessDenied|UnauthorizedOperation|not authorized/i.test(message)) {
    return new AwsCliError(403, 'AWS_ACCESS_DENIED', 'The selected AWS profile lacks permission for this AWS action.');
  }
  if (/RepositoryNotFoundException/i.test(message)) {
    return new AwsCliError(404, 'REPOSITORY_NOT_FOUND', 'This repository was not found in the selected account and Region.');
  }
  if (/ImageNotFoundException/i.test(message)) {
    return new AwsCliError(404, 'IMAGE_NOT_FOUND', 'This image was not found in the selected repository.');
  }
  if (/PreconditionFailed|InvalidRange|NoSuchKey/i.test(message)) {
    return new AwsCliError(409, 'AWS_OBJECT_CHANGED',
      'The Inspector SBOM object changed or disappeared during retrieval. Start a new export and retry.');
  }
  if (/LimitExceededException|ThrottlingException|TooManyRequestsException/i.test(message)) {
    return new AwsCliError(429, 'AWS_LIMIT', 'AWS request limit reached. Wait before trying again.');
  }
  if (/Could not connect to the endpoint URL|Connection was closed|Connect timeout/i.test(message)) {
    return new AwsCliError(502, 'AWS_CONNECTION', 'Could not reach AWS. Check the VPN, DNS, and selected Region.');
  }
  return new AwsCliError(502, 'AWS_REQUEST_FAILED', 'The AWS CLI request failed. Check the selected profile, Region, and VPN, then retry.');
}

function cliEnvironment() {
  const env = Object.fromEntries(
    Object.entries(process.env).filter(([key]) => !key.startsWith('AWS_ENDPOINT_URL')),
  );
  return {
    ...env,
    AWS_PAGER: '',
    AWS_CLI_AUTO_PROMPT: 'off',
    AWS_EC2_METADATA_DISABLED: 'true',
    AWS_IGNORE_CONFIGURED_ENDPOINT_URLS: 'true',
  };
}

function isolatedCredentialEnvironment(credentials) {
  return {
    AWS_ACCESS_KEY_ID: credentials.accessKeyId,
    AWS_SECRET_ACCESS_KEY: credentials.secretAccessKey,
    AWS_SESSION_TOKEN: credentials.sessionToken ?? '',
    AWS_CONFIG_FILE: '/dev/null',
    AWS_SHARED_CREDENTIALS_FILE: '/dev/null',
    AWS_PROFILE: undefined,
    AWS_DEFAULT_PROFILE: undefined,
    AWS_ROLE_ARN: undefined,
    AWS_WEB_IDENTITY_TOKEN_FILE: undefined,
  };
}

function rolePartition(region) {
  if (region.startsWith('cn-')) return 'aws-cn';
  if (region.startsWith('us-gov-')) return 'aws-us-gov';
  return 'aws';
}

export function validateInspectorDestination(value, region) {
  const bucketName = value?.bucketName;
  const keyPrefix = value?.keyPrefix ?? '';
  const kmsKeyArn = value?.kmsKeyArn;
  const partition = rolePartition(region);
  if (typeof bucketName !== 'string' || bucketName.length < 3 || bucketName.length > 63
    || !/^[a-z0-9][a-z0-9.-]*[a-z0-9]$/.test(bucketName)
    || bucketName.includes('..') || /(?:\.-|-\.)/.test(bucketName)
    || /^\d+\.\d+\.\d+\.\d+$/.test(bucketName)) {
    throw new AwsCliError(400, 'INVALID_INPUT', 'Enter a valid S3 bucket name for Inspector exports.');
  }
  if (typeof keyPrefix !== 'string' || keyPrefix.length > 512
    || (keyPrefix && (!/^[A-Za-z0-9!_.*'()/-]+$/.test(keyPrefix)
      || keyPrefix.startsWith('/') || keyPrefix.split('/').includes('..')))) {
    throw new AwsCliError(400, 'INVALID_INPUT', 'Enter a simple S3 key prefix without spaces or parent-directory segments.');
  }
  if (typeof kmsKeyArn !== 'string' || kmsKeyArn.length > 256
    || !new RegExp(`^arn:${partition}:kms:${region}:\\d{12}:key/[A-Za-z0-9-]{8,128}$`).test(kmsKeyArn)) {
    throw new AwsCliError(400, 'INVALID_INPUT', 'Enter a KMS key ARN in the selected AWS Region.');
  }
  return { bucketName, keyPrefix, kmsKeyArn };
}

function validProfileName(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 128
    && !/[\x00-\x1f\x7f]/.test(value);
}

async function inspectorPermission(promise, code, message) {
  try {
    return await promise;
  } catch (error) {
    if (error instanceof AwsCliError && error.code === 'AWS_ACCESS_DENIED') {
      throw new AwsCliError(403, code, message);
    }
    throw error;
  }
}

function activeCredentials(record) {
  return record && record.expiration > Date.now() + MFA_SESSION_MARGIN_MS;
}

async function configStamp() {
  const paths = [process.env.AWS_CONFIG_FILE || join(homedir(), '.aws', 'config'),
    process.env.AWS_SHARED_CREDENTIALS_FILE || join(homedir(), '.aws', 'credentials')];
  const stamps = await Promise.all(paths.map(async (path) => {
    try {
      const item = await stat(path);
      return [path, item.dev, item.ino, item.size, item.mtimeMs, item.ctimeMs];
    } catch (error) {
      if (error?.code === 'ENOENT') return [path, null];
      throw error;
    }
  }));
  return JSON.stringify(stamps);
}

function mapMfaError(error) {
  if (error instanceof AwsCliError) return error;
  const name = String(error?.name ?? error?.Code ?? '');
  if (/Timeout|Abort|ETIMEDOUT/i.test(name) || /timed out/i.test(String(error?.message ?? ''))) {
    return new AwsCliError(504, 'AWS_TIMEOUT', 'AWS did not respond in time. Check the VPN and try again.');
  }
  if (/Throttl|TooManyRequests|LimitExceeded/i.test(name)) {
    return new AwsCliError(429, 'AWS_LIMIT', 'AWS request limit reached. Wait before trying again.');
  }
  if (/CredentialsProvider|SSO|TokenProvider/i.test(name)) {
    return new AwsCliError(401, 'AWS_MFA_SOURCE_UNAVAILABLE', 'The source profile could not provide credentials. Sign in to that profile, then retry.');
  }
  return new AwsCliError(401, 'AWS_MFA_FAILED', 'AWS rejected the code or role sign-in. Check the current code and role access, then try again.');
}

export class AwsCliService {
  constructor({ run = execFileAsync, command = 'aws', maxConcurrent = 6,
    credentialProviderFactory = fromIni, configStampProvider = configStamp } = {}) {
    this.run = run;
    this.command = command;
    this.maxConcurrent = maxConcurrent;
    this.inFlight = 0;
    this.cachedProfiles = null;
    this.cachedProfilesAt = 0;
    this.pendingProfiles = null;
    this.credentialProviderFactory = credentialProviderFactory;
    this.configStampProvider = configStampProvider;
    this.mfaSessions = new Map();
    this.mfaInFlight = new Set();
    this.mfaAttempts = new Map();
  }

  async execute(args, { json = true, allowMissingSetting = false, maxBuffer = 16 * 1024 * 1024,
    envOverrides = {}, signal, timeoutMs = 35_000 } = {}) {
    if (this.inFlight >= this.maxConcurrent) {
      throw new AwsCliError(429, 'LOCAL_BUSY', 'Too many AWS requests are in progress. Try again shortly.');
    }
    this.inFlight += 1;
    try {
      const { stdout } = await this.run(this.command, args, {
        shell: false,
        windowsHide: true,
        timeout: timeoutMs,
        signal,
        maxBuffer,
        encoding: 'utf8',
        env: Object.fromEntries(Object.entries({ ...cliEnvironment(), ...envOverrides })
          .filter(([, value]) => value !== undefined && value !== null)),
      });
      if (!json) return stdout;
      try {
        return JSON.parse(stdout);
      } catch {
        throw new AwsCliError(502, 'AWS_BAD_RESPONSE', 'AWS CLI returned an unreadable response.');
      }
    } catch (error) {
      if (allowMissingSetting && error?.code === 1 && !String(error?.stderr ?? '').trim()) return '';
      throw mapCliError(error);
    } finally {
      this.inFlight -= 1;
    }
  }

  async listProfiles(force = false) {
    if (force && this.pendingProfiles) await this.pendingProfiles.catch(() => {});
    if (!force && this.cachedProfiles && Date.now() - this.cachedProfilesAt < 10_000) return this.cachedProfiles;
    if (this.pendingProfiles) return this.pendingProfiles;
    this.pendingProfiles = this.execute(['configure', 'list-profiles'], { json: false })
      .then((output) => {
        const profiles = [...new Set(output.split(/\r?\n/)
          .map((name) => name.trim())
          .filter((name) => name.length > 0 && name.length <= 128 && !/[\x00-\x1f\x7f]/.test(name)))];
        this.cachedProfiles = profiles;
        this.cachedProfilesAt = Date.now();
        return profiles;
      })
      .finally(() => { this.pendingProfiles = null; });
    return this.pendingProfiles;
  }

  async requireProfile(profile) {
    if (!validProfileName(profile)) {
      throw new AwsCliError(400, 'INVALID_INPUT', 'Select a configured AWS profile.');
    }
    const profiles = await this.listProfiles();
    if (!profiles.includes(profile)) {
      throw new AwsCliError(400, 'UNKNOWN_PROFILE', 'Select an AWS profile listed on this Mac.');
    }
    return profile;
  }

  async profileSetting(profile, setting) {
    const value = await this.execute(['configure', 'get', setting, `--profile=${profile}`], {
      json: false,
      allowMissingSetting: true,
    });
    return value.trim();
  }

  async authMethod(profile) {
    await this.requireProfile(profile);
    const mfaSerial = await this.profileSetting(profile, 'mfa_serial');
    const roleArn = await this.profileSetting(profile, 'role_arn');
    if (mfaSerial && roleArn) return 'role-mfa';
    if (await this.profileSetting(profile, 'sso_session')) return 'sso';
    if (await this.profileSetting(profile, 'sso_start_url')) return 'sso';
    if (await this.profileSetting(profile, 'login_session')) return 'login';
    if (mfaSerial) return 'iam-user-mfa';
    return 'standard';
  }

  async requireTarget(profile, region) {
    await this.requireProfile(profile);
    validateRegion(region);
    const history = await this.profileSetting(profile, 'cli_history');
    if (history.toLowerCase() === 'enabled') {
      throw new AwsCliError(409, 'CLI_HISTORY_ENABLED',
        'AWS CLI history is enabled for this profile and can store credentials or inventory on disk. Disable cli_history for this profile, then retry.');
    }
    return { profile, region };
  }

  async roleMfaConfig(profile, region) {
    await this.requireTarget(profile, region);
    const names = ['role_arn', 'mfa_serial', 'source_profile', 'credential_source',
      'external_id', 'duration_seconds', 'role_session_name', 'credential_process', 'web_identity_token_file'];
    const values = {};
    for (const name of names) values[name] = await this.profileSetting(profile, name);
    const role = ROLE_ARN_RE.exec(values.role_arn);
    const partition = rolePartition(region);
    if (!role || role[1] !== partition || !(MFA_ARN_RE.test(values.mfa_serial)
      || /^[A-Za-z0-9]{8,256}$/.test(values.mfa_serial))) {
      throw new AwsCliError(400, 'AWS_MFA_UNSUPPORTED', 'This profile has an invalid role ARN or MFA device setting. Use Terminal to sign in or correct its AWS configuration.');
    }
    if (values.mfa_serial.startsWith('arn:') && !values.mfa_serial.startsWith(`arn:${partition}:`)) {
      throw new AwsCliError(400, 'AWS_MFA_UNSUPPORTED', 'The role and MFA device use different AWS partitions. Correct the profile or use Terminal.');
    }
    if (!validProfileName(values.source_profile) || values.source_profile === profile
      || values.credential_source || values.credential_process || values.web_identity_token_file) {
      throw new AwsCliError(400, 'AWS_MFA_UNSUPPORTED', 'In-app MFA requires a role with one source_profile. This profile needs its existing Terminal sign-in.');
    }
    await this.requireProfile(values.source_profile);
    for (const setting of ['role_arn', 'mfa_serial', 'source_profile', 'credential_source',
      'credential_process', 'sso_session', 'sso_start_url', 'sso_account_id', 'sso_region',
      'sso_role_name', 'login_session', 'web_identity_token_file']) {
      if (await this.profileSetting(values.source_profile, setting)) {
        throw new AwsCliError(400, 'AWS_MFA_UNSUPPORTED', 'This source profile has another credential step. Sign in using Terminal for this profile.');
      }
    }
    if (values.role_session_name && !/^[A-Za-z0-9_+=,.@-]{2,64}$/.test(values.role_session_name)) {
      throw new AwsCliError(400, 'AWS_MFA_UNSUPPORTED', 'The role session name is invalid. Correct the profile or use Terminal.');
    }
    if (values.external_id && !/^[A-Za-z0-9_+=,.@:/-]{2,1224}$/.test(values.external_id)) {
      throw new AwsCliError(400, 'AWS_MFA_UNSUPPORTED', 'The external ID setting is invalid. Correct the profile or use Terminal.');
    }
    if (values.duration_seconds && (!/^\d{3,5}$/.test(values.duration_seconds)
      || Number(values.duration_seconds) < 900 || Number(values.duration_seconds) > 43_200)) {
      throw new AwsCliError(400, 'AWS_MFA_UNSUPPORTED', 'The role duration setting is invalid. Correct the profile or use Terminal.');
    }
    return { roleArn: values.role_arn, roleName: role[3].split('/').at(-1), account: role[2],
      mfaSerial: values.mfa_serial, sourceProfile: values.source_profile, partition };
  }

  async sessionFor(profile) {
    const session = this.mfaSessions.get(profile);
    if (!session) return null;
    if (!activeCredentials(session)) {
      this.clearMfaSession(profile);
      return null;
    }
    try {
      if (session.configStamp !== await this.configStampProvider()) {
        this.clearMfaSession(profile);
        return null;
      }
    } catch {
      this.clearMfaSession(profile);
      return null;
    }
    return session;
  }

  clearMfaSession(profile) {
    const session = this.mfaSessions.get(profile);
    if (session?.expiryTimer) clearTimeout(session.expiryTimer);
    this.mfaSessions.delete(profile);
  }

  async authenticateRoleMfa(profile, region, code) {
    if (typeof code !== 'string' || !MFA_CODE_RE.test(code)) {
      throw new AwsCliError(400, 'INVALID_MFA_CODE', 'Enter the current 6-digit code from your MFA device.');
    }
    await this.requireTarget(profile, region);
    if (this.mfaInFlight.has(profile)) {
      throw new AwsCliError(429, 'AWS_MFA_BUSY', 'An MFA sign-in for this profile is already in progress. Wait and try again.');
    }
    if (this.mfaInFlight.size > 0) {
      throw new AwsCliError(429, 'AWS_MFA_BUSY', 'Another MFA sign-in is in progress. Wait for it to finish, then try again.');
    }
    const now = Date.now();
    const attempts = (this.mfaAttempts.get(profile) ?? []).filter((time) => now - time < 60_000);
    if (attempts.length >= 5) {
      throw new AwsCliError(429, 'AWS_MFA_RATE_LIMIT', 'Too many sign-in attempts. Wait one minute, then try again.');
    }
    attempts.push(now);
    this.mfaAttempts.set(profile, attempts);
    this.mfaInFlight.add(profile);
    try {
      this.clearMfaSession(profile);
      const config = await this.roleMfaConfig(profile, region);
      const before = await this.configStampProvider();
      let prompts = 0;
      const endpoint = `https://sts.${region}.${config.partition === 'aws-cn' ? 'amazonaws.com.cn' : 'amazonaws.com'}`;
      const provider = this.credentialProviderFactory({
        profile,
        ignoreCache: true,
        clientConfig: {
          region, endpoint, maxAttempts: 1,
          requestHandler: new NodeHttpHandler({ connectionTimeout: 5_000, requestTimeout: 20_000 }),
        },
        mfaCodeProvider: async (serial) => {
          prompts += 1;
          if (prompts !== 1 || serial !== config.mfaSerial) {
            throw new AwsCliError(400, 'AWS_MFA_UNSUPPORTED', 'This profile requires another MFA device. Sign in using Terminal for this profile.');
          }
          return code;
        },
      });
      let deadline;
      const resolved = await Promise.race([
        provider(),
        new Promise((_, reject) => {
          deadline = setTimeout(() => reject(new AwsCliError(504, 'AWS_TIMEOUT',
            'AWS sign-in did not finish in time. Check the VPN and try again.')), 45_000);
        }),
      ]).finally(() => clearTimeout(deadline));
      const expiration = resolved?.expiration instanceof Date ? resolved.expiration.getTime()
        : Date.parse(resolved?.expiration ?? '');
      if (prompts !== 1 || !/^(?:AKIA|ASIA)[A-Z0-9]{16}$/.test(resolved?.accessKeyId ?? '')
        || typeof resolved?.secretAccessKey !== 'string' || resolved.secretAccessKey.length < 16
        || typeof resolved?.sessionToken !== 'string' || !resolved.sessionToken
        || !Number.isFinite(expiration) || expiration <= Date.now() + MFA_SESSION_MARGIN_MS) {
        throw new AwsCliError(502, 'AWS_MFA_BAD_SESSION', 'AWS did not return a usable temporary role session. Try signing in again.');
      }
      if (before !== await this.configStampProvider()) {
        throw new AwsCliError(409, 'AWS_PROFILE_CHANGED', 'The AWS profile changed during sign-in. Retry with the current profile.');
      }
      const credentials = { accessKeyId: resolved.accessKeyId, secretAccessKey: resolved.secretAccessKey,
        sessionToken: resolved.sessionToken };
      const caller = await this.callerForCredentials(credentials, region);
      const expectedArn = `arn:${config.partition}:sts::${config.account}:assumed-role/${config.roleName}/`;
      if (caller.Account !== config.account || typeof caller.Arn !== 'string' || !caller.Arn.startsWith(expectedArn)) {
        throw new AwsCliError(409, 'AWS_ACCOUNT_CHANGED', 'AWS returned a different role or account. The session was not saved.');
      }
      if (before !== await this.configStampProvider()) {
        throw new AwsCliError(409, 'AWS_PROFILE_CHANGED', 'The AWS profile changed during sign-in. Retry with the current profile.');
      }
      const session = { credentials, expiration, configStamp: before };
      session.expiryTimer = setTimeout(() => {
        if (this.mfaSessions.get(profile) === session) this.clearMfaSession(profile);
      }, Math.max(1, expiration - Date.now() - MFA_SESSION_MARGIN_MS));
      session.expiryTimer.unref?.();
      this.mfaSessions.set(profile, session);
      this.mfaAttempts.delete(profile);
      return {
        account: caller.Account, arn: caller.Arn, region,
        scanner: 'LOCAL_TRIVY', scanType: 'LOCAL', scanRules: [],
        authMethod: 'role-mfa', expiresAt: new Date(expiration).toISOString(),
      };
    } catch (error) {
      throw mapMfaError(error);
    } finally {
      this.mfaInFlight.delete(profile);
    }
  }

  async aws(profile, region, service, operation, extra = [], options = {}) {
    await this.requireTarget(profile, region);
    const session = await this.sessionFor(profile);
    return this.execute([
      service, operation, ...(session ? [] : [`--profile=${profile}`]), `--region=${region}`,
      '--output=json', '--no-cli-pager', '--cli-connect-timeout=5', '--cli-read-timeout=20',
      ...extra,
    ], { ...options, envOverrides: session ? isolatedCredentialEnvironment(session.credentials) : {} });
  }

  async identity(profile, region) {
    const caller = await this.aws(profile, region, 'sts', 'get-caller-identity');
    if (!/^\d{12}$/.test(caller.Account ?? '')) {
      throw new AwsCliError(502, 'AWS_BAD_RESPONSE', 'AWS did not return a valid account identity.');
    }
    return {
      account: caller.Account,
      arn: caller.Arn ?? null,
      region,
      scanner: 'LOCAL_TRIVY',
      scanType: 'LOCAL',
      scanRules: [],
    };
  }

  async repositories(profile, region, nextToken) {
    const token = validateNextToken(nextToken);
    const raw = await this.aws(profile, region, 'ecr', 'describe-repositories', [
      '--page-size=100', '--max-items=100', ...(token ? [`--starting-token=${token}`] : []),
    ]);
    return {
      items: (raw.repositories ?? []).map((item) => ({
        name: item.repositoryName,
        uri: item.repositoryUri ?? null,
        createdAt: item.createdAt ?? null,
        tagMutability: item.imageTagMutability ?? null,
      })),
      nextToken: raw.NextToken ?? raw.nextToken ?? null,
    };
  }

  async repository(profile, region, repository) {
    validateRepository(repository);
    const raw = await this.aws(profile, region, 'ecr', 'describe-repositories', [
      `--repository-names=${repository}`,
    ]);
    const item = raw.repositories?.[0];
    if (!item || item.repositoryName !== repository) {
      throw new AwsCliError(404, 'REPOSITORY_NOT_FOUND', 'This repository was not found in the selected account and Region.');
    }
    return item;
  }

  async images(profile, region, repository, nextToken) {
    validateRepository(repository);
    const token = validateNextToken(nextToken);
    const raw = await this.aws(profile, region, 'ecr', 'describe-images', [
      `--repository-name=${repository}`,
      '--page-size=100', '--max-items=100', ...(token ? [`--starting-token=${token}`] : []),
    ]);
    return {
      items: (raw.imageDetails ?? []).map((item) => ({
        digest: item.imageDigest,
        tags: item.imageTags ?? [],
        pushedAt: item.imagePushedAt ?? null,
        sizeBytes: item.imageSizeInBytes ?? null,
        artifactMediaType: item.artifactMediaType ?? null,
        manifestMediaType: item.imageManifestMediaType ?? null,
        lastRecordedPullTime: item.lastRecordedPullTime ?? null,
        status: item.imageStatus ?? null,
      })),
      nextToken: raw.NextToken ?? raw.nextToken ?? null,
    };
  }

  async image(profile, region, repository, digest) {
    validateRepository(repository);
    validateDigest(digest);
    const raw = await this.aws(profile, region, 'ecr', 'describe-images', [
      `--repository-name=${repository}`, `--image-ids=imageDigest=${digest}`,
    ]);
    const item = raw.imageDetails?.[0];
    if (!item || item.imageDigest !== digest) {
      throw new AwsCliError(404, 'IMAGE_NOT_FOUND', 'This image was not found in the selected repository.');
    }
    return item;
  }

  async createInspectorSbomExport(target, account, destination, signal) {
    const { profile, region, repository, digest } = target;
    validateRepository(repository);
    validateDigest(digest);
    if (!/^\d{12}$/.test(account)) throw new AwsCliError(400, 'INVALID_INPUT', 'The AWS account is invalid.');
    const selected = validateInspectorDestination(destination, region);
    const resourceId = `arn:${rolePartition(region)}:ecr:${region}:${account}:repository/${repository}/${digest}`;
    const filter = {
      accountId: [{ comparison: 'EQUALS', value: account }],
      resourceId: [{ comparison: 'EQUALS', value: resourceId }],
      resourceType: [{ comparison: 'EQUALS', value: 'AWS_ECR_CONTAINER_IMAGE' }],
    };
    const result = await inspectorPermission(this.aws(profile, region, 'inspector2', 'create-sbom-export', [
      '--report-format=CYCLONEDX_1_4',
      `--resource-filter-criteria=${JSON.stringify(filter)}`,
      `--s3-destination=${JSON.stringify(selected)}`,
    ], { signal }), 'INSPECTOR_CREATE_DENIED',
    'This profile cannot start an Inspector SBOM export. Check inspector2:CreateSbomExport and Inspector write access to the S3 bucket and KMS key.');
    if (!INSPECTOR_REPORT_ID_RE.test(result?.reportId ?? '')) {
      throw new AwsCliError(502, 'INSPECTOR_BAD_RESPONSE', 'Inspector did not return a valid SBOM export ID.');
    }
    return { reportId: result.reportId, resourceId };
  }

  async getInspectorSbomExport(target, reportId, signal) {
    if (!INSPECTOR_REPORT_ID_RE.test(reportId ?? '')) {
      throw new AwsCliError(400, 'INVALID_INPUT', 'The Inspector SBOM export ID is invalid.');
    }
    const result = await inspectorPermission(this.aws(target.profile, target.region, 'inspector2', 'get-sbom-export', [
      `--report-id=${reportId}`,
    ], { signal }), 'INSPECTOR_STATUS_DENIED',
    'This profile cannot read Inspector SBOM export status. Grant inspector2:GetSbomExport and retry.');
    if (result?.reportId !== reportId || !['IN_PROGRESS', 'SUCCEEDED', 'FAILED', 'CANCELLED'].includes(result.status)) {
      throw new AwsCliError(502, 'INSPECTOR_BAD_RESPONSE', 'Inspector returned an unexpected SBOM export status.');
    }
    return result;
  }

  async listInspectorSbomObject(target, destination, signal) {
    const result = await inspectorPermission(this.aws(target.profile, target.region, 's3api', 'list-objects-v2', [
      `--bucket=${destination.bucketName}`, `--prefix=${destination.keyPrefix}`, '--max-keys=2', '--no-paginate',
    ], { signal }), 'INSPECTOR_S3_LIST_DENIED',
    'This profile cannot list the Inspector export prefix. Grant s3:ListBucket on the export bucket for this prefix.');
    const objects = result?.Contents ?? [];
    if (result?.IsTruncated || !Array.isArray(objects) || objects.length !== 1) {
      throw new AwsCliError(422, 'INSPECTOR_EXPORT_AMBIGUOUS',
        'The Inspector export prefix does not contain exactly one SBOM object. Use a clean bucket prefix and retry.');
    }
    const object = objects[0];
    if (typeof object?.Key !== 'string' || !object.Key.startsWith(destination.keyPrefix)
      || object.Key.length > 1024 || !Number.isInteger(object.Size) || object.Size <= 0
      || !/^"[^"\x00-\x1f\x7f]{1,128}"$/.test(object.ETag ?? '')) {
      throw new AwsCliError(502, 'INSPECTOR_EXPORT_INVALID', 'Inspector returned an invalid SBOM object listing.');
    }
    if (object.Size > INSPECTOR_MAX_SBOM_BYTES) {
      throw new AwsCliError(413, 'SBOM_TOO_LARGE', 'The Inspector SBOM exceeds the 16 MiB local import limit.');
    }
    return { key: object.Key, etag: object.ETag, size: object.Size };
  }

  async downloadInspectorSbomObject(target, destination, object, outputPath, signal) {
    if (!object || typeof object.key !== 'string' || !object.key.startsWith(destination.keyPrefix)
      || typeof outputPath !== 'string' || !outputPath) {
      throw new AwsCliError(400, 'INVALID_INPUT', 'The Inspector SBOM object selection is invalid.');
    }
    const result = await inspectorPermission(this.aws(target.profile, target.region, 's3api', 'get-object', [
      `--bucket=${destination.bucketName}`, `--key=${object.key}`, `--if-match=${object.etag}`,
      `--range=bytes=0-${INSPECTOR_MAX_SBOM_BYTES}`, outputPath,
    ], { signal, maxBuffer: 64 * 1024, timeoutMs: 90_000 }), 'INSPECTOR_S3_READ_DENIED',
    'This profile cannot read or decrypt the Inspector SBOM. Grant s3:GetObject for the export prefix and kms:Decrypt on its KMS key.');
    if (result?.ETag !== object.etag || result?.ContentLength !== object.size) {
      throw new AwsCliError(502, 'INSPECTOR_EXPORT_CHANGED',
        'The Inspector SBOM object changed during retrieval. The local copy was rejected.');
    }
    return result;
  }

  // The in-app MFA session takes priority when present. Otherwise AWS CLI
  // resolves the selected profile and its own cached session. Credentials go
  // only to the Trivy child process environment, never to the browser or argv.
  async exportCredentials(profile, region) {
    await this.requireTarget(profile, region);
    const session = await this.sessionFor(profile);
    if (session) return { ...session.credentials };
    const raw = await this.execute([
      'configure', 'export-credentials', `--profile=${profile}`, '--format=process',
      '--no-cli-pager',
    ], { maxBuffer: 8192 });
    if (raw.Version !== 1 || !/^(?:AKIA|ASIA)[A-Z0-9]{16}$/.test(raw.AccessKeyId ?? '')
      || typeof raw.SecretAccessKey !== 'string' || raw.SecretAccessKey.length < 16
      || (raw.SessionToken !== undefined && typeof raw.SessionToken !== 'string')) {
      throw new AwsCliError(502, 'AWS_BAD_CREDENTIALS', 'AWS CLI could not export usable credentials for the selected profile.');
    }
    if (raw.Expiration && Date.parse(raw.Expiration) <= Date.now() + 60_000) {
      throw new AwsCliError(401, 'AWS_SESSION_EXPIRED', 'Your AWS session has expired. Sign in again using the app or Terminal, then retry.');
    }
    return {
      accessKeyId: raw.AccessKeyId,
      secretAccessKey: raw.SecretAccessKey,
      sessionToken: raw.SessionToken ?? null,
    };
  }

  async identityForCredentials(credentials, region) {
    const caller = await this.callerForCredentials(credentials, region);
    return caller.Account;
  }

  async callerForCredentials(credentials, region) {
    validateRegion(region);
    const caller = await this.execute([
      'sts', 'get-caller-identity', `--region=${region}`, '--output=json',
      '--no-cli-pager', '--cli-connect-timeout=5', '--cli-read-timeout=20',
    ], {
      envOverrides: isolatedCredentialEnvironment(credentials),
    });
    if (!/^\d{12}$/.test(caller.Account ?? '')) {
      throw new AwsCliError(502, 'AWS_BAD_RESPONSE', 'AWS did not return a valid account identity.');
    }
    return caller;
  }
}
