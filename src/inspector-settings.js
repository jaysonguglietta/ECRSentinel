import { createHash, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, rename, unlink } from 'node:fs/promises';
import { homedir } from 'node:os';
import { isAbsolute, join } from 'node:path';
import { AwsCliError, validateInspectorDestination } from './aws-cli.js';

const MAX_SETTINGS_BYTES = 128 * 1024;
const SETTINGS_FILE = 'inspector-destinations.json';

function defaultRoot() {
  if (process.env.ECR_SENTINEL_DATA_DIR) return process.env.ECR_SENTINEL_DATA_DIR;
  if (process.platform === 'darwin') return join(homedir(), 'Library', 'Application Support', 'ECR Sentinel');
  return join(process.env.XDG_DATA_HOME || join(homedir(), '.local', 'share'), 'ECR Sentinel');
}

function invalidSettings() {
  return new AwsCliError(500, 'INSPECTOR_SETTINGS_INVALID',
    'The local Inspector export settings are invalid. Check the private app data directory before trying again.');
}

function unsafeSettings() {
  return new AwsCliError(500, 'INSPECTOR_SETTINGS_UNSAFE',
    'The local Inspector export settings are not private. Secure the app data directory before trying again.');
}

function ownerUid() {
  return typeof process.getuid === 'function' ? process.getuid() : null;
}

function privateMetadata(details, directory) {
  const owner = ownerUid();
  return !details.isSymbolicLink() && (owner === null || details.uid === owner)
    && (details.mode & 0o077) === 0 && (directory ? details.isDirectory() : details.isFile());
}

function contextKey({ profile, account, region }) {
  return createHash('sha256').update(JSON.stringify([profile, account, region])).digest('hex');
}

export class InspectorDestinationStore {
  constructor({ root = defaultRoot() } = {}) {
    if (typeof root !== 'string' || !isAbsolute(root)) {
      throw new Error('Inspector settings directory must be an absolute path.');
    }
    this.root = root;
    this.path = join(root, SETTINGS_FILE);
    this.mutationTail = Promise.resolve();
  }

  async ensureRoot() {
    try {
      await mkdir(this.root, { recursive: true, mode: 0o700 });
    } catch (error) {
      if (error?.code !== 'EEXIST') throw error;
    }
    const details = await lstat(this.root);
    if (!privateMetadata(details, true)) throw unsafeSettings();
  }

  async read() {
    await this.ensureRoot();
    let handle;
    try {
      handle = await open(this.path, constants.O_RDONLY | constants.O_NOFOLLOW);
    } catch (error) {
      if (error?.code === 'ENOENT') return { version: 1, destinations: {} };
      if (error?.code === 'ELOOP') throw unsafeSettings();
      throw error;
    }
    try {
      const details = await handle.stat();
      if (!privateMetadata(details, false)) throw unsafeSettings();
      if (details.size > MAX_SETTINGS_BYTES) throw invalidSettings();
      const value = JSON.parse((await handle.readFile('utf8')));
      if (value?.version !== 1 || !value.destinations || typeof value.destinations !== 'object'
        || Array.isArray(value.destinations)) throw invalidSettings();
      return value;
    } catch (error) {
      if (error instanceof SyntaxError) throw invalidSettings();
      throw error;
    } finally {
      await handle.close();
    }
  }

  async write(value) {
    await this.ensureRoot();
    const body = JSON.stringify(value);
    if (Buffer.byteLength(body) > MAX_SETTINGS_BYTES) {
      throw new AwsCliError(413, 'INSPECTOR_SETTINGS_FULL', 'Too many local Inspector export destinations are saved.');
    }
    const temporary = join(this.root, `.${SETTINGS_FILE}.${randomUUID()}`);
    let handle;
    try {
      handle = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      await handle.writeFile(body, 'utf8');
      await handle.sync();
      await handle.close();
      handle = null;
      await rename(temporary, this.path);
    } finally {
      if (handle) await handle.close();
      await unlink(temporary).catch((error) => { if (error?.code !== 'ENOENT') throw error; });
    }
  }

  async get(context) {
    const value = await this.read();
    const record = value.destinations[contextKey(context)];
    if (!record) return null;
    if (record.profile !== context.profile || record.account !== context.account || record.region !== context.region) {
      throw invalidSettings();
    }
    try {
      const destination = validateInspectorDestination(record.destination, context.region);
      if (destination.keyPrefix.length > 400 || destination.keyPrefix.endsWith('/')) throw invalidSettings();
      return destination;
    } catch {
      throw invalidSettings();
    }
  }

  mutate(action) {
    const next = this.mutationTail.then(action);
    this.mutationTail = next.catch(() => {});
    return next;
  }

  async put(context, destination) {
    const checked = validateInspectorDestination(destination, context.region);
    if (checked.keyPrefix.length > 400) {
      throw new AwsCliError(400, 'INVALID_INPUT', 'The S3 key prefix must be 400 characters or fewer.');
    }
    const normalized = { ...checked, keyPrefix: checked.keyPrefix.replace(/\/+$/, '') };
    return this.mutate(async () => {
      const value = await this.read();
      value.destinations[contextKey(context)] = { ...context, destination: normalized };
      await this.write(value);
      return normalized;
    });
  }

  async delete(context) {
    return this.mutate(async () => {
      const value = await this.read();
      delete value.destinations[contextKey(context)];
      await this.write(value);
    });
  }
}
