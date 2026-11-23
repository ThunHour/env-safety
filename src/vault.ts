/**
 * Env Safety vault: like .NET User Secrets, but encrypted.
 *
 * The project keeps only an id (envSafety.vaultId). The encrypted secret files live OUTSIDE the
 * project, in <vaultRoot>/<id>/, so an AI agent working in the project folder never sees them.
 *
 *   <vaultRoot>/<id>/vault.json        { format, v, salt }   (no secrets, no file names)
 *   <vaultRoot>/<id>/<sha256>.locked   encrypted envelope { path, data, lockedAt }
 *
 * Blob names are SHA-256(salt || relative path): stable, so re-locking a file replaces its blob,
 * but they do not show which file they hold. The real path is only inside the ciphertext.
 * Note: anyone who can read vault.json can still confirm a guess ("is .env in here?").
 *
 * No VS Code dependency, so it is unit-testable with plain Node.
 */
import { createHash, randomBytes } from 'crypto';
import * as fs from 'fs/promises';
import * as os from 'os';
import * as path from 'path';
import { decryptFile, encryptFile, PrivateKeys, PublicKeys, SignCheck, signLocked, verifyLocked } from './crypto';

export const VAULT_FORMAT = 'env-lock-vault';
const BLOB_EXT = '.locked';
const META = 'vault.json';
const TMP = '.envlock-tmp';

export interface Vault {
  id: string;
  dir: string;
  salt: Buffer;
}

export interface VaultEnvelope {
  path: string; // relative to the project root, forward slashes
  data: Buffer;
  lockedAt: number;
  sign: SignCheck; // made by this machine's Env Safety, for this file? (see signLocked)
}

const PREV = '.prev';

/** What a signature is bound to (see signLocked). */
export const vaultBinding = (v: Vault, rel: string) => `vault:${v.id}:${normalizeRel(rel)}`;
export const fileBinding = (rel: string) => `file:${normalizeRel(rel)}`;

export function defaultVaultRoot(): string {
  return path.join(os.homedir(), '.env-safety', 'vault');
}

export function newVaultId(): string {
  return randomBytes(16).toString('hex');
}

const ID_RE = /^[A-Za-z0-9_-]{8,64}$/;
export const isValidVaultId = (id: string) => ID_RE.test(id);

/** Normalised relative path; case-insensitive on Windows, like the file system. */
export function normalizeRel(rel: string, platform: NodeJS.Platform = process.platform): string {
  const p = rel.replace(/\\/g, '/').replace(/^\.\//, '');
  return platform === 'win32' ? p.toLowerCase() : p;
}

export function blobName(salt: Buffer, rel: string, platform: NodeJS.Platform = process.platform): string {
  return createHash('sha256').update(salt).update(normalizeRel(rel, platform)).digest('hex') + BLOB_EXT;
}

/** Opens (and creates on first use) the vault of one project. */
export async function openVault(root: string, id: string): Promise<Vault> {
  if (!isValidVaultId(id)) throw new Error(`Invalid vault id "${id}".`);
  const dir = path.join(root, id);
  const meta = path.join(dir, META);
  try {
    const j = JSON.parse(await fs.readFile(meta, 'utf8'));
    if (j.format !== VAULT_FORMAT || typeof j.salt !== 'string') throw new Error(`${meta} is not an Env Safety vault.`);
    return { id, dir, salt: Buffer.from(j.salt, 'base64') };
  } catch (e: any) {
    if (e.code !== 'ENOENT') throw e;
  }
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  const salt = randomBytes(32);
  await fs.writeFile(meta, JSON.stringify({ format: VAULT_FORMAT, v: 1, salt: salt.toString('base64') }, null, 2) + '\n', {
    encoding: 'utf8',
    mode: 0o600,
    flag: 'wx', // never overwrite another window's salt
  }).catch(async (e) => {
    if (e.code !== 'EEXIST') throw e;
  });
  return openVault(root, id);
}

/**
 * Encrypts a file into the vault (public key only), signed when macKey is given. The blob it
 * replaces is kept as <blob>.prev, so one bad overwrite or deletion is recoverable.
 */
export async function vaultPut(
  v: Vault,
  rel: string,
  plain: Buffer,
  pub: PublicKeys,
  macKey?: Buffer,
  signedAt = Date.now()
): Promise<string> {
  const envelope = JSON.stringify({ path: rel.replace(/\\/g, '/'), data: plain.toString('base64'), lockedAt: signedAt });
  const blob = path.join(v.dir, blobName(v.salt, rel));
  const tmp = blob + TMP;
  const locked = encryptFile(Buffer.from(envelope, 'utf8'), pub);
  await fs.writeFile(tmp, macKey ? signLocked(locked, macKey, vaultBinding(v, rel), signedAt) : locked, { encoding: 'utf8', mode: 0o600 });
  await fs.copyFile(blob, blob + PREV).catch(() => undefined); // no previous blob: fine
  await fs.rename(tmp, blob);
  return blob;
}

/** Blob a file would have in this vault (to notice blobs that disappeared). */
export const expectedBlob = (v: Vault, rel: string) => path.join(v.dir, blobName(v.salt, rel));

/** Blob paths in the vault (does not need the passphrase). */
export async function vaultList(v: Vault): Promise<string[]> {
  let names: string[];
  try {
    names = await fs.readdir(v.dir);
  } catch (e: any) {
    if (e.code === 'ENOENT') return [];
    throw e;
  }
  return names.filter((n) => n.endsWith(BLOB_EXT)).map((n) => path.join(v.dir, n));
}

/**
 * Decrypts one blob. Throws WrongKeyError / corruption errors from crypto. The signature is
 * checked against the path found INSIDE the ciphertext and against the blob's own name, so a
 * valid blob copied over another file's blob does not verify.
 */
export async function vaultRead(v: Vault, blob: string, priv: PrivateKeys, macKey?: Buffer | Buffer[]): Promise<VaultEnvelope> {
  const text = await fs.readFile(blob, 'utf8');
  const j = JSON.parse(decryptFile(text, priv).toString('utf8'));
  if (typeof j.path !== 'string' || typeof j.data !== 'string') throw new Error(`${path.basename(blob)}: not a vault entry.`);
  let sign = verifyLocked(text, macKey, vaultBinding(v, j.path));
  if (sign.state === 'valid' && path.basename(blob) !== blobName(v.salt, j.path)) sign = { state: 'invalid', signedAt: 0 };
  return { path: j.path, data: Buffer.from(j.data, 'base64'), lockedAt: Number(j.lockedAt) || 0, sign };
}

/**
 * Where an envelope may be restored. The public key is not secret, so anyone could plant a blob:
 * refuse anything that escapes the project root. Returns undefined if unsafe.
 */
/** Fingerprint of a vault's salt, pinned in the protected records (a rewritten vault.json is noticed). */
export const saltFingerprint = (v: Vault) => createHash('sha256').update('env-lock-vault-salt\0').update(v.salt).digest('hex');

const isInside = (root: string, p: string) => {
  const r = path.relative(root, p);
  return r === '' || (!r.startsWith('..') && !path.isAbsolute(r));
};

/**
 * restoreTarget only checks the path TEXT. Links decide where a write really lands: an agent can
 * turn "config" into a junction (no admin rights needed on Windows) or ".env" into a dangling
 * symlink, so the plaintext would be written outside the project (a synced folder, a network share).
 * True if `target` does not exist yet (not even as a link) and its nearest existing folder,
 * with every link resolved, is inside the project.
 */
export async function safeToWrite(projectRoot: string, target: string): Promise<boolean> {
  try {
    await fs.lstat(target);
    return false; // exists: a file, a folder or a link (even a dangling one)
  } catch (e: any) {
    if (e.code !== 'ENOENT') return false;
  }
  let realRoot: string;
  try {
    realRoot = await fs.realpath(projectRoot);
  } catch {
    return false;
  }
  for (let dir = path.dirname(target); ; ) {
    try {
      return isInside(realRoot, await fs.realpath(dir));
    } catch (e: any) {
      if (e.code !== 'ENOENT') return false;
      if (await fs.lstat(dir).then(() => true, () => false)) return false; // a dangling link
      const up = path.dirname(dir);
      if (up === dir) return false;
      dir = up;
    }
  }
}

export function restoreTarget(projectRoot: string, rel: string): string | undefined {
  if (!rel || path.isAbsolute(rel) || /^[A-Za-z]:/.test(rel)) return undefined;
  const root = path.resolve(projectRoot);
  const target = path.resolve(root, rel);
  const inside = path.relative(root, target);
  if (!inside || inside.startsWith('..') || path.isAbsolute(inside)) return undefined;
  return target;
}
