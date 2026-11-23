/**
 * Post-quantum hybrid encryption core (no VS Code dependency, unit-testable with plain Node).
 *
 * File encryption (no passphrase needed to LOCK):
 *   ML-KEM-768 (FIPS 203)  +  X25519 (ephemeral-static)
 *      -> X-Wing style combiner: SHA3-256(ss_mlkem || ss_x25519 || ct_x25519 || pk_x25519 || label)
 *      -> HKDF-SHA256 -> AES-256-GCM (header bound as AAD)
 *   Every file gets a fresh encapsulation, so a fresh key.
 *   Secure if EITHER ML-KEM-768 OR X25519 remains unbroken.
 *
 * Private key protection (needed to UNLOCK):
 *   scrypt (N=2^17, r=8, p=1) over passphrase [+ SHA-256 of an optional key file] -> AES-256-GCM.
 */
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  KeyObject,
  randomBytes,
  scrypt,
  timingSafeEqual,
} from 'crypto';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { sha3_256 } from '@noble/hashes/sha3.js';

export const ALG = 'ML-KEM-768+X25519/HKDF-SHA256/AES-256-GCM';
const XWING_LABEL = Buffer.from('5c2e2f2f5e5c', 'hex'); // "\.//^\"
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const SEAL_KDF = { N: 2 ** 17, r: 8, p: 1 };

export class WrongPassphraseError extends Error {
  constructor() {
    super('Wrong passphrase or key file.');
    this.name = 'WrongPassphraseError';
  }
}

export class WrongKeyError extends Error {
  constructor(public readonly keyId: string) {
    super(`File was locked with a different key (${keyId}).`);
    this.name = 'WrongKeyError';
  }
}

export interface Secret {
  passphrase: string;
  keyFile?: Buffer;
}

interface Sealed {
  kdf: { name: 'scrypt'; N: number; r: number; p: number; salt: string };
  keyFile: boolean;
  iv: string;
  tag: string;
  data: string;
}

export interface KeyringFile {
  format: 'env-lock-keyring';
  v: 1;
  alg: string;
  keyId: string;
  created: string;
  public: { mlkem: string; x25519: string };
  private: Sealed;
}

export interface PublicKeys {
  keyId: string;
  mlkem: Uint8Array;
  x25519: Buffer; // raw 32 bytes
}

export interface PrivateKeys extends PublicKeys {
  mlkemSecret: Uint8Array;
  x25519Private: KeyObject;
}

const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64');
/**
 * Strings only: files are attacker-writable JSON, and Buffer.from({ length: 2e8 }) allocates 200 MB
 * and takes ~9 s (fuzzed: a planted .locked file with such a field froze unlock).
 */
const unb64 = (s: unknown) => {
  if (typeof s !== 'string' || s.length > 64 * 1024 * 1024) throw new Error('Bad base64 field.');
  return Buffer.from(s, 'base64');
};

/** GCM tags are always 16 bytes here: a truncated tag would be much easier to forge. */
const TAG_LEN = 16;
function fullTag(s: string): Buffer {
  const t = unb64(s);
  if (t.length !== TAG_LEN) throw new Error('Bad authentication tag.');
  return t;
}

// ------------------------------------------------------------------ passphrase sealing

function kdfInput(secret: Secret): Buffer {
  const pass = Buffer.from(secret.passphrase.normalize('NFKC'), 'utf8');
  if (!secret.keyFile) return pass;
  return Buffer.concat([pass, Buffer.from([0]), createHash('sha256').update(secret.keyFile).digest()]);
}

function deriveKey(secret: Secret, salt: Buffer, N: number, r: number, p: number): Promise<Buffer> {
  return new Promise((resolve, reject) =>
    scrypt(kdfInput(secret), salt, 32, { N, r, p, maxmem: 256 * N * r }, (err, key) =>
      err ? reject(err) : resolve(key)
    )
  );
}

async function seal(plain: Buffer, secret: Secret, aad: Buffer): Promise<Sealed> {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = await deriveKey(secret, salt, SEAL_KDF.N, SEAL_KDF.r, SEAL_KDF.p);
  const c = createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(aad);
  const data = Buffer.concat([c.update(plain), c.final()]);
  return {
    kdf: { name: 'scrypt', ...SEAL_KDF, salt: b64(salt) },
    keyFile: !!secret.keyFile,
    iv: b64(iv),
    tag: b64(c.getAuthTag()),
    data: b64(data),
  };
}

async function unseal(s: Sealed, secret: Secret, aad: Buffer): Promise<Buffer> {
  const { N, r, p } = s.kdf;
  // Too weak = easy offline attack; too strong = a planted keyring can make "Trust this keyring"
  // allocate gigabytes and hang VS Code. Env Lock writes N=2^17, r=8, p=1 (128 MiB).
  if (s.kdf.name !== 'scrypt' || !(N >= 2 ** 14 && N <= 2 ** 18 && r >= 1 && r <= 8 && p >= 1 && p <= 4)) {
    throw new Error('Refusing unsafe KDF parameters in keyring.');
  }
  if (s.keyFile && !secret.keyFile) throw new WrongPassphraseError();
  const key = await deriveKey(
    { passphrase: secret.passphrase, keyFile: s.keyFile ? secret.keyFile : undefined },
    unb64(s.kdf.salt),
    N,
    r,
    p
  );
  const d = createDecipheriv('aes-256-gcm', key, unb64(s.iv), { authTagLength: TAG_LEN });
  d.setAAD(aad);
  try {
    d.setAuthTag(fullTag(s.tag));
    return Buffer.concat([d.update(unb64(s.data)), d.final()]);
  } catch {
    throw new WrongPassphraseError();
  }
}

// ------------------------------------------------------------------ keyring

function x25519Raw(k: KeyObject): Buffer {
  return (k.export({ format: 'der', type: 'spki' }) as Buffer).subarray(X25519_SPKI_PREFIX.length);
}

function x25519FromRaw(raw: Buffer): KeyObject {
  if (raw.length !== 32) throw new Error('Bad X25519 public key.');
  return createPublicKey({ key: Buffer.concat([X25519_SPKI_PREFIX, raw]), format: 'der', type: 'spki' });
}

function keyIdOf(mlkemPub: Uint8Array, x25519Pub: Buffer): string {
  return createHash('sha256').update(mlkemPub).update(x25519Pub).digest('hex').slice(0, 16);
}

const keyringAad = (keyId: string) => Buffer.from(`env-lock-keyring:v1:${keyId}`);

export async function createKeyring(secret: Secret): Promise<KeyringFile> {
  const kem = ml_kem768.keygen();
  const x = generateKeyPairSync('x25519');
  const xPub = x25519Raw(x.publicKey);
  const keyId = keyIdOf(kem.publicKey, xPub);
  const priv = JSON.stringify({
    mlkem: b64(kem.secretKey),
    x25519: (x.privateKey.export({ format: 'der', type: 'pkcs8' }) as Buffer).toString('base64'),
  });
  return {
    format: 'env-lock-keyring',
    v: 1,
    alg: ALG,
    keyId,
    created: new Date().toISOString(),
    public: { mlkem: b64(kem.publicKey), x25519: b64(xPub) },
    private: await seal(Buffer.from(priv, 'utf8'), secret, keyringAad(keyId)),
  };
}

export function parseKeyring(text: string): KeyringFile {
  const k = JSON.parse(text) as KeyringFile;
  if (k.format !== 'env-lock-keyring' || k.v !== 1 || k.alg !== ALG) throw new Error('Unsupported keyring format.');
  const pub = publicKeys(k);
  if (keyIdOf(pub.mlkem, pub.x25519) !== k.keyId) throw new Error('Keyring public key does not match its id.');
  return k;
}

export function publicKeys(k: KeyringFile): PublicKeys {
  return { keyId: k.keyId, mlkem: unb64(k.public.mlkem), x25519: unb64(k.public.x25519) };
}

export const keyringNeedsKeyFile = (k: KeyringFile) => k.private.keyFile;

export async function openKeyring(k: KeyringFile, secret: Secret): Promise<PrivateKeys> {
  const priv = JSON.parse((await unseal(k.private, secret, keyringAad(k.keyId))).toString('utf8'));
  return {
    ...publicKeys(k),
    mlkemSecret: unb64(priv.mlkem),
    x25519Private: createPrivateKey({ key: unb64(priv.x25519), format: 'der', type: 'pkcs8' }),
  };
}

/** Re-protects the same key pair with a new passphrase / key file. Locked files stay valid. */
export async function resealKeyring(k: KeyringFile, oldSecret: Secret, newSecret: Secret): Promise<KeyringFile> {
  const plain = await unseal(k.private, oldSecret, keyringAad(k.keyId));
  return { ...k, private: await seal(plain, newSecret, keyringAad(k.keyId)) };
}

export function generateKeyFile(): Buffer {
  return randomBytes(64);
}

// ------------------------------------------------------------------ file encryption

interface LockedHeader {
  format: 'env-lock';
  v: 2;
  alg: string;
  keyId: string;
  kem: { mlkem: string; x25519: string };
  iv: string;
}

function header(p: LockedHeader): LockedHeader {
  // fixed key order: this exact JSON is the AAD
  return { format: p.format, v: p.v, alg: p.alg, keyId: p.keyId, kem: { mlkem: p.kem.mlkem, x25519: p.kem.x25519 }, iv: p.iv };
}

function fileKey(ssM: Uint8Array, ssX: Buffer, ctX: Buffer, pkX: Buffer, keyId: string): Buffer {
  // SHA3 via @noble/hashes: VS Code's Electron (BoringSSL) has no 'sha3-256' in node:crypto.
  const ss = sha3_256.create().update(ssM).update(ssX).update(ctX).update(pkX).update(XWING_LABEL).digest();
  return Buffer.from(hkdfSync('sha256', ss, Buffer.alloc(0), `env-lock v2 file key ${keyId}`, 32));
}

/** Encrypts with the PUBLIC key only. */
export function encryptFile(plain: Buffer, pub: PublicKeys): string {
  const { cipherText: ctM, sharedSecret: ssM } = ml_kem768.encapsulate(pub.mlkem);
  const eph = generateKeyPairSync('x25519');
  const ctX = x25519Raw(eph.publicKey);
  const ssX = diffieHellman({ privateKey: eph.privateKey, publicKey: x25519FromRaw(pub.x25519) });
  const key = fileKey(ssM, ssX, ctX, pub.x25519, pub.keyId);
  const h = header({
    format: 'env-lock',
    v: 2,
    alg: ALG,
    keyId: pub.keyId,
    kem: { mlkem: b64(ctM), x25519: b64(ctX) },
    iv: b64(randomBytes(12)),
  });
  const c = createCipheriv('aes-256-gcm', key, unb64(h.iv));
  c.setAAD(Buffer.from(JSON.stringify(h)));
  const data = Buffer.concat([c.update(plain), c.final()]);
  return JSON.stringify({ ...h, tag: b64(c.getAuthTag()), data: b64(data) }, null, 2) + '\n';
}

export function isLockedFile(text: string): boolean {
  try {
    const p = JSON.parse(text);
    return p.format === 'env-lock' && p.v === 2;
  } catch {
    return false;
  }
}

export function lockedKeyId(text: string): string | undefined {
  try {
    return JSON.parse(text).keyId;
  } catch {
    return undefined;
  }
}

export function decryptFile(text: string, priv: PrivateKeys): Buffer {
  let p: LockedHeader & { tag: string; data: string };
  try {
    p = JSON.parse(text);
  } catch {
    throw new Error('Not an env-lock file.');
  }
  if (p.format !== 'env-lock' || p.v !== 2 || p.alg !== ALG) throw new Error('Unsupported env-lock file format.');
  if (p.keyId !== priv.keyId) throw new WrongKeyError(p.keyId);
  const h = header(p);
  const ctX = unb64(h.kem.x25519);
  try {
    const ssM = ml_kem768.decapsulate(unb64(h.kem.mlkem), priv.mlkemSecret);
    const ssX = diffieHellman({ privateKey: priv.x25519Private, publicKey: x25519FromRaw(ctX) });
    const d = createDecipheriv('aes-256-gcm', fileKey(ssM, ssX, ctX, priv.x25519, priv.keyId), unb64(h.iv), {
      authTagLength: TAG_LEN,
    });
    d.setAAD(Buffer.from(JSON.stringify(h)));
    d.setAuthTag(fullTag(p.tag));
    return Buffer.concat([d.update(unb64(p.data)), d.final()]);
  } catch {
    throw new Error('Locked file is corrupted or was modified.');
  }
}

// ================================================================= authenticity (signing)
//
// Locking only needs the PUBLIC key, which is not secret: anyone (an AI agent too) can create a
// file that decrypts fine. To prove a locked file was made by YOUR Env Lock, it carries an
// HMAC-SHA256 made with a random signing key that never touches disk in readable form
// (it is kept in the OS credential store via VS Code SecretStorage).

export type SignState = 'valid' | 'invalid' | 'unsigned';

export interface SignCheck {
  state: SignState;
  signedAt: number; // ms since epoch, from inside the signed data (0 if unsigned)
}

const MAC_V = 2;

/**
 * `bind` says WHICH file this is ("file:<rel path>" or "vault:<id>:<rel path>"). It is not stored:
 * the verifier recomputes it from where the file actually is, so a signed file renamed or copied
 * to another name (e.g. production keys moved onto .env) no longer verifies.
 */
const macOf = (macKey: Buffer, body: object, bind: string) =>
  createHmac('sha256', macKey).update(`env-lock-mac:v${MAC_V}\0${bind}\0`).update(JSON.stringify(body)).digest('base64');

export function newMacKey(): Buffer {
  return randomBytes(32);
}

/**
 * The signing key, derived from YOUR private key (so only someone with your passphrase can make it).
 * Locking needs no passphrase, so a copy is kept in the OS credential store; but that store is
 * wiped when Env Lock is uninstalled (red-team test T30: an agent can do it with two `code`
 * commands), and a random key would then be lost for good: every one of your files would look
 * forged. A derived key comes back the next time you unlock.
 */
export function macKeyFromPrivate(priv: PrivateKeys): Buffer {
  const x = priv.x25519Private.export({ format: 'der', type: 'pkcs8' }) as Buffer;
  const ikm = Buffer.concat([Buffer.from(priv.mlkemSecret), x]);
  try {
    return Buffer.from(hkdfSync('sha256', ikm, Buffer.alloc(0), `env-lock signing key v1 ${priv.keyId}`, 32));
  } finally {
    ikm.fill(0);
    x.fill(0);
  }
}

/** Adds `macv`, `signedAt` and `mac` to a locked file (in-place .locked file or vault blob). */
export function signLocked(text: string, macKey: Buffer, bind: string, signedAt = Date.now()): string {
  const { mac: _m, macv: _v, signedAt: _s, ...rest } = JSON.parse(text);
  const body = { ...rest, macv: MAC_V, signedAt };
  return JSON.stringify({ ...body, mac: macOf(macKey, body, bind) }, null, 2) + '\n';
}

/** Valid if any of the keys signed it (the stored key, and the key derived from your private key). */
export function verifyLocked(text: string, macKey: Buffer | Buffer[] | undefined, bind: string): SignCheck {
  const keys = (Array.isArray(macKey) ? macKey : [macKey]).filter((k): k is Buffer => !!k);
  if (keys.length > 1) {
    let last: SignCheck = { state: 'invalid', signedAt: 0 };
    for (const k of keys) {
      last = verifyLocked(text, k, bind);
      if (last.state !== 'invalid') return last;
    }
    return last;
  }
  return verifyOne(text, keys[0], bind);
}

function verifyOne(text: string, macKey: Buffer | undefined, bind: string): SignCheck {
  let j: any;
  try {
    j = JSON.parse(text);
  } catch {
    return { state: 'invalid', signedAt: 0 };
  }
  const { mac, ...body } = j;
  // No mac, or an older unbound mac (Env Lock 0.3.0): needs the user's consent, like any unsigned file.
  if (typeof mac !== 'string' || body.macv !== MAC_V) return { state: 'unsigned', signedAt: 0 };
  if (!macKey) return { state: 'invalid', signedAt: 0 };
  const want = Buffer.from(macOf(macKey, body, bind), 'base64');
  const got = Buffer.from(mac, 'base64');
  const ok = got.length === want.length && timingSafeEqual(got, want);
  return ok ? { state: 'valid', signedAt: Number(body.signedAt) || 0 } : { state: 'invalid', signedAt: 0 };
}

/** Best effort: overwrite secret key bytes once they are no longer needed. */
export function wipePrivate(priv: PrivateKeys | undefined) {
  priv?.mlkemSecret.fill(0);
}
