/**
 * Finding COPIES of a secret after it was locked (red-team X2, X7).
 *
 * While a secret is unlocked, an agent can copy it somewhere Env Safety does not lock: rename `.env`
 * to `.env.example` (allow-listed), hard-link it to `notes.txt`, paste a key into `config.js`.
 * Locking then removes `.env`, but the copy stays readable for every later agent session.
 *
 * At lock time Env Safety remembers a KEYED hash (HMAC with your signing key) of each secret value
 * and of each whole secret file, plus the lengths of those values. Later it hashes only the tokens
 * of matching length in other files and compares. The records never hold a plain hash of a secret
 * (a short password's plain SHA-256 could be guessed), and nothing here needs the passphrase.
 *
 * No VS Code dependency, so it is unit-testable with plain Node.
 */
import { createHmac } from 'crypto';
import { parseDotenv } from './dotenv';

/** Shorter values are too common (and too guessable) to fingerprint. */
export const MIN_SECRET_LEN = 12;
const MAX_SECRET_LEN = 4096;
/** At most this many fingerprints are kept (newest first). */
export const MAX_STAMPS = 4000;

export interface SecretPrints {
  stamps: string[];
  lengths: number[];
}

export const stamp = (macKey: Buffer, value: string) =>
  createHmac('sha256', macKey).update('env-lock-copy\0').update(value).digest('base64').slice(0, 22);

const clean = (v: string) => v.trim().replace(/^["'`]|["'`]$/g, '');
/**
 * Worth fingerprinting: long enough, no spaces, and shaped like a secret (letters mixed with digits,
 * or mixed case). Plain words, numbers and URLs without credentials ("https://api.example.com")
 * are config, not secrets, and appear all over a project: they would only raise false alarms.
 */
export function looksSecret(v: string): boolean {
  if (v.length < MIN_SECRET_LEN || v.length > MAX_SECRET_LEN || /\s/.test(v)) return false;
  const url = /^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i.exec(v);
  if (url) return url[1].includes('@'); // only URLs carrying user:password@
  const letter = /[A-Za-z]/.test(v);
  return (letter && /\d/.test(v)) || (/[a-z]/.test(v) && /[A-Z]/.test(v));
}
const usable = looksSecret;

/** Values worth fingerprinting in one secret file: dotenv values and "key: value" / "key = value" lines. */
export function secretValues(text: string): string[] {
  const out = new Set<string>();
  let env: Record<string, string> = {};
  try {
    env = parseDotenv(text);
  } catch {
    /* not dotenv */
  }
  for (const v of Object.values(env)) if (usable(v)) out.add(v);
  // YAML / properties / JSON / TOML: the value after the first ":" or "=" of a line.
  for (const line of text.split(/\r?\n/)) {
    const m = /^[^:=]{1,200}[:=]\s*(.+?)\s*,?\s*$/.exec(line);
    if (m) {
      const v = clean(m[1]);
      if (usable(v)) out.add(v);
    }
  }
  return [...out];
}

/** Fingerprints of one secret file (its values and its whole content). */
export function printsOf(macKey: Buffer, text: string): SecretPrints {
  const values = secretValues(text);
  const stamps = values.map((v) => stamp(macKey, v));
  const whole = text.trim();
  if (whole.length >= MIN_SECRET_LEN) stamps.push(stamp(macKey, 'file\0' + whole));
  return { stamps, lengths: [...new Set(values.map((v) => v.length))] };
}

/** Merges new fingerprints in front of the old ones, capped. */
export function mergePrints(old: SecretPrints | undefined, add: SecretPrints): SecretPrints {
  const stamps = [...new Set([...add.stamps, ...(old?.stamps ?? [])])].slice(0, MAX_STAMPS);
  const lengths = [...new Set([...add.lengths, ...(old?.lengths ?? [])])].sort((a, b) => a - b).slice(0, 512);
  return { stamps, lengths };
}

/**
 * true if `text` contains a remembered secret value, or IS a remembered secret file. Only tokens
 * whose length matches a remembered value are hashed, so scanning a source file is cheap.
 */
export function containsSecret(macKey: Buffer, text: string, prints: SecretPrints, known?: Set<string>): boolean {
  if (!prints.stamps.length) return false;
  const set = known ?? new Set(prints.stamps);
  const whole = text.trim();
  if (whole.length >= MIN_SECRET_LEN && set.has(stamp(macKey, 'file\0' + whole))) return true;
  const lengths = new Set(prints.lengths);
  const tried = new Set<string>();
  const check = (t: string) => {
    const v = clean(t);
    if (!lengths.has(v.length) || tried.has(v)) return false;
    tried.add(v);
    return set.has(stamp(macKey, v));
  };
  for (const raw of text.split(/[\s"'`,;(){}[\]<>]+/)) {
    if (raw.length < MIN_SECRET_LEN) continue;
    if (check(raw)) return true;
    // KEY=value / key:value glued together: also try what follows the first "=" or ":".
    const i = raw.search(/[=:]/);
    if (i > 0 && check(raw.slice(i + 1))) return true;
  }
  return false;
}
