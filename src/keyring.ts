import * as fs from 'fs/promises';
import * as os from 'os';
import * as path from 'path';
import { KeyringFile, parseKeyring } from './crypto';

/** Outside every project, so it is never part of a workspace an agent works in. */
export function defaultKeyringPath(): string {
  return path.join(os.homedir(), '.env-lock', 'keyring.json');
}

export function expandHome(p: string): string {
  return p.replace(/^~(?=$|[\\/])/, os.homedir());
}

export async function readKeyring(file: string): Promise<KeyringFile | undefined> {
  let text: string;
  try {
    text = await fs.readFile(file, 'utf8');
  } catch (e: any) {
    if (e.code === 'ENOENT') return undefined;
    throw e;
  }
  return parseKeyring(text);
}

export async function writeKeyring(file: string, k: KeyringFile): Promise<void> {
  await fs.mkdir(path.dirname(file), { recursive: true });
  const tmp = file + '.tmp';
  await fs.writeFile(tmp, JSON.stringify(k, null, 2) + '\n', { encoding: 'utf8', mode: 0o600 });
  await fs.rename(tmp, file);
}
