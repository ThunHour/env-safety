/**
 * Env Safety was called Env Lock before 0.8.0. Its keyring and vaults lived in ~/.env-lock and its
 * settings were envLock.*. This copies the folder once, so your existing keys and locked files keep
 * working. File formats did not change (they still say "env-lock" inside, on purpose).
 *
 * No VS Code dependency, so it is unit-testable with plain Node.
 */
import * as fs from 'fs/promises';
import * as os from 'os';
import * as path from 'path';

export const LEGACY_HOME_DIR = '.env-lock';
export const HOME_DIR = '.env-safety';
export const LEGACY_SECTION = 'envLock';

export type MigrateResult = 'none' | 'migrated' | 'exists';

/**
 * Copies ~/.env-lock to ~/.env-safety if only the old one exists. The old folder is KEPT, as a
 * backup. Never follows a link: a ~/.env-lock that is a link (to a folder an agent prepared) is ignored.
 */
export async function migrateHome(home = os.homedir()): Promise<MigrateResult> {
  const from = path.join(home, LEGACY_HOME_DIR);
  const to = path.join(home, HOME_DIR);
  if (await fs.lstat(to).then(() => true, () => false)) return 'exists';
  let st;
  try {
    st = await fs.lstat(from);
  } catch {
    return 'none';
  }
  if (!st.isDirectory()) return 'none';
  // Copy to a temporary name, then rename: a crash never leaves a half-copied ~/.env-safety.
  const tmp = to + '.migrating';
  await fs.rm(tmp, { recursive: true, force: true });
  await fs.cp(from, tmp, { recursive: true, errorOnExist: true, force: false, verbatimSymlinks: true });
  await fs.rename(tmp, to);
  return 'migrated';
}
