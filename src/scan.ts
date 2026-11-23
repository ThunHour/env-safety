/**
 * Lists a workspace folder's files without VS Code's search (no VS Code dependency, unit-testable).
 *
 * vscode.workspace.findFiles honours .ignore / .rgignore files and search/files.exclude settings,
 * all of which live in the project where an agent can write them: red-team test T25 hid a .env
 * file from Env Safety that way, so it was never locked. This walk only skips what YOUR (user-level)
 * envSafety.exclude says, never follows links into other folders, and stops at fixed limits so a
 * huge planted tree cannot hang VS Code.
 */
import * as fs from 'fs/promises';
import * as path from 'path';
import { matchesAny } from './patterns';

export interface ScanResult {
  /** Paths relative to the root, "/"-separated: regular files and links (links are reported, never followed). */
  files: string[];
  /** true if a limit was hit: the list is incomplete. */
  truncated: boolean;
}

/**
 * Build output folders: generated, often huge (Rust target/, .next/), but a build step can copy a
 * secret into them (dist/.env, red-team X5). They are walked AFTER everything else, with their own
 * budget, so a huge (or planted) output tree can never use up the budget of the real project.
 */
export const OUTPUT_DIRS = ['**/{build,dist,out,target,.next,.nuxt,.output}/**'];

export async function scanFiles(
  root: string,
  exclude: string[],
  {
    maxEntries = 200_000,
    maxDepth = 64,
    later = OUTPUT_DIRS,
    laterEntries = 100_000,
  }: { maxEntries?: number; maxDepth?: number; later?: string[]; laterEntries?: number } = {}
): Promise<ScanResult> {
  const files: string[] = [];
  let seen = 0;
  let truncated = false;
  const deferred: Array<{ rel: string; depth: number }> = [];
  let deferring = true;
  const walk = async (rel: string, depth: number): Promise<void> => {
    if (truncated) return;
    if (depth > maxDepth) {
      truncated = true;
      return;
    }
    let entries;
    try {
      entries = await fs.readdir(path.join(root, rel), { withFileTypes: true });
    } catch {
      return; // unreadable folder: skip
    }
    for (const d of entries) {
      if (++seen > maxEntries) {
        truncated = true;
        return;
      }
      const r = rel ? `${rel}/${d.name}` : d.name;
      if (d.isDirectory()) {
        // "**/node_modules/**" matches "node_modules/x": test a path inside the folder.
        if (matchesAny(`${r}/x`, exclude)) continue;
        if (deferring && matchesAny(`${r}/x`, later)) deferred.push({ rel: r, depth: depth + 1 });
        else await walk(r, depth + 1);
      } else if (d.isFile() || d.isSymbolicLink()) {
        files.push(r);
      }
    }
  };
  await walk('', 0);
  // Second pass: build output folders, with a budget of their own.
  deferring = false;
  seen = 0;
  const mainTruncated = truncated;
  truncated = false;
  maxEntries = laterEntries;
  for (const d of deferred) await walk(d.rel, d.depth);
  return { files, truncated: mainTruncated || truncated };
}
