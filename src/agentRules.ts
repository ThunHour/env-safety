/**
 * Writes "don't touch secrets" rules for AI agents, generated from the active secret patterns.
 * These are SOFT guards (an agent with shell access can try other routes); the real protection
 * is the encryption. They stop the common accidental reads.
 */
import * as fs from 'fs/promises';
import * as path from 'path';
import { DEFAULT_ALLOW, expandBraces, globToRegExp, PRESETS } from './patterns';

/** Used by the hook if its config is missing or broken: fail closed, not open. */
const FALLBACK = { patterns: PRESETS.filter((p) => p.always).flatMap((p) => p.patterns), allow: DEFAULT_ALLOW };

export const IGNORE_FILES = [
  '.cursorignore', // Cursor
  '.clineignore', // Cline
  '.geminiignore', // Gemini CLI
  '.aiexclude', // Gemini Code Assist / Android Studio
  '.codeiumignore', // Windsurf / Codeium
  '.aiderignore', // Aider
];

const BEGIN = '# >>> env-lock (managed, do not edit) >>>';
const END = '# <<< env-lock <<<';

export const HOOK_REL_PATH = '.claude/hooks/env-guard.js';
export const HOOK_CONFIG_REL_PATH = '.claude/hooks/env-guard.json';
const HOOK_COMMAND = `node "$CLAUDE_PROJECT_DIR/${HOOK_REL_PATH}"`;
const HOOK_MATCHER = 'Read|Edit|MultiEdit|Write|NotebookEdit|Bash|PowerShell|Grep';

/** Claude Code PreToolUse hook. Exit code 2 blocks the tool call and shows stderr to the model. */
export function guardScript(): string {
  return `#!/usr/bin/env node
// Managed by the env-lock VS Code extension. Patterns live in env-guard.json next to this file.
// Claude Code PreToolUse hook: blocks tool calls that reference protected secret files.
const fs = require('fs');
const path = require('path');
const globToRegExp = ${globToRegExp.toString()};
const expandBraces = ${expandBraces.toString()};

// Missing or broken config (e.g. deleted by an agent): fall back to the built-in patterns, never allow everything.
const FALLBACK = ${JSON.stringify(FALLBACK)};
const compile = (globs) => globs.flatMap((g) => { try { return expandBraces(g); } catch { return []; } })
  .flatMap((g) => { try { return [[g, globToRegExp(g)]]; } catch { return []; } });
let cfg;
try { cfg = JSON.parse(fs.readFileSync(path.join(__dirname, 'env-guard.json'), 'utf8')); } catch { cfg = FALLBACK; }
if (!cfg || !Array.isArray(cfg.patterns) || !Array.isArray(cfg.allow)) cfg = FALLBACK;
const secretPairs = compile(cfg.patterns);
const patterns = secretPairs.map((p) => p[0]);
const secretRes = secretPairs.map((p) => p[1]);
const allowRes = compile(cfg.allow).map((p) => p[1]);
// concrete sample names, used to test wildcard arguments such as "cat .e*"
const examples = patterns.map((p) =>
  p.replace(/^\\.?\\//, '').replace(/\\*\\*\\//g, '').replace(/\\*\\*/g, 'x').replace(/[*?]/g, 'x').replace(/\\[[^\\]]*\\]/g, 'x')
);
const norm = (s) => s.replace(/\\\\/g, '/').replace(/^["'\`]+|["'\`]+$/g, '');
const allowed = (p) => allowRes.some((r) => r.test(p));

function isSecret(arg) {
  const p = norm(arg);
  if (!p || p.endsWith('.locked')) return false;
  if (/[*?[{]/.test(p)) {
    if (!/[^*?/.[\\]{}]/.test(p)) return false; // bare wildcard like "*"
    let r;
    try { r = globToRegExp(p); } catch { return true; } // too complex to check: block rather than guess
    return examples.some((e) => r.test(e) && !allowed(e));
  }
  return !allowed(p) && secretRes.some((r) => r.test(p));
}

let raw = '';
process.stdin.on('data', (c) => (raw += c));
process.stdin.on('end', () => {
  let input;
  try { input = JSON.parse(raw); } catch { process.exit(0); }
  const t = (input && input.tool_input) || {};
  const args = [];
  if (typeof t.command === 'string') args.push(...t.command.split(/[\\s;|&<>()=\`$"',]+/));
  for (const f of ['file_path', 'notebook_path', 'path', 'glob']) if (typeof t[f] === 'string') args.push(t[f]);
  const hit = args.find((a) => a && isSecret(a));
  if (hit) {
    process.stderr.write(
      'Blocked by env-lock: ' + (input.tool_name || 'tool') + ' references a protected secret file (' + norm(hit) + '). ' +
      'Secrets are off-limits to AI agents. Use an example/template file or ask the user for non-secret values.\\n'
    );
    process.exit(2);
  }
  process.exit(0);
});
`;
}

async function readOr(file: string, fallback: string): Promise<string> {
  try {
    return await fs.readFile(file, 'utf8');
  } catch (e: any) {
    if (e.code === 'ENOENT') return fallback;
    throw e;
  }
}

async function writeIfChanged(file: string, content: string, changed: string[]) {
  if ((await readOr(file, '\u0000')) === content) return;
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.writeFile(file, content, 'utf8');
  changed.push(file);
}

/** gitignore-style lines (gitignore has no brace expansion). */
function ignoreLines(patterns: string[], allow: string[]): string[] {
  const clean = (p: string) => p.replace(/\\/g, '/').replace(/^\.\//, '');
  return [
    ...patterns.flatMap(expandBraces).map(clean),
    ...allow.flatMap(expandBraces).map((a) => '!' + clean(a)),
  ];
}

function upsertBlock(existing: string, lines: string[]): string {
  const block = [BEGIN, ...lines, END].join('\n');
  const start = existing.indexOf(BEGIN);
  const end = existing.indexOf(END);
  if (start >= 0 && end > start) return existing.slice(0, start) + block + existing.slice(end + END.length);
  if (!existing) return block + '\n';
  return existing + (existing.endsWith('\n') ? '\n' : '\n\n') + block + '\n';
}

/** Claude permission rule paths: "**​/x" stays, root-relative "a/b" becomes "./a/b". */
function claudeRules(patterns: string[]): string[] {
  const rules: string[] = [];
  for (const p of patterns.flatMap(expandBraces)) {
    const g = p.replace(/\\/g, '/');
    const rel = g.startsWith('**/') || g.startsWith('./') ? g : './' + g.replace(/^\//, '');
    rules.push(`Read(${rel})`, `Edit(${rel})`);
  }
  return rules;
}

async function applyClaude(root: string, patterns: string[], allow: string[], changed: string[]) {
  const cfgFile = path.join(root, HOOK_CONFIG_REL_PATH);
  let previous: string[] = [];
  try {
    previous = JSON.parse(await readOr(cfgFile, '{}')).managedDeny ?? [];
  } catch {
    /* ignore */
  }

  const file = path.join(root, '.claude', 'settings.json');
  const raw = await readOr(file, '');
  let json: any = {};
  if (raw.trim()) {
    try {
      json = JSON.parse(raw);
    } catch {
      throw new Error(`Could not parse ${file}; fix it or add the deny rules by hand.`);
    }
  }
  const managed = claudeRules(patterns);
  json.permissions ??= {};
  const deny: string[] = (json.permissions.deny ?? []).filter((r: string) => !previous.includes(r) || managed.includes(r));
  for (const r of managed) if (!deny.includes(r)) deny.push(r);
  json.permissions.deny = deny;
  json.hooks ??= {};
  json.hooks.PreToolUse ??= [];
  const existing = json.hooks.PreToolUse.find((h: any) => JSON.stringify(h).includes('env-guard.js'));
  if (existing) existing.matcher = HOOK_MATCHER;
  else json.hooks.PreToolUse.push({ matcher: HOOK_MATCHER, hooks: [{ type: 'command', command: HOOK_COMMAND }] });

  await writeIfChanged(file, JSON.stringify(json, null, 2) + '\n', changed);
  await writeIfChanged(path.join(root, HOOK_REL_PATH), guardScript(), changed);
  await writeIfChanged(cfgFile, JSON.stringify({ patterns, allow, managedDeny: managed }, null, 2) + '\n', changed);
}

/** Applies all agent rules under a workspace root. Returns the files it created or changed. */
export async function applyAgentRules(root: string, patterns: string[], allow: string[]): Promise<string[]> {
  const changed: string[] = [];
  const lines = ignoreLines(patterns, allow);
  for (const name of IGNORE_FILES) {
    const file = path.join(root, name);
    await writeIfChanged(file, upsertBlock(await readOr(file, ''), lines), changed);
  }
  await applyClaude(root, patterns, allow, changed);
  return changed;
}
