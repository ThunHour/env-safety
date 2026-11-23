/**
 * Security policy that does not depend on VS Code (unit-testable).
 *
 * A project's .vscode/settings.json lives INSIDE the project, where any AI agent can write. So it
 * may only ever ADD protection (more secret patterns / presets). Every setting that could weaken
 * protection is read from the user's own settings only.
 */

/** Settings a project may NOT override: they are read from user settings (or the default) only. */
export const SECURE_KEYS = [
  'allowList',
  'exclude',
  'storage',
  'autoLockMinutes',
  'confirmUnlockToDisk',
  'agentExtensions',
  'agentCommands',
  'lockOnStartup',
  'lockWhenAgentStarts',
  'lockOnClose',
  'keyringPath',
  'vaultPath',
  'keyFile',
] as const;

/** Settings a project may extend (union with the user's value), never shrink. */
export const ADDITIVE_KEYS = ['presets', 'customPatterns'] as const;

/**
 * User settings compared with the values you approved. The additive ones are included: a project
 * can only add to them, but the USER value (in an ordinary file an agent can edit) can shrink.
 */
export const REVIEWED_KEYS = [...SECURE_KEYS, ...ADDITIVE_KEYS] as const;

export interface Inspected<T> {
  defaultValue?: T;
  globalValue?: T;
  workspaceValue?: T;
  workspaceFolderValue?: T;
}

/** User value, else default. Project (workspace / folder) values are ignored. */
export function secureValue<T>(i: Inspected<T> | undefined, fallback: T): T {
  return (i?.globalValue ?? i?.defaultValue ?? fallback) as T;
}

/** User value (else default) plus anything the project adds. */
export function additiveValue(i: Inspected<string[]> | undefined, fallback: string[], extraFolderValues: string[][] = []): string[] {
  const base = i?.globalValue ?? i?.defaultValue ?? fallback;
  return [...new Set([...base, ...(i?.workspaceValue ?? []), ...(i?.workspaceFolderValue ?? []), ...extraFolderValues.flat()])];
}

/**
 * Parses a VS Code settings file (JSON with comments and trailing commas). undefined if it cannot.
 * Needed because VS Code drops application/machine-scoped values from a project's settings before
 * an extension can inspect them: to TELL you a project tried to weaken Env Lock, it must read the
 * file itself (red-team test T07).
 */
export function parseJsonc(text: string): Record<string, unknown> | undefined {
  let out = '';
  let inStr = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inStr) {
      out += c;
      if (c === '\\') out += text[++i] ?? '';
      else if (c === '"') inStr = false;
    } else if (c === '"') {
      inStr = true;
      out += c;
    } else if (c === '/' && text[i + 1] === '/') {
      while (i < text.length && text[i] !== '\n') i++;
      out += '\n';
    } else if (c === '/' && text[i + 1] === '*') {
      const end = text.indexOf('*/', i + 2);
      i = end < 0 ? text.length : end + 1;
    } else out += c;
  }
  try {
    const j = JSON.parse(out.replace(/,(\s*[}\]])/g, '$1'));
    return j && typeof j === 'object' && !Array.isArray(j) ? j : undefined;
  } catch {
    return undefined;
  }
}

/** Keys whose project value differs from the value actually used (i.e. that we ignored). */
export function ignoredOverrides(inspects: Record<string, Inspected<unknown> | undefined>): string[] {
  const out: string[] = [];
  for (const [key, i] of Object.entries(inspects)) {
    if (!i) continue;
    const used = JSON.stringify(i.globalValue ?? i.defaultValue);
    for (const v of [i.workspaceValue, i.workspaceFolderValue]) {
      if (v !== undefined && JSON.stringify(v) !== used) {
        out.push(key);
        break;
      }
    }
  }
  return out;
}

/**
 * Which of `next` weakens protection compared to `prev` (the values you approved). User settings
 * live in a plain file (%APPDATA%/Code/User/settings.json) that an agent can edit too, so weakening
 * changes need your confirmation; strengthening ones are accepted silently.
 */
export function weakenings(prev: Record<string, unknown>, next: Record<string, unknown>): string[] {
  const out: string[] = [];
  const arr = (v: unknown) => (Array.isArray(v) ? (v as string[]) : []);
  for (const key of REVIEWED_KEYS) {
    if (!(key in prev) && !(key in next)) continue;
    const a = prev[key];
    const b = next[key];
    if (JSON.stringify(a) === JSON.stringify(b)) continue;
    let weaker: boolean;
    switch (key) {
      case 'confirmUnlockToDisk':
      case 'lockOnStartup':
      case 'lockWhenAgentStarts':
      case 'lockOnClose':
        weaker = a === true && b !== true;
        break;
      case 'autoLockMinutes': {
        const x = Number(a) || 0;
        const y = Number(b) || 0;
        weaker = x > 0 && (y === 0 || y > x); // turned off, or longer
        break;
      }
      case 'allowList': // more exceptions = fewer protected files
        weaker = arr(b).some((v) => !arr(a).includes(v));
        break;
      case 'agentExtensions':
      case 'agentCommands': // fewer agents recognised
      case 'presets': // fewer kinds of secret files ("auto" removed, a language dropped)
      case 'customPatterns': // fewer of your own secret files
        weaker = arr(a).some((v) => !arr(b).includes(v));
        break;
      case 'storage':
        weaker = a === 'vault' && b !== 'vault';
        break;
      default: // exclude, keyringPath, vaultPath, keyFile: any change can hide files or redirect keys
        weaker = true;
    }
    if (weaker) out.push(key);
  }
  return out;
}

const COMMON = ['password', 'passphrase', 'qwerty', 'letmein', 'welcome', 'iloveyou', 'admin', 'secret', '123456'];

/**
 * Why a NEW passphrase is too weak, or undefined if acceptable. The private key file can be copied
 * and attacked offline, so: at least 12 characters, and either 16+ characters (a few words) or
 * 3 kinds of characters, no long repeats, no common words as most of it.
 */
export function passphraseProblem(p: string): string | undefined {
  if (p.length < 12) return 'At least 12 characters (a few random words is best).';
  if (/(.)\1{3,}/.test(p)) return 'Avoid repeating the same character.';
  const lower = p.toLowerCase();
  for (const w of COMMON) {
    if (lower.includes(w) && lower.replace(new RegExp(w, 'g'), '').length < 8) return `Too close to "${w}".`;
  }
  const kinds = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((r) => r.test(p)).length;
  if (p.length < 16 && kinds < 3) return 'Use 16+ characters, or mix 3 of: lower case, upper case, digits, symbols.';
  return undefined;
}
