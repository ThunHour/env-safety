/**
 * Environments present in a folder's dotenv files: ".env.production", ".env.test.local",
 * "staging.env" → production, staging, test.
 */
export function dotenvModes(names: string[]): string[] {
  const modes = new Set<string>();
  for (const n of names) {
    let m = /^\.env\.(.+?)(\.local)?$/.exec(n);
    if (m && m[1] !== 'local') modes.add(m[1]);
    else if ((m = /^([^.].*)\.env$/.exec(n))) modes.add(m[1]);
  }
  return [...modes].sort();
}

/**
 * Which files "Run with secrets" loads, lowest precedence first (like Next.js and Vite):
 * .env, .envrc, .env.<mode>, <mode>.env, .env.local, .env.<mode>.local.
 * Without a mode only .env, .envrc and .env.local: before 0.7.2 every .env.* file in the folder was
 * merged, so .env.production silently overrode .env and a development run got PRODUCTION keys
 * (found by red-team test T11).
 */
export function dotenvPlan(names: string[], mode?: string): string[] {
  const order = ['.env', '.envrc', ...(mode ? [`.env.${mode}`, `${mode}.env`] : []), '.env.local', ...(mode ? [`.env.${mode}.local`] : [])];
  return order.filter((n) => names.includes(n));
}

/** Minimal dotenv parser: KEY=value, export prefix, quotes, multi-line quoted values, # comments. */
export function parseDotenv(src: string): Record<string, string> {
  const out: Record<string, string> = {};
  const lines = src.replace(/\r\n?/g, '\n').split('\n');
  const re = /^\s*(?:export\s+)?([A-Za-z_][\w.-]*)\s*=\s*(.*)$/;

  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(re);
    if (!m) continue;
    let v = m[2].trim();
    const q = v[0];
    if (q === '"' || q === "'" || q === '`') {
      // Scan line by line and join once: re-scanning (or appending to) one growing string made an
      // unclosed quote quadratic (a planted 0.8 MB .env.local took 54 s and froze VS Code).
      const parts: string[] = [];
      let line = v.slice(1);
      let end: number;
      for (;;) {
        end = findClose(line, q);
        if (end >= 0 || i + 1 >= lines.length) break;
        parts.push(line);
        line = lines[++i];
      }
      parts.push(end < 0 ? line : line.slice(0, end));
      v = parts.join('\n');
      if (q === '"') {
        const map: Record<string, string> = { n: '\n', r: '\r', t: '\t', '"': '"', '\\': '\\' };
        v = v.replace(/\\([nrt"\\])/g, (_, c: string) => map[c]);
      }
    } else {
      const hash = v.search(/(^|\s)#/);
      if (hash >= 0) v = v.slice(0, hash).trim();
    }
    out[m[1]] = v;
  }
  return out;
}

/**
 * Index of the closing quote in one line, or -1. A "\" at the very end of a line escapes the "\n"
 * that joins it to the next line, so every line can be scanned from its start.
 */
function findClose(s: string, q: string): number {
  for (let i = 0; i < s.length; i++) {
    if (q === '"' && s[i] === '\\') {
      i++;
      continue;
    }
    if (s[i] === q) return i;
  }
  return -1;
}
