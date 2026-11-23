/**
 * Which files count as secrets. Presets per language/ecosystem, auto-detected from marker files,
 * plus the user's own custom patterns. No VS Code dependency.
 *
 * NOTE: globToRegExp and expandBraces are also embedded (via toString) into the Claude Code hook,
 * so they must stay self-contained: no references to anything outside their own body.
 */

export interface Preset {
  id: string;
  label: string;
  /** Always included in "auto" mode. */
  always?: boolean;
  /** Marker globs; if any exists in the workspace, "auto" mode includes the preset. */
  detect?: string[];
  patterns: string[];
}

export const PRESETS: Preset[] = [
  {
    id: 'dotenv',
    label: 'dotenv for every framework (.env, .env.*, *.env, direnv .envrc)',
    always: true,
    patterns: ['**/.env', '**/.env.*', '**/*.env', '**/.envrc'],
  },
  {
    id: 'cloud',
    label: 'Cloud credentials (GCP/Firebase service accounts, AWS)',
    always: true,
    patterns: [
      '**/credentials.json',
      '**/service-account*.json',
      '**/serviceAccountKey*.json',
      '**/*-credentials.json',
      '**/.aws/credentials',
    ],
  },
  {
    id: 'node',
    label: 'Node.js / Next / Nest / Firebase (.npmrc, .yarnrc.yml, .runtimeconfig.json)',
    detect: ['**/package.json'],
    patterns: ['**/.npmrc', '**/.yarnrc.yml', '**/.runtimeconfig.json'],
  },
  {
    id: 'python',
    label: 'Python / Django / Flask / FastAPI (instance config, local settings, .secrets.toml)',
    detect: ['**/requirements*.txt', '**/pyproject.toml', '**/setup.py', '**/Pipfile'],
    patterns: [
      '**/.pypirc',
      '**/.streamlit/secrets.toml',
      '**/local_settings.py',
      '**/settings/local.py', // Django split settings
      '**/instance/config.py', // Flask instance folder
      '**/instance/*.cfg',
      '**/.secrets.toml', // Dynaconf
    ],
  },
  {
    id: 'ruby',
    label: 'Ruby / Rails (master.key, credentials keys)',
    detect: ['**/Gemfile'],
    patterns: ['**/config/master.key', '**/config/credentials/*.key'],
  },
  {
    id: 'php',
    label: 'PHP / Laravel / Symfony / WordPress (Passport keys, Symfony secrets key, auth.json)',
    detect: ['**/composer.json', '**/wp-config.php', '**/artisan'],
    patterns: [
      '**/auth.json',
      '**/wp-config.php',
      '**/storage/oauth-private.key', // Laravel Passport
      '**/config/secrets/*/*.decrypt.private.php', // Symfony secrets vault key
    ],
  },
  {
    id: 'java',
    label: 'Java / Spring (application-local / -secret config)',
    detect: ['**/pom.xml', '**/build.gradle', '**/build.gradle.kts'],
    patterns: [
      '**/application-local.properties',
      '**/application-local.yml',
      '**/application-local.yaml',
      '**/application-secret*.properties',
      '**/application-secret*.yml',
      '**/application-secret*.yaml',
    ],
  },
  {
    id: 'dotnet',
    label: '.NET / ASP.NET (appsettings.Development/Local.json, secrets.json, publish profiles, .pfx)',
    detect: ['**/*.csproj', '**/*.fsproj', '**/*.vbproj', '**/*.sln'],
    patterns: [
      '**/appsettings.Development.json',
      '**/appsettings.Local.json',
      '**/secrets.json',
      '**/*.pfx',
      '**/*.pubxml.user', // publish profile passwords
      '**/*.PublishSettings', // Azure publish profiles
      '**/*.publishsettings',
    ],
  },
  {
    id: 'android',
    label: 'Android / Gradle (local.properties, keystores, google-services.json)',
    detect: ['**/AndroidManifest.xml'],
    patterns: [
      '**/local.properties',
      '**/keystore.properties',
      '**/key.properties',
      '**/*.jks',
      '**/*.keystore',
      '**/google-services.json',
    ],
  },
  {
    id: 'ios',
    label: 'iOS / Apple (GoogleService-Info.plist, .p12, provisioning profiles)',
    detect: ['**/Podfile', '**/*.xcodeproj/project.pbxproj', '**/Package.swift'],
    patterns: ['**/GoogleService-Info.plist', '**/*.p12', '**/*.mobileprovision', '**/AuthKey_*.p8'],
  },
  {
    id: 'flutter',
    label: 'Flutter / Dart (key.properties, Firebase configs)',
    detect: ['**/pubspec.yaml'],
    patterns: ['**/key.properties', '**/google-services.json', '**/GoogleService-Info.plist', '**/*.jks'],
  },
  {
    id: 'go',
    label: 'Go (.netrc for private modules, config.local.*)',
    detect: ['**/go.mod'],
    patterns: ['**/.netrc', '**/config.local.yaml', '**/config.local.yml', '**/config.local.json', '**/config.local.toml'],
  },
  {
    id: 'elixir',
    label: 'Elixir / Phoenix (*.secret.exs)',
    detect: ['**/mix.exs'],
    patterns: ['**/config/*.secret.exs'],
  },
  {
    id: 'rust',
    label: 'Rust (Cargo registry credentials)',
    detect: ['**/Cargo.toml'],
    patterns: ['**/.cargo/credentials', '**/.cargo/credentials.toml'],
  },
  {
    id: 'terraform',
    label: 'Terraform (*.tfvars, state files)',
    detect: ['**/*.tf'],
    patterns: ['**/*.tfvars', '**/*.tfvars.json', '**/terraform.tfstate', '**/terraform.tfstate.backup', '**/.terraformrc'],
  },
  {
    id: 'containers',
    label: 'Docker / Kubernetes (docker config, kubeconfig, secret manifests)',
    detect: ['**/Dockerfile', '**/docker-compose*.yml', '**/compose.yaml', '**/kustomization.yaml'],
    patterns: ['**/.docker/config.json', '**/kubeconfig', '**/*.kubeconfig', '**/secret*.yaml', '**/secret*.yml'],
  },
  {
    id: 'keys',
    label: 'Private keys & certificates (*.pem, *.key, id_rsa…) — opt-in',
    patterns: ['**/*.pem', '**/*.key', '**/id_rsa', '**/id_ecdsa', '**/id_ed25519', '**/*.p12', '**/*.pfx'],
  },
];

/** File names / paths that are never treated as secrets. */
export const DEFAULT_ALLOW = ['**/.env.example', '**/.env.sample', '**/.env.template', '**/.env.dist', '**/*.example', '**/*.sample', '**/*.template'];

export const DOTENV_PATTERNS = PRESETS[0].patterns;

/** Resolves the active secret patterns. `selected` may contain "auto" and/or preset ids. */
export function resolvePatterns(selected: string[], detected: Set<string>, custom: string[]): string[] {
  const ids = new Set<string>();
  for (const s of selected) {
    if (s === 'auto') {
      for (const p of PRESETS) if (p.always || detected.has(p.id)) ids.add(p.id);
    } else ids.add(s);
  }
  ids.add('dotenv'); // dotenv is always protected
  const out = new Set<string>();
  for (const p of PRESETS) if (ids.has(p.id)) p.patterns.forEach((x) => out.add(x));
  for (const c of custom) if (c.trim() && isSafePattern(c.trim())) out.add(c.trim());
  return [...out];
}

/** false for a pattern too complex to match safely (see globToRegExp). Such patterns are skipped. */
export function isSafePattern(glob: string): boolean {
  try {
    expandBraces(glob).forEach(globToRegExp);
    return true;
  } catch {
    return false;
  }
}

/** Every built-in secret pattern, for settings that must cover all of them (e.g. local history). */
export const ALL_PRESET_PATTERNS = [...new Set(PRESETS.flatMap((p) => p.patterns))];

/** "a/{b,c}/*.{x,y}" -> 4 patterns. At most 4 groups: "{a,b}{a,b}…" would expand exponentially. */
export function expandBraces(glob: string): string[] {
  if ((glob.match(/\{/g) || []).length > 4) throw new Error('Pattern has too many {…} groups: ' + glob);
  const m = /\{([^{}]*)\}/.exec(glob);
  if (!m) return [glob];
  const before = glob.slice(0, m.index);
  const after = glob.slice(m.index + m[0].length);
  return m[1].split(',').flatMap((alt) => expandBraces(before + alt + after));
}

/**
 * Glob -> RegExp matched against a "/"-separated path. Patterns not starting with "**​/" are
 * matched at any depth too (a protected "config/app.yml" also blocks "/abs/path/config/app.yml").
 */
export function globToRegExp(glob: string): RegExp {
  let g = glob.replace(/\\/g, '/').replace(/^\.\//, '').replace(/^\//, '');
  if (!g.startsWith('**/')) g = '**/' + g;
  // A project can add patterns, so they are untrusted input to a backtracking regex engine (ReDoS):
  // "**/**/**/…" or "*a*a*a*a…" can freeze the extension host. Collapse repeated globstars, then
  // refuse what is still too complex.
  g = g.replace(/\*{3,}/g, '**').replace(/(?:\*\*\/)+/g, '**/');
  // Each segment is matched ONCE (atomically, below), so the cost is bounded by these limits.
  const segs = g.split('/');
  const tooComplex =
    g.length > 300 ||
    segs.filter((s) => s === '**').length > 3 ||
    segs.some((s) => s !== '**' && (s.match(/[*?]/g) || []).length > 3) ||
    /\{[^}]*\//.test(g); // a "/" inside {…} would span segments
  if (tooComplex) throw new Error('Pattern too complex: ' + glob);

  // One segment (no "/") -> regex source.
  const segment = (s: string) => {
    let re = '';
    let depth = 0;
    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (c === '*') {
        re += '[^/]*';
        while (s[i + 1] === '*') i++; // "**" inside a segment is just "*"
      } else if (c === '?') re += '[^/]';
      else if (c === '{') {
        re += '(?:';
        depth++;
      } else if (c === '}' && depth > 0) {
        re += ')';
        depth--;
      } else if (c === ',' && depth > 0) re += '|';
      else if (c === '[' && s.indexOf(']', i) > i + 1) {
        const end = s.indexOf(']', i);
        const body = s.slice(i + 1, end).replace(/\\/g, '\\\\');
        // never let a class match "/": the segment must not grow into the next one
        re += body.startsWith('!') || body.startsWith('^') ? '[^/' + body.slice(1) + ']' : '[' + body.replace(/\//g, '') + ']';
        i = end;
      } else re += c.replace(/[.+^$()|\\[\]{}]/g, '\\$&');
    }
    return re;
  };

  // Backtracking ACROSS segments is what made "*a*a*/*a*a*/…" exponential (4 segments: 5 s).
  // A segment cannot contain "/", so where it ends is fixed: match each wildcard segment inside a
  // lookahead and consume it with a backreference, which the engine never re-enters (an atomic group).
  let re = '';
  let group = 0;
  segs.forEach((s, i) => {
    const last = i === segs.length - 1;
    if (s === '**') {
      re += last ? '.*' : '(?:[^/]*/)*';
      return;
    }
    const src = segment(s);
    re += /[*?[{]/.test(s) ? `(?=(${src})(?:/|$))\\${++group}` : src;
    if (!last) re += '/';
  });
  return new RegExp('^' + re + '$', process.platform === 'win32' ? 'i' : '');
}

// Compiled once per glob: matchesAny runs for every file on every scan.
// (Kept out of globToRegExp, which must stay self-contained for the Claude Code hook.)
const reCache = new Map<string, RegExp[]>();

export function matchesAny(filePath: string, globs: string[]): boolean {
  const p = filePath.replace(/\\/g, '/');
  return globs.some((g) => {
    let re = reCache.get(g);
    if (!re) {
      try {
        // Braces first: "{a/b,c}/x" spans segments, which globToRegExp handles only after expansion.
        // (One regex per alternative: joining them would renumber the backreferences.)
        re = expandBraces(g).map(globToRegExp);
      } catch {
        re = []; // too complex: never matches (resolvePatterns already drops these)
      }
      if (reCache.size > 500) reCache.clear();
      reCache.set(g, re);
    }
    return re.some((r) => r.test(p));
  });
}
