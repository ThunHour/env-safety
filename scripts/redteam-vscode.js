#!/usr/bin/env node
/**
 * Runs the Env Safety red-team attacks inside a REAL, isolated VS Code, unattended.
 *
 *   npm run redteam
 *
 * Everything lives in .redteam/: VS Code profile, extensions, home folder (so ~/.env-safety is
 * .redteam/home/.env-safety), project. Your own VS Code, settings and ~/.env-safety are never used.
 *
 * Steps:
 *   1. builds a TEST variant of Env Safety whose dialogs are answered by a script
 *      (test/redteam/vscode-shim.js; the shipped bundle is untouched) and installs it;
 *   2. builds two attacker extensions: a harmless dummy (test 13) and a fake 9.9.9 with Env Safety's own id (test 21);
 *   3. phase 1: launches VS Code with test/redteam/runner.js, which runs the attacks and quits;
 *   4. between phases, attacks while VS Code is CLOSED (weakens the user settings file);
 *   5. phases 2 and 3: restarts to check what must survive a restart (lock on close, settings, vault salt);
 *   6. writes docs/redteam-results.md.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync, spawn } = require('child_process');

const REPO = path.join(__dirname, '..');
const PKG = require(path.join(REPO, 'package.json'));
const EXT_ID = `${PKG.publisher}.${PKG.name}`; // e.g. SeakKimhour.env-safety
const RT = path.join(REPO, '.redteam');
const U = path.join(RT, 'user-data');
const E = path.join(RT, 'extensions');
const HOME = path.join(RT, 'home');
const PROJECT = path.join(RT, 'project');
const BUILD = path.join(RT, 'build');
const RESULTS = path.join(RT, 'results');
const USER_SETTINGS = path.join(U, 'User', 'settings.json');

const log = (s) => console.log(`[redteam] ${s}`);
const sh = (cmd, args, opts = {}) => execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], ...opts });
const writeJson = (f, j) => {
  fs.mkdirSync(path.dirname(f), { recursive: true });
  fs.writeFileSync(f, JSON.stringify(j, null, 2) + '\n');
};
const readJson = (f) => JSON.parse(fs.readFileSync(f, 'utf8'));

// ---------------------------------------------------------------- VS Code

function findCode() {
  if (process.env.CODE_EXE && process.env.CODE_CLI_JS) return { exe: process.env.CODE_EXE, cli: process.env.CODE_CLI_JS };
  const cmd = sh('where.exe', ['code.cmd']).split(/\r?\n/)[0].trim();
  const m = /"%~dp0\.\.\\([^"]*cli\.js)"/.exec(fs.readFileSync(cmd, 'utf8'));
  if (!m) throw new Error(`cannot find cli.js in ${cmd}`);
  const base = path.dirname(path.dirname(cmd));
  return { exe: path.join(base, 'Code.exe'), cli: path.join(base, m[1]) };
}
const CODE = findCode();

/** No VSCODE_* / ELECTRON_* from the VS Code this may run in, so the test window is a separate instance. */
function cleanEnv(extra = {}) {
  const env = { ...process.env };
  for (const k of Object.keys(env)) if (/^(VSCODE_|ELECTRON_)/.test(k) || k === 'NoDefaultCurrentDirectoryInExePath') delete env[k];
  return { ...env, ...extra };
}
const isolated = { USERPROFILE: HOME, HOME };

function cli(...args) {
  return sh(CODE.exe, [CODE.cli, '--user-data-dir', U, '--extensions-dir', E, ...args], {
    env: cleanEnv({ ELECTRON_RUN_AS_NODE: '1', ...isolated }),
    timeout: 180000,
  });
}

function vsce(dir, out) {
  sh(process.platform === 'win32' ? 'npx.cmd' : 'npx', ['--yes', '@vscode/vsce', 'package', '--no-dependencies', '--allow-missing-repository', '--skip-license', '-o', out], {
    cwd: dir,
    shell: true,
    timeout: 300000,
  });
}

// ---------------------------------------------------------------- build

function buildTestVariant() {
  const dir = path.join(BUILD, PKG.name);
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(path.join(dir, 'dist'), { recursive: true });
  sh(process.platform === 'win32' ? 'npx.cmd' : 'npx', [
    'esbuild', 'src/extension.ts', '--bundle', '--platform=node', '--format=cjs', '--target=node18',
    '--alias:vscode=./test/redteam/vscode-shim.js', `--outfile=${path.join(dir, 'dist', 'extension.js')}`, '--log-level=error',
  ], { cwd: REPO, shell: true });
  const pkg = readJson(path.join(REPO, 'package.json'));
  delete pkg.scripts;
  delete pkg.devDependencies;
  delete pkg.dependencies;
  delete pkg.icon; // the test variant needs no icon (and does not ship images/)
  writeJson(path.join(dir, 'package.json'), pkg);
  fs.copyFileSync(path.join(REPO, 'README.md'), path.join(dir, 'README.md'));
  fs.writeFileSync(path.join(dir, '.vscodeignore'), '');
  const out = path.join(BUILD, 'env-safety-redteam.vsix');
  vsce(dir, out);
  return out;
}

function buildExtension(name, publisher, version, readme) {
  const dir = path.join(BUILD, `${publisher}.${name}`);
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
  writeJson(path.join(dir, 'package.json'), {
    name, publisher, version, displayName: `${name} (red team)`, description: readme, engines: { vscode: '^1.93.0' },
    main: './extension.js', activationEvents: ['onStartupFinished'],
  });
  fs.writeFileSync(path.join(dir, 'extension.js'), 'exports.activate = () => {};\nexports.deactivate = () => {};\n');
  fs.writeFileSync(path.join(dir, 'README.md'), `# ${name}\n\n${readme}\n`);
  fs.writeFileSync(path.join(dir, '.vscodeignore'), '');
  const out = path.join(BUILD, `${publisher}.${name}-${version}.vsix`);
  vsce(dir, out);
  return out;
}

// ---------------------------------------------------------------- setup

/** A fresh VS Code profile, home folder and project (extensions stay installed). */
function freshProfile() {
  for (const d of [U, HOME, PROJECT]) fs.rmSync(d, { recursive: true, force: true });
  for (const d of [U, E, HOME, PROJECT]) fs.mkdirSync(d, { recursive: true });
  fs.writeFileSync(path.join(PROJECT, '.env'), 'API_KEY=dev-key-111\nAPI_URL=https://api.example.com\n');
  fs.writeFileSync(path.join(PROJECT, '.env.production'), 'API_KEY=PRODUCTION-key-999\nAPI_URL=https://api.example.com\n');
  sh('git', ['init', '-q'], { cwd: PROJECT });
  writeJson(USER_SETTINGS, {
    // No envSafety.* here: Env Safety must start from its secure defaults (keyring in the isolated home).
    'security.workspace.trust.enabled': false,
    'git.enabled': false, // VS Code's own git would trigger test 28's control by itself
    'workbench.startupEditor': 'none',
    'extensions.autoUpdate': false,
    'extensions.autoCheckUpdates': false,
    'update.mode': 'none',
    'telemetry.telemetryLevel': 'off',
  });
}

function setup() {
  fs.rmSync(RT, { recursive: true, force: true });
  for (const d of [BUILD, RESULTS]) fs.mkdirSync(d, { recursive: true });
  freshProfile();
  const runner = path.join(BUILD, 'runner');
  fs.mkdirSync(runner, { recursive: true });
  writeJson(path.join(runner, 'package.json'), {
    name: 'envlock-redteam-runner', publisher: 'redteam', version: '0.0.1', engines: { vscode: '^1.93.0' },
  });
  return runner;
}

/** What Env Lock (before the rename) left behind: ~/.env-lock, a signed vault, envLock.* settings. */
async function plantEnvLock() {
  const C = require(path.join(REPO, 'out', 'crypto.js'));
  const V = require(path.join(REPO, 'out', 'vault.js'));
  const K = require(path.join(REPO, 'out', 'keyring.js'));
  const legacy = path.join(HOME, '.env-lock');
  const secret = { passphrase: 'test passphrase words' };
  const k = await C.createKeyring(secret);
  await K.writeKeyring(path.join(legacy, 'keyring.json'), k);
  const priv = await C.openKeyring(k, secret);
  const id = V.newVaultId();
  const v = await V.openVault(path.join(legacy, 'vault'), id);
  await V.vaultPut(v, '.env', Buffer.from('API_KEY=legacy-key-777\n'), C.publicKeys(k), C.macKeyFromPrivate(priv));
  for (const f of ['.env', '.env.production']) fs.rmSync(path.join(PROJECT, f), { force: true });
  writeJson(path.join(PROJECT, '.vscode', 'settings.json'), { 'envLock.vaultId': id });
  const us = readJson(USER_SETTINGS);
  // A weakened setting (as an agent could leave it) and a harmless addition.
  Object.assign(us, { 'envLock.autoLockMinutes': 0, 'envLock.customPatterns': ['config/legacy.yml'] });
  writeJson(USER_SETTINGS, us);
  fs.writeFileSync(path.join(RT, 'legacy-vault-id.txt'), id);
}

function installEnvSafety(vsix) {
  try {
    cli('--uninstall-extension', EXT_ID);
  } catch {
    /* not installed */
  }
  cli('--install-extension', vsix, '--force');
}

function launch(phase, runnerDir, extraEnv, timeoutMs) {
  const out = path.join(RESULTS, `phase${phase}.json`);
  fs.rmSync(out, { force: true });
  const args = [
    '--user-data-dir', U, '--extensions-dir', E,
    `--extensionDevelopmentPath=${runnerDir}`,
    `--extensionTestsPath=${path.join(REPO, 'test', 'redteam', 'runner.js')}`,
    '--skip-welcome', '--skip-release-notes', '--disable-telemetry', '--disable-workspace-trust', '--new-window',
    PROJECT,
  ];
  const env = cleanEnv({
    ...isolated,
    REDTEAM_ROOT: RT, REDTEAM_REPO: REPO, REDTEAM_PHASE: String(phase), REDTEAM_OUT: out,
    REDTEAM_EXT_ID: EXT_ID, REDTEAM_CODE_EXE: CODE.exe, REDTEAM_CLI_JS: CODE.cli, REDTEAM_USER_DATA: U, REDTEAM_EXT_DIR: E,
    ...extraEnv,
  });
  log(`phase ${phase}: starting VS Code (a window opens; do not click in it)…`);
  return new Promise((resolve) => {
    const p = spawn(CODE.exe, args, { env, stdio: ['ignore', 'pipe', 'pipe'] });
    const logFile = fs.createWriteStream(path.join(RESULTS, `phase${phase}.log`));
    p.stdout.pipe(logFile);
    p.stderr.pipe(logFile);
    const timer = setTimeout(() => {
      log(`phase ${phase}: timed out, killing VS Code`);
      p.kill();
    }, timeoutMs);
    p.on('exit', () => {
      clearTimeout(timer);
      // Give the window's own shutdown (Env Safety's lock on close) a moment if the launcher exited first.
      setTimeout(() => resolve(fs.existsSync(out) ? readJson(out) : { phase, results: [{ id: `PHASE${phase}`, name: 'phase did not report', status: 'error', checks: [] }] }), 5000);
    });
  });
}

// ---------------------------------------------------------------- checks outside VS Code

function plaintextLeft() {
  return fs.readdirSync(PROJECT).filter((n) => n.startsWith('.env') && !n.endsWith('.locked'));
}

function bundleHashCheck() {
  const vsix = fs.readdirSync(REPO).filter((n) => /^env-safety-.*\.vsix$/.test(n)).sort().pop();
  const pkgVersion = readJson(path.join(REPO, 'package.json')).version;
  const want = crypto.createHash('sha256').update(fs.readFileSync(path.join(REPO, 'dist', 'extension.js'))).digest('hex');
  const tmp = path.join(BUILD, 'unzip');
  fs.rmSync(tmp, { recursive: true, force: true });
  fs.mkdirSync(tmp, { recursive: true });
  // Windows' own tar (bsdtar) reads zip and "D:\" paths; Git Bash's GNU tar takes "D:" for a remote host.
  const tar = process.platform === 'win32' ? path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'tar.exe') : 'tar';
  sh(tar, ['-xf', path.join(REPO, `env-safety-${pkgVersion}.vsix`), '-C', tmp]);
  const got = crypto.createHash('sha256').update(fs.readFileSync(path.join(tmp, 'extension', 'dist', 'extension.js'))).digest('hex');
  return {
    id: 'T18', name: `Released VSIX bundle matches the build (env-safety-${pkgVersion}.vsix)`, owasp: 'A03',
    status: got === want ? 'pass' : 'fail',
    checks: [{ ok: got === want, what: `dist/extension.js ${want.slice(0, 16)}… vs VSIX ${got.slice(0, 16)}… (latest VSIX file: ${vsix})` }],
  };
}

// ---------------------------------------------------------------- report

function report(phases, outside, started) {
  const rows = [];
  const all = [...phases.flatMap((p) => p.results), ...outside];
  const icon = { pass: '✅ pass', fail: '❌ FAIL', error: '⚠️ error', skip: '⏭ skip' };
  for (const r of all) {
    const ev = (r.checks || []).map((c) => `${c.ok ? '✔' : '✘'} ${c.what}`).join('<br>') + (r.error ? `<br>error: ${r.error}` : '');
    rows.push(`| ${r.id} | ${r.name} | ${r.owasp || ''} | ${icon[r.status] || r.status} | ${ev.replace(/\|/g, '\\|')} |`);
  }
  const count = (s) => all.filter((r) => r.status === s).length;
  const md = [
    '# Env Safety red-team run: results',
    '',
    `Generated by \`npm run redteam\` (scripts/redteam-vscode.js) on ${new Date(started).toISOString()}, ` +
      `VS Code ${sh(CODE.exe, [CODE.cli, '--version'], { env: cleanEnv({ ELECTRON_RUN_AS_NODE: '1' }) }).split(/\r?\n/)[0]}, ` +
      `Env Safety ${phases[0]?.version ?? '?'} (test variant: dialogs answered by script), Windows ${require('os').release()}.`,
    '',
    `**${count('pass')} passed, ${count('fail')} failed, ${count('error')} errors** out of ${all.length}. ` +
      'A failed check is a finding: the defence did not do what it should. See docs/redteam-report.md for the analysis.',
    '',
    '| ID | Attack | OWASP | Result | Evidence |',
    '|---|---|---|---|---|',
    ...rows,
    '',
    '<details><summary>Every dialog Env Safety showed during phase 1 (the scripted user\'s answers)</summary>',
    '',
    '```',
    ...(phases[0]?.log || []).map((l) => `[${l.kind}] ${l.text.replace(/\s+/g, ' ').slice(0, 220)}${l.buttons?.length ? `  {${l.buttons.join(' | ')}}` : ''} -> ${l.answer ?? 'cancel'}`),
    '```',
    '',
    '</details>',
    '',
  ].join('\n');
  fs.writeFileSync(path.join(REPO, 'docs', 'redteam-results.md'), md);
  return { pass: count('pass'), fail: count('fail'), error: count('error'), total: all.length };
}

// ---------------------------------------------------------------- main

(async () => {
  const started = Date.now();
  log(`VS Code: ${CODE.exe}`);
  log('building (compile, test variant, attacker extensions)…');
  sh(process.platform === 'win32' ? 'npm.cmd' : 'npm', ['run', '-s', 'compile'], { cwd: REPO, shell: true });
  const runner = setup();
  const envSafetyVsix = buildTestVariant();
  const dummy = buildExtension('dummy-extension', 'redteam', '1.0.0', 'Harmless extension installed by the red-team run (test 13).');
  const fake = buildExtension(PKG.name, PKG.publisher, '9.9.9', 'FAKE Env Safety with the same id (red-team test 21). Does nothing.');
  installEnvSafety(envSafetyVsix);

  // Phase M: an Env Lock user (keyring, signed vault, settings) installs Env Safety. Then a fresh profile.
  const migration = process.argv.some((a) => a.startsWith('--only=')) ? { results: [] } : await (async () => {
    await plantEnvLock();
    const r = await launch('M', runner, {}, 5 * 60000);
    freshProfile();
    return r;
  })();

  const phases = [];
  // --only=X1,X2: quick loop, phase 1 only (S0 setup always runs), no report file.
  const only = (process.argv.find((a) => a.startsWith('--only=')) || '').slice(7);
  if (only) {
    const r = await launch(1, runner, { REDTEAM_DUMMY_VSIX: dummy, REDTEAM_ONLY: only }, 15 * 60000);
    for (const t of r.results) {
      log(`${t.status.toUpperCase().padEnd(5)} ${t.id} ${t.name}${t.error ? `
      error: ${t.error}` : ''}`);
      for (const ch of t.checks || []) log(`      ${ch.ok ? '✔' : '✘'} ${ch.what}`);
    }
    return;
  }
  phases.push(await launch(1, runner, { REDTEAM_DUMMY_VSIX: dummy }, 15 * 60000));

  // Between phases: what an agent can do while VS Code is closed.
  const outside = [];
  const left = plaintextLeft();
  outside.push({
    id: 'T26c', name: 'Lock on close, checked on disk right after VS Code exited', owasp: 'A04',
    status: left.length ? 'fail' : 'pass',
    checks: [{ ok: !left.length, what: left.length ? `plaintext left: ${left.join(', ')}` : 'no plaintext .env files in the project' }],
  });
  const us = readJson(USER_SETTINGS);
  Object.assign(us, { 'envSafety.lockOnClose': false, 'envSafety.confirmUnlockToDisk': false });
  writeJson(USER_SETTINGS, us);
  phases.push(await launch(2, runner, {}, 5 * 60000));
  phases.push(await launch(3, runner, { REDTEAM_FAKE_VSIX: fake }, 5 * 60000));
  // An agent's reset: uninstall and reinstall Env Safety (also removes test 21's fake). Test 30 checks the effect.
  installEnvSafety(envSafetyVsix);
  phases.push(await launch(4, runner, {}, 5 * 60000));
  outside.push(bundleHashCheck());
  outside.push(...migration.results);

  const s = report(phases, outside, started);
  log(`done in ${Math.round((Date.now() - started) / 1000)} s: ${s.pass} passed, ${s.fail} failed, ${s.error} errors of ${s.total}`);
  log('results: docs/redteam-results.md (raw JSON and VS Code logs in .redteam/results/)');
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
