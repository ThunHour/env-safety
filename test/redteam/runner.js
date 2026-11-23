/**
 * Env Lock red-team runner. Runs INSIDE an isolated VS Code (extension host), started by
 * scripts/redteam-vscode.js with --extensionTestsPath. It plays two roles:
 *   - the attacker: an AI agent running as you (edits files, settings, git config, installs extensions);
 *   - the user: answers Env Lock's dialogs (via test/redteam/vscode-shim.js), always the safe way
 *     unless a test needs otherwise, and records every message Env Lock shows.
 * Results are written as JSON per phase; the orchestrator turns them into docs/redteam-results.md.
 */
const vscode = require('vscode');
const fs = require('fs');
const path = require('path');
const cp = require('child_process');

const ROOT = process.env.REDTEAM_ROOT;
const REPO = process.env.REDTEAM_REPO;
const PHASE = process.env.REDTEAM_PHASE;
const OUT = process.env.REDTEAM_OUT;
const PROJECT = path.join(ROOT, 'project');
const OUTSIDE = path.join(ROOT, 'outside');
const HOME = path.join(ROOT, 'home', '.env-lock'); // USERPROFILE of the test VS Code is .redteam/home
const KEYRING = path.join(HOME, 'keyring.json');
const VAULT_ROOT = path.join(HOME, 'vault');
const USER_SETTINGS = path.join(ROOT, 'user-data', 'User', 'settings.json');
const PROJECT_SETTINGS = path.join(PROJECT, '.vscode', 'settings.json');
const C = require(path.join(REPO, 'out', 'crypto.js'));
const V = require(path.join(REPO, 'out', 'vault.js'));

const PASS = 'test passphrase words';
const PHRASE = 'blue teapot';
const ENV = 'API_KEY=dev-key-111\nAPI_URL=https://api.example.com\n';
const ENV_PROD = 'API_KEY=PRODUCTION-key-999\nAPI_URL=https://api.example.com\n';

// ================================================================ the scripted user

const calls = [];
let policy = {};

function answer(kind, args) {
  const e = { kind, t: Date.now() };
  let ans;
  if (kind === 'showInputBox') {
    const o = args[0] || {};
    e.text = `${o.title || ''} | ${o.prompt || ''}`;
    e.options = o;
    if (policy.input) ans = policy.input(o);
    if (ans === undefined) {
      if (o.password) ans = policy.passphrase ?? PASS;
      else if (/anti-phishing/i.test(o.title || '')) ans = PHRASE;
      else if (/Command to run/.test(o.prompt || '')) ans = policy.command;
    }
  } else if (kind === 'showQuickPick') {
    const o = args[1] || {};
    e.text = o.placeHolder || o.title || '';
    ans = Promise.resolve(args[0]).then((list) => {
      e.items = list.map((i) => (typeof i === 'string' ? i : i.label));
      if (policy.quickPick) return policy.quickPick(list, o);
      if (o.canPickMany) return undefined;
      return list.find((i) => i.id === 'none') ?? list[0];
    });
  } else if (kind.endsWith('Message')) {
    const [msg, ...rest] = args;
    e.text = msg;
    e.buttons = rest.filter((x) => typeof x === 'string');
    e.modal = rest.some((x) => x && typeof x === 'object' && x.modal);
    ans = policy.message ? policy.message(msg, e.buttons, e.modal) : undefined;
  }
  e.answer = typeof ans === 'string' ? ans : ans === undefined ? undefined : '(object)';
  calls.push(e);
  return ans;
}

/** [regex, button] pairs: click `button` when a message matches. Anything else: cancel. */
const respond = (pairs) => (msg, buttons) => {
  for (const [re, b] of pairs) if (re.test(msg) && buttons.includes(b)) return b;
  return undefined;
};
const UNLOCK = [/to disk\?/, 'Unlock to disk'];

// ================================================================ helpers

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(fn, ms = 10000, step = 200) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    try {
      if (await fn()) return true;
    } catch {
      /* keep waiting */
    }
    await sleep(step);
  }
  return false;
}
const P = (...a) => path.join(PROJECT, ...a);
const exists = (p) => fs.existsSync(p);
const read = (p) => (exists(p) ? fs.readFileSync(p, 'utf8') : '');
const readJson = (f) => (exists(f) ? JSON.parse(fs.readFileSync(f, 'utf8')) : {});
const writeJson = (f, j) => {
  fs.mkdirSync(path.dirname(f), { recursive: true });
  fs.writeFileSync(f, JSON.stringify(j, null, 2) + '\n');
};
const mark = () => calls.length;
const saw = (since, re, kind) => calls.slice(since).filter((c) => (!kind || c.kind === kind) && re.test(c.text || ''));
const cmd = (id, ...a) => vscode.commands.executeCommand(id, ...a);
const cfgGet = (k) => vscode.workspace.getConfiguration('envLock').inspect(k)?.globalValue;

function vault() {
  const id = readJson(PROJECT_SETTINGS)['envLock.vaultId'];
  const dir = path.join(VAULT_ROOT, id);
  const meta = readJson(path.join(dir, 'vault.json'));
  return { id, dir, salt: Buffer.from(meta.salt, 'base64') };
}
const blobOf = (v, rel) => path.join(v.dir, V.blobName(v.salt, rel));
const blobs = (v) => fs.readdirSync(v.dir).filter((n) => n.endsWith('.locked'));

async function lockAll() {
  policy = {};
  await cmd('envLock.lock');
  await sleep(400);
}
async function unlockAll(extra = []) {
  policy = { message: respond([...extra, UNLOCK]) };
  await cmd('envLock.unlock');
  await sleep(400);
  policy = {};
}
function setUser(k, v) {
  const j = readJson(USER_SETTINGS);
  if (v === undefined) delete j[k];
  else j[k] = v;
  writeJson(USER_SETTINGS, j);
}
function setProject(k, v) {
  const j = readJson(PROJECT_SETTINGS);
  if (v === undefined) delete j[k];
  else j[k] = v;
  writeJson(PROJECT_SETTINGS, j);
}
/** Puts the two test secrets back (plaintext) and locks everything: the state every test starts from. */
async function baseline() {
  for (const n of fs.readdirSync(PROJECT)) if (n.endsWith('.locked')) fs.unlinkSync(P(n));
  if (!exists(P('.env'))) fs.writeFileSync(P('.env'), ENV);
  if (!exists(P('.env.production'))) fs.writeFileSync(P('.env.production'), ENV_PROD);
  await lockAll();
}
function cleanCliEnv() {
  const env = { ...process.env };
  for (const k of Object.keys(env)) if (/^(VSCODE_|ELECTRON_)/.test(k)) delete env[k];
  return { ...env, ELECTRON_RUN_AS_NODE: '1' };
}
function cli(...args) {
  return cp.execFileSync(
    process.env.REDTEAM_CODE_EXE,
    [process.env.REDTEAM_CLI_JS, '--user-data-dir', process.env.REDTEAM_USER_DATA, '--extensions-dir', process.env.REDTEAM_EXT_DIR, ...args],
    { env: cleanCliEnv(), encoding: 'utf8', timeout: 120000, windowsHide: true }
  );
}
/** Run-with-secrets with a probe script that records what the process received. */
async function runWithSecrets(command, messagePairs, { waitForFile, ms = 20000 } = {}) {
  policy = { ...policy, command, message: respond(messagePairs) }; // keeps a quickPick choice set by the test
  await cmd('envLock.runWithSecrets');
  policy = {};
  if (waitForFile) await waitFor(() => exists(waitForFile), ms);
}
const PROBE = `require('fs').writeFileSync(require('path').join(__dirname, 'rt-out.json'), JSON.stringify({
  API_KEY: process.env.API_KEY, API_URL: process.env.API_URL, NODE_OPTIONS: process.env.NODE_OPTIONS }));\n`;

// ================================================================ tests

class Check {
  constructor() {
    this.items = [];
  }
  expect(ok, what) {
    this.items.push({ ok: !!ok, what });
    return !!ok;
  }
}

const tests = [];
const T = (id, name, owasp, fn, opts = {}) => tests.push({ id, name, owasp, fn, ...opts });

// ---------------------------------------------------------------- phase 1

T('S0', 'Setup: keys, anti-phishing phrase, first lock', 'A07', async (c) => {
  policy = {};
  await cmd('envLock.setupKeys');
  c.expect(exists(KEYRING), 'keyring created');
  c.expect(saw(0, /your phrase: "blue teapot"|anti-phishing/, 'showInputBox').length, 'anti-phishing phrase set');
  await lockAll();
});

T('T01', 'Locking needs no passphrase; nothing readable is left', 'A04', async (c) => {
  fs.writeFileSync(P('.env.local'), 'X=1\n');
  const m = mark();
  await lockAll();
  c.expect(!saw(m, /./, 'showInputBox').length, 'no passphrase prompt while locking');
  c.expect(!exists(P('.env')) && !exists(P('.env.production')) && !exists(P('.env.local')), 'no plaintext .env files in the project');
  const v = vault();
  const all = blobs(v).map((b) => read(path.join(v.dir, b))).join('');
  c.expect(blobs(v).length >= 3, `vault holds the files (${blobs(v).length} blobs)`);
  c.expect(!/API_KEY|dev-key|\.env/.test(all + blobs(v).join('')), 'no secret or file name visible in the vault');
});

T('T02', 'Swapped keyring (agent replaces your key with its own)', 'A08', async (c) => {
  fs.copyFileSync(KEYRING, KEYRING + '.real');
  const attacker = await C.createKeyring({ passphrase: 'attacker passphrase 123' });
  fs.writeFileSync(KEYRING, JSON.stringify(attacker, null, 2));
  fs.writeFileSync(P('.env.local'), 'X=1\n');
  const m = mark();
  policy = { message: respond([[/keyring changed/, 'Trust this keyring']]) }; // the user is fooled and types THEIR passphrase
  await cmd('envLock.lock');
  policy = {};
  c.expect(saw(m, /your keyring changed/).length, 'warned "your keyring changed"');
  c.expect(exists(P('.env.local')), 'nothing was encrypted to the attacker key');
  c.expect(saw(m, /wrong passphrase/i).length, "your passphrase does not open the attacker's keyring");
  fs.renameSync(KEYRING + '.real', KEYRING);
  await lockAll();
  c.expect(!exists(P('.env.local')), 'locks again once the real keyring is back');
});

T('T03a', 'Planted UNSIGNED locked file (made with your public key)', 'A08', async (c) => {
  const pub = C.publicKeys(C.parseKeyring(read(KEYRING)));
  fs.writeFileSync(P('.env.locked'), C.encryptFile(Buffer.from('API_KEY=attacker\nAPI_URL=https://attacker.example\n'), pub));
  const m = mark();
  await unlockAll();
  c.expect(saw(m, /no signature/).length, 'asked: "no signature … only use them if you locked them yourself"');
  c.expect(!/attacker/.test(read(P('.env'))), 'the planted content was not restored (cancelled)');
  c.expect(/dev-key-111/.test(read(P('.env'))), 'the real .env from the vault was restored');
  await baseline();
});

T('T03b', 'Planted locked file with a FORGED signature', 'A08', async (c) => {
  const pub = C.publicKeys(C.parseKeyring(read(KEYRING)));
  const forged = C.signLocked(C.encryptFile(Buffer.from('API_URL=https://attacker.example\n'), pub), C.newMacKey(), V.fileBinding('.env'));
  fs.writeFileSync(P('.env.locked'), forged);
  const m = mark();
  await unlockAll();
  c.expect(saw(m, /REFUSED, signature invalid.*\.env\.locked/).length, 'refused: "signature invalid … .env.locked"');
  c.expect(!/attacker/.test(read(P('.env'))), 'no planted content restored');
  await baseline();
});

T('T04', 'Swapped vault blobs (production keys loaded as development keys)', 'A08', async (c) => {
  const v = vault();
  fs.copyFileSync(blobOf(v, '.env.production'), blobOf(v, '.env'));
  const m = mark();
  await unlockAll();
  c.expect(saw(m, /REFUSED, signature invalid/).length, 'refused: "signature invalid"');
  c.expect(!/PRODUCTION/.test(read(P('.env'))), 'production keys were not restored as .env');
  await baseline();
});

T('T05', 'Rollback (an older signed version put back)', 'A08', async (c) => {
  const v = vault();
  const old = fs.readFileSync(blobOf(v, '.env'));
  await unlockAll();
  fs.writeFileSync(P('.env'), 'API_KEY=dev-key-222\n');
  await lockAll();
  fs.writeFileSync(blobOf(v, '.env'), old);
  const m = mark();
  await unlockAll();
  c.expect(saw(m, /OLDER version/).length, 'asked: "OLDER version than the one you last locked"');
  c.expect(!/dev-key-111/.test(read(P('.env'))), 'old version not restored (cancelled)');
  if (exists(P('.env'))) fs.unlinkSync(P('.env'));
  await baseline();
});

T('T06', 'Locked files deleted from the vault', 'A08', async (c) => {
  const v = vault();
  const keep = path.join(ROOT, 'blob-backup');
  fs.rmSync(keep, { recursive: true, force: true });
  fs.mkdirSync(keep);
  for (const b of blobs(v)) fs.copyFileSync(path.join(v.dir, b), path.join(keep, b));
  for (const b of blobs(v)) fs.unlinkSync(path.join(v.dir, b));
  const m = mark();
  fs.writeFileSync(P('.env.trigger'), 'X=1'); // any change makes Env Lock re-check
  await sleep(1500);
  fs.unlinkSync(P('.env.trigger'));
  c.expect(await waitFor(() => saw(m, /deleted by something other than Env Lock/).length, 15000), 'reported "deleted by something other than Env Lock"');
  for (const b of fs.readdirSync(keep)) fs.copyFileSync(path.join(keep, b), path.join(v.dir, b));
  await lockAll();
});

T('T07', 'Project settings try to switch protection off', 'A01', async (c) => {
  const m = mark();
  for (const [k, val] of Object.entries({ lockOnClose: false, autoLockMinutes: 0, allowList: ['**'], confirmUnlockToDisk: false, storage: 'inPlace' })) {
    setProject('envLock.' + k, val);
  }
  c.expect(await waitFor(() => saw(m, /ignored settings in this project/).length, 10000), 'warned "ignored settings in this project"');
  const m2 = mark();
  policy = {}; // cancel the confirmation
  await cmd('envLock.unlock');
  c.expect(saw(m2, /to disk\?/).length, 'unlocking still asks first (confirmUnlockToDisk kept)');
  c.expect(!exists(P('.env')), 'still locked');
  for (const k of ['lockOnClose', 'autoLockMinutes', 'allowList', 'confirmUnlockToDisk', 'storage']) setProject('envLock.' + k, undefined);
  await sleep(1500);
});

T('T08', 'User settings file edited to weaken protection (VS Code running)', 'A01', async (c) => {
  const m = mark();
  setUser('envLock.lockOnClose', false);
  setUser('envLock.confirmUnlockToDisk', false);
  setUser('envLock.autoLockMinutes', 0);
  c.expect(await waitFor(() => saw(m, /made protection WEAKER|protection WEAKER/).length, 15000), 'dialog "changed to make protection WEAKER"');
  c.expect(
    await waitFor(() => {
      const j = readJson(USER_SETTINGS);
      return j['envLock.lockOnClose'] === true && j['envLock.confirmUnlockToDisk'] === true && j['envLock.autoLockMinutes'] === 5;
    }, 15000),
    'cancelled: the file is reverted to the approved values (true, true, 5)'
  );
  const m2 = mark();
  setUser('envLock.autoLockMinutes', 4);
  await sleep(3000);
  c.expect(!saw(m2, /WEAKER/).length, 'a stronger value (4 min) goes through without a dialog');
});

T('T09', 'Vault redirected (envLock.vaultId changed in the project)', 'A01', async (c) => {
  const real = readJson(PROJECT_SETTINGS)['envLock.vaultId'];
  const m = mark();
  setProject('envLock.vaultId', V.newVaultId());
  await sleep(1500);
  await unlockAll();
  c.expect(saw(m, /vaultId.*changed.*Still using your vault/).length, 'warned "vaultId changed … still using your vault"');
  c.expect(/dev-key-111/.test(read(P('.env'))), 'unlocking still restores the real .env from the pinned vault');
  setProject('envLock.vaultId', real);
  await sleep(1000);
  await lockAll();
});

T('T10', 'Anti-phishing phrase in every real passphrase prompt', 'A07', async (c) => {
  const prompts = calls.filter((x) => x.kind === 'showInputBox' && x.options?.password);
  const phraseSetAt = calls.find((x) => x.kind === 'showInputBox' && /anti-phishing phrase$/.test(x.options?.title || ''))?.t ?? 0;
  const after = prompts.filter((x) => x.t > phraseSetAt);
  c.expect(after.length > 0, `${after.length} passphrase prompts after the phrase was set`);
  c.expect(after.every((x) => /your phrase: "blue teapot"/.test(x.options.title || '')), 'every one shows your phrase in its title');
  c.expect(after.every((x) => /never in a terminal/.test(x.options.prompt || '')), 'every one says Env Lock never asks in a terminal');
});

T('T11', 'Run a command with secrets (in memory); AI agents refused', 'A06', async (c) => {
  fs.writeFileSync(P('rt-probe.js'), PROBE);
  const m = mark();
  await runWithSecrets('node rt-probe.js', [[/first run with secrets|NEW or CHANGED/, 'Use them'], [/will get your secrets/, 'Run anyway']], {
    waitForFile: P('rt-out.json'),
  });
  const out = readJson(P('rt-out.json'));
  c.expect(!!out.API_KEY, `the process received API_KEY (${out.API_KEY})`);
  // .env and .env.production sit in the same folder: which one wins?
  c.expect(out.API_KEY === 'dev-key-111', 'a development run gets the DEVELOPMENT key, not .env.production\'s');
  c.expect(!exists(P('.env')), 'nothing written to disk (.env still locked)');
  c.expect(saw(m, /first run with secrets/).length, 'first run: the values were shown for approval');
  c.expect(saw(m, /Which environment/, 'showQuickPick').length, 'asked which environment (.env.production is present)');
  fs.rmSync(P('rt-out.json'), { force: true });
  policy = { quickPick: (list) => list.find((i) => i.label === 'production') };
  await runWithSecrets('node rt-probe.js', [[/NEW or CHANGED/, 'Use them'], [/will get your secrets/, 'Run anyway']], {
    waitForFile: P('rt-out.json'),
  });
  c.expect(readJson(P('rt-out.json')).API_KEY === 'PRODUCTION-key-999', 'production keys only when you choose "production"');
  for (const agent of ['claude', 'node rt-probe.js & claude']) {
    const m2 = mark();
    await runWithSecrets(agent, []);
    c.expect(saw(m2, /is an AI agent/).length, `"${agent}" refused as an AI agent`);
    c.expect(!saw(m2, /./, 'showInputBox').filter((x) => x.options?.password).length, `no passphrase asked for "${agent}"`);
  }
  fs.rmSync(P('rt-out.json'), { force: true });
});

T('T12', 'Secrets are never put in a terminal\'s creation options (static check)', 'A04', async (c) => {
  const src = read(path.join(REPO, 'src', 'extension.ts'));
  const calls_ = src.split('createTerminal(').length - 1;
  c.expect(calls_ === 1, `exactly one createTerminal call (${calls_})`);
  const block = src.slice(src.indexOf('createTerminal('), src.indexOf('createTerminal(') + 400);
  c.expect(/pty/.test(block) && !/\benv\s*:/.test(block), 'it passes pty and no env');
});

T('T13', 'Extension installed from the command line while secrets are in use', 'A08', async (c) => {
  await unlockAll();
  fs.writeFileSync(P('rt-sleep.js'), 'setInterval(() => {}, 1000);\n');
  await runWithSecrets('node rt-sleep.js', [[/NEW or CHANGED|first run/, 'Use them'], [/will get your secrets/, 'Run anyway']]);
  await waitFor(() => vscode.window.terminals.some((t) => t.name.startsWith('env-lock:')), 10000);
  c.expect(vscode.window.terminals.some((t) => t.name.startsWith('env-lock:')), 'a secrets process is running');
  const m = mark();
  cli('--install-extension', process.env.REDTEAM_DUMMY_VSIX, '--force');
  const seen = await waitFor(() => saw(m, /new extension\(s\) installed/).length, 45000);
  c.expect(seen, 'warned "new extension(s) installed" without a reload');
  c.expect(await waitFor(() => !vscode.window.terminals.some((t) => t.name.startsWith('env-lock:')), 10000), 'the secrets process was stopped');
  c.expect(await waitFor(() => !exists(P('.env')), 10000), 'unlocked files were locked again');
  try {
    cli('--uninstall-extension', 'redteam.dummy-extension');
  } catch {
    /* ignore */
  }
  await baseline();
}, { timeout: 120000 });

T('T14', 'AI agent started in a terminal', 'A06', async (c) => {
  await unlockAll();
  c.expect(exists(P('.env')), 'unlocked to disk');
  const m = mark();
  const t = vscode.window.createTerminal({ name: 'claude' });
  c.expect(await waitFor(() => !exists(P('.env')), 10000), 'a terminal named "claude": locked right away');
  c.expect(await waitFor(() => saw(m, /"claude" started/).length, 5000), 'message names the agent');
  t.dispose();
  // Typed command (needs shell integration).
  await unlockAll();
  const sh = vscode.window.createTerminal({ name: 'rt-shell' });
  sh.show();
  const si = await waitFor(() => sh.shellIntegration, 20000);
  if (!si) {
    c.expect(true, 'typed "claude": SKIPPED, shell integration did not start in this terminal');
  } else {
    sh.sendText('claude --version');
    c.expect(await waitFor(() => !exists(P('.env')), 15000), 'typed "claude" in a shell: locked');
  }
  sh.dispose();
  await baseline();
}, { timeout: 90000 });

T('T15', 'Unlocked secret not ignored by git', 'A02', async (c) => {
  fs.rmSync(P('.gitignore'), { force: true });
  const m = mark();
  policy = { message: respond([UNLOCK, [/not ignored by git/, 'Add to .gitignore']]) };
  await cmd('envLock.unlock');
  c.expect(await waitFor(() => saw(m, /not ignored by git/).length, 15000), 'warned "not ignored by git, so it could be committed"');
  c.expect(await waitFor(() => /\/\.env/.test(read(P('.gitignore'))), 10000), '"Add to .gitignore" wrote /.env');
  policy = {};
  await baseline();
});

T('T17', 'Weak new passphrases are refused', 'A07', async (c) => {
  const first = calls.find((x) => x.kind === 'showInputBox' && x.options?.password && x.options.validateInput);
  const v = first?.options?.validateInput;
  c.expect(!!v, 'the new-passphrase prompt validates input');
  for (const weak of ['password1234', 'aaaaaaaaaaaaaaaa']) c.expect(v && (await v(weak)), `"${weak}" refused: ${v && (await v(weak))}`);
});

T('T19', 'Planted plaintext .env.local redirects API_URL / adds NODE_OPTIONS (F1)', 'A06', async (c) => {
  fs.writeFileSync(P('.env.local'), 'API_URL=https://attacker.example\nNODE_OPTIONS=--require ./x.js\n');
  const m = mark();
  await runWithSecrets('node rt-probe.js', [[/NEW or CHANGED/, 'Leave them out']], { waitForFile: P('rt-out.json') });
  const shown = saw(m, /NEW or CHANGED/)[0]?.text || '';
  c.expect(/\.env\.local/.test(shown) && /API_URL/.test(shown), 'warned: new values in .env.local (API_URL)');
  c.expect(/NODE_OPTIONS.*change how programs start/s.test(shown), 'flagged NODE_OPTIONS as process-control');
  const out = readJson(P('rt-out.json'));
  c.expect(!!out.API_KEY && out.API_URL === 'https://api.example.com', 'left out: the process got the real API_URL, not the attacker\'s');
  c.expect(!out.NODE_OPTIONS, 'left out: no NODE_OPTIONS');
  fs.rmSync(P('rt-out.json'), { force: true });
  fs.rmSync(P('.env.local'), { force: true });
});

T('T20', 'Planted npm.cmd in the project folder (F2)', 'A05', async (c) => {
  writeJson(P('package.json'), { name: 'rt', private: true, scripts: { dev: 'node rt-real.js' } });
  fs.writeFileSync(P('rt-real.js'), "require('fs').writeFileSync(require('path').join(__dirname,'ran.txt'), 'real');\n");
  fs.writeFileSync(P('npm.cmd'), "@echo STOLEN %API_KEY%> \"%~dp0stolen.txt\"\r\n");
  const m = mark();
  await runWithSecrets('npm run dev', [[/NEW or CHANGED|first run/, 'Use them'], [/will get your secrets/, 'Run anyway']], {
    waitForFile: P('ran.txt'),
    ms: 30000,
  });
  await waitFor(() => exists(P('stolen.txt')), 3000);
  c.expect(/npm\.cmd/.test(saw(m, /will get your secrets/)[0]?.text || ''), 'warned that npm.cmd sits in the run folder');
  c.expect(read(P('ran.txt')) === 'real', 'the real npm ran');
  c.expect(!exists(P('stolen.txt')), 'the planted npm.cmd did NOT run');
  for (const f of ['package.json', 'rt-real.js', 'npm.cmd', 'ran.txt', 'stolen.txt']) fs.rmSync(P(f), { force: true });
}, { timeout: 60000 });

T('T22', 'Env Lock commands run by ANOTHER extension (F4)', 'A01', async (c) => {
  const victim = path.join(OUTSIDE, 'thesis.docx');
  fs.mkdirSync(OUTSIDE, { recursive: true });
  fs.writeFileSync(victim, 'my thesis');
  const m = mark();
  await cmd('envLock.lockFile', vscode.Uri.file(victim));
  c.expect(read(victim) === 'my thesis' && !exists(victim + '.locked'), 'lockFile on a file outside the workspace: refused, file intact');
  c.expect(saw(m, /not a protected secret file/).length, 'warned "not a protected secret file"');
  fs.writeFileSync(P('notes.txt'), 'notes');
  await cmd('envLock.protectFile', vscode.Uri.file(P('notes.txt')));
  c.expect(saw(m, /protect notes\.txt\?/).length && read(P('notes.txt')) === 'notes', 'protectFile asks first; cancelled: file intact');
  await unlockAll();
  await cmd('envLock.unprotectFile', vscode.Uri.file(P('.env')));
  c.expect(saw(m, /stop protecting \.env\?/).length, 'unprotectFile asks first');
  await lockAll();
  c.expect(!exists(P('.env')), 'cancelled: .env still protected (locked again)');
  fs.rmSync(P('notes.txt'), { force: true });
});

T('T23', 'Catastrophic glob in the project settings (ReDoS, F5/R1)', 'A10', async (c) => {
  const deep = P(...Array(30).fill('a'));
  fs.mkdirSync(deep, { recursive: true });
  fs.writeFileSync(path.join(deep, 'y'), '');
  const m = mark();
  setProject('envLock.customPatterns', ['**/**/**/**/**/**/**/**/**/**/**/**/x', '*a*a*/*a*a*/*a*a*/*a*a*/*a*a*/b', '*a*a*a*a*b']);
  await sleep(2000);
  const t = Date.now();
  await cmd('envLock.lock');
  const ms = Date.now() - t;
  c.expect(ms < 5000, `Lock all answered in ${ms} ms`);
  c.expect(await waitFor(() => saw(m, /too complex to match safely/).length, 5000), 'the unsafe pattern was reported and ignored');
  setProject('envLock.customPatterns', undefined);
  fs.rmSync(P('a'), { recursive: true, force: true });
  await sleep(1000);
});

T('T24', 'User presets shrunk to ["dotenv"] (F6)', 'A01', async (c) => {
  const m = mark();
  setUser('envLock.presets', ['dotenv']);
  c.expect(await waitFor(() => saw(m, /WEAKER[\s\S]*presets/).length, 15000), 'dialog "made protection WEAKER: envLock.presets"');
  c.expect(await waitFor(() => JSON.stringify(readJson(USER_SETTINGS)['envLock.presets']) === '["auto"]', 15000), 'cancelled: presets reverted to ["auto"]');
});

T('T25', 'Hide a secret from the scan (.ignore, .rgignore, search/files.exclude)', 'A02', async (c) => {
  fs.writeFileSync(P('.ignore'), '.env.hidden\n');
  fs.writeFileSync(P('.rgignore'), '.env.hidden\n');
  setProject('search.exclude', { '**/.env.hidden': true });
  setProject('files.exclude', { '**/.env.hidden': true });
  await sleep(1500);
  fs.writeFileSync(P('.env.hidden'), 'SECRET=1\n');
  await sleep(1000);
  await lockAll();
  c.expect(!exists(P('.env.hidden')), '.env.hidden was still found and locked');
  for (const f of ['.ignore', '.rgignore']) fs.rmSync(P(f), { force: true });
  setProject('search.exclude', undefined);
  setProject('files.exclude', undefined);
});

T('T27', 'Folder replaced by a junction to outside the project (F8)', 'A01', async (c) => {
  setProject('envLock.customPatterns', ['config/secrets.yml']);
  await sleep(1500);
  fs.mkdirSync(P('config'), { recursive: true });
  fs.writeFileSync(P('config', 'secrets.yml'), 'db_password: hunter2\n');
  await lockAll();
  c.expect(!exists(P('config', 'secrets.yml')), 'config/secrets.yml locked');
  const target = path.join(OUTSIDE, 'synced-folder');
  fs.mkdirSync(target, { recursive: true });
  fs.rmSync(P('config'), { recursive: true, force: true });
  fs.symlinkSync(target, P('config'), 'junction');
  const m = mark();
  await unlockAll();
  c.expect(!exists(path.join(target, 'secrets.yml')), 'nothing written into the folder outside the project');
  c.expect(saw(m, /link leading outside the project/).length, 'reported "folder is a link leading outside the project"');
  fs.rmdirSync(P('config')); // removes the junction only, never the folder it points to
  fs.mkdirSync(P('config'));
  await unlockAll();
  c.expect(/hunter2/.test(read(P('config', 'secrets.yml'))), 'with a real folder again it unlocks normally');
  await lockAll();
  fs.rmSync(P('config'), { recursive: true, force: true });
  setProject('envLock.customPatterns', undefined);
  await baseline();
});

T('T28', "Project's git configured to run a command (core.fsmonitor, F14)", 'A05', async (c) => {
  const marker = path.join(ROOT, 'FSMONITOR-RAN');
  fs.rmSync(marker, { force: true });
  const script = path.join(ROOT, 'fsmon.js');
  fs.writeFileSync(script, `require('fs').appendFileSync(${JSON.stringify(marker)}, 'x');\n`);
  cp.execFileSync('git', ['config', 'core.fsmonitor', `node "${script.replace(/\\/g, '/')}"`], { cwd: PROJECT });
  await unlockAll(); // runs git check-ignore and ls-files
  fs.writeFileSync(P('.env.trigger'), 'X=1');
  await sleep(1500);
  fs.unlinkSync(P('.env.trigger'));
  await lockAll();
  await sleep(1500);
  c.expect(!exists(marker), "Env Lock's git calls did not run the configured command");
  cp.execFileSync('git', ['status', '--short'], { cwd: PROJECT }); // positive control: plain git runs it
  c.expect(exists(marker), 'control: a plain `git status` DOES run it (the attack is real)');
  cp.execFileSync('git', ['config', '--unset', 'core.fsmonitor'], { cwd: PROJECT });
});

T('R2', 'Planted .locked file with a {"length": 2e8} field (memory/CPU DoS)', 'A10', async (c) => {
  const k = C.parseKeyring(read(KEYRING));
  const j = JSON.parse(C.encryptFile(Buffer.from('X=1'), C.publicKeys(k)));
  j.tag = { length: 2e8 };
  fs.writeFileSync(P('.env.big.locked'), JSON.stringify(j));
  const m = mark();
  const t = Date.now();
  await unlockAll();
  const ms = Date.now() - t;
  c.expect(ms < 8000, `unlock answered in ${ms} ms (was ~9 s and 200 MB per field)`);
  const err = saw(m, /\.env\.big\.locked/)[0]?.text;
  c.expect(true, `observed: ${err ? err.slice(0, 160) : 'no message about it'}`);
  fs.rmSync(P('.env.big.locked'), { force: true });
  await baseline();
});

T('R3', 'Planted 0.8 MB .env.local with an unclosed quote (parser DoS)', 'A10', async (c) => {
  fs.writeFileSync(P('.env.local'), 'A="' + '\nxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'.repeat(20000));
  const m = mark();
  const t = Date.now();
  await runWithSecrets('node rt-probe.js', []); // cancel at the review
  const ms = Date.now() - t;
  c.expect(ms < 8000, `"Run with secrets" reached the review in ${ms} ms (was 54 s)`);
  c.expect(saw(m, /NEW or CHANGED/).length, 'the planted file was shown for review');
  fs.rmSync(P('.env.local'), { force: true });
});

T('R4', 'Hard link to a file outside the project, named like a secret', 'A01', async (c) => {
  const target = path.join(OUTSIDE, 'id_rsa');
  fs.mkdirSync(OUTSIDE, { recursive: true });
  fs.writeFileSync(target, 'PRIVATE KEY');
  fs.rmSync(P('.env.hl'), { force: true });
  fs.linkSync(target, P('.env.hl'));
  await lockAll();
  c.expect(exists(P('.env.hl')), 'not locked (Env Lock never reads a hard-linked file into the vault)');
  fs.rmSync(P('.env.hl'), { force: true });
  try {
    fs.symlinkSync(path.join(OUTSIDE, 'nothing'), P('.env.sym'), 'file');
    await unlockAll();
    c.expect(!exists(path.join(OUTSIDE, 'nothing')), 'dangling symlink: nothing written through it');
    fs.rmSync(P('.env.sym'), { force: true });
  } catch (e) {
    c.expect(true, `dangling symlink: SKIPPED (${e.code}: needs Developer Mode on Windows)`);
  }
  await baseline();
});

// ---------------------------------------------------------------- round 5: persistence & evasion (X*)

const git = (...a) => cp.execFileSync('git', a, { cwd: PROJECT, encoding: 'utf8' });
const shown = (since, re) => calls.slice(since).filter((x) => /Message$/.test(x.kind) && re.test(x.text || ''));

T('X1', 'Agent stages .env in git while unlocked, so lock skips it forever', 'A04', async (c) => {
  await unlockAll();
  git('add', '-f', '.env');
  const m = mark();
  await lockAll();
  c.expect(!exists(P('.env')), 'plaintext .env removed by the next lock although it was staged');
  c.expect(!git('ls-files', '--', '.env').trim(), '.env is no longer staged for commit');
  c.expect(shown(m, /staged|git/i).length, `user told: ${(shown(m, /staged|git/i)[0]?.text || 'nothing').slice(0, 140)}`);
  try { git('rm', '--cached', '-q', '--ignore-unmatch', '.env'); } catch {}
  await baseline();
});

T('X2', 'Agent hard-links .env to notes.txt while unlocked (lock refuses, plaintext stays)', 'A04', async (c) => {
  await unlockAll();
  fs.rmSync(P('notes.txt'), { force: true });
  fs.linkSync(P('.env'), P('notes.txt'));
  const m = mark();
  await lockAll();
  const left = exists(P('.env')) || /dev-key-111/.test(read(P('notes.txt')));
  c.expect(!left || shown(m, /hard link|other name|nlink/i).length, `plaintext left on disk is reported to the user: ${(shown(m, /hard link|other name/i)[0]?.text || 'NOT reported').slice(0, 160)}`);
  c.expect(true, `observed: .env ${exists(P('.env')) ? 'still plaintext' : 'locked'}, notes.txt ${/dev-key-111/.test(read(P('notes.txt'))) ? 'HOLDS the secret' : 'clean'}`);
  fs.rmSync(P('notes.txt'), { force: true });
  await baseline();
});

T('X3', 'Secret hidden in an NTFS alternate data stream (.env:hidden)', 'A04', async (c) => {
  await unlockAll();
  fs.writeFileSync(P('.env') + ':hidden', 'ADS_SECRET=ads-777');
  await lockAll();
  let ads = '';
  try { ads = fs.readFileSync(P('.env') + ':hidden', 'utf8'); } catch {}
  c.expect(!exists(P('.env')) && !/ads-777/.test(ads), 'no plaintext and no stream left after lock');
  await baseline();
});

T('X4', 'Case and folder variants: .ENV.Local, sub/.Env, App/Config/.env', 'A04', async (c) => {
  fs.mkdirSync(P('sub'), { recursive: true });
  fs.mkdirSync(P('App', 'Config'), { recursive: true });
  fs.writeFileSync(P('.ENV.Local'), 'K=case-1');
  fs.writeFileSync(P('sub', '.Env'), 'K=case-2');
  fs.writeFileSync(P('App', 'Config', '.env'), 'K=case-3');
  await lockAll();
  c.expect(!exists(P('.ENV.Local')) && !exists(P('sub', '.Env')) && !exists(P('App', 'Config', '.env')), 'all three locked');
  fs.rmSync(P('sub'), { recursive: true, force: true });
  fs.rmSync(P('App'), { recursive: true, force: true });
  await baseline();
});

T('X5', 'Secret copied into a build folder (dist/.env, build/.env.production)', 'A04', async (c) => {
  fs.mkdirSync(P('dist'), { recursive: true });
  fs.mkdirSync(P('build'), { recursive: true });
  fs.writeFileSync(P('dist', '.env'), 'API_KEY=dist-copy-555');
  fs.writeFileSync(P('build', '.env.production'), 'API_KEY=build-copy-556');
  const m = mark();
  await lockAll();
  const left = [P('dist', '.env'), P('build', '.env.production')].filter(exists);
  c.expect(!left.length, `locked (left: ${left.map((f) => path.relative(PROJECT, f)).join(', ') || 'none'})`);
  fs.rmSync(P('dist'), { recursive: true, force: true });
  fs.rmSync(P('build'), { recursive: true, force: true });
  await baseline();
});

T('X6', 'Secret still readable from an open document after lock (other extensions read textDocuments)', 'A04', async (c) => {
  await unlockAll();
  // Opened like a user does (an editor tab), not through openTextDocument: VS Code keeps documents
  // that an EXTENSION opened alive for minutes whatever Env Lock does (and that extension read it already).
  await cmd('vscode.open', vscode.Uri.file(P('.env')));
  await sleep(1000);
  await lockAll();
  await sleep(5000);
  const still = vscode.workspace.textDocuments.filter((d) => /dev-key-111/.test(d.getText()));
  c.expect(!exists(P('.env')), '.env locked');
  c.expect(!still.length, `no loaded document still holds the secret (found: ${still.map((d) => path.basename(d.uri.fsPath)).join(', ') || 'none'})`);
  await baseline();
});

T('X7', 'Agent renames .env to .env.example (allow-listed) while unlocked', 'A04', async (c) => {
  await unlockAll();
  fs.renameSync(P('.env'), P('.env.example'));
  const m = mark();
  await lockAll();
  const kept = /dev-key-111/.test(read(P('.env.example')));
  c.expect(!kept || shown(m, /\.env\.example/).length, `secret in an allow-listed file is locked or reported: ${(shown(m, /\.env\.example/)[0]?.text || (kept ? 'NOT reported' : 'locked')).slice(0, 160)}`);
  fs.rmSync(P('.env.example'), { force: true });
  fs.rmSync(P('.env.example.locked'), { force: true });
  await baseline();
});

T('X8', 'Agent pastes a live key into src/config.js while unlocked (copy outside any secret file)', 'A04', async (c) => {
  const KEY = 'sk-LIVE-8f3a9c2e71b4';
  await unlockAll();
  fs.writeFileSync(P('.env'), ENV + `STRIPE_KEY=${KEY}\n`);
  await lockAll(); // Env Lock fingerprints the values it locks
  await unlockAll();
  fs.mkdirSync(P('src'), { recursive: true });
  fs.writeFileSync(P('src', 'config.js'), `module.exports = { stripe: "${KEY}" };\n`);
  fs.writeFileSync(P('README.md'), 'The API lives at https://api.example.com (not a secret).\n');
  const m = mark();
  policy = { message: respond([[/copies of locked secret values/, 'Protect and lock']]) };
  await cmd('envLock.lock');
  c.expect(await waitFor(() => shown(m, /copies of locked secret values/).length, 15000), 'copy reported after lock');
  const msg = shown(m, /copies of locked secret values/)[0]?.text || '';
  c.expect(/config\.js/.test(msg), `names src/config.js: ${msg.slice(0, 140)}`);
  c.expect(!/README/.test(msg), 'no false alarm for README.md (plain URL)');
  c.expect(await waitFor(() => !exists(P('src', 'config.js')), 10000), '"Protect and lock" locked src/config.js');
  policy = {};
  await sleep(500);
  await unlockAll();
  fs.writeFileSync(P('.env'), ENV);
  fs.rmSync(P('src'), { recursive: true, force: true });
  fs.rmSync(P('README.md'), { force: true });
  setProject('envLock.customPatterns', undefined);
  await baseline();
}, { timeout: 90000 });

T('T16', 'Auto-lock after the timer (1 minute)', 'A04', async (c) => {
  setUser('envLock.autoLockMinutes', 1);
  await sleep(2500);
  await unlockAll();
  c.expect(exists(P('.env')), 'unlocked');
  const m = mark();
  c.expect(await waitFor(() => !exists(P('.env')), 80000, 1000), 'locked again by the timer within 80 s');
  c.expect(await waitFor(() => saw(m, /auto-lock timer/).length, 5000), 'message says "auto-lock timer"');
}, { timeout: 120000 });

T('T26', 'Lock on close: leave secrets unlocked, then quit VS Code', 'A04', async (c) => {
  await unlockAll();
  c.expect(exists(P('.env')) && exists(P('.env.production')), 'unlocked before quitting (the orchestrator checks after exit)');
});

// ---------------------------------------------------------------- phase 2 (after a restart)

const phase2 = [];
const T2 = (id, name, owasp, fn) => phase2.push({ id, name, owasp, fn });

T2('T26b', 'Lock on close: files locked after the restart', 'A04', async (c) => {
  c.expect(!exists(P('.env')) && !exists(P('.env.production')), 'no plaintext .env files after VS Code was closed');
});
T2('T08b', 'User settings weakened while VS Code was CLOSED', 'A01', async (c) => {
  // Startup dialogs may come before the scripted user is in place (answered "cancel" and kept in
  // the early list) or after (answered "cancel" by default): look in both.
  const early = (globalThis.__envLockRedteamEarly || []).map((x) => String(x.args?.[0]));
  const weak = [...early, ...calls.map((x) => x.text || '')].find((t) => /WEAKER/.test(t));
  c.expect(!!weak, 'dialog "made protection WEAKER" at startup');
  c.expect(/lockOnClose/.test(weak || '') && /confirmUnlockToDisk/.test(weak || ''), 'it names both settings');
  c.expect(
    await waitFor(() => readJson(USER_SETTINGS)['envLock.lockOnClose'] === true && readJson(USER_SETTINGS)['envLock.confirmUnlockToDisk'] === true, 15000),
    'cancelled (the default before anyone answers): values reverted'
  );
});
T2('PREP9','Prepare F9: rewrite the vault salt while VS Code runs', '-', async (c) => {
  const v = vault();
  const meta = path.join(v.dir, 'vault.json');
  const j = readJson(meta);
  fs.writeFileSync(path.join(ROOT, 'real-salt.txt'), j.salt);
  j.salt = Buffer.alloc(32, 7).toString('base64');
  writeJson(meta, j);
  c.expect(true, 'vault.json salt rewritten');
});

const phase3 = [];
const phase4 = [];
phase2.push({
  id: 'T29',
  name: 'Vault salt rewritten in vault.json (F9)',
  owasp: 'A08',
  fn: async (c) => {
    fs.writeFileSync(P('.env.trigger'), 'X=1'); // make Env Lock re-scan (it also does every 60 s)
    await sleep(1500);
    fs.unlinkSync(P('.env.trigger'));
    const texts = () => [...(globalThis.__envLockRedteamEarly || []).map((x) => String(x.args?.[0])), ...calls.map((x) => x.text || '')];
    c.expect(await waitFor(() => texts().some((t) => /vault\.json of vault .* was changed/.test(t)), 15000), 'reported "vault.json … was changed by something other than Env Lock"');
    c.expect(!fs.existsSync(P('.env')), 'nothing was unlocked from the tampered vault at startup');
    const m = mark();
    await unlockAll();
    const summary = calls.slice(m).map((x) => x.text || '').filter((t) => /vault|unlock|REFUSED/i.test(t) && !/passphrase/i.test(t));
    c.expect(!/dev-key-111/.test(read(P('.env'))), 'an unlock attempt does not restore anything from it');
    c.expect(true, `observed on unlock: ${summary.map((t) => t.replace(/\s+/g, ' ').slice(0, 140)).join(' || ') || 'nothing'}`);
  },
});

phase2.push({
  id: 'T29r',
  name: 'Restore the real vault salt (cleanup after T29)',
  owasp: '-',
  fn: async (c) => {
    const v = vault();
    const meta = path.join(v.dir, 'vault.json');
    const j = readJson(meta);
    j.salt = read(path.join(ROOT, 'real-salt.txt'));
    writeJson(meta, j);
    c.expect(true, 'restored');
  },
});
const T3 = (id, name, owasp, fn, opts = {}) => phase3.push({ id, name, owasp, fn, ...opts });
T3('T21', 'Env Lock ITSELF replaced by a same-id extension (F3)', 'A08', async (c) => {
  const m = mark();
  cli('--install-extension', process.env.REDTEAM_FAKE_VSIX, '--force');
  const seen = await waitFor(() => saw(m, /Env Lock ITSELF was/).length, 45000);
  c.expect(seen, 'the running Env Lock warned "Env Lock ITSELF was updated, replaced or removed"');
  const e = vscode.extensions.getExtension('local.env-lock');
  c.expect(true, `observed: getExtension("local.env-lock") now reports version ${e?.packageJSON?.version}`);
}, { timeout: 90000 });


const T4 = (id, name, owasp, fn, opts = {}) => phase4.push({ id, name, owasp, fn, ...opts });
T4('T30', 'Env Lock credential store wiped (deleted VS Code state, reset, or reinstall)', 'A08', async (c) => {
  // The orchestrator ran `code --uninstall-extension local.env-lock` + `--install-extension` between
  // phases 1 and 2 (needed to remove test 21's fake). Does Env Lock still know its keyring, signing
  // key, pins and version history?
  const m = mark();
  await unlockAll();
  const summary = saw(m, /unlocked \d+ file/)[0]?.text || '';
  const dialogs = calls.slice(m).map((x) => x.text || '').filter((t) => t && !/passphrase/i.test(t));
  c.expect(/dev-key-111/.test(read(P('.env'))), 'unlock restores the real .env');
  c.expect(!/REFUSED/.test(summary), `no file refused (signing key kept): ${summary.slice(0, 160)}`);
  const early = (globalThis.__envLockRedteamEarly || []).map((x) => String(x.args?.[0]));
  const startup = [...early, ...calls.map((x) => x.text || '')];
  c.expect(startup.some((t) => /protected records are gone although you have keys/.test(t)), 'the wipe is reported at startup ("protected records are gone although you have keys")');
  c.expect(true, `observed dialogs: ${dialogs.map((t) => t.replace(/\s+/g, ' ').slice(0, 90)).join(' || ') || 'none'}`);
  await lockAll();
});

// ================================================================ run

async function runAll(list) {
  const results = [];
  for (const t of list) {
    const c = new Check();
    const start = Date.now();
    let error;
    try {
      await Promise.race([t.fn(c), sleep(t.timeout || 60000).then(() => Promise.reject(new Error('test timed out')))]);
    } catch (e) {
      error = String(e && e.stack ? e.stack.split('\n').slice(0, 3).join(' ') : e);
    }
    policy = {};
    const status = error ? 'error' : c.items.every((i) => i.ok) ? 'pass' : 'fail';
    results.push({ id: t.id, name: t.name, owasp: t.owasp, status, checks: c.items, error, ms: Date.now() - start });
  }
  return results;
}

exports.run = async function run() {
  globalThis.__envLockRedteam = { answer };
  const ext = vscode.extensions.getExtension('local.env-lock');
  let results;
  try {
    if (!ext) throw new Error('Env Lock (local.env-lock) is not installed in the test profile');
    await ext.activate();
    await sleep(3000); // startup locking, settings review
    const only = (process.env.REDTEAM_ONLY || '').split(',').filter(Boolean);
    const pick = (list) => (only.length ? list.filter((t) => t.id === 'S0' || only.includes(t.id)) : list);
    results = await runAll(pick({ 1: tests, 2: phase2, 3: phase3, 4: phase4 }[PHASE]));
  } catch (e) {
    results = [{ id: 'HARNESS', name: 'harness', status: 'error', error: String(e.stack || e), checks: [] }];
  }
  const early = (globalThis.__envLockRedteamEarly || []).map((x) => ({ kind: x.kind, text: String(x.args?.[0]).slice(0, 300) }));
  const log = calls.map((x) => ({ kind: x.kind, text: (x.text || '').slice(0, 300), buttons: x.buttons, answer: x.answer }));
  fs.writeFileSync(OUT, JSON.stringify({ phase: PHASE, version: ext?.packageJSON?.version, results, early, log }, null, 2));
  // Quit like a user would, so Env Lock's deactivate (lock on close) runs normally.
  await vscode.commands.executeCommand('workbench.action.quit');
  await sleep(60000);
};
