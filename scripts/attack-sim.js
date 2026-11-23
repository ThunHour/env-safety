#!/usr/bin/env node
/**
 * Env Lock attack simulator: does what a hostile AI agent running as you could do, so each defense
 * can be checked in a real VS Code window. See docs/attack-tests.md.
 *
 * Everything happens under .attack-test/ (its own VS Code user data, keyring, vault and project),
 * never in your real ~/.env-lock. Run `npm run compile` first (it uses the compiled out/ modules).
 *
 *   node scripts/attack-sim.js <command>
 */
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const REPO = path.join(__dirname, '..');
const ROOT = path.join(REPO, '.attack-test');
const HOME = path.join(ROOT, 'home');
const KEYRING = path.join(HOME, 'keyring.json');
const VAULT_ROOT = path.join(HOME, 'vault');
const PROJECT = path.join(ROOT, 'project');
const USER_SETTINGS = path.join(ROOT, 'user-data', 'User', 'settings.json');
const PROJECT_SETTINGS = path.join(PROJECT, '.vscode', 'settings.json');
const SNAPSHOT = path.join(ROOT, 'snapshot');

function load(mod) {
  const file = path.join(REPO, 'out', mod + '.js');
  if (!fs.existsSync(file)) fail('out/ is missing: run `npm run compile` first.');
  return require(file);
}
function fail(msg) {
  console.error('✖ ' + msg);
  process.exit(1);
}
const readJson = (f, d = {}) => (fs.existsSync(f) ? JSON.parse(fs.readFileSync(f, 'utf8')) : d);
const writeJson = (f, j) => {
  fs.mkdirSync(path.dirname(f), { recursive: true });
  fs.writeFileSync(f, JSON.stringify(j, null, 2) + '\n');
};
function keyring() {
  if (!fs.existsSync(KEYRING)) fail(`no keyring at ${KEYRING}: run "Env Lock: Set up post-quantum keys" in the test window first.`);
  return load('crypto').parseKeyring(fs.readFileSync(KEYRING, 'utf8'));
}
function vault() {
  const id = readJson(PROJECT_SETTINGS)['envLock.vaultId'];
  if (!id) fail('the project has no envLock.vaultId yet: lock once in the test window first.');
  const dir = path.join(VAULT_ROOT, id);
  const meta = readJson(path.join(dir, 'vault.json'), null);
  if (!meta) fail(`no vault at ${dir}`);
  return { id, dir, salt: Buffer.from(meta.salt, 'base64') };
}
// An agent can compute blob names too: vault.json (with the salt) is readable.
const blobOf = (v, rel) => path.join(v.dir, load('vault').blobName(v.salt, rel));

const commands = {
  setup: [
    'Create the isolated test environment (project, user settings, git repo).',
    () => {
      fs.mkdirSync(PROJECT, { recursive: true });
      fs.writeFileSync(path.join(PROJECT, '.env'), 'API_KEY=dev-key-111\nAPI_URL=https://api.example.com\n');
      fs.writeFileSync(path.join(PROJECT, '.env.production'), 'API_KEY=PRODUCTION-key-999\nAPI_URL=https://api.example.com\n');
      fs.writeFileSync(path.join(PROJECT, 'index.js'), "console.log('API_KEY =', process.env.API_KEY);\n");
      writeJson(USER_SETTINGS, { 'envLock.keyringPath': KEYRING, 'envLock.vaultPath': VAULT_ROOT });
      try {
        execFileSync('git', ['init', '-q'], { cwd: PROJECT });
      } catch {
        console.log('  (git not found: skip test 15)');
      }
      console.log(`✔ test project: ${PROJECT}\n✔ isolated user settings: ${USER_SETTINGS}`);
      console.log('Next: in VS Code, Run and Debug → "Env Lock: attack tests (isolated)".');
    },
  ],
  'swap-keyring': [
    'Test 2: replace keyring.json with an attacker keyring (a backup of yours is kept).',
    async () => {
      keyring();
      fs.copyFileSync(KEYRING, KEYRING + '.real');
      const k = await load('crypto').createKeyring({ passphrase: 'attacker passphrase 123' });
      fs.writeFileSync(KEYRING, JSON.stringify(k, null, 2));
      console.log(`✔ keyring swapped (attacker key ${k.keyId}). Restore with: restore-keyring`);
    },
  ],
  'restore-keyring': [
    'Undo swap-keyring.',
    () => {
      if (!fs.existsSync(KEYRING + '.real')) fail('nothing to restore');
      fs.renameSync(KEYRING + '.real', KEYRING);
      console.log('✔ your keyring is back');
    },
  ],
  'plant-unsigned': [
    'Test 3a: plant an UNSIGNED locked .env (made with your public key) that points at an attacker URL.',
    () => {
      const C = load('crypto');
      const text = C.encryptFile(Buffer.from('API_KEY=attacker\nAPI_URL=https://attacker.example\n'), C.publicKeys(keyring()));
      fs.writeFileSync(path.join(PROJECT, '.env.locked'), text);
      console.log('✔ planted .env.locked (unsigned)');
    },
  ],
  'plant-forged': [
    'Test 3b: plant a locked .env signed with a key that is NOT yours.',
    () => {
      const C = load('crypto');
      const locked = C.encryptFile(Buffer.from('API_URL=https://attacker.example\n'), C.publicKeys(keyring()));
      fs.writeFileSync(path.join(PROJECT, '.env.locked'), C.signLocked(locked, C.newMacKey(), load('vault').fileBinding('.env')));
      console.log('✔ planted .env.locked (forged signature)');
    },
  ],
  'swap-blobs': [
    'Test 4: copy the .env.production vault blob over the .env blob (production keys loaded as dev).',
    () => {
      const v = vault();
      const prod = blobOf(v, '.env.production');
      if (!fs.existsSync(prod)) fail('.env.production is not in the vault: lock all first.');
      fs.copyFileSync(prod, blobOf(v, '.env'));
      console.log('✔ .env blob replaced by the .env.production blob');
    },
  ],
  'save-env': [
    'Test 5 (step 1): keep a copy of the current locked .env (the "old version").',
    () => {
      const b = blobOf(vault(), '.env');
      if (!fs.existsSync(b)) fail('.env is not in the vault: lock first.');
      fs.mkdirSync(SNAPSHOT, { recursive: true });
      fs.copyFileSync(b, path.join(SNAPSHOT, 'env.blob'));
      console.log('✔ saved the current locked .env');
    },
  ],
  'rollback-env': [
    'Test 5 (step 2): put the old locked .env back (rollback).',
    () => {
      const src = path.join(SNAPSHOT, 'env.blob');
      if (!fs.existsSync(src)) fail('run save-env first');
      fs.copyFileSync(src, blobOf(vault(), '.env'));
      console.log('✔ old version of .env put back');
    },
  ],
  'delete-vault': [
    'Test 6: delete every locked file in the vault.',
    () => {
      const v = vault();
      const gone = fs.readdirSync(v.dir).filter((n) => n.endsWith('.locked'));
      for (const n of gone) fs.unlinkSync(path.join(v.dir, n));
      console.log(`✔ deleted ${gone.length} locked file(s) (.prev copies kept)`);
    },
  ],
  'weaken-project': [
    'Test 7: try to switch protection off through the PROJECT settings.',
    () => {
      const j = readJson(PROJECT_SETTINGS);
      Object.assign(j, {
        'envLock.lockOnClose': false,
        'envLock.autoLockMinutes': 0,
        'envLock.allowList': ['**'],
        'envLock.confirmUnlockToDisk': false,
        'envLock.storage': 'inPlace',
      });
      writeJson(PROJECT_SETTINGS, j);
      console.log('✔ project settings weakened');
    },
  ],
  'weaken-user': [
    'Test 8: try to switch protection off through the USER settings file.',
    () => {
      const j = readJson(USER_SETTINGS);
      Object.assign(j, { 'envLock.lockOnClose': false, 'envLock.confirmUnlockToDisk': false, 'envLock.autoLockMinutes': 0 });
      writeJson(USER_SETTINGS, j);
      console.log('✔ user settings weakened');
    },
  ],
  'change-vault-id': [
    "Test 9: point the project's envLock.vaultId at a new, empty vault.",
    () => {
      const j = readJson(PROJECT_SETTINGS);
      j['envLock.vaultId'] = load('vault').newVaultId();
      writeJson(PROJECT_SETTINGS, j);
      console.log(`✔ vaultId changed to ${j['envLock.vaultId']}`);
    },
  ],
  'clean-project-settings': [
    'After tests 7 and 9: remove the attack values from the project settings (keeps the real vaultId).',
    () => {
      const j = readJson(PROJECT_SETTINGS);
      for (const k of Object.keys(j)) if (k !== 'envLock.vaultId') delete j[k];
      writeJson(PROJECT_SETTINGS, j);
      console.log('✔ project settings cleaned (fix envLock.vaultId by hand if test 9 changed it)');
    },
  ],
  'plant-env-local': [
    'Test 19: plant a PLAINTEXT .env.local that redirects API_URL and adds NODE_OPTIONS.',
    () => {
      fs.writeFileSync(path.join(PROJECT, '.env.local'), 'API_URL=https://attacker.example\nNODE_OPTIONS=--require ./x.js\n');
      console.log('✔ planted .env.local (delete it to undo)');
    },
  ],
  'plant-npm-cmd': [
    'Test 20: plant npm.cmd in the project folder (cmd.exe would run it instead of the real npm).',
    () => {
      fs.writeFileSync(path.join(PROJECT, 'npm.cmd'), '@echo STOLEN API_KEY=%API_KEY%\r\n');
      console.log('✔ planted npm.cmd (delete it to undo)');
    },
  ],
  'redos-pattern': [
    'Test 23: add a catastrophic glob to the project settings and a deep folder to match it against.',
    () => {
      const j = readJson(PROJECT_SETTINGS);
      j['envLock.customPatterns'] = ['**/**/**/**/**/**/**/**/**/**/**/**/x'];
      writeJson(PROJECT_SETTINGS, j);
      const deep = path.join(PROJECT, ...Array(30).fill('a'));
      fs.mkdirSync(deep, { recursive: true });
      fs.writeFileSync(path.join(deep, 'y'), '');
      console.log('✔ pattern added (undo: clean-project-settings, and delete .attack-test/project/a)');
    },
  ],
  'shrink-presets': [
    'Test 24: drop "auto" from the USER presets (only dotenv stays protected).',
    () => {
      const j = readJson(USER_SETTINGS);
      j['envLock.presets'] = ['dotenv'];
      writeJson(USER_SETTINGS, j);
      console.log('✔ user presets shrunk to ["dotenv"]');
    },
  ],
  'fsmonitor': [
    "Test 28: make the project's git run a command (core.fsmonitor) whenever Env Lock calls git.",
    () => {
      const marker = path.join(ROOT, 'FSMONITOR-RAN');
      const script = path.join(ROOT, 'fsmon.js');
      fs.writeFileSync(script, `require('fs').appendFileSync(${JSON.stringify(marker)}, new Date().toISOString() + '\\n');\n`);
      execFileSync('git', ['config', 'core.fsmonitor', `node "${script.replace(/\\/g, '/')}"`], { cwd: PROJECT });
      console.log(`✔ core.fsmonitor set. Expect NO file ${marker} after Env Lock refreshes. Undo: git config --unset core.fsmonitor`);
    },
  ],
  'junction': [
    'Test 27: replace the project folder "config" with a junction to a folder OUTSIDE the project.',
    () => {
      const target = path.join(ROOT, 'outside');
      fs.mkdirSync(target, { recursive: true });
      const link = path.join(PROJECT, 'config');
      if (fs.existsSync(link)) fs.rmSync(link, { recursive: true });
      fs.symlinkSync(target, link, 'junction');
      console.log(`✔ config → ${target}. After unlocking, nothing may appear in ${target}.`);
    },
  ],
  status: [
    'Show what is where (no secrets).',
    () => {
      const ls = (d) => (fs.existsSync(d) ? fs.readdirSync(d) : []);
      console.log('project :', ls(PROJECT).filter((n) => n.startsWith('.env')).join(', ') || '(no .env files)');
      const id = readJson(PROJECT_SETTINGS)['envLock.vaultId'];
      console.log('vault   :', id ? `${id}: ${ls(path.join(VAULT_ROOT, id)).join(', ') || '(empty)'}` : '(none yet)');
      console.log('keyring :', fs.existsSync(KEYRING) ? KEYRING : '(none yet)');
    },
  ],
  reset: [
    'Delete the whole test environment.',
    () => {
      fs.rmSync(ROOT, { recursive: true, force: true });
      console.log('✔ .attack-test removed');
    },
  ],
};

const name = process.argv[2];
if (!commands[name]) {
  console.log('Env Lock attack simulator (isolated in .attack-test/). Commands:\n');
  for (const [n, [desc]] of Object.entries(commands)) console.log(`  ${n.padEnd(24)} ${desc}`);
  process.exit(name ? 1 : 0);
}
Promise.resolve(commands[name][1]()).catch((e) => fail(e.message));
