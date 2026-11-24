const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const C = require('../out/crypto');
const { parseDotenv } = require('../out/dotenv');
const { applyAgentRules, HOOK_REL_PATH } = require('../out/agentRules');
const P = require('../out/patterns');
const { readKeyring, writeKeyring } = require('../out/keyring');

const SAMPLE = Buffer.from('API_KEY=sk-live-123\nDB_PASS="p@ss word"\n');
const PASS = { passphrase: 'correct horse battery' };

let keyring; // shared: scrypt N=2^17 is deliberately slow
test.before(async () => {
  keyring = await C.createKeyring(PASS);
});

// ------------------------------------------------------------ PQC crypto

test('keyring: public part needs no passphrase, private part is sealed', async () => {
  assert.strictEqual(keyring.alg, 'ML-KEM-768+X25519/HKDF-SHA256/AES-256-GCM');
  assert.strictEqual(Buffer.from(keyring.public.mlkem, 'base64').length, 1184); // ML-KEM-768 pk
  assert.strictEqual(Buffer.from(keyring.public.x25519, 'base64').length, 32);
  assert.ok(!JSON.stringify(keyring).includes('"mlkem":"' + keyring.public.mlkem + '","x25519":"MC4'), 'no plaintext private key');
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'envlock-')), 'k', 'keyring.json');
  await writeKeyring(file, keyring);
  assert.deepStrictEqual(await readKeyring(file), keyring);
});

test('lock with public key only, unlock with passphrase', async () => {
  const locked = C.encryptFile(SAMPLE, C.publicKeys(keyring)); // no secret involved
  assert.ok(C.isLockedFile(locked));
  assert.ok(!locked.includes('sk-live-123'));
  const j = JSON.parse(locked);
  assert.strictEqual(Buffer.from(j.kem.mlkem, 'base64').length, 1088); // ML-KEM-768 ciphertext
  const priv = await C.openKeyring(keyring, PASS);
  assert.ok(C.decryptFile(locked, priv).equals(SAMPLE));
});

test('each lock uses a fresh encapsulation', () => {
  const pub = C.publicKeys(keyring);
  const a = JSON.parse(C.encryptFile(SAMPLE, pub));
  const b = JSON.parse(C.encryptFile(SAMPLE, pub));
  assert.notStrictEqual(a.kem.mlkem, b.kem.mlkem);
  assert.notStrictEqual(a.kem.x25519, b.kem.x25519);
  assert.notStrictEqual(a.data, b.data);
});

test('wrong passphrase is rejected', async () => {
  await assert.rejects(C.openKeyring(keyring, { passphrase: 'wrong horse battery' }), C.WrongPassphraseError);
});

test('tampering with ciphertext, KEM ciphertext or header is detected', async () => {
  const priv = await C.openKeyring(keyring, PASS);
  const base = JSON.parse(C.encryptFile(SAMPLE, C.publicKeys(keyring)));
  const flip = (s) => {
    const b = Buffer.from(s, 'base64');
    b[5] ^= 1;
    return b.toString('base64');
  };
  for (const mutate of [
    (j) => (j.data = flip(j.data)),
    (j) => (j.kem.mlkem = flip(j.kem.mlkem)),
    (j) => (j.kem.x25519 = flip(j.kem.x25519)),
    (j) => (j.iv = flip(j.iv)),
    (j) => (j.tag = flip(j.tag)),
  ]) {
    const j = structuredClone(base);
    mutate(j);
    assert.throws(() => C.decryptFile(JSON.stringify(j), priv), /corrupted|modified/);
  }
});

test('file locked for another keyring is refused with WrongKeyError', async () => {
  const other = await C.createKeyring({ passphrase: 'another passphrase' });
  const locked = C.encryptFile(SAMPLE, C.publicKeys(other));
  const priv = await C.openKeyring(keyring, PASS);
  assert.throws(() => C.decryptFile(locked, priv), C.WrongKeyError);
});

test('key file is a required second factor; reseal keeps files valid', async () => {
  const keyFile = C.generateKeyFile();
  const k2 = await C.resealKeyring(keyring, PASS, { passphrase: 'new passphrase here', keyFile });
  assert.strictEqual(C.keyringNeedsKeyFile(k2), true);
  await assert.rejects(C.openKeyring(k2, { passphrase: 'new passphrase here' }), C.WrongPassphraseError);
  await assert.rejects(C.openKeyring(k2, { passphrase: 'new passphrase here', keyFile: C.generateKeyFile() }), C.WrongPassphraseError);
  const locked = C.encryptFile(SAMPLE, C.publicKeys(keyring)); // locked with the OLD keyring object
  const priv = await C.openKeyring(k2, { passphrase: 'new passphrase here', keyFile });
  assert.ok(C.decryptFile(locked, priv).equals(SAMPLE));
});

test('swapped public key in keyring is detected', () => {
  const bad = structuredClone(keyring);
  bad.public.x25519 = Buffer.alloc(32, 7).toString('base64');
  assert.throws(() => C.parseKeyring(JSON.stringify(bad)), /does not match/);
});

// ------------------------------------------------------------ patterns

test('glob matching', () => {
  const m = (p, g) => P.matchesAny(p, [g]);
  assert.ok(m('.env', '**/.env'));
  assert.ok(m('apps/web/.env', '**/.env'));
  assert.ok(m('D:\\proj\\.env.local', '**/.env.*'));
  assert.ok(!m('.envrc', '**/.env'));
  assert.ok(m('android/app/upload.jks', '**/*.jks'));
  assert.ok(m('config/master.key', '**/config/master.key'));
  assert.ok(!m('src/config/master.key.ts', '**/config/master.key'));
  assert.ok(m('src/main/resources/application-secret-prod.yml', '**/application-secret*.yml'));
  assert.ok(m('a/config/secrets.yml', 'config/secrets.yml'), 'custom relative pattern matches at depth');
  assert.ok(m('x.yaml', '*.{yml,yaml}'));
  assert.deepStrictEqual(P.expandBraces('a.{x,y}.{1,2}'), ['a.x.1', 'a.x.2', 'a.y.1', 'a.y.2']);
});

test('presets: auto = dotenv + cloud + detected languages + custom', () => {
  const pats = P.resolvePatterns(['auto'], new Set(['flutter', 'java']), ['config/secrets.yml']);
  assert.ok(pats.includes('**/.env'));
  assert.ok(pats.includes('**/credentials.json'));
  assert.ok(pats.includes('**/key.properties'));
  assert.ok(pats.includes('**/application-local.yml'));
  assert.ok(pats.includes('config/secrets.yml'));
  assert.ok(!pats.includes('**/*.tfvars'), 'terraform not detected');
  assert.ok(!pats.includes('**/*.pem'), 'keys preset is opt-in');
  assert.ok(P.resolvePatterns(['keys'], new Set(), []).includes('**/.env'), 'dotenv is always on');
});

test('presets cover the secret files of each framework, and only when detected', () => {
  const all = new Set(P.PRESETS.map((p) => p.id).filter((id) => id !== 'keys')); // keys (*.key, *.pem) is opt-in
  const pats = P.resolvePatterns(['auto'], all, []);
  const secret = [
    // any framework (always on)
    '.env', 'api/.env.local', '.env.production', 'deploy/prod.env', '.envrc', 'gcp/service-account-prod.json',
    // .NET / ASP.NET
    'src/Api/appsettings.Development.json', 'src/Api/appsettings.Local.json',
    'src/Api/Properties/PublishProfiles/Azure.pubxml.user', 'MyApp.PublishSettings', 'certs/dev.pfx',
    // Python: Flask, Django, Dynaconf
    'instance/config.py', 'instance/prod.cfg', 'mysite/settings/local.py', 'app/local_settings.py', '.secrets.toml',
    // PHP: Laravel, Symfony, Composer
    'storage/oauth-private.key', 'config/secrets/prod/prod.decrypt.private.php', 'auth.json',
    // Go
    '.netrc', 'config.local.yaml', 'cmd/server/config.local.json',
    // Elixir / Phoenix, Rails, Spring, Node
    'config/prod.secret.exs', 'config/master.key', 'src/main/resources/application-local.yml', '.npmrc',
    'functions/.runtimeconfig.json',
  ];
  for (const f of secret) assert.ok(P.matchesAny(f, pats), `should protect ${f}`);

  const notSecret = [
    'appsettings.json', 'src/Api/Program.cs', 'go.mod', 'main.go', 'config.yaml', 'app/__init__.py',
    'routes/web.php', 'storage/oauth-public.key', 'mix.exs', 'config/config.exs', '.flaskenv', 'package.json',
  ];
  for (const f of notSecret) assert.ok(!P.matchesAny(f, pats), `should NOT protect ${f}`);
  for (const f of ['.env.example', '.envrc.example']) assert.ok(P.matchesAny(f, P.DEFAULT_ALLOW), `${f} is allow-listed`);

  // Framework presets only switch on when detected.
  const plain = P.resolvePatterns(['auto'], new Set(), []);
  assert.ok(!plain.includes('**/.netrc') && !plain.includes('**/instance/config.py') && !plain.includes('**/config/*.secret.exs'));
  for (const id of ['go', 'elixir']) assert.ok(P.PRESETS.find((p) => p.id === id).detect.length, `${id} has detection`);
});

// ------------------------------------------------------------ dotenv

test('dotenv parser', () => {
  const env = parseDotenv(
    ['# c', 'export A=1', 'B = two # trailing', 'C="line1\\nline2"', "D='raw \\n'", 'E="multi', 'line"', 'F=', 'URL=http://x/#frag'].join('\r\n')
  );
  assert.deepStrictEqual(env, { A: '1', B: 'two', C: 'line1\nline2', D: 'raw \\n', E: 'multi\nline', F: '', URL: 'http://x/#frag' });
});

test('dotenv parser is linear on an unclosed quote (a planted file must not freeze VS Code)', () => {
  const s = 'A="' + '\nxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'.repeat(40000); // 1.6 MB; 0.8 MB took 54 s before
  const t = Date.now();
  const env = parseDotenv(s);
  assert.ok(Date.now() - t < 500, `took ${Date.now() - t} ms`);
  assert.ok(env.A.startsWith('\nxxx'));
  // an escaped quote at a line end still continues the value
  assert.deepStrictEqual(parseDotenv('A="x\\\\"\nB=1'), { A: 'x\\', B: '1' });
  assert.deepStrictEqual(parseDotenv('A="x\\"\ny"\nB=1'), { A: 'x"\ny', B: '1' });
});

test('R11 signing key is derived from the private key: back after a wiped store, impossible without it', async () => {
  const priv = await C.openKeyring(keyring, PASS);
  const k1 = C.macKeyFromPrivate(priv);
  const k2 = C.macKeyFromPrivate(await C.openKeyring(keyring, PASS));
  assert.ok(k1.equals(k2), 'same key every time you unlock (survives a wiped credential store)');
  const other = await C.createKeyring({ passphrase: 'another passphrase' });
  assert.ok(!k1.equals(C.macKeyFromPrivate(await C.openKeyring(other, { passphrase: 'another passphrase' }))), 'another keyring, another key');
  // A file signed before the wipe (stored key == derived key) verifies with the re-derived key;
  // a file signed with an older random key still verifies while that key is also offered.
  const legacy = C.newMacKey();
  const f1 = C.signLocked(C.encryptFile(SAMPLE, C.publicKeys(keyring)), k1, 'file:.env');
  const f2 = C.signLocked(C.encryptFile(SAMPLE, C.publicKeys(keyring)), legacy, 'file:.env');
  assert.strictEqual(C.verifyLocked(f1, [legacy, k2], 'file:.env').state, 'valid');
  assert.strictEqual(C.verifyLocked(f2, [legacy, k2], 'file:.env').state, 'valid');
  assert.strictEqual(C.verifyLocked(f2, [k2], 'file:.env').state, 'invalid', 'the lost random key cannot be recovered');
  assert.strictEqual(C.verifyLocked(f1, [C.newMacKey(), C.newMacKey()], 'file:.env').state, 'invalid');
});

test('R8 run with secrets never mixes .env.production into a run you did not choose it for', () => {
  const D = require('../out/dotenv');
  const names = ['.env', '.env.local', '.env.production', '.env.production.local', '.env.test', 'staging.env', '.envrc'];
  assert.deepStrictEqual(D.dotenvModes(names), ['production', 'staging', 'test']);
  assert.deepStrictEqual(D.dotenvPlan(names), ['.env', '.envrc', '.env.local'], 'no environment: base files only');
  assert.deepStrictEqual(D.dotenvPlan(names, 'production'), ['.env', '.envrc', '.env.production', '.env.local', '.env.production.local']);
  assert.deepStrictEqual(D.dotenvPlan(names, 'staging'), ['.env', '.envrc', 'staging.env', '.env.local']);
  assert.deepStrictEqual(D.dotenvModes(['.env', '.env.local']), [], 'no question when there is nothing to choose');
});

test('R9 the secret scan does not honour .ignore files, skips only excluded folders, never follows links', async () => {
  const { scanFiles } = require('../out/scan');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'envlock-scan-'));
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'envlock-out-'));
  fs.writeFileSync(path.join(root, '.env.hidden'), 'X=1');
  fs.writeFileSync(path.join(root, '.ignore'), '.env.hidden\n');
  fs.writeFileSync(path.join(root, '.rgignore'), '.env.hidden\n');
  fs.mkdirSync(path.join(root, 'node_modules', 'x'), { recursive: true });
  fs.writeFileSync(path.join(root, 'node_modules', 'x', '.env'), 'X=1');
  fs.mkdirSync(path.join(root, 'api'));
  fs.writeFileSync(path.join(root, 'api', '.env'), 'X=1');
  fs.writeFileSync(path.join(outside, '.env'), 'X=1');
  fs.symlinkSync(outside, path.join(root, 'linked'), 'junction');
  const { files, truncated } = await scanFiles(root, ['**/node_modules/**', '**/.git/**']);
  assert.ok(files.includes('.env.hidden'), '.ignore / .rgignore do not hide files');
  assert.ok(files.includes('api/.env'));
  assert.ok(!files.some((f) => f.startsWith('node_modules/')), 'excluded folder skipped');
  assert.ok(!files.includes('linked/.env'), 'links are never followed');
  assert.strictEqual(truncated, false);
  assert.strictEqual((await scanFiles(root, [], { maxEntries: 3 })).truncated, true, 'limits are reported');
});

test('T07 settings files with comments and trailing commas are read (to report ignored project settings)', () => {
  const Pol2 = require('../out/policy');
  const j = Pol2.parseJsonc('{\n // comment\n "envSafety.lockOnClose": false, /* block */\n "url": "http://x//y",\n "a": [1,2,],\n}\n');
  assert.deepStrictEqual(j, { 'envSafety.lockOnClose': false, url: 'http://x//y', a: [1, 2] });
  assert.strictEqual(Pol2.parseJsonc('{ broken'), undefined);
});

// ------------------------------------------------------------ agent rules + hook

const PATTERNS = P.resolvePatterns(['auto'], new Set(['android', 'ruby']), ['config/secrets.yml']);

test('agent rules are idempotent, merge settings, and track managed rules', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'envlock-'));
  fs.mkdirSync(path.join(root, '.claude'));
  fs.writeFileSync(path.join(root, '.claude', 'settings.json'), JSON.stringify({ permissions: { allow: ['Bash(npm test)'], deny: ['Bash(rm -rf *)'] } }));
  fs.writeFileSync(path.join(root, '.cursorignore'), 'dist/\n');

  assert.ok((await applyAgentRules(root, PATTERNS, P.DEFAULT_ALLOW)).length > 0);
  assert.deepStrictEqual(await applyAgentRules(root, PATTERNS, P.DEFAULT_ALLOW), [], 'second run changes nothing');

  let s = JSON.parse(fs.readFileSync(path.join(root, '.claude', 'settings.json'), 'utf8'));
  assert.deepStrictEqual(s.permissions.allow, ['Bash(npm test)']);
  assert.ok(s.permissions.deny.includes('Bash(rm -rf *)'));
  assert.ok(s.permissions.deny.includes('Read(**/*.jks)'));
  assert.ok(s.permissions.deny.includes('Read(./config/secrets.yml)'));
  const cursor = fs.readFileSync(path.join(root, '.cursorignore'), 'utf8');
  assert.ok(cursor.startsWith('dist/\n') && cursor.includes('**/config/master.key') && cursor.includes('!**/.env.example'));

  // removing a pattern removes only its managed rules
  await applyAgentRules(root, PATTERNS.filter((p) => p !== '**/*.jks'), P.DEFAULT_ALLOW);
  s = JSON.parse(fs.readFileSync(path.join(root, '.claude', 'settings.json'), 'utf8'));
  assert.ok(!s.permissions.deny.includes('Read(**/*.jks)'));
  assert.ok(s.permissions.deny.includes('Bash(rm -rf *)'), 'user rule kept');
  assert.strictEqual(s.hooks.PreToolUse.length, 1);
});

test('Claude Code hook blocks protected files of any language, allows the rest', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'envlock-'));
  await applyAgentRules(root, PATTERNS, P.DEFAULT_ALLOW);
  const hook = path.join(root, HOOK_REL_PATH);
  const run = (tool_name, tool_input) =>
    spawnSync(process.execPath, [hook], { input: JSON.stringify({ tool_name, tool_input }) }).status;

  const blocked = [
    ['Read', { file_path: 'D:\\proj\\.env' }],
    ['Read', { file_path: '/home/u/proj/.env.local' }],
    ['Read', { file_path: '/p/android/app/release.jks' }],
    ['Read', { file_path: '/p/config/master.key' }],
    ['Read', { file_path: '/p/config/secrets.yml' }],
    ['Read', { file_path: '/p/service-account-prod.json' }],
    ['Edit', { file_path: '/p/android/key.properties', old_string: 'a', new_string: 'b' }],
    ['Bash', { command: 'cat .env' }],
    ['Bash', { command: 'cat .e*' }],
    ['Bash', { command: 'cat config/master.key | base64' }],
    ['PowerShell', { command: 'Get-Content ./.env.production | Select -First 3' }],
    ['Bash', { command: 'echo $(<.env)' }],
    ['Bash', { command: 'node -e "console.log(process.env)"' }],
    ['Grep', { pattern: 'KEY', glob: '.env*' }],
    ['Bash', { command: 'cat .envrc' }], // direnv files hold exported secrets too
  ];
  for (const [t, i] of blocked) assert.strictEqual(run(t, i), 2, `should block ${t} ${JSON.stringify(i)}`);

  const allowed = [
    ['Read', { file_path: '/proj/.env.example' }],
    ['Read', { file_path: '/proj/src/index.ts' }],
    ['Read', { file_path: '/proj/.env.locked' }],
    ['Read', { file_path: '/proj/.env.envsafe' }],
    ['Read', { file_path: '/proj/src/config/master.key.ts' }],
    ['Edit', { file_path: '/proj/src/a.ts', old_string: 'process.env.X', new_string: 'y' }],
    ['Bash', { command: 'node -e "console.log(process.env.NODE_ENV)"' }],
    ['Bash', { command: 'ls *' }],
    ['Bash', { command: 'npm test -- src/*.ts' }],
    ['Bash', { command: 'cat .envrc.example' }],
    ['Grep', { pattern: 'TODO', path: 'src' }],
  ];
  for (const [t, i] of allowed) assert.strictEqual(run(t, i), 0, `should allow ${t} ${JSON.stringify(i)}`);
});

// ------------------------------------------------------------ vault

const V = require('../out/vault');

test('vault: lock into vault with public key only, read back with passphrase', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'envlock-vault-'));
  const v = await V.openVault(root, V.newVaultId());
  const blob = await V.vaultPut(v, 'api/.env', SAMPLE, C.publicKeys(keyring));
  assert.ok(blob.startsWith(v.dir));
  const raw = fs.readFileSync(blob, 'utf8');
  assert.ok(!raw.includes('sk-live-123') && !raw.includes('.env'), 'neither secret nor file name visible');
  assert.ok(/^[0-9a-f]{64}\.envsafe$/.test(path.basename(blob)), 'blob name does not reveal the file (hash + fixed extension)');
  assert.ok(!fs.readFileSync(path.join(v.dir, 'vault.json'), 'utf8').includes('.env'));
  const env = await V.vaultRead(v, blob, await C.openKeyring(keyring, PASS));
  assert.strictEqual(env.path, 'api/.env');
  assert.ok(env.data.equals(SAMPLE));
});

test('vault: re-locking the same file replaces its blob; reopening keeps the salt', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'envlock-vault-'));
  const id = V.newVaultId();
  const v = await V.openVault(root, id);
  const pub = C.publicKeys(keyring);
  await V.vaultPut(v, '.env', SAMPLE, pub);
  await V.vaultPut(v, '.env', Buffer.from('A=2\n'), pub);
  await V.vaultPut(v, '.env.local', SAMPLE, pub);
  assert.strictEqual((await V.vaultList(v)).length, 2);
  const again = await V.openVault(root, id);
  assert.ok(again.salt.equals(v.salt));
  assert.strictEqual(V.blobName(v.salt, '.ENV', 'win32'), V.blobName(v.salt, '.env', 'win32'), 'case-insensitive on Windows');
  assert.notStrictEqual(V.blobName(v.salt, '.ENV', 'linux'), V.blobName(v.salt, '.env', 'linux'));
  assert.deepStrictEqual(await V.vaultList(await V.openVault(root, V.newVaultId())), []);
});

test('vault: planted entries cannot escape the project', () => {
  const proj = path.resolve('/proj');
  assert.strictEqual(V.restoreTarget(proj, '.env'), path.join(proj, '.env'));
  assert.strictEqual(V.restoreTarget(proj, 'api/.env.local'), path.join(proj, 'api', '.env.local'));
  for (const bad of ['', '../.bashrc', 'a/../../x', '/etc/passwd', 'C:/Windows/x', 'C:\\x', '..', '.']) {
    assert.strictEqual(V.restoreTarget(proj, bad), undefined, `should refuse ${JSON.stringify(bad)}`);
  }
  for (const bad of ['../x', 'a/b', '', 'x'.repeat(65)]) assert.ok(!V.isValidVaultId(bad));
});

// ------------------------------------------------------------ signing (authenticity)

test('signed locked files verify, still decrypt, and detect forgery', async () => {
  const macKey = C.newMacKey();
  const pub = C.publicKeys(keyring);
  const B = 'file:.env';
  const st = (text, key = macKey, bind = B) => C.verifyLocked(text, key, bind).state;
  const signed = C.signLocked(C.encryptFile(SAMPLE, pub), macKey, B, 1000);
  assert.deepStrictEqual(C.verifyLocked(signed, macKey, B), { state: 'valid', signedAt: 1000 });
  assert.ok(C.isLockedFile(signed));
  assert.ok(C.decryptFile(signed, await C.openKeyring(keyring, PASS)).equals(SAMPLE), 'mac field does not break decryption');

  // Attacker knows the public key but not the signing key: a planted file is unsigned or invalid.
  const planted = C.encryptFile(Buffer.from('API_URL=https://attacker.example\n'), pub);
  assert.strictEqual(st(planted), 'unsigned');
  assert.strictEqual(st(C.signLocked(planted, C.newMacKey(), B)), 'invalid');

  // Copying a valid signature onto other ciphertext fails.
  const j = JSON.parse(planted);
  Object.assign(j, { mac: JSON.parse(signed).mac, macv: 2, signedAt: 1000 });
  assert.strictEqual(st(JSON.stringify(j)), 'invalid');
  // Any change to a signed file fails, including its timestamp (no faking "newest").
  const t = JSON.parse(signed);
  t.iv = JSON.parse(planted).iv;
  assert.strictEqual(st(JSON.stringify(t)), 'invalid');
  const later = JSON.parse(signed);
  later.signedAt = 9e15;
  assert.strictEqual(st(JSON.stringify(later)), 'invalid');
  // Re-signing replaces the old mac; no signing key = cannot be valid.
  assert.strictEqual(st(C.signLocked(signed, macKey, B)), 'valid');
  assert.strictEqual(C.verifyLocked(signed, undefined, B).state, 'invalid');
  assert.strictEqual(st('not json'), 'invalid');
  // Signatures from Env Safety 0.3.0 (no binding) count as unsigned: they need consent once.
  const old = JSON.parse(signed);
  delete old.macv;
  assert.strictEqual(st(JSON.stringify(old)), 'unsigned');
});

test('a signature is bound to its file: renamed or moved files do not verify', () => {
  const macKey = C.newMacKey();
  const prod = C.signLocked(C.encryptFile(Buffer.from('KEY=prod\n'), C.publicKeys(keyring)), macKey, 'file:.env.production');
  assert.strictEqual(C.verifyLocked(prod, macKey, 'file:.env.production').state, 'valid');
  assert.strictEqual(C.verifyLocked(prod, macKey, 'file:.env').state, 'invalid', 'production keys renamed onto .env');
  assert.strictEqual(C.verifyLocked(prod, macKey, 'file:other/.env.production').state, 'invalid');
  assert.strictEqual(V.fileBinding('A' + String.fromCharCode(92) + '.env'), process.platform === 'win32' ? 'file:a/.env' : 'file:A/.env');
});

test('vault blobs are signed, bound to their vault, path and blob name', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'envlock-vault-'));
  const v = await V.openVault(root, V.newVaultId());
  const macKey = C.newMacKey();
  const pub = C.publicKeys(keyring);
  const priv = await C.openKeyring(keyring, PASS);
  const mine = await V.vaultPut(v, '.env', SAMPLE, pub, macKey);
  const local = await V.vaultPut(v, '.env.local', Buffer.from('X=1\n'), pub, macKey);
  const planted = await V.vaultPut(v, '.env.test', Buffer.from('X=evil\n'), pub); // no signing key
  assert.strictEqual((await V.vaultRead(v, mine, priv, macKey)).sign.state, 'valid');
  assert.strictEqual((await V.vaultRead(v, planted, priv, macKey)).sign.state, 'unsigned');
  assert.strictEqual((await V.vaultRead(v, mine, priv, C.newMacKey())).sign.state, 'invalid');

  // Copy the valid .env.local blob over the .env blob: content says .env.local, name says .env.
  fs.copyFileSync(local, mine);
  assert.strictEqual((await V.vaultRead(v, mine, priv, macKey)).sign.state, 'invalid');

  // The same blob in ANOTHER project's vault does not verify (vault id is bound).
  const other = await V.openVault(root, V.newVaultId());
  const otherBlob = V.expectedBlob(other, '.env.local');
  fs.copyFileSync(local, otherBlob);
  assert.notStrictEqual((await V.vaultRead(other, otherBlob, priv, macKey)).sign.state, 'valid');

  // Re-locking keeps the previous version as .prev (recoverable after a bad overwrite or deletion).
  await V.vaultPut(v, '.env.local', Buffer.from('X=2\n'), pub, macKey);
  assert.ok(fs.existsSync(local + '.prev'));
  assert.strictEqual((await V.vaultList(v)).filter((b) => b.endsWith('.prev')).length, 0, '.prev is not listed as a locked file');
});

test('vault blobs are .envsafe (not the ransomware-like .locked); .locked blobs of 0.8.0 still read, then replaced', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'envlock-vault-'));
  const v = await V.openVault(root, V.newVaultId());
  const macKey = C.newMacKey();
  const pub = C.publicKeys(keyring);
  const priv = await C.openKeyring(keyring, PASS);
  const blob = await V.vaultPut(v, '.env', SAMPLE, pub, macKey);
  assert.ok(blob.endsWith('.envsafe') && !blob.endsWith('.locked'));

  // A vault written by 0.8.0: the same blob under its old name.
  const legacy = path.join(v.dir, V.legacyBlobName(v.salt, '.env'));
  assert.ok(legacy.endsWith('.locked'));
  fs.renameSync(blob, legacy);
  assert.deepStrictEqual(await V.vaultList(v), [legacy], 'legacy blob is listed');
  const env = await V.vaultRead(v, legacy, priv, macKey);
  assert.ok(env.data.equals(SAMPLE));
  assert.strictEqual(env.sign.state, 'valid', 'legacy name still verifies');

  // A blob copied under another file's legacy name does not verify.
  const other = path.join(v.dir, V.legacyBlobName(v.salt, '.env.production'));
  fs.copyFileSync(legacy, other);
  assert.strictEqual((await V.vaultRead(v, other, priv, macKey)).sign.state, 'invalid');
  fs.unlinkSync(other);

  // Locking again writes .envsafe, keeps the old blob as .prev and removes the .locked one.
  const again = await V.vaultPut(v, '.env', Buffer.from('A=2\n'), pub, macKey);
  assert.deepStrictEqual(await V.vaultList(v), [again]);
  assert.ok(!fs.existsSync(legacy) && fs.existsSync(again + '.prev'));
});

// ------------------------------------------------------------ policy

const Pol = require('../out/policy');

test('policy: a project can never weaken security settings', () => {
  const i = { defaultValue: 5, globalValue: undefined, workspaceValue: 0, workspaceFolderValue: 0 };
  assert.strictEqual(Pol.secureValue(i, 99), 5, 'project value ignored, default used');
  assert.strictEqual(Pol.secureValue({ ...i, globalValue: 10 }, 99), 10, 'user value used');
  assert.deepStrictEqual(Pol.ignoredOverrides({ autoLockMinutes: i, lockOnClose: { defaultValue: true } }), ['autoLockMinutes']);
  assert.deepStrictEqual(Pol.ignoredOverrides({ x: { defaultValue: true, workspaceValue: true } }), [], 'same value is not reported');
  for (const k of ['allowList', 'lockOnClose', 'confirmUnlockToDisk', 'agentExtensions', 'storage', 'exclude', 'keyringPath']) {
    assert.ok(Pol.SECURE_KEYS.includes(k), `${k} must be user-only`);
  }
  // Additive settings: a project can add, not remove.
  const presets = { defaultValue: ['auto'], workspaceValue: ['node'] };
  assert.deepStrictEqual(Pol.additiveValue(presets, []), ['auto', 'node']);
  assert.deepStrictEqual(Pol.additiveValue({ defaultValue: ['auto'], workspaceValue: [] }, []), ['auto']);
  assert.deepStrictEqual(Pol.additiveValue({ globalValue: ['a'] }, [], [['b'], ['a']]), ['a', 'b']);
});

test('policy: weak new passphrases are rejected', () => {
  for (const weak of ['short', 'password1234', 'aaaaaaaaaaaaaaaa', 'abcdefghijkl', 'mysecret12345']) {
    assert.ok(Pol.passphraseProblem(weak), `should reject ${weak}`);
  }
  for (const ok of ['correct horse battery staple', 'Tr0ub4dor&3xyz', 'blue-teapot-42-river']) {
    assert.strictEqual(Pol.passphraseProblem(ok), undefined, `should accept ${ok}`);
  }
});

test('a swapped keyring has a different id (what the pinned trust compares)', async () => {
  const attacker = await C.createKeyring({ passphrase: 'attacker passphrase' });
  assert.notStrictEqual(attacker.keyId, keyring.keyId);
  // Forging the id to match ours is caught when the keyring is parsed.
  const forged = { ...attacker, keyId: keyring.keyId };
  assert.throws(() => C.parseKeyring(JSON.stringify(forged)), /does not match its id/);
  // And our passphrase cannot open the attacker's keyring.
  await assert.rejects(C.openKeyring(attacker, PASS), C.WrongPassphraseError);
});

test('bundle builds and loads ML-KEM in CommonJS (as VS Code will)', () => {
  const bundle = fs.readFileSync(path.join(__dirname, '..', 'dist', 'extension.js'), 'utf8');
  assert.ok(bundle.includes('ml_kem768') || bundle.includes('ML-KEM'), 'noble ml-kem bundled');
  assert.ok(!/require\(["']@noble/.test(bundle), 'no runtime require of ESM-only package');
});

// ------------------------------------------------------------ red-team fixes (docs/redteam-report.md)

test('F5 ReDoS: repeated globstars are collapsed, too-complex patterns refused, built-ins all safe', () => {
  const deep = Array(30).fill('a').join('/') + '/y';
  const t = Date.now();
  const re = P.globToRegExp(Array(20).fill('**').join('/') + '/x'); // took > 120 s before the fix
  assert.ok(!re.test(deep));
  assert.ok(re.test('a/b/x'));
  assert.ok(Date.now() - t < 500, 'matched in linear time');
  for (const bad of ['*a*a*a*a*b', '**/a/**/b/**/c/**/d/**/e/**/f', 'x'.repeat(301), '{a,b}{a,b}{a,b}{a,b}{a,b}']) {
    assert.strictEqual(P.isSafePattern(bad), false, `should refuse ${bad.slice(0, 40)}`);
  }
  assert.ok(!P.resolvePatterns(['dotenv'], new Set(), ['*a*a*a*a*b', 'config/secrets.yml']).includes('*a*a*a*a*b'));
  assert.ok(P.resolvePatterns(['dotenv'], new Set(), ['config/secrets.yml']).includes('config/secrets.yml'));
  assert.strictEqual(P.matchesAny('aaaaaaaaaaaaaaaaaaaaaaaaaaaaac', ['*a*a*a*a*b']), false, 'unsafe pattern never matches, never hangs');
  for (const p of P.ALL_PRESET_PATTERNS) assert.ok(P.isSafePattern(p), `built-in ${p} must stay safe`);
});

test('F5b ReDoS across segments: "*a*a*/*a*a*/…" stays linear (0.7.0 took 5 s at 4 segments)', () => {
  for (const n of [4, 8, 16, 40]) {
    const glob = Array(n).fill('*a*a*').join('/') + '/b';
    if (!P.isSafePattern(glob)) continue; // too long: refused, also fine
    const t = Date.now();
    assert.ok(!P.globToRegExp(glob).test(Array(n).fill('a'.repeat(30)).join('/') + '/c'));
    assert.ok(!P.globToRegExp(glob).test(Array(n).fill('xbyb').join('/') + '/b'), 'a segment without two "a" fails');
    assert.ok(P.globToRegExp(glob).test(Array(n).fill('xaxax').join('/') + '/b'));
    assert.ok(Date.now() - t < 200, `${n} segments matched in ${Date.now() - t} ms`);
  }
  // Worst case allowed by the limits: 3 globstars + 3-wildcard segments against a deep path.
  const worst = '**/*a*a*/**/*a*a*/**/*a*a*/b';
  const t = Date.now();
  P.globToRegExp(worst).test(Array(60).fill('a'.repeat(20)).join('/') + '/c');
  assert.ok(Date.now() - t < 1000, `worst case took ${Date.now() - t} ms`);
  // Semantics kept: character classes never cross "/", "**" inside a segment is "*".
  assert.ok(P.matchesAny('a/b', ['a[!x]b']) === false);
  assert.ok(P.matchesAny('cfg/app.yml', ['**/app.[tx]ml']) === false && P.matchesAny('cfg/app.yml', ['**/app.[xy]ml']));
  assert.ok(P.matchesAny('x/foo.env', ['**/foo**.env']) && !P.matchesAny('foo/bar.env', ['foo**.env']));
  // "/" inside braces: expanded first, so it still works where patterns are used.
  assert.ok(P.isSafePattern('{config/a,c}/x.yml'));
  assert.ok(P.matchesAny('p/config/a/x.yml', ['{config/a,c}/x.yml']) && P.matchesAny('c/x.yml', ['{config/a,c}/x.yml']));
});

test('F6 policy: shrinking presets or custom patterns in user settings is a weakening', () => {
  assert.deepStrictEqual(Pol.weakenings({ presets: ['auto'] }, { presets: ['dotenv'] }), ['presets']);
  assert.deepStrictEqual(Pol.weakenings({ presets: ['auto'] }, { presets: ['auto', 'keys'] }), [], 'adding is stronger');
  assert.deepStrictEqual(Pol.weakenings({ customPatterns: ['a.yml'] }, { customPatterns: [] }), ['customPatterns']);
  assert.deepStrictEqual(Pol.weakenings({}, { presets: ['auto'] }), [], 'first sight (upgrade) is not a weakening');
  assert.ok(Pol.REVIEWED_KEYS.includes('presets') && Pol.REVIEWED_KEYS.includes('customPatterns'));
});

test('F7 local history never keeps copies of any built-in secret file type', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
  const ex = pkg.contributes.configurationDefaults['workbench.localHistory.exclude'];
  for (const p of [...P.ALL_PRESET_PATTERNS, '**/*.envsafe', '**/*.locked']) assert.strictEqual(ex[p], true, `local history must exclude ${p}`);
});

test('F8 unlock refuses targets that exist or lead outside the project through a link', async () => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'envlock-link-'));
  const proj = path.join(base, 'proj');
  const outside = path.join(base, 'outside');
  fs.mkdirSync(proj);
  fs.mkdirSync(outside);
  assert.strictEqual(await V.safeToWrite(proj, path.join(proj, '.env')), true);
  assert.strictEqual(await V.safeToWrite(proj, path.join(proj, 'new', 'dir', 'secrets.yml')), true, 'missing folders are fine');
  fs.writeFileSync(path.join(proj, '.env'), 'X=1');
  assert.strictEqual(await V.safeToWrite(proj, path.join(proj, '.env')), false, 'never overwrite');
  // Directory junction: no admin rights needed on Windows.
  fs.symlinkSync(outside, path.join(proj, 'config'), 'junction');
  assert.strictEqual(await V.safeToWrite(proj, path.join(proj, 'config', 'secrets.yml')), false, 'junction to outside');
  assert.strictEqual(await V.safeToWrite(proj, path.join(proj, 'config', 'deeper', 'x.yml')), false);
  // Dangling file symlink (needs Developer Mode / admin on Windows: skipped if not allowed).
  try {
    fs.symlinkSync(path.join(outside, 'nothing-yet'), path.join(proj, '.env.local'), 'file');
    assert.strictEqual(await V.safeToWrite(proj, path.join(proj, '.env.local')), false, 'dangling symlink');
  } catch (e) {
    if (e.code !== 'EPERM') throw e;
  }
});

test('F9 vault salt fingerprint changes when vault.json is rewritten', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'envlock-vault-'));
  const id = V.newVaultId();
  const v = await V.openVault(root, id);
  assert.strictEqual(V.saltFingerprint(await V.openVault(root, id)), V.saltFingerprint(v));
  const meta = path.join(v.dir, 'vault.json');
  const j = JSON.parse(fs.readFileSync(meta, 'utf8'));
  j.salt = Buffer.alloc(32, 1).toString('base64');
  fs.writeFileSync(meta, JSON.stringify(j));
  assert.notStrictEqual(V.saltFingerprint(await V.openVault(root, id)), V.saltFingerprint(v));
});

test('F10/F11 crypto: truncated GCM tags and extreme KDF parameters are refused', async () => {
  const priv = await C.openKeyring(keyring, PASS);
  const j = JSON.parse(C.encryptFile(SAMPLE, C.publicKeys(keyring)));
  j.tag = Buffer.from(j.tag, 'base64').subarray(0, 4).toString('base64');
  assert.throws(() => C.decryptFile(JSON.stringify(j), priv), /corrupted|modified/);
  const shortTag = structuredClone(keyring);
  shortTag.private.tag = Buffer.from(shortTag.private.tag, 'base64').subarray(0, 8).toString('base64');
  await assert.rejects(C.openKeyring(shortTag, PASS), C.WrongPassphraseError);
  const heavy = structuredClone(keyring);
  Object.assign(heavy.private.kdf, { N: 2 ** 20, r: 32, p: 16 });
  await assert.rejects(C.openKeyring(heavy, PASS), /unsafe KDF/);
});

test('R2 planted locked file with array-like fields fails fast (was ~9 s and 200 MB per field)', async () => {
  const priv = await C.openKeyring(keyring, PASS);
  for (const field of ['iv', 'tag', 'data']) {
    const j = JSON.parse(C.encryptFile(SAMPLE, C.publicKeys(keyring)));
    j[field] = { length: 2e8 };
    const t = Date.now();
    assert.throws(() => C.decryptFile(JSON.stringify(j), priv));
    assert.ok(Date.now() - t < 200, `${field}: ${Date.now() - t} ms`);
  }
  const k = structuredClone(keyring);
  k.public.mlkem = { length: 2e8 };
  const t = Date.now();
  assert.throws(() => C.parseKeyring(JSON.stringify(k)));
  assert.ok(Date.now() - t < 200);
});

test('F12 Claude hook fails closed: missing config still blocks .env; complex wildcards are blocked', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'envlock-'));
  await applyAgentRules(root, PATTERNS, P.DEFAULT_ALLOW);
  const hook = path.join(root, HOOK_REL_PATH);
  const run = (tool_name, tool_input) => spawnSync(process.execPath, [hook], { input: JSON.stringify({ tool_name, tool_input }) }).status;
  assert.strictEqual(run('Bash', { command: 'cat *.*.*.*e*n*v' }), 2, 'too complex to check: blocked');
  fs.unlinkSync(path.join(root, '.claude', 'hooks', 'env-guard.json'));
  assert.strictEqual(run('Read', { file_path: '/p/.env' }), 2, 'config deleted: built-in patterns still apply');
  assert.strictEqual(run('Read', { file_path: '/p/.env.example' }), 0);
  assert.strictEqual(run('Read', { file_path: '/p/src/index.ts' }), 0);
});

test('F2/F14 hardening stays in place: no cwd command lookup, no repo-configured git commands', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.ts'), 'utf8');
  const gitCalls = src.match(/execFile\(\s*'git',\s*\[[^\]]*/g) ?? [];
  assert.ok(gitCalls.length >= 2);
  for (const c of gitCalls) assert.ok(c.includes('...GIT_SAFE'), `git call without core.fsmonitor=false: ${c}`);
  assert.match(src, /GIT_SAFE = \['-c', 'core\.fsmonitor=false'\]/);
  assert.match(src, /\.\.\.pending, NoDefaultCurrentDirectoryInExePath: '1'/);
});

test('policy: settings changes that weaken protection are detected, others are not', () => {
  const base = {
    allowList: ['**/.env.example'],
    exclude: '**/node_modules/**',
    storage: 'vault',
    autoLockMinutes: 5,
    confirmUnlockToDisk: true,
    agentExtensions: ['github.copilot'],
    agentCommands: ['claude'],
    lockOnStartup: true,
    lockWhenAgentStarts: true,
    lockOnClose: true,
    keyringPath: '',
    vaultPath: '',
    keyFile: '',
  };
  const w = (change) => Pol.weakenings(base, { ...base, ...change });
  // weaker: needs confirmation
  assert.deepStrictEqual(w({ lockOnClose: false }), ['lockOnClose']);
  assert.deepStrictEqual(w({ autoLockMinutes: 0 }), ['autoLockMinutes']);
  assert.deepStrictEqual(w({ autoLockMinutes: 60 }), ['autoLockMinutes']);
  assert.deepStrictEqual(w({ allowList: ['**/.env.example', '**/.env'] }), ['allowList']);
  assert.deepStrictEqual(w({ agentCommands: [] }), ['agentCommands']);
  assert.deepStrictEqual(w({ storage: 'inPlace' }), ['storage']);
  assert.deepStrictEqual(w({ keyringPath: 'C:/evil/keyring.json' }), ['keyringPath']);
  assert.deepStrictEqual(w({ exclude: '**/*' }), ['exclude']);
  // stronger or neutral: accepted silently
  assert.deepStrictEqual(w({ autoLockMinutes: 2 }), []);
  assert.deepStrictEqual(w({ allowList: [] }), []);
  assert.deepStrictEqual(w({ agentCommands: ['claude', 'codex'] }), []);
  assert.deepStrictEqual(w({}), []);
  // several at once
  assert.deepStrictEqual(w({ lockOnClose: false, confirmUnlockToDisk: false }).sort(), ['confirmUnlockToDisk', 'lockOnClose']);
});

// ------------------------------------------------------------ copies of secrets (red-team X2, X5, X7, X8)

const K = require('../out/copies');
const { scanFiles } = require('../out/scan');

test('copies: secret-shaped values only; URLs without credentials and plain words are ignored', () => {
  assert.ok(K.looksSecret('sk-LIVE-8f3a9c2e71b4'));
  assert.ok(K.looksSecret('postgres://app:Hunter2pw@db:5432/app'));
  assert.ok(!K.looksSecret('https://api.example.com/v1'));
  assert.ok(!K.looksSecret('my-app-production'));
  assert.ok(!K.looksSecret('short1'));
  assert.ok(!K.looksSecret('has a space 123456'));
});

test('copies: finds a copied value, a renamed whole file, and nothing in unrelated text', () => {
  const key = Buffer.alloc(32, 7);
  const env = 'API_KEY=sk-LIVE-8f3a9c2e71b4\nAPI_URL=https://api.example.com\nDB="postgres://app:Hunter2pw@db/app"\n';
  const prints = K.printsOf(key, env);
  assert.ok(!JSON.stringify(prints).includes('8f3a9c'), 'no plaintext in the fingerprints');
  assert.ok(K.containsSecret(key, 'const k = "sk-LIVE-8f3a9c2e71b4";', prints));
  assert.ok(K.containsSecret(key, 'KEY=sk-LIVE-8f3a9c2e71b4', prints), 'KEY=value glued together');
  assert.ok(K.containsSecret(key, "url: 'postgres://app:Hunter2pw@db/app'", prints));
  assert.ok(K.containsSecret(key, env, prints), 'the whole file, renamed');
  assert.ok(!K.containsSecret(key, 'See https://api.example.com for the API docs.', prints), 'no false alarm on a plain URL');
  assert.ok(!K.containsSecret(Buffer.alloc(32, 8), 'sk-LIVE-8f3a9c2e71b4', prints), 'another key never matches');
  const merged = K.mergePrints(prints, K.printsOf(key, 'TOKEN=ghp_A1b2C3d4E5f6G7h8\n'));
  assert.ok(K.containsSecret(key, 'ghp_A1b2C3d4E5f6G7h8', merged) && K.containsSecret(key, 'sk-LIVE-8f3a9c2e71b4', merged));
});

test('scan: build output folders are scanned last, with their own budget', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'envlock-scan-'));
  fs.mkdirSync(path.join(root, 'dist'));
  for (let i = 0; i < 30; i++) fs.writeFileSync(path.join(root, 'dist', `junk${i}.js`), '');
  fs.writeFileSync(path.join(root, 'dist', '.env'), 'X=1');
  fs.mkdirSync(path.join(root, 'src'));
  fs.writeFileSync(path.join(root, 'src', '.env'), 'X=1');
  fs.mkdirSync(path.join(root, 'node_modules'));
  fs.writeFileSync(path.join(root, 'node_modules', '.env'), 'X=1');
  const r = await scanFiles(root, ['**/node_modules/**'], { maxEntries: 10, laterEntries: 100 });
  assert.ok(r.files.includes('src/.env'), 'a flooded dist/ cannot hide src/.env');
  assert.ok(r.files.includes('dist/.env'), 'dist/.env is found');
  assert.ok(!r.files.includes('node_modules/.env'), 'excluded folders stay skipped');
  const tight = await scanFiles(root, ['**/node_modules/**'], { maxEntries: 10, laterEntries: 5 });
  assert.ok(tight.files.includes('src/.env') && tight.truncated, 'a huge build folder truncates only its own pass');
});

// ------------------------------------------------------------ rename: Env Lock -> Env Safety (0.8.0)

const M = require('../out/migrate');

test('migrate: ~/.env-lock is copied once to ~/.env-safety and kept as a backup', async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'envsafety-home-'));
  assert.strictEqual(await M.migrateHome(home), 'none', 'nothing to move');
  fs.mkdirSync(path.join(home, '.env-lock', 'vault', 'abc'), { recursive: true });
  fs.writeFileSync(path.join(home, '.env-lock', 'keyring.json'), '{"k":1}');
  fs.writeFileSync(path.join(home, '.env-lock', 'vault', 'abc', 'x.locked'), 'blob');
  assert.strictEqual(await M.migrateHome(home), 'migrated');
  assert.strictEqual(fs.readFileSync(path.join(home, '.env-safety', 'keyring.json'), 'utf8'), '{"k":1}');
  assert.strictEqual(fs.readFileSync(path.join(home, '.env-safety', 'vault', 'abc', 'x.locked'), 'utf8'), 'blob');
  assert.ok(fs.existsSync(path.join(home, '.env-lock', 'keyring.json')), 'old folder kept');
  fs.writeFileSync(path.join(home, '.env-lock', 'keyring.json'), '{"k":"planted"}');
  assert.strictEqual(await M.migrateHome(home), 'exists', 'never runs again');
  assert.strictEqual(fs.readFileSync(path.join(home, '.env-safety', 'keyring.json'), 'utf8'), '{"k":1}', 'existing keyring untouched');
});

test('migrate: a ~/.env-lock that is a link is not followed', async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'envsafety-home-'));
  const elsewhere = fs.mkdtempSync(path.join(os.tmpdir(), 'envsafety-planted-'));
  fs.writeFileSync(path.join(elsewhere, 'keyring.json'), '{"k":"attacker"}');
  fs.symlinkSync(elsewhere, path.join(home, '.env-lock'), 'junction');
  assert.strictEqual(await M.migrateHome(home), 'none');
  assert.ok(!fs.existsSync(path.join(home, '.env-safety')));
});

test('agent rules: a block written by Env Lock is replaced, not duplicated', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'envsafety-rules-'));
  fs.writeFileSync(path.join(root, '.cursorignore'), 'mine\n# >>> env-lock (managed, do not edit) >>>\nold\n# <<< env-lock <<<\n');
  await applyAgentRules(root, ['**/.env'], []);
  const t = fs.readFileSync(path.join(root, '.cursorignore'), 'utf8');
  assert.ok(t.startsWith('mine\n'), 'user lines kept');
  assert.ok(!t.includes('env-lock') && !t.includes('\nold\n'), 'legacy block gone');
  assert.strictEqual(t.split('>>> env-safety').length, 2, 'exactly one Env Safety block');
});
