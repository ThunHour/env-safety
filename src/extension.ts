import * as vscode from 'vscode';
import * as fs from 'fs/promises';
import * as path from 'path';
import { ChildProcess, execFile, spawn } from 'child_process';
import { createHash, createHmac } from 'crypto';
import {
  createKeyring,
  decryptFile,
  encryptFile,
  generateKeyFile,
  isLockedFile,
  KeyringFile,
  keyringNeedsKeyFile,
  macKeyFromPrivate,
  newMacKey,
  openKeyring,
  PrivateKeys,
  PublicKeys,
  publicKeys,
  resealKeyring,
  Secret,
  SignCheck,
  signLocked,
  verifyLocked,
  wipePrivate,
  WrongKeyError,
  WrongPassphraseError,
} from './crypto';
import { defaultKeyringPath, expandHome, readKeyring, writeKeyring } from './keyring';
import { DEFAULT_ALLOW, DOTENV_PATTERNS, expandBraces, isSafePattern, matchesAny, PRESETS, resolvePatterns } from './patterns';
import { dotenvModes, dotenvPlan, parseDotenv } from './dotenv';
import { scanFiles } from './scan';
import { containsSecret, mergePrints, printsOf, SecretPrints } from './copies';
import { applyAgentRules } from './agentRules';
import {
  ADDITIVE_KEYS,
  additiveValue,
  ignoredOverrides,
  parseJsonc,
  passphraseProblem,
  REVIEWED_KEYS,
  SECURE_KEYS,
  secureValue,
  weakenings,
} from './policy';
import {
  defaultVaultRoot,
  fileBinding,
  isValidVaultId,
  newVaultId,
  openVault,
  restoreTarget,
  safeToWrite,
  saltFingerprint,
  Vault,
  vaultBinding,
  vaultList,
  vaultPut,
  vaultRead,
} from './vault';

const LOCKED = '.locked';
const TMP = '.envlock-tmp';
const MIN_PASS = 10;

let statusItem: vscode.StatusBarItem;
let knownPlain: string[] = [];
let cachedPub: PublicKeys | undefined; // public key only: enough to lock, useless to unlock
let lockOnClose = true;
let autoLockTimer: NodeJS.Timeout | undefined;
let busy = false;
let detected = new Set<string>();
let watcher: vscode.FileSystemWatcher | undefined;
let refreshTimer: NodeJS.Timeout | undefined;
let secrets: vscode.SecretStorage;
const secretTerminals = new Set<vscode.Terminal>();

/** Closes every terminal holding decrypted secrets in its environment. */
function closeSecretTerminals(why: string) {
  if (!secretTerminals.size) return;
  for (const t of secretTerminals) t.dispose();
  secretTerminals.clear();
  log.info(`Closed secrets terminal(s): ${why}`);
}
let state: vscode.Memento; // only used to migrate records from Env Lock 0.4.0
let log: vscode.LogOutputChannel;

// ================================================================= protected records
//
// Env Lock's own records (vault pins, newest versions, your "stop protecting" exceptions, and the
// security settings you approved) must not live in plain files: settings.json and VS Code's
// state.vscdb are ordinary files an agent can edit. They are kept in SecretStorage, which VS Code
// encrypts with the OS credential store (DPAPI on Windows).

interface Records {
  pins: Record<string, string>; // workspace folder -> vault id
  latest: Record<string, Latest>; // signature binding -> newest version you locked
  allow: Record<string, string[]>; // workspace folder -> files you stopped protecting
  settings?: Record<string, unknown>; // security settings you approved
  lastCommand?: string; // last "Run a command with secrets" command (pre-filled, so it must be tamper-proof)
  vaultSalts?: Record<string, string>; // vault id -> fingerprint of its salt (a rewritten vault.json is noticed)
  envSeen?: Record<string, Record<string, string>>; // dotenv file -> key -> keyed hash of the value you approved
  runFiles?: Record<string, Record<string, string>>; // run folder -> file deciding what runs -> hash
  copyPrints?: SecretPrints; // keyed hashes of locked secret values, to find copies left elsewhere (see copies.ts)
}
const RECORDS_SECRET = 'envLock.records.v1';
let records: Records = { pins: {}, latest: {}, allow: {} };
/** Env Lock's records were wiped (reinstalled): signatures by a lost random key can only be confirmed by you. */
let recordsReset = false;
let recordsWrite: Promise<void> = Promise.resolve();

async function loadRecords() {
  const raw = await secrets.get(RECORDS_SECRET);
  let tampered = false;
  if (raw) {
    try {
      records = { pins: {}, latest: {}, allow: {}, ...JSON.parse(raw) };
      return;
    } catch {
      tampered = true;
    }
  } else if ((await readTrust())?.hasRecords) {
    tampered = true; // trust says records existed: someone deleted them (e.g. to reset rollback protection)
  } else if (!(await readTrust()) && (await fs.access(keyringPath()).then(() => true, () => false))) {
    // No records and no trust, but a keyring: Env Lock has been used here before and its whole
    // credential store is gone. VS Code wipes it when an extension is uninstalled, so an agent can
    // reset Env Lock with `code --uninstall-extension` + `--install-extension` (red-team test T30).
    recordsReset = true;
    log.error('Env Lock records and trust are missing although a keyring exists: Env Lock was reinstalled, or its store was wiped.');
    void vscode.window.showErrorMessage(
      'Env Lock: its protected records are gone although you have keys: Env Lock was uninstalled and reinstalled ' +
        '(by you, or by something running as you), or its credential store was wiped. Rollback protection, vault pins, ' +
        'approved settings and your anti-phishing phrase start over: set the phrase again before typing your passphrase. ' +
        'Your files still unlock with your passphrase. If you did not reinstall Env Lock, check your extensions.',
      { modal: true }
    );
  }
  if (tampered) {
    log.error('Env Lock records were deleted or damaged in the credential store.');
    void vscode.window.showErrorMessage(
      'Env Lock: its protected records (vault pins, version history, approved settings) were deleted or damaged. ' +
        'If you did not reset VS Code, something tampered with them. Locked files stay encrypted; ' +
        'settings now start from the secure defaults. Check the security log.'
    );
  }
  // Migrate from 0.4.0 (VS Code state, a plain file).
  records = {
    pins: state.get(VAULT_PINS, {}),
    latest: state.get(LATEST, {}),
    allow: state.get(ALLOW_STATE, {}),
  };
  await saveRecords();
  for (const k of [VAULT_PINS, LATEST, ALLOW_STATE]) await state.update(k, undefined);
}

/** Writes are queued so concurrent updates never overwrite each other. */
function saveRecords(): Promise<void> {
  const snapshot = JSON.stringify(records);
  // .catch first: one failed write must not make every later write fail.
  recordsWrite = recordsWrite.catch(() => undefined).then(async () => {
    await secrets.store(RECORDS_SECRET, snapshot);
    const t = await readTrust();
    if (t && !t.hasRecords) await writeTrust(t.keyId, true);
  });
  return recordsWrite;
}

// ================================================================= security settings
//
// Read from the settings you APPROVED (kept in the protected records), not from settings.json
// directly. A change that weakens protection only takes effect after you confirm it, so an agent
// editing %APPDATA%/Code/User/settings.json cannot switch Env Lock off.

const liveSecure = () => Object.fromEntries(REVIEWED_KEYS.map((k) => [k, secureValue(cfg().inspect(k), undefined)]));
let selfUpdate = 0; // our own settings writes (e.g. choosing a key file) are approved already

/** A setting that could weaken protection: the approved user value; a project's value is ignored. */
function secure<T>(key: (typeof SECURE_KEYS)[number], fallback: T): T {
  const approved = records.settings;
  if (approved && key in approved) return (approved[key] ?? fallback) as T;
  return secureValue<T>(cfg().inspect<T>(key), fallback);
}

async function updateOwnSetting(key: string, value: unknown) {
  selfUpdate++;
  try {
    await cfg().update(key, value, vscode.ConfigurationTarget.Global);
    records.settings = { ...records.settings, [key]: value };
    await saveRecords();
  } finally {
    selfUpdate--;
  }
}

let reviewingSettings = false;
/** Compares settings.json with what you approved; asks about anything that weakens protection. */
async function reviewSettings(reason: string) {
  if (selfUpdate || reviewingSettings) return;
  reviewingSettings = true;
  try {
    const live = liveSecure();
    if (!records.settings) {
      // First run, or the records were deleted: start from the SECURE DEFAULTS, not from whatever
      // settings.json says now, so a weakened settings file is never adopted silently.
      records.settings = Object.fromEntries(REVIEWED_KEYS.map((k) => [k, cfg().inspect(k)?.defaultValue]));
    }
    const weak = weakenings(records.settings, live);
    const accepted = { ...live };
    if (weak.length) {
      const list = weak.map((k) => `envLock.${k}: ${JSON.stringify(records.settings![k])} → ${JSON.stringify(live[k])}`).join('\n');
      log.warn(`Settings weakened (${reason}):\n${list}`);
      const keep = await vscode.window.showWarningMessage(
        `Env Lock: these settings were changed to make protection WEAKER:\n\n${list}\n\n` +
          'Your user settings file can be edited by AI agents too. Did you make this change yourself?',
        { modal: true },
        'Yes, I changed them'
      );
      if (keep) {
        log.info('Weakened settings approved by you');
      } else {
        for (const k of weak) accepted[k] = records.settings[k];
        selfUpdate++;
        try {
          for (const k of weak) await cfg().update(k, records.settings[k], vscode.ConfigurationTarget.Global);
        } finally {
          selfUpdate--;
        }
        log.info(`Reverted: ${weak.join(', ')}`);
      }
    }
    records.settings = accepted;
    await saveRecords();
  } finally {
    reviewingSettings = false;
  }
}

/** A setting a project may extend but never shrink. */
function additive(key: (typeof ADDITIVE_KEYS)[number], fallback: string[]): string[] {
  const folderValues = (vscode.workspace.workspaceFolders ?? []).map((f) => cfg(f.uri).inspect<string[]>(key)?.workspaceFolderValue ?? []);
  return additiveValue(cfg().inspect<string[]>(key), fallback, folderValues);
}

const autoLockMinutes = () => secure<number>('autoLockMinutes', 5);

// Files you chose to stop protecting, per project. Kept in VS Code's user storage, not in the
// project, so an agent cannot "unprotect" files by editing .vscode/settings.json.
const ALLOW_STATE = 'envLock.projectAllow';
const projectAllow = () => records.allow;
async function setProjectAllow(folder: vscode.WorkspaceFolder, list: string[]) {
  records.allow = { ...records.allow, [folder.uri.fsPath]: list };
  await saveRecords();
}

let warnedOverrides = '';
/** Tells the user (once per change) which project settings were ignored because they would weaken protection. */
async function auditProjectSettings() {
  const inspects: Record<string, any> = {};
  for (const k of SECURE_KEYS) inspects[k] = cfg().inspect(k);
  for (const f of vscode.workspace.workspaceFolders ?? []) {
    // VS Code drops user-only (application / machine scoped) values from a project's settings before
    // inspect() sees them, so read the file itself to be able to tell you (red-team test T07).
    const file = f.uri.scheme === 'file' ? await fs.readFile(path.join(f.uri.fsPath, '.vscode', 'settings.json'), 'utf8').catch(() => '') : '';
    const fromFile = (file && parseJsonc(file)) || {};
    for (const k of SECURE_KEYS) {
      const v = cfg(f.uri).inspect(k)?.workspaceFolderValue ?? fromFile[`envLock.${k}`];
      if (v !== undefined) inspects[`${k} (${f.name})`] = { ...cfg().inspect(k), workspaceFolderValue: v, workspaceValue: undefined };
    }
  }
  const ignored = ignoredOverrides(inspects);
  const sig = ignored.join(',');
  if (!ignored.length || sig === warnedOverrides) return;
  warnedOverrides = sig;
  log.warn(`Ignored project settings that would weaken protection: ${ignored.join(', ')}`);
  void vscode.window.showWarningMessage(
    `Env Lock: ignored settings in this project's .vscode/settings.json: ${ignored.map((k) => 'envLock.' + k).join(', ')}. ` +
      'A project (and any AI agent working in it) cannot weaken Env Lock. Set them in your User settings if you really want them.'
  );
}

const cfg = (scope?: vscode.Uri) => vscode.workspace.getConfiguration('envLock', scope);
const exclude = () => secure<string>('exclude', '**/{node_modules,.git}/**');
const rel = (u: vscode.Uri) => vscode.workspace.asRelativePath(u, false).replace(/\\/g, '/');

// ================================================================= patterns

function activePatterns(): string[] {
  const custom = additive('customPatterns', []).filter((c) => typeof c === 'string');
  warnUnsafePatterns(custom.filter((c) => c.trim() && !isSafePattern(c.trim())));
  return resolvePatterns(additive('presets', ['auto']), detected, custom);
}

let warnedUnsafe = '';
/** Patterns too complex to match safely (they could freeze VS Code) are skipped: say so once. */
function warnUnsafePatterns(bad: string[]) {
  const sig = bad.join('\n');
  if (!bad.length || sig === warnedUnsafe) return;
  warnedUnsafe = sig;
  log.warn(`Ignored envLock.customPatterns that are too complex to match safely: ${bad.join(', ')}`);
  void vscode.window.showWarningMessage(
    `Env Lock: ignored envLock.customPatterns too complex to match safely (they could freeze VS Code): ${bad.join(', ')}. ` +
      'If a project added them and you did not, something may be trying to stop Env Lock.'
  );
}

function allowList(): string[] {
  return [...secure<string[]>('allowList', DEFAULT_ALLOW), ...Object.values(projectAllow()).flat()];
}

async function detectPresets() {
  // Own walk, not findFiles: a .ignore file must not be able to hide "*.csproj" and so switch the
  // .NET secret files off (see workspaceFiles).
  const files = (await workspaceFiles()).map((f) => f.rel);
  const found = new Set<string>();
  for (const p of PRESETS) {
    if (p.detect && files.some((f) => matchesAny(f, p.detect!))) found.add(p.id);
  }
  detected = found;
}

const combinedGlob = (globs: string[]) => {
  const list = [...new Set(globs.flatMap(expandBraces))];
  return list.length === 1 ? list[0] : `{${list.join(',')}}`;
};

interface VaultItem {
  folder: vscode.WorkspaceFolder;
  vault: Vault;
  blob: string;
}

interface SecretFiles {
  plain: vscode.Uri[];
  locked: vscode.Uri[]; // encrypted in place: <file>.locked next to where the file was
  vault: VaultItem[]; // encrypted outside the project, in the vault
}

// ================================================================= vault

const storageMode = (_folder: vscode.WorkspaceFolder) => secure<string>('storage', 'vault');

function vaultRoot(): string {
  const p = secure<string>('vaultPath', '').trim();
  return p ? expandHome(p) : defaultVaultRoot();
}

/** The folder's vault. create=false never writes settings (safe during shutdown). */
async function folderVault(folder: vscode.WorkspaceFolder, create: boolean): Promise<Vault | undefined> {
  const c = cfg(folder.uri);
  let id = c.get<string>('vaultId', '').trim();
  if (id && !isValidVaultId(id)) throw new Error(`envLock.vaultId "${id}" is not valid.`);
  // vaultId lives in the project, where an agent can edit it (e.g. to point at another project's
  // vault, or a fresh one). The first id seen for this folder is pinned in the protected records.
  const pins = records.pins;
  const pinned = pins[folder.uri.fsPath];
  if (pinned && id !== pinned) {
    if (!vaultIdWarned.has(folder.uri.fsPath)) {
      vaultIdWarned.add(folder.uri.fsPath);
      log.warn(`vaultId of ${folder.name} changed in .vscode/settings.json: "${id}" (pinned: "${pinned}")`);
      void vscode.window
        .showWarningMessage(
          `Env Lock: envLock.vaultId in ${folder.name}/.vscode/settings.json changed to "${id || '(removed)'}". ` +
            `Still using your vault "${pinned}". If you changed it yourself, switch to the new id.`,
          'Use the new id'
        )
        .then(async (pick) => {
          if (pick && id) {
            records.pins = { ...records.pins, [folder.uri.fsPath]: id };
            await saveRecords();
            log.info(`vaultId of ${folder.name} re-pinned to "${id}"`);
            void refreshStatus();
          }
        });
    }
    id = pinned;
  }
  if (!id) {
    if (!create) return undefined;
    id = newVaultId();
    await c.update('vaultId', id, vscode.ConfigurationTarget.WorkspaceFolder);
  }
  if (!pinned) {
    records.pins = { ...records.pins, [folder.uri.fsPath]: id };
    await saveRecords();
  }
  // vault.json never changes once written: read it once per vault, not on every scan.
  const key = path.join(vaultRoot(), id);
  let v = vaultCache.get(key);
  if (!v) {
    v = openVault(vaultRoot(), id);
    vaultCache.set(key, v);
    v.catch(() => vaultCache.delete(key));
  }
  const vault = await v;
  // vault.json is read once and cached: also compare the file NOW, so a salt rewritten while VS Code
  // runs is noticed at the next scan, not only after a restart (and a pin lost with the credential
  // store does not hide it either).
  const onDisk = await fs.readFile(path.join(vault.dir, 'vault.json'), 'utf8').then(
    (t) => (JSON.parse(t) as { salt?: string }).salt,
    () => undefined
  );
  if (onDisk !== vault.salt.toString('base64')) {
    vaultCache.delete(key);
    throw new Error(
      `vault.json of vault "${id}" was changed by something other than Env Lock (its salt is not the one in use). ` +
        'Restore that file from your backup ("Env Lock: Back up keys and vault").'
    );
  }
  // vault.json is a plain file: a rewritten salt would make every blob look forged (or be used to
  // swap blob names). Its fingerprint is pinned in the protected records on first use.
  const fp = saltFingerprint(vault);
  const pinnedSalt = records.vaultSalts?.[id];
  if (!pinnedSalt) {
    records.vaultSalts = { ...records.vaultSalts, [id]: fp };
    await saveRecords();
  } else if (pinnedSalt !== fp) {
    vaultCache.delete(key);
    throw new Error(
      `vault.json of vault "${id}" was changed by something other than Env Lock (its salt is not the one pinned). ` +
        'Restore that file from your backup ("Env Lock: Back up keys and vault").'
    );
  }
  return vault;
}

const vaultProblemsWarned = new Set<string>();
/** A broken vault must not look like "nothing is locked". */
function reportVaultProblem(folder: vscode.WorkspaceFolder, e: unknown) {
  const msg = `${folder.name}: ${(e as Error)?.message ?? e}`;
  if (vaultProblemsWarned.has(msg)) return;
  vaultProblemsWarned.add(msg);
  log.error(`Vault unreadable: ${msg}`);
  void vscode.window.showErrorMessage(`Env Lock: cannot read the vault of ${msg}`, 'Show vault folder').then((pick) => {
    if (pick) void revealVaultCommand();
  });
}

const vaultCache = new Map<string, Promise<Vault>>();
const VAULT_PINS = 'envLock.vaultPins';
const vaultIdWarned = new Set<string>();

async function vaultItems(): Promise<VaultItem[]> {
  const items: VaultItem[] = [];
  for (const folder of vscode.workspace.workspaceFolders ?? []) {
    if (folder.uri.scheme !== 'file') continue;
    try {
      const v = await folderVault(folder, false);
      if (v) items.push(...(await vaultList(v)).map((blob) => ({ folder, vault: v, blob })));
    } catch (e) {
      reportVaultProblem(folder, e);
    }
  }
  return items;
}

const relTo = (folder: vscode.WorkspaceFolder, u: vscode.Uri) => path.relative(folder.uri.fsPath, u.fsPath).replace(/\\/g, '/');

/** Signature binding of an in-place locked file, from where its readable copy belongs. */
function inPlaceBinding(plainPath: string): string {
  const uri = vscode.Uri.file(plainPath);
  const folder = vscode.workspace.getWorkspaceFolder(uri);
  return fileBinding(folder ? relTo(folder, uri) : plainPath);
}

/**
 * Every file of the workspace's local folders. Env Lock walks them itself instead of using
 * vscode.workspace.findFiles, which honours .ignore / .rgignore / search.exclude / files.exclude:
 * project files an agent can write to hide a secret from Env Lock (red-team test T25).
 */
async function workspaceFiles(): Promise<Array<{ folder: vscode.WorkspaceFolder; rel: string }>> {
  let ex: string[];
  try {
    ex = expandBraces(exclude());
  } catch {
    ex = ['**/node_modules/**', '**/.git/**']; // unusable envLock.exclude: still never skip secrets elsewhere
  }
  const out: Array<{ folder: vscode.WorkspaceFolder; rel: string }> = [];
  for (const folder of vscode.workspace.workspaceFolders ?? []) {
    if (folder.uri.scheme !== 'file') continue;
    const { files, truncated } = await scanFiles(folder.uri.fsPath, ex);
    if (truncated) warnTruncated(folder);
    for (const r of files) out.push({ folder, rel: r });
  }
  return out;
}

const truncatedWarned = new Set<string>();
function warnTruncated(folder: vscode.WorkspaceFolder) {
  if (truncatedWarned.has(folder.uri.fsPath)) return;
  truncatedWarned.add(folder.uri.fsPath);
  log.warn(`${folder.name}: too many files or folders too deep to scan completely; some secret files may be missed`);
  void vscode.window.showWarningMessage(
    `Env Lock: ${folder.name} has too many files (or folders nested too deep) to scan completely, so some secret files may be missed. ` +
      'Add large generated folders to envLock.exclude in your User settings.'
  );
}

async function findSecretFiles(): Promise<SecretFiles> {
  const allow = allowList();
  const patterns = activePatterns();
  const [all, vault] = await Promise.all([workspaceFiles(), vaultItems()]);
  const plain: vscode.Uri[] = [];
  const candidates: vscode.Uri[] = [];
  const templates: vscode.Uri[] = [];
  for (const { folder, rel: r } of all) {
    const lower = r.toLowerCase();
    if (lower.endsWith(TMP)) continue;
    const u = vscode.Uri.file(path.join(folder.uri.fsPath, r));
    if (lower.endsWith(LOCKED)) candidates.push(u);
    else if (matchesAny(r, patterns)) (matchesAny(r, allow) ? templates : plain).push(u);
  }
  plain.push(...(await templatesWithSecrets(templates)));
  const isLocked = await Promise.all(
    candidates.map((u) =>
      fs.readFile(u.fsPath, 'utf8').then(isLockedFile, () => false) // unreadable: skip
    )
  );
  return { plain, locked: candidates.filter((_, i) => isLocked[i]), vault };
}

/** Text of a small regular file, or undefined (missing, a link, too big, binary). */
async function smallText(p: string, max = 256 * 1024): Promise<string | undefined> {
  try {
    const st = await fs.lstat(p);
    if (!st.isFile() || st.size > max || st.size < 12) return undefined;
    const buf = await fs.readFile(p);
    return buf.includes(0) ? undefined : buf.toString('utf8');
  } catch {
    return undefined;
  }
}

const warnedTemplates = new Set<string>();
/**
 * Allow-listed templates (.env.example…) are never locked: they should hold no real secret. An
 * agent can rename `.env` to `.env.example` while it is unlocked so that lock skips it (red-team X7).
 * A template holding a value of a secret you locked is locked like a secret.
 */
async function templatesWithSecrets(templates: vscode.Uri[]): Promise<vscode.Uri[]> {
  const prints = records.copyPrints;
  if (!templates.length || !prints?.stamps.length) return [];
  const key = (await readTrust())?.macKey;
  if (!key) return [];
  const known = new Set(prints.stamps);
  const out: vscode.Uri[] = [];
  for (const u of templates) {
    const text = await smallText(u.fsPath);
    if (text === undefined || !containsSecret(key, text, prints, known)) continue;
    out.push(u);
    const k = u.fsPath.toLowerCase();
    if (!warnedTemplates.has(k)) {
      warnedTemplates.add(k);
      log.warn(`Template holds a real secret value, locked like a secret: ${rel(u)}`);
      void vscode.window.showWarningMessage(
        `Env Lock: ${rel(u)} is a template (normally never locked) but holds a real value of a secret you locked. ` +
          'Something (an AI agent?) may have copied or renamed a secret file to it while it was unlocked. Env Lock locks it like a secret.'
      );
    }
  }
  return out;
}

let warnedCopies = '';
/**
 * After a lock: look for copies of the locked secret values in files Env Lock does not lock
 * (notes.txt, src/config.js…), made while they were unlocked (red-team X2/X7), and report them.
 */
async function huntCopies() {
  try {
    const prints = records.copyPrints;
    if (!prints?.stamps.length) return;
    const key = (await readTrust())?.macKey;
    if (!key) return;
    const known = new Set(prints.stamps);
    const patterns = activePatterns();
    const found: vscode.Uri[] = [];
    let read = 0;
    for (const { folder, rel: r } of await workspaceFiles()) {
      if (read >= 5000) break;
      const lower = r.toLowerCase();
      if (lower.endsWith(LOCKED) || lower.endsWith(TMP) || matchesAny(r, patterns)) continue;
      const p = path.join(folder.uri.fsPath, r);
      const text = await smallText(p, 64 * 1024);
      if (text === undefined) continue;
      read++;
      if (containsSecret(key, text, prints, known)) found.push(vscode.Uri.file(p));
    }
    const sig = found.map((u) => u.fsPath).join('|');
    if (!found.length || sig === warnedCopies) return;
    warnedCopies = sig;
    const names = found.map(rel).join(', ');
    log.error(`Copies of locked secret values found in files Env Lock does not lock: ${names}`);
    const pick = await vscode.window.showErrorMessage(
      `Env Lock: copies of locked secret values are still readable in: ${names}. If you did not put them there, something ` +
        '(an AI agent?) copied them while your secrets were unlocked. Protect and lock these files, or remove the values and rotate the secrets.',
      'Protect and lock'
    );
    if (pick !== 'Protect and lock') return;
    for (const u of found) {
      const folder = vscode.workspace.getWorkspaceFolder(u);
      if (!folder) continue;
      const c = cfg(folder.uri);
      const custom = c.get<string[]>('customPatterns', []);
      const r = relTo(folder, u);
      if (!custom.includes(r)) await c.update('customPatterns', [...custom, r], vscode.ConfigurationTarget.WorkspaceFolder);
    }
    // This check starts inside a lock: wait for that lock to finish, or lockCommand would skip (busy).
    for (let i = 0; busy && i < 300; i++) await new Promise((r) => setTimeout(r, 100));
    if (!(await lockCommand(undefined, found))) {
      void vscode.window.showErrorMessage(`Env Lock: could not lock ${names}; try "Env Lock: Lock all secret files".`);
    }
  } catch (e) {
    log.warn(`Looking for copies of secrets failed: ${(e as Error).message}`);
  }
}

// ================================================================= keys

function keyringPath(): string {
  const p = secure<string>('keyringPath', '').trim();
  return p ? expandHome(p) : defaultKeyringPath();
}

// ================================================================= trust (pinned keyring + signing key)
//
// keyring.json sits in your home folder, where an agent running as you can replace it. Locking
// needs no passphrase, so a swapped keyring would silently encrypt your secrets to the agent's key.
// Trust = the key id you set up + a random signing key, kept in the OS credential store
// (VS Code SecretStorage), never in a file. Locking refuses any keyring that does not match.

interface Trust {
  keyId: string;
  macKey: Buffer;
  hasRecords?: boolean; // protected records exist (their disappearance is then reported)
}
const TRUST_SECRET = 'envLock.trust.v1';
let cachedTrust: Trust | undefined;

async function readTrust(): Promise<Trust | undefined> {
  if (cachedTrust) return cachedTrust;
  try {
    const j = JSON.parse((await secrets.get(TRUST_SECRET)) ?? '');
    if (typeof j.keyId === 'string' && typeof j.macKey === 'string') {
      cachedTrust = { keyId: j.keyId, macKey: Buffer.from(j.macKey, 'base64'), hasRecords: j.hasRecords === true };
    }
  } catch {
    /* none yet */
  }
  return cachedTrust;
}

async function writeTrust(keyId: string, hasRecords?: boolean, macKey?: Buffer): Promise<Trust> {
  const old = await readTrust();
  // Normally the key derived from your private key (see macKeyFromPrivate); a random one only for
  // keyrings pinned by an older Env Lock, which still verify through the stored copy.
  const t: Trust = { keyId, macKey: macKey ?? old?.macKey ?? newMacKey(), hasRecords: hasRecords ?? old?.hasRecords };
  await secrets.store(
    TRUST_SECRET,
    JSON.stringify({ keyId: t.keyId, macKey: t.macKey.toString('base64'), hasRecords: t.hasRecords === true })
  );
  cachedTrust = t;
  return t;
}

/** Keys a signature may come from: the stored one, and the one derived from your private key. */
async function signingKeys(priv: PrivateKeys): Promise<Buffer[]> {
  const stored = (await readTrust())?.macKey;
  const derived = macKeyFromPrivate(priv);
  return stored && !stored.equals(derived) ? [stored, derived] : [derived];
}

/** The trust for keyring k: undefined if k is not the pinned keyring and the user did not prove it is theirs. */
async function trustedFor(k: KeyringFile, interactive: boolean): Promise<Trust | undefined> {
  const t = await readTrust();
  if (t && t.keyId === k.keyId) {
    cachedPub = publicKeys(k);
    return t;
  }
  if (t) log.error(`Keyring changed: ${keyringPath()} holds key ${k.keyId}, pinned key is ${t.keyId}. Refusing to lock with it.`);
  if (!interactive) return undefined;
  const pick = t
    ? await vscode.window.showWarningMessage(
        `Env Lock: your keyring changed. ${keyringPath()} now holds key ${k.keyId}, not your key ${t.keyId}. ` +
          'Something may have replaced it to read your secrets, so nothing was locked. ' +
          'Only trust it if you replaced it yourself (it needs that keyring\'s passphrase).',
        { modal: true },
        'Trust this keyring'
      )
    : await vscode.window.showWarningMessage(
        'Env Lock: confirm your passphrase once so Env Lock can pin your keyring and sign locked files.',
        'Confirm passphrase'
      );
  if (!pick) return undefined;
  // An attacker's keyring is sealed with the attacker's passphrase: yours will not open it.
  const opened = await unlockKeyring(k, `Passphrase of keyring ${k.keyId}`);
  if (!opened) return undefined;
  cachedPub = publicKeys(k);
  const t2 = await writeTrust(k.keyId, undefined, macKeyFromPrivate(opened.priv));
  wipePrivate(opened.priv);
  return t2;
}

async function loadKeyring(): Promise<KeyringFile | undefined> {
  try {
    const k = await readKeyring(keyringPath());
    if (!k) cachedPub = undefined;
    return k;
  } catch (e: any) {
    vscode.window.showErrorMessage(`Env Lock: cannot read keyring ${keyringPath()}: ${e.message ?? e}`);
    return undefined;
  }
}

// Anti-phishing: an agent can print "Env Lock passphrase:" in a terminal. A real prompt is always a
// VS Code input box and shows a personal phrase that only you (and the OS credential store) know.
const PHRASE_SECRET = 'envLock.phrase.v1';

async function promptPass(prompt: string, isNew = false): Promise<string | undefined> {
  const phrase = await secrets.get(PHRASE_SECRET);
  return vscode.window.showInputBox({
    title: phrase ? `Env Lock · your phrase: "${phrase}"` : 'Env Lock (set an anti-phishing phrase: "Env Lock: Set anti-phishing phrase")',
    prompt: `${prompt}. Env Lock only ever asks here, never in a terminal${phrase ? ', and always shows your phrase above' : ''}.`,
    password: true,
    ignoreFocusOut: true,
    // Existing passphrases only need the old minimum; new ones must pass the strength check.
    validateInput: (v) => (isNew ? passphraseProblem(v) : v.length < MIN_PASS ? `At least ${MIN_PASS} characters` : undefined),
  });
}

async function setPhraseCommand(): Promise<boolean> {
  const phrase = await vscode.window.showInputBox({
    title: 'Env Lock: anti-phishing phrase',
    prompt:
      'A short personal phrase shown in every real Env Lock passphrase prompt (e.g. "blue teapot 42"). ' +
      'If a prompt does not show it, or asks in a terminal, it is fake: do not type your passphrase.',
    ignoreFocusOut: true,
    validateInput: (v) => (v.trim().length < 4 ? 'At least 4 characters' : v.length > 40 ? 'At most 40 characters' : undefined),
  });
  if (!phrase) return false;
  await secrets.store(PHRASE_SECRET, phrase.trim());
  vscode.window.showInformationMessage(`Env Lock: real passphrase prompts will now show "${phrase.trim()}".`);
  return true;
}

async function askNewPassphrase(): Promise<string | undefined> {
  const p1 = await promptPass('Choose a passphrase to protect your PQC private key (a few random words is best)', true);
  if (!p1) return;
  const p2 = await promptPass('Confirm the passphrase');
  if (p2 === undefined) return;
  if (p1 !== p2) {
    vscode.window.showErrorMessage('Env Lock: passphrases do not match.');
    return;
  }
  return p1;
}

/** Reads the key file required by the keyring. null = cancelled / unreadable. */
async function loadKeyFile(): Promise<Buffer | null> {
  let file = expandHome(secure<string>('keyFile', '').trim());
  if (!file) {
    const picked = await vscode.window.showOpenDialog({ title: 'Select your Env Lock key file', canSelectMany: false });
    if (!picked?.length) return null;
    file = picked[0].fsPath;
  }
  try {
    return await fs.readFile(file);
  } catch {
    vscode.window.showErrorMessage(`Env Lock: cannot read key file "${file}". Is the drive plugged in?`);
    return null;
  }
}

/** Lets the user choose key-file protection. undefined = cancelled, null = no key file. */
async function chooseKeyFile(): Promise<Buffer | null | undefined> {
  const pick = await vscode.window.showQuickPick(
    [
      { id: 'none', label: 'Passphrase only' },
      { id: 'new', label: 'Passphrase + NEW key file', description: 'strongest: keep it on a USB drive' },
      { id: 'existing', label: 'Passphrase + EXISTING key file' },
    ],
    { placeHolder: 'How should your private key be protected?', ignoreFocusOut: true }
  );
  if (!pick) return undefined;
  if (pick.id === 'none') {
    await updateOwnSetting('keyFile', '');
    return null;
  }
  let file: string;
  if (pick.id === 'new') {
    const target = await vscode.window.showSaveDialog({ title: 'Save key file (outside your projects!)', filters: { 'Env Lock key': ['envkey'] } });
    if (!target) return undefined;
    if (vscode.workspace.getWorkspaceFolder(target)) {
      vscode.window.showErrorMessage('Env Lock: do not store the key file inside the workspace; agents could read it.');
      return undefined;
    }
    file = target.fsPath;
    await fs.writeFile(file, generateKeyFile());
  } else {
    const picked = await vscode.window.showOpenDialog({ title: 'Select key file', canSelectMany: false });
    if (!picked?.length) return undefined;
    file = picked[0].fsPath;
  }
  await updateOwnSetting('keyFile', file);
  return fs.readFile(file);
}

/** Asks for passphrase (+ key file) and returns the verified secret and private keys. */
async function unlockKeyring(k: KeyringFile, prompt: string): Promise<{ secret: Secret; priv: PrivateKeys } | undefined> {
  let keyFile: Buffer | undefined;
  if (keyringNeedsKeyFile(k)) {
    const kf = await loadKeyFile();
    if (!kf) return;
    keyFile = kf;
  }
  const passphrase = await promptPass(prompt);
  if (!passphrase) return;
  const secret: Secret = { passphrase, keyFile };
  try {
    const priv = await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Window, title: 'Env Lock: deriving key…' },
      () => openKeyring(k, secret)
    );
    return { secret, priv };
  } catch (e) {
    if (e instanceof WrongPassphraseError) {
      vscode.window.showErrorMessage('Env Lock: wrong passphrase or key file.');
      return;
    }
    throw e;
  }
}

async function setupKeysCommand(): Promise<boolean> {
  const file = keyringPath();
  if (await readKeyring(file).catch(() => undefined)) {
    vscode.window.showInformationMessage(`Env Lock: keys already exist at ${file}. Use "Change passphrase" to change protection.`);
    return true;
  }
  const keyFile = await chooseKeyFile();
  if (keyFile === undefined) return false;
  const passphrase = await askNewPassphrase();
  if (!passphrase) return false;
  const k = await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: 'Env Lock: generating ML-KEM-768 + X25519 key pair…' },
    () => createKeyring({ passphrase, keyFile: keyFile ?? undefined })
  );
  await writeKeyring(file, k);
  cachedPub = publicKeys(k);
  const fresh = await openKeyring(k, { passphrase, keyFile: keyFile ?? undefined });
  await writeTrust(k.keyId, undefined, macKeyFromPrivate(fresh));
  wipePrivate(fresh);
  log.info(`New keyring ${k.keyId} created and pinned`);
  if (!(await secrets.get(PHRASE_SECRET))) await setPhraseCommand();
  const pick = await vscode.window.showWarningMessage(
    `Env Lock: post-quantum keys created (id ${k.keyId}).\n\nBACK UP ${file}${keyFile ? ' and your key file' : ''}. ` +
      `Without it (and your passphrase) locked files can never be recovered.`,
    { modal: true },
    'Reveal keyring'
  );
  if (pick) await vscode.commands.executeCommand('revealFileInOS', vscode.Uri.file(file));
  return true;
}

async function changePassphraseCommand() {
  const k = await loadKeyring();
  if (!k) return void vscode.window.showErrorMessage('Env Lock: no keys yet. Run "Set up post-quantum keys".');
  const current = await unlockKeyring(k, 'CURRENT passphrase');
  if (!current) return;
  const keyFile = await chooseKeyFile();
  if (keyFile === undefined) return;
  const passphrase = await askNewPassphrase();
  if (!passphrase) return;
  const next = await resealKeyring(k, current.secret, { passphrase, keyFile: keyFile ?? undefined });
  await writeKeyring(keyringPath(), next);
  vscode.window.showInformationMessage('Env Lock: passphrase changed. Locked files stay valid (same key pair).');
}

// ================================================================= lock / unlock

/**
 * Encrypts each file into its folder's vault, or next to it (<file>.locked) in "inPlace" mode,
 * then deletes the plaintext. create=false: never create a vault id (used during shutdown).
 */
async function lockFiles(paths: string[], pub: PublicKeys, macKey: Buffer | undefined, create = true): Promise<void> {
  const seen: Record<string, Latest> = {};
  const linked: string[] = [];
  let prints = records.copyPrints;
  try {
    for (const p of paths) {
      const uri = vscode.Uri.file(p);
      const folder = vscode.workspace.getWorkspaceFolder(uri);
      const r = folder ? relTo(folder, uri) : p;
      // A link named ".env" would make Env Lock read (and sign) whatever file it points to, and a later
      // unlock would copy that file into the project: a sandboxed agent could read e.g. ~/.ssh this way.
      // Check, open, then check that the OPENED file is the one checked (no swap in between).
      const st = await fs.lstat(p);
      if (!st.isFile() || st.nlink > 1) {
        log.warn(`Not locked, not a plain regular file (link or hard link): ${r}`);
        linked.push(p);
        continue;
      }
      const fh = await fs.open(p, 'r');
      let data: Buffer;
      try {
        const opened = await fh.stat();
        if (opened.ino !== st.ino || opened.dev !== st.dev || opened.nlink > 1) {
          log.warn(`Not locked, file was swapped while being locked: ${r}`);
          continue;
        }
        data = await fh.readFile();
      } finally {
        await fh.close();
      }
      const signedAt = Date.now();
      const vault = folder && storageMode(folder) === 'vault' ? await folderVault(folder, create) : undefined;
      let lockedPath: string;
      let bind: string;
      if (vault) {
        bind = vaultBinding(vault, r);
        lockedPath = await vaultPut(vault, r, data, pub, macKey, signedAt);
      } else {
        bind = fileBinding(r);
        lockedPath = p + LOCKED;
        const tmp = lockedPath + TMP;
        const locked = encryptFile(data, pub);
        await fs.writeFile(tmp, macKey ? signLocked(locked, macKey, bind, signedAt) : locked, 'utf8');
        await fs.rename(tmp, lockedPath);
      }
      if (macKey) prints = mergePrints(prints, printsOf(macKey, data.toString('utf8')));
      data.fill(0);
      await fs.unlink(p);
      if (macKey) seen[bind] = { at: signedAt, locked: true, lockedPath, plainPath: p, label: r };
    }
  } finally {
    if (prints !== records.copyPrints) {
      records.copyPrints = prints;
      if (!Object.keys(seen).length) await saveRecords(); // otherwise recordLatest saves them
    }
    await recordLatest(seen);
    if (linked.length) void warnLinked(linked);
  }
}

/** Other names of a hard-linked file (Windows: fsutil; elsewhere unknown). */
function hardLinkNames(file: string): Promise<string[]> {
  if (process.platform !== 'win32') return Promise.resolve([]);
  return new Promise((resolve) =>
    execFile('fsutil', ['hardlink', 'list', file], { timeout: 5000, windowsHide: true }, (err, stdout) => {
      if (err) return resolve([]);
      const drive = path.parse(path.resolve(file)).root.replace(/[\\/]$/, '');
      const me = path.resolve(file).toLowerCase();
      resolve(
        String(stdout)
          .split(/\r?\n/)
          .map((l) => l.trim())
          .filter(Boolean)
          .map((l) => (/^[\\/]/.test(l) ? drive + l : l))
          .filter((l) => path.resolve(l).toLowerCase() !== me)
      );
    })
  );
}

let warnedLinked = '';
/**
 * A secret file that is a link or has a second name (hard link) is never encrypted: it could point
 * at a file outside the project (red-team R4). But then its plaintext stays readable, under this
 * name AND the other one, which an agent may have made while it was unlocked (red-team X2): say so.
 */
async function warnLinked(files: string[]) {
  const sig = files.join('|');
  if (sig === warnedLinked) return;
  warnedLinked = sig;
  const parts: string[] = [];
  for (const f of files) {
    const others = await hardLinkNames(f);
    parts.push(
      vscode.workspace.asRelativePath(f) +
        (others.length ? ` (same file as: ${others.map((o) => vscode.workspace.asRelativePath(o)).join(', ')})` : '')
    );
  }
  log.error(`NOT locked, link or hard link, plaintext still readable: ${parts.join('; ')}`);
  void vscode.window.showErrorMessage(
    `Env Lock: NOT locked, still readable: ${parts.join('; ')}. The file is a link or has a second name on disk (a hard link), ` +
      'so its secret can also be read under the other name. Something may have made it while your secrets were unlocked. ' +
      'Env Lock never encrypts a linked file (it could be a link to a file outside the project). ' +
      'Delete the other name(s) and lock again; rotate the secret if you did not make the link.'
  );
}

// ================================================================= versions (rollback & deletion)
//
// For every file you lock, remember (in VS Code's user storage, outside the project) when its
// newest signed version was made and where it lives. An agent could otherwise put back an OLDER
// signed version (e.g. with a revoked key) or silently delete a locked file.

interface Latest {
  at: number; // signedAt of the newest version you locked
  locked: boolean; // false once you unlocked it
  lockedPath: string;
  plainPath: string;
  label: string;
}
const LATEST = 'envLock.latest';
const latestAll = () => records.latest;

async function recordLatest(updates: Record<string, Partial<Latest>>) {
  if (!Object.keys(updates).length) return;
  const all = { ...latestAll() };
  for (const [bind, u] of Object.entries(updates)) all[bind] = { ...all[bind], ...u } as Latest;
  records.latest = all;
  await saveRecords();
}

const missingWarned = new Set<string>();
/** Locked files of this workspace that vanished (neither locked nor readable copy exists). */
async function checkMissing() {
  const roots = (vscode.workspace.workspaceFolders ?? []).map((f) => f.uri.fsPath.toLowerCase() + path.sep);
  const exists = (p: string) => fs.access(p).then(() => true, () => false);
  const missing: Latest[] = [];
  for (const [bind, l] of Object.entries(latestAll())) {
    if (!l.locked || missingWarned.has(bind) || !roots.some((r) => l.plainPath.toLowerCase().startsWith(r))) continue;
    if (!(await exists(l.lockedPath)) && !(await exists(l.plainPath))) {
      missingWarned.add(bind);
      missing.push(l);
    }
  }
  if (!missing.length) return;
  const names = missing.map((m) => m.label).join(', ');
  log.error(`Locked file(s) disappeared: ${names}`);
  const inVault = missing.some((m) => m.lockedPath !== m.plainPath + LOCKED);
  const pick = await vscode.window.showErrorMessage(
    `Env Lock: locked secret file(s) were deleted by something other than Env Lock: ${names}. ` +
      (inVault ? 'The vault may still hold the previous version (<name>.locked.prev). ' : '') +
      'Restore from your backup ("Env Lock: Back up keys and vault").',
    ...(inVault ? ['Show vault folder'] : [])
  );
  if (pick) await revealVaultCommand();
}

async function saveAndCloseEditors(uris: vscode.Uri[]) {
  const set = new Set(uris.map((u) => u.fsPath.toLowerCase()));
  for (const d of vscode.workspace.textDocuments) {
    if (d.isDirty && set.has(d.uri.fsPath.toLowerCase())) await d.save();
  }
  const tabs = vscode.window.tabGroups.all
    .flatMap((g) => g.tabs)
    .filter((t) => t.input instanceof vscode.TabInputText && set.has(t.input.uri.fsPath.toLowerCase()));
  if (tabs.length) await vscode.window.tabGroups.close(tabs);
}

function clearAutoLock() {
  if (autoLockTimer) clearTimeout(autoLockTimer);
  autoLockTimer = undefined;
}

function ensureAutoLock() {
  const minutes = autoLockMinutes();
  if (autoLockTimer || minutes <= 0 || !knownPlain.length || !cachedPub) return;
  autoLockTimer = setTimeout(() => {
    autoLockTimer = undefined;
    void lockCommand('auto-lock timer');
  }, minutes * 60_000);
}

async function lockCommand(reason?: string, only?: vscode.Uri[]): Promise<boolean> {
  if (busy) return false;
  busy = true;
  try {
    let k = await loadKeyring();
    if (!k) {
      const pick = await vscode.window.showWarningMessage(
        'Env Lock: no post-quantum keys yet. Set them up once; after that locking never needs a passphrase.',
        'Set up keys'
      );
      if (!pick || !(await setupKeysCommand())) return false;
      k = await loadKeyring();
      if (!k) return false;
    }
    // "Lock all" by hand also ends in-memory sessions (their apps stop). Automatic locks leave them.
    if (!reason && !only) closeSecretTerminals('Lock all secret files');
    let plain = only ?? (await findSecretFiles()).plain;
    const tracked = await committedSecrets(plain, true);
    if (tracked.size) {
      warnTracked(plain.filter((u) => tracked.has(u.fsPath.toLowerCase())).map((u) => u.fsPath));
      plain = plain.filter((u) => !tracked.has(u.fsPath.toLowerCase()));
    }
    if (!plain.length) {
      if (!reason) vscode.window.showInformationMessage('Env Lock: nothing to lock.');
      void huntCopies();
      return true;
    }
    // Never encrypt to a keyring that is not the one you set up (it may have been swapped).
    const trust = await trustedFor(k, true);
    if (!trust) return false;
    await saveAndCloseEditors(plain);
    await lockFiles(
      plain.map((u) => u.fsPath),
      publicKeys(k),
      trust.macKey
    );
    clearAutoLock();
    await autoApplyRules();
    void huntCopies();
    const inVault = plain.some((u) => {
      const f = vscode.workspace.getWorkspaceFolder(u);
      return f && storageMode(f) === 'vault';
    });
    vscode.window.showInformationMessage(
      `Env Lock: 🔒 locked ${plain.length} file(s) with ML-KEM-768 + X25519${inVault ? ' and moved them to the vault, outside the project' : ''}` +
        `${reason ? ` (${reason})` : ''}.`
    );
    return true;
  } catch (e: any) {
    vscode.window.showErrorMessage(`Env Lock: ${e.message ?? e}`);
    return false;
  } finally {
    busy = false;
    void refreshStatus();
  }
}

interface Decrypted {
  target: string; // where the readable file goes
  data: Buffer;
  remove: string; // the locked copy to delete once restored
  label: string;
  bind: string;
  sign: SignCheck;
}

/**
 * Keeps only files made by this machine's Env Lock, for this file, in their newest version.
 * Invalid signatures are refused (reported in `bad`). Unsigned files (older Env Lock, or planted
 * with your public key) and older versions (possible rollback) need explicit consent.
 */
async function checkSignatures(entries: Decrypted[], bad: string[]): Promise<Decrypted[]> {
  if (recordsReset) {
    // Files signed by an Env Lock older than 0.7.2 used a random key, lost with the wiped store: such a
    // signature can no longer be told from a forged one. Ask (like an unsigned file) instead of refusing
    // the user's own files forever. Files signed since 0.7.2 still verify (derived key).
    for (const e of entries) if (e.sign.state === 'invalid') e.sign = { state: 'unsigned', signedAt: 0 };
  }
  const invalid = entries.filter((e) => e.sign.state === 'invalid');
  bad.push(...invalid.map((e) => e.label));
  if (invalid.length) log.error(`Refused, invalid signature (not made by your Env Lock, or renamed): ${invalid.map((e) => e.label).join(', ')}`);
  const newest = latestAll();
  const stale = entries.filter((e) => e.sign.state === 'valid' && e.sign.signedAt < (newest[e.bind]?.at ?? 0));
  const unsigned = entries.filter((e) => e.sign.state === 'unsigned');
  const ask = async (list: Decrypted[], why: string) => {
    if (!list.length) return false;
    const yes = !!(await vscode.window.showWarningMessage(
      `Env Lock: ${list.map((e) => e.label).join(', ')}: ${why}`,
      { modal: true },
      'Use them'
    ));
    log.warn(`${yes ? 'Accepted' : 'Rejected'}: ${list.map((e) => e.label).join(', ')} (${why.split('.')[0]})`);
    return yes;
  };
  const useUnsigned = await ask(
    unsigned,
    'no signature. Locked by an older Env Lock, or created by someone else using your public key (e.g. to swap in a fake API URL). ' +
      'Only use them if you locked them yourself. They are signed when locked again.'
  );
  const useStale = await ask(
    stale,
    'OLDER version than the one you last locked. Something may have put back an old copy (e.g. with a revoked key). ' +
      'Only use it if you restored it on purpose.'
  );
  return entries.filter(
    (e) => (e.sign.state === 'valid' && (!stale.includes(e) || useStale)) || (e.sign.state === 'unsigned' && useUnsigned)
  );
}

/** Decrypts every vault blob of the workspace. Unsafe or foreign entries are reported, not returned. */
async function readVault(items: VaultItem[], priv: PrivateKeys, foreign: string[], refused: string[]): Promise<Decrypted[]> {
  const out: Decrypted[] = [];
  const macKey = await signingKeys(priv);
  for (const it of items) {
    let env;
    try {
      env = await vaultRead(it.vault, it.blob, priv, macKey);
    } catch (e) {
      if (e instanceof WrongKeyError) foreign.push(`vault/${path.basename(it.blob)}`);
      else throw new Error(`vault/${path.basename(it.blob)}: ${(e as Error).message}`);
      continue;
    }
    // The public key is not secret: anyone could plant a blob. Only restore secret files inside the project.
    const target = restoreTarget(it.folder.uri.fsPath, env.path);
    if (!target || !matchesAny(env.path, activePatterns())) {
      refused.push(env.path);
      continue;
    }
    out.push({ target, data: env.data, remove: it.blob, label: env.path, bind: vaultBinding(it.vault, env.path), sign: env.sign });
  }
  return out;
}

// ================================================================= AI extensions & git

const DEFAULT_AGENT_EXTENSIONS = [
  'anthropic.claude-code',
  'github.copilot',
  'github.copilot-chat',
  'saoudrizwan.claude-dev', // Cline
  'rooveterinaryinc.roo-cline',
  'kilocode.kilo-code',
  'continue.continue',
  'codeium.codeium',
  'google.geminicodeassist',
  'amazonwebservices.amazon-q-vscode',
  'sourcegraph.cody-ai',
  'tabnine.tabnine-vscode',
  'openai.chatgpt',
];

/** Installed AI extensions: they run inside VS Code, so terminal detection never sees them. */
function installedAgentExtensions(): string[] {
  const ids = new Set(secure<string[]>('agentExtensions', DEFAULT_AGENT_EXTENSIONS).map((x) => x.toLowerCase()));
  return vscode.extensions.all.filter((e) => ids.has(e.id.toLowerCase())).map((e) => e.packageJSON?.displayName ?? e.id);
}

/**
 * The project's .git/config is writable by agents, and git runs commands named there. Tested:
 * `core.fsmonitor = <command>` runs that command on `git ls-files` and `git check-ignore`, so every
 * status refresh would run it, from VS Code, outside the agent's sandbox. Switch it off.
 */
const GIT_SAFE = ['-c', 'core.fsmonitor=false'];

/** true = ignored by git, false = would be committed, undefined = not a git repo / git missing. */
function gitIgnored(cwd: string, file: string): Promise<boolean | undefined> {
  return new Promise((resolve) =>
    execFile('git', [...GIT_SAFE, 'check-ignore', '-q', '--', file], { cwd, timeout: 5000, windowsHide: true }, (err) => {
      if (!err) resolve(true);
      else resolve((err as any).code === 1 ? false : undefined);
    })
  );
}

/**
 * Secret files git already tracks. Locking one would delete it from the working tree: git shows a
 * deletion that could be committed, and the secret is in the git history anyway. Those are skipped.
 */
async function gitTrackedFiles(paths: string[]): Promise<Set<string>> {
  const tracked = new Set<string>();
  const byFolder = new Map<vscode.WorkspaceFolder, string[]>();
  for (const p of paths) {
    const folder = vscode.workspace.getWorkspaceFolder(vscode.Uri.file(p));
    if (folder) byFolder.set(folder, [...(byFolder.get(folder) ?? []), p]);
  }
  await Promise.all(
    [...byFolder].map(
      ([folder, files]) =>
        new Promise<void>((resolve) =>
          execFile(
            'git',
            [...GIT_SAFE, 'ls-files', '-z', '--', ...files.map((f) => path.relative(folder.uri.fsPath, f))],
            { cwd: folder.uri.fsPath, timeout: 5000, windowsHide: true, maxBuffer: 1 << 20 },
            (err, stdout) => {
              // Output paths are relative to cwd (the folder), with "/" separators.
              if (!err) {
                const listed = new Set(stdout.split('\0').filter(Boolean).map((x) => x.toLowerCase()));
                for (const f of files) {
                  if (listed.has(path.relative(folder.uri.fsPath, f).replace(/\\/g, '/').toLowerCase())) tracked.add(f.toLowerCase());
                }
              }
              resolve(); // not a git repo / no git: nothing is tracked
            }
          )
        )
    )
  );
  return tracked;
}

/**
 * Which of these (tracked) files are in the last commit. undefined if that cannot be known (then
 * every tracked file is treated as committed, the safe side: never unstage a committed file).
 */
async function gitHeadFiles(paths: string[]): Promise<Set<string> | undefined> {
  const out = new Set<string>();
  const byFolder = new Map<vscode.WorkspaceFolder, string[]>();
  for (const p of paths) {
    const folder = vscode.workspace.getWorkspaceFolder(vscode.Uri.file(p));
    if (folder) byFolder.set(folder, [...(byFolder.get(folder) ?? []), p]);
  }
  const run = (cwd: string, args: string[]) =>
    new Promise<{ code: number; out: string }>((resolve) =>
      execFile('git', [...GIT_SAFE, ...args], { cwd, timeout: 5000, windowsHide: true, maxBuffer: 1 << 20 }, (err: any, stdout) =>
        resolve({ code: err ? (typeof err.code === 'number' ? err.code : -1) : 0, out: String(stdout) })
      )
    );
  for (const [folder, files] of byFolder) {
    const cwd = folder.uri.fsPath;
    const r = await run(cwd, ['ls-tree', '-r', '-z', '--name-only', 'HEAD', '--', ...files.map((f) => path.relative(cwd, f))]);
    if (r.code !== 0) {
      // No commit yet (unborn branch): nothing is committed. Any other failure: unknown.
      const head = await run(cwd, ['rev-parse', '--verify', '-q', 'HEAD']);
      if (head.code === 1) continue;
      return undefined;
    }
    const listed = new Set(r.out.split('\0').filter(Boolean).map((x) => x.toLowerCase()));
    for (const f of files) if (listed.has(path.relative(cwd, f).replace(/\\/g, '/').toLowerCase())) out.add(f.toLowerCase());
  }
  return out;
}

/** `git rm --cached` (unstage; the file itself stays). Returns the files that were unstaged. */
async function gitUnstage(paths: string[]): Promise<Set<string>> {
  const done = new Set<string>();
  for (const p of paths) {
    const folder = vscode.workspace.getWorkspaceFolder(vscode.Uri.file(p));
    if (!folder) continue;
    const ok = await new Promise<boolean>((resolve) =>
      execFile(
        'git',
        [...GIT_SAFE, 'rm', '--cached', '-q', '--', path.relative(folder.uri.fsPath, p)],
        { cwd: folder.uri.fsPath, timeout: 5000, windowsHide: true },
        (err) => resolve(!err)
      )
    );
    if (ok) done.add(p.toLowerCase());
  }
  return done;
}

/**
 * Git-tracked secret files are never locked (locking would delete them from git). But a file that
 * is only STAGED (git add, never committed) is not in your history yet: an agent can `git add .env`
 * while it is unlocked so that every later lock skips it (red-team X1). With `unstage`, those are
 * unstaged so they can be locked. Returns the (lower-case) files that must stay unlocked.
 */
async function committedSecrets(plain: vscode.Uri[], unstage: boolean): Promise<Set<string>> {
  const tracked = await gitTrackedFiles(plain.map((u) => u.fsPath));
  if (!tracked.size) return tracked;
  const head = await gitHeadFiles([...tracked]);
  if (!head) return tracked;
  if (!unstage) return head;
  const stagedOnly = plain.filter((u) => tracked.has(u.fsPath.toLowerCase()) && !head.has(u.fsPath.toLowerCase()));
  const unstaged = await gitUnstage(stagedOnly.map((u) => u.fsPath));
  if (unstaged.size) {
    const names = stagedOnly.filter((u) => unstaged.has(u.fsPath.toLowerCase())).map(rel).join(', ');
    log.warn(`Unstaged (git rm --cached) secret files that were staged but never committed: ${names}`);
    void vscode.window.showWarningMessage(
      `Env Lock: ${names} had been staged for commit (git add) but never committed. Env Lock unstaged it and locked it, ` +
        'so it cannot be committed. If you did not stage it, something (an AI agent?) did. Make sure .gitignore lists it; ' +
        'its staged copy stays in .git/objects until "git gc --prune=now".'
    );
  }
  return new Set([...tracked].filter((t) => !unstaged.has(t)));
}

let warnedTracked = '';
function warnTracked(files: string[]) {
  const sig = files.join('|');
  if (!files.length || sig === warnedTracked) return;
  warnedTracked = sig;
  const names = files.map((f) => vscode.workspace.asRelativePath(f)).join(', ');
  log.warn(`Not locked, tracked by git: ${names}`);
  void vscode.window.showWarningMessage(
    `Env Lock: not locked because git tracks them: ${names}. Locking would delete them from git. ` +
      'They are already in your git history, so treat those secrets as exposed: rotate them, then run ' +
      '"git rm --cached <file>" and add the file to .gitignore. Env Lock locks it from then on.'
  );
}

async function warnIfNotGitIgnored(targets: string[]) {
  const missing: Array<{ folder: vscode.WorkspaceFolder; rel: string }> = [];
  for (const t of targets) {
    const folder = vscode.workspace.getWorkspaceFolder(vscode.Uri.file(t));
    if (!folder) continue;
    const r = path.relative(folder.uri.fsPath, t).replace(/\\/g, '/');
    if ((await gitIgnored(folder.uri.fsPath, r)) === false) missing.push({ folder, rel: r });
  }
  if (!missing.length) return;
  const pick = await vscode.window.showWarningMessage(
    `Env Lock: not ignored by git, so it could be committed: ${missing.map((m) => m.rel).join(', ')}.`,
    'Add to .gitignore'
  );
  if (!pick) return;
  for (const m of missing) {
    const file = path.join(m.folder.uri.fsPath, '.gitignore');
    const cur = await fs.readFile(file, 'utf8').catch(() => '');
    await fs.writeFile(file, cur + (cur && !cur.endsWith('\n') ? '\n' : '') + '/' + m.rel + '\n');
  }
}

/**
 * Unlocking writes readable secrets to disk, where any agent can read them. Confirm it, and offer
 * the in-memory terminal instead. Returns true to go ahead.
 */
async function confirmUnlockToDisk(count: number): Promise<boolean> {
  if (!secure<boolean>('confirmUnlockToDisk', true)) return true;
  const ai = installedAgentExtensions();
  const pick = await vscode.window.showWarningMessage(
    `Env Lock: unlock ${count} file(s) to disk?\n\nWhile unlocked, AI agents can read them` +
      (ai.length ? `, including these installed AI extensions: ${ai.join(', ')}` : '') +
      `. To run your app, "Run a command with secrets" gives them to it in memory instead (nothing written to disk).`,
    { modal: true },
    'Run a command with secrets',
    'Unlock to disk'
  );
  if (pick === 'Run a command with secrets') void runWithSecretsCommand();
  return pick === 'Unlock to disk';
}

async function unlockCommand(only?: { locked: vscode.Uri[]; vault: VaultItem[] }): Promise<void> {
  if (busy) return;
  busy = true;
  try {
    const { locked, vault } = only ?? (await findSecretFiles());
    const total = locked.length + vault.length;
    if (!total) return void vscode.window.showInformationMessage('Env Lock: nothing is locked.');
    if (!(await confirmUnlockToDisk(total))) return;
    const k = await loadKeyring();
    if (!k) return void vscode.window.showErrorMessage(`Env Lock: keyring not found at ${keyringPath()}.`);
    const opened = await unlockKeyring(k, `Passphrase to unlock ${total} file(s)`);
    if (!opened) return;
    // The passphrase proved this keyring is yours: pin it (first run, after an upgrade, or after
    // Env Lock's credential store was wiped), with the signing key derived from it.
    if ((await readTrust())?.keyId !== k.keyId) await writeTrust(k.keyId, undefined, macKeyFromPrivate(opened.priv));
    cachedPub = publicKeys(k);
    const macKey = await signingKeys(opened.priv);

    // Decrypt everything first so a failure never leaves a half-unlocked workspace.
    const all: Decrypted[] = [];
    const foreign: string[] = [];
    const refused: string[] = [];
    const badSig: string[] = [];
    for (const u of locked) {
      try {
        const text = await fs.readFile(u.fsPath, 'utf8');
        all.push({
          target: u.fsPath.slice(0, -LOCKED.length),
          data: decryptFile(text, opened.priv),
          remove: u.fsPath,
          label: rel(u),
          bind: inPlaceBinding(u.fsPath.slice(0, -LOCKED.length)),
          sign: verifyLocked(text, macKey, inPlaceBinding(u.fsPath.slice(0, -LOCKED.length))),
        });
      } catch (e) {
        if (e instanceof WrongKeyError) foreign.push(rel(u));
        else throw new Error(`${rel(u)}: ${(e as Error).message}`);
      }
    }
    all.push(...(await readVault(vault, opened.priv, foreign, refused)));
    const ok = await checkSignatures(all, badSig);

    const skipped: string[] = [];
    const restored: string[] = [];
    const viaLink: string[] = [];
    const unlockedBinds: Record<string, Partial<Latest>> = {};
    for (const { target, data, remove, bind, label } of ok) {
      if (await fs.lstat(target).then(() => true, () => false)) {
        skipped.push(path.basename(target)); // exists already (or is a link): never overwrite
        continue;
      }
      // Links decide where the write really lands: refuse anything leading outside the project.
      const root = vscode.workspace.getWorkspaceFolder(vscode.Uri.file(target))?.uri.fsPath;
      if (!root || !(await safeToWrite(root, target))) {
        viaLink.push(label);
        continue;
      }
      await fs.mkdir(path.dirname(target), { recursive: true });
      if (!(await safeToWrite(root, target))) {
        viaLink.push(label); // a link appeared while the folder was being created
        continue;
      }
      // 'wx': fails if anything (a link included) appeared at the target in the meantime.
      await fs.writeFile(target, data, { mode: 0o600, flag: 'wx' }); // owner-only where the OS supports it
      await fs.unlink(remove);
      restored.push(target);
      unlockedBinds[bind] = { locked: false };
    }
    await recordLatest(unlockedBinds);
    for (const e of all) e.data.fill(0); // best effort: do not keep secrets in memory
    wipePrivate(opened.priv);
    log.info(`Unlocked to disk: ${restored.map((t) => vscode.workspace.asRelativePath(t)).join(', ') || 'nothing'}`);
    if (viaLink.length) log.error(`Refused to unlock through a link leading outside the project: ${viaLink.join(', ')}`);
    const minutes = autoLockMinutes();
    vscode.window.showWarningMessage(
      `Env Lock: 🔓 unlocked ${restored.length} file(s). AI agents CAN read them now.` +
        (minutes > 0 ? ` Auto-lock in ${minutes} min.` : '') +
        (skipped.length ? ` Skipped (plaintext already exists): ${skipped.join(', ')}.` : '') +
        (foreign.length ? ` Locked with a different key: ${foreign.join(', ')}.` : '') +
        (refused.length
          ? ` Kept in the vault (outside the project, or no longer a protected file type; add it to envLock.customPatterns to restore it): ${refused.join(', ')}.`
          : '') +
        (badSig.length ? ` ⚠ REFUSED, signature invalid (not made by your Env Lock; possibly planted): ${badSig.join(', ')}.` : '') +
        (viaLink.length
          ? ` ⚠ REFUSED, its folder is a link leading outside the project (the secret would be written elsewhere): ${viaLink.join(', ')}. Kept locked.`
          : '')
    );
    void warnIfNotGitIgnored(restored);
  } catch (e: any) {
    vscode.window.showErrorMessage(`Env Lock: ${e.message ?? e}`);
  } finally {
    busy = false;
    await refreshStatus();
    ensureAutoLock();
  }
}

async function toggleCommand() {
  const { plain } = await findSecretFiles();
  if (plain.length) await lockCommand();
  else await unlockCommand();
}

// ================================================================= per-file (explorer menu)

const targetUri = (uri?: vscode.Uri) => uri ?? vscode.window.activeTextEditor?.document.uri;

async function protectFileCommand(uri?: vscode.Uri) {
  uri = targetUri(uri);
  if (!uri || uri.scheme !== 'file') return;
  const folder = vscode.workspace.getWorkspaceFolder(uri);
  if (!folder) return void vscode.window.showErrorMessage('Env Lock: the file must be inside the workspace.');
  const r = path.relative(folder.uri.fsPath, uri.fsPath).replace(/\\/g, '/');
  const c = cfg(folder.uri);
  const mine = projectAllow()[folder.uri.fsPath] ?? [];
  if (!matchesAny(r, activePatterns()) || mine.includes(r)) {
    // Any extension can run this command: never encrypt and move a file without asking.
    const ok = await vscode.window.showWarningMessage(
      `Env Lock: protect ${r}? It is encrypted now (moved out of the project in vault mode) and from then on.`,
      { modal: true },
      'Protect and lock'
    );
    if (!ok) return;
  }
  if (mine.includes(r)) await setProjectAllow(folder, mine.filter((a) => a !== r));
  if (!matchesAny(r, activePatterns())) {
    // Adding protection may live in the project (it can only add, never remove).
    const custom = c.get<string[]>('customPatterns', []);
    await c.update('customPatterns', [...custom, r], vscode.ConfigurationTarget.WorkspaceFolder);
  }
  await lockCommand(undefined, [uri]);
}

async function unprotectFileCommand(uri?: vscode.Uri) {
  uri = targetUri(uri);
  if (!uri || uri.scheme !== 'file') return;
  if (uri.fsPath.endsWith(LOCKED)) {
    return void vscode.window.showWarningMessage('Env Lock: unlock this file first (right-click → Env Lock: Unlock this file).');
  }
  const folder = vscode.workspace.getWorkspaceFolder(uri);
  if (!folder) return;
  const r = path.relative(folder.uri.fsPath, uri.fsPath).replace(/\\/g, '/');
  // Weakens protection, and other extensions (AI ones too) can run commands: always confirm.
  const ok = await vscode.window.showWarningMessage(
    `Env Lock: stop protecting ${r}? It will stay readable by AI agents.`,
    { modal: true },
    'Stop protecting'
  );
  if (!ok) return;
  const c = cfg(folder.uri);
  const custom = c.inspect<string[]>('customPatterns')?.workspaceFolderValue ?? [];
  if (custom.includes(r)) {
    await c.update('customPatterns', custom.filter((x) => x !== r), vscode.ConfigurationTarget.WorkspaceFolder);
  }
  if (matchesAny(r, activePatterns())) {
    // Stored in VS Code's user storage, not in the project: an agent cannot add exceptions.
    const mine = projectAllow()[folder.uri.fsPath] ?? [];
    await setProjectAllow(folder, [...new Set([...mine, r])]);
  }
  log.info(`Stopped protecting ${r} (${folder.name})`);
  vscode.window.showInformationMessage(`Env Lock: ${r} is no longer protected.`);
  await autoApplyRules();
  void refreshStatus();
}

const samePath = (a: string, b: string) => (process.platform === 'win32' ? a.toLowerCase() === b.toLowerCase() : a === b);

/**
 * Commands can be run by any extension (AI ones too), with any file. Lock / unlock only what Env
 * Lock itself lists as a protected file of this workspace, so they cannot encrypt-and-delete an
 * arbitrary file, or unlock a planted .locked file somewhere else on disk.
 */
async function protectedUri(uri: vscode.Uri, kind: 'plain' | 'locked'): Promise<vscode.Uri | undefined> {
  const found = (await findSecretFiles())[kind];
  const hit = found.find((u) => samePath(u.fsPath, uri.fsPath));
  if (!hit) {
    log.warn(`Refused ${kind === 'plain' ? 'lock' : 'unlock'} of a file that is not a protected file of this workspace: ${uri.fsPath}`);
    void vscode.window.showWarningMessage(
      `Env Lock: ${vscode.workspace.asRelativePath(uri)} is not a protected secret file of this workspace` +
        (kind === 'plain' ? ' (right-click → "Env Lock: Protect this file" first).' : '.')
    );
  }
  return hit;
}

async function lockFileCommand(uri?: vscode.Uri) {
  uri = targetUri(uri);
  if (!uri || uri.scheme !== 'file' || uri.fsPath.endsWith(LOCKED)) return;
  const hit = await protectedUri(uri, 'plain');
  if (hit) await lockCommand(undefined, [hit]);
}

async function unlockFileCommand(uri?: vscode.Uri) {
  uri = targetUri(uri);
  if (!uri || uri.scheme !== 'file' || !uri.fsPath.endsWith(LOCKED)) return;
  if (!(await protectedUri(uri, 'locked'))) return;
  const wasActive = vscode.window.activeTextEditor?.document.uri.fsPath === uri.fsPath;
  await unlockCommand({ locked: [uri], vault: [] });
  const plainUri = vscode.Uri.file(uri.fsPath.slice(0, -LOCKED.length));
  try {
    await fs.access(uri.fsPath);
    return; // still locked: cancelled or failed
  } catch {
    /* .locked file is gone: unlocked */
  }
  // Swap the tab of the encrypted file for the readable one.
  for (const g of vscode.window.tabGroups.all) {
    for (const t of g.tabs) {
      if (t.input instanceof vscode.TabInputText && t.input.uri.fsPath === uri.fsPath) await vscode.window.tabGroups.close(t);
    }
  }
  if (wasActive) await vscode.window.showTextDocument(plainUri);
}

// ================================================================= presets & listing

async function choosePresetsCommand() {
  await detectPresets();
  const current = new Set(additive('presets', ['auto']));
  type Item = vscode.QuickPickItem & { id: string };
  const items: Item[] = [
    { id: 'auto', label: 'Auto-detect', description: `detected: ${[...detected].join(', ') || 'nothing'}`, picked: current.has('auto') },
    ...PRESETS.map((p) => ({
      id: p.id,
      label: p.label,
      description: p.always ? 'always on' : detected.has(p.id) ? 'detected' : '',
      detail: p.patterns.join('  '),
      picked: current.has(p.id) || p.id === 'dotenv',
    })),
  ];
  const picked = await vscode.window.showQuickPick(items, {
    canPickMany: true,
    placeHolder: 'Which kinds of secret files should be locked? (custom files: right-click → Env Lock: Protect this file)',
  });
  if (!picked) return;
  // User settings: a project can only add presets, so choosing fewer must happen at user level.
  // Through updateOwnSetting: you chose it here, so it is approved (no "made WEAKER" dialog).
  await updateOwnSetting('presets', picked.map((p) => p.id));
  await autoApplyRules();
  await refreshStatus();
}

async function showProtectedCommand() {
  const { plain, locked, vault } = await findSecretFiles();
  const items: Array<vscode.QuickPickItem & { uri?: vscode.Uri; vault?: boolean }> = [
    ...plain.map((u) => ({ label: `$(unlock) ${rel(u)}`, description: 'unlocked: readable by agents', uri: u })),
    ...locked.map((u) => ({ label: `$(lock) ${rel(u)}`, description: 'locked in place', uri: u })),
  ];
  if (vault.length) {
    items.push({ label: `$(archive) ${vault.length} file(s) in the vault`, description: 'names are encrypted; outside the project', vault: true });
  }
  if (!items.length) return void vscode.window.showInformationMessage('Env Lock: no protected files found.');
  const pick = await vscode.window.showQuickPick(items, { placeHolder: `Patterns: ${activePatterns().join(', ')}` });
  if (pick?.vault) await revealVaultCommand();
  else if (pick?.uri) await vscode.commands.executeCommand('revealInExplorer', pick.uri);
}

/**
 * Copies the keyring and every vault (all encrypted) to a folder you choose, e.g. a USB drive or
 * cloud backup. Without them, locked secrets cannot be recovered, and an agent could delete them.
 */
async function backupCommand() {
  const picked = await vscode.window.showOpenDialog({
    title: 'Back up Env Lock keys and vault to… (outside your projects, ideally removable or cloud storage)',
    canSelectFiles: false,
    canSelectFolders: true,
  });
  if (!picked?.length) return;
  const base = picked[0];
  if (vscode.workspace.getWorkspaceFolder(base)) {
    return void vscode.window.showErrorMessage('Env Lock: choose a folder outside your projects; agents work inside them.');
  }
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const dest = path.join(base.fsPath, `env-lock-backup-${stamp}`);
  await fs.mkdir(dest, { recursive: true });
  const copied: string[] = [];
  for (const [src, name] of [
    [keyringPath(), 'keyring.json'],
    [vaultRoot(), 'vault'],
  ] as const) {
    try {
      await fs.cp(src, path.join(dest, name), { recursive: true, errorOnExist: true });
      copied.push(name);
    } catch (e: any) {
      if (e.code !== 'ENOENT') throw e;
    }
  }
  log.info(`Backup written to ${dest}: ${copied.join(', ')}`);
  const k = await loadKeyring();
  const pick = await vscode.window.showInformationMessage(
    `Env Lock: backed up ${copied.join(' and ') || 'nothing (no keys yet)'} to ${dest}. ` +
      `Everything is encrypted; you still need your passphrase${k && keyringNeedsKeyFile(k) ? ' and key file' : ''} to restore.`,
    'Reveal'
  );
  if (pick) await vscode.commands.executeCommand('revealFileInOS', vscode.Uri.file(dest));
}

async function revealVaultCommand() {
  const folder = vscode.workspace.workspaceFolders?.[0];
  const v = folder ? await folderVault(folder, false).catch(() => undefined) : undefined;
  // A damaged vault (e.g. vault.json rewritten) still has a folder to show: the pinned one.
  const pinned = folder ? records.pins[folder.uri.fsPath] : undefined;
  const dir = v?.dir ?? (pinned ? path.join(vaultRoot(), pinned) : undefined);
  if (!dir) return void vscode.window.showInformationMessage('Env Lock: this project has no vault yet. It is created on the first lock.');
  await vscode.commands.executeCommand('revealFileInOS', vscode.Uri.file(v ? path.join(dir, 'vault.json') : dir));
}

// ================================================================= run with secrets

async function runWithSecretsCommand() {
  // Ask for the command first: the secrets go to that one process only. (They are NOT put in a
  // terminal's environment: VS Code shows every terminal's creation options, env included, to
  // every installed extension.)
  const command = await vscode.window.showInputBox({
    title: 'Env Lock: run with secrets',
    prompt: 'Command to run with your secrets in its environment, e.g. npm run dev. Nothing is written to disk.',
    // From the protected records: an agent editing a pre-filled command could add "& curl attacker…".
    value: records.lastCommand ?? 'npm run dev',
    ignoreFocusOut: true,
  });
  if (!command?.trim()) return;
  const agent = agentIn(command);
  if (agent) {
    log.warn(`Refused to run an AI agent with secrets: ${command}`);
    return void vscode.window.showErrorMessage(`Env Lock: "${agent}" is an AI agent; it will not be given your secrets.`);
  }
  records.lastCommand = command;
  await saveRecords();
  const { plain, locked, vault } = await findSecretFiles();
  const isDotenv = (f: string) => matchesAny(f, DOTENV_PATTERNS);

  let priv: PrivateKeys | undefined;
  const getPriv = async () => {
    if (priv) return priv;
    const k = await loadKeyring();
    if (!k) return void vscode.window.showErrorMessage(`Env Lock: keyring not found at ${keyringPath()}.`);
    priv = (await unlockKeyring(k, 'Passphrase to load secrets into a terminal'))?.priv;
    // The passphrase proved this keyring is yours: pin it (first run / after an upgrade).
    if (priv && (await readTrust())?.keyId !== k.keyId) await writeTrust(k.keyId, undefined, macKeyFromPrivate(priv));
    return priv;
  };

  // Decrypt locked dotenv files up front (vault names are encrypted, so the vault must be opened to
  // know what is in it), and keep only those whose signature shows you locked them.
  const lockedDotenv = locked.filter((u) => isDotenv(u.fsPath.slice(0, -LOCKED.length)));
  const decrypted: Decrypted[] = [];
  const badSig: string[] = [];
  if (vault.length || lockedDotenv.length) {
    if (!(await getPriv())) return;
    try {
      const macKey = await signingKeys(priv!);
      for (const u of lockedDotenv) {
        const text = await fs.readFile(u.fsPath, 'utf8');
        decrypted.push({
          target: u.fsPath.slice(0, -LOCKED.length),
          data: decryptFile(text, priv!),
          remove: u.fsPath,
          label: rel(u),
          bind: inPlaceBinding(u.fsPath.slice(0, -LOCKED.length)),
          sign: verifyLocked(text, macKey, inPlaceBinding(u.fsPath.slice(0, -LOCKED.length))),
        });
      }
      decrypted.push(...(await readVault(vault, priv!, [], [])));
    } catch (e: any) {
      return void vscode.window.showErrorMessage(`Env Lock: ${e.message ?? e}`);
    }
  }
  const trusted = await checkSignatures(
    decrypted.filter((e) => isDotenv(e.target)),
    badSig
  );
  if (badSig.length) {
    vscode.window.showErrorMessage(`Env Lock: ⚠ not loaded, signature invalid (possibly planted): ${badSig.join(', ')}.`);
  }

  type Entry = { file: string; data?: Buffer };
  const entries: Entry[] = [
    ...plain.filter((u) => isDotenv(u.fsPath)).map((u) => ({ file: u.fsPath })),
    // A readable copy on disk is newer than its locked copy.
    ...trusted
      .filter((e) => !plain.some((u) => u.fsPath.toLowerCase() === e.target.toLowerCase()))
      .map((e) => ({ file: e.target, data: e.data })),
  ];
  if (!entries.length) return void vscode.window.showInformationMessage('Env Lock: no dotenv files found.');

  const dirs = [...new Set(entries.map((e) => path.dirname(e.file)))];
  let dir = dirs[0];
  if (dirs.length > 1) {
    const pick = await vscode.window.showQuickPick(
      dirs.map((d) => ({ label: vscode.workspace.asRelativePath(d) || d, dir: d })),
      { placeHolder: 'Load secrets from which folder?' }
    );
    if (!pick) return;
    dir = pick.dir;
  }
  const inDir = entries.filter((e) => path.dirname(e.file) === dir);
  const names = inDir.map((e) => path.basename(e.file));
  const modes = dotenvModes(names);
  let mode: string | undefined;
  if (modes.length) {
    // Never mix .env.production (or any other environment) into a run unless you choose it.
    const pick = await vscode.window.showQuickPick(
      [
        { label: 'No environment', description: dotenvPlan(names).join(' → ') || '(none)', mode: undefined as string | undefined },
        ...modes.map((m) => ({ label: m, description: dotenvPlan(names, m).join(' → '), mode: m as string | undefined })),
      ],
      { placeHolder: 'Which environment? .env.<name> files are only loaded when you choose that environment.' }
    );
    if (!pick) return;
    mode = pick.mode;
  }
  const chosen = dotenvPlan(names, mode).map((n) => inDir.find((e) => path.basename(e.file) === n)!);
  if (!chosen.length) return void vscode.window.showInformationMessage('Env Lock: no dotenv files for that choice.');

  const files: ParsedEnv[] = [];
  try {
    for (const e of chosen) {
      const buf = e.data ?? (await fs.readFile(e.file));
      files.push({ file: e.file, vars: parseDotenv(buf.toString('utf8')) });
    }
  } catch (e: any) {
    return void vscode.window.showErrorMessage(`Env Lock: ${e.message ?? e}`);
  } finally {
    for (const e of decrypted) e.data.fill(0); // best effort: only the terminal keeps the values
    wipePrivate(priv);
  }

  const env = await reviewDotenvValues(files);
  if (!env) return;
  if (!(await reviewRunFiles(dir, command))) return;
  runWithSecretEnv(command, dir, env);
}

// ----------------------------------------------------------------- what "Run with secrets" trusts
//
// A signature shows Env Lock locked a file, not that YOU wrote it: an agent can write .env.local
// (plaintext, or auto-locked and signed later) with API_URL=https://attacker… while your real
// API_KEY comes from the vault, or NODE_OPTIONS=--require ./x.js to run code inside your app.
// So every value is compared with the values you approved on your last run.

interface ParsedEnv {
  file: string;
  vars: Record<string, string>;
}

/** Variables that change how programs start or load code, rather than holding a secret. */
const PROCESS_CONTROL_KEYS = new RegExp(
  '^(' +
    [
      // load or run other code
      'NODE_OPTIONS|NODE_PATH|PATH|PATHEXT|COMSPEC|LD_PRELOAD|LD_LIBRARY_PATH|DYLD_.*|PYTHONSTARTUP|PYTHONPATH|PYTHONHOME',
      'PERL5OPT|PERL5LIB|RUBYOPT|RUBYLIB|BASH_ENV|ENV|PROMPT_COMMAND|GIT_SSH_COMMAND|GIT_EXEC_PATH|JAVA_TOOL_OPTIONS',
      '_JAVA_OPTIONS|JDK_JAVA_OPTIONS|DOTNET_STARTUP_HOOKS|NPM_CONFIG_.*|ELECTRON_RUN_AS_NODE',
      // route traffic through someone else, or stop checking certificates: your keys travel with the requests
      'HTTPS?_PROXY|ALL_PROXY|NO_PROXY|GLOBAL_AGENT_.*|NODE_TLS_REJECT_UNAUTHORIZED|NODE_EXTRA_CA_CERTS|SSL_CERT_(FILE|DIR)',
      'REQUESTS_CA_BUNDLE|CURL_CA_BUNDLE|PYTHONHTTPSVERIFY|GIT_SSL_NO_VERIFY',
    ].join('|') +
    ')$',
  'i'
);

const fileKey = (f: string) => (process.platform === 'win32' ? f.toLowerCase() : f);

/** Keyed hash of a value (the signing key), so the records never hold a guessable plain hash of a secret. */
async function valueStamp(key: string, value: string): Promise<string> {
  const mac = (await readTrust())?.macKey;
  const h = mac ? createHmac('sha256', mac) : createHash('sha256');
  return h.update(`env-lock-value\0${key}\0${value}`).digest('base64').slice(0, 22);
}

/**
 * Returns the environment to give the process, or undefined if you cancelled. Values that are new
 * or changed since you last approved them are listed first; process-control variables are flagged.
 */
async function reviewDotenvValues(files: ParsedEnv[]): Promise<Record<string, string> | undefined> {
  const seen = records.envSeen ?? {};
  const changes: Array<{ file: string; key: string; isNew: boolean }> = [];
  const stamps: Record<string, Record<string, string>> = {};
  for (const f of files) {
    const before = seen[fileKey(f.file)];
    stamps[fileKey(f.file)] = {};
    for (const [k, v] of Object.entries(f.vars)) {
      const s = await valueStamp(k, v);
      stamps[fileKey(f.file)][k] = s;
      if (before?.[k] !== s) changes.push({ file: f.file, key: k, isNew: !before || !(k in before) });
    }
  }
  let skip = new Set<string>();
  if (changes.length) {
    const firstRun = !Object.keys(seen).length;
    const control = changes.filter((c) => PROCESS_CONTROL_KEYS.test(c.key));
    const byFile = new Map<string, string[]>();
    for (const c of changes) {
      const name = vscode.workspace.asRelativePath(c.file);
      const list = byFile.get(name) ?? [];
      list.push(`${c.key}${c.isNew ? '' : ' (changed)'}`);
      byFile.set(name, list);
    }
    const lines = [...byFile].map(([f, keys]) => `${f}: ${keys.join(', ')}`).join('\n');
    const pick = await vscode.window.showWarningMessage(
      (firstRun
        ? 'Env Lock: first run with secrets. Check that you wrote these values:\n\n'
        : 'Env Lock: these values are NEW or CHANGED since you last ran with secrets. An AI agent could have planted them, ' +
          'e.g. a URL that sends your real keys elsewhere:\n\n') +
        lines +
        (control.length
          ? `\n\n⚠ ${control.map((c) => c.key).join(', ')} change how programs start or where their traffic goes: ` +
            'they can run code inside your app, or send its requests (and your keys) through someone else.'
          : '') +
        '\n\n"Leave them out" keeps them out of this process only: your app may still read the file itself ' +
        '(dotenv, Next.js, Vite…). If you did not write them, delete them from the file.',
      { modal: true },
      'Use them',
      'Leave them out'
    );
    if (!pick) return undefined;
    if (pick === 'Leave them out') skip = new Set(changes.map((c) => `${fileKey(c.file)}\0${c.key}`));
    log.warn(`Run with secrets: ${pick === 'Use them' ? 'approved' : 'left out'} new/changed values: ${lines.replace(/\n/g, '; ')}`);
  }
  const env: Record<string, string> = {};
  const approved: Record<string, Record<string, string>> = {};
  for (const f of files) {
    const fk = fileKey(f.file);
    approved[fk] = { ...seen[fk] };
    for (const [k, v] of Object.entries(f.vars)) {
      if (skip.has(`${fk}\0${k}`)) continue;
      env[k] = v;
      approved[fk][k] = stamps[fk][k];
    }
  }
  records.envSeen = { ...seen, ...approved };
  await saveRecords();
  return env;
}

/** Files in the run folder that decide what a command actually runs. */
const RUN_FILES =
  /^(package\.json|pyproject\.toml|makefile|justfile|taskfile\.ya?ml|composer\.json|gemfile|deno\.jsonc?|bunfig\.toml|\.npmrc|\.yarnrc(\.yml)?|\.pnpmfile\.cjs)$/i; // .npmrc: node-options, script-shell
const RUN_EXECUTABLES = /\.(cmd|bat|com|exe|ps1|sh)$/i;

/**
 * The command runs code from the project, which an agent can edit: a package.json script, or a
 * planted npm.cmd (cmd.exe looks in the current folder before PATH; that lookup is also switched
 * off for the process). Warn when those files changed since your last run.
 */
async function reviewRunFiles(dir: string, command: string): Promise<boolean> {
  let names: string[];
  try {
    names = (await fs.readdir(dir, { withFileTypes: true })).filter((d) => d.isFile()).map((d) => d.name);
  } catch {
    return true;
  }
  const now: Record<string, string> = {};
  for (const n of names.filter((x) => RUN_FILES.test(x) || RUN_EXECUTABLES.test(x))) {
    try {
      now[n] = createHash('sha256').update(await fs.readFile(path.join(dir, n))).digest('hex');
    } catch {
      /* unreadable: ignore */
    }
  }
  const all = records.runFiles ?? {};
  const before = all[fileKey(dir)];
  // First run: the project files are your baseline, but executables next to them are always shown.
  const changed = Object.keys(now).filter((n) => (before ? before[n] !== now[n] : RUN_EXECUTABLES.test(n)));
  if (changed.length) {
    const pick = await vscode.window.showWarningMessage(
      `Env Lock: "${command}" will get your secrets, and these files that decide what it runs are ` +
        `${before ? 'new or changed since your last run' : 'in its folder'}:\n\n${changed.join('\n')}\n\n` +
        'An AI agent could have edited them to send your secrets elsewhere. Run only if you made these changes.',
      { modal: true },
      'Run anyway'
    );
    log.warn(`Run with secrets: ${pick ? 'approved' : 'cancelled'}, changed run files: ${changed.join(', ')}`);
    if (!pick) return false;
  }
  records.runFiles = { ...all, [fileKey(dir)]: now };
  await saveRecords();
  return true;
}


/**
 * Runs `command` with the secrets in ITS environment only, showing its output in a terminal that
 * Env Lock drives (a pseudoterminal). The terminal's creation options, which every extension can
 * read, hold only this object: the secrets stay in a closure and are dropped after spawning.
 */
function runWithSecretEnv(command: string, cwd: string, secretEnv: Record<string, string>) {
  const count = Object.keys(secretEnv).length;
  let pending: Record<string, string> | undefined = secretEnv;
  const write = new vscode.EventEmitter<string>();
  const closed = new vscode.EventEmitter<number | void>();
  let child: ChildProcess | undefined;
  let exited = false;
  const ESC = '\x1b';
  const out = (s: string) => write.fire(s.replace(/\r?\n/g, '\r\n'));
  const stop = () => {
    if (!child?.pid || exited) return;
    if (process.platform === 'win32') execFile('taskkill', ['/pid', String(child.pid), '/T', '/F'], () => undefined);
    else {
      try {
        process.kill(-child.pid, 'SIGTERM'); // the whole process group (dev servers start children)
      } catch {
        child.kill('SIGTERM');
      }
    }
  };
  const pty: vscode.Pseudoterminal = {
    onDidWrite: write.event,
    onDidClose: closed.event,
    open: () => {
      out(`${ESC}[33m[env-lock] ${count} secret(s) given to this process only: ${command}${ESC}[0m\n`);
      try {
        child = spawn(command, {
          cwd,
          shell: true,
          // NoDefaultCurrentDirectoryInExePath: cmd.exe must not run npm.cmd / node.exe… from the
          // project folder before PATH (an agent can plant one; tested). Set last: a .env cannot undo it.
          env: { ...process.env, ...pending, NoDefaultCurrentDirectoryInExePath: '1' },
          windowsHide: true,
          detached: process.platform !== 'win32',
        });
      } finally {
        pending = undefined; // only the child process keeps them now
      }
      child.stdout?.on('data', (d) => out(d.toString()));
      child.stderr?.on('data', (d) => out(d.toString()));
      child.on('error', (e) => out(`${ESC}[31m[env-lock] ${e.message}${ESC}[0m\n`));
      child.on('exit', (code) => {
        exited = true;
        out(`\n${ESC}[33m[env-lock] exited (${code ?? 'killed'}). Press any key to close.${ESC}[0m\n`);
      });
    },
    close: stop,
    handleInput: (data) => {
      if (exited) return closed.fire();
      if (data === '\x03') {
        out('^C\n');
        return stop();
      }
      out(data === '\r' ? '\n' : data); // local echo: there is no tty
      child?.stdin?.write(data.replace(/\r/g, '\n'));
    },
  };
  const term = vscode.window.createTerminal({
    name: `env-lock: ${command}`,
    pty,
    isTransient: true, // never restored after a reload
    iconPath: new vscode.ThemeIcon('key'),
    color: new vscode.ThemeColor('terminal.ansiYellow'),
  });
  secretTerminals.add(term);
  log.info(`Started with ${count} secret(s) in ${vscode.workspace.asRelativePath(cwd)}: ${command}`);
  term.show();
}

// ================================================================= agent rules & detection

/** Writes agent rule files into the workspace only when the user opted in. */
async function autoApplyRules() {
  if (cfg().get<boolean>('autoApplyAgentRules', false)) await applyRules(true);
}

async function applyRules(quiet: boolean) {
  const changed: string[] = [];
  for (const folder of vscode.workspace.workspaceFolders ?? []) {
    if (folder.uri.scheme !== 'file') continue;
    try {
      changed.push(...(await applyAgentRules(folder.uri.fsPath, activePatterns(), allowList())));
    } catch (e: any) {
      vscode.window.showWarningMessage(`Env Lock: ${e.message ?? e}`);
    }
  }
  if (!quiet || changed.length) {
    vscode.window.showInformationMessage(
      changed.length
        ? `Env Lock: updated agent rules: ${changed.map((f) => vscode.workspace.asRelativePath(f)).join(', ')}.`
        : 'Env Lock: agent rules already up to date.'
    );
  }
}

function escapeRe(s: string) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function agentIn(text: string): string | undefined {
  for (const name of secure<string[]>('agentCommands', [])) {
    const re = new RegExp(`(^|[\\s/\\\\"'@])${escapeRe(name)}(\\.exe|\\.cmd|\\.ps1)?($|[\\s"'])`, 'i');
    if (re.test(text)) return name;
  }
  return undefined;
}

async function onAgentDetected(name: string) {
  log.warn(`AI agent detected: ${name}`);
  if (!secure<boolean>('lockWhenAgentStarts', true)) return;
  const { plain } = await findSecretFiles();
  if (plain.length) await lockCommand(`"${name}" started`);
}

// ================================================================= status

// Refreshes never overlap: a request during a running refresh is folded into one more run after it.
let refreshing: Promise<void> | undefined;
let refreshAgain = false;

function refreshStatus(): Promise<void> {
  if (refreshing) {
    refreshAgain = true;
    return refreshing;
  }
  refreshing = (async () => {
    try {
      do {
        refreshAgain = false;
        await doRefreshStatus();
      } while (refreshAgain);
    } finally {
      refreshing = undefined;
    }
  })();
  return refreshing;
}

async function doRefreshStatus() {
  const found = await findSecretFiles();
  const { locked, vault } = found;
  let plain = found.plain;
  // Git-tracked secret files are never locked (see gitTrackedFiles): keep them out of auto-lock,
  // lock-on-close and the tab lock button, and say so in the status tooltip.
  const tracked = await committedSecrets(plain, false); // staged-only files stay lockable (lock unstages them)
  const trackedList = plain.filter((u) => tracked.has(u.fsPath.toLowerCase()));
  plain = plain.filter((u) => !tracked.has(u.fsPath.toLowerCase()));
  knownPlain = plain.map((u) => u.fsPath);
  lockOnClose = secure<boolean>('lockOnClose', true);
  void vscode.commands.executeCommand('setContext', 'envLock.unlocked', plain.length > 0);
  // Drives the lock button in the editor tab bar (`resourcePath in envLock.plainFiles`).
  void vscode.commands.executeCommand('setContext', 'envLock.plainFiles', knownPlain);
  if (!plain.length) clearAutoLock();
  else ensureAutoLock();
  if (!plain.length && !locked.length && !vault.length) {
    statusItem.hide();
    void checkMissing();
    return;
  }
  if (plain.length) {
    statusItem.text = `$(unlock) ${plain.length} secret${plain.length > 1 ? 's' : ''} unlocked`;
    statusItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
    statusItem.tooltip =
      `Readable by AI agents:\n${plain.map(rel).join('\n')}\n\nClick to lock.` +
      (trackedList.length ? `\n\nNot lockable, tracked by git (rotate these secrets):\n${trackedList.map(rel).join('\n')}` : '');
  } else {
    statusItem.text = `$(lock) ${locked.length + vault.length} locked`;
    statusItem.backgroundColor = undefined;
    statusItem.tooltip =
      'Encrypted with ML-KEM-768 + X25519 / AES-256-GCM:\n' +
      [...locked.map(rel), ...(vault.length ? [`${vault.length} file(s) in the vault, outside the project`] : [])].join('\n') +
      '\n\nClick to unlock.';
  }
  statusItem.show();
  void checkMissing();
}

function rebuildWatcher(ctx: vscode.ExtensionContext) {
  watcher?.dispose();
  watcher = vscode.workspace.createFileSystemWatcher(combinedGlob([...activePatterns(), `**/*${LOCKED}`]));
  const debounced = () => {
    if (refreshTimer) clearTimeout(refreshTimer);
    refreshTimer = setTimeout(() => void refreshStatus(), 300);
  };
  watcher.onDidCreate(debounced);
  watcher.onDidDelete(debounced);
  ctx.subscriptions.push(watcher);
}

/**
 * Env Lock ITSELF replaced (same id, other version or files) or removed: the new code would get
 * Env Lock's credential store, including your anti-phishing phrase, so its passphrase prompt would
 * look real. Only the running (real) Env Lock can still warn.
 */
function selfReplaced(details: string) {
  log.error(`Env Lock itself was replaced or removed: ${details}`);
  closeSecretTerminals('Env Lock was replaced');
  void onAgentDetected('Env Lock was replaced');
  void vscode.window.showErrorMessage(
    'Env Lock: Env Lock ITSELF was updated, replaced or removed. If you did not do this, an impostor could ' +
      'show a perfect passphrase prompt (with your phrase) after the next reload: do NOT reload or type your ' +
      'passphrase. Check the installed version and run "npm run hash" (attack test 18) first.',
    { modal: true }
  );
}

// ================================================================= lifecycle

export async function activate(ctx: vscode.ExtensionContext) {
  secrets = ctx.secrets;
  state = ctx.globalState;
  log = vscode.window.createOutputChannel('Env Lock Security', { log: true });
  ctx.subscriptions.push(log);
  // Records first: settings, pins and version history are read from them from here on.
  await loadRecords();
  await reviewSettings('VS Code started (settings.json may have been edited while it was closed)');
  let knownExtensions = new Set(vscode.extensions.all.map((e) => e.id.toLowerCase()));
  const selfStamp = () => {
    const e = vscode.extensions.getExtension(ctx.extension.id);
    return e ? `${e.packageJSON?.version} at ${e.extensionPath}` : 'removed';
  };
  const selfAtStart = selfStamp();
  // Red-team test T21: after `code --install-extension fake.vsix --force`, VS Code keeps reporting
  // the OLD version until a reload, so the check in onDidChange never fires. Watch the disk instead:
  // a new "<publisher>.<name>-*" folder next to ours, or our bundle changed or gone.
  const selfDir = ctx.extension.extensionPath;
  const extRoot = path.dirname(selfDir);
  const prefix = ctx.extension.id.toLowerCase() + '-';
  const mainFile = path.join(selfDir, ctx.extension.packageJSON?.main ?? 'dist/extension.js');
  const siblings = async () =>
    (await fs.readdir(extRoot).catch(() => [] as string[])).filter((n) => n.toLowerCase().startsWith(prefix)).sort().join('|');
  const mainStamp = async () =>
    fs.stat(mainFile).then(
      (s) => `${s.size}:${s.mtimeMs}`,
      () => 'missing'
    );
  const siblingsAtStart = await siblings();
  const mainAtStart = await mainStamp();
  let replacedWarned = false;
  const checkReplaced = async () => {
    if (replacedWarned) return;
    const [sib, main] = [await siblings(), await mainStamp()];
    if (sib === siblingsAtStart && main === mainAtStart) return;
    replacedWarned = true;
    selfReplaced(`folders: ${siblingsAtStart} → ${sib}; bundle: ${mainAtStart} → ${main}`);
  };
  const replacedTimer = setInterval(() => void checkReplaced(), 5000);
  ctx.subscriptions.push({ dispose: () => clearInterval(replacedTimer) });
  // Backstop for anything the watcher misses (e.g. a project's files.watcherExclude).
  const periodic = setInterval(() => void refreshStatus(), 60_000);
  ctx.subscriptions.push({ dispose: () => clearInterval(periodic) });
  statusItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusItem.command = 'envLock.toggle';

  const reg = (id: string, fn: (...a: any[]) => unknown) => vscode.commands.registerCommand(id, fn);
  ctx.subscriptions.push(
    statusItem,
    reg('envLock.setupKeys', setupKeysCommand),
    reg('envLock.changePassphrase', changePassphraseCommand),
    reg('envLock.lock', () => lockCommand()),
    reg('envLock.unlock', () => unlockCommand()),
    reg('envLock.toggle', toggleCommand),
    reg('envLock.runWithSecrets', runWithSecretsCommand),
    reg('envLock.applyAgentRules', () => applyRules(false)),
    reg('envLock.choosePresets', choosePresetsCommand),
    reg('envLock.showProtected', showProtectedCommand),
    reg('envLock.protectFile', protectFileCommand),
    reg('envLock.unprotectFile', unprotectFileCommand),
    reg('envLock.unlockFile', unlockFileCommand),
    reg('envLock.lockFile', lockFileCommand),
    reg('envLock.revealVault', revealVaultCommand),
    reg('envLock.setPhrase', setPhraseCommand),
    reg('envLock.backup', backupCommand),
    reg('envLock.showLog', () => log.show()),
    vscode.window.onDidCloseTerminal((t) => secretTerminals.delete(t)),
    reg('envLock.revealKeyring', () => vscode.commands.executeCommand('revealFileInOS', vscode.Uri.file(keyringPath()))),
    vscode.workspace.onDidChangeConfiguration(async (e) => {
      if (!e.affectsConfiguration('envLock')) return;
      await reviewSettings('settings changed');
      await auditProjectSettings();
      rebuildWatcher(ctx);
      await refreshStatus();
    }),
    vscode.workspace.onDidChangeWorkspaceFolders(async () => {
      await detectPresets();
      rebuildWatcher(ctx);
      await refreshStatus();
    }),
    vscode.window.onDidOpenTerminal((t) => {
      const a = agentIn(t.name);
      if (a) void onAgentDetected(a);
    }),
    vscode.window.onDidStartTerminalShellExecution((e) => {
      const a = agentIn(e.execution.commandLine.value);
      if (!a) return;
      if (secretTerminals.has(e.terminal)) {
        // This terminal holds decrypted secrets in its environment: the agent would inherit them.
        secretTerminals.delete(e.terminal);
        e.terminal.dispose();
        log.warn(`Closed the secrets terminal: "${a}" was started in it`);
        vscode.window.showErrorMessage(
          `Env Lock: closed the secrets terminal because "${a}" was started in it. Agents would inherit every secret in its environment.`
        );
      }
      void onAgentDetected(a);
    }),
    vscode.extensions.onDidChange(() => {
      // Env Lock ITSELF replaced (same id, other version or folder): the new code would get Env Lock's
      // credential store, including your anti-phishing phrase, so its passphrase prompt would look real.
      // An agent can do it with `code --install-extension fake.vsix --force`. The running (real)
      // Env Lock is the only one that can still warn.
      const now = selfStamp();
      if (now !== selfAtStart && !replacedWarned) {
        replacedWarned = true;
        selfReplaced(`${selfAtStart} → ${now}`);
      }
      void checkReplaced();
      // ANY new extension runs in the same process as Env Lock and could read what it decrypts.
      // An agent can install one with a single shell command (code --install-extension).
      const added = vscode.extensions.all.filter((e) => !knownExtensions.has(e.id.toLowerCase()));
      knownExtensions = new Set(vscode.extensions.all.map((e) => e.id.toLowerCase()));
      if (!added.length) return;
      const names = added.map((e) => `${e.packageJSON?.displayName ?? e.id} (${e.id})`).join(', ');
      log.warn(`Extension(s) installed: ${names}`);
      closeSecretTerminals(`extension installed: ${names}`);
      void onAgentDetected(`extension installed: ${names}`);
      void vscode.window.showWarningMessage(
        `Env Lock: new extension(s) installed: ${names}. Extensions share VS Code's process with Env Lock, ` +
          'so secrets were re-locked and secret processes stopped. If you did not install it, uninstall it now.',
        'Show extensions'
      ).then((pick) => pick && vscode.commands.executeCommand('workbench.extensions.action.showInstalledExtensions'));
    }),
    { dispose: clearAutoLock }
  );
  // User-only settings in a project file may not raise a configuration event at all: watch the file.
  const projectSettingsWatcher = vscode.workspace.createFileSystemWatcher('**/.vscode/settings.json');
  for (const ev of [projectSettingsWatcher.onDidCreate, projectSettingsWatcher.onDidChange]) {
    ev(() => void auditProjectSettings());
  }
  ctx.subscriptions.push(projectSettingsWatcher);

  await auditProjectSettings();
  await detectPresets();
  rebuildWatcher(ctx);
  const k = await loadKeyring();
  if (k) await trustedFor(k, false); // only a pinned keyring may be used to lock on close
  await refreshStatus();

  if (knownPlain.length) {
    if (k && secure<boolean>('lockOnStartup', true)) {
      await lockCommand('workspace opened');
    } else if (!k) {
      const pick = await vscode.window.showWarningMessage(
        `Env Lock: ${knownPlain.length} secret file(s) are readable by AI agents. Set up post-quantum keys to lock them.`,
        'Set up keys'
      );
      if (pick && (await setupKeysCommand())) await lockCommand();
    }
  }
}

export async function deactivate() {
  // Locking only needs the public key, so we can always re-lock on close.
  if (!lockOnClose || !cachedPub || !knownPlain.length) return;
  const still: string[] = [];
  for (const p of knownPlain) {
    try {
      await fs.access(p);
      still.push(p);
    } catch {
      /* gone */
    }
  }
  try {
    // cachedPub is only ever set from the pinned keyring. No settings writes during shutdown.
    await lockFiles(still, cachedPub, cachedTrust?.macKey, false);
  } catch {
    /* nothing useful to do during shutdown */
  }
}
