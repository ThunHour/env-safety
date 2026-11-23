# Env Safety red-team report

**Version tested:** 0.7.5 (fixes from every round included) · **Date:** 2026-11-23 · **Tester:** Claude (automated red team)
**Environment:** Windows 11, VS Code 1.147, Node 22 · **Raw results:** [redteam-results.md](redteam-results.md) (generated)

## 1. Summary

Every attack in this report was **run against a real, isolated VS Code**, not only reasoned about, with a scripted user
answering Env Safety's dialogs. 48 attacks run in four VS Code sessions, between which the attacker
also acts while VS Code is closed. They are backed by 43 unit tests and
by fuzzing (random patterns, damaged locked files and keyrings, bit flips).

**Result of the latest run (0.7.5): 48 of 48 attacks defended, 0 failed, 0 errors** (plus 43/43 unit tests).
Round 5 (attacks X1–X8, [§6](#6-round-5-keeping-secrets-readable-after-a-lock-075)) found five more problems, all fixed in 0.7.5.

For round 4 (0.7.4, 40 attacks) it took four runs: the first three each failed on real problems, listed below, which were fixed before the next run.

Running the attacks for real found **six problems that code review had missed**. All are fixed in 0.7.4, and the
same attacks were run again to show the fixes hold:

| # | Problem found by running the attack | Severity | Fixed by |
|---|---|---|---|
| R8 | **"Run with secrets" gave a development run the PRODUCTION keys**: every `.env.*` in the folder was merged, `.env.production` last | High | Only `.env`, `.envrc`, `.env.local` by default; other environments only when you pick one |
| R9 | **A secret can be hidden from Env Safety** with a `.ignore` / `.rgignore` file or `search.exclude`/`files.exclude` in the project: it is never locked | High | Env Safety lists files itself instead of using VS Code's search, which honours those project files |
| R11 | **If Env Safety's credential store is emptied, every one of your files is refused as "forged", with no warning**: the signing key was random and stored only there. An agent can empty it, e.g. by deleting VS Code's state file | High | Signing key derived from your private key (back after your next unlock); a wiped store is reported at startup |
| R10 | **The 0.7.0 fix for "Env Safety replaced by a same-id extension" did not work**: VS Code keeps reporting the old version until a reload | High | Env Safety watches its own install folder on disk |
| R13 | A rewritten `vault.json` salt was only noticed after a restart | Low | `vault.json` is re-checked on every scan |
| R12 | No notice when a project tries to switch Env Safety off: VS Code drops those values before an extension can see them. Protection itself held | Low | Env Safety reads `.vscode/settings.json` itself to tell you |

Also caught by checking the package: a log file of the test run had been packed into `env-lock-0.7.2.vsix`
(local paths, user name). Removed; `*.log` is now excluded. 0.7.1 and 0.7.3–0.7.4 contain only the 4 intended files.

## 2. Scope and attacker

Same attacker as the earlier rounds, and as an AI coding agent really is: it **runs as you**. It can read and
write the project, your home folder, VS Code's settings and state files, run any command (`git`, `code
--install-extension`), and plant files anywhere you can. It does **not** know your passphrase or have your key
file. It wins if it reads a secret, gets your passphrase, makes your app use values it chose, or stops Env Safety
from protecting you without you noticing.

Out of scope (Env Safety's documented limits): reading another process's memory, an extension already installed
before Env Safety started, an OS-level compromise.

## 3. How the attacks were run

`npm run redteam` ([scripts/redteam-vscode.js](../scripts/redteam-vscode.js) +
[test/redteam/runner.js](../test/redteam/runner.js)):

- **Isolated:** its own VS Code profile, extensions folder, project and home folder under `.redteam/`. Env Safety's
  home is redirected (`USERPROFILE`), so even a faulty test cannot touch the real `~/.env-safety`.
- **Real Env Safety code:** the same source, built with one difference: VS Code's dialog functions are routed to
  a scripted user ([test/redteam/vscode-shim.js](../test/redteam/vscode-shim.js)). The shipped bundle is unchanged
  (test T18 checks its hash against the VSIX). The scripted user always answers the **safe** way (cancel) unless a
  test is about what happens when the user is fooled. Every message Env Safety shows is recorded as evidence.
- **Real attacker actions:** files planted and swapped, settings files edited, `git config`, junctions and hard
  links, and real extensions installed with `code --install-extension` (a dummy one, and a fake Env Safety with the
  same id).
- **Four sessions**, with attacks in between while VS Code is closed:
  1. 31 attacks, then quit with secrets unlocked (lock on close);
  2. after restart: settings weakened while closed, vault salt rewritten while running;
  3. a fake Env Safety with the same id installed while running;
  4. after an uninstall + reinstall of Env Safety: is your data still usable, is the reset reported?
- **Limit of the harness:** in this test mode VS Code keeps extension storage in memory, so Env Safety's
  credential store is empty after every restart. Tests across a restart therefore always see a wiped store
  (which is exactly how R11 was found); they cannot show whether an uninstall alone wipes it in a normal VS Code.

## 4. Attack list

Result column: ✅ defended in the final run · 🔧 failed in an earlier run of this round, fixed, then defended ·
🧪 unit test or fuzzing (outside VS Code) · ⚠ not testable automatically (see §7).
ATT&CK = MITRE ATT&CK technique the attack belongs to.

### Getting the secrets

| ID | Attack (what the agent does) | OWASP | CWE | ATT&CK | Result |
|---|---|---|---|---|---|
| T01 | Read `.env` while Env Safety is set up | A04 | 312 | T1552.001 | ✅ nothing readable in project or vault; locking asked for no passphrase |
| T02 | Replace `keyring.json` with its own so the next lock encrypts to it | A08 | 345 | T1565.001 | ✅ "your keyring changed", nothing encrypted; your passphrase does not open its keyring |
| T14 | Wait for the user to unlock, then start in a terminal | A06 | — | T1552.001 | ✅ locked at once when a terminal named `claude` opened or `claude` was typed |
| T16 | Wait for the user to forget to lock again | A04 | — | T1552.001 | ✅ auto-lock after 1 min |
| T26 | Wait for VS Code to close with secrets unlocked | A04 | — | T1552.001 | ✅ nothing readable on disk after exit (checked inside the next session and from outside) |
| T13 | Install an extension (it runs in VS Code's process) while secrets are in use | A08 | 829 | T1176 | ✅ warned without a reload, secret process stopped, files locked |
| T11 | Get itself run with the secrets (`claude`, `node x.js & claude`) | A06 | — | T1552.001 | ✅ refused as an AI agent, no passphrase asked |
| T12 | Read the secrets from a terminal's creation options (visible to every extension) | A04 | 200 | T1552 | ✅ secrets never in terminal options (static check) |
| T15 | Get the user to commit an unlocked secret | A02 | 538 | — | ✅ "not ignored by git" warning, one-click `.gitignore` |
| R4 | Name a hard link `.env.hl` → `~/.ssh/id_rsa`, so Env Safety copies it into the project | A01 | 59 | T1005 | ✅ hard link not locked (never read into the vault) |
| T27 | Turn `config/` into a junction to a synced folder, so unlock writes the secret there | A01 | 59 | T1565 | ✅ refused, nothing written outside; works again with a real folder |
| R9 | **Hide** `.env.hidden` with `.ignore`, `.rgignore`, `search.exclude`, `files.exclude` (T25) | A02 | 693 | T1564 | 🔧 was never locked; ✅ now locked |

### Making your app use the agent's values

| ID | Attack | OWASP | CWE | ATT&CK | Result |
|---|---|---|---|---|---|
| T03a | Plant an unsigned `.env.locked` (`API_URL=https://attacker…`) made with your public key | A08 | 345 | T1565.001 | ✅ "no signature … only if you locked them yourself", not restored |
| T03b | Plant one with a forged signature | A08 | 347 | T1565.001 | ✅ "REFUSED, signature invalid" |
| T04 | Copy the `.env.production` vault blob over `.env`'s | A08 | 345 | T1565.001 | ✅ refused (signature bound to the file) |
| T05 | Put back an older signed version | A08 | 294 | T1565.001 | ✅ "OLDER version than the one you last locked" |
| T19 | Plant a plaintext `.env.local` with `API_URL` and `NODE_OPTIONS` | A06 | 15 | T1574 | ✅ listed as new values, `NODE_OPTIONS` flagged, left out on request |
| T20 | Plant `npm.cmd` so "Run with secrets → npm run dev" runs it | A05 | 427 | T1574.008 | ✅ warned; the real npm ran, the planted one did not |
| R8 | Rely on `.env.production` being merged into a development run (T11) | A04 | 15 | — | 🔧 production key was used; ✅ now only when you choose "production" |

### Switching Env Safety off or blinding it

| ID | Attack | OWASP | CWE | ATT&CK | Result |
|---|---|---|---|---|---|
| T07 | Set `lockOnClose: false`, `allowList: ["**"]`, … in the project's `.vscode/settings.json` | A01 | 15 | T1562.001 | ✅ ignored; 🔧 the notice was missing, ✅ now shown |
| T08 | Edit the user `settings.json` while VS Code runs | A01 | 15 | T1562.001 | ✅ "made protection WEAKER", reverted; stronger values pass |
| T08b | Edit it while VS Code is closed | A01 | 15 | T1562.001 | ✅ same dialog at startup, reverted |
| T24 | Shrink the user presets to `["dotenv"]` | A01 | 15 | T1562.001 | ✅ "made protection WEAKER", reverted |
| T09 | Point `envSafety.vaultId` at an empty vault | A01 | 15 | T1562.001 | ✅ warned, real vault still used |
| T06 | Delete the locked files from the vault | A08 | 404 | T1485 | ✅ "deleted by something other than Env Safety" |
| T29 | Rewrite `vault.json`'s salt | A08 | 345 | T1565.001 | 🔧 only noticed after a restart (R13); ✅ now reported at the next scan, nothing unlocked from it |
| T30 | Empty Env Safety's credential store (signing key, pins, history, phrase) | A08 | 354 | T1070 | 🔧 all files refused, no warning (R11); ✅ now reported, files unlock |
| T21 | Install a fake Env Safety with the same id (`--force`) to inherit its store and show a perfect prompt | A08 | 494 | T1036 | 🔧 not detected (R10); ✅ detected within 5 s |
| T22 | Run Env Safety's commands from another extension: lock any file, protect/unprotect files | A01 | 862 | — | ✅ refused or asked first |
| T28 | Set `core.fsmonitor` in the project's `.git/config` so Env Safety's git calls run a command | A05 | 78 | T1546 | ✅ not run (control: a plain `git status` does run it) |
| T23 | Add catastrophic globs to freeze VS Code (and auto-lock) | A10 | 1333 | T1499.004 | ✅ answered in ms; the unsafe one reported and ignored |
| R2 | Plant a `.locked` file with `"tag": {"length": 2e8}` | A10 | 400 | T1499.004 | ✅ fails fast (was 9 s and 200 MB per field) |
| R3 | Plant a 0.8 MB `.env.local` with an unclosed quote | A10 | 407 | T1499.004 | ✅ under 1 s (was 54 s) |

### Stealing the passphrase

| ID | Attack | OWASP | CWE | ATT&CK | Result |
|---|---|---|---|---|---|
| T10 | Fake passphrase prompt (terminal, or another extension's input box) | A07 | 1021 | T1056.002 | ✅ every real prompt shows your phrase and says Env Safety never asks in a terminal |
| T17 | Offline guessing of a weak passphrase | A07 | 521 | T1110.002 | ✅ weak passphrases refused at setup |
| T21 | Fake Env Safety showing a perfect prompt | A07 | 494 | T1036 | ✅ see above |

### Supply chain and crypto (outside VS Code)

| ID | Attack | OWASP | CWE | Result |
|---|---|---|---|---|
| T18 | Swap the released bundle | A03 | 494 | ✅ VSIX bundle hash = build hash |
| — | Vulnerable dependency | A03 | 1395 | 🧪 `npm audit`: 0 vulnerabilities |
| — | Flip bits in encrypted or authenticated fields | A04 | 353 | 🧪 5,000 flips: 0 decrypted |
| — | Truncated GCM tag, extreme scrypt parameters, damaged keyring/locked file | A04/A10 | 310/400 | 🧪 refused; 3,000 + 2,000 fuzzed inputs, only clean errors |
| — | 20,000 random glob patterns against hostile paths | A10 | 1333 | 🧪 slowest match 1 ms |

## 5. Findings of this round in detail

**R8: production keys in a development run (High, A04).** *Found by T11:* the probe process received
`API_KEY=PRODUCTION-key-999` although `.env` holds `dev-key-111`. "Run with secrets" merged every dotenv file
of the folder, ordered so `.env.production` came after `.env`. A development command could then migrate,
seed or send test traffic against production. *Fix:* [src/dotenv.ts](../src/dotenv.ts) `dotenvPlan`: like
Next.js/Vite, only `.env`, `.envrc`, `.env.local` unless you pick an environment in a quick pick; then
`.env.<env>` and `.env.<env>.local` are added. *Verified:* T11 gets the development key by default and the
production key only when "production" is chosen.

**R9: hiding a secret from Env Safety (High, A02).** *Found by T25:* with `.ignore`, `.rgignore` and
`search.exclude`/`files.exclude` entries for `.env.hidden` in the project, "Lock all" left it readable; once those
were removed it was locked. VS Code's `findFiles` honours these project files, and the same trick could hide a
marker like `*.csproj` and so switch a whole framework's secret files off. *Fix:* [src/scan.ts](../src/scan.ts):
Env Safety walks the folders itself, skipping only your user-level `envSafety.exclude`, never following links, with
limits against huge planted trees (reported if hit). A 60-second re-scan backs up the file watcher.
*Verified:* T25 locks the file; unit test R9.

**R11: an emptied credential store locked you out, silently (High, A08/A10).** *Found by T30 (run 2):* with Env
Lock's credential store empty, unlocking refused **all four** real files as "signature invalid (not made by
your Env Safety; possibly planted)", and nothing said why. The signing key was random and existed only in that
store; the "records were deleted" warning depended on a marker in the same store. The store is VS Code's state
file, which an agent can delete; resets and new profiles empty it too. *Fix:* the signing key is now **derived
from your private key** (`macKeyFromPrivate`, HKDF), so it is restored the moment you unlock with your passphrase
and still cannot be made by an agent; files signed by an older random key are verified with both keys while it
exists. A store that is empty although a keyring exists is reported at startup ("protected records are gone
although you have keys … set your anti-phishing phrase again"); in that state, signatures by a lost random key
are asked about instead of refused. *Verified:* T30 in run 3: reset reported, files unlock normally; unit test R11.

**R10: the same-id replacement check did not fire (High, A08).** *Found by T21:* after
`code --install-extension fake.vsix --force` (version 9.9.9), `vscode.extensions` still reported 0.7.1, so the
0.7.0 check never fired. *Fix:* every 5 seconds Env Safety compares its install folder with the start: a new
`local.env-safety-*` folder next to it, or its bundle changed or gone, means it was replaced or removed. *Verified:*
T21 warns within the test window.

**R12: project settings ignored without a word (Low, A01).** *Found by T07:* VS Code itself drops user-only
settings from a project file, so Env Safety never saw the values it should report. Protection was not affected (T07's
other checks passed). *Fix:* Env Safety also reads `.vscode/settings.json` (comments allowed) and watches it.
*Verified:* T07 shows the notice; unit test.

**R13: vault salt only checked at startup (Low, A08).** *Found by T29:* the salt is cached when the vault is
opened, so a rewrite during a session went unnoticed (data stayed safe: unlock refused every file, but without
saying why). *Fix:* `vault.json` is compared with the cached salt on every scan.

## 6. Round 5: keeping secrets readable after a lock (0.7.5)

The attacker acts **while secrets are unlocked** (which it may: they are readable then) to make them stay
readable after the next lock, for itself later or for another agent.

| ID | Attack | 0.7.4 | Fix in 0.7.5 |
|---|---|---|---|
| X1 | `git add .env`: git-tracked files are never locked | ❌ plaintext stayed, staged for commit | Staged-only secrets are unstaged (`git rm --cached`) and locked; you are told |
| X2 | Hard-link `.env` ↔ `notes.txt` | ❌ not locked, only logged | Visible error naming the other name (`fsutil hardlink list`) |
| X3 | Secret in an NTFS stream `.env:hidden` | ✅ the stream is deleted with the file | — |
| X4 | `.ENV.Local`, `sub/.Env`, nested folders | ✅ locked | — |
| X5 | Copy into `dist/.env`, `build/.env.production` | ❌ never scanned | Build output folders scanned last, with their own budget |
| X6 | Secret still in an editor tab after lock | ✅ dropped | — (API-opened documents: residual, §7) |
| X7 | Rename `.env` → `.env.example` (allow-listed) | ❌ never locked, no warning | Templates holding a real secret value are locked |
| X8 | Paste a key into `src/config.js` | ❌ undetected | After each lock, copies are searched (HMAC fingerprints, no plaintext kept); *Protect and lock* |

Also found while fixing X8: `envSafety.customPatterns` could not be written per folder, so *Protect this file*
failed for unmatched files in single-folder workspaces. Fixed (`resource` scope).

## 7. Not tested automatically, and residual risk

- **Does uninstalling an extension wipe its credential store in a normal VS Code?** The harness cannot tell (its
  storage is in memory). Either way R11's fix covers it: a wipe is reported and your files still unlock.
- **Typed `claude` in a terminal** needs VS Code's shell integration: it started in the test profile, so T14 covered it.
- **Restricted Mode** (untrusted folder): workspace trust was turned off in the test profile; Env Safety declares
  support for untrusted workspaces. Check by hand once.
- **macOS / Linux:** not run. Dangling symlinks need Developer Mode on Windows and were skipped there (R4 notes it).
- **Residual, by design:** while secrets are unlocked an agent can read them; code your command runs
  (`package.json` scripts, `node_modules`) can be changed by an agent (Env Safety shows changes to the files in the
  run folder, not deeper); a link swapped into a parent folder in the microseconds between Env Safety's last check
  and its write; an agent that reads the OS credential store or another process's memory; copies of a secret
  in a changed form (encoded, split); a document another extension opened through the API (kept in memory for
  a few minutes after lock).

## 8. Run history

| Run | Version | Result | What happened |
|---|---|---|---|
| 1 | 0.7.1 | 31 of 36 | Failures T07, T11, T21, T25, T29: findings R8, R9, R10, R12 (T29 then looked like a harness issue); the bundle check (T18) did not run: the script crashed on `tar` at the end |
| 2 | 0.7.2 | 37 of 39 | T07/T11/T21/T25 fixed; T30 found R11 (store wiped → every file refused); T29 still failing |
| 3 | 0.7.3 | 39 of 40 | R11 fixed (T30 passes); T29 traced to the salt being checked only at startup (R13) |
| 4 | 0.7.4 | 39 of 40 | R13 fixed (T29 passes); T14 failed on a timing race **in the test** (it checked for the message before Env Safety showed it; the defence itself worked) |
| 5 | 0.7.4 | **40 of 40** | test race fixed (it now waits for the message) |
| 6 | 0.7.4 | 3 of 8 (X1–X7 only) | X1, X2, X5, X7 failed (findings); X6 failed because the test itself held the document open (test fixed) |
| 7 | 0.7.5-dev | X8 1 of 2 checks | copy found, but *Protect and lock* failed: `customPatterns` scope bug (fixed) |
| 8 | 0.7.5 | 47 of 48 | everything passes except T18: the old 0.7.4 package no longer matched the build (repackaged) |
| 9 | 0.7.5 | **48 of 48** | all attacks defended, run again after installing the 0.7.5 package |

## 9. Reproduce

```
npm install
npm test            # 43 unit tests
npm run redteam     # 48 attacks in an isolated VS Code (~4 min); a window opens: do not click in it
node scripts/redteam-vscode.js --only=X1,X8   # selected attacks only
```

Results go to [docs/redteam-results.md](redteam-results.md); raw JSON and VS Code logs to `.redteam/results/`.
Run it after any change to Env Safety's security code, and before every release.
