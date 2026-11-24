# Env Safety: hide your .env secrets from AI coding agents

**AI coding agents can read every file in your project, including `.env`.** GitHub Copilot agent, Claude Code,
Cursor, Cline, Gemini CLI, Codex and Aider all run as you, so a `.gitignore` or an ignore file does not stop
them from reading your API keys, database passwords and cloud credentials.

**Env Safety encrypts your secret files while agents work**, so there is nothing readable to leak. Your app
still gets its environment variables: run it with secrets in memory, never written to disk.

- 🔒 **Encrypts `.env` and secret files automatically**: when the project opens, when an AI agent starts, after a
  timeout, and when VS Code closes. Locking needs no passphrase.
- 🧠 **Knows every stack**: Node, Python, Django, Rails, Laravel, Spring, .NET, Go, Flutter, Android, iOS,
  Rust, Terraform, Docker and Kubernetes secret files are detected for you.
- ▶️ **Runs your app with secrets in memory** (`npm run dev`, `python manage.py runserver`…): files stay locked.
- 🛡️ **Post-quantum encryption**: ML-KEM-768 (FIPS 203) + X25519, AES-256-GCM, every file signed.
- 🕵️ **Resists hostile agents**: swapped keys, planted or rolled-back files, settings changes and copied
  secrets are detected. 51 automated attacks are run against every release.
- 🚫 **Writes deny rules** for Claude Code, Cursor, Cline, Gemini, Codeium and Aider.
- 🆓 **Free and open source (MIT)**; works offline, sends nothing over the network.

## Quick start

1. **Install** Env Safety from the Extensions view (VS Code Marketplace; Open VSX for Cursor, Windsurf, VSCodium),
   or from a file: `code --install-extension env-safety-<version>.vsix`.
2. Open a project with a `.env` file and run **Env Safety: Set up post-quantum keys** (`Ctrl+Shift+P`):
   choose a passphrase (optionally a key file). Your secret files are locked at once.
3. Run **Env Safety: Set anti-phishing phrase**, then **Env Safety: Back up keys and vault**.
4. Start your app with **Env Safety: Run a command with secrets** (e.g. `npm run dev`): secrets go to that
   process in memory and the files stay locked.

📖 **Full documentation:** [User guide](docs/user-guide.md) · [Changelog](CHANGELOG.md) ·
[Security policy](SECURITY.md) · [Red-team report](docs/redteam-report.md) · [Contributing](CONTRIBUTING.md)

## Why encryption, not "blocking"

An AI agent runs as **your** OS user, just like VS Code. No extension can stop a same-user process from
opening a file. So Env Safety makes sure the **plaintext isn't on disk** while you're not using it.

| Layer | What it does | Stops |
|---|---|---|
| 🔒 **Encrypt at rest** (main protection) | `secret` → `secret.envsafe` (in the vault by default), plaintext deleted | every agent, every route (tool, shell, script) |
| 🪝 **Claude Code hook** | `.claude/hooks/env-guard.js` rejects tool calls touching protected files | accidental reads, `cat .env`, `cat .e*`, `process.env` dumps |
| 📄 **Deny/ignore rules** | `.claude/settings.json` deny, `.cursorignore`, `.clineignore`, `.geminiignore`, `.aiexclude`, `.codeiumignore`, `.aiderignore` | agents indexing/reading secrets |
| 🕘 **Local history off** | `workbench.localHistory.exclude` for every built-in secret file type | VS Code keeping plaintext copies |

## Post-quantum encryption

```
lock (public key only, no passphrase)          unlock (private key)
───────────────────────────────────            ─────────────────────────────
ML-KEM-768 encapsulate  ─┐                     passphrase [+ key file]
X25519 ephemeral DH     ─┼─ X-Wing combiner        └─ scrypt (N=2^17) ─ AES-256-GCM
                         │   (SHA3-256)                 └─ private keys (ML-KEM + X25519)
                         └─ HKDF-SHA256 ─ AES-256-GCM(file, header as AAD)
```

- **Hybrid ML-KEM-768 (FIPS 203) + X25519**: stays secure if *either* algorithm holds, which protects
  against future quantum computers (ML-KEM) and against an undiscovered flaw in the new PQC math (X25519).
- **Fresh encapsulation per file**, so every file has its own key.
- **Locking needs only the public key**, so Env Safety can lock automatically at any time (agent starts,
  startup, timer, window close) without asking you anything.
- **Unlocking** needs your passphrase (and optionally a **key file**, a second factor you can keep on a USB drive).
- ML-KEM comes from [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum); X25519,
  SHA3, HKDF, scrypt and AES-GCM come from Node's built-in OpenSSL.

### Keyring

`~/.env-safety/keyring.json` (outside every project). Holds the public keys and the passphrase-encrypted
private keys. **Back it up.** Without the keyring and your passphrase (and key file, if used), locked files
cannot be recovered. *Env Safety: Reveal keyring* opens its folder.

## Which files? Dynamic, per language

`envSafety.presets` = `["auto"]` (default) locks:

- **always**: dotenv for every framework (`.env`, `.env.*`, `*.env`, direnv `.envrc`) and cloud credentials (`credentials.json`, `service-account*.json`, `.aws/credentials`)
- **detected from marker files**:

| Preset | Detected by | Locks |
|---|---|---|
| node | `package.json` | `.npmrc`, `.yarnrc.yml`, Firebase `.runtimeconfig.json` |
| python (Django, Flask, FastAPI) | `requirements*.txt`, `pyproject.toml`, `Pipfile` | `.pypirc`, `.streamlit/secrets.toml`, `local_settings.py`, `settings/local.py`, Flask `instance/config.py` + `instance/*.cfg`, Dynaconf `.secrets.toml` |
| ruby (Rails) | `Gemfile` | `config/master.key`, `config/credentials/*.key` |
| php (Laravel, Symfony, WordPress) | `composer.json`, `artisan` | `auth.json`, `wp-config.php`, Laravel Passport `storage/oauth-private.key`, Symfony `config/secrets/*/*.decrypt.private.php` |
| java (Spring) | `pom.xml`, `build.gradle` | `application-local.*`, `application-secret*.*` |
| dotnet (ASP.NET) | `*.csproj`, `*.fsproj`, `*.sln` | `appsettings.Development.json`, `appsettings.Local.json`, `secrets.json`, `*.pfx`, publish profiles `*.pubxml.user`, `*.PublishSettings` |
| go | `go.mod` | `.netrc` (private modules), `config.local.{yaml,yml,json,toml}` |
| elixir (Phoenix) | `mix.exs` | `config/*.secret.exs` |
| android | `AndroidManifest.xml` | `local.properties`, `key(store).properties`, `*.jks`, `*.keystore`, `google-services.json` |
| ios | `Podfile`, `*.xcodeproj` | `GoogleService-Info.plist`, `*.p12`, `*.mobileprovision`, `AuthKey_*.p8` |
| flutter | `pubspec.yaml` | `key.properties`, Firebase configs, `*.jks` |
| rust | `Cargo.toml` | `.cargo/credentials(.toml)` |
| terraform | `*.tf` | `*.tfvars`, `terraform.tfstate*`, `.terraformrc` |
| containers | `Dockerfile`, compose, kustomize | `.docker/config.json`, `kubeconfig`, `secret*.yaml` |
| keys *(opt-in)* | – | `*.pem`, `*.key`, `id_rsa`, `id_ed25519`, `*.p12`, `*.pfx` |

Laravel, Symfony, Next.js, NestJS, Express, Flask, FastAPI, Gin/Echo (Go) and Phoenix all read `.env` files,
which are always protected.

- **Pick visually**: *Env Safety: Choose secret file types*.
- **Any other file**: right-click it → **Env Safety: Protect this file** (added to `envSafety.customPatterns`).
- **Exclude one**: right-click → **Stop protecting this file**.
- `*.example`, `*.sample`, `*.template`, `.env.dist` are never locked, **unless** one holds a real value of a
  secret you locked (e.g. `.env` renamed to `.env.example`): then it is locked like a secret and you are told.
- Build output folders (`build`, `dist`, `out`, `target`, `.next`…) are scanned too, last and with their own
  limit, because a build can copy `.env` into them. Third-party folders (`node_modules`, `.git`, `vendor`,
  virtualenvs, `Pods`) are skipped (`envSafety.exclude`).
- **Files git already tracks are never locked**: locking would delete them from git (a deletion that could be
  committed). Env Safety warns instead: the secret is in your git history, so rotate it, run
  `git rm --cached <file>` and add it to `.gitignore`. .NET templates often commit `appsettings.Development.json`.
  A file that is only **staged** (`git add`, never committed) is not in your history yet: Env Safety unstages it
  (`git rm --cached`) and locks it, so an agent cannot `git add .env` to keep it out of every later lock.
- **.NET User Secrets** (`dotnet user-secrets`, stored in `%APPDATA%\Microsoft\UserSecrets\<id>\secrets.json`,
  outside the project) are not covered yet: that file is outside the workspace.

The agent rules and the Claude Code hook are regenerated from the active patterns every time you lock.

## Commands

| Command | |
|---|---|
| **Set up post-quantum keys** | one time: generate ML-KEM-768 + X25519 keys, choose passphrase (+ key file) |
| **Lock all secret files** | encrypt everything matched (no passphrase needed) |
| **Unlock all secret files** | asks first (offers the in-memory terminal instead) → passphrase → restore plaintext → auto-relock after 5 min |
| **Unlock this file** (right-click `.envsafe`) | unlock just one file |
| **Run a command with secrets** | e.g. `npm run dev`: decrypts dotenv files **in memory** and gives them to that one process only; its output shows in a terminal; files stay locked |
| **Choose secret file types** / **Show protected files** | presets / list what's matched |
| **Change passphrase / key file** | re-protect the private key; locked files stay valid |
| **Set anti-phishing phrase** | a personal phrase shown in every real passphrase prompt |
| **Back up keys and vault** | copy the (encrypted) keyring and vaults to a folder outside your projects |
| **Show security log** | keyring changes, refused files, ignored settings, detected agents |
| **Reveal this project's vault folder** | open `~/.env-safety/vault/<id>/` |
| **Write AI agent deny rules** | regenerate hook + ignore files (optional) |

Status bar: `🔒 3 locked` / `🔓 2 secrets unlocked` (yellow). Click to toggle.

**Automatic locking** (no prompt needed, thanks to public-key locking):
on workspace open, when `claude` / `codex` / `gemini` / `aider`… starts in a VS Code terminal,
N minutes after secrets become readable, and when the window closes.

## Honest limits

- **While unlocked, nothing protects you.** Keep unlock windows short; prefer *Run a command with secrets*.
- An agent that can run code **inside** a process holding the secrets (your running dev server) can print
  them, and a process running as you can read another process's memory. Env Safety refuses to give secrets
  to known AI agents, but it cannot stop a program you run from passing them on.
- If Env Safety's protected records are deleted together with its pinned key, it starts over: it asks for
  your passphrase again and re-pins the vault from the project's `envSafety.vaultId`, and the version history
  (rollback protection) starts empty. Settings always restart from the secure defaults.
- The hook and ignore files are soft guards; a determined agent can bypass them. The encryption is what
  actually protects you.
- Agent detection sees agents started in **VS Code terminals** with shell integration, and known AI
  **extensions** (installing one re-locks). Unknown tools are covered by lock-on-startup and the timer only.
- The keyring's private key is only as strong as your passphrase. New passphrases must pass a strength
  check; a few random words, or a key file on removable media, is best.
- **The command you run with secrets runs project code** (`package.json` scripts, your app), which an
  agent can edit. Env Safety shows you what changed since your last run, but read it before you approve.
- Detection is best-effort: `c^laude`, aliases or wrapper scripts get past the agent-name check; killing
  VS Code skips lock-on-close and the timer. The encryption holds; only the unlocked window is exposed.
- If secrets were ever read before, they may be in agent transcripts, git history or local history
  (`%APPDATA%\Code\User\History`: delete entries for secret files edited before Env Safety 0.7.0), or in
  your cloud sync's version history if the project is in OneDrive/Dropbox. **Rotate them.**
- Deleting a file on an SSD doesn't guarantee the old bytes are physically erased.
- **Copies** are found only for values that look like secrets (12+ characters, letters with digits or mixed
  case, URLs only with `user:password@`), in text files up to 64 KB (5,000 files per lock). A copy that was
  changed (encoded, split, reversed) is not recognised. A value staged with `git add` stays in `.git/objects`
  until `git gc --prune=now`.
- A document **another extension** opened through the VS Code API stays in that extension host's memory for
  a few minutes after lock, whatever Env Safety does (that extension could read it while it was unlocked anyway).
- `@noble/post-quantum` is a young library; ML-KEM is new. That's why X25519 is combined with it.

## Security model

An AI agent runs **as you**: it can read and write anything your Windows account can. Env Safety assumes the
agent may be hostile, and defends like this:

| Attack | Defence |
|---|---|
| Read `.env` | Encrypted with ML-KEM-768 + X25519; in vault mode it is not even in the project |
| Swap `keyring.json` so the next lock encrypts to the agent's key | Your key id is pinned in the OS credential store (VS Code SecretStorage); locking refuses any other keyring |
| Plant a fake locked file (e.g. `API_URL=https://attacker…`) using your public key | Every locked file is signed (HMAC, key in the credential store); invalid → refused, unsigned → asks you |
| Rename `.env.production.envsafe` → `.env.envsafe`, or copy blobs between vaults | Signatures are bound to the file's path and vault id |
| Put back an old signed version (rollback) | The newest version of each file is recorded outside the project; older ones need your consent |
| Delete locked files | Detected and reported; the vault keeps `.prev` copies; **Back up keys and vault** |
| Edit `.vscode/settings.json` to switch protection off | Security settings are read from **user** settings only; a project can only *add* patterns; ignored values are reported |
| Edit the **user** `settings.json` (also a plain file) | Env Safety uses the settings you **approved**, kept in the credential store; a weakening change is shown to you and reverted unless you confirm it |
| Edit Env Safety's records (vault pins, version history, exceptions) | Kept in the credential store, not in VS Code's plain state file; deleting them is reported |
| Change `envSafety.vaultId` to redirect the vault | The first id is pinned; a change is reported and ignored until you accept it |
| Fake passphrase prompt in a terminal | Env Safety only asks in a VS Code input box, which shows **your anti-phishing phrase** |
| Read the secrets from a terminal's settings (VS Code shows every terminal's creation options, env included, to every extension) | Secrets are never put in a terminal's options: **Run a command with secrets** gives them to one process directly |
| Run an AI agent with your secrets | Commands that are AI agents are refused |
| Install an extension with `code --install-extension` | Any new extension triggers a re-lock, stops secret processes and warns you |
| Replace Env Safety itself (`code --install-extension fake-env-safety.vsix --force`) to inherit its credential store and show a perfect prompt | The running Env Safety notices it was replaced, re-locks, stops secret processes and tells you not to reload or type your passphrase |
| Plant `.env.local` with `API_URL=https://attacker…` or `NODE_OPTIONS=…` (plaintext, or auto-locked and signed later) | **Run a command with secrets** lists every value that is new or changed since you last approved it and flags process-control variables; you can leave them out |
| Plant `npm.cmd` in the project (cmd.exe runs it before the real npm) | The process runs with `NoDefaultCurrentDirectoryInExePath=1`; changed `package.json` / scripts / executables in the run folder are shown before it starts |
| Set `core.fsmonitor` in `.git/config` so Env Safety's git calls run a command | Env Safety runs git with `-c core.fsmonitor=false` |
| Turn a folder into a junction / `.env` into a symlink so unlock writes outside the project | Unlock resolves links and refuses targets outside the project; locking skips links |
| Call `envSafety.lockFile` from another extension on any file | Lock / unlock accept only files Env Safety lists as protected in this workspace; *Protect this file* asks first |
| Add a catastrophic glob (`**/**/**/…`) to freeze VS Code and stop auto-lock | Repeated globstars are collapsed; patterns too complex to match safely are ignored and reported |
| Rewrite `vault.json` (salt) or the keyring's KDF cost | The vault salt is pinned and re-checked on every scan; KDF parameters are capped |
| While unlocked, `git add .env` so every later lock skips it (git-tracked files are never locked) | A file staged but never committed is unstaged and locked, and you are told |
| While unlocked, rename `.env` to `.env.example` (allow-listed) or copy it into `dist/` | Templates holding a real secret value are locked like secrets; build folders are scanned |
| While unlocked, hard-link `.env` to `notes.txt` (Env Safety never encrypts a linked file) | You are told the file is NOT locked and has another name on disk |
| While unlocked, paste a key into `src/config.js` | After each lock Env Safety looks for copies of the locked values (keyed hashes, no plaintext kept) and offers *Protect and lock* |
| Hide a secret file with a project `.ignore` / `.rgignore` / `search.exclude` / `files.exclude` | Env Safety lists files itself (only your user-level `envSafety.exclude` applies), not through VS Code's search |
| Empty Env Safety's credential store (delete VS Code's state file, reset, reinstall) so your files look forged | The signing key is derived from your private key and comes back at your next unlock; the wipe is reported at startup |
| Count on `.env.production` being mixed into a development run | *Run with secrets* loads `.env`, `.envrc`, `.env.local` only, unless you pick an environment |

What Env Safety **cannot** stop, and what to do instead:

- **Another extension in the same VS Code window.** VS Code runs all extensions in one process, so a
  malicious or compromised extension (AI ones included) could in principle read what Env Safety decrypts or
  what you type. Install few extensions, from publishers you trust. For the strongest separation, use a
  separate [VS Code profile](https://code.visualstudio.com/docs/editor/profiles) for AI extensions, and
  open your secrets work in a profile without them.
- **Changes to Env Safety's own code.** Installed extensions live in `~/.vscode/extensions/`, writable by
  anything running as you. A self-check would be useless (whoever edits the code deletes the check), so
  verify from **outside** VS Code, now and then and after any suspicion, that the installed bundle matches
  the one you built or downloaded:

  ```powershell
  # the hash of the build you trust (run in this repo after `npm run build`, or published with a release)
  npm run hash
  # the installed copy
  Get-FileHash "$env:USERPROFILE\.vscode\extensions\*.env-safety-*\dist\extension.js" -Algorithm SHA256
  ```

  Publishing to the Marketplace adds VS Code's own signature check at install time.
- **Agents running as you, with determination.** They can, in theory, also read the OS credential store.
  The only hard boundary is the operating system: run agents in a dev container, WSL, or a separate
  Windows account that cannot open `~/.env-safety`.

## Develop

```powershell
npm install
npm test          # tsc + esbuild bundle + 46 unit tests (PQC crypto, signing, vault, policy, patterns, scan, copies, migration, agent rules, hook)
npm run redteam   # 51 attacks run unattended in an isolated VS Code (~4 min) -> docs/redteam-results.md
node scripts/redteam-vscode.js --only=X1,X8   # selected attacks only
npm run audit     # known vulnerabilities + registry signatures of dependencies
npm run hash      # SHA-256 of dist/extension.js, to verify an installed copy
npm run attack    # attack simulator for the manual security tests in docs/attack-tests.md
```

Before trusting a build with real secrets, run `npm run redteam` (in the source repository; a VS Code window opens,
do not click in it). The attacks, method and findings are in `docs/redteam-report.md`.

Press **F5** to launch an Extension Development Host. Package with `npx @vscode/vsce package`.
See [CONTRIBUTING.md](CONTRIBUTING.md) for the project layout and the rules for changes.

## Author

Created by **Seak Kimhour**. Released under the [MIT License](LICENSE).
