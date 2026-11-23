# Env Lock user guide

Env Lock keeps your secret files (`.env`, cloud credentials, keystores, `master.key`, `*.tfvars`…) encrypted
while AI coding agents work in your project. This guide covers everything from installation to recovery.
For the threat model and the attacks Env Lock was tested against, see the [README](../README.md#security-model)
and the [red-team report](redteam-report.md).

- [1. How it works](#1-how-it-works)
- [2. Install](#2-install)
- [3. First-time setup](#3-first-time-setup)
- [4. Everyday use](#4-everyday-use)
- [5. Which files are protected](#5-which-files-are-protected)
- [6. Where locked files are kept](#6-where-locked-files-are-kept)
- [7. Working with AI agents](#7-working-with-ai-agents)
- [8. Warnings and what to do](#8-warnings-and-what-to-do)
- [9. Backup, recovery and a new computer](#9-backup-recovery-and-a-new-computer)
- [10. Commands](#10-commands)
- [11. Settings](#11-settings)
- [12. Troubleshooting and FAQ](#12-troubleshooting-and-faq)
- [13. Uninstall](#13-uninstall)

---

## 1. How it works

An AI agent (Claude Code, Copilot agent, Cursor, Cline, Gemini CLI, Codex, Aider…) runs as **your** user
account. No extension can stop a process running as you from opening a file. So Env Lock does not try to
"block" agents: it makes sure the **plaintext of your secrets is not on disk** while you are not using it.

```
 .env (plaintext)  ──lock──►  encrypted copy in ~/.env-lock/vault/<project-id>/   (plaintext deleted)
                   ◄─unlock─  needs your passphrase (and key file, if you set one)
```

- **Locking needs no passphrase.** It uses your public key only, so Env Lock locks automatically: when the
  workspace opens, when an AI agent starts in a terminal, a few minutes after you unlock, and when VS Code closes.
- **Unlocking needs your passphrase.** Better still, **Run a command with secrets** gives the secrets to one
  process (e.g. `npm run dev`) in memory, without writing them to disk at all.
- **Encryption:** hybrid post-quantum ML-KEM-768 (FIPS 203) + X25519, combined with SHA3-256, then
  HKDF-SHA256 and AES-256-GCM. Every file gets its own key and is signed, so planted, swapped or older
  files are detected.

## 2. Install

**Requirements:** VS Code 1.93 or newer (or a VS Code–based editor: Cursor, Windsurf, VSCodium…), on
Windows, macOS or Linux. The project must be a local folder (remote/virtual workspaces are not supported).

| Editor | How |
|---|---|
| VS Code | Extensions view (`Ctrl+Shift+X`) → search **Env Lock** → Install |
| Cursor, Windsurf, VSCodium | Same, from Open VSX |
| From a file | Extensions view → `…` menu → **Install from VSIX…** → pick `env-lock-<version>.vsix`, or `code --install-extension env-lock-<version>.vsix` |

To check that an installed copy has not been tampered with, see
[Verify the installed bundle](../README.md#security-model) in the README.

## 3. First-time setup

Open a project that contains a secret file (e.g. `.env`). Env Lock offers to set up keys; or run
**Env Lock: Set up post-quantum keys** from the Command Palette (`Ctrl+Shift+P`).

1. **Choose a passphrase.** It protects your private key. It must pass a strength check: a few random words
   (e.g. `copper lantern violet orbit`) work well. There is **no recovery** if you forget it.
2. **Optional: a key file** (second factor). Env Lock can create one; keep it outside your projects,
   ideally on a USB drive. Unlocking then needs both the passphrase and the file.
3. **Set your anti-phishing phrase** (*Env Lock: Set anti-phishing phrase*). Every real Env Lock passphrase
   prompt shows it. A prompt without your phrase, or any passphrase request in a terminal, is fake.
4. **Back up** (*Env Lock: Back up keys and vault*) to a folder outside your projects. Without your keyring
   and passphrase, locked files cannot be recovered.

Your keys are stored in `~/.env-lock/keyring.json` (public keys + passphrase-encrypted private keys).

## 4. Everyday use

### The status bar

| Shows | Meaning | Click to |
|---|---|---|
| 🔒 `3 locked` | All secrets encrypted | Unlock |
| 🔓 `2 secrets unlocked` (yellow) | Readable by AI agents right now | Lock |

The tooltip lists the files. Files you cannot lock (tracked by git) are listed separately.

### Run your app: *Run a command with secrets* (recommended)

1. Command Palette → **Env Lock: Run a command with secrets (in memory)**.
2. Type the command, e.g. `npm run dev`, `python manage.py runserver`, `dotnet run`.
3. Enter your passphrase (check your anti-phishing phrase first).
4. If dotenv values are **new or changed** since you last approved them, Env Lock lists them, and flags
   process-control variables (`NODE_OPTIONS`, `PATH`…). Check that you put them there yourself.
5. The process gets the secrets as environment variables. Its output appears in a VS Code terminal.
   **Nothing is written to disk**; files stay locked.

By default `.env`, `.envrc` and `.env.local` are loaded. Other environments (`.env.production`…) only when
you pick one. Commands that are AI agents (`claude`, `codex`…) are refused.

### Unlock to disk (when you must edit a secret)

1. **Env Lock: Unlock all secret files** (or right-click a locked file → **Unlock this file**).
2. Confirm: Env Lock lists installed AI extensions and offers the in-memory option instead.
3. Enter your passphrase. Files are restored to their places.
4. Edit, then lock again (status bar, or **Lock all secret files**). Env Lock also re-locks automatically
   after `envLock.autoLockMinutes` (default 5).

### Automatic locking

| When | Setting |
|---|---|
| The workspace opens | `envLock.lockOnStartup` |
| An AI agent starts in a VS Code terminal | `envLock.lockWhenAgentStarts`, `envLock.agentCommands` |
| An extension is installed | always |
| N minutes after secrets became readable | `envLock.autoLockMinutes` |
| The VS Code window closes | `envLock.lockOnClose` |

## 5. Which files are protected

`envLock.presets` = `["auto"]` (default) protects dotenv files and cloud credentials always, and adds
the secret files of every language it detects (Node, Python, Ruby, PHP, Java, .NET, Go, Elixir, Android,
iOS, Flutter, Rust, Terraform, containers). The full list is in the [README](../README.md#which-files-dynamic-per-language).

- **Pick visually:** *Env Lock: Choose secret file types*.
- **See what is matched:** *Env Lock: Show protected files*.
- **Protect any file:** right-click → **Env Lock: Protect this file** (added to `envLock.customPatterns`).
- **Stop protecting one:** right-click → **Stop protecting this file**. Kept in your own records, so a
  project or an agent cannot do this for you.
- **Templates** (`*.example`, `*.sample`, `*.template`, `.env.dist`) are never locked, **unless** one holds
  a real value of a secret you locked (e.g. `.env` renamed to `.env.example`): then it is locked and you are told.
- **Build output folders** (`build`, `dist`, `out`, `target`, `.next`…) are scanned too, because a build
  can copy `.env` into them. Third-party folders (`node_modules`, `.git`, `vendor`, virtualenvs) are skipped.
- **Files git tracks are never locked**: locking would delete them from git. Env Lock warns you instead;
  the secret is in your git history, so **rotate it**, run `git rm --cached <file>`, and add it to
  `.gitignore`. A file that is only *staged* (`git add`, never committed) is unstaged and locked.
- **Links are never locked.** A secret file that is a symbolic link or has a second name (a hard link) stays
  readable, and Env Lock tells you so, with the other name. Delete the extra name and lock again.

A project can **add** protected files and types in its `.vscode/settings.json`, never remove them.

## 6. Where locked files are kept

`envLock.storage`:

- **`vault`** (default): locked files move **out of the project** to `~/.env-lock/vault/<vaultId>/`. Blob names
  are hashes; even the file names are encrypted. The project only stores `envLock.vaultId` in
  `.vscode/settings.json` (safe to commit). *Env Lock: Reveal this project's vault folder* opens it.
- **`inPlace`**: `secret` becomes `secret.locked` next to the original.

The vault keeps the previous version of each file as `<blob>.prev`.

## 7. Working with AI agents

Env Lock's protection does not depend on the agent cooperating: locked files are encrypted. These extra
layers reduce accidents while files are unlocked:

- **Agent detection:** a terminal named, or running, a command from `envLock.agentCommands` triggers an
  immediate lock. AI **extensions** (`envLock.agentExtensions`) cannot be seen in terminals: unlocking warns
  about them, and installing a new extension re-locks.
- **Deny / ignore rules** (*Env Lock: Write AI agent deny rules*, or `envLock.autoApplyAgentRules`):
  `.claude/settings.json` deny rules + a Claude Code hook, `.cursorignore`, `.clineignore`, `.geminiignore`,
  `.aiexclude`, `.codeiumignore`, `.aiderignore`. They are soft guards: a determined agent can bypass them.
- **Copy detection:** after each lock, Env Lock looks for copies of the locked values in other files
  (`notes.txt`, `src/config.js`…) and offers **Protect and lock**. It keeps only keyed hashes of the values.

**Strongest setup:** use a separate [VS Code profile](https://code.visualstudio.com/docs/editor/profiles)
without AI extensions for secret work, or run agents in a dev container / WSL / another OS account that
cannot read `~/.env-lock`.

## 8. Warnings and what to do

| Env Lock says | What happened | Do this |
|---|---|---|
| *your keyring changed* | `keyring.json` differs from the one you set up (maybe swapped by an agent) | Restore your keyring from backup. Nothing was encrypted to the other key |
| *signature invalid … possibly planted* | A locked file was not made by your Env Lock, or was renamed/swapped | Keep it refused. Rotate that secret if you did not cause it |
| *no signature … only use them if you locked them yourself* | Unsigned locked file (older Env Lock, or planted with your public key) | Accept only if you locked it |
| *OLDER version than the one you last locked* | Possible rollback | Refuse unless you restored a backup on purpose |
| *deleted by something other than Env Lock* | Locked files disappeared | Restore from backup; the vault may hold `.prev` copies |
| *not locked because git tracks them* | The secret is in git history | Rotate it, `git rm --cached <file>`, add to `.gitignore` |
| *had been staged for commit … unstaged it and locked it* | Something ran `git add` on a secret | Check `.gitignore`; run `git gc --prune=now` to drop the staged copy |
| *NOT locked, still readable … same file as: X* | A hard link or symlink | Delete the other name, lock again, rotate if you did not make it |
| *copies of locked secret values are still readable in: X* | A secret value was copied into a normal file | **Protect and lock**, or remove the value and rotate the secret |
| *is a template … but holds a real value* | A template contains a real secret | It is locked; replace the values with placeholders after unlocking |
| *link leading outside the project* | A folder became a junction/symlink | Remove the link; unlock again |
| *Env Lock ITSELF was updated, replaced or removed* | Someone replaced the extension | **Do not type your passphrase**; check your extensions; verify the bundle hash |
| *protected records are gone although you have keys* | Env Lock was reinstalled or its store wiped | Set your anti-phishing phrase again before typing your passphrase |
| *ignored … project settings* | A project tried to weaken Env Lock | Nothing; it was ignored. Check who changed `.vscode/settings.json` |

All events are in **Env Lock: Show security log**.

## 9. Backup, recovery and a new computer

- **Back up:** *Env Lock: Back up keys and vault* copies the (encrypted) keyring and vaults to a folder you
  choose outside your projects. Do this after setup and from time to time. A key file, if used, must be
  backed up separately.
- **Change passphrase or key file:** *Env Lock: Change passphrase / key file*. Locked files stay valid.
- **New computer:** install Env Lock, copy `keyring.json` to `~/.env-lock/` and the vault folders to
  `~/.env-lock/vault/`, open the project (its `.vscode/settings.json` holds the vault id) and unlock with
  your passphrase. The first unlock pins this keyring as yours.
- **Lost passphrase or keyring:** the files cannot be decrypted, by design. Re-create the secrets from
  their source (cloud console, password manager) and run setup again.

## 10. Commands

| Command | What it does |
|---|---|
| Env Lock: Set up post-quantum keys | One time: generate keys, choose passphrase (+ key file) |
| Env Lock: Lock all secret files | Encrypt everything matched (no passphrase) |
| Env Lock: Unlock all secret files | Passphrase → restore plaintext → auto-lock later |
| Env Lock: Toggle lock | Lock if anything is readable, otherwise unlock (status bar click) |
| Env Lock: Run a command with secrets (in memory) | Run one process with secrets in its environment; files stay locked |
| Env Lock: Choose secret file types (languages) | Pick presets |
| Env Lock: Show protected files | List what is matched, locked and readable |
| Env Lock: Protect this file / Stop protecting this file | Explorer right-click |
| Env Lock: Lock this file / Unlock this file | Explorer or editor tab |
| Env Lock: Change passphrase / key file | Re-protect the private key |
| Env Lock: Set anti-phishing phrase | Phrase shown in every real passphrase prompt |
| Env Lock: Back up keys and vault | Copy keyring and vaults outside your projects |
| Env Lock: Reveal keyring (for backup) | Open the keyring's folder |
| Env Lock: Reveal this project's vault folder | Open `~/.env-lock/vault/<id>/` |
| Env Lock: Write AI agent deny rules | Write hook + ignore files into the project |
| Env Lock: Show security log | Keyring changes, refused files, ignored settings, detected agents |

## 11. Settings

Settings marked **user only** are read from your User settings (and only as you approved them); a
project's `.vscode/settings.json`, which an agent can edit, cannot change them.

| Setting | Default | Scope | Description |
|---|---|---|---|
| `envLock.presets` | `["auto"]` | add-only | Secret file types to lock. A project may add, never remove |
| `envLock.customPatterns` | `[]` | add-only | Extra globs to lock, e.g. `config/secrets.yml` |
| `envLock.allowList` | templates | user only | Globs never locked (unless they hold a real secret value) |
| `envLock.exclude` | `**/{node_modules,.git,vendor,.venv,venv,Pods}/**` | user only | Folders skipped when scanning |
| `envLock.storage` | `vault` | user only | `vault` (outside the project) or `inPlace` (`<file>.locked`) |
| `envLock.vaultPath` | `~/.env-lock/vault` | machine | Folder of all vaults |
| `envLock.vaultId` | set on first lock | project | This project's vault id; safe to commit; pinned on first use |
| `envLock.keyringPath` | `~/.env-lock/keyring.json` | machine | Keyring location |
| `envLock.keyFile` | none | machine | Optional key file (second factor) |
| `envLock.autoLockMinutes` | `5` | user only | Re-lock N minutes after unlocking; `0` disables |
| `envLock.confirmUnlockToDisk` | `true` | user only | Ask before unlocking to disk, offering the in-memory option |
| `envLock.lockOnStartup` | `true` | user only | Lock when the workspace opens |
| `envLock.lockWhenAgentStarts` | `true` | user only | Lock when an AI agent starts in a terminal |
| `envLock.lockOnClose` | `true` | user only | Lock when the window closes |
| `envLock.agentCommands` | `claude`, `codex`, `gemini`, `aider`… | user only | Terminal commands treated as AI agents |
| `envLock.agentExtensions` | Claude Code, Copilot, Cline… | user only | AI extension ids (warned about; installing one re-locks) |
| `envLock.autoApplyAgentRules` | `false` | window | Write deny/ignore rule files on every lock |

A change that **weakens** a user-only setting (e.g. `autoLockMinutes: 0`) is shown to you and reverted
unless you confirm it, because an agent can edit your User `settings.json` too.

## 12. Troubleshooting and FAQ

**My app can't find its environment variables.**
Locked files are gone from the project by design. Start the app with *Run a command with secrets*, or
unlock while you run it.

**A file is not locked.** Check *Show protected files*. Common reasons: it is tracked by git, it is a link
or hard link, it is a template, it is in an excluded folder, or no preset covers it (right-click →
*Protect this file*).

**"Nothing to lock" but the status bar is yellow.** The readable files are tracked by git: see the tooltip.

**I get a "copies of locked secret values" warning for a file I meant to contain the value.** Choose
*Protect and lock*, or better, load the value from the environment instead of hard-coding it.

**Does it work with Cursor / Windsurf?** Yes, they are VS Code–based. Agent detection covers their
terminals; built-in AI features count as AI extensions.

**Can an agent just read `~/.env-lock`?** It reads only encrypted data. Your private key is encrypted
with your passphrase (scrypt, N=2^17).

**Is it safe to commit `.vscode/settings.json` with `envLock.vaultId`?** Yes, the id is not a secret.

**Does Env Lock send anything over the network?** No.

## 13. Uninstall

1. **Unlock** the files you still need (or make sure you have a backup and your passphrase).
2. Uninstall the extension.
3. Your keyring and vaults stay in `~/.env-lock/` until you delete them. Locked files can be decrypted by
   reinstalling Env Lock later with the same keyring and passphrase.
