# Env Lock attack tests

Unit tests (`npm test`) check the crypto and the rules outside VS Code. These tests check that the
**defenses actually work inside a running VS Code**, by doing what a hostile AI agent running as you
could do. Run them before trusting Env Lock with real secrets, and again after changing its security code.

A test **fails** if the "Expect" doesn't happen. A failure is a finding: write down what happened
instead and keep going.

## Setup (once, about 5 minutes)

Everything runs in an isolated copy of VS Code, with its own settings, credential storage, extensions,
keyring and vault under `.attack-test/`. Your real VS Code and `~/.env-lock` are never touched.

1. In this repo: `npm install`, then `npm run attack setup`.
   This creates a test project `.attack-test/project` with a fake `.env` (`API_KEY=dev-key-111`) and
   `.env.production` (`API_KEY=PRODUCTION-key-999`), as a git repo without `.gitignore`.
2. In VS Code: **Run and Debug → "Env Lock: attack tests (isolated)" → F5**. A second window opens on
   the test project. That window is called **the test window** below.
3. In the test window, Command Palette → **Env Lock: Set up post-quantum keys**: "Passphrase only",
   passphrase `test passphrase words`. When asked, set the anti-phishing phrase `blue teapot`.
4. A dialog may say `envLock.keyringPath` and `envLock.vaultPath` were changed to make protection
   weaker. That's the test setup itself (it points the keyring into `.attack-test/`), so choose
   **Yes, I changed them**. (This dialog is itself the check in test 8.)
5. Command Palette → **Env Lock: Lock all secret files**. Both `.env` files should vanish from the
   project. `npm run attack status` should show 2 files in the vault.

Run the attack commands in a terminal **of this repo** (not the test window): `npm run attack <command>`.
`npm run attack` with no command lists them all. `npm run attack reset` deletes everything.

---

## Key and file integrity

### 1. Locking needs no passphrase; nothing readable is left
- **Do:** after setup step 5, look in `.attack-test/project` and in the vault (`npm run attack status`).
- **Expect:** no `.env` or `.env.production` in the project. Vault file names are long hex strings, and
  opening one shows only base64 (no `API_KEY`, no `.env`).
- Result: ☐ pass ☐ fail

### 2. Swapped keyring (agent replaces your key with its own)
- **Do:** `npm run attack swap-keyring`. In the test window: Command Palette → **Env Lock: Show protected
  files** (to be sure nothing is unlocked), then create a file `.env.local` with `X=1` and run **Lock all
  secret files**.
- **Expect:** a dialog *"your keyring changed … nothing was locked"*. `.env.local` stays unlocked.
  Choosing **Trust this keyring** and typing `test passphrase words` fails (wrong passphrase).
  The security log (**Env Lock: Show security log**) has *"Keyring changed"*.
- **Undo:** `npm run attack restore-keyring`, then lock again (it should work without a dialog).
- Result: ☐ pass ☐ fail

### 3a. Planted unsigned file (agent encrypts a fake `.env` with your public key)
- **Do:** `npm run attack plant-unsigned`. In the test window: **Unlock all secret files** → **Unlock to
  disk** → passphrase.
- **Expect:** a dialog *".env.locked: no signature … Only use them if you locked them yourself"*.
  Press **Cancel**: no `.env` containing `attacker.example` appears; `.env.production` and the real
  vault `.env` are handled normally.
- **Undo:** delete `.attack-test/project/.env.locked`, then **Lock all secret files**.
- Result: ☐ pass ☐ fail

### 3b. Planted file with a forged signature
- **Do:** `npm run attack plant-forged`, then unlock as in 3a.
- **Expect:** no dialog for it; the unlock message ends with *"⚠ REFUSED, signature invalid … .env.locked"*.
  No `.env` with `attacker.example`.
- **Undo:** delete `.attack-test/project/.env.locked`, then lock all.
- Result: ☐ pass ☐ fail

### 4. Swapped files (production keys loaded as development keys)
- **Do:** make sure everything is locked. `npm run attack swap-blobs`. Then unlock to disk.
- **Expect:** the unlock message contains *"REFUSED, signature invalid … .env.production"* for the copied
  file. No `.env` containing `PRODUCTION-key-999` appears.
- **Undo:** `npm run attack reset`, then repeat setup (the real `.env` blob was overwritten, which is
  exactly what test 6 is about).
- Result: ☐ pass ☐ fail

### 5. Rollback (agent puts back an older version)
- **Do:** with everything locked: `npm run attack save-env`. Unlock to disk, change `.env` to
  `API_KEY=dev-key-222`, then **Lock all**. Now `npm run attack rollback-env`, and unlock to disk again.
- **Expect:** a dialog *".env: OLDER version than the one you last locked"*. **Cancel** → `.env` is not
  restored (no file with `dev-key-111`).
- Result: ☐ pass ☐ fail

### 6. Deleted locked files
- **Do:** with everything locked: `npm run attack delete-vault`. In the test window: Command Palette →
  **Developer: Reload Window**.
- **Expect:** an error *"locked secret file(s) were deleted by something other than Env Lock: .env,
  .env.production"*, with **Show vault folder**. The security log has *"Locked file(s) disappeared"*.
  (Files locked more than once also have a `.prev` copy in the vault.)
- **Undo:** `npm run attack reset` and repeat setup.
- Result: ☐ pass ☐ fail

## Settings and records

### 7. Project settings try to switch protection off
- **Do:** `npm run attack weaken-project` (sets `lockOnClose: false`, `autoLockMinutes: 0`,
  `allowList: ["**"]`, `confirmUnlockToDisk: false`, `storage: "inPlace"` in the project's
  `.vscode/settings.json`).
- **Expect:** a warning *"ignored settings in this project's .vscode/settings.json: …"* naming them.
  Protection is unchanged: **Unlock all** still asks before unlocking to disk, and `.env` still counts as
  a secret (status bar). VS Code's own Settings UI also marks them as user-only.
- **Undo:** `npm run attack clean-project-settings`.
- Result: ☐ pass ☐ fail

### 8. User settings file edited (the agent edits `settings.json` directly)
- **Do (VS Code running):** `npm run attack weaken-user`.
- **Expect:** a dialog *"these settings were changed to make protection WEAKER"* listing `lockOnClose`,
  `confirmUnlockToDisk` and `autoLockMinutes`. Press **Cancel**: open
  `.attack-test/user-data/User/settings.json`; the three values are back to what you approved
  (`true`, `true`, `5`). The security log has *"Reverted"*.
- **Do (VS Code closed):** stop the test window, run `npm run attack weaken-user`, start it again.
- **Expect:** the same dialog right at startup, and the same revert.
- **Strengthening goes through:** set `"envLock.autoLockMinutes": 1` in that settings file by hand.
  **Expect:** no dialog (a shorter auto-lock is stronger).
- Result: ☐ pass ☐ fail

### 9. Vault redirected (`envLock.vaultId` changed in the project)
- **Do:** with everything locked: `npm run attack change-vault-id`.
- **Expect:** a warning *"envLock.vaultId … changed … Still using your vault"*. The status bar still shows
  the same number of locked files, and unlocking restores the real `.env`.
- **Undo:** put the original id back in `.attack-test/project/.vscode/settings.json` (the security log
  shows the pinned id), or `npm run attack reset`.
- Result: ☐ pass ☐ fail

## Using secrets

### 10. Anti-phishing phrase
- **Do:** **Unlock all secret files** → **Unlock to disk**.
- **Expect:** the passphrase box title shows *your phrase: "blue teapot"* and says Env Lock never asks in
  a terminal. (Any prompt without it, or in a terminal, is fake.)
- Result: ☐ pass ☐ fail

### 11. Run a command with secrets
- **Do:** lock all. Command Palette → **Env Lock: Run a command with secrets (in memory)** → command
  `node index.js` → passphrase.
- **Expect:** a terminal `env-lock: node index.js` prints `API_KEY = dev-key-111`. No `.env` appears in
  the project. Pressing a key closes the terminal.
- **Do:** run it again with the command `claude`, and once with `node index.js & claude`.
- **Expect:** both refused: *"is an AI agent; it will not be given your secrets"*. No passphrase prompt.
- Result: ☐ pass ☐ fail

### 12. Secrets are not readable through VS Code's terminal API
- This one needs code, so check it by review: in `src/extension.ts`, `runWithSecretEnv` must pass
  `pty` and never `env` to `createTerminal`, and the secrets must only reach `spawn(…, { env })`.
  Search for `createTerminal(`: there must be exactly one call, and it must have no `env:`.
- Result: ☐ pass ☐ fail

### 13. Extension installed from the command line
- **Do:** with a command running from test 11 (e.g. `node -e "setInterval(()=>{},1000)"`), in a terminal
  of this repo:
  `code --extensions-dir .attack-test/extensions --install-extension esbenp.prettier-vscode`
- **Expect:** in the test window, a warning *"new extension(s) installed: Prettier …"*; the
  `env-lock:` terminal is closed; unlocked files (if any) are locked.
- **If nothing happens** until you reload the window, that is a **finding**: VS Code may not report
  installs made from outside while it runs. Write it down.
- **Undo:** `code --extensions-dir .attack-test/extensions --uninstall-extension esbenp.prettier-vscode`
- Result: ☐ pass ☐ fail ☐ finding

### 14. AI agent started in a terminal
- **Do:** unlock to disk. Open a normal terminal in the test window and type `claude` (it doesn't need to
  be installed; the command line is what's detected).
- **Expect:** files are locked right away: *"locked 2 file(s) … ("claude" started)"*.
- Result: ☐ pass ☐ fail

### 15. Unlocked secret not ignored by git
- **Do:** unlock to disk (the test project is a git repo without `.gitignore`).
- **Expect:** a warning *"not ignored by git, so it could be committed: .env, .env.production"* with
  **Add to .gitignore**. Clicking it creates `.gitignore` with `/.env` and `/.env.production`.
- Result: ☐ pass ☐ fail

### 16. Auto-lock and lock on close
- **Do:** with `autoLockMinutes: 1` (from test 8), unlock to disk and wait 1 minute.
- **Expect:** locked again (*"auto-lock timer"*).
- **Do:** unlock to disk, then close the test window.
- **Expect:** after it closes, `.attack-test/project` has no `.env` files.
- Result: ☐ pass ☐ fail

### 17. Weak passphrases are refused
- **Do:** `npm run attack reset`, setup step 1–2, then **Set up post-quantum keys** and try
  `password1234`, then `aaaaaaaaaaaaaaaa`.
- **Expect:** both refused with a reason, before you can confirm them.
- Result: ☐ pass ☐ fail

### 18. Installed bundle matches the build
- **Do:** after installing the `.vsix` in your real VS Code: `npm run hash` here, and
  `Get-FileHash "$env:USERPROFILE\.vscode\extensions\local.env-lock-*\dist\extension.js" -Algorithm SHA256`
- **Expect:** the same hash.
- Result: ☐ pass ☐ fail

---

## Not covered here

These can't be checked from a test like this; they are limits, listed in the README's security model:
an agent reading the OS credential store or another process's memory, a malicious extension already
installed before Env Lock started, and an agent deleting Env Lock's records together with its pinned key.

## Results

| Date | Env Lock version | Tester | Passed | Failed / findings |
|---|---|---|---|---|
| | | | | |
