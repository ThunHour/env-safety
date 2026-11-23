# Changelog

All notable changes to Env Lock. Security fixes reference the attack IDs in
[docs/redteam-report.md](docs/redteam-report.md).

## 0.8.0 — 2026-11-23

### Renamed: Env Lock is now **Env Safety**
- New extension id `SeakKimhour.env-safety`, commands and settings `envSafety.*`, folder `~/.env-safety`.
- **Automatic move:** on first start, `~/.env-lock` (keyring and vaults) is copied to `~/.env-safety` (the old
  folder is kept as a backup), your `envLock.*` user settings are copied to `envSafety.*`, and each project's
  `envLock.vaultId` keeps pointing at its vault. Locked files and keyrings did not change format.
- Env Safety's protected records start over (they belonged to the old extension id): set your anti-phishing
  phrase again and unlock once with your passphrase. Copied settings that weaken protection are shown to you
  for confirmation, as always.
- Agent rule blocks written by Env Lock in `.cursorignore` etc. are replaced, not duplicated.
- Uninstall Env Lock after installing Env Safety.

## 0.7.5 — 2026-11-23

Red-team round 5: attacks an agent can make **while secrets are unlocked** to keep them readable afterwards.
48 of 48 automated attacks defended.

### Security
- **Staged secrets are locked (X1).** A secret file that is staged (`git add`) but never committed is
  unstaged (`git rm --cached`) and locked. Previously any git-tracked file was skipped forever.
- **Hard-linked secrets are reported (X2).** A secret file with a second name on disk is still never
  encrypted, but you now get a visible error naming the other file, instead of a log line only.
- **Build output folders are scanned (X5).** `build`, `dist`, `out`, `target`, `.next`… are scanned last,
  with their own limit. Removed `build`, `dist`, `target` from the default `envLock.exclude`.
- **Templates holding real secrets are locked (X7).** An allow-listed file (`.env.example`…) that contains a
  value of a secret you locked is locked like a secret.
- **Copy detection (X8).** After each lock, Env Lock looks for copies of the locked values in other text files
  and offers *Protect and lock*. Only keyed hashes (HMAC) of the values are kept.

### Fixed
- *Protect this file* and *Protect and lock* failed in single-folder workspaces: `envLock.customPatterns`
  now has `resource` scope.
- *Protect and lock* could be skipped when chosen while a lock was still running.

### Added
- Extension icon, author, LICENSE, user guide, security policy, contributing guide.
- `node scripts/redteam-vscode.js --only=X1,X8` runs selected attacks only.

## 0.7.4

- A rewritten vault salt (`vault.json`) is noticed on every scan, not only at startup (R13).

## 0.7.3

- The signing key is derived from your private key, so wiping Env Lock's credential store no longer makes
  every file look forged; a wiped store is reported at startup (R11).

## 0.7.2

- *Run with secrets* loads only `.env`, `.envrc`, `.env.local` by default; other environments only when you
  pick one (R8).
- Env Lock lists files itself, so a project `.ignore` / `.rgignore` / `search.exclude` cannot hide a secret (R9).
- Replacement of Env Lock by a same-id extension is detected by watching its install folder (R10).
- You are told when a project tries to switch Env Lock off (R12).
- `*.log` excluded from the package.

## 0.7.0 and earlier

- Vault storage outside the project, signed locked files, rollback and deletion detection, pinned keyring,
  approved security settings, anti-phishing phrase, *Run a command with secrets*, agent detection, deny rules
  and Claude Code hook, local history exclusion for secret files.
