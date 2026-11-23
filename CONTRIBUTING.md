# Contributing to Env Safety

Thanks for helping. Env Safety protects people's secrets, so every change is judged first on whether it keeps
them safe.

## Set up

Requirements: Node.js 18+ and VS Code 1.93+, plus git (the red-team run uses it).

```powershell
git clone <this repository>
cd env-safety
npm install
npm test
```

Press **F5** in VS Code to start an Extension Development Host with your build.

## Project layout

| Path | What |
|---|---|
| `src/extension.ts` | VS Code integration: commands, locking, unlocking, status bar, agent detection |
| `src/crypto.ts` | ML-KEM-768 + X25519 hybrid encryption, keyring, signatures |
| `src/vault.ts` | Vault storage outside the project, safe restore targets |
| `src/patterns.ts` | Secret file presets and glob matching (also embedded in the Claude Code hook) |
| `src/scan.ts` | Workspace file listing (no VS Code search, so project ignore files cannot hide secrets) |
| `src/copies.ts` | Keyed fingerprints to find copies of locked secrets |
| `src/policy.ts` | Which settings a project may change (add-only / user-only) |
| `src/agentRules.ts` | Deny/ignore rule files and the Claude Code hook |
| `src/dotenv.ts` | dotenv parsing for *Run with secrets* |
| `test/core.test.js` | Unit tests (plain Node, no VS Code) |
| `test/redteam/runner.js` | Attacks run inside an isolated VS Code |
| `scripts/redteam-vscode.js` | Builds a test variant, launches VS Code, writes `docs/redteam-results.md` |
| `docs/` | User guide, red-team report and results, attack list, OWASP review |

## Checks before a pull request

```powershell
npm test                                       # compile, bundle, unit tests
node scripts/redteam-vscode.js --only=X1,X8    # quick: selected attacks (a VS Code window opens; don't click in it)
npm run redteam                                # full run (~4 min): every attack must pass
npm run audit                                  # dependency vulnerabilities and signatures
```

## Rules

- **A security fix comes with an attack.** Add a test to `test/redteam/runner.js` that fails before your
  fix and passes after it, plus a unit test when the logic is VS Code-free.
- **A project must never weaken protection.** New security settings are `application` scope (user only) or
  add-only; see `src/policy.ts`.
- **Never write a secret where an agent can read it**: no plaintext in logs, messages, terminal options,
  VS Code state, or temporary files.
- **No new runtime dependencies** without a strong reason; crypto comes from Node's OpenSSL and
  `@noble/post-quantum` only.
- Keep user-facing text plain and short, and update `README.md`, `docs/user-guide.md` and `CHANGELOG.md`.

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).
