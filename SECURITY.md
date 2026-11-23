# Security policy

Env Lock is a security tool, so reports of weaknesses are very welcome.

## Supported versions

Only the latest released version receives security fixes.

## Reporting a vulnerability

**Please do not open a public issue for a vulnerability.** Report it privately through GitHub:
**Security** tab of this repository → **Report a vulnerability**.

Include:
- the Env Lock version, your OS and editor (VS Code, Cursor…) and its version;
- what an attacker can do (read a secret, disable protection, make you type your passphrase somewhere…);
- steps to reproduce, ideally as an attack the red-team runner can automate
  (see [test/redteam/runner.js](test/redteam/runner.js)).

You will get an answer within 7 days. Once a fix is released, the report is credited in the
[changelog](CHANGELOG.md) unless you prefer otherwise.

## Scope

In scope: anything that lets a process running as the user (an AI agent) read a protected secret while it is
locked, keep it readable after a lock, make Env Lock encrypt to another key, accept planted or old files
without telling you, or switch protection off without your consent.

Out of scope, documented limits (see [README → Honest limits](README.md#honest-limits)): reading secrets while
they are unlocked, reading another process's memory, another extension running in the same VS Code window,
and changing Env Lock's installed code.

## How Env Lock is tested

- `npm test`: unit tests (crypto, signing, vault, policy, patterns, scan, copy detection, agent rules, hook).
- `npm run redteam`: 48 attacks run unattended against a real, isolated VS Code; results in
  [docs/redteam-results.md](docs/redteam-results.md), analysis in [docs/redteam-report.md](docs/redteam-report.md).
