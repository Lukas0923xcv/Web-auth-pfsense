# Scorecard

Each round is scored by a fresh reviewer (a separate agent that has not seen the work) against the fixed rubric. A criterion without evidence counts as not met; a category reaches 90 only when all of its 90 criteria are met.

## Round 0 — 2026-10-21, commit 51c469c (baseline)

| # | Category | Score | Main gap |
|---|---|---|---|
| 1 | Cryptographic correctness | 68 | No real authenticator vectors, no BS/BE check, gaps in negative tests for spec 7.1/7.2 |
| 2 | Security design | 62 | Failed-passkey limit is per session, so a new session resets it |
| 3 | pfSense integration | 50 | No CI against upstream pfSense sources, no docs/VM-TEST.md (capped at 85 until a VM test is reported) |
| 4 | Install / supply chain | 45 | No release workflow, no CI check of the README pin, no install/uninstall test |
| 5 | Testing / CI | 45 | No coverage, no shellcheck, suites named review3/review4, no tests/README.md |
| 6 | Code quality | 40 | No PHPStan; webauthn_gate() 139 lines and the gate page 84 lines without a reason |
| 7 | Documentation | 35 | No CHANGELOG, upgrade notes, troubleshooting or docs/ |
| 8 | Independent review | 20 | No human review, no review guide (capped at 50 without a human) |
