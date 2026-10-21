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

## Round 1 — 2026-10-21, commit 72f8892

CI: [run 39584881826](https://github.com/Lukas0923xcv/web-auth-pfsense/actions/runs/39584881826), all 7 jobs green.

| # | Category | Score | Main gap |
|---|---|---|---|
| 1 | Cryptographic correctness | 87 | userHandle (§7.2 step 6) and topOrigin not checked; no gate-level test for another user's credential |
| 2 | Security design | 86 | Attempt limit is per account *and address*: rotating addresses is not capped and not listed as an accepted risk |
| 3 | pfSense integration | 84 (cap 85) | Waits on the VM test. "2.8.1 release tag" does not exist upstream (impossible as worded); CI uses the official 2.8.1 package instead. Fixtures are master copies, not 2.8.1 |
| 4 | Install / supply chain | 85 | Release workflow never ran (needs a tag from the owner); a skipped system test would not fail CI |
| 5 | Testing / CI | 90 | — |
| 6 | Code quality | 90 | — |
| 7 | Documentation | 90 | — (small inaccuracies) |
| 8 | Independent review | 50 (cap) | Needs a human review |
