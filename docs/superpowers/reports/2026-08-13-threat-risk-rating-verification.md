# Threat risk rating verification

Final evidence date: 2026-08-14

Authoritative golden implementation commit:
`d86423ce6930eab49b925587d3e21547b8bb593c`

## Verdict

INCOMPLETE. The deterministic threat-risk design, externally bound movie
witness, documentation contract, complete Python regression suite, and static
distribution checks passed. The strengthened clean-install host verification
did not produce a fully accepted Claude-and-Codex run, so this report does not
claim the first-release workflow is completely verified.

The prior PASS verdict and the prior installed-host claims are superseded.
Review found that the earlier movie witness did not execute the public
confirmation boundary, installed payloads came from a mutable worktree, event
checks were aggregate string searches, and project/config hash scopes were
incomplete. This fix round corrected the deterministic witness and README. It
also built a stricter host harness. The latest current-commit run proved an
isolated login-shell interpreter binding, immutable installation, a complete
canonical read-only fixture, and an unchanged hostile project across the Codex
model phase. Its natural-audit prompt explicitly prohibited shell-state and
command-resolution mutation. Codex then emitted the installed adapter's exact
documented root-resolution block, but the unchanged audit-only verifier did
not normalize its double-quoted space-containing paths as equivalent to the
single-quoted form in its allowlist. It failed closed before accepting the
semantic sequence or framed execution log and before starting Claude. The
dual-host witness therefore remains incomplete.

### Final stderr-transport host attempt

A final ignored-harness remediation removed the shim's sandbox-blocked
evidence-file reopen. The compiled shim instead emitted one bounded binary
execution record as a capability-tagged stderr frame after each pinned Python
child completed. A trusted controller outside the host sandbox decoded each
frame, rejected malformed, unauthenticated, truncated, oversized, and
non-canonical records, and created a mode-`0600`, `O_EXCL` binary log with
`flock` and `fsync`. The shim did not open or create an evidence path. Fresh
offline tests passed before the host attempt:

```text
compiled shim behavior: 8 passed
event, controller-recorder, shim-log, signal, retention, and prompt behavior: 43 passed
Seatbelt deny-file-write emission, spaces/Unicode, stderr coexistence,
exit/signal propagation, ZDOTDIR, INT=130, fail-fast, and zsh syntax: pass
```

The single material run used the exact current commit
`89b7cfa9f4e864d43f4e91d67773dd5ed7dccfb0` through a `git archive` with
SHA-256
`da68bca5f4a672b801de139278d2494f1242bed69a8ddb7975058fcfd5efb16e`.
Both isolated installations byte-matched the archive for all three runtime
scripts and the respective Claude command and Codex skill adapters. Codex
produced seven decoded execution frames, whose controller-owned binary log
hashes to
`ea46619e588d328a5632e4cbfc03a6284fd7484ed23d33b397859cd53aecaf91`.
The complete Codex hostile project was unchanged immediately before and after
the model phase:
`512e1fc1591b23e9fbc97524506ee1c29de865d1ec3fcc6a85a21510dd0abced`.

The attempt nevertheless failed closed during independent semantic command
verification:

```text
codex structured shell command 5 has an unexpected interpreter invocation
```

No accepted execution-log or adapter-success claim was emitted. Because Codex
did not pass, Claude's model phase was not started. The exact temporary root
was removed. Immediate post-cleanup measurements matched their pre-run values:

| Measured scope | SHA-256 before and after |
|---|---|
| Codex declared config scope | `cf20e23f3c9e27b8c2365d655334c67910f4f997878d6c231986486776d0fb1a` |
| Claude declared config scope | `5f263acaed3c6d7b8ce15ad5030fdb57ffe5beaf99eea223f746af5529a79cd6` |
| Claude declared plugin-control scope | `f52da02d688ae7468f6308616cbc4ab3320004c99368803e61ad1200551459ab` |
| security-requirements persistent risk data | `27fb3bc2458de6aeb70fa84e77d3693d81d5c8ed27a72bf7116816f0db066176` |
| trusted Python executable | `f99b6dedada5ef94e58e6479f0015a2e112f6f34b3e7e7e925611ce96ca0d3de` |

The mode-`0700` failure-evidence directory was retained because the run did
not pass. Its secret scan passed with one credential-file redaction, and the
retained Codex raw-event hash is
`54e22b36de41871775d202f9c1fc32f73dfafacf0b1f5fea4949b2e4e3426a8a`.

An independent pre-live review returned after the bounded Codex run had
already begun and rejected the transport as sufficient proof. It found that
the aggregate frame check was not bijectively bound to each host lifecycle
event and terminal status, that the readable bearer capability was not a
signature or MAC and therefore did not prevent replay, and that an entirely
truncated prefix could be omitted without an explicit end/count commitment.
Those findings, independently of the semantic-command rejection above, mean
the stderr transport cannot support an accepted exact-execution claim. No
rerun was performed. Items 14, the live portion of 15, and 17 remain unproven.

## Environment

| Component | Version |
|---|---|
| Python | 3.12.11 |
| Codex CLI | 0.147.0 |
| Claude Code | 2.1.145 |
| Plugin payload | 0.2.0 |
| Host OS | macOS |

## Authoritative movie-rating witness

The synthetic fixture is pinned to AWS's archived
`aws-samples/aws-serverless-crud-sample` revision
`e974c2cce7b5c4774e0fbd18a9ba3c0208c3a37f`. It assumes a public API
Gateway/Lambda/DynamoDB movie service: anonymous reads are allowed; anonymous
writes are not; movie content is public; confidentiality is Low, integrity
Moderate, availability Low; RTO is one day or longer; RPO is several hours; no
additional obligation is declared; storage region is undetermined.

The model contains exactly eight active, service-specific threats. Its literal
hand-reviewed result remains:

```yaml
inherent:
  overall: high
  status: confirmed
  coverage: 8/8
  counts: {critical: 0, high: 5, medium: 3, low: 0}
residual:
  overall: UNDETERMINED
  coverage: 0/8
  confirmed: 0
  undetermined: 8
```

`run_risk_golden` now creates two isolated project roots and two external
`SECURITY_REQUIREMENTS_DATA` roots. For both the default policy and a separate
explicit-opt-in policy it invokes public `risk.py` CLI processes under
`python -I` in this order:

```text
policy-confirm
confirm           # one complete eight-record batch
check
```

Each successful `check` requires matching repository and plugin-owned external
confirmations. Tests independently compare exact policy, aggregate-threat,
assessment, and risk-state digests. The default confirmed policy produces no
public summary. The independently confirmed opt-in policy produces only the
aggregate public summary. Both temporary project/authority roots are removed
before the test returns. No generated timestamp or absolute local path is
stored in golden YAML.

The README now distinguishes two distributions rather than conflating them:

- eight profile goldens derive to one Low, four Moderates, and three Highs;
- the movie risk witness contains five High and three Medium threats.

`test_readme_binds_current_golden_profile_and_movie_risk_distributions`
binds those claims to the actual profile set and literal expected-risk file.

## TDD and regression evidence

Fix-round RED:

```text
3 failed, 1 passed, 965 deselected
```

The failures were the intended missing authority evidence/cleanup fields and
stale seven-profile README prose. Fix-round GREEN:

```text
6 passed, 963 deselected in 3.55s
```

Fresh complete execution at implementation commit `d86423c`:

```text
1265 passed, 2 skipped, 1 pre-existing SyntaxWarning in 97.62s
1267 collected; 0 failures; 0 errors
```

The skips are explicit platform gates: one needs a case-sensitive filesystem;
the other needs a real Windows junction. Portable exact-case,
junction-predicate, and redirect-boundary coverage executed.

## Static distribution evidence

After moving only test-generated ignored payload `__pycache__` files to Trash,
these checks passed at `d86423c`:

```text
scripts/validate_distribution.py: pass
Codex official plugin validator: pass
Claude strict plugin validator: pass
Claude strict marketplace validator: pass
payload symlinks: 0
git diff --check: pass
```

The immutable E2E candidate was `git archive d86423c`, SHA-256
`505632e77fdaff101ad9c3982dbb9ff92b4bb7e0d17d1854b2a95ca2b9743420`.
Its extracted distribution validator passed. Both temporary host installs were
then byte-compared directly with `git show d86423c` for all of:

```text
scripts/runtime_paths.py
scripts/safe_paths.py
scripts/risk.py
skills/security-requirements-risk/SKILL.md   # Codex
commands/sec-req-risk.md                     # Claude
```

Those immutable install and byte-match checks passed in the attempted runs.
They do not by themselves prove adapter execution.

## Installed-host evidence gap

No fix-round host run is accepted as end-to-end evidence.

### Final quoted-adapter attempt against `b222a6e`

The ignored harness retained its fail-closed verifier unchanged and added only
host-evidence controls. Both natural-audit prompts explicitly prohibited
`set`, `export`, `unset`, `typeset`, `read`, `hash`, `alias`, shell-option
changes, and changes to `PATH`, `path`, or `FPATH`. They required only the
installed adapter's exact root-resolution, broad preflight, inherent-check,
and residual-view command forms. Failure cleanup now removes installations,
hostile projects, and the disposable root while retaining raw host JSONL and
length-framed shim logs in a separate ignored mode-`0700` directory. A bounded
scanner compares evidence against credential sources and secret-like forms,
redacts any match before retention, and records SHA-256 hashes.

Fresh pre-run checks passed:

```text
event/log/harness behavior: 39 passed
compiled shim behavior: 6 passed
zsh and Python syntax: pass
immutable HEAD pin and tracked-worktree cleanliness: pass
git diff --check: pass
```

Those 45 offline tests include the prior 43 adversarial and shim gates plus
explicit prompt-contract and failed-run evidence-retention tests. Exactly one
material run used only
`git archive b222a6eb79bc6a53b361ad1a0eac0f50e845c54b`, SHA-256
`6b696d1b14ef4082bfed97aa9d2510588c52689f6fba05bc604a00d516748412`.
The extracted distribution validated. Both isolated installs matched the
archive byte-for-byte before model execution:

| Installed immutable file | SHA-256 |
|---|---:|
| `scripts/runtime_paths.py` | `0cb933c604659f98a60757225ced7ebf79c4ac223624d531df6912b006d39a3d` |
| `scripts/safe_paths.py` | `9f09f687ad4a35e819476f0ef0faf8ccd906622666b5f114d9d3418de30319ee` |
| `scripts/risk.py` | `a4ad8c1c14ff0ef5058c78dcf793d7bf8580b43fc955bf2abb02bc13c9e9162c` |
| Codex `skills/security-requirements-risk/SKILL.md` | `891050c2ef848fe2e76eaf3c11592b872cf35a09e0080fbb830250ab6de3c5ee` |
| Claude `commands/sec-req-risk.md` | `b84489e95ff08389d66d1205e177d16b1db79709b007deea594f83b703f84993` |

The complete Codex hostile project matched immediately before and after its
model phase:

```text
1e2c0b4468849312ff5b6ce11c7c61dbc00621760f580b3811ee6c14eacf7bb0
```

Codex first read the installed risk skill. Its second completed shell event
was the adapter's documented root-resolution block: an inline
`SECURITY_REQUIREMENTS_ROOT="$(python3 -I .../runtime_paths.py --skill
.../SKILL.md)"` assignment followed by the exact root equality test. Both
space-containing installed paths used double quotes, as shown in the installed
adapter. The unchanged verifier rejected that event:

```text
codex structured shell command 2 uses a prohibited assignment:
SECURITY_REQUIREMENTS_ROOT
FALLBACK_TEMP_ROOT_ABSENT=pass
```

This is a verifier canonicalization gap, not a product-adapter or prompt
violation: the offline allowlist constructed the semantically equivalent
space-containing paths with `shlex.join`, which used single quotes, while the
live adapter used double quotes. The verifier compares the reconstructed
assignment value to that one quote spelling. Per the bounded-run rule it was
not relaxed and the host workflow was not retried. No Codex semantic sequence
or model-phase shim log is accepted, Claude was not started, and no
`TASK11_HOST_E2E=pass` marker exists.

Failure cleanup removed the exact disposable root. Immediate independent
post-failure hashes matched every declared pre-run nonvolatile scope and the
pinned interpreter:

| Measured scope | SHA-256 before and after |
|---|---:|
| Codex config/control | `cf20e23f3c9e27b8c2365d655334c67910f4f997878d6c231986486776d0fb1a` |
| Claude config/control | `5f263acaed3c6d7b8ce15ad5030fdb57ffe5beaf99eea223f746af5529a79cd6` |
| Claude plugin control | `f52da02d688ae7468f6308616cbc4ab3320004c99368803e61ad1200551459ab` |
| security-requirements persistent risk data | `27fb3bc2458de6aeb70fa84e77d3693d81d5c8ed27a72bf7116816f0db066176` |
| trusted Python 3.12.11 executable | `f99b6dedada5ef94e58e6479f0015a2e112f6f34b3e7e7e925611ce96ca0d3de` |

The failed-run evidence remains under the ignored
`.superpowers/sdd/2026-08-13-threat-risk-rating/retained-host-evidence/`
directory for diagnosis. Its exact run directory is mode `0700`; all files are
mode `0600`. The secret scan passed. It conservatively redacted one false
positive: the `sk-assessment.md` substring inside the loaded prose path
`risk-assessment.md`; the exact rejected command was unaffected and the JSONL
remains valid. Retained file hashes after that redaction are:

| Retained evidence | SHA-256 |
|---|---:|
| Claude framed argv log | `569830c708bb5da3c18cd2313ef0737b5392896f56d4b0eaa4e5b4a90cc587d1` |
| Claude raw events | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| Codex framed argv log | `1cd6803701ce673fb9966259fab721e7bba6575a7e3a7df9e7bde7e49018f92f` |
| Codex raw events | `89ec4d3629a8e352050d4a1caab46cd582264192e0a405561420b2ccb35b6658` |

Items 14, the complete live portion of 15, and 17 remain unproven.

### Semantic read-only attempt against `c7e2147`

The final ignored harness created independent Codex and Claude hostile
projects, each with a complete canonical fixture: profile, policy, threats,
assessment, risk state, empty valid requirements, and empty valid risk
evidence. The plugin-owned external authority root was intentionally empty.
Direct fixture smoke tests proved that both `check` and `residual` report only
the missing policy and assessment confirmations and make zero authority
writes.

Raw host JSONL and length-framed shim records lived in a separate mode `0700`
evidence root outside the disposable host root and hostile projects. The
harness retained them through verification and hashing, with cleanup scheduled
only afterward. Each host used its own compiled `python3` shim and an exact
four-tool PATH allowlist: `/usr/bin/env`, pinned Node 24.14.0, `/bin/cat`, and
`/usr/bin/sed`. Real Codex and Claude `--version` and `--help` probes succeeded
under that minimal PATH.

Fresh pre-run gates passed:

```text
host event/log/harness tests: 37 passed
compiled shim tests: 6 passed
per-host nested ZDOTDIR/login probe: pass
faithful Codex and Claude compound adapter forms: pass
full Python suite: 1265 passed, 2 skipped
distribution and official host validators: pass
zsh syntax and git diff checks: pass
```

The bounded adversarial tests covered missing/duplicate operations, Codex
fresh-resolver adjacency, extra legitimate resource resolvers, absolute and
alternate interpreters, Python frontends, command-resolution aliases, output
redirects, in-place edits, foreign or side-effecting Python, truncated framed
logs, and signal/fail-fast cleanup. This is evidence for the actual harness,
not a claim that its parser models every possible shell program.

Exactly one material run used
`git archive c7e21479b35b6cea67c31e020ccd9f7c344dee0b`, SHA-256
`ee6b11fdcdc581debc129119b9f436f94ff7e7ae0b652af672575e3305725ff1`.
The extracted distribution validated, and both isolated installations matched
the archive byte-for-byte:

| Installed immutable file | SHA-256 |
|---|---:|
| `scripts/runtime_paths.py` | `0cb933c604659f98a60757225ced7ebf79c4ac223624d531df6912b006d39a3d` |
| `scripts/safe_paths.py` | `9f09f687ad4a35e819476f0ef0faf8ccd906622666b5f114d9d3418de30319ee` |
| `scripts/risk.py` | `a4ad8c1c14ff0ef5058c78dcf793d7bf8580b43fc955bf2abb02bc13c9e9162c` |
| Codex `skills/security-requirements-risk/SKILL.md` | `891050c2ef848fe2e76eaf3c11592b872cf35a09e0080fbb830250ab6de3c5ee` |
| Claude `commands/sec-req-risk.md` | `b84489e95ff08389d66d1205e177d16b1db79709b007deea594f83b703f84993` |

The complete Codex hostile project had the same hash immediately before and
after its model phase:

```text
cad3482f8eedcac582eef689206a4b39bc8eec83b09730f8bcccec6769eb43b1
```

The run then failed closed during structured event verification:

```text
codex structured shell command 2 uses prohibited top-level executable: set
FALLBACK_TEMP_ROOT_ABSENT=pass
FALLBACK_EVIDENCE_ROOT_ABSENT=pass
```

`set` was excluded because shell-state mutation can alter later command
resolution. Therefore neither the Codex semantic sequence nor its framed
model-phase execution records are accepted. Claude was not reached, no
`TASK11_HOST_E2E=pass` marker was emitted, and the one-material-run bound
prohibited a retry. Fallback cleanup removed both exact temporary roots,
including raw event and framed-log evidence after failed verification.

Independent immediate post-failure hashing matched every declared pre-run
nonvolatile scope and the pinned interpreter:

| Measured scope | SHA-256 before and after |
|---|---|
| Codex config/control | `cf20e23f3c9e27b8c2365d655334c67910f4f997878d6c231986486776d0fb1a` |
| Claude config/control | `5f263acaed3c6d7b8ce15ad5030fdb57ffe5beaf99eea223f746af5529a79cd6` |
| Claude plugin control | `f52da02d688ae7468f6308616cbc4ab3320004c99368803e61ad1200551459ab` |
| security-requirements persistent risk data | `27fb3bc2458de6aeb70fa84e77d3693d81d5c8ed27a72bf7116816f0db066176` |
| trusted Python 3.12.11 executable | `f99b6dedada5ef94e58e6479f0015a2e112f6f34b3e7e7e925611ce96ca0d3de` |

This attempt strengthens complete-fixture, current-HEAD archive, minimal-PATH,
installed-byte, Codex-project immutability, cleanup, and real-state evidence.
It does not prove an accepted Codex sequence or any Claude model execution.
Items 14, the complete live portion of 15, and 17 remain unproven.

### Isolated `ZDOTDIR` attempt against `3129efa`

The final ignored harness revision bound each host to its own mode-`0700`
`ZDOTDIR`. The mode-`0400` `.zprofile` exported an exact two-component PATH:
the compiled-shim directory first and an isolated required-tools directory
second. Before archive creation, installation, or model execution, both hosts
ran the exact nested login-shell probe:

```text
/bin/zsh -lc 'command -v python3; python3 -I <probe>'
```

For Codex and Claude, `command -v` returned the exact compiled shim and the
append-only binary log contained exactly one successful framed record with the
expected `python3 -I <probe>` argv. Exact inventories found that shim as the
only Python/PyPy interpreter command; retained `python*-config` and
`python-build` entries were reported separately as non-interpreter helpers.
`ZDOTDIR` was also passed into each model-host environment.

Before the live run, six compiled-shim tests and 27 event/log/harness tests
passed. Adversarial coverage included alternate, absolute, versioned, direct,
indirect, quoted, escaped, parameter-built, glob-built, and launcher-prefixed
interpreter commands; exact ordered Codex root revalidation; duplicate and
extra calls; and realistic Codex `item.started` plus `item.completed` command
lifecycle events. The final independent frozen-scope review was clean. Zsh
syntax, the standalone `ZDOTDIR` probe, and `git diff --check` also passed.

Exactly one material live run used only
`git archive 3129efa3f2453c41a24af18e9b0e7f3e30aa3ab2`, SHA-256
`82dfe56b53363398f64e65d472c670c819628fe6324f1d83816766cd4745b489`.
The extracted distribution validator passed. Both isolated installs again
byte-matched all three runtime scripts and the matching Claude/Codex adapter
from that immutable archive. The complete hostile project matched immediately
before and after the Codex phase:

```text
2c4b60ecca0d4041bb1e984f8df4f5caaf007a4e5863cf91d28dcb9bfb4de6c8
```

The run then failed closed during Codex structured-command verification:

```text
codex structured shell commands missed expected installed invocation:
['check', 'residual', 'runtime_skill', 'safe_paths']
FALLBACK_TEMP_ROOT_ABSENT=pass
```

The Codex model did not follow the exact installed adapter sequence required by
the harness. Consequently its framed model-phase execution log and assistant
confirmation-stop output are not accepted. The Claude model phase was not
reached, no `TASK11_HOST_E2E=pass` marker was emitted, and the one-run rule
prohibited a retry.

Fallback cleanup removed the exact temporary root
`security requirements risk E2E 테스트-3129efa.dMr8D2`; an independent check
confirmed it absent. Immediate independent post-failure hashes matched every
declared pre-run nonvolatile scope and the pinned interpreter:

| Measured scope | SHA-256 before and after |
|---|---|
| Codex config/control | `cf20e23f3c9e27b8c2365d655334c67910f4f997878d6c231986486776d0fb1a` |
| Claude config/control | `01c858a36d6c4201b080b6fd2433d34941e8bb13630d92454505c76380ebe35d` |
| Claude plugin control | `f52da02d688ae7468f6308616cbc4ab3320004c99368803e61ad1200551459ab` |
| security-requirements persistent risk data | `27fb3bc2458de6aeb70fa84e77d3693d81d5c8ed27a72bf7116816f0db066176` |
| trusted Python 3.12.11 executable | `f99b6dedada5ef94e58e6479f0015a2e112f6f34b3e7e7e925611ce96ca0d3de` |

This attempt strengthens interpreter-resolution, immutable-install,
hostile-project immutability, cleanup, and scoped real-state evidence. It does
not prove a completed equivalent Claude-and-Codex risk workflow. Items 14, the
complete live portion of 15, and 17 therefore remain unproven.

### Final compiled-shim attempt against `6360308`

The reviewed ignored compiled-shim harness was first rerun offline. All 22
tests passed: six compiled-shim behavior tests and sixteen event, binary-log,
signal, and fail-fast tests. An exact-name PATH regression additionally proved
that non-interpreter `python-config` helpers remain usable while alternate
commands named exactly `python` or `python3` are rejected. Zsh syntax and
`git diff --check` passed. A saved-baseline diff contained only that PATH
filter correction, the current immutable-commit pin, and its truthful scope
description before the live run.

Exactly one material live attempt then used
`git archive 63603082c289dddf09fa81d6907bc26586c1d918`, SHA-256
`89e835392adf5560b34eaf8edc8f51db877f7a4d9ec9feab1f57ed855a8f5195`.
The extracted distribution validator passed. Both isolated version `0.2.0`
installs matched the immutable archive byte-for-byte before model execution:

| Installed immutable file | SHA-256 |
|---|---:|
| `scripts/runtime_paths.py` | `0cb933c604659f98a60757225ced7ebf79c4ac223624d531df6912b006d39a3d` |
| `scripts/safe_paths.py` | `9f09f687ad4a35e819476f0ef0faf8ccd906622666b5f114d9d3418de30319ee` |
| `scripts/risk.py` | `a4ad8c1c14ff0ef5058c78dcf793d7bf8580b43fc955bf2abb02bc13c9e9162c` |
| Codex `skills/security-requirements-risk/SKILL.md` | `891050c2ef848fe2e76eaf3c11592b872cf35a09e0080fbb830250ab6de3c5ee` |
| Claude `commands/sec-req-risk.md` | `b84489e95ff08389d66d1205e177d16b1db79709b007deea594f83b703f84993` |

The Codex phase selected the exact installed adapter and reported the explicit
missing-policy-confirmation stop. Its hostile-project hash matched immediately
before and after the phase:

```text
f2ed592a61d4db9b49633f2722291fe2f29fcec715c7566a80f22e2f7c4ece99
```

The run nevertheless failed closed when the compiled-shim verifier found no
valid positive-size execution-interception log:

```text
execution-interception log size is invalid
FALLBACK_TEMP_ROOT_ABSENT=pass
```

Assistant-authored selection and stop markers do not prove that the required
installed Python commands actually executed. Consequently no exact Codex
Python argv evidence is accepted. The Claude model phase was not reached, the
run emitted no `TASK11_HOST_E2E=pass`, and the one-run rule prohibited a retry.

Fallback cleanup removed the exact temporary root
`security requirements risk E2E 테스트-6360308.792FAr`. Immediate independent
post-failure hashes matched all pre-run declared nonvolatile scopes and the
pinned trusted interpreter:

| Measured scope | SHA-256 before and after |
|---|---|
| Codex config/control | `cf20e23f3c9e27b8c2365d655334c67910f4f997878d6c231986486776d0fb1a` |
| Claude config/control | `b25625b873007cb6f4f6e787c362a03bbbbd043b74a4decd19637363e4fe28d5` |
| Claude plugin control | `f52da02d688ae7468f6308616cbc4ab3320004c99368803e61ad1200551459ab` |
| security-requirements persistent risk data | `27fb3bc2458de6aeb70fa84e77d3693d81d5c8ed27a72bf7116816f0db066176` |
| trusted Python 3.12.11 executable | `f99b6dedada5ef94e58e6479f0015a2e112f6f34b3e7e7e925611ce96ca0d3de` |

The exclusions remain the volatile caches and runtime state enumerated below;
no claim is made about them. This final attempt proves immutable installation,
Codex adapter selection/confirmation-stop behavior, immediate Codex project
immutability, cleanup, and scoped real-state immutability. It does not prove
exact Python execution or a completed equivalent Claude-and-Codex workflow.

### Execution-interception attempt against `1b036a2`

The final remediation replaced shell-command parsing with direct execution
interception. A compiled `python3` shim was designed to execute only the pinned
Python 3.12.11 binary, wait for it, and append a lossless length-prefixed record
containing PID, wall-clock start/end time, argv, and exit result. It never
records environment variables or process output. Separate per-host logs were
created outside the hostile project with mode `0600` and the macOS `uappnd`
append-only flag. The verifier accepted invocation facts only from those binary
records; structured Codex/Claude events were restricted to adapter
selection/discovery and the explicit confirmation stop.

Before any live run, 22 offline tests passed:

```text
compiled shim behavior: 6 passed
event/log/harness behavior: 16 passed
zsh syntax and git diff checks: pass
```

They covered space-and-Unicode argv, exact pinned executor and shim identity,
PID/time/exit capture, environment-secret omission, nonzero and signaled child
propagation, copied-shim rejection, archive byte mismatch, assistant-event
spoofing boundaries, exact-once required invocations, missing `-I`, foreign and
side-effecting scripts, truncated binary logs, signal cleanup, and fail-fast
marker suppression. An independent pre-live review found three issues: Claude
discovery had been conflated with selection, allowed calls could repeat, and
the cleanup trap was installed too late. Those were fixed, retested, and the
same reviewer returned a clean verdict. Non-login `sh`, `zsh`, and `bash`
preflights also resolved `python3` to the intended per-host shim.

Exactly one live attempt was then made from commit
`1b036a2edf112ff1619ab0d3bddcb71d5169ef0d`. It failed closed during isolated
PATH inventory, before archive creation, plugin installation, or either model
phase:

```text
isolated host PATH contains an alternate Python command
FALLBACK_TEMP_ROOT_ABSENT=pass
```

The check counted the non-interpreter helper `python-config`, which the PATH
builder had retained, as an alternate Python executable. The ignored harness
was corrected offline to omit every `python*`/`pypy*` helper, but it was not
rerun. Consequently this attempt generated no immutable-archive digest, no
installed-payload comparison, no host event, no shim invocation record, and no
hostile-project before/after model-phase hashes. It also emitted no
`TASK11_HOST_E2E=pass` marker. Fallback cleanup removed the isolated temporary
root. Because failure occurred before any Codex or Claude CLI invocation in the
installation/model phase, the attempt did not touch real host registration or
plugin state; however, it also did not emit a same-run before/after hash pair,
so no new real-state immutability claim is derived from it.

Per the one-live-run bound, no retry followed. This execution-interception
attempt therefore leaves verification items 14, the live-host portion of 15,
and 17 unproven and does not change the INCOMPLETE verdict.

### Earlier bounded attempt against `a0f65bc`

After this report was corrected to INCOMPLETE, the ignored verifier and host
harness were rebuilt around streamed JSON event objects rather than a single
concatenated string. Eleven offline self-tests passed. They covered exact
per-invocation paths and arguments, mandatory `python3 -I`, adapter-digest
binding, non-command-field and completion-marker spoofing, event size limits,
irrelevant-command avoidance, `INT` exit status 130, fail-fast behavior,
cleanup, and suppression of false pass markers.

Exactly one subsequent host run was permitted. It used the exact bytes of
`git archive a0f65bce9f23ce12849b4044e9d20a2949b6fc57`, SHA-256
`76fa470b4045a81a7bb2388725955d320e2a062abdc2b888fbbfdb2c09f644d6`.
The archive was written once, hashed, extracted, and used as the only
marketplace source from the hostile space-and-Unicode cwd. Distribution
validation passed. Both isolated installations byte-matched that extracted
archive with these SHA-256 values:

| Installed immutable file | Codex | Claude |
|---|---:|---:|
| `scripts/runtime_paths.py` | `0cb933c604659f98a60757225ced7ebf79c4ac223624d531df6912b006d39a3d` | same |
| `scripts/safe_paths.py` | `9f09f687ad4a35e819476f0ef0faf8ccd906622666b5f114d9d3418de30319ee` | same |
| `scripts/risk.py` | `a4ad8c1c14ff0ef5058c78dcf793d7bf8580b43fc955bf2abb02bc13c9e9162c` | same |
| Codex `skills/security-requirements-risk/SKILL.md` | `891050c2ef848fe2e76eaf3c11592b872cf35a09e0080fbb830250ab6de3c5ee` | n/a |
| Claude `commands/sec-req-risk.md` | n/a | `b84489e95ff08389d66d1205e177d16b1db79709b007deea594f83b703f84993` |

The run was rejected during Codex structured-event verification with
`unclosed command substitution in structured shell event`. The live event
contained a shell form outside the offline verifier corpus. Therefore no
Codex execution evidence from that run is accepted, the Claude risk-adapter
phase was never started, and the hostile-project post-execution hash was not
reached. Per the one-run rule, the host workflow was not rerun. The log
contains no `TASK11_HOST_E2E=pass`, project-unchanged pass, or temp-absence
pass marker.

Fallback cleanup removed the exact isolated root
`security requirements risk E2E 테스트-a0f65bc.NzUneL`; an independent
post-failure existence check confirmed it absent. Immediate read-only hashes
of every declared nonvolatile scope matched the pre-run values exactly:

| Measured real scope | SHA-256 before and after |
|---|---|
| Codex config/control: `config.toml`, `auth.json`, `AGENTS.md`, `hooks.json`, `rules`, `agents`, `skills` | `b6469319245bf10d0ba240a7d597b55c811759c58be2ae7ddd2d0280eaccfc2b` |
| Claude config/control: `~/.claude.json`, `~/.claude.json.backup`, `settings.json`, `settings.json.bak`, `remote-settings.json`, `commands`, `agents`, `skills` | `8991e831c0e1340e9ed01d5f3667a091c708977f7d08fc1b130e7c160890a1de` |
| Claude plugin control: blocklist, installed/known registries, marketplaces, security-requirements persistent plugin data | `75064fa14693ec50e63d8e2555a3f01e243c004ca1c186d7a2c0d14b0e097420` |
| security-requirements persistent risk data | `27fb3bc2458de6aeb70fa84e77d3693d81d5c8ed27a72bf7116816f0db066176` |

The declared exclusions were volatile Codex sessions, history, logs, SQLite,
IPC, locks, shell snapshots, model/application caches, and plugin
cache/staging/appserver data; and volatile Claude history, debug, sessions,
file history, backups, cache, last-use sweep, plugin cache, and catalog cache.
No claim is made about those excluded paths. These cleanup and real-state
results constrain the rejected attempt; they do not turn it into accepted
adapter or hostile-project evidence.

One run did produce independently validated Codex events for installed
`runtime_paths.py --skill`, `runtime_paths.py --project-root`, `safe_paths.py`,
`risk.py check`, and `risk.py residual`. Every matched invocation had its own
`python3 -I`, exact installed path, and exact expected arguments; the selected
installed Codex `SKILL.md` and explicit confirmation stop were also observed.
That run did not reach an accepted Claude result and is therefore not counted
as the requested dual-host witness.

Later attempts exposed several fail-closed verifier defects around nested
shell commands, literal same-event variables, command boundaries, and multiple
command substitutions. The last attempt produced an extremely large Codex
command event; event parsing was interrupted after approximately three minutes.
The interrupt exposed a harness signal bug: cleanup returned instead of
terminating, disabled `errexit`, and allowed a false trailing
`TASK11_HOST_E2E=pass` marker. That marker, and all dependent project/hash
claims from the interrupted run, are explicitly invalid.

The ignored harness has since been corrected offline so HUP/INT/TERM exit with
nonzero status after cleanup and command events/substitution counts are bounded.
Signal cleanup and fail-fast limits passed self-checks. No host rerun followed
that correction until the single final bounded attempt documented above; that
attempt exposed another parser gap and was rejected, so the offline corrections
remain non-host evidence.

The exact temporary roots were absent after rejected/interrupted attempts. The
following explicitly scoped real-state hashes matched before and after the
last interrupted attempt:

| Measured real scope | SHA-256 before and after |
|---|---|
| Codex config: `config.toml`, `AGENTS.md`, `hooks.json`, `rules`, `agents`, `skills` | `0761fe3599dfe1e6cd400e999e5d33afb6b2fa51d700b007767088ffe4e063fd` |
| Claude config: `settings.json`, `commands`, `agents`, `skills` | `b6fdcc95285f33cc5f4819dd7e0dbec331fae4542b1dece52f7ece206b9ce5e9` |
| Claude plugin control: installed/known registries, marketplaces, security-requirements data | `9919ed9d1b7a63feb17393cbe893d9a491fcea412a5ea970b6b6d0ed19c345df` |
| security-requirements persistent risk data | `27fb3bc2458de6aeb70fa84e77d3693d81d5c8ed27a72bf7116816f0db066176` |

Volatile Codex plugin cache/source-staging/appserver data and volatile Claude
plugin cache/last-use/catalog-cache files were explicitly excluded. No claim is
made about excluded paths. The interrupted run did not prove the complete
hostile-project tree unchanged because cleanup removed the project before the
post-run hash; its emitted project pass line is invalid.

## Requirement audit

The deterministic design criteria remain covered by the 1,267-test suite,
including calculation boundaries, high-water impact, active coverage, external
approval anti-forgery, staleness, aggregation, evidence validity, acceptance,
lifecycle, transactional publication, redaction, migration, and dual-package
equivalence. The fix-round movie tests additionally prove public CLI approval
and explicit-opt-in authority binding.

The following Task 11 verification items remain unproven by accepted live-host
evidence:

- item 14: an accepted dual-host execution over the immutable shared engine;
- item 15: complete hostile-project before/after no-write proof for that run;
- item 17: accepted current-commit clean-install Claude and Codex discovery,
  exact per-command execution, and confirmation stops in one completed run.

Consequently the success criterion “equivalent Claude and Codex workflows over
one engine” has strong deterministic/package coverage but incomplete live-host
coverage. All other success criteria retain deterministic passing evidence;
this report does not use that fact to override the incomplete release verdict.

## Residual boundaries

- Local `self_declared` identity is recorded, not authenticated. IAM, IdP, and
  signed-CI integration are outside this release.
- No movie control is asserted as implemented; all residual risk remains
  `UNDETERMINED`.
- Real Windows-junction and case-sensitive-volume executions were unavailable.
- No fix-round run proves complete dual-host execution or exact installed
  Python invocation evidence across both hosts. The final run proves the
  complete Codex project tree unchanged for its model phase, but did not reach
  the Claude phase.
- Side-effecting live confirmations/publication were intentionally not run in
  the host adapters. The golden CLI witness safely covers confirmations in
  isolated temporary roots.
