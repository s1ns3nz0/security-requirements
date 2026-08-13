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
also built a stricter host harness, but the harness did not complete an
accepted run.

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
Signal cleanup and fail-fast limits passed self-checks. There was no subsequent
host rerun, so those harness corrections are not host evidence.

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
- No fix-round run proves complete dual-host execution, whole hostile-project
  immutability, or absence of writes/publication across that complete run.
- Side-effecting live confirmations/publication were intentionally not run in
  the host adapters. The golden CLI witness safely covers confirmations in
  isolated temporary roots.
