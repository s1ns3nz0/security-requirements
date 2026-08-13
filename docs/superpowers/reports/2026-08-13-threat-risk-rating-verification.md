# Threat risk rating verification

Final evidence date: 2026-08-14

Implementation and installed-host evidence commit:
`98ce26e652b31a777804ef77d3e78dd5a529037b`

## Verdict

PASS for the first-release threat-risk design, subject to the residual
boundaries stated below. The deterministic suite passed, both distribution
formats passed their authoritative validators, the movie-rating witness
produced the approved eight-threat result, and both installed host adapters
executed the same packaged risk engine from a hostile cwd before stopping at
the external human-confirmation boundary.

The accepted installed-host run did not confirm a policy or assessment and did
not publish documents. Those side-effecting transitions are covered by the
deterministic transaction and anti-forgery tests; they are not represented as
live host evidence.

## Environment

| Component | Version |
|---|---|
| Python | 3.12.11 |
| Codex CLI | 0.147.0 |
| Claude Code | 2.1.145 |
| Plugin payload | 0.2.0 |
| Host OS | macOS |

## Movie-rating witness

The fixture is synthetic and pinned to AWS's archived
`aws-samples/aws-serverless-crud-sample` revision
`e974c2cce7b5c4774e0fbd18a9ba3c0208c3a37f`. Its approved operating context is
a public API Gateway/Lambda/DynamoDB movie service: anonymous reads are
allowed, anonymous writes are not; movie content is public; confidentiality is
Low, integrity Moderate, availability Low; RTO is one day or longer; RPO is
several hours; no additional obligation is declared; storage region remains
undetermined.

The fixed threat model contains exactly eight active, service-specific threats:
static AWS credentials, an overprivileged Lambda role, anonymous mutation,
unbounded input, client-visible AWS errors, attacker-controlled log content,
mutation repudiation, and route/operation confusion.

| Threat | Likelihood | Impact | Score | Rating | Residual |
|---|---:|---:|---:|---|---|
| T-01 | 2 | 4 | 8 | medium | `UNDETERMINED` |
| T-02 | 3 | 4 | 12 | high | `UNDETERMINED` |
| T-03 | 5 | 3 | 15 | high | `UNDETERMINED` |
| T-04 | 5 | 3 | 15 | high | `UNDETERMINED` |
| T-05 | 4 | 2 | 8 | medium | `UNDETERMINED` |
| T-06 | 4 | 2 | 8 | medium | `UNDETERMINED` |
| T-07 | 5 | 2 | 10 | high | `UNDETERMINED` |
| T-08 | 4 | 3 | 12 | high | `UNDETERMINED` |

The deterministic result is:

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

`test_movie_rating_risk_witness` recalculates every row with the bundled
engine and compares it with hand-reviewed literal expectations.
`test_movie_rating_reports_keep_detail_internal_and_require_explicit_opt_in`
proves that the sensitive internal register contains scenarios, paths,
criteria, treatment owner, and residual reasons while the default public
summary is absent. The explicit opt-in variant contains only aggregate overall,
coverage, and distribution fields. The golden YAML contains neither generated
timestamps nor absolute local paths.

## TDD and deterministic regression evidence

The three initial golden tests were run before the fixture existed and failed
for the intended missing-input reason:

```text
3 failed, 965 deselected
FileNotFoundError: golden/movie-rating-aws/{profile,threats}.yaml
```

After adding only the deterministic fixture and runner, the focused selection
was green:

```text
3 passed, 966 deselected in 0.65s
```

Adding a new golden directory exposed three existing assumptions that treated
every golden as a requirements-coverage case and hard-coded the prior impact
distribution. They were corrected to distinguish golden contracts by their
files. The affected regression selection then passed:

```text
13 passed, 955 deselected in 1.41s
```

Fresh complete execution used the prepared interpreter and disabled bytecode
and pytest cache writes:

```bash
PYTHONDONTWRITEBYTECODE=1 \
  /Users/s1ns3nz0/.pyenv/versions/3.12.11/bin/python \
  -m pytest -p no:cacheprovider -q \
  --junitxml=/tmp/security-requirements-task11-golden-final.xml
```

Result:

```text
1264 passed, 2 skipped in 91.17s
1266 collected; 0 failures; 0 errors
```

The skips were explicit platform gates:

- the case-variant-sibling integration requires a case-sensitive temporary
  filesystem; this macOS volume is case-insensitive;
- the real filesystem-junction integration requires Windows.

Portable same-file, exact-case, junction-predicate, and redirect-boundary tests
executed on this host. Neither skipped case is described as real platform
execution.

## Distribution and static validation

After removing test-generated ignored Python caches, the following fresh
commands all exited 0:

```bash
python scripts/validate_distribution.py .
python /Users/s1ns3nz0/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py \
  plugins/security-requirements
claude plugin validate --strict plugins/security-requirements
claude plugin validate --strict .
find plugins/security-requirements -type l -print
git diff --check
git archive HEAD | tar -x -C <temporary-directory>
python <temporary-directory>/scripts/validate_distribution.py <temporary-directory>
```

Observed results:

```text
distribution validator: no output, exit 0
Codex plugin validator: Plugin validation passed
Claude plugin manifest: Validation passed
Claude marketplace manifest: Validation passed
payload symlinks: 0
diff check: no output, exit 0
literal git archive HEAD validator: no output, exit 0
```

The first validator invocation intentionally failed closed when it found
ignored `scripts/__pycache__/*.pyc` created by an earlier non-isolated test
import. Only those generated caches were deleted; the same validator command
then passed. This is retained as evidence that a dirty local payload is not
mistaken for a valid release archive.

The completion search found no unfinished marker in the new fixture or risk
payload. The only marker-like strings in the affected tests are deliberate
negative-test inputs. Both payload manifests declare `0.2.0`; the remaining
`0.1.0` in the root marketplace file is marketplace metadata, not a payload
manifest, and is unchanged as required by the release plan. The packaged tree
contains exactly one `scripts/risk.py` and one `risk/default-policy.yaml`; the
distribution validator independently enforces the same no-duplicate contract.

## Installed Claude and Codex risk workflow

The accepted run installed the exact worktree independently into temporary
Codex and Claude config roots. Config, data, shim, and hostile project paths
contained spaces and Unicode. A mode-0600 copy of Codex authentication was
placed only in the temporary Codex root and was removed with that root.

The hostile project contained `sitecustomize.py`, `pathlib.py`, and `yaml.py`.
Each poison module would create a marker and raise if imported. `PYTHONPATH`
pointed at that directory. Before execution, both installed 0.2.0 copies of
`runtime_paths.py`, `safe_paths.py`, and `risk.py` compared byte-for-byte with
the implementation commit.

Codex selected the installed `security-requirements-risk` adapter. Structured
`command_execution` events proved calls to the installed cache under
`python3 -I` for:

```text
runtime_paths.py --skill <installed security-requirements-risk/SKILL.md>
runtime_paths.py --project-root <hostile project>
safe_paths.py --project-root <hostile project> --check-output .security-requirements
risk.py check <canonical project documents>
risk.py residual <canonical project documents>
```

Claude invoked `/security-requirements:sec-req-risk show`. Streamed Bash
tool-use/result events proved the installed `runtime_paths.py`, `safe_paths.py`,
and both `risk.py` activities under `python3 -I`.

Both adapters reported the missing external risk-policy confirmation and
emitted their accepted confirmation-stop markers. Event inspection rejected
`policy-confirm`, inherent `confirm`, and `residual-confirm`; none executed.
The poison marker count and external authority write count were both zero.

Cleanup then removed the exact isolated plugins and marketplaces. Final
isolated plugin and marketplace lists were empty for both hosts, and the exact
temporary root was absent. The accepted run used no real host CLI inventory
command; it only read and SHA-256 hashed real filesystem state. These hashes
were identical before and after:

| Real state | SHA-256 before and after |
|---|---|
| Codex `config.toml` | `b7c5d7935bbfcfe69957a6bdb9e9003b502eebcc72017cb3879779a0426c67cd` |
| Codex plugin tree | `22e97982afa257e9c76d1a3eb29a2e89e126e06a58dbe70995e1792db9972091` |
| Claude plugin tree | `f95dd1ed24292e772a88d4fe277f54b069b7d93f303e4db021633217335927d7` |
| security-requirements persistent risk data | `27fb3bc2458de6aeb70fa84e77d3693d81d5c8ed27a72bf7116816f0db066176` |

Several candidate harness runs were rejected rather than counted as evidence:
one parsed Codex's marketplace source path instead of its installed-cache path;
another exposed the `/tmp` versus `/private/tmp` physical alias; and an early
audit showed that a real Codex `plugin list` is not a purely read-only check
because it can refresh cache content. The accepted run removed real inventory
calls and proved the four read/hash-only before/after values above. The earlier
cache refresh means this report does not claim that every discarded exploratory
preflight left the entire real plugin cache byte-identical to its pre-task
state.

## Success-criteria audit

| Design success criterion | Authoritative evidence |
|---|---|
| Reproducible 5×5 assessment for every active threat | `test_default_policy_rating_boundaries`, `test_assessment_validation_requires_confirmed_active_coverage`, movie witness 8/8 |
| Model proposes; human/engine confirms | `test_cli_confirmation_survives_separate_processes_and_calculates_scores`, `test_risk_workflow_preserves_confirmation_stops_and_security_boundaries`, installed-host stop markers |
| Repository content cannot forge approval | `test_repository_only_assessment_confirmation_is_rejected`, `test_policy_confirmation_requires_external_state`, project-contained-authority rejection tests |
| Policy criteria, structured evidence, rationale, and canonical scores | unknown/mismatched-criterion, rationale, structured-evidence, high-water consequence, and stable-digest tests |
| Inherent score does not take residual implementation credit | separate `calculate_inherent` and evidence-gated `calculate_residual` paths; requirement-text and evidence-validity tests |
| Residual remains undetermined without implementation evidence | `test_requirement_text_is_not_implementation_evidence`, `test_residual_confirm_keeps_missing_evidence_undetermined_and_atomic`, movie witness 0/8 |
| Acceptance does not reduce or hide rating | `test_acceptance_never_changes_rating`, expiry/provisional tests |
| Highest active rating plus distribution and coverage | `test_overall_is_highest_active_rating_not_average`, incomplete-coverage test, movie aggregate |
| Internal detail; public summary opt-in | internal-register, strict-redaction, confirmed-policy opt-in, and movie report tests |
| Safe legacy 0.1.0 migration | migration proposal, atomic rollback, publication preservation, and successful human promotion tests |
| Equivalent Claude and Codex workflows over one engine | package/workflow equivalence tests, distribution validator, both installed-host event streams |

## Verification-strategy audit

| # | Required verification | Evidence |
|---:|---|---|
| 1 | Rating boundaries | `test_default_policy_rating_boundaries` covers 1/4, 5/9, 10/16, 17/25 |
| 2 | Criterion/rationale/calculation/digest | focused risk validation and stable-digest tests |
| 3 | Active coverage and hard gate | active-coverage tests and `test_build_and_refresh_gate_publication_on_confirmed_inherent_risk` |
| 4 | Threat/policy staleness | policy/threat/rationale stale tests and confirmed-policy refresh tests |
| 5 | Repository/project-contained authority rejection | repository-only and project-contained state-root tests |
| 6 | Risk versus requirement priority | `test_cross_risk_exposure_links_confirmed_assessments_without_changing_priority`, byte-preservation test |
| 7 | Aggregation/distribution/provisional/ordering | highest-active, provisional, unresolved-order, and render-order tests |
| 8 | Evidence validity and residual reassessment | validity, expiry, requirement drift, per-axis reduction, and residual-confirm tests |
| 9 | Acceptance semantics | acceptance score, role, owner, expiry, and aggregate tests |
| 10 | Threat lifecycle | retire/supersede/reopen/stable-ID and delta tests |
| 11 | Transactional build/refresh preservation | publication rollback/race/recovery tests and refresh transaction rollback tests |
| 12 | Register redaction and opt-in summary | register/public-summary tests and movie report witness |
| 13 | Legacy migration | migration scaffold, non-publication, rollback, and schema-promotion tests |
| 14 | Shared host engine | dual-package/workflow tests plus installed-host script hashes/events |
| 15 | Space/Unicode, poison cwd, redirects | accepted installed-host run; hostile-project unit test; symlink/junction validators |
| 16 | Full suite and host validators | 1264 passed/2 platform skips; all official validators pass |
| 17 | Current-head clean-install discovery/execution | accepted implementation-commit Codex and Claude installations and confirmation stops |
| 18 | Eight-threat movie example | movie profile/threat/assessment/expected fixtures and three focused golden tests |

## Residual boundaries

- Local `self_declared` identity is recorded, not authenticated. Corporate IAM,
  signed CI, and IdP integration remain outside this release.
- No implementation control is asserted for the movie fixture. All eight
  residual risks intentionally remain `UNDETERMINED`.
- The real Windows junction test did not execute on macOS. Portable junction
  predicates and redirect-boundary seams passed.
- The case-sensitive sibling integration did not execute on this
  case-insensitive volume. Portable exact-case and physical-containment seams
  passed.
- The installed-host run exercised discovery, immutable installed payloads,
  isolated path handling, risk status calculation, and confirmation stops. It
  did not run the side-effecting interview, policy confirmation, assessment
  confirmation, residual confirmation, or publication workflow.
- A preflight followed by a model Write/Edit remains a check-then-use protocol,
  not an operating-system directory capability. Transaction-owned publishers
  and engine writes provide the stronger atomic boundary where applicable.
