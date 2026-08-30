# Design-review runner — contract of record

Written after `sdr-runner-design` failed to deliver. Derived from the plan of
record (`security-design-review-plan.md`) reconciled against the source, with
the source winning wherever they disagree.

Covers plan §3, §4.1, §4.2, §4.3, §8, §10, and ids N26–N29.

---

## 1. What the runner replaces

`risk.main` currently refuses both new subcommands:

```python
if args.command in ("design-review", "design-review-confirm"):
    raise RiskValidationError(f"{args.command} is not wired to a runner yet")
```

That refusal is the thing this contract removes. It exists so a parsed-but-unwired
command cannot fall through to `check_policy`, which reads a `--policy` these
subcommands do not declare.

## 2. Module layout

Two new modules, and only two. Everything else is `EXTEND` on a file that
already exists.

| Module | Status | Owns |
|---|---|---|
| `sdr_report.py` | **NEW** | Assembling the §4.2 record. Pure, deterministic, no I/O. |
| `sdr_artifacts.py` | **NEW** | Deciding the artifact set and writing it. The disclosure boundary. |
| `sdr_entry.py` | EXTEND | Already owns store detection, intake invocation, `run.profile`. |
| `risk.py` | EXTEND | `main` dispatch, and one extraction (§4 below). |

The split between the two new modules is deliberate and is not "one file would
have been fine". Record assembly is pure and changes when the report grows a
field. Artifact writing is I/O and changes when the disclosure boundary moves.
§4.1 records that `status`, `exception`, `expiry`, threat ids, and
`retired_reason` have **each leaked across that boundary once and been fixed** —
five separate incidents on one seam. It gets its own module and its own test
file so there is an obvious place to look.

## 3. The runner

```python
# sdr_report.py
def build_report(
    documents: Mapping,      # policy, threats, assessment, requirements, evidence, architecture
    *,
    entry: Mapping,          # sdr_entry.design_review(...) result
    scope_record: Mapping,   # sdr_scope.resolve_scope(...) result
    confirmation: Mapping | None,
    risk_appetite: str,
    invocation: Mapping,     # platform, model, plugin_version, command, timestamp
    today: date,
) -> dict
    """The §4.2 record. Raises RiskValidationError; never writes."""

def report_problems(documents, *, scope, policy, today) -> list[str]
    """Every problem with the inputs, house `validate_*` shape: returns, never raises."""
```

```python
# sdr_artifacts.py
def artifact_entries(report, *, project_root, output_root, policy, confirmed) -> list[tuple]
    """The (path, root, content, create_parents) tuples for one run."""

def write_artifacts(entries) -> None
    """One `_write_text_transaction` call. Never more than one."""
```

Sequence for `design-review`:

1. `sdr_entry.design_review(...)` — store detection, intake if absent, `run.profile`.
2. Load documents. The appetite file selects the policy (`risk/appetite/<name>.yaml`).
3. `sdr_scope.scope_problems(...)` then `sdr_scope.resolve_scope(...)`.
4. `report_problems(...)` — assessment, attack-path, evidence and scope problems, collected.
5. **Gate** (§4 below). If output is not allowed, write nothing, print problems, exit 1.
6. `build_report(...)`.
7. `artifact_entries(...)` → `write_artifacts(...)`.

`design-review-confirm` is the same sequence with `confirmation` required and
non-`None`, and a different artifact set.

## 4. The suppression rule — extract, do not restate

N29 already exists in the source, verbatim, at `risk.py:3719`:

```python
preview_allowed = not problems or (
    bool(evidence_problems)
    and all(problem in evidence_problems for problem in problems)
)
```

Output is allowed when there are no problems at all, **or** when every problem
is an evidence problem. Stale evidence still renders an `UNDETERMINED` preview;
any binding or document-integrity error suppresses everything.

**Contract:** extract this into `risk.output_allowed(problems, evidence_problems) -> bool`
and have both `main`'s residual branch and the design-review runner call it.

Restating the rule in the new module would be the actual N29 failure mode: two
copies that agree today, and a fix applied to one of them later. One rule, one
test, two callers.

## 5. The confirmation gate

`_read_trusted_confirmation(project_root, kind)` (`risk.py:2290`) already does
what N28 asks. It reads only through `_state_target`, which resolves under
`plugin_data_root(project_root)` and runs `safe_path`. A confirmation that
exists only in the repository has no plugin-owned state, so the function
returns `None` and the run is unconfirmed.

**No new gate is written.** N28 is satisfied by calling the existing one.

| Id | Rule | Mechanism |
|---|---|---|
| N26 | No trusted confirmation → only `design-review.preview.md`, marked UNCONFIRMED, nothing publishable | `confirmation is None` selects the preview artifact set |
| N27 | `design-review-confirm` writes the authoritative set with a passing gate, refuses without | `confirmation is None` → `RiskValidationError`, exit 1 |
| N28 | Repository-only confirmation rejected | `_read_trusted_confirmation` reads plugin-owned state only |
| N29 | Any binding/integrity error suppresses **all** output | `risk.output_allowed` gates the whole entry list |

N29 gates the entry list, not each artifact. "Suppresses all rendered output"
includes the preview: a suppressed run writes nothing at all.

## 6. Artifacts and the publish boundary

Per §4.1, with `--output` overriding the base of **both** trees:

| File | Tree | Disclosure | Written when |
|---|---|---|---|
| `design-review.preview.md` | `.security-requirements/` | sensitive | any allowed preview run |
| `design-review.md` | `.security-requirements/` | sensitive | after confirm |
| `design-review.json` | `.security-requirements/` | sensitive | after confirm |
| `design-review-summary.md` | `docs/security/` | publishable | after confirm **and** `publish_risk_summary: true` |

Three rules, each load-bearing:

**One transaction.** Every artifact of a run goes into a single
`_write_text_transaction` call. A partial write that leaves a published summary
beside a missing sensitive report is a disclosure bug. `_write_text_transaction`
already refuses key material before writing a byte, so the runner inherits that.

**The publishable summary is decided by `render_public_summary`, not by the
runner.** It returns `None` unless `policy["publish_risk_summary"] is True`.
The runner adds an entry only when the return is not `None`. Re-implementing the
check would create a second opinion about what is publishable.

**A withheld summary is stated, not silent.** With `publish_risk_summary: false`
the file is not written and the run says so. Silence reads as "published".

## 7. §4.2 key-by-key producers

| Key | Producer | Status |
|---|---|---|
| `schema_version` | module constant | trivial |
| `run.mode`, `run.profile` | `sdr_entry` | **exists** |
| `run.scope` | `sdr_scope.resolve_scope` | **exists** |
| `run.policy_digest` | `risk.policy_digest` | **exists** |
| `run.risk_appetite` | `--risk-appetite` | **exists** |
| `run.confirmed` | `_read_trusted_confirmation` | **exists** |
| `run.timestamp` | injected, like `confirmed_at` | trivial |
| `run.command` | rebuilt from `argv` | trivial |
| `run.platform`, `run.model` | — | **no producer** |
| `run.plugin_version` | `.claude-plugin/plugin.json` (`0.2.0`) | trivial |
| `run.repo.branch`, `.commit` | readable from `.git` | new, small |
| `run.repo.dirty` | — | **no producer** |
| `architecture.*` | — | **no producer, no file, no §10 row** |
| `findings[].calculated` | `calculate_inherent` | **exists** |
| `findings[].cia` | `risk.cia_scores` | **exists** |
| `findings[].requirement` | requirements doc + `order_requirements` | **exists** |
| `findings[].risk_exposure` | `derive_risk_links` | **exists** |
| `attack_paths` | `sdr_attack_paths` | **exists** |
| `verdict.inherent` | `aggregate_risk` | **exists** |
| `verdict.release_threshold_rating` | appetite yaml | **exists** |
| `verdict.exceeds_threshold` | comparison against `RATINGS` | trivial |
| `limitations` | scope `excluded` + `unconfirmed_critical_facts` | new, small |
| `disclosures_blocked` | `key_material_problems` | **exists** |

Most of the record already has a producer. Three do not.

### Gap 1 — `architecture` has no source at all

This is the largest block of the report. §4.2 specifies it in full; the plan
never names a file for it, never gives it a producer, and §10 has no row for it.
`render_register` already *consumes* `summary["architecture"]` to embed the
Mermaid DFD, so the consumer shipped before the producer.

`sdr_scope.resolve_scope` also takes an architecture mapping as its first
argument, and every test for it builds that mapping locally.

**Recommendation:** `.security-requirements/architecture.yaml`, a new file
(§5.4 permits new files; it forbids new top-level keys on existing documents),
written by intake alongside `profile.yaml` and `threats.yaml`. Needs a decision
before the runner can assemble a report, because without it the runner has
nothing to put in the block and nothing to scope against.

### Gap 2 — `run.repo.dirty` cannot be computed under N36

`branch` and `commit` are readable from `.git/HEAD` and the ref file, which is
what `sdr_entry._branch_head_marker` already does. `dirty` is different: it
means "the worktree differs from the index", which requires stat-ing and hashing
every tracked file. N36 bans subprocess execution, so `git status` is not
available.

**Recommendation:** either drop `dirty` from the record, or state it as
`null` with an explicit reason. Do not compute it approximately — a report that
says `"dirty": false` when the tree is dirty is worse than one that declines to
answer, because a reader uses that field to decide whether the commit id means
anything.

### Gap 3 — `run.platform` and `run.model` must be injected

Nothing in the repository knows which platform or model is running; that is
knowledge the calling skill has and the engine does not. They arrive as
parameters or they are `null`. Detecting them would mean guessing.

## 8. Ordering and determinism

§4.3 is unchanged by this contract. `order_requirements` stays the single
ordering choke point; the runner sorts nothing itself. `resolve_scope` already
returns ordered lists, and `unconfirmed_critical_facts` is sorted. No set
iteration reaches output.

Every date the report depends on arrives as `today`, which is now injectable at
every site that reaches a score, rating, or digest.

## 9. Implementation sequence

1. Extract `risk.output_allowed`; repoint `main`'s residual branch at it. No
   behaviour change, and it is provable by the existing suite staying green.
2. Decide gap 1. Nothing downstream can be assembled until the architecture
   document has a home.
3. `sdr_report.build_report` against a fixture architecture.
4. `sdr_artifacts` — the artifact set and the single transaction.
5. Wire `main`, replacing the refusal.
6. N26–N29 against the wired runner.

Steps 1 and 2 are the ones to settle first: the first is free, and the second
blocks everything after it.
