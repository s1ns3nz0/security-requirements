# Threat Risk Rating Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add confirmed 5×5 inherent and evidence-backed residual risk ratings to every active threat without conflating risk magnitude with requirement priority.

**Architecture:** A bundled policy and one deterministic `risk.py` engine own criterion validation, arithmetic, canonical digests, confirmation, evidence checks, aggregation, migration, and reports. Model-authored threat and assessment proposals remain inside the project; matching authoritative confirmations stay in the plugin's external state root. Thin Claude and Codex risk adapters invoke the same shared engine, while build and refresh add a transactional inherent-risk gate.

**Tech Stack:** Python 3.12+, PyYAML, pytest, Markdown workflow adapters, Claude/Codex plugin manifests and validators.

**Spec:** `docs/superpowers/specs/2026-08-13-threat-risk-rating-design.md`

## Global Constraints

- Keep risk rating separate from existing `requirement.priority`; never overwrite one with the other.
- Use `score = likelihood × impact` with Low 1–4, Medium 5–9, High 10–16, Critical 17–25.
- Models may propose criteria and rationale but may not write authoritative scores, ratings, approvals, or risk acceptance.
- Confirmed inherent risk is required for every active threat before publication; residual risk may remain `UNDETERMINED`.
- Do not reduce residual risk without valid implementation evidence; do not use fixed control-effectiveness subtraction.
- Keep authoritative policy and assessment approval state outside the inspected repository and bind it to project, policy, threat, and assessment digests.
- Detailed risk registers remain internal; `docs/security/risk-summary.md` is generated only by an approved opt-in policy.
- Preserve human-owned fields, stable IDs, history, existing public documents on failure, and all current security/path invariants.
- Require Python 3.12 or newer, invoke packaged scripts with `python3 -I`, and add no runtime dependency beyond PyYAML.
- Use the single payload at `plugins/security-requirements/`; do not duplicate or symlink catalogs, scripts, commands, or skills.
- Run test commands with `/Users/s1ns3nz0/.pyenv/versions/3.12.11/bin/python` in this worktree.

---

### Task 1: Bundled Risk Policy and Pure Calculation Core

**Files:**
- Create: `plugins/security-requirements/risk/default-policy.yaml`
- Create: `plugins/security-requirements/scripts/risk.py`
- Create: `tests/risk_helpers.py`
- Create: `tests/test_risk.py`

**Interfaces:**
- Consumes: YAML policy mappings and assessment proposal mappings.
- Produces: `load_policy(path: Path) -> dict`, `criterion_score(policy: dict, axis: str, criterion: str) -> int`, `rating_for_score(policy: dict, score: int) -> str`, `calculate_inherent(policy: dict, proposed: dict) -> dict`, and `canonical_digest(value: object) -> str`.
- Test helpers defined in `tests/risk_helpers.py` and reused later: `consequence(id: str, criterion: str) -> dict`, `proposal(likelihood: str, impact: str) -> dict`, `threat_record(id: str, status: str = "active", **changes) -> dict`, `assessment_record(threat_id: str, status: str, rating: str | None = None, **changes) -> dict`, `confirmed_assessment(score: int, rating: str, strategy: str, approval: dict) -> dict`, `expired_acceptance() -> dict`, `requirements_with_exposure(*ratings: str) -> dict`, `seed_public_docs(root: Path) -> dict[str, bytes]`, `read_public_docs(root: Path) -> dict[str, bytes]`, `run_publish_with_unconfirmed_inherent_risk(root: Path) -> subprocess.CompletedProcess[str]`, and `run_risk_golden(case: Path) -> dict`.
- Test fixture defined in `tests/risk_helpers.py`: `RiskFixture`, with attributes used by later tests (`paths`, `policy`, `inherent`, `summary`, `v010_threats`, `requirements`, `failed_or_expired_evidence`, `reduced_proposal`) and methods `confirm_all()`, `change_threat(id: str, **changes)`, `write_repo_confirmation_without_external_state()`, `public_bytes()`, and `run_failing_migration()`.

- [ ] **Step 1: Write failing policy-boundary and criterion tests**

Place the reusable constructors below in `tests/risk_helpers.py`; import them
into `tests/test_risk.py`. Later tasks extend the same helper module with the
declared `RiskFixture` interface instead of inventing local fixture shapes.

```python
def consequence(id: str, criterion: str) -> dict:
    return {"id": id, "asset": "movie_records", "axis": "integrity",
            "criterion": criterion, "rationale": ["catalogue records are affected"]}

def proposal(likelihood: str, impact: str) -> dict:
    return {
        "likelihood": {"criterion": likelihood,
                       "evidence": {"exposure": "public", "access_required": "none",
                                    "exploit_complexity": "low", "preconditions": ["route is reachable"],
                                    "observed_controls": []},
                       "rationale": ["the route is publicly reachable"]},
        "consequences": [consequence("C-01", impact)],
        "impact": {"selected_from": "C-01"},
    }

def threat_record(id: str, status: str = "active", **changes) -> dict:
    record = {"id": id, "boundary": "TB-1", "category": "STRIDE:T",
              "novelty": "service_specific", "persona": "anonymous_external",
              "attack_path": "public_write_route", "scenario": "anonymous mutation",
              "affected_assets": ["movie_records"], "related_controls": ["AC-3"],
              "lifecycle": {"status": status, "superseded_by": []}}
    record.update(changes)
    return record

def assessment_record(threat_id: str, status: str,
                      rating: str | None = None, **changes) -> dict:
    record = {"threat_id": threat_id, "status": status}
    if rating is not None:
        record["calculated"] = {"rating": rating}
    record.update(changes)
    return record

@pytest.mark.parametrize("likelihood,impact,lscore,iscore,score,rating", [
    ("L1-EXCEPTIONAL", "I1-LOCAL-RECOVERABLE", 1, 1, 1, "low"),
    ("L2-RESTRICTED", "I2-LIMITED-SCOPE", 2, 2, 4, "low"),
    ("L1-EXCEPTIONAL", "I5-ORGANISATION-IRREVERSIBLE", 1, 5, 5, "medium"),
    ("L3-AUTHENTICATED", "I3-CORE-SERVICE", 3, 3, 9, "medium"),
    ("L2-RESTRICTED", "I5-ORGANISATION-IRREVERSIBLE", 2, 5, 10, "high"),
    ("L4-PUBLIC-LOW-COMPLEXITY", "I4-CROSS-SYSTEM", 4, 4, 16, "high"),
    ("L5-DIRECT-AUTOMATABLE", "I4-CROSS-SYSTEM", 5, 4, 20, "critical"),
    ("L5-DIRECT-AUTOMATABLE", "I5-ORGANISATION-IRREVERSIBLE", 5, 5, 25, "critical"),
])
def test_default_policy_rating_boundaries(default_policy, likelihood, impact,
                                          lscore, iscore, score, rating):
    result = risk.calculate_inherent(default_policy, proposal(likelihood, impact))
    assert result == {"likelihood": lscore, "impact": iscore,
                      "score": score, "rating": rating}

def test_unknown_or_mismatched_criterion_is_rejected(default_policy):
    with pytest.raises(risk.RiskValidationError, match="unknown likelihood criterion"):
        risk.calculate_inherent(default_policy, proposal("L9-MADE-UP", "I3-CORE-SERVICE"))
```

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `/Users/s1ns3nz0/.pyenv/versions/3.12.11/bin/python -m pytest tests/test_risk.py -q`

Expected: collection fails because `scripts/risk.py` and the bundled policy do not exist.

- [ ] **Step 3: Add the exact default policy**

```yaml
version: "1.0.0"
thresholds:
  - {min: 1, max: 4, rating: low}
  - {min: 5, max: 9, rating: medium}
  - {min: 10, max: 16, rating: high}
  - {min: 17, max: 25, rating: critical}
likelihood:
  L1-EXCEPTIONAL: {score: 1, definition: "Requires multiple independent, exceptional preconditions."}
  L2-RESTRICTED: {score: 2, definition: "Requires restricted access and non-trivial preconditions."}
  L3-AUTHENTICATED: {score: 3, definition: "Requires ordinary authenticated or internal access."}
  L4-PUBLIC-LOW-COMPLEXITY: {score: 4, definition: "Reachable from a public surface with low complexity."}
  L5-DIRECT-AUTOMATABLE: {score: 5, definition: "Directly reproducible without an effective control and readily automated."}
impact:
  I1-LOCAL-RECOVERABLE: {score: 1, definition: "Localised and immediately recoverable effect."}
  I2-LIMITED-SCOPE: {score: 2, definition: "Limited users or records with routine recovery."}
  I3-CORE-SERVICE: {score: 3, definition: "Core service function or a broad record set is materially affected."}
  I4-CROSS-SYSTEM: {score: 4, definition: "Account-wide, cross-system, prolonged, contractual, or regulated effect."}
  I5-ORGANISATION-IRREVERSIBLE: {score: 5, definition: "Organisation-wide compromise, irreversible harm, or safety impact."}
publish_risk_summary: false
```

- [ ] **Step 4: Implement the pure calculation and canonical digest functions**

```python
class RiskValidationError(ValueError):
    pass

def criterion_score(policy: dict, axis: str, criterion: str) -> int:
    try:
        score = policy[axis][criterion]["score"]
    except (KeyError, TypeError) as exc:
        raise RiskValidationError(f"unknown {axis} criterion: {criterion}") from exc
    if not isinstance(score, int) or not 1 <= score <= 5:
        raise RiskValidationError(f"{axis} criterion {criterion} has invalid score")
    return score

def rating_for_score(policy: dict, score: int) -> str:
    matches = [row["rating"] for row in policy["thresholds"]
               if row["min"] <= score <= row["max"]]
    if len(matches) != 1:
        raise RiskValidationError(f"score {score} matches {len(matches)} thresholds")
    return matches[0]

def calculate_inherent(policy: dict, proposed: dict) -> dict:
    likelihood = criterion_score(policy, "likelihood", proposed["likelihood"]["criterion"])
    consequences = proposed.get("consequences") or []
    impacts = [criterion_score(policy, "impact", item["criterion"]) for item in consequences]
    if not impacts:
        raise RiskValidationError("at least one consequence is required")
    impact = max(impacts)
    score = likelihood * impact
    return {"likelihood": likelihood, "impact": impact, "score": score,
            "rating": rating_for_score(policy, score)}
```

- [ ] **Step 5: Add policy integrity tests and make them pass**

Cover overlapping/gapped thresholds, scores outside 1–5, missing rationale,
missing consequences, incorrect `selected_from`, and deterministic digest under
mapping-key reordering.

Run: `/Users/s1ns3nz0/.pyenv/versions/3.12.11/bin/python -m pytest tests/test_risk.py -q`

Expected: PASS.

- [ ] **Step 6: Commit the calculation core**

```bash
git add plugins/security-requirements/risk/default-policy.yaml plugins/security-requirements/scripts/risk.py tests/risk_helpers.py tests/test_risk.py
git commit -m "feat: add deterministic threat risk calculation"
```

### Task 2: Assessment Schema, Threat Digests, and Aggregation

**Files:**
- Modify: `plugins/security-requirements/scripts/risk.py`
- Modify: `tests/test_risk.py`
- Modify: `plugins/security-requirements/skills/deriving-security-requirements/references/threat-modeling.md`
- Modify: `golden/b2b-saas-aws/threats.yaml`

**Interfaces:**
- Consumes: threat schema `0.2.0`, active/retired/superseded lifecycle, assessment proposals, and policy from Task 1.
- Produces: `threat_digest(threat: dict) -> str`, `validate_assessment(threats: dict, assessment: dict, policy: dict) -> list[str]`, and `aggregate_risk(threats: dict, assessment: dict) -> dict`.

- [ ] **Step 1: Write failing schema, lifecycle, high-water-mark, and coverage tests**

```python
def test_impact_uses_highest_consequence(default_policy):
    proposed = proposal("L3-AUTHENTICATED", "I2-LIMITED-SCOPE")
    proposed["consequences"].append(consequence("C-02", "I4-CROSS-SYSTEM"))
    proposed["impact"]["selected_from"] = "C-02"
    assert risk.calculate_inherent(default_policy, proposed)["impact"] == 4

def test_overall_is_highest_active_rating_not_average(default_policy):
    threats_doc = {"version": "0.2.0", "threats": [
        threat_record("T-1"), threat_record("T-2"), threat_record("T-3", status="retired")
    ]}
    assessment = {"assessments": [
        assessment_record("T-1", "CONFIRMED", "critical"),
        assessment_record("T-2", "CONFIRMED", "low"),
        assessment_record("T-3", "CONFIRMED", "critical"),
    ]}
    result = risk.aggregate_risk(threats_doc, assessment)
    assert result["overall"] == "critical"
    assert result["counts"] == {"critical": 1, "high": 0, "medium": 0, "low": 1}
    assert result["coverage"] == "2/2"
```

- [ ] **Step 2: Run focused tests and verify RED**

Run: `/Users/s1ns3nz0/.pyenv/versions/3.12.11/bin/python -m pytest tests/test_risk.py -k 'impact or overall or lifecycle or coverage' -q`

Expected: FAIL because threat validation and aggregation are not implemented.

- [ ] **Step 3: Implement canonical threat material and lifecycle validation**

```python
THREAT_DIGEST_FIELDS = ("id", "boundary", "category", "novelty", "persona",
                        "attack_path", "scenario", "affected_assets", "related_controls")

def threat_digest(threat: dict) -> str:
    material = {key: threat.get(key) for key in THREAT_DIGEST_FIELDS}
    return canonical_digest(material)

def active_threats(threats_doc: dict) -> list[dict]:
    result = []
    for threat in threats_doc.get("threats") or []:
        status = ((threat.get("lifecycle") or {}).get("status") or "active").lower()
        if status == "active":
            result.append(threat)
        elif status == "superseded" and not (threat.get("lifecycle") or {}).get("superseded_by"):
            raise RiskValidationError(f"{threat['id']} is superseded without replacement IDs")
    return result
```

- [ ] **Step 4: Implement assessment validation and aggregation**

Require unique threat IDs, unique assessment records, exact selected
high-water-mark consequence, structured likelihood evidence, canonical
rationale, scope-expansion evidence when present, and confirmed coverage for
every active threat. Return provisional overall state whenever any active
record is `UNDETERMINED`, `PROPOSED`, or `STALE`.

- [ ] **Step 5: Document threat schema `0.2.0` and update one golden witness**

Add `risk_family`, `attack_path`, and `lifecycle` to the reference record. In
`golden/b2b-saas-aws/threats.yaml`, preserve all scenarios and IDs while adding
explicit active lifecycle and unique attack paths.

- [ ] **Step 6: Run focused and existing cross tests**

Run: `/Users/s1ns3nz0/.pyenv/versions/3.12.11/bin/python -m pytest tests/test_risk.py tests/test_pipeline.py -k 'risk or threat or cross' -q`

Expected: PASS and existing threat × baseline behavior unchanged.

- [ ] **Step 7: Commit assessment semantics**

```bash
git add plugins/security-requirements/scripts/risk.py plugins/security-requirements/skills/deriving-security-requirements/references/threat-modeling.md golden/b2b-saas-aws/threats.yaml tests/test_risk.py
git commit -m "feat: validate threat risk assessments"
```

### Task 3: Digest-Bound Policy and Assessment Confirmation

**Files:**
- Modify: `plugins/security-requirements/scripts/risk.py`
- Modify: `plugins/security-requirements/scripts/runtime_paths.py`
- Modify: `tests/test_risk.py`
- Modify: `tests/test_confirmation.py`

**Interfaces:**
- Consumes: `plugin_data_root(project_root=...)`, safe write helpers, policy/threat/assessment canonical digests.
- Produces: `confirmation_state_path(project_root: Path, kind: str) -> Path`, `stamp_policy(...)`, `check_policy(...)`, `stamp_assessment(...)`, and `check_assessment(...)` plus CLI `policy-confirm`, `confirm`, and `check`.

- [ ] **Step 1: Write failing anti-forgery and stale-state tests**

```python
def test_repository_only_assessment_confirmation_is_rejected(risk_fixture):
    risk_fixture.write_repo_confirmation_without_external_state()
    result = risk.check_assessment(risk_fixture.paths)
    assert result == ["plugin-owned risk assessment confirmation is missing"]

def test_policy_or_threat_change_makes_confirmation_stale(risk_fixture):
    risk_fixture.confirm_all()
    risk_fixture.change_threat("T-01", scenario="changed")
    assert "threat digest changed" in risk.check_assessment(risk_fixture.paths)
```

- [ ] **Step 2: Run confirmation tests and verify RED**

Run: `/Users/s1ns3nz0/.pyenv/versions/3.12.11/bin/python -m pytest tests/test_risk.py tests/test_confirmation.py -k 'risk or policy or assessment' -q`

Expected: FAIL because risk confirmation functions and state paths do not exist.

- [ ] **Step 3: Implement external state paths and project containment rejection**

```python
def confirmation_state_path(project_root: Path, kind: str) -> Path:
    key = hashlib.sha256(str(project_root.resolve()).encode()).hexdigest()
    root = plugin_data_root(project_root=project_root)
    target = root / "risk" / kind / f"{key}.yaml"
    if path_is_within_project(target, project_root):
        raise ValueError(f"{kind} confirmation state must remain outside the project")
    return target
```

Reuse `safe_path()` and `safe_write_text(..., create_parents=True)` for every
authoritative write. Store project, policy, aggregate threat, and assessment
digests plus confirmer, timestamp, and `authority` (`self_declared` or
`externally_attested`).

- [ ] **Step 4: Implement CLI confirmation commands**

Use strict subparsers:

```text
risk.py policy-confirm --project-root ROOT --policy POLICY --by ID --authority self_declared
risk.py confirm --project-root ROOT --policy POLICY --threats THREATS --assessment ASSESSMENT --by ID --authority self_declared
risk.py check --project-root ROOT --policy POLICY --threats THREATS --assessment ASSESSMENT
```

The CLI calculates and writes score/rating fields itself before stamping; it
rejects repository-supplied authoritative state and unknown extra arguments.

- [ ] **Step 5: Test paths, separate invocations, forged copies, and atomicity**

Cover project paths with spaces/Unicode, macOS `/tmp` canonicalization,
project-contained state, parent-state containment, symlink/junction seams,
changed policy, changed rationale, changed threat, and separate stamp/check
processes.

- [ ] **Step 6: Run confirmation suites**

Run: `/Users/s1ns3nz0/.pyenv/versions/3.12.11/bin/python -m pytest tests/test_risk.py tests/test_confirmation.py -q`

Expected: PASS.

- [ ] **Step 7: Commit trusted risk confirmation**

```bash
git add plugins/security-requirements/scripts/risk.py plugins/security-requirements/scripts/runtime_paths.py tests/test_risk.py tests/test_confirmation.py
git commit -m "feat: persist trusted risk confirmations"
```

### Task 4: Treatment, Acceptance, and Immutable History

**Files:**
- Modify: `plugins/security-requirements/scripts/risk.py`
- Modify: `tests/test_risk.py`
- Modify: `tests/test_pipeline.py`

**Interfaces:**
- Consumes: confirmed assessment from Task 3 and existing requirement human exceptions.
- Produces: `validate_treatment(record: dict, policy: dict, today: date) -> list[str]`, `append_snapshot(state: dict, snapshot: dict) -> dict`, `risk_delta(previous: dict, current: dict) -> dict`, and migration proposals for requirement exceptions.

- [ ] **Step 1: Write failing treatment and acceptance tests**

```python
def test_acceptance_never_changes_rating(default_policy):
    assessed = confirmed_assessment(score=16, rating="high", strategy="accept",
        approval={"approver": "alice", "role": "head-of-engineering",
                  "owner": "platform", "rationale": "migration window",
                  "expires": "2026-12-31"})
    threats_doc = {"version": "0.2.0", "threats": [threat_record("T-1")]}
    assert risk.aggregate_risk(threats_doc, assessed)["overall"] == "high"

def test_expired_acceptance_is_unresolved(default_policy):
    problems = risk.validate_treatment(expired_acceptance(), default_policy,
                                       date(2027, 1, 1))
    assert "acceptance expired" in problems
```

- [ ] **Step 2: Run treatment tests and verify RED**

Run: `/Users/s1ns3nz0/.pyenv/versions/3.12.11/bin/python -m pytest tests/test_risk.py -k 'treatment or acceptance or history or delta' -q`

Expected: FAIL because treatment and history behavior is absent.

- [ ] **Step 3: Implement treatment enums and approval rules**

Allow `mitigate`, `avoid`, `transfer`, and `accept`. Require owner for every
strategy. Require approver, role, rationale, expiry, and authority for accept.
Validate declared role against an approved policy allowlist when configured,
without claiming that the local identity was authenticated. Never modify
numeric risk because of treatment.

- [ ] **Step 4: Implement append-only snapshots and delta calculation**

Snapshots include assessed time, policy/threat/assessment digests, inherent and
residual values, treatment, and evidence refs. `risk_delta()` returns new,
increased, decreased, stale, retired, reopened, and expired-acceptance IDs plus
rating-distribution changes. Do not calculate totals or averages.

- [ ] **Step 5: Preserve requirement exceptions through pending migration**

Add a deterministic proposal that maps existing `human.status:
accepted_risk`/`exception` records to threat-level treatment when `threat_refs`
exist. Preserve the original requirement block and write the proposal under
`pending_review`; never silently activate it.

- [ ] **Step 6: Run focused merge/history tests**

Run: `/Users/s1ns3nz0/.pyenv/versions/3.12.11/bin/python -m pytest tests/test_risk.py tests/test_pipeline.py -k 'accepted or exception or retired or reopened or delta' -q`

Expected: PASS and all existing human-block preservation tests remain green.

- [ ] **Step 7: Commit governance state**

```bash
git add plugins/security-requirements/scripts/risk.py tests/test_risk.py tests/test_pipeline.py
git commit -m "feat: govern risk treatment and history"
```

### Task 5: Implementation Evidence and Residual Risk

**Files:**
- Modify: `plugins/security-requirements/scripts/risk.py`
- Modify: `plugins/security-requirements/scripts/lint.py`
- Modify: `tests/test_risk.py`
- Modify: `tests/test_pipeline.py`

**Interfaces:**
- Consumes: requirement records, `risk-evidence.yaml`, inherent assessments, and approved policy.
- Produces: `validate_evidence(evidence: dict, requirements: dict, today: date) -> list[str]`, `calculate_residual(...) -> dict`, and CLI `evidence`/`residual` commands.

- [ ] **Step 1: Write failing evidence and residual tests**

```python
def test_requirement_text_is_not_implementation_evidence(risk_fixture):
    result = risk.calculate_residual(risk_fixture.inherent, {}, risk_fixture.policy)
    assert result == {"status": "UNDETERMINED",
                      "reason": "linked requirements have no valid implementation evidence"}

def test_residual_reduction_requires_current_passing_evidence(risk_fixture):
    with pytest.raises(risk.RiskValidationError, match="residual reduction requires"):
        risk.calculate_residual(risk_fixture.inherent,
                                risk_fixture.failed_or_expired_evidence,
                                risk_fixture.policy,
                                risk_fixture.reduced_proposal)
```

- [ ] **Step 2: Run residual tests and verify RED**

Run: `/Users/s1ns3nz0/.pyenv/versions/3.12.11/bin/python -m pytest tests/test_risk.py -k 'evidence or residual' -q`

Expected: FAIL because evidence validation is absent.

- [ ] **Step 3: Implement evidence schema and requirement binding**

Require evidence ID, requirement ID, supported method, `pass` result,
observation time/person, artifact kind/location/digest, and optional expiry.
Compare a canonical digest of the linked requirement managed block so any
managed change makes evidence stale. Record but do not publish artifact
locations.

- [ ] **Step 4: Implement evidence-based residual validation**

Residual proposals use the same criterion IDs and consequence rules as
inherent assessments. Require evidence refs for every reduction and a rationale
that names the changed attack condition or consequence. Permit increases.
Warn on a two-level reduction; require attack-path-removal evidence for score 1.

- [ ] **Step 5: Add CLI commands and lint reference checks**

```text
risk.py evidence --project-root ROOT --requirements REQUIREMENTS --evidence EVIDENCE
risk.py residual --project-root ROOT --policy POLICY --threats THREATS --assessment ASSESSMENT --requirements REQUIREMENTS --evidence EVIDENCE
```

Extend `lint.py` to reject unknown `risk_refs`, evidence refs, requirement refs,
and use of stale evidence as current.

- [ ] **Step 6: Run risk and pipeline lint suites**

Run: `/Users/s1ns3nz0/.pyenv/versions/3.12.11/bin/python -m pytest tests/test_risk.py tests/test_pipeline.py -k 'risk or evidence or lint' -q`

Expected: PASS.

- [ ] **Step 7: Commit residual assessment support**

```bash
git add plugins/security-requirements/scripts/risk.py plugins/security-requirements/scripts/lint.py tests/test_risk.py tests/test_pipeline.py
git commit -m "feat: derive residual risk from evidence"
```

### Task 6: Requirement Linking, Ordering, and Risk Reports

**Files:**
- Modify: `plugins/security-requirements/scripts/merge.py`
- Modify: `plugins/security-requirements/scripts/render.py`
- Modify: `plugins/security-requirements/scripts/risk.py`
- Modify: `tests/test_pipeline.py`
- Modify: `tests/test_risk.py`

**Interfaces:**
- Consumes: confirmed risk assessment, crossed work items, requirements, policy opt-in, and internal evidence.
- Produces: requirement `risk_refs`, display-only `risk_exposure`, deterministic risk-aware ordering, `render_register(...) -> str`, and `render_public_summary(...) -> str | None`.

- [ ] **Step 1: Write failing linking, ordering, and redaction tests**

```python
def test_unresolved_risk_sorts_after_critical_before_high():
    ordered = risk.order_requirements(requirements_with_exposure(
        "high", "UNDETERMINED", "critical", "medium"))
    assert [r["id"] for r in ordered] == ["REQ-CRITICAL", "REQ-UNKNOWN",
                                             "REQ-HIGH", "REQ-MEDIUM"]

def test_public_summary_is_opt_in_and_redacted(risk_fixture):
    assert risk.render_public_summary(risk_fixture.summary, {"publish_risk_summary": False}) is None
    published = risk.render_public_summary(risk_fixture.summary, {"publish_risk_summary": True})
    for secret in ("attack_path", "owner", "approver", "internal-ci-artifact"):
        assert secret not in published
```

- [ ] **Step 2: Run report tests and verify RED**

Run: `/Users/s1ns3nz0/.pyenv/versions/3.12.11/bin/python -m pytest tests/test_risk.py tests/test_pipeline.py -k 'risk_exposure or risk_summary or risk_register or ordering' -q`

Expected: FAIL because linking and rendering are absent.

- [ ] **Step 3: Add deterministic risk refs without changing priority**

During cross/apply, derive `risk_refs` from `threat_refs`. Calculate display
exposure from the highest active confirmed linked threat. Assert in tests that
existing priority values remain byte-for-byte unchanged.

- [ ] **Step 4: Add risk-aware ordering**

Use `critical`, unresolved, `high`, `medium`, `low`, then existing requirement
priority, then stable ID. Treat `UNDETERMINED`, `STALE`, and `PROPOSED` as
unresolved without assigning them numeric scores.

- [ ] **Step 5: Render internal register and opt-in public summary**

The internal register includes scenario, criteria, rationale, inherent and
residual rating, owner, treatment, acceptance, evidence, expiry, lifecycle,
and delta. The public summary includes only overall rating, rating counts, and
coverage. Add explicit leak tests for every internal field.

- [ ] **Step 6: Run render, merge, disclosure, and golden tests**

Run: `/Users/s1ns3nz0/.pyenv/versions/3.12.11/bin/python -m pytest tests/test_risk.py tests/test_pipeline.py -k 'render or merge or disclosure or risk' -q`

Expected: PASS.

- [ ] **Step 7: Commit risk-aware output**

```bash
git add plugins/security-requirements/scripts/risk.py plugins/security-requirements/scripts/merge.py plugins/security-requirements/scripts/render.py tests/test_risk.py tests/test_pipeline.py
git commit -m "feat: link and render threat risk"
```

### Task 7: Transactional Build and Refresh Gate

**Files:**
- Create: `plugins/security-requirements/scripts/publish.py`
- Modify: `plugins/security-requirements/commands/sec-req-build.md`
- Modify: `plugins/security-requirements/commands/sec-req-refresh.md`
- Modify: `plugins/security-requirements/skills/deriving-security-requirements/SKILL.md`
- Modify: `tests/test_plugin_workflow.py`
- Modify: `tests/test_pipeline.py`

**Interfaces:**
- Consumes: `risk.py check`, existing lint/render outputs, safe path helpers, and current `docs/security/`.
- Produces: `stage_and_publish(project_root: Path, generated: Path, managed_files: tuple[str, ...]) -> None` and build/refresh hard-gate instructions.

- [ ] **Step 1: Write failing publication-preservation tests**

```python
def test_failed_risk_gate_preserves_all_previous_public_documents(tmp_path):
    before = seed_public_docs(tmp_path)
    result = run_publish_with_unconfirmed_inherent_risk(tmp_path)
    assert result.returncode != 0
    assert read_public_docs(tmp_path) == before
```

Add structural tests requiring build and refresh to call the exact packaged
`risk.py check` after threat authoring and before responsibility/cross output is
officially published.

- [ ] **Step 2: Run workflow tests and verify RED**

Run: `/Users/s1ns3nz0/.pyenv/versions/3.12.11/bin/python -m pytest tests/test_plugin_workflow.py tests/test_pipeline.py -k 'risk_gate or transactional or publication' -q`

Expected: FAIL because no risk gate or staging publisher exists.

- [ ] **Step 3: Implement safe staging and atomic managed-file publication**

Use a temporary directory outside repository-controlled output trees. Validate
every final target with `safe_path` immediately before replacement. Replace
only plugin-managed files after all validations succeed; preserve prior files
on any exception. Never delete human-owned files or an opt-out summary without
an explicit managed-state record.

- [ ] **Step 4: Insert inherent confirmation into build and refresh**

After threat writing, direct the model to create proposals, display the batch
review table, stop for explicit confirmation, call `risk.py confirm`, then call
`risk.py check`. Do not proceed from conversation memory. Residual
`UNDETERMINED` is displayed but does not block.

- [ ] **Step 5: Add exact safe-path preflights for new internal outputs**

Preflight `risk-policy.yaml`, `risk-assessment.yaml`, `risk-evidence.yaml`,
`risk-state.yaml`, `.security-requirements/reports/risk-register.md`, the
staging location, and opt-in `docs/security/risk-summary.md` immediately before
each write. Preserve the canonical broad preflight rules already enforced by
the distribution validator.

- [ ] **Step 6: Run workflow and failure-injection suites**

Run: `/Users/s1ns3nz0/.pyenv/versions/3.12.11/bin/python -m pytest tests/test_plugin_workflow.py tests/test_pipeline.py -k 'build or refresh or publish or risk' -q`

Expected: PASS, including simulated lint/render/risk failures with unchanged
prior public bytes.

- [ ] **Step 7: Commit the pipeline gate**

```bash
git add plugins/security-requirements/scripts/publish.py plugins/security-requirements/commands/sec-req-build.md plugins/security-requirements/commands/sec-req-refresh.md plugins/security-requirements/skills/deriving-security-requirements/SKILL.md tests/test_plugin_workflow.py tests/test_pipeline.py
git commit -m "feat: gate transactional publication on risk"
```

### Task 8: Legacy Migration and Refresh State Transitions

**Files:**
- Modify: `plugins/security-requirements/scripts/risk.py`
- Modify: `plugins/security-requirements/commands/sec-req-refresh.md`
- Modify: `tests/test_risk.py`
- Modify: `tests/test_plugin_workflow.py`
- Modify: `golden/b2b-saas-aws/expected-coverage.yaml`

**Interfaces:**
- Consumes: threat schema `0.1.0`, legacy requirements/exceptions, stable IDs, and confirmed `0.2.0` state.
- Produces: CLI `migrate`, `legacy_unassessed` detection, selective stale transitions, and migration report.

- [ ] **Step 1: Write failing non-destructive migration tests**

```python
def test_legacy_migration_proposes_no_confirmed_numbers(risk_fixture):
    result = risk.migrate(risk_fixture.v010_threats, risk_fixture.requirements)
    assert result["status"] == "legacy_unassessed"
    assert all(row["status"] == "PROPOSED" for row in result["assessments"])
    assert not any("confirmed" in row for row in result["assessments"])

def test_migration_failure_preserves_existing_public_bytes(risk_fixture):
    before = risk_fixture.public_bytes()
    risk_fixture.run_failing_migration()
    assert risk_fixture.public_bytes() == before
```

- [ ] **Step 2: Run migration tests and verify RED**

Run: `/Users/s1ns3nz0/.pyenv/versions/3.12.11/bin/python -m pytest tests/test_risk.py tests/test_plugin_workflow.py -k 'legacy or migrate or stale or reopen' -q`

Expected: FAIL because migration is not implemented.

- [ ] **Step 3: Implement schema-only migration**

Create policy and assessment proposal files with no numeric confirmation.
Preserve threat IDs/scenarios and public files. Keep schema `0.1.0` until the
new assessment is confirmed; only then record `0.2.0`.

- [ ] **Step 4: Implement selective refresh invalidation**

Invalidate inherent confirmation on scenario, boundary, persona, attack path,
or affected-asset change. Invalidate residual confirmation on related-control
or requirement/evidence change. Reuse stable IDs, keep retired/superseded
history, and never resurrect old approval when a threat reopens.

- [ ] **Step 5: Add migration guidance to refresh workflow**

The workflow must print the number of active legacy threats, state that prior
published documents were not modified, and direct the user into the risk
confirmation review rather than silently continuing.

- [ ] **Step 6: Run migration, refresh, and golden coverage tests**

Run: `/Users/s1ns3nz0/.pyenv/versions/3.12.11/bin/python -m pytest tests/test_risk.py tests/test_plugin_workflow.py tests/test_pipeline.py -k 'migrate or refresh or retired or stable or risk' -q`

Expected: PASS.

- [ ] **Step 7: Commit migration support**

```bash
git add plugins/security-requirements/scripts/risk.py plugins/security-requirements/commands/sec-req-refresh.md tests/test_risk.py tests/test_plugin_workflow.py golden/b2b-saas-aws/expected-coverage.yaml
git commit -m "feat: migrate legacy threats to risk assessment"
```

### Task 9: Shared Risk Workflow and Dual-Host Adapters

**Files:**
- Create: `plugins/security-requirements/commands/sec-req-risk.md`
- Create: `plugins/security-requirements/skills/security-requirements-risk/SKILL.md`
- Create: `plugins/security-requirements/skills/deriving-security-requirements/references/risk-assessment.md`
- Modify: `plugins/security-requirements/skills/deriving-security-requirements/SKILL.md`
- Modify: `plugins/security-requirements/.codex-plugin/plugin.json`
- Modify: `tests/test_plugin_workflow.py`
- Modify: `tests/test_dual_plugin_package.py`

**Interfaces:**
- Consumes: `risk.py` subcommands from Tasks 1–8 and the existing immutable-root/state bootstrap contract.
- Produces: Claude `/security-requirements:sec-req-risk`, Codex `security-requirements-risk`, and shared assess/show/adjust/evidence/residual/policy instructions.

- [ ] **Step 1: Write failing adapter parity and discovery tests**

```python
def test_both_hosts_expose_risk_workflow(payload):
    assert (payload / "commands/sec-req-risk.md").is_file()
    assert (payload / "skills/security-requirements-risk/SKILL.md").is_file()
    prompts = json.loads((payload / ".codex-plugin/plugin.json").read_text())["interface"]["defaultPrompt"]
    assert "Assess and review threat risk for this repository." in prompts
```

Require both adapters to execute installed `runtime_paths.py`, `safe_paths.py`,
and `risk.py` under isolated Python, with no persistent shell exports and no
repository-derived executable path.

- [ ] **Step 2: Run structural tests and verify RED**

Run: `/Users/s1ns3nz0/.pyenv/versions/3.12.11/bin/python -m pytest tests/test_plugin_workflow.py tests/test_dual_plugin_package.py -k 'risk' -q`

Expected: FAIL because the fourth workflow is absent.

- [ ] **Step 3: Write shared risk-assessment instructions**

Document policy review, batch proposals, targeted adjustments, explicit
confirmation, treatment, evidence registration, residual review, reporting,
locale rules, and every stopping condition. State explicitly that High/Medium
requirement priority is not a risk rating.

- [ ] **Step 4: Add Claude and Codex thin adapters**

Copy the proven adapter structure, changing only selected skill/command names
and allowed `risk.py` operations. Preserve fresh-shell root derivation, exact
literal substitution, isolated Python, broad/scoped preflights, and explicit
human gates.

- [ ] **Step 5: Extend Codex discovery prompts and manifest validation**

Append the exact risk starter prompt without changing the existing init/build/
refresh prompts. Keep manifest version strict semver and update it in the later
release task, not with a non-semver cache suffix.

- [ ] **Step 6: Run workflow, package, and distribution tests**

Run: `/Users/s1ns3nz0/.pyenv/versions/3.12.11/bin/python -m pytest tests/test_plugin_workflow.py tests/test_dual_plugin_package.py tests/test_distribution_docs.py -q`

Expected: PASS.

- [ ] **Step 7: Commit host workflows**

```bash
git add plugins/security-requirements/commands/sec-req-risk.md plugins/security-requirements/skills/security-requirements-risk/SKILL.md plugins/security-requirements/skills/deriving-security-requirements/references/risk-assessment.md plugins/security-requirements/skills/deriving-security-requirements/SKILL.md plugins/security-requirements/.codex-plugin/plugin.json tests/test_plugin_workflow.py tests/test_dual_plugin_package.py
git commit -m "feat: expose threat risk workflow on both hosts"
```

### Task 10: Distribution Validation, Documentation, and Versioning

**Files:**
- Modify: `scripts/validate_distribution.py`
- Modify: `tests/test_distribution_docs.py`
- Modify: `README.md`
- Modify: `DESIGN.md`
- Modify: `plugins/security-requirements/.codex-plugin/plugin.json`
- Modify: `plugins/security-requirements/.claude-plugin/plugin.json`

**Interfaces:**
- Consumes: complete four-workflow payload and new risk assets.
- Produces: strict distribution checks, installation/invocation documentation, migration guide, and release version `0.2.0`.

- [ ] **Step 1: Write failing distribution and documentation contract tests**

Require the validator to check exactly one default policy, `risk.py`, the risk
reference, both host adapters, manifest prompt, schema/version agreement, and
no symlinks/junctions or duplicate payload copies. Add README assertions for
both host invocations and the distinction between rating and priority.

- [ ] **Step 2: Run distribution tests and verify RED**

Run: `/Users/s1ns3nz0/.pyenv/versions/3.12.11/bin/python -m pytest tests/test_distribution_docs.py -q`

Expected: FAIL on missing risk distribution rules and documentation.

- [ ] **Step 3: Strengthen the read-only distribution validator**

Validate every manifest-declared path, risk asset containment, default policy
schema, four host entrypoints, no unapproved components, no symlinks/junctions,
and exact payload completeness. Aggregate errors without executing repository
content.

- [ ] **Step 4: Update README and DESIGN**

Document:

```text
Claude: /security-requirements:sec-req-risk
Codex:  select security-requirements-risk or use the risk starter prompt
```

Include the 5×5 scale, confirmation flow, internal/public split, residual
evidence rule, legacy migration, accepted-risk semantics, and an explicit note
that the model proposes but does not approve scores.

- [ ] **Step 5: Bump both payload manifests to `0.2.0`**

Keep marketplace name/source unchanged. Confirm Codex interface metadata and
all four default prompts pass the official validator.

- [ ] **Step 6: Run documentation and validators**

Run:

```bash
/Users/s1ns3nz0/.pyenv/versions/3.12.11/bin/python -m pytest tests/test_distribution_docs.py -q
/Users/s1ns3nz0/.pyenv/versions/3.12.11/bin/python scripts/validate_distribution.py .
/Users/s1ns3nz0/.pyenv/versions/3.12.11/bin/python /Users/s1ns3nz0/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py plugins/security-requirements
claude plugin validate --strict plugins/security-requirements
claude plugin validate --strict .
```

Expected: tests pass and every validator exits 0.

- [ ] **Step 7: Commit distribution and docs**

```bash
git add scripts/validate_distribution.py tests/test_distribution_docs.py README.md DESIGN.md plugins/security-requirements/.codex-plugin/plugin.json plugins/security-requirements/.claude-plugin/plugin.json
git commit -m "docs: publish threat risk rating workflow"
```

### Task 11: Movie-Rating Golden Case, Full Regression, and Host E2E

**Files:**
- Create: `golden/movie-rating-aws/profile.yaml`
- Create: `golden/movie-rating-aws/threats.yaml`
- Create: `golden/movie-rating-aws/risk-assessment.yaml`
- Create: `golden/movie-rating-aws/expected-risk.yaml`
- Create: `docs/superpowers/reports/2026-08-13-threat-risk-rating-verification.md`
- Modify: `tests/test_pipeline.py`
- Modify: `tests/test_risk.py`

**Interfaces:**
- Consumes: all implemented engine, workflow, migration, packaging, and report behavior.
- Produces: deterministic eight-threat witness, complete regression evidence, and clean-install Claude/Codex execution evidence.

- [ ] **Step 1: Add the movie-rating golden fixture and expected risk**

Record the approved operating assumptions, eight service-specific STRIDE
threats, structured likelihood and consequence criteria, proposed treatment,
and exact expected score/rating distribution. Keep residual risk
`UNDETERMINED` because no implementation evidence exists. Generate the public
summary only in the explicit opt-in fixture variant.

- [ ] **Step 2: Write failing end-to-end golden assertions**

```python
def test_movie_rating_risk_witness():
    result = run_risk_golden(GOLDEN_ROOT / "movie-rating-aws")
    expected = yaml.safe_load((GOLDEN_ROOT / "movie-rating-aws/expected-risk.yaml").read_text())
    assert result["inherent"] == expected["inherent"]
    assert result["residual"]["overall"] == "UNDETERMINED"
    assert result["coverage"] == "8/8"
```

- [ ] **Step 3: Run golden tests and verify RED, then generate only deterministic expected artifacts**

Run: `/Users/s1ns3nz0/.pyenv/versions/3.12.11/bin/python -m pytest tests/test_risk.py tests/test_pipeline.py -k 'movie_rating' -q`

Expected initial result: FAIL until fixture values and report rendering align;
then PASS without loosening assertions or snapshotting timestamps/absolute
paths.

- [ ] **Step 4: Run the complete Python regression suite**

Run: `/Users/s1ns3nz0/.pyenv/versions/3.12.11/bin/python -m pytest -q`

Expected: every test passes; only explicitly platform-gated Windows junction
and case-sensitive-volume tests may skip.

- [ ] **Step 5: Run all static validators and clean-tree checks**

```bash
/Users/s1ns3nz0/.pyenv/versions/3.12.11/bin/python scripts/validate_distribution.py .
/Users/s1ns3nz0/.pyenv/versions/3.12.11/bin/python /Users/s1ns3nz0/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py plugins/security-requirements
claude plugin validate --strict plugins/security-requirements
claude plugin validate --strict .
find plugins/security-requirements -type l -print -quit | test $(wc -l) -eq 0
git diff --check
```

Expected: all commands exit 0 with no unexpected symlink output.

- [ ] **Step 6: Execute isolated current-HEAD host E2E**

Create temporary Claude and Codex config/data roots with spaces and Unicode,
install the exact worktree marketplace into each, and invoke the risk adapter
from a hostile unrelated cwd containing `pathlib.py`, `yaml.py`, and
`sitecustomize.py` poison files. Verify command events execute the installed
`runtime_paths.py`, `safe_paths.py`, and `risk.py` under `python3 -I`, reach the
explicit confirmation stop, and never execute poison code.

Clean up plugin, marketplace, cache, temporary state, and copied auth in an
EXIT trap. Prove isolated lists are empty, the temp root is absent, and real
user Claude/Codex config and plugin data hashes are unchanged.

- [ ] **Step 7: Write the verification report**

Record exact commit, test totals, skipped-test reasons, validator outputs,
movie-rating risk distribution, both host command evidence, cleanup evidence,
and residual limitations. Do not claim CI/IdP integration, authenticated local
identity, real Windows junction execution, or implemented residual controls.

- [ ] **Step 8: Commit golden case and verification evidence separately**

```bash
git add golden/movie-rating-aws tests/test_risk.py tests/test_pipeline.py
git commit -m "test: add movie rating risk witness"
git add docs/superpowers/reports/2026-08-13-threat-risk-rating-verification.md
git commit -m "docs: verify threat risk rating workflow"
```

- [ ] **Step 9: Final completion audit**

Map every success criterion and every verification-strategy item in the design
spec to a passing test or explicit host evidence. Search for unfinished
markers, unsupported completion claims, stale `0.1.0` manifest versions, and
duplicate risk payloads. Require a clean worktree before reporting completion.
