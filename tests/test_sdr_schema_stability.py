"""Schema-stability guards for the security-design-review extension (R3, R5, R6).

These tests are tripwires, not behaviour tests. They fail when the planned
extension moves a new field into a digest or refresh tuple, bumps a schema
version, or widens the allowed top-level key set of ``risk-assessment.yaml``.
"""

from __future__ import annotations

import copy
from datetime import date
from pathlib import Path

import pytest
import yaml

import risk


REPO_ROOT = Path(__file__).resolve().parents[1]
GOLDEN_CASE = REPO_ROOT / "golden" / "movie-rating-aws"
PLUGIN_ROOT = REPO_ROOT / "plugins" / "security-requirements"

PINNED_TODAY = date(2026, 8, 13)
PINNED_CONFIRMED_AT = "2026-08-13T00:00:00Z"

# The three fields §5.2 of the plan adds inside each threat record. None of them
# may enter THREAT_DIGEST_FIELDS or INHERENT_REFRESH_FIELDS.
PLANNED_THREAT_FIELDS = ("evidence_status", "confidence", "attack_path_ids")
PLANNED_FIELD_VALUES = {
    "evidence_status": "inferred",
    "confidence": "medium",
    "attack_path_ids": ["AP-01"],
}

# Discovered from risk.py: THREAT_DIGEST_FIELDS (module top) and
# INHERENT_REFRESH_FIELDS (beside refresh_assessment).
EXPECTED_THREAT_DIGEST_FIELDS = (
    "id",
    "boundary",
    "category",
    "novelty",
    "persona",
    "attack_path",
    "scenario",
    "affected_assets",
    "related_controls",
)
EXPECTED_INHERENT_REFRESH_FIELDS = (
    "scenario",
    "boundary",
    "persona",
    "attack_path",
    "affected_assets",
)

# Discovered from risk._bound_residual_assessment_problems.
EXPECTED_ASSESSMENT_TOP_LEVEL_KEYS = {
    "version",
    "migration",
    "assessments",
    "confirmation",
}


def _load_golden(name: str) -> dict:
    return yaml.safe_load((GOLDEN_CASE / name).read_text(encoding="utf-8"))


def _default_policy() -> dict:
    return risk.load_policy(PLUGIN_ROOT / "risk" / "default-policy.yaml")


def _confirmed_golden_assessment() -> dict:
    """The golden assessment carrying a pinned repository confirmation block."""

    assessment = _load_golden("risk-assessment.yaml")
    assessment["confirmation"] = {
        "status": "confirmed",
        "assessment_digest": risk.assessment_digest(assessment),
        "confirmed_at": PINNED_CONFIRMED_AT,
        "confirmed_by": "movie-rating-risk-owner",
    }
    return assessment


def _with_planned_threat_fields(threats_doc: dict) -> dict:
    """Every threat record gains the three fields planned in §5.2."""

    extended = copy.deepcopy(threats_doc)
    for record in extended["threats"]:
        record.update(copy.deepcopy(PLANNED_FIELD_VALUES))
    return extended


def _statuses(assessment: dict) -> dict[str, str]:
    return {
        record["threat_id"]: record.get("status")
        for record in assessment["assessments"]
    }


def _residual_statuses(assessment: dict) -> dict[str, str | None]:
    statuses: dict[str, str | None] = {}
    for record in assessment["assessments"]:
        residual = record.get("residual")
        statuses[record["threat_id"]] = (
            residual.get("status") if isinstance(residual, dict) else None
        )
    return statuses


def _field_names_present(node: object, names: tuple[str, ...]) -> set[str]:
    found: set[str] = set()
    if isinstance(node, dict):
        for key, value in node.items():
            if key in names:
                found.add(key)
            found |= _field_names_present(value, names)
    elif isinstance(node, list):
        for item in node:
            found |= _field_names_present(item, names)
    return found


def _unexpected_top_level_reported(assessment: dict) -> bool:
    """True when risk.py rejects this document's top-level key set."""

    problems = risk._bound_residual_assessment_problems(
        {"refreshed_assessment_digest": "sha256:pinned"},
        {"snapshots": []},
        assessment,
        _load_golden("threats.yaml"),
        _default_policy(),
    )
    return any("unexpected top-level fields" in problem for problem in problems)


# --- R5: refresh on an unchanged threat document stales nothing --------------


def test_planned_threat_fields_are_absent_from_the_refresh_and_digest_tuples():
    assert risk.THREAT_DIGEST_FIELDS == EXPECTED_THREAT_DIGEST_FIELDS, (
        "THREAT_DIGEST_FIELDS changed; every threat digest and every aggregate "
        f"confirmation is invalidated: {risk.THREAT_DIGEST_FIELDS}"
    )
    assert risk.INHERENT_REFRESH_FIELDS == EXPECTED_INHERENT_REFRESH_FIELDS, (
        "INHERENT_REFRESH_FIELDS changed; refresh_assessment will stale "
        f"confirmed records it used to keep: {risk.INHERENT_REFRESH_FIELDS}"
    )
    contaminated = {
        "THREAT_DIGEST_FIELDS": sorted(
            set(PLANNED_THREAT_FIELDS) & set(risk.THREAT_DIGEST_FIELDS)
        ),
        "INHERENT_REFRESH_FIELDS": sorted(
            set(PLANNED_THREAT_FIELDS) & set(risk.INHERENT_REFRESH_FIELDS)
        ),
    }
    assert not any(contaminated.values()), (
        "a planned threat field entered a refresh tuple, which stales every "
        f"existing confirmation on the first refresh: {contaminated}"
    )


def test_refresh_on_an_unchanged_threat_document_leaves_every_confirmation_intact():
    threats = _load_golden("threats.yaml")
    assessment = _confirmed_golden_assessment()
    before = _statuses(assessment)
    before_residual = _residual_statuses(assessment)

    refreshed = risk.refresh_assessment(
        copy.deepcopy(threats), copy.deepcopy(threats), assessment
    )

    assert set(before.values()) == {"CONFIRMED"}
    stale = [
        threat_id
        for threat_id, status in _statuses(refreshed).items()
        if status == "STALE"
    ]
    assert stale == [], f"unchanged threat document staled {stale}"
    assert _statuses(refreshed) == before
    assert _residual_statuses(refreshed) == before_residual
    assert refreshed["confirmation"]["confirmed_at"] == PINNED_CONFIRMED_AT


def test_refresh_leaves_confirmations_intact_when_planned_threat_fields_appear():
    """The real death scenario: last run's document lacks the new fields."""

    previous = _load_golden("threats.yaml")
    current = _with_planned_threat_fields(previous)
    assessment = _confirmed_golden_assessment()
    before = _statuses(assessment)

    refreshed = risk.refresh_assessment(copy.deepcopy(previous), current, assessment)

    stale = [
        threat_id
        for threat_id, status in _statuses(refreshed).items()
        if status == "STALE"
    ]
    assert stale == [], (
        "adding evidence_status/confidence/attack_path_ids staled "
        f"{stale}: a planned field reached INHERENT_REFRESH_FIELDS"
    )
    assert _statuses(refreshed) == before
    assert "confirmation" in refreshed, (
        "the aggregate confirmation was dropped: a planned field reached "
        "THREAT_DIGEST_FIELDS"
    )
    assert refreshed["confirmation"]["confirmed_at"] == PINNED_CONFIRMED_AT


@pytest.mark.parametrize("field", PLANNED_THREAT_FIELDS)
def test_threat_digests_ignore_each_planned_threat_field(field):
    threats = _load_golden("threats.yaml")
    baseline_aggregate = risk.aggregate_threat_digest(threats)
    baseline_records = [risk.threat_digest(record) for record in threats["threats"]]

    extended = copy.deepcopy(threats)
    for record in extended["threats"]:
        record[field] = copy.deepcopy(PLANNED_FIELD_VALUES[field])

    assert [
        risk.threat_digest(record) for record in extended["threats"]
    ] == baseline_records, f"{field} changed per-threat digests"
    assert risk.aggregate_threat_digest(extended) == baseline_aggregate, (
        f"{field} changed the aggregate threat digest, so every existing "
        "confirmation binding breaks"
    )


# --- R3: a document without the new fields validates and scores as today -----


def test_golden_documents_carry_no_planned_field_today():
    present = _field_names_present(
        _load_golden("threats.yaml"), PLANNED_THREAT_FIELDS
    ) | _field_names_present(
        _load_golden("risk-assessment.yaml"), PLANNED_THREAT_FIELDS
    )
    assert present == set(), (
        f"the golden case already carries planned fields {sorted(present)}; "
        "R3 no longer exercises a document without them"
    )


def test_document_without_planned_fields_validates_with_no_problems():
    threats = _load_golden("threats.yaml")
    assessment = _load_golden("risk-assessment.yaml")

    assert risk._current_threat_schema_problems(threats) == []
    assert risk.validate_assessment(threats, assessment, _default_policy()) == []


def test_document_without_planned_fields_scores_identically_to_the_golden_expectation():
    threats = _load_golden("threats.yaml")
    assessment = _load_golden("risk-assessment.yaml")
    expected = _load_golden("expected-risk.yaml")
    policy = _default_policy()

    expected_by_id = {row["threat_id"]: row for row in expected["assessments"]}
    for record in assessment["assessments"]:
        calculated = risk.calculate_inherent(policy, copy.deepcopy(record["proposed"]))
        assert calculated == record["calculated"], record["threat_id"]
        row = expected_by_id[record["threat_id"]]
        assert calculated == {
            "likelihood": row["likelihood"],
            "impact": row["impact"],
            "score": row["score"],
            "rating": row["rating"],
        }

    assert (
        risk.aggregate_risk(threats, assessment, today=PINNED_TODAY)
        == expected["inherent"]
    )


def test_document_without_planned_fields_needs_no_migration_and_stales_nothing():
    threats = _load_golden("threats.yaml")
    assert threats["version"] == risk.CURRENT_THREAT_SCHEMA_VERSION
    with pytest.raises(risk.RiskValidationError, match="legacy threat schema"):
        risk.migrate(threats, {"requirements": []})

    refreshed = risk.refresh_assessment(
        copy.deepcopy(threats),
        copy.deepcopy(threats),
        _confirmed_golden_assessment(),
    )
    assert set(_statuses(refreshed).values()) == {"CONFIRMED"}
    assert "confirmation" in refreshed


# --- R6: versions stay 0.2.0 and no new top-level key ------------------------


def test_all_three_risk_documents_still_declare_version_0_2_0():
    assert risk.CURRENT_THREAT_SCHEMA_VERSION == "0.2.0"
    assert risk.RISK_SCHEMA_VERSION == "0.2.0"
    assert _load_golden("threats.yaml")["version"] == "0.2.0"
    assert _load_golden("risk-state.yaml")["version"] == "0.2.0"
    # risk-assessment.yaml may omit version; risk.py accepts only None or 0.2.0.
    assert _load_golden("risk-assessment.yaml").get("version") in (None, "0.2.0")


def test_threat_schema_check_still_rejects_any_version_other_than_0_2_0():
    threats = _load_golden("threats.yaml")
    assert risk._current_threat_schema_problems(threats) == []
    bumped = copy.deepcopy(threats)
    bumped["version"] = "0.3.0"
    assert risk._current_threat_schema_problems(bumped) == [
        "threat schema version must be 0.2.0"
    ]


def test_risk_state_loading_still_rejects_any_version_other_than_0_2_0(tmp_path):
    documents = tmp_path / ".security-requirements"
    documents.mkdir()
    state_path = documents / "risk-state.yaml"
    paths = {"project_root": tmp_path, "state": state_path}

    state_path.write_text(
        (GOLDEN_CASE / "risk-state.yaml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    _root, _path, loaded = risk._load_validated_risk_state(paths)
    assert loaded["version"] == "0.2.0"

    bumped = _load_golden("risk-state.yaml")
    bumped["version"] = "0.3.0"
    state_path.write_text(yaml.safe_dump(bumped, sort_keys=False), encoding="utf-8")
    with pytest.raises(risk.RiskValidationError, match="risk state version must be"):
        risk._load_validated_risk_state(paths)


def test_risk_assessment_permits_exactly_four_top_level_keys():
    candidates = [
        "version",
        "migration",
        "assessments",
        "confirmation",
        "attack_paths",
        "attack_path_ids",
        "evidence_status",
        "confidence",
        "design_review",
        "risk_appetite",
        "snapshots",
    ]
    allowed = {
        key
        for key in candidates
        if not _unexpected_top_level_reported({"assessments": [], key: None})
    }
    assert allowed == EXPECTED_ASSESSMENT_TOP_LEVEL_KEYS


def test_unexpected_top_level_is_silent_on_the_golden_assessment_document():
    assessment = _load_golden("risk-assessment.yaml")
    assert set(assessment) <= EXPECTED_ASSESSMENT_TOP_LEVEL_KEYS
    assert not _unexpected_top_level_reported(assessment)

    fully_populated = copy.deepcopy(assessment)
    fully_populated["version"] = "0.2.0"
    fully_populated["migration"] = {"status": "legacy_unassessed"}
    fully_populated["confirmation"] = {"confirmed_at": PINNED_CONFIRMED_AT}
    assert not _unexpected_top_level_reported(fully_populated)
