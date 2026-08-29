"""Content-duplicate threats (plan §8, N42).

Plan §4.2 calls ``threat_digest`` "the identity key for deduplication" and §8
requires that a duplicate be "flagged as duplicate, not scored twice". N42 words
that as *two threats with different ids but identical ``threat_digest``*.

That wording is unsatisfiable against the source: ``id`` is a member of
``risk.THREAT_DIGEST_FIELDS`` (``plugins/security-requirements/scripts/risk.py``
line 27, member at line 28), so two records with different ids can never share a
digest. The first test below proves that, so the contradiction lives in the suite
rather than only in a commit message.

The remaining tests exercise the substance §8 actually protects against: the same
threat entered twice under two ids being scored twice, which inflates the
register and double-counts risk. Those are expected RED today — no content-level
duplicate detection exists; ``active_threats`` / ``_validate_threats`` /
``aggregate_risk`` reject only an exact repeated ``id``, which is a different
defect.
"""

from __future__ import annotations

import copy
from datetime import date
from pathlib import Path

import pytest

import risk
from risk_helpers import proposal, threat_record


REPO_ROOT = Path(__file__).resolve().parents[1]
PLUGIN_ROOT = REPO_ROOT / "plugins" / "security-requirements"

PINNED_TODAY = date(2026, 8, 13)
LIKELIHOOD_CRITERION = "L4-PUBLIC-LOW-COMPLEXITY"
IMPACT_CRITERION = "I4-CROSS-SYSTEM"

# The identifier members of THREAT_DIGEST_FIELDS — the fields that name a record
# rather than describe the threat. A digest usable for deduplication must exclude
# these. Today the tuple holds exactly one: `id`.
IDENTIFIER_DIGEST_FIELDS = ("id",)


def _default_policy() -> dict:
    return risk.load_policy(PLUGIN_ROOT / "risk" / "default-policy.yaml")


def _substance_digest(threat: dict) -> str:
    """``threat_digest`` with the identifier fields removed."""

    material = {
        key: threat.get(key)
        for key in risk.THREAT_DIGEST_FIELDS
        if key not in IDENTIFIER_DIGEST_FIELDS
    }
    return risk.canonical_digest(material)


def _threat_pair(**second_changes) -> tuple[dict, dict]:
    """T-01 and T-02, identical in every material field unless told otherwise."""

    return threat_record("T-01"), threat_record("T-02", **second_changes)


def _documents(first: dict, second: dict) -> tuple[dict, dict, dict]:
    """A threats document, a matching confirmed assessment, and the policy."""

    policy = _default_policy()
    proposed = proposal(LIKELIHOOD_CRITERION, IMPACT_CRITERION)
    calculated = risk.calculate_inherent(policy, copy.deepcopy(proposed))
    threats = {"version": "0.2.0", "threats": [first, second]}
    assessment = {
        "assessments": [
            {
                "threat_id": record["id"],
                "status": "CONFIRMED",
                "proposed": copy.deepcopy(proposed),
                "calculated": copy.deepcopy(calculated),
            }
            for record in (first, second)
        ]
    }
    return threats, assessment, policy


def _duplicate_problems(problems: list[str]) -> list[str]:
    """Problems that name a duplicate but are not the exact-id collision."""

    return [
        problem
        for problem in problems
        if "duplicate" in problem.lower() and "duplicate threat id" not in problem
    ]


# --- the contradiction in N42 as worded --------------------------------------


def test_two_threats_differing_only_in_id_produce_different_threat_digests():
    """N42 as worded cannot be constructed: `id` is a digest field.

    `id` is the first member of THREAT_DIGEST_FIELDS
    (plugins/security-requirements/scripts/risk.py:27-37, `"id"` at line 28), and
    `threat_digest` (risk.py:664) digests exactly those fields. So a differing id
    always moves the digest, and "different ids, identical threat_digest" names a
    state the engine cannot reach. N42 needs restating in terms of substance.
    """

    first, second = _threat_pair()

    assert first["id"] != second["id"]
    assert {key: first[key] for key in first if key != "id"} == {
        key: second[key] for key in second if key != "id"
    }, "the pair must differ in id alone for this proof to mean anything"
    assert "id" in risk.THREAT_DIGEST_FIELDS, (
        "`id` left THREAT_DIGEST_FIELDS; N42 as worded may now be "
        f"constructible: {risk.THREAT_DIGEST_FIELDS}"
    )
    assert risk.threat_digest(first) != risk.threat_digest(second), (
        "two records differing only in id share a digest; THREAT_DIGEST_FIELDS "
        "no longer covers `id`"
    )
    assert _substance_digest(first) == _substance_digest(second), (
        "dropping the identifier fields does not make the two records identical, "
        "so some other identifier hides in THREAT_DIGEST_FIELDS"
    )


def test_the_aggregate_threat_digest_also_separates_records_differing_only_in_id():
    """`aggregate_threat_digest` keys by id as well, so it cannot collapse them."""

    first, second = _threat_pair()
    both = {"version": "0.2.0", "threats": [first, second]}
    single = {"version": "0.2.0", "threats": [first]}

    assert risk.aggregate_threat_digest(both) != risk.aggregate_threat_digest(single)


# --- the real requirement: a content duplicate is flagged (RED today) ---------


def test_the_threat_validator_flags_two_threats_identical_except_for_their_id():
    """§8 — a content duplicate is reported, not silently accepted."""

    first, second = _threat_pair()
    threats = {"version": "0.2.0", "threats": [first, second]}

    problems, _active = risk._validate_threats(threats)

    assert _duplicate_problems(problems), (
        "_validate_threats accepted two threats identical in every material "
        "field except id; §8 requires the duplicate be flagged. Only the exact-id "
        f"collision is detected today (risk.py:762). problems={problems}"
    )


def test_assessment_validation_flags_two_threats_identical_except_for_their_id():
    """The same duplicate reaching `validate_assessment` is reported there too."""

    threats, assessment, policy = _documents(*_threat_pair())

    problems = risk.validate_assessment(threats, assessment, policy)

    assert _duplicate_problems(problems), (
        "validate_assessment returned no duplicate problem for a threat entered "
        f"twice under two ids. problems={problems}"
    )


def test_a_threat_entered_twice_under_two_ids_is_not_scored_twice():
    """§8 — "not scored twice". Either flag it or collapse it; never count both.

    A conforming engine may reject the document (raising RiskValidationError, the
    way the exact-id collision is rejected at risk.py:938) or collapse the pair to
    one scored finding. Both satisfy §8; counting two high findings does not.
    """

    threats, assessment, _policy = _documents(*_threat_pair())

    try:
        summary = risk.aggregate_risk(threats, assessment, today=PINNED_TODAY)
    except risk.RiskValidationError:
        return  # flagged rather than scored — §8 satisfied

    scored = sum(summary["counts"].values())
    assert scored == 1, (
        "the same threat entered under two ids was scored twice, inflating the "
        f"register: counts={summary['counts']} coverage={summary['coverage']}"
    )


# --- negative guard: genuinely different threats are never flagged -----------


@pytest.mark.parametrize(
    "field, value",
    [
        ("scenario", "authenticated mutation by a stolen session"),
        ("boundary", "TB-2"),
    ],
)
def test_threats_differing_in_a_material_field_are_not_flagged_as_duplicates(
    field, value
):
    """A rule that fires on distinct threats is worse than no rule at all.

    The remedy for a duplicate is deleting a record, so a false positive deletes a
    real threat. Vacuously green today (nothing flags anything); it becomes load
    bearing the moment content-level detection lands.
    """

    first, second = _threat_pair(**{field: value})
    threats, assessment, policy = _documents(first, second)

    assert first[field] != second[field]
    assert _substance_digest(first) != _substance_digest(second)

    validator_problems, _active = risk._validate_threats(threats)
    assert _duplicate_problems(validator_problems) == [], (
        f"threats differing in {field} were flagged as duplicates: "
        f"{validator_problems}"
    )
    assert _duplicate_problems(
        risk.validate_assessment(threats, assessment, policy)
    ) == [], f"threats differing in {field} were flagged as duplicates"


@pytest.mark.parametrize(
    "field, value",
    [
        ("scenario", "authenticated mutation by a stolen session"),
        ("boundary", "TB-2"),
    ],
)
def test_threats_differing_in_a_material_field_are_both_scored(field, value):
    """The other half of the guard: distinct threats must each reach the counts."""

    threats, assessment, policy = _documents(*_threat_pair(**{field: value}))

    summary = risk.aggregate_risk(threats, assessment, today=PINNED_TODAY)

    assert sum(summary["counts"].values()) == 2, (
        f"threats differing in {field} were collapsed: counts={summary['counts']}"
    )
    assert summary["coverage"] == "2/2"
