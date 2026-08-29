"""N7 — `evidence_status` is evidence provenance, a separate axis from `status`.

Plan of record §5.2 / §7 constraint 9 / §11.2 "Evidence provenance" N7.

`ASSESSMENT_STATUSES` (`CONFIRMED | UNDETERMINED | PROPOSED | STALE`) is the
assessment lifecycle. `evidence_status` (`observed | inferred | unverified`) is
evidence provenance. They are independent: `status: CONFIRMED` together with
`evidence_status: inferred` is a legal record and must not be downgraded.

House error convention (plan §10.1, verified against risk.py): `validate_*`
returns `list[str]` of problems; calculation functions raise
`RiskValidationError`. These tests exercise `validate_assessment`, so they
assert on the returned problem list.

Builders are defined locally on purpose — `tests/risk_helpers.py` is under
concurrent edit by other agents and this file must not depend on its shape.
"""

from __future__ import annotations

import copy
from pathlib import Path
import sys

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
PLUGIN_ROOT = REPO_ROOT / "plugins" / "security-requirements"
sys.path.insert(0, str(PLUGIN_ROOT / "scripts"))

import risk  # noqa: E402


DEFAULT_POLICY_PATH = PLUGIN_ROOT / "risk" / "default-policy.yaml"

#: Plan §5.2 / §7 constraint 9 — the closed provenance vocabulary.
EVIDENCE_PROVENANCE_VALUES = ("observed", "inferred", "unverified")

#: Plan §5.2 — the assessment-lifecycle vocabulary, a different axis entirely.
LIFECYCLE_STATUSES = ("CONFIRMED", "UNDETERMINED", "PROPOSED", "STALE")


@pytest.fixture(scope="module")
def default_policy() -> dict:
    return risk.load_policy(DEFAULT_POLICY_PATH)


def _threat(threat_id: str = "T-1", **changes) -> dict:
    """A minimally complete active threat record at threat schema 0.2.0."""

    record = {
        "id": threat_id,
        "boundary": "TB-1",
        "category": "STRIDE:T",
        "novelty": "service_specific",
        "persona": "anonymous_external",
        "attack_path": "public_write_route",
        "scenario": "anonymous mutation",
        "affected_assets": ["movie_records"],
        "related_controls": ["AC-3"],
        "lifecycle": {"status": "active", "superseded_by": []},
    }
    record.update(changes)
    return record


def _threats_doc(*threats: dict) -> dict:
    return {"version": "0.2.0", "threats": [copy.deepcopy(t) for t in threats]}


def _proposal(likelihood: str, impact: str) -> dict:
    return {
        "likelihood": {
            "criterion": likelihood,
            "evidence": {
                "exposure": "public",
                "access_required": "none",
                "exploit_complexity": "low",
                "preconditions": ["route is reachable"],
                "observed_controls": [],
            },
            "rationale": ["the route is publicly reachable"],
        },
        "consequences": [
            {
                "id": "C-01",
                "asset": "movie_records",
                "axis": "integrity",
                "criterion": impact,
                "rationale": ["catalogue records are affected"],
            }
        ],
        "impact": {"selected_from": "C-01"},
    }


def _assessment_doc(threat_id: str, status: str) -> dict:
    """One assessment record; no `treatment`, so nothing here reads the clock."""

    return {
        "assessments": [
            {
                "threat_id": threat_id,
                "status": status,
                "proposed": _proposal("L3-AUTHENTICATED", "I3-CORE-SERVICE"),
            }
        ]
    }


def _evidence_status_problems(problems: list[str]) -> list[str]:
    return [problem for problem in problems if "evidence_status" in problem]


# --------------------------------------------------------------------------
# A. All three provenance values are accepted on a threat record.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("value", EVIDENCE_PROVENANCE_VALUES)
def test_a_threat_record_accepts_each_evidence_provenance_value(value, default_policy):
    """§7 constraint 9 — `observed | inferred | unverified` are all legal."""

    threats = _threats_doc(_threat("T-1", evidence_status=value))
    assessment = _assessment_doc("T-1", "CONFIRMED")

    problems = risk.validate_assessment(threats, assessment, default_policy)

    assert problems == [], (
        f"evidence_status={value!r} is a legal provenance value but was reported: "
        + "; ".join(problems)
    )


# --------------------------------------------------------------------------
# B. A fourth value is rejected, and the vocabulary is closed at three.
# --------------------------------------------------------------------------


def test_b_unknown_evidence_status_value_is_rejected(default_policy):
    """§7 constraint 9 — `evidence_status` outside the three values is a problem.

    Two requirements are encoded:
      1. risk.py owns the closed vocabulary as a module-level constant, the way
         it already owns ASSESSMENT_STATUSES / EVIDENCE_METHODS / EVIDENCE_SUPPORTS.
      2. A threat carrying a fourth value is reported by `validate_assessment`
         as a problem attributed to that threat id (house convention would spell
         it "T-1 evidence_status is invalid"), not silently ignored and not
         coerced to a legal value.
    """

    allowed = getattr(risk, "EVIDENCE_STATUSES", None)
    assert allowed is not None, "risk.py must expose the closed evidence_status vocabulary"
    assert set(allowed) == set(EVIDENCE_PROVENANCE_VALUES), (
        "evidence_status vocabulary must be exactly observed|inferred|unverified, "
        f"got {allowed!r}"
    )

    threats = _threats_doc(_threat("T-1", evidence_status="assumed"))
    assessment = _assessment_doc("T-1", "CONFIRMED")

    problems = risk.validate_assessment(threats, assessment, default_policy)

    assert problems, "evidence_status 'assumed' must be rejected, not silently ignored"
    assert any(
        "T-1" in problem and "evidence_status" in problem for problem in problems
    ), "rejection must name the threat id and the evidence_status field: " + "; ".join(
        problems
    )


# --------------------------------------------------------------------------
# C. CONFIRMED + inferred is legal and is never downgraded.
# --------------------------------------------------------------------------


def test_c_confirmed_with_inferred_evidence_is_legal_and_not_downgraded(default_policy):
    """§5.2 — `status: CONFIRMED` with `evidence_status: inferred` is a legal record.

    It must validate clean, and a change to provenance alone must not stale the
    confirmation: `evidence_status` is in neither INHERENT_REFRESH_FIELDS nor
    THREAT_DIGEST_FIELDS, so `refresh_assessment` has no reason to touch it.
    """

    threats = _threats_doc(_threat("T-1", evidence_status="inferred"))
    assessment = _assessment_doc("T-1", "CONFIRMED")

    problems = risk.validate_assessment(threats, assessment, default_policy)
    assert problems == [], (
        "CONFIRMED + inferred is a legal combination: " + "; ".join(problems)
    )

    previous = _threats_doc(_threat("T-1", evidence_status="unverified"))
    current = _threats_doc(_threat("T-1", evidence_status="inferred"))
    confirmed = {
        "confirmation": {"status": "confirmed", "assessment_digest": "sha256:pinned"},
        "assessments": [
            {
                "threat_id": "T-1",
                "status": "CONFIRMED",
                "confirmed_at": "2026-01-15",
                "proposed": _proposal("L3-AUTHENTICATED", "I3-CORE-SERVICE"),
            }
        ],
    }

    refreshed = risk.refresh_assessment(previous, current, confirmed)

    record = refreshed["assessments"][0]
    assert record["status"] == "CONFIRMED", (
        "a provenance-only change must not transition a CONFIRMED record to STALE"
    )
    assert record["confirmed_at"] == "2026-01-15"
    assert "confirmation" in refreshed, (
        "a provenance-only change must not invalidate the batch confirmation"
    )


# --------------------------------------------------------------------------
# D. The two fields do not constrain each other.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("lifecycle_status", LIFECYCLE_STATUSES)
@pytest.mark.parametrize("evidence_status", EVIDENCE_PROVENANCE_VALUES)
def test_d_evidence_status_and_assessment_status_are_independent_axes(
    lifecycle_status, evidence_status, default_policy
):
    """§5.2 — every cross-product of the two axes is structurally legal.

    A naive "evidence_status is an overload of status" implementation would
    reject CONFIRMED+inferred, CONFIRMED+unverified, or force STALE whenever
    provenance is not `observed`. None of those couplings may exist: adding
    `evidence_status` to a threat must not change the problem list at all, and
    the lifecycle status on the record must be left exactly as authored.
    """

    threats = _threats_doc(_threat("T-1", evidence_status=evidence_status))
    assessment = _assessment_doc("T-1", lifecycle_status)

    problems = risk.validate_assessment(threats, assessment, default_policy)

    baseline = risk.validate_assessment(
        _threats_doc(_threat("T-1")),
        _assessment_doc("T-1", lifecycle_status),
        default_policy,
    )

    assert _evidence_status_problems(problems) == [], (
        f"status={lifecycle_status} + evidence_status={evidence_status} must not be "
        "rejected on provenance grounds: " + "; ".join(problems)
    )
    assert problems == baseline, (
        "evidence_status must not change assessment-lifecycle validation; "
        f"with={problems!r} without={baseline!r}"
    )
    assert assessment["assessments"][0]["status"] == lifecycle_status, (
        "validate_assessment must not mutate or downgrade the lifecycle status"
    )
