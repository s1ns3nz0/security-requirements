"""N9 / N10 — cross-threat attack-path linking (F11).

Plan of record §11.2 "Attack paths": **N9** a path over two threats puts its id
on both findings and ``combined_rating`` is at least the highest participating
rating; **N10** a path referencing a retired or superseded threat is rejected.
§7 constraint 13/14 puts a step naming a threat absent from the document in the
same class of error.

The module under test does not exist yet. These tests are the specification, so
they are RED by construction: the import is guarded only so the file still
*collects*, and every test that needs the module fails with a message naming
``scripts/sdr_attack_paths.py``. Nothing here skips — a skipped test is
invisible.

Pinned surface (plan §10, F11 row — ``scripts/sdr_attack_paths.py`` +
``attack-paths.yaml``):

    validate_attack_paths(document, threats_doc) -> list[str]
    link_attack_paths(document) -> dict[str, list[str]]
    combined_rating(path_id, document, assessment, policy) -> str

``validate_*`` returns a list of problem strings and never raises: the house
error convention recorded in plan §10.1 and verified against ``risk.py``
(``validate_assessment``, ``validate_treatment``).

Vocabularies are read from ``risk.py``, never invented:

* rating order — ``risk.RATINGS`` (``risk.py:38``) is ordered most-severe-first,
  ``("critical", "high", "medium", "low")``. ``risk.py`` ranks by
  ``RATINGS.index`` (see ``risk.py:1546``, ``risk.py:1035``), so a *lower* index
  is a *higher* rating. There is no public rank helper; ``RATINGS.index`` is it.
* threat lifecycle — ``risk._lifecycle_status`` (``risk.py:673``) closes the
  vocabulary at ``{active, retired, superseded}``, and ``risk.active_threats``
  (``risk.py:688``) requires a ``superseded`` record to carry a non-empty
  ``lifecycle.superseded_by`` naming known threat IDs.

Builders are local on purpose: ``tests/risk_helpers.py`` and
``tests/conftest.py`` are shared, and two other agents are adding test files in
parallel. This file adds nothing to either.
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


try:  # The module ships with F11 and does not exist yet.
    import sdr_attack_paths as _sdr_attack_paths
except ImportError as exc:  # pragma: no cover - the RED path, exercised today
    _sdr_attack_paths = None
    _IMPORT_ERROR: ImportError | None = exc
else:  # pragma: no cover - the GREEN path, once F11 lands
    _IMPORT_ERROR = None


DEFAULT_POLICY_PATH = PLUGIN_ROOT / "risk" / "default-policy.yaml"

#: Read from risk.py, not invented. Most severe first.
EXPECTED_RATING_ORDER = ("critical", "high", "medium", "low")

#: Read from risk._lifecycle_status (risk.py:681).
EXPECTED_LIFECYCLE_STATUSES = {"active", "retired", "superseded"}

#: Plan §5.4 — attack-paths.yaml is a NEW document, so no version bump is
#: implied anywhere; it declares the same 0.2.0 the store already uses.
ATTACK_PATHS_VERSION = "0.2.0"


def attack_paths():
    """The module under test, or a failure naming what is missing.

    Called inside the test body rather than through a fixture: a fixture that
    raises is reported by pytest as an ERROR, and this must read as a FAILURE
    against a named, missing capability.
    """

    if _sdr_attack_paths is None:
        raise AssertionError(
            "F11 is not implemented: "
            "plugins/security-requirements/scripts/sdr_attack_paths.py is "
            "missing, so validate_attack_paths / link_attack_paths / "
            f"combined_rating cannot be exercised ({_IMPORT_ERROR})"
        )
    return _sdr_attack_paths


def rank(rating: str) -> int:
    """Severity rank from the engine's own ordering. Lower is more severe."""

    return risk.RATINGS.index(rating)


@pytest.fixture(scope="module")
def default_policy() -> dict:
    return risk.load_policy(DEFAULT_POLICY_PATH)


# --------------------------------------------------------------------------
# Local builders
# --------------------------------------------------------------------------


def _threat(threat_id: str, status: str = "active", **changes) -> dict:
    """A minimally complete threat record at threat schema 0.2.0."""

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
        "lifecycle": {"status": status, "superseded_by": []},
    }
    record.update(changes)
    return record


def _superseded(threat_id: str, by: list[str]) -> dict:
    """A superseded record shaped the way active_threats demands."""

    return _threat(threat_id, lifecycle={"status": "superseded", "superseded_by": by})


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


def _assessment_doc(policy: dict, proposals: dict[str, dict]) -> dict:
    """Confirmed records whose `calculated` block is engine-derived, not typed."""

    return {
        "assessments": [
            {
                "threat_id": threat_id,
                "status": "CONFIRMED",
                "proposed": copy.deepcopy(proposed),
                "calculated": risk.calculate_inherent(policy, copy.deepcopy(proposed)),
            }
            for threat_id, proposed in proposals.items()
        ]
    }


def _path(path_id: str, title: str, steps: list[str]) -> dict:
    return {"id": path_id, "title": title, "steps": list(steps)}


def _paths_doc(*paths: dict) -> dict:
    return {
        "version": ATTACK_PATHS_VERSION,
        "attack_paths": [copy.deepcopy(p) for p in paths],
    }


AP_01 = _path(
    "AP-01",
    "Anonymous order tamper to payment capture mismatch",
    ["T-01", "T-02"],
)
AP_02 = _path(
    "AP-02",
    "Payment capture mismatch to ledger drift",
    ["T-02", "T-03"],
)


# --------------------------------------------------------------------------
# Vocabulary anchors — these pin what the rest of the file asserts against.
# --------------------------------------------------------------------------


def test_the_engine_rating_order_is_critical_high_medium_low_most_severe_first():
    """risk.py:38. `combined_rating` is compared against this, not a local list."""

    assert risk.RATINGS == EXPECTED_RATING_ORDER
    assert rank("critical") < rank("high") < rank("medium") < rank("low")


def test_the_threat_lifecycle_vocabulary_is_active_retired_superseded(default_policy):
    """risk._lifecycle_status (risk.py:673) closes the vocabulary at three."""

    for status in sorted(EXPECTED_LIFECYCLE_STATUSES):
        assert risk._lifecycle_status(_threat("T-01", status)) == status
    with pytest.raises(risk.RiskValidationError, match="unknown lifecycle status"):
        risk._lifecycle_status(_threat("T-01", "deprecated"))

    # active_threats drops retired and superseded records from the current set.
    threats = _threats_doc(
        _threat("T-01"),
        _threat("T-04", "retired"),
        _superseded("T-05", ["T-01"]),
    )
    assert [record["id"] for record in risk.active_threats(threats)] == ["T-01"]


# --------------------------------------------------------------------------
# N9 — a path over two threats puts its id on both findings.
# --------------------------------------------------------------------------


def test_a_path_over_two_threats_puts_its_id_on_both_participating_findings():
    module = attack_paths()

    links = module.link_attack_paths(_paths_doc(AP_01))

    assert links["T-01"] == ["AP-01"], (
        "T-01 is step 1 of AP-01 and must carry the path id: " f"{links!r}"
    )
    assert links["T-02"] == ["AP-01"], (
        "T-02 is step 2 of AP-01 and must carry the same path id: " f"{links!r}"
    )


def test_a_threat_in_no_attack_path_maps_to_an_empty_list_not_a_missing_key():
    """`link_attack_paths` receives only the attack-paths document, so the
    mapping it returns must default an unlisted threat to ``[]`` rather than
    raising ``KeyError`` — a missing key would force every caller to guess
    between "no paths" and "unknown threat"."""

    module = attack_paths()

    links = module.link_attack_paths(_paths_doc(AP_01))

    try:
        unlisted = links["T-99"]
    except KeyError:  # pragma: no cover - the assertion below carries the message
        raise AssertionError(
            "a threat that participates in no attack path raised KeyError; it "
            "must map to an empty list"
        )
    assert unlisted == [], f"expected [] for a threat in no path, got {unlisted!r}"


def test_attack_path_ids_come_back_sorted_when_a_threat_joins_two_paths():
    """Determinism: T-02 is in both paths, declared AP-02 first in the document."""

    module = attack_paths()

    links = module.link_attack_paths(_paths_doc(AP_02, AP_01))

    assert links["T-02"] == ["AP-01", "AP-02"], (
        "membership must come back sorted regardless of declaration order, "
        f"otherwise every rendered finding churns: {links!r}"
    )
    assert links["T-01"] == ["AP-01"]
    assert links["T-03"] == ["AP-02"]


def test_combined_rating_is_at_least_the_highest_participating_rating(default_policy):
    """AP-01 runs a medium threat into a high one, so it is high or critical."""

    module = attack_paths()
    document = _paths_doc(AP_01)
    assessment = _assessment_doc(
        default_policy,
        {
            "T-01": _proposal("L3-AUTHENTICATED", "I2-LIMITED-SCOPE"),
            "T-02": _proposal("L4-PUBLIC-LOW-COMPLEXITY", "I4-CROSS-SYSTEM"),
        },
    )
    participating = {
        record["threat_id"]: record["calculated"]["rating"]
        for record in assessment["assessments"]
    }
    # Anchored on the engine, not on this file's arithmetic.
    assert participating == {"T-01": "medium", "T-02": "high"}
    assert risk.rating_for_score(default_policy, 6) == "medium"
    assert risk.rating_for_score(default_policy, 16) == "high"

    result = module.combined_rating("AP-01", document, assessment, default_policy)

    highest = min(rank(rating) for rating in participating.values())
    assert rank(result) <= highest, (
        f"AP-01 combines {participating} so its rating must be at least "
        f"{risk.RATINGS[highest]!r}, got {result!r}"
    )


def test_combined_rating_returns_a_member_of_the_engine_rating_vocabulary(
    default_policy,
):
    module = attack_paths()
    document = _paths_doc(AP_01)
    assessment = _assessment_doc(
        default_policy,
        {
            "T-01": _proposal("L3-AUTHENTICATED", "I2-LIMITED-SCOPE"),
            "T-02": _proposal("L4-PUBLIC-LOW-COMPLEXITY", "I4-CROSS-SYSTEM"),
        },
    )

    result = module.combined_rating("AP-01", document, assessment, default_policy)

    assert result in risk.RATINGS, (
        "combined_rating must speak the engine vocabulary "
        f"{risk.RATINGS}, got {result!r}"
    )


# --------------------------------------------------------------------------
# N10 — a path referencing a retired or superseded threat is rejected.
# --------------------------------------------------------------------------


def _reported(problems: list[str], *fragments: str) -> list[str]:
    return [
        problem
        for problem in problems
        if all(fragment in problem for fragment in fragments)
    ]


def test_validate_attack_paths_returns_a_problem_list_and_never_raises():
    """House convention, plan §10.1: `validate_*` returns list[str]."""

    module = attack_paths()
    threats = _threats_doc(_threat("T-01"), _threat("T-04", "retired"))

    problems = module.validate_attack_paths(
        _paths_doc(_path("AP-01", "retired step", ["T-01", "T-04"])), threats
    )

    assert isinstance(problems, list), f"expected list[str], got {type(problems)!r}"
    assert all(isinstance(problem, str) for problem in problems), problems


def test_a_path_over_active_threats_alone_reports_no_problems():
    module = attack_paths()
    threats = _threats_doc(_threat("T-01"), _threat("T-02"), _threat("T-03"))

    problems = module.validate_attack_paths(_paths_doc(AP_01, AP_02), threats)

    assert problems == [], (
        "AP-01 and AP-02 step only through active threats: " + "; ".join(problems)
    )


def test_a_path_step_naming_a_retired_threat_is_reported_with_both_ids():
    module = attack_paths()
    threats = _threats_doc(_threat("T-01"), _threat("T-04", "retired"))
    document = _paths_doc(_path("AP-07", "steps through a retired threat", ["T-01", "T-04"]))

    problems = module.validate_attack_paths(document, threats)

    assert problems, "a path stepping through a retired threat must be rejected"
    matched = _reported(problems, "AP-07", "T-04")
    assert matched, (
        "the problem must name the offending path id AND the offending threat "
        f"id, otherwise it cannot be acted on: {problems!r}"
    )
    assert not _reported(problems, "T-01"), (
        f"T-01 is active and must not be reported: {problems!r}"
    )


def test_a_path_step_naming_a_superseded_threat_is_reported_with_both_ids():
    module = attack_paths()
    threats = _threats_doc(_threat("T-01"), _superseded("T-05", ["T-01"]))
    document = _paths_doc(
        _path("AP-08", "steps through a superseded threat", ["T-05", "T-01"])
    )

    problems = module.validate_attack_paths(document, threats)

    assert problems, "a path stepping through a superseded threat must be rejected"
    matched = _reported(problems, "AP-08", "T-05")
    assert matched, (
        "the problem must name the offending path id AND the offending threat "
        f"id: {problems!r}"
    )


def test_a_path_step_naming_a_threat_absent_from_the_document_is_reported_with_both_ids():
    """§7 constraint 13 — a reference to an id the document does not define."""

    module = attack_paths()
    threats = _threats_doc(_threat("T-01"))
    document = _paths_doc(_path("AP-09", "steps through an unknown threat", ["T-01", "T-42"]))

    problems = module.validate_attack_paths(document, threats)

    assert problems, "a path step naming an unknown threat id must be rejected"
    matched = _reported(problems, "AP-09", "T-42")
    assert matched, (
        "the problem must name the offending path id AND the missing threat "
        f"id: {problems!r}"
    )


def test_every_offending_step_is_reported_not_just_the_first():
    module = attack_paths()
    threats = _threats_doc(
        _threat("T-01"),
        _threat("T-04", "retired"),
        _superseded("T-05", ["T-01"]),
    )
    document = _paths_doc(
        _path("AP-10", "retired then superseded", ["T-04", "T-05"]),
        _path("AP-11", "unknown step", ["T-42"]),
    )

    problems = module.validate_attack_paths(document, threats)

    for path_id, threat_id in (
        ("AP-10", "T-04"),
        ("AP-10", "T-05"),
        ("AP-11", "T-42"),
    ):
        assert _reported(problems, path_id, threat_id), (
            f"{path_id} step {threat_id} was not reported; validate_* must "
            f"report every problem, not stop at the first: {problems!r}"
        )


# --------------------------------------------------------------------------
# R5 tripwire — attack-path membership must never move a threat digest.
#
# Plan §5.2: `attack_path_ids` lives deliberately OUTSIDE THREAT_DIGEST_FIELDS
# and INHERENT_REFRESH_FIELDS. A field added to either tuple invalidates every
# existing confirmation on the first run, which is how F11 stops being additive.
# --------------------------------------------------------------------------


def test_attack_path_membership_does_not_move_a_threat_digest():
    before = _threat("T-01")
    baseline = risk.threat_digest(before)

    after = _threat("T-01", attack_path_ids=["AP-01", "AP-02"])

    assert risk.threat_digest(after) == baseline, (
        "attack-path membership moved the threat digest, so every existing "
        "confirmation binding breaks on the first run: attack_path_ids has "
        f"entered THREAT_DIGEST_FIELDS ({risk.THREAT_DIGEST_FIELDS})"
    )
    assert risk.aggregate_threat_digest(
        _threats_doc(after)
    ) == risk.aggregate_threat_digest(_threats_doc(before)), (
        "attack-path membership moved the aggregate threat digest"
    )


def test_attack_path_ids_stays_outside_the_digest_and_refresh_tuples():
    assert "attack_path_ids" not in risk.THREAT_DIGEST_FIELDS, (
        "attack_path_ids entered THREAT_DIGEST_FIELDS; every aggregate "
        f"confirmation dies on the first run: {risk.THREAT_DIGEST_FIELDS}"
    )
    assert "attack_path_ids" not in risk.INHERENT_REFRESH_FIELDS, (
        "attack_path_ids entered INHERENT_REFRESH_FIELDS; refresh_assessment "
        f"will stale confirmed records it used to keep: "
        f"{risk.INHERENT_REFRESH_FIELDS}"
    )


def test_adding_attack_path_membership_stales_no_confirmed_record(default_policy):
    """The death scenario in miniature: last run's document had no membership."""

    previous = _threats_doc(_threat("T-01"), _threat("T-02"))
    current = _threats_doc(
        _threat("T-01", attack_path_ids=["AP-01"]),
        _threat("T-02", attack_path_ids=["AP-01"]),
    )
    assessment = _assessment_doc(
        default_policy,
        {
            "T-01": _proposal("L3-AUTHENTICATED", "I2-LIMITED-SCOPE"),
            "T-02": _proposal("L4-PUBLIC-LOW-COMPLEXITY", "I4-CROSS-SYSTEM"),
        },
    )

    refreshed = risk.refresh_assessment(previous, current, copy.deepcopy(assessment))

    stale = [
        record["threat_id"]
        for record in refreshed["assessments"]
        if record.get("status") == "STALE"
    ]
    assert stale == [], (
        f"adding attack_path_ids staled {stale}: attack-path membership reached "
        "INHERENT_REFRESH_FIELDS"
    )
