"""CIA floor tests for the security design review (plan F6, F7, §7.4, §7.5).

These tests target capability that does not exist yet. They are expected to be
RED. Nothing here writes or patches production code.

Two ids are covered:

* **N5** — a raise above the floor requires a written reason, and a
  whitespace-only reason is rejected (plan F7, §7 constraint 5).
* **N6** — editing the floor in policy data moves floors with no code change,
  and `policy_digest` changes with it (plan §9 change point 3, §10.1 OCP).

Shapes encoded here follow the **source**, not the plan, wherever the two
disagree:

* Consequence `axis` already exists in `golden/movie-rating-aws/risk-assessment.yaml`
  and `tests/risk_helpers.py:20` with LONG-FORM values
  (`confidentiality | integrity | availability`), not the `c | i | a` of plan
  §5.3. Long form is used below.
* `profile.yaml` carries no `impact` key at all. FIPS 199 impact is *derived* by
  `select_baseline.py`, which emits
  `{confidentiality: {level, because}, integrity: {...}, availability: {...},
  system: ...}` with levels drawn from `select_baseline.LEVELS`
  (`low | moderate | high`). That derived mapping — not the `impact.c/i/a` of
  plan §5.1 — is what the floor is fed here.

The house error convention is followed: calculation functions raise
`RiskValidationError`; `validate_*` returns `list[str]`.

Intended (not yet existing) surfaces under test:

* ``risk.impact_floor(policy, level)`` -> int, a pure lookup into the policy
  document's ``impact_floor`` map.
* ``risk.calculate_inherent(policy, proposed, profile_impact=<derived impact>)``
  — one engine, per plan §5.3 "no parallel CIA scorer".
* A consequence scored above its axis floor carries ``raise_reason``, a
  non-empty list of non-blank strings, exactly like every other rationale field
  the repo already validates through ``risk._require_rationale``.
"""

from __future__ import annotations

import copy
from pathlib import Path
import sys

import pytest
import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
PLUGIN_ROOT = REPO_ROOT / "plugins" / "security-requirements"
sys.path.insert(0, str(PLUGIN_ROOT / "scripts"))

import risk  # noqa: E402


DEFAULT_POLICY_PATH = PLUGIN_ROOT / "risk" / "default-policy.yaml"
APPETITE_DIR = PLUGIN_ROOT / "risk" / "appetite"

# Plan F6 / §5.5: low -> 2, moderate -> 3, high -> 4.
STANDARD_IMPACT_FLOOR = {"low": 2, "moderate": 3, "high": 4}
# The same policy document with one edit, and only one: the moderate floor.
RAISED_IMPACT_FLOOR = {"low": 2, "moderate": 4, "high": 5}


def _profile_impact(level: str) -> dict:
    """Build the derived FIPS 199 impact block `select_baseline.py` emits."""

    return {
        "confidentiality": {"level": level, "because": ["pinned for the test"]},
        "integrity": {"level": level, "because": ["pinned for the test"]},
        "availability": {"level": level, "because": ["pinned for the test"]},
        "system": level,
        "overridden_by_user": False,
        "override_reason": None,
        "driver": None,
    }


def _consequence(
    id: str,
    criterion: str,
    axis: str = "confidentiality",
    **changes,
) -> dict:
    """Local copy of the house consequence builder (helpers are not edited)."""

    record = {
        "id": id,
        "asset": "movie_records",
        "axis": axis,
        "criterion": criterion,
        "rationale": ["catalogue records are affected"],
    }
    record.update(changes)
    return record


def _proposal(likelihood: str, consequences: list[dict]) -> dict:
    """Local copy of the house proposal builder, with explicit consequences."""

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
        "consequences": consequences,
        "impact": {"selected_from": consequences[0]["id"]},
    }


def _write_policy(tmp_path: Path, name: str, impact_floor: dict) -> dict:
    """Write an appetite policy that differs from default only by the floor."""

    policy = copy.deepcopy(risk.load_policy(DEFAULT_POLICY_PATH))
    policy["impact_floor"] = copy.deepcopy(impact_floor)
    policy["release_threshold_rating"] = "high"
    path = tmp_path / name
    path.write_text(
        yaml.safe_dump(policy, allow_unicode=True, sort_keys=False), encoding="utf-8"
    )
    return risk.load_policy(path)


@pytest.fixture()
def standard_policy(tmp_path: Path) -> dict:
    return _write_policy(tmp_path, "standard.yaml", STANDARD_IMPACT_FLOOR)


@pytest.fixture()
def raised_policy(tmp_path: Path) -> dict:
    return _write_policy(tmp_path, "raised.yaml", RAISED_IMPACT_FLOOR)


# ---------------------------------------------------------------------------
# N5 — a raise above the floor requires a written reason
# ---------------------------------------------------------------------------


def test_the_house_rationale_helper_rejects_a_whitespace_only_raise_above_the_floor_reason() -> None:
    """Anchor the convention the raise reason must follow.

    `risk._require_rationale` already rejects a non-sequence, a bare string, an
    empty list, a non-string member, and a whitespace-only member. The raise
    reason of plan §7 constraint 5 is the same shape and must reuse it rather
    than fork a second rule.
    """

    risk._require_rationale(["the asset is a public catalogue"], "raise")

    for rejected in (None, "a string", [], [""], ["   "], ["\t\n"], [1], ["ok", "  "]):
        with pytest.raises(risk.RiskValidationError):
            risk._require_rationale(rejected, "raise")


def test_a_raise_above_the_floor_requires_a_written_reason(standard_policy: dict) -> None:
    """Plan F7 / §7 constraint 5. Floor 3; a confidentiality I4 is a raise."""

    proposed = _proposal(
        "L2-RESTRICTED",
        [_consequence("C-01", "I4-CROSS-SYSTEM", axis="confidentiality")],
    )

    with pytest.raises(risk.RiskValidationError):
        risk.calculate_inherent(
            standard_policy,
            proposed,
            profile_impact=_profile_impact("moderate"),
        )


def test_a_raise_above_the_floor_with_a_whitespace_only_reason_is_rejected(
    standard_policy: dict,
) -> None:
    """Plan §7 constraint 5 names the whitespace-only reason explicitly."""

    for blank in ([" "], ["\t"], ["\n"], ["   ", "also blank  "], [""]):
        proposed = _proposal(
            "L2-RESTRICTED",
            [
                _consequence(
                    "C-01",
                    "I4-CROSS-SYSTEM",
                    axis="confidentiality",
                    raise_reason=blank,
                )
            ],
        )
        with pytest.raises(risk.RiskValidationError):
            risk.calculate_inherent(
                standard_policy,
                proposed,
                profile_impact=_profile_impact("moderate"),
            )


def test_a_raise_above_the_floor_with_a_written_reason_is_accepted(
    standard_policy: dict,
) -> None:
    """The reason is a gate, not a ban: a written one lets the raise through."""

    proposed = _proposal(
        "L2-RESTRICTED",
        [
            _consequence(
                "C-01",
                "I4-CROSS-SYSTEM",
                axis="confidentiality",
                raise_reason=["the table holds unreleased titles under embargo"],
            )
        ],
    )

    result = risk.calculate_inherent(
        standard_policy,
        proposed,
        profile_impact=_profile_impact("moderate"),
    )

    assert result["impact"] == 4
    assert result["likelihood"] == 2
    assert result["score"] == 8
    assert result["rating"] == "medium"


def test_a_score_at_the_floor_needs_no_raise_above_the_floor_reason(
    standard_policy: dict,
) -> None:
    """Only a raise is gated. Sitting exactly on the floor is unremarkable."""

    proposed = _proposal(
        "L2-RESTRICTED",
        [_consequence("C-01", "I3-CORE-SERVICE", axis="confidentiality")],
    )

    result = risk.calculate_inherent(
        standard_policy,
        proposed,
        profile_impact=_profile_impact("moderate"),
    )

    assert result["impact"] == 3
    assert result["score"] == 6
    assert result["rating"] == "medium"


# ---------------------------------------------------------------------------
# N6 — the floor is policy data (OCP)
# ---------------------------------------------------------------------------


def test_the_impact_floor_is_read_from_policy_data(standard_policy: dict) -> None:
    """Plan F6 / §5.5: low -> 2, moderate -> 3, high -> 4, from the document."""

    assert risk.impact_floor(standard_policy, "low") == 2
    assert risk.impact_floor(standard_policy, "moderate") == 3
    assert risk.impact_floor(standard_policy, "high") == 4


def test_editing_the_impact_floor_in_policy_data_moves_the_floor_with_no_code_change(
    standard_policy: dict, raised_policy: dict
) -> None:
    """Plan §9 change point 3, §10.1 OCP.

    Two policy documents, identical but for `impact_floor`. The same engine
    function is called both times — no branch, no second scorer. Under the
    standard floor a confidentiality I3 sits exactly on the floor; under the
    raised floor the same record is below it and is rejected, never clamped
    (plan §7 constraint 4).
    """

    difference = {
        key
        for key in set(standard_policy) | set(raised_policy)
        if standard_policy.get(key) != raised_policy.get(key)
    }
    assert difference == {"impact_floor"}

    assert risk.impact_floor(standard_policy, "moderate") == 3
    assert risk.impact_floor(raised_policy, "moderate") == 4

    proposed = _proposal(
        "L2-RESTRICTED",
        [_consequence("C-01", "I3-CORE-SERVICE", axis="confidentiality")],
    )
    profile_impact = _profile_impact("moderate")

    accepted = risk.calculate_inherent(
        standard_policy, copy.deepcopy(proposed), profile_impact=profile_impact
    )
    assert accepted["impact"] == 3

    with pytest.raises(risk.RiskValidationError):
        risk.calculate_inherent(
            raised_policy, copy.deepcopy(proposed), profile_impact=profile_impact
        )


def test_editing_the_impact_floor_in_policy_data_changes_the_policy_digest(
    standard_policy: dict, raised_policy: dict
) -> None:
    """A moved floor is a different policy, and the snapshot must say so."""

    assert risk.policy_digest(standard_policy) != risk.policy_digest(raised_policy)
    assert risk.policy_digest(standard_policy) == risk.policy_digest(
        copy.deepcopy(standard_policy)
    )


def test_the_shipped_appetite_policy_data_defines_an_impact_floor() -> None:
    """Plan §5.5: three appetite files, each carrying the four policy keys.

    `standard` must reproduce today's `default-policy.yaml` thresholds exactly.
    """

    default_policy = risk.load_policy(DEFAULT_POLICY_PATH)

    for name in ("conservative", "standard", "tolerant"):
        path = APPETITE_DIR / f"{name}.yaml"
        assert path.is_file(), f"missing appetite policy: {path}"
        policy = risk.load_policy(path)
        assert set(policy) >= {
            "thresholds",
            "impact_floor",
            "release_threshold_rating",
            "publish_risk_summary",
        }
        assert set(policy["impact_floor"]) == {"low", "moderate", "high"}

    standard = risk.load_policy(APPETITE_DIR / "standard.yaml")
    assert standard["thresholds"] == default_policy["thresholds"]
    assert standard["impact_floor"] == STANDARD_IMPACT_FLOOR
