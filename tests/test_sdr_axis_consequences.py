"""Axis-tagged consequences and the derived CIA block (plan N2, N3).

These tests encode capability described in the security-design-review plan of
record (§5.3 axis-tagged consequences, §4.2 the ``cia`` block, §5.6 the
model-emitted delta). Most of that capability does not exist yet, so most of
these tests are expected to be RED.

They also pin down a collision the plan does not resolve. Plan §5.3 says each
consequence "gains ``axis: c | i | a``". The field already exists and the
vocabulary already in use is the LONG form -- ``confidentiality``,
``integrity``, ``availability`` -- see
``golden/movie-rating-aws/risk-assessment.yaml`` lines 24, 58, 91, 122, 152,
182, 213, 244, and ``tests/risk_helpers.py:20``. ``risk.py`` reads neither
form: every ``axis`` reference in that module names the likelihood/impact axis,
not a CIA axis. If the extension validates a closed set of the short letters,
the golden fixtures stop loading. The vocabulary decision belongs to the plan
owner; these tests only make the collision visible.
"""

from pathlib import Path
import sys

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
PLUGIN_ROOT = REPO_ROOT / "plugins" / "security-requirements"
sys.path.insert(0, str(PLUGIN_ROOT / "scripts"))

import risk  # noqa: E402


DEFAULT_POLICY_PATH = PLUGIN_ROOT / "risk" / "default-policy.yaml"

LONG_FORM_AXES = ("confidentiality", "integrity", "availability")
SHORT_FORM_AXES = ("c", "i", "a")


@pytest.fixture()
def policy() -> dict:
    if not DEFAULT_POLICY_PATH.exists():
        pytest.fail(f"bundled policy is missing: {DEFAULT_POLICY_PATH}")
    return risk.load_policy(DEFAULT_POLICY_PATH)


def _consequence(id: str, criterion: str, axis: str | None = None) -> dict:
    """A consequence built locally so the shared helper's axis is not assumed."""

    record = {
        "id": id,
        "asset": "movie_records",
        "criterion": criterion,
        "rationale": ["catalogue records are affected"],
    }
    if axis is not None:
        record["axis"] = axis
    return record


def _likelihood(criterion: str = "L4-PUBLIC-LOW-COMPLEXITY") -> dict:
    return {
        "criterion": criterion,
        "evidence": {
            "exposure": "public",
            "access_required": "none",
            "exploit_complexity": "low",
            "preconditions": ["route is reachable"],
            "observed_controls": [],
        },
        "rationale": ["the route is publicly reachable"],
    }


def _proposal(consequences: list[dict], selected_from: str) -> dict:
    return {
        "likelihood": _likelihood(),
        "consequences": consequences,
        "impact": {"selected_from": selected_from},
    }


def _confirmed_record(proposed: dict, **extra) -> dict:
    record = {"threat_id": "T-01", "status": "CONFIRMED", "proposed": proposed}
    record.update(extra)
    return record


def _axis_scores(block: dict) -> dict:
    """Read a ``cia`` block under either candidate key vocabulary."""

    pairs = zip(SHORT_FORM_AXES, LONG_FORM_AXES)
    return {
        short: block[short] if short in block else block.get(long)
        for short, long in pairs
    }


# --- N2: axis absence scores, unknown axis is rejected -----------------------


def test_consequence_without_an_axis_still_scores(policy):
    """N2-A. Omitting ``axis`` entirely must not change the arithmetic.

    Legacy records predate the field, so its absence stays legal.
    """

    proposed = _proposal(
        [_consequence("C-01", "I4-CROSS-SYSTEM")], selected_from="C-01"
    )

    calculated = risk.calculate_inherent(policy, proposed)

    assert calculated["likelihood"] == 4
    assert calculated["impact"] == 4
    assert calculated["score"] == 16
    assert calculated["rating"] == "high"


def test_unknown_consequence_axis_is_rejected(policy):
    """N2-B. An axis value outside the agreed vocabulary is a validation error.

    ``calculate_inherent`` is a calculation function, so the house convention
    (plan §10.1) is to raise ``RiskValidationError`` rather than return
    problems. Today the value is read by nothing and accepted silently.
    """

    proposed = _proposal(
        [_consequence("C-01", "I4-CROSS-SYSTEM", axis="banana")],
        selected_from="C-01",
    )

    with pytest.raises(risk.RiskValidationError) as excinfo:
        risk.calculate_inherent(policy, proposed)

    assert "axis" in str(excinfo.value).lower()


@pytest.mark.parametrize("axis", LONG_FORM_AXES)
def test_existing_long_form_axis_values_are_accepted(policy, axis):
    """N2-C. The vocabulary already on disk must keep scoring.

    This is the guard on the plan §5.3 wording. The golden fixtures and
    ``tests/risk_helpers.py`` write ``confidentiality``/``integrity``/
    ``availability``. A closed set of ``{c, i, a}`` would break every one of
    them, so this test fails the moment the short form is enforced alone.
    """

    proposed = _proposal(
        [_consequence("C-01", "I4-CROSS-SYSTEM", axis=axis)], selected_from="C-01"
    )

    calculated = risk.calculate_inherent(policy, proposed)

    assert calculated["score"] == 16
    assert calculated["rating"] == "high"


# --- N3: the derived cia block, and rejection of a literal one ---------------


def test_cia_block_is_derived_from_axis_tagged_consequences(policy):
    """N3-A. Per-axis scores fall out of the same consequence list.

    Plan §5.3 says ``max(C,I,A)`` falls out of the existing ``max(impacts)``:
    one engine, no parallel CIA scorer. That is a statement about *arithmetic
    reuse*, not about return shape. The contract of record is §4.2, where
    ``cia`` and ``calculated`` are **siblings** on the finding::

        "calculated": { "likelihood": 4, "impact": 4, ... },
        "cia":        { "c": 3, "i": 4, "a": 2, ... },

    So the derived block must not be nested inside the calculation result.
    Keeping it out is also what preserves the stored ``calculated`` contract at
    four keys, which ``risk_helpers._golden_report`` compares by exact equality
    (R2). An earlier draft of this test asserted the nested shape; it encoded a
    requirement the plan does not have.
    """

    proposed = _proposal(
        [
            _consequence("C-01", "I3-CORE-SERVICE", axis="confidentiality"),
            _consequence("C-02", "I4-CROSS-SYSTEM", axis="integrity"),
            _consequence("C-03", "I2-LIMITED-SCOPE", axis="availability"),
        ],
        selected_from="C-02",
    )

    calculated = risk.calculate_inherent(policy, proposed)
    assert "cia" not in calculated, (
        "the cia block is a sibling of calculated (§4.2), not a member of it; "
        "nesting it breaks the stored four-key calculated contract"
    )
    assert set(calculated) == {"likelihood", "impact", "score", "rating"}

    cia = risk.cia_scores(policy, proposed)

    assert _axis_scores(cia) == {"c": 3, "i": 4, "a": 2}
    assert calculated["impact"] == 4
    # The overall impact is the highest axis score: same arithmetic, one engine.
    assert calculated["impact"] == max(_axis_scores(cia).values())


def test_cia_derivation_omits_axes_no_consequence_claims(policy):
    """An untagged or unclaimed axis is absent, never a zero that scores."""

    proposed = _proposal(
        [
            _consequence("C-01", "I3-CORE-SERVICE", axis="integrity"),
            _consequence("C-02", "I2-LIMITED-SCOPE"),
        ],
        selected_from="C-01",
    )

    assert risk.cia_scores(policy, proposed) == {"i": 3}


def test_delta_carrying_a_literal_cia_object_is_rejected(policy):
    """N3-B. The model never emits a scored ``cia`` block; it is derived.

    Plan §5.6: the model emits criterion IDs and rationale, never ``score``,
    ``rating``, ``id``, or the verdict. ``_validated_calculation`` already
    rejects a declared ``calculated`` result that disagrees with policy, and a
    declared ``cia`` object is the same class of claim. That function returns
    ``list[str]``, matching the ``validate_*`` half of the house convention.
    """

    proposed = _proposal(
        [
            _consequence("C-01", "I3-CORE-SERVICE", axis="confidentiality"),
            _consequence("C-02", "I4-CROSS-SYSTEM", axis="integrity"),
        ],
        selected_from="C-02",
    )
    literal_cia = {"c": 1, "i": 1, "a": 1}

    on_record = risk._validated_calculation(
        "T-01", _confirmed_record(proposed, cia=dict(literal_cia)), policy
    )
    assert any(
        "cia" in problem.lower() for problem in on_record
    ), f"a literal cia object on the record was accepted: {on_record}"

    delta = dict(proposed, cia=dict(literal_cia))
    in_delta = risk._validated_calculation("T-01", _confirmed_record(delta), policy)
    assert any(
        "cia" in problem.lower() for problem in in_delta
    ), f"a literal cia object inside the delta was accepted: {in_delta}"


# --- N1: the worked example, end to end -------------------------------------


def _n1_consequences() -> list[dict]:
    """Plan §11.2 N1, written in the input vocabulary.

    N1 is spelled ``{c: I3}, {i: I4}, {a: I2}``, but the short letters are
    output keys, not input. Plan §5.3 is long form in, short form out: the
    authored ``axis`` values are the members of ``risk.CONSEQUENCE_AXES``
    (``risk.py:56``) and the letters are produced by ``risk.cia_scores`` through
    ``risk.CIA_OUTPUT_KEYS`` (``risk.py:59``). So ``{c: I3}`` is authored as
    ``axis="confidentiality"`` with criterion ``I3-CORE-SERVICE``.
    """

    return [
        _consequence("C-01", "I3-CORE-SERVICE", axis="confidentiality"),
        _consequence("C-02", "I4-CROSS-SYSTEM", axis="integrity"),
        _consequence("C-03", "I2-LIMITED-SCOPE", axis="availability"),
    ]


def test_three_axis_tagged_consequences_score_from_the_highest_axis(policy):
    """N1. L4 over confidentiality I3, integrity I4, availability I2.

    The whole worked example in one place: likelihood 4, impact 4 (integrity is
    the highest axis), score 16, rating "high". The impact is not the sum or
    the mean of the three axes, it is the max, which is the same ``max(impacts)``
    the untagged path already used.
    """

    proposed = _proposal(_n1_consequences(), selected_from="C-02")

    calculated = risk.calculate_inherent(policy, proposed)

    assert calculated["likelihood"] == 4
    assert calculated["impact"] == 4
    assert calculated["score"] == 16
    assert calculated["rating"] == "high"


def test_axis_tagged_scoring_keeps_the_four_key_calculated_contract(policy):
    """N1. The derived block is a sibling; ``calculated`` stays at four keys.

    Load-bearing: ``risk_helpers._golden_report`` compares a stored
    ``calculated`` block by exact equality, so a fifth key -- ``cia`` most of
    all -- breaks every golden fixture. ``risk.cia_scores`` is the separate
    entry point, and its values feed the same arithmetic: the overall impact is
    the largest of them, not a second opinion computed elsewhere.
    """

    proposed = _proposal(_n1_consequences(), selected_from="C-02")

    calculated = risk.calculate_inherent(policy, proposed)
    cia = risk.cia_scores(policy, proposed)

    assert list(calculated) == ["likelihood", "impact", "score", "rating"]
    assert "cia" not in calculated
    assert _axis_scores(cia) == {"c": 3, "i": 4, "a": 2}
    assert calculated["impact"] == max(_axis_scores(cia).values())


@pytest.mark.parametrize(
    ("selected_from", "axis"),
    [("C-01", "confidentiality"), ("C-03", "availability")],
)
def test_impact_selected_from_must_name_the_highest_axis_consequence(
    policy, selected_from, axis
):
    """N1. Naming any axis below integrity is rejected, not silently corrected.

    ``selected_from`` is the author's claim about which consequence drives the
    impact. When it disagrees with the arithmetic the claim is wrong, and
    ``calculate_inherent`` is a calculation function, so the house convention
    (plan §10.1) is to raise ``RiskValidationError`` rather than return
    problems or quietly score the max anyway.
    """

    proposed = _proposal(_n1_consequences(), selected_from=selected_from)

    with pytest.raises(risk.RiskValidationError) as excinfo:
        risk.calculate_inherent(policy, proposed)

    assert str(excinfo.value) == (
        "impact selected_from must identify the highest consequence"
    ), f"the {axis} consequence was accepted as the impact driver"


def test_impact_selected_from_names_the_integrity_consequence(policy):
    """N1. The counterpart: the highest axis is the one that is accepted.

    Paired with the rejection above so the error is known to be about *which*
    consequence was named, not about axis tagging making the check stricter.
    """

    proposed = _proposal(_n1_consequences(), selected_from="C-02")
    integrity_ids = [
        row["id"] for row in _n1_consequences() if row["axis"] == "integrity"
    ]

    assert integrity_ids == ["C-02"]
    assert risk.calculate_inherent(policy, proposed)["impact"] == 4
