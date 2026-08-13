from pathlib import Path
import sys

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
PLUGIN_ROOT = REPO_ROOT / "plugins" / "security-requirements"
sys.path.insert(0, str(PLUGIN_ROOT / "scripts"))

import risk  # noqa: E402
from risk_helpers import consequence, proposal  # noqa: E402


DEFAULT_POLICY_PATH = PLUGIN_ROOT / "risk" / "default-policy.yaml"


@pytest.fixture()
def default_policy():
    if not DEFAULT_POLICY_PATH.exists():
        pytest.fail(f"bundled policy is missing: {DEFAULT_POLICY_PATH}")
    return risk.load_policy(DEFAULT_POLICY_PATH)


@pytest.mark.parametrize(
    "likelihood,impact,lscore,iscore,score,rating",
    [
        ("L1-EXCEPTIONAL", "I1-LOCAL-RECOVERABLE", 1, 1, 1, "low"),
        ("L2-RESTRICTED", "I2-LIMITED-SCOPE", 2, 2, 4, "low"),
        (
            "L1-EXCEPTIONAL",
            "I5-ORGANISATION-IRREVERSIBLE",
            1,
            5,
            5,
            "medium",
        ),
        ("L3-AUTHENTICATED", "I3-CORE-SERVICE", 3, 3, 9, "medium"),
        (
            "L2-RESTRICTED",
            "I5-ORGANISATION-IRREVERSIBLE",
            2,
            5,
            10,
            "high",
        ),
        ("L4-PUBLIC-LOW-COMPLEXITY", "I4-CROSS-SYSTEM", 4, 4, 16, "high"),
        ("L5-DIRECT-AUTOMATABLE", "I4-CROSS-SYSTEM", 5, 4, 20, "critical"),
        (
            "L5-DIRECT-AUTOMATABLE",
            "I5-ORGANISATION-IRREVERSIBLE",
            5,
            5,
            25,
            "critical",
        ),
    ],
)
def test_default_policy_rating_boundaries(
    default_policy, likelihood, impact, lscore, iscore, score, rating
):
    result = risk.calculate_inherent(default_policy, proposal(likelihood, impact))
    assert result == {
        "likelihood": lscore,
        "impact": iscore,
        "score": score,
        "rating": rating,
    }


def test_unknown_or_mismatched_criterion_is_rejected(default_policy):
    with pytest.raises(risk.RiskValidationError, match="unknown likelihood criterion"):
        risk.calculate_inherent(
            default_policy, proposal("L9-MADE-UP", "I3-CORE-SERVICE")
        )


def test_policy_loads_as_mapping():
    policy = risk.load_policy(DEFAULT_POLICY_PATH)
    assert policy["version"] == "1.0.0"
    assert policy["publish_risk_summary"] is False


def test_overlapping_thresholds_are_rejected(default_policy):
    policy = dict(default_policy)
    policy["thresholds"] = [
        {"min": 1, "max": 5, "rating": "low"},
        {"min": 5, "max": 9, "rating": "medium"},
    ]
    with pytest.raises(risk.RiskValidationError, match="matches 2 thresholds"):
        risk.rating_for_score(policy, 5)


def test_gapped_thresholds_are_rejected(default_policy):
    policy = dict(default_policy)
    policy["thresholds"] = [
        {"min": 1, "max": 4, "rating": "low"},
        {"min": 6, "max": 9, "rating": "medium"},
    ]
    with pytest.raises(risk.RiskValidationError, match="matches 0 thresholds"):
        risk.rating_for_score(policy, 5)


@pytest.mark.parametrize("score", [0, 6])
def test_criterion_scores_must_be_between_one_and_five(default_policy, score):
    policy = dict(default_policy)
    policy["likelihood"] = dict(default_policy["likelihood"])
    policy["likelihood"]["L1-EXCEPTIONAL"] = {"score": score}
    with pytest.raises(risk.RiskValidationError, match="invalid score"):
        risk.criterion_score(policy, "likelihood", "L1-EXCEPTIONAL")


def test_missing_likelihood_rationale_is_rejected(default_policy):
    proposed = proposal("L3-AUTHENTICATED", "I3-CORE-SERVICE")
    proposed["likelihood"].pop("rationale")
    with pytest.raises(risk.RiskValidationError, match="likelihood rationale"):
        risk.calculate_inherent(default_policy, proposed)


def test_missing_consequence_rationale_is_rejected(default_policy):
    proposed = proposal("L3-AUTHENTICATED", "I3-CORE-SERVICE")
    proposed["consequences"][0].pop("rationale")
    with pytest.raises(risk.RiskValidationError, match="consequence rationale"):
        risk.calculate_inherent(default_policy, proposed)


def test_missing_consequences_are_rejected(default_policy):
    proposed = proposal("L3-AUTHENTICATED", "I3-CORE-SERVICE")
    proposed["consequences"] = []
    with pytest.raises(risk.RiskValidationError, match="at least one consequence"):
        risk.calculate_inherent(default_policy, proposed)


def test_incorrect_selected_consequence_is_rejected(default_policy):
    proposed = proposal("L3-AUTHENTICATED", "I3-CORE-SERVICE")
    proposed["impact"]["selected_from"] = "C-99"
    with pytest.raises(risk.RiskValidationError, match="selected_from"):
        risk.calculate_inherent(default_policy, proposed)


def test_canonical_digest_is_stable_under_mapping_reordering():
    left = {"z": [1, {"b": 2, "a": 3}], "a": "value"}
    right = {"a": "value", "z": [1, {"a": 3, "b": 2}]}
    assert risk.canonical_digest(left) == risk.canonical_digest(right)
