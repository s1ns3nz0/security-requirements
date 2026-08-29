"""Pre-extension regression tripwires for the security-design-review work.

These guards freeze the behaviour the planned extension must not move: the
golden risk reproduction (R2), the material digests (R4), and the two field
tuples that decide whether every existing confirmation survives (R1).

Nothing here is date-sensitive by construction — the digests under test are
taken over material content with the reviewable confirmation copy removed, and
the one test that could drift on a clock pins ``confirmed_at`` explicitly.
"""

import copy
from pathlib import Path
import sys

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
PLUGIN_ROOT = REPO_ROOT / "plugins" / "security-requirements"
sys.path.insert(0, str(PLUGIN_ROOT / "scripts"))

import risk  # noqa: E402
from risk_helpers import run_risk_golden  # noqa: E402


DEFAULT_POLICY_PATH = PLUGIN_ROOT / "risk" / "default-policy.yaml"
MOVIE_RATING_GOLDEN = REPO_ROOT / "golden" / "movie-rating-aws"

# Frozen at HEAD 0cfcabf, before any security-design-review extension lands.
# A change to any value below means the extension moved a material digest and
# would invalidate every existing confirmation on its first run.
BASELINE_POLICY_DIGEST = (
    "sha256:25be9ee86c4943aabff88908303e19fd480348c532cd2d44d6a219bbd7a2d8ac"
)
BASELINE_AGGREGATE_THREAT_DIGEST = (
    "sha256:24fc2ff306e6a9e0a7e64a9357762782e48f8bcca3c2c83d1e806dc45621c773"
)
BASELINE_THREAT_DIGESTS = {
    "T-01": "sha256:468056d2a0c432647ebfcc1f5c537024ccb8d0c4b4c0f2aa646738c9e02d877a",
    "T-02": "sha256:6c476636957e90b770c9babd35b3a107303cb4f2adbca947f83f97ae0c3ab708",
    "T-03": "sha256:c3b8a5c18cd19ad4b6f2eb5bc79e83a557c92537fd9b8fe4670cfcb841647bd6",
    "T-04": "sha256:8c68330c4be1a8be541019e99f435d6f0662038de0b40a79b0be3f5d0718787b",
    "T-05": "sha256:5cdde3b199a7c1b2914da4d15e6586788d185bd3e861f2bbfbcafc3292bf8221",
    "T-06": "sha256:fa287a19d723b2ff02de97e8bb6f1448b3808fb5e6e922dd6b028712d0b312be",
    "T-07": "sha256:39f607a25b37a5ff123405a8704ea47161cfc951693363fa9230a447e0557395",
    "T-08": "sha256:08700c0e948f8cbba07c84bc6e8d6e97f2e2194f233c3ccff8ea240836f8cb39",
}

# Frozen tuple membership, read from risk.py at HEAD 0cfcabf, not from the plan.
BASELINE_THREAT_DIGEST_FIELDS = (
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
BASELINE_INHERENT_REFRESH_FIELDS = (
    "scenario",
    "boundary",
    "persona",
    "attack_path",
    "affected_assets",
)

PINNED_CONFIRMED_AT = "2026-01-01T00:00:00+00:00"


def _golden_threat_document() -> dict:
    return yaml.safe_load(
        (MOVIE_RATING_GOLDEN / "threats.yaml").read_text(encoding="utf-8")
    )


def test_the_regression_baseline_freezes_the_digest_and_refresh_field_tuples():
    """R1 — the two tuples that decide whether confirmations survive."""

    assert risk.THREAT_DIGEST_FIELDS == BASELINE_THREAT_DIGEST_FIELDS
    assert risk.INHERENT_REFRESH_FIELDS == BASELINE_INHERENT_REFRESH_FIELDS

    # Both are tuples, so a later `+= (...)` is a visible edit rather than an
    # in-place mutation from somewhere else in the module.
    assert isinstance(risk.THREAT_DIGEST_FIELDS, tuple)
    assert isinstance(risk.INHERENT_REFRESH_FIELDS, tuple)

    # Every refresh field is also a digest field: a change that marks a
    # confirmed record STALE must also move its threat digest.
    assert set(risk.INHERENT_REFRESH_FIELDS) <= set(risk.THREAT_DIGEST_FIELDS)

    # The additive fields named in the plan stay outside both tuples.
    for field in ("evidence_status", "confidence", "attack_path_ids", "axis"):
        assert field not in risk.THREAT_DIGEST_FIELDS
        assert field not in risk.INHERENT_REFRESH_FIELDS


def test_the_regression_baseline_reproduces_the_movie_rating_golden_case():
    """R2 — the golden case still scores exactly as its expected document says."""

    expected = yaml.safe_load(
        (MOVIE_RATING_GOLDEN / "expected-risk.yaml").read_text(encoding="utf-8")
    )
    result = run_risk_golden(MOVIE_RATING_GOLDEN)

    assert result["assessments"] == expected["assessments"]
    assert len(result["assessments"]) == 8
    assert len(expected["assessments"]) == 8

    by_threat = {row["threat_id"]: row for row in result["assessments"]}
    for row in expected["assessments"]:
        actual = by_threat[row["threat_id"]]
        assert actual["likelihood"] == row["likelihood"]
        assert actual["impact"] == row["impact"]
        assert actual["score"] == row["score"]
        assert actual["rating"] == row["rating"]
        # score is the product the 5x5 engine promises, not a stored number.
        assert row["score"] == row["likelihood"] * row["impact"]

    assert result["inherent"] == expected["inherent"]
    assert result["residual"] == expected["residual"]
    assert result["inherent"]["overall"] == "high"
    assert result["coverage"] == expected["inherent"]["coverage"] == "8/8"
    assert result["temporary_root_removed"] is True


def test_the_regression_baseline_pins_the_golden_policy_and_threat_digests():
    """R4 — the pre-extension digest tripwire."""

    policy = risk.load_policy(DEFAULT_POLICY_PATH)
    assert risk.policy_digest(policy) == BASELINE_POLICY_DIGEST

    threats = _golden_threat_document()
    assert threats["version"] == "0.2.0"
    assert risk.aggregate_threat_digest(threats) == BASELINE_AGGREGATE_THREAT_DIGEST

    observed = {
        record["id"]: risk.threat_digest(record) for record in threats["threats"]
    }
    assert observed == BASELINE_THREAT_DIGESTS

    # The digests cover material content only: attaching a pinned confirmation
    # block leaves both the policy and the aggregate threat digest unmoved, so
    # these frozen values cannot drift with the clock.
    confirmed_policy = copy.deepcopy(policy)
    confirmed_policy["confirmation"] = {
        "status": "confirmed",
        "confirmed_by": "movie-rating-risk-owner",
        "confirmed_at": PINNED_CONFIRMED_AT,
        "authority": "self_declared",
    }
    assert risk.policy_digest(confirmed_policy) == BASELINE_POLICY_DIGEST

    stamped_threats = copy.deepcopy(threats)
    for record in stamped_threats["threats"]:
        record["lifecycle"] = dict(record.get("lifecycle") or {})
        record["lifecycle"]["confirmed_at"] = PINNED_CONFIRMED_AT
    assert (
        risk.aggregate_threat_digest(stamped_threats)
        == BASELINE_AGGREGATE_THREAT_DIGEST
    )
