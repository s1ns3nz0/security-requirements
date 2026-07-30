import copy
from pathlib import Path
import sys

import yaml


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import confirmation  # noqa: E402


def profile():
    return {
        "version": "0.1.0",
        "locale": "en",
        "inferred": {"csp": "aws", "deployment_model": "serverless"},
        "declared": {"data_types": [{"id": "basic_contact"}]},
        "derived": {"baseline": "nist-800-53b-moderate"},
    }


def test_stamp_binds_confirmation_to_exact_profile():
    original = profile()
    stamped = confirmation.stamp(copy.deepcopy(original), "user", "2026-07-31T10:00:00Z")

    assert stamped["confirmation"] == {
        "status": "confirmed",
        "confirmed_by": "user",
        "confirmed_at": "2026-07-31T10:00:00Z",
        "profile_digest": confirmation.profile_digest(original),
    }
    assert confirmation.validate(stamped) == []


def test_profile_change_invalidates_confirmation():
    stamped = confirmation.stamp(profile(), "user", "2026-07-31T10:00:00Z")
    stamped["declared"]["data_types"].append({"id": "payment_card"})

    assert confirmation.validate(stamped) == [
        "profile changed after confirmation; run the confirmation gate again"
    ]


def test_missing_confirmation_is_rejected():
    assert confirmation.validate(profile()) == [
        "profile has no persisted confirmation"
    ]


def test_cli_check_rejects_unconfirmed_profile(tmp_path):
    path = tmp_path / "profile.yaml"
    path.write_text(yaml.safe_dump(profile()), encoding="utf-8")

    assert confirmation.main(["--check", str(path)]) == 1
