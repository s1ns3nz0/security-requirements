import copy
import os
from pathlib import Path
import subprocess
import sys

import pytest
import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
PLUGIN_ROOT = REPO_ROOT / "plugins" / "security-requirements"
sys.path.insert(0, str(PLUGIN_ROOT / "scripts"))

import risk  # noqa: E402
from risk_helpers import assessment_record, consequence, proposal, threat_record  # noqa: E402


DEFAULT_POLICY_PATH = PLUGIN_ROOT / "risk" / "default-policy.yaml"


class _RiskFixture:
    def __init__(self, project: Path):
        self.paths = {
            "project_root": project,
            "policy": project / ".security-requirements" / "risk-policy.yaml",
            "threats": project / ".security-requirements" / "threats.yaml",
            "assessment": project
            / ".security-requirements"
            / "risk-assessment.yaml",
        }
        self.paths["policy"].parent.mkdir(parents=True)
        self.paths["policy"].write_text(
            DEFAULT_POLICY_PATH.read_text(encoding="utf-8"), encoding="utf-8"
        )
        self.threats = {
            "version": "0.2.0",
            "threats": [threat_record("T-01")],
        }
        proposed = proposal("L4-PUBLIC-LOW-COMPLEXITY", "I4-CROSS-SYSTEM")
        self.assessment = {
            "assessments": [assessment_record("T-01", "PROPOSED", proposed=proposed)]
        }
        self._write_documents()

    def _write_documents(self):
        self.paths["threats"].write_text(
            yaml.safe_dump(self.threats, sort_keys=False), encoding="utf-8"
        )
        self.paths["assessment"].write_text(
            yaml.safe_dump(self.assessment, sort_keys=False), encoding="utf-8"
        )

    def confirm_all(self):
        risk.stamp_policy(
            self.paths,
            "risk-owner",
            "self_declared",
            confirmed_at="2026-08-13T00:00:00Z",
        )
        self.assessment = risk.stamp_assessment(
            self.paths,
            "risk-owner",
            "self_declared",
            confirmed_at="2026-08-13T00:01:00Z",
        )

    def change_threat(self, threat_id: str, **changes):
        for threat in self.threats["threats"]:
            if threat["id"] == threat_id:
                threat.update(changes)
                self.paths["threats"].write_text(
                    yaml.safe_dump(self.threats, sort_keys=False), encoding="utf-8"
                )
                return
        raise AssertionError(f"unknown fixture threat: {threat_id}")

    def write_repo_confirmation_without_external_state(self):
        document = copy.deepcopy(self.assessment)
        document["confirmation"] = {
            "status": "confirmed",
            "confirmed_by": "attacker",
            "confirmed_at": "2026-08-13T00:00:00Z",
            "authority": "self_declared",
            "project": str(self.paths["project_root"].resolve()),
            "policy_digest": "sha256:forged",
            "threat_digest": "sha256:forged",
            "assessment_digest": "sha256:forged",
        }
        self.paths["assessment"].write_text(
            yaml.safe_dump(document, sort_keys=False), encoding="utf-8"
        )


@pytest.fixture()
def risk_fixture(tmp_path, monkeypatch):
    project = tmp_path / "project with spaces 한글"
    monkeypatch.setenv("SECURITY_REQUIREMENTS_DATA", str(tmp_path / "trusted state"))
    monkeypatch.delenv("CLAUDE_PLUGIN_DATA", raising=False)
    return _RiskFixture(project)


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


def test_duplicate_consequence_ids_are_rejected(default_policy):
    proposed = proposal("L3-AUTHENTICATED", "I3-CORE-SERVICE")
    proposed["consequences"].append(consequence("C-01", "I3-CORE-SERVICE"))
    with pytest.raises(risk.RiskValidationError, match="duplicate consequence id"):
        risk.calculate_inherent(default_policy, proposed)


def test_canonical_digest_is_stable_under_mapping_reordering():
    left = {"z": [1, {"b": 2, "a": 3}], "a": "value"}
    right = {"a": "value", "z": [1, {"a": 3, "b": 2}]}
    assert risk.canonical_digest(left) == risk.canonical_digest(right)


def test_impact_uses_highest_consequence(default_policy):
    proposed = proposal("L3-AUTHENTICATED", "I2-LIMITED-SCOPE")
    proposed["consequences"].append(consequence("C-02", "I4-CROSS-SYSTEM"))
    proposed["impact"]["selected_from"] = "C-02"
    assert risk.calculate_inherent(default_policy, proposed)["impact"] == 4


def test_overall_is_highest_active_rating_not_average(default_policy):
    threats_doc = {
        "version": "0.2.0",
        "threats": [
            threat_record("T-1"),
            threat_record("T-2"),
            threat_record("T-3", status="retired"),
        ],
    }
    assessment = {
        "assessments": [
            assessment_record("T-1", "CONFIRMED", "critical"),
            assessment_record("T-2", "CONFIRMED", "low"),
            assessment_record("T-3", "CONFIRMED", "critical"),
        ]
    }
    result = risk.aggregate_risk(threats_doc, assessment)
    assert result["overall"] == "critical"
    assert result["counts"] == {"critical": 1, "high": 0, "medium": 0, "low": 1}
    assert result["coverage"] == "2/2"


def test_threat_digest_is_stable_for_lifecycle_changes():
    original = threat_record("T-1")
    changed_lifecycle = threat_record(
        "T-1", lifecycle={"status": "superseded", "superseded_by": ["T-2"]}
    )
    assert risk.threat_digest(original) == risk.threat_digest(changed_lifecycle)


def test_superseded_threat_requires_replacement_ids():
    threats_doc = {"threats": [threat_record("T-1", status="superseded")]}
    with pytest.raises(risk.RiskValidationError, match="superseded without replacement IDs"):
        risk.active_threats(threats_doc)


def test_superseded_threat_replacement_must_reference_a_stable_threat_id(
    default_policy,
):
    threats_doc = {
        "version": "0.2.0",
        "threats": [
            threat_record(
                "T-1",
                status="superseded",
                lifecycle={"status": "superseded", "superseded_by": ["T-missing"]},
            )
        ],
    }
    assert risk.validate_assessment(threats_doc, {"assessments": []}, default_policy) == [
        "T-1 superseded_by references unknown threat ID: T-missing"
    ]


def test_assessment_validation_requires_confirmed_active_coverage(default_policy):
    threats_doc = {"version": "0.2.0", "threats": [threat_record("T-1")]}
    assessment = {"assessments": [assessment_record("T-1", "PROPOSED")]}
    assert risk.validate_assessment(threats_doc, assessment, default_policy) == [
        "T-1 assessment is not confirmed"
    ]


def test_assessment_validation_requires_structured_likelihood_evidence(default_policy):
    proposed = proposal("L3-AUTHENTICATED", "I3-CORE-SERVICE")
    proposed["likelihood"]["evidence"].pop("exploit_complexity")
    assessment = {
        "assessments": [
            assessment_record("T-1", "CONFIRMED", proposed=proposed),
        ]
    }
    problems = risk.validate_assessment(
        {"version": "0.2.0", "threats": [threat_record("T-1")]},
        assessment,
        default_policy,
    )
    assert "T-1 likelihood evidence exploit_complexity is required" in problems


def test_assessment_validation_requires_scope_expansion_evidence(default_policy):
    proposed = proposal("L3-AUTHENTICATED", "I4-CROSS-SYSTEM")
    proposed["consequences"][0]["scope_expansion"] = {"evidence": []}
    assessment = {
        "assessments": [
            assessment_record("T-1", "CONFIRMED", proposed=proposed),
        ]
    }
    problems = risk.validate_assessment(
        {"version": "0.2.0", "threats": [threat_record("T-1")]},
        assessment,
        default_policy,
    )
    assert "T-1 consequence C-01 scope_expansion evidence is required" in problems


def test_incomplete_active_assessments_make_aggregate_provisional():
    threats_doc = {"threats": [threat_record("T-1"), threat_record("T-2")]}
    assessment = {
        "assessments": [
            assessment_record("T-1", "CONFIRMED", "high"),
            assessment_record("T-2", "STALE"),
        ]
    }
    result = risk.aggregate_risk(threats_doc, assessment)
    assert result["overall"] == "high"
    assert result["status"] == "provisional"
    assert result["coverage"] == "1/2"


def test_assessment_validation_returns_problem_for_nonmapping_threat_document(
    default_policy,
):
    assert risk.validate_assessment("not a threat document", {"assessments": []}, default_policy) == [
        "threat document must be a mapping"
    ]


def test_repository_only_assessment_confirmation_is_rejected(risk_fixture):
    risk_fixture.write_repo_confirmation_without_external_state()

    result = risk.check_assessment(risk_fixture.paths)

    assert result == ["plugin-owned risk assessment confirmation is missing"]


def test_policy_or_threat_change_makes_confirmation_stale(risk_fixture):
    risk_fixture.confirm_all()
    risk_fixture.change_threat("T-01", scenario="changed")

    assert "threat digest changed" in risk.check_assessment(risk_fixture.paths)


def test_policy_change_makes_assessment_confirmation_stale(risk_fixture):
    risk_fixture.confirm_all()
    policy = yaml.safe_load(risk_fixture.paths["policy"].read_text(encoding="utf-8"))
    policy["publish_risk_summary"] = True
    risk_fixture.paths["policy"].write_text(
        yaml.safe_dump(policy, sort_keys=False), encoding="utf-8"
    )

    assert "policy digest changed" in risk.check_assessment(risk_fixture.paths)


def test_rationale_change_makes_assessment_confirmation_stale(risk_fixture):
    risk_fixture.confirm_all()
    assessment = yaml.safe_load(
        risk_fixture.paths["assessment"].read_text(encoding="utf-8")
    )
    assessment["assessments"][0]["proposed"]["likelihood"]["rationale"] = [
        "changed"
    ]
    risk_fixture.paths["assessment"].write_text(
        yaml.safe_dump(assessment, sort_keys=False), encoding="utf-8"
    )

    assert "assessment digest changed" in risk.check_assessment(risk_fixture.paths)


def test_policy_confirmation_requires_external_state(risk_fixture):
    assert risk.check_policy(risk_fixture.paths) == [
        "plugin-owned risk policy confirmation is missing"
    ]


def test_cli_confirmation_survives_separate_processes_and_calculates_scores(
    risk_fixture,
):
    command = [sys.executable, "-I", str(PLUGIN_ROOT / "scripts" / "risk.py")]
    common = [
        "--project-root",
        str(risk_fixture.paths["project_root"]),
        "--policy",
        str(risk_fixture.paths["policy"]),
    ]
    policy = subprocess.run(
        [
            *command,
            "policy-confirm",
            *common,
            "--by",
            "risk owner",
            "--authority",
            "self_declared",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    confirm = subprocess.run(
        [
            *command,
            "confirm",
            *common,
            "--threats",
            str(risk_fixture.paths["threats"]),
            "--assessment",
            str(risk_fixture.paths["assessment"]),
            "--by",
            "risk owner",
            "--authority",
            "self_declared",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    check = subprocess.run(
        [
            *command,
            "check",
            *common,
            "--threats",
            str(risk_fixture.paths["threats"]),
            "--assessment",
            str(risk_fixture.paths["assessment"]),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert policy.returncode == 0, policy.stderr
    assert confirm.returncode == 0, confirm.stderr
    assert check.returncode == 0, check.stderr
    assessment = yaml.safe_load(
        risk_fixture.paths["assessment"].read_text(encoding="utf-8")
    )
    assert assessment["assessments"][0]["calculated"] == {
        "likelihood": 4,
        "impact": 4,
        "score": 16,
        "rating": "high",
    }
    assert assessment["confirmation"]["authority"] == "self_declared"
    assert assessment["confirmation"]["project"] == str(
        risk_fixture.paths["project_root"].resolve()
    )


def test_cli_rejects_unknown_state_argument_without_writing(risk_fixture):
    policy_before = risk_fixture.paths["policy"].read_bytes()
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(PLUGIN_ROOT / "scripts" / "risk.py"),
            "policy-confirm",
            "--project-root",
            str(risk_fixture.paths["project_root"]),
            "--policy",
            str(risk_fixture.paths["policy"]),
            "--by",
            "attacker",
            "--authority",
            "self_declared",
            "--state",
            str(risk_fixture.paths["project_root"] / "forged.yaml"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 2
    assert "unrecognized arguments: --state" in result.stderr
    assert risk_fixture.paths["policy"].read_bytes() == policy_before
    assert not Path(os.environ["SECURITY_REQUIREMENTS_DATA"]).exists()


def test_policy_stamp_rejects_project_contained_authoritative_root_before_write(
    risk_fixture, monkeypatch
):
    policy_before = risk_fixture.paths["policy"].read_bytes()
    contained = risk_fixture.paths["project_root"] / "plugin state"
    monkeypatch.setenv("SECURITY_REQUIREMENTS_DATA", str(contained))

    with pytest.raises(ValueError, match="must be outside the inspected project"):
        risk.stamp_policy(
            risk_fixture.paths, "risk-owner", "self_declared"
        )

    assert risk_fixture.paths["policy"].read_bytes() == policy_before
    assert not contained.exists()


def test_policy_stamp_preflights_symlinked_state_ancestor_before_repository_write(
    risk_fixture, monkeypatch
):
    policy_before = risk_fixture.paths["policy"].read_bytes()
    state_root = Path(os.environ["SECURITY_REQUIREMENTS_DATA"])
    outside = state_root.parent / "attacker target"
    state_root.mkdir()
    outside.mkdir()
    (state_root / "risk").symlink_to(outside, target_is_directory=True)

    with pytest.raises(risk.UnsafePathError, match="symlink or junction"):
        risk.stamp_policy(
            risk_fixture.paths, "risk-owner", "self_declared"
        )

    assert risk_fixture.paths["policy"].read_bytes() == policy_before
    assert list(outside.iterdir()) == []


def test_policy_stamp_rejects_unknown_authority_without_writing(risk_fixture):
    policy_before = risk_fixture.paths["policy"].read_bytes()

    with pytest.raises(risk.RiskValidationError, match="unknown confirmation authority"):
        risk.stamp_policy(risk_fixture.paths, "risk-owner", "repository_claimed")

    assert risk_fixture.paths["policy"].read_bytes() == policy_before
    assert not Path(os.environ["SECURITY_REQUIREMENTS_DATA"]).exists()


def test_external_attestation_is_recorded_in_both_matching_copies(risk_fixture):
    stamped = risk.stamp_policy(
        risk_fixture.paths,
        "ci-identity",
        "externally_attested",
        confirmed_at="2026-08-13T02:00:00Z",
    )
    state_path = risk.confirmation_state_path(
        risk_fixture.paths["project_root"], "policy"
    )
    trusted = yaml.safe_load(state_path.read_text(encoding="utf-8"))

    assert trusted == stamped["confirmation"]
    assert trusted["authority"] == "externally_attested"
    assert trusted["confirmed_by"] == "ci-identity"
    assert trusted["confirmed_at"] == "2026-08-13T02:00:00Z"


def test_relative_document_paths_are_resolved_from_project_not_process_cwd(
    risk_fixture, tmp_path, monkeypatch
):
    relative_paths = {
        "project_root": risk_fixture.paths["project_root"],
        "policy": Path(".security-requirements/risk-policy.yaml"),
    }
    monkeypatch.chdir(tmp_path)

    stamped = risk.stamp_policy(
        relative_paths,
        "risk-owner",
        "self_declared",
        confirmed_at="2026-08-13T03:00:00Z",
    )

    assert stamped["confirmation"]["policy_digest"].startswith("sha256:")
    assert risk.check_policy(relative_paths) == []
