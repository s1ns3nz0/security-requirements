import copy
from datetime import date
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
from risk_helpers import (  # noqa: E402
    assessment_record,
    consequence,
    proposal,
    run_risk_golden,
    threat_record,
)


DEFAULT_POLICY_PATH = PLUGIN_ROOT / "risk" / "default-policy.yaml"
MOVIE_RATING_GOLDEN = REPO_ROOT / "golden" / "movie-rating-aws"


class _RiskFixture:
    def __init__(self, project: Path):
        self.paths = {
            "project_root": project,
            "policy": project / ".security-requirements" / "risk-policy.yaml",
            "threats": project / ".security-requirements" / "threats.yaml",
            "assessment": project
            / ".security-requirements"
            / "risk-assessment.yaml",
            "requirements": project
            / ".security-requirements"
            / "requirements.yaml",
            "evidence": project
            / ".security-requirements"
            / "risk-evidence.yaml",
            "state": project / ".security-requirements" / "risk-state.yaml",
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
        self.requirements = _requirement_document()
        self.requirements["requirements"][0]["managed"]["risk_refs"] = ["T-01"]
        self.evidence = {"evidence": []}
        self._write_documents()
        self.paths["requirements"].write_text(
            yaml.safe_dump(self.requirements, sort_keys=False), encoding="utf-8"
        )
        self.paths["evidence"].write_text(
            yaml.safe_dump(self.evidence, sort_keys=False), encoding="utf-8"
        )

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


def test_movie_rating_risk_witness():
    result = run_risk_golden(MOVIE_RATING_GOLDEN)
    expected = yaml.safe_load(
        (MOVIE_RATING_GOLDEN / "expected-risk.yaml").read_text(encoding="utf-8")
    )

    assert result["inherent"] == expected["inherent"]
    assert result["residual"] == expected["residual"]
    assert result["coverage"] == "8/8"
    assert result["assessments"] == expected["assessments"]


def test_movie_rating_reports_keep_detail_internal_and_require_explicit_opt_in():
    result = run_risk_golden(MOVIE_RATING_GOLDEN)

    assert result["default_public_summary"] is None
    public = result["opt_in_public_summary"]
    assert public is not None
    assert "Overall | high" in public
    assert "Coverage | 8/8" in public
    assert "high | 5" in public
    assert "medium | 3" in public
    for secret in (
        "deployment_archive_static_credentials",
        "movie-service-team",
        "L5-DIRECT-AUTOMATABLE",
        "linked requirements have no valid implementation evidence",
    ):
        assert secret in result["internal_register"]
        assert secret not in public


def _requirement_document():
    return {
        "requirements": [
            {
                "id": "REQ-WRITE-AUTHORIZATION-01",
                "managed": {
                    "statement": "Writes require explicit authorization.",
                    "verification": {
                        "method": "test_case",
                        "expect": "anonymous writes are denied",
                    },
                },
                "human": {},
            }
        ]
    }


def _evidence_record(requirements, *, supports=("likelihood",), **changes):
    managed = requirements["requirements"][0]["managed"]
    record = {
        "id": "EVID-AUTHZ-INTEGRATION-01",
        "requirement_id": "REQ-WRITE-AUTHORIZATION-01",
        "requirement_digest": risk.canonical_digest(managed),
        "method": "test_case",
        "result": "pass",
        "observed_at": "2026-08-12T09:00:00Z",
        "observed_by": "security-reviewer",
        "artifact": {
            "kind": "test_report",
            "location": "internal-ci-artifact/1234",
            "digest": "sha256:" + "a" * 64,
        },
        "supports": list(supports),
        "valid_until": "2026-12-10",
    }
    record.update(changes)
    return record


def _residual_proposal(likelihood, impact, *, likelihood_refs=(), impact_refs=()):
    proposed = proposal(likelihood, impact)
    proposed["likelihood"]["changed_attack_condition"] = (
        "anonymous access is denied before the write handler"
    )
    proposed["likelihood"]["evidence_refs"] = list(likelihood_refs)
    proposed["impact"]["changed_consequence"] = (
        "authorization confines writes to one tenant"
    )
    proposed["impact"]["evidence_refs"] = list(impact_refs)
    return proposed


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


def test_requirement_text_is_not_implementation_evidence(default_policy):
    inherent = risk.calculate_inherent(
        default_policy, proposal("L4-PUBLIC-LOW-COMPLEXITY", "I4-CROSS-SYSTEM")
    )

    assert risk.calculate_residual(inherent, {}, default_policy) == {
        "status": "UNDETERMINED",
        "reason": "linked requirements have no valid implementation evidence",
    }

    assert risk.calculate_residual(
        inherent,
        {},
        default_policy,
        _residual_proposal(
            "L3-AUTHENTICATED",
            "I4-CROSS-SYSTEM",
            likelihood_refs=["EVID-FORGED"],
        ),
    ) == {
        "status": "UNDETERMINED",
        "reason": "linked requirements have no valid implementation evidence",
    }


def test_evidence_is_bound_to_the_current_managed_requirement(default_policy):
    requirements = _requirement_document()
    evidence = {"evidence": [_evidence_record(requirements)]}

    assert risk.validate_evidence(evidence, requirements, date(2026, 8, 13)) == []

    requirements["requirements"][0]["managed"]["statement"] = (
        "Every write requires explicit authorization."
    )
    assert risk.validate_evidence(evidence, requirements, date(2026, 8, 13)) == [
        "EVID-AUTHZ-INTEGRATION-01 is stale because requirement "
        "REQ-WRITE-AUTHORIZATION-01 changed"
    ]


def test_requirement_stale_evidence_cannot_reduce_residual_risk(default_policy):
    requirements = _requirement_document()
    record = _evidence_record(requirements)
    evidence = {"evidence": [record]}
    requirements["requirements"][0]["managed"]["statement"] = (
        "Every write requires explicit authorization."
    )
    inherent = risk.calculate_inherent(
        default_policy, proposal("L4-PUBLIC-LOW-COMPLEXITY", "I4-CROSS-SYSTEM")
    )
    reduced = _residual_proposal(
        "L3-AUTHENTICATED",
        "I4-CROSS-SYSTEM",
        likelihood_refs=[record["id"]],
    )

    with pytest.raises(
        risk.RiskValidationError, match="residual reduction requires current passing evidence"
    ):
        risk.calculate_residual(
            inherent,
            evidence,
            default_policy,
            reduced,
            requirements=requirements,
            today=date(2026, 8, 13),
        )


def test_future_observation_is_not_current_evidence():
    requirements = _requirement_document()
    evidence = {
        "evidence": [
            _evidence_record(
                requirements, observed_at="2026-08-14T00:00:00+09:00"
            )
        ]
    }

    assert risk.validate_evidence(evidence, requirements, date(2026, 8, 13)) == [
        "EVID-AUTHZ-INTEGRATION-01 observed_at is in the future"
    ]


@pytest.mark.parametrize(
    "changes",
    [
        {"result": "fail"},
        {"valid_until": "2026-08-12"},
        {"artifact": {"kind": "test_report", "location": "ci/1234"}},
    ],
)
def test_residual_reduction_requires_current_passing_evidence(
    default_policy, changes
):
    requirements = _requirement_document()
    evidence = {"evidence": [_evidence_record(requirements, **changes)]}
    inherent = risk.calculate_inherent(
        default_policy, proposal("L4-PUBLIC-LOW-COMPLEXITY", "I4-CROSS-SYSTEM")
    )
    reduced = _residual_proposal(
        "L3-AUTHENTICATED",
        "I4-CROSS-SYSTEM",
        likelihood_refs=["EVID-AUTHZ-INTEGRATION-01"],
    )

    with pytest.raises(
        risk.RiskValidationError, match="residual reduction requires current passing evidence"
    ):
        risk.calculate_residual(
            inherent,
            evidence,
            default_policy,
            reduced,
            requirements=requirements,
            today=date(2026, 8, 13),
        )


def test_likelihood_only_evidence_cannot_reduce_impact(default_policy):
    requirements = _requirement_document()
    evidence = {"evidence": [_evidence_record(requirements, supports=("likelihood",))]}
    inherent = risk.calculate_inherent(
        default_policy, proposal("L4-PUBLIC-LOW-COMPLEXITY", "I4-CROSS-SYSTEM")
    )
    reduced = _residual_proposal(
        "L4-PUBLIC-LOW-COMPLEXITY",
        "I2-LIMITED-SCOPE",
        impact_refs=["EVID-AUTHZ-INTEGRATION-01"],
    )

    with pytest.raises(risk.RiskValidationError, match="does not support impact"):
        risk.calculate_residual(
            inherent,
            evidence,
            default_policy,
            reduced,
            requirements=requirements,
            today=date(2026, 8, 13),
        )


def test_score_one_requires_attack_path_removal_evidence(default_policy):
    requirements = _requirement_document()
    record = _evidence_record(requirements, supports=("likelihood", "impact"))
    evidence = {"evidence": [record]}
    inherent = risk.calculate_inherent(
        default_policy, proposal("L4-PUBLIC-LOW-COMPLEXITY", "I4-CROSS-SYSTEM")
    )
    reduced = _residual_proposal(
        "L1-EXCEPTIONAL",
        "I1-LOCAL-RECOVERABLE",
        likelihood_refs=[record["id"]],
        impact_refs=[record["id"]],
    )

    with pytest.raises(risk.RiskValidationError, match="score 1 requires attack-path-removal"):
        risk.calculate_residual(
            inherent,
            evidence,
            default_policy,
            reduced,
            requirements=requirements,
            today=date(2026, 8, 13),
        )

    record["supports"].append("attack_path_removal")
    result = risk.calculate_residual(
        inherent,
        evidence,
        default_policy,
        reduced,
        requirements=requirements,
        today=date(2026, 8, 13),
    )
    assert result["score"] == 1
    assert result["rating"] == "low"


def test_two_level_reduction_warns_and_residual_may_increase(default_policy):
    requirements = _requirement_document()
    record = _evidence_record(requirements)
    evidence = {"evidence": [record]}
    inherent = risk.calculate_inherent(
        default_policy, proposal("L4-PUBLIC-LOW-COMPLEXITY", "I4-CROSS-SYSTEM")
    )
    reduced = _residual_proposal(
        "L2-RESTRICTED",
        "I4-CROSS-SYSTEM",
        likelihood_refs=[record["id"]],
    )

    result = risk.calculate_residual(
        inherent,
        evidence,
        default_policy,
        reduced,
        requirements=requirements,
        today=date(2026, 8, 13),
    )
    assert result["score"] == 8
    assert result["warnings"] == [
        "likelihood decreases by 2 levels; independent review is recommended"
    ]

    increased = _residual_proposal(
        "L5-DIRECT-AUTOMATABLE", "I5-ORGANISATION-IRREVERSIBLE"
    )
    result = risk.calculate_residual(
        inherent, {}, default_policy, increased, today=date(2026, 8, 13)
    )
    assert result["score"] == 25
    assert result["rating"] == "critical"


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


def _requirements_with_exposure(*rows):
    return [
        {
            "id": requirement_id,
            "risk_exposure": exposure,
            "managed": {"priority": priority},
        }
        for requirement_id, exposure, priority in rows
    ]


def test_unresolved_risk_ordering_is_after_critical_before_high():
    requirements = _requirements_with_exposure(
        ("REQ-HIGH", "high", "high"),
        ("REQ-PROPOSED", "PROPOSED", "low"),
        ("REQ-CRITICAL", "critical", "low"),
        ("REQ-STALE", "STALE", "medium"),
        ("REQ-UNKNOWN-B", "UNDETERMINED", "low"),
        ("REQ-UNKNOWN-A", "UNDETERMINED", "high"),
        ("REQ-MEDIUM", "medium", "high"),
        ("REQ-LOW", "low", "high"),
    )
    original = copy.deepcopy(requirements)

    ordered = risk.order_requirements(requirements)

    assert [record["id"] for record in ordered] == [
        "REQ-CRITICAL",
        "REQ-UNKNOWN-A",
        "REQ-STALE",
        "REQ-PROPOSED",
        "REQ-UNKNOWN-B",
        "REQ-HIGH",
        "REQ-MEDIUM",
        "REQ-LOW",
    ]
    assert requirements == original


def test_retired_risk_ref_is_preserved_but_excluded_from_exposure():
    threats = {
        "threats": [
            threat_record("T-ACTIVE"),
            threat_record("T-RETIRED", status="retired"),
        ]
    }
    assessment = {
        "assessments": [
            {
                "threat_id": "T-ACTIVE",
                "status": "CONFIRMED",
                "calculated": {"rating": "medium"},
                "lifecycle": {"status": "retired"},
            },
            {
                "threat_id": "T-RETIRED",
                "status": "CONFIRMED",
                "calculated": {"rating": "critical"},
            },
        ]
    }

    assert risk.derive_risk_links(
        ["T-RETIRED", "T-ACTIVE"], assessment, threats
    ) == {
        "risk_refs": ["T-ACTIVE", "T-RETIRED"],
        "risk_exposure": "medium",
    }


def test_unknown_risk_ref_is_preserved_for_lint():
    result = risk.derive_risk_links(
        ["T-UNKNOWN"],
        {"assessments": []},
        {"threats": [threat_record("T-ACTIVE")]},
    )

    assert result == {"risk_refs": ["T-UNKNOWN"]}


def test_expired_acceptance_risk_exposure_is_unresolved_and_sorts_before_high():
    today = date(2027, 1, 1)
    threats = {
        "threats": [threat_record("T-EXPIRED"), threat_record("T-HIGH")]
    }
    assessment = {
        "assessments": [
            {
                "threat_id": "T-EXPIRED",
                "status": "CONFIRMED",
                "calculated": {"rating": "high"},
                "treatment": {
                    "strategy": "accept",
                    "approval": {"expires": "2026-12-31"},
                },
            },
            {
                "threat_id": "T-HIGH",
                "status": "CONFIRMED",
                "calculated": {"rating": "high"},
            },
        ]
    }
    expired = risk.derive_risk_links(
        ["T-EXPIRED"], assessment, threats, today=today
    )
    high = risk.derive_risk_links(["T-HIGH"], assessment, threats, today=today)
    requirements = [
        {"id": "REQ-HIGH", "managed": {"priority": "high"}, **high},
        {"id": "REQ-EXPIRED", "managed": {"priority": "low"}, **expired},
    ]

    assert expired["risk_exposure"] == "STALE"
    assert [record["id"] for record in risk.order_requirements(requirements)] == [
        "REQ-EXPIRED",
        "REQ-HIGH",
    ]


def _risk_report_summary():
    return {
        "inherent": {
            "overall": "high",
            "counts": {"critical": 0, "high": 1, "medium": 0, "low": 0},
            "coverage": "1/1",
        },
        "residual": {
            "overall": "UNDETERMINED",
            "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "coverage": "0/1",
        },
        "risks": [
            {
                "threat_id": "T-01",
                "scenario": "scenario-internal-canary",
                "attack_path": "attack_path",
                "status": "CONFIRMED",
                "lifecycle": {"status": "active", "superseded_by": []},
                "proposed": {
                    "likelihood": {
                        "criterion": "L4-PUBLIC-LOW-COMPLEXITY",
                        "rationale": ["likelihood-rationale-canary"],
                    },
                    "consequences": [
                        {
                            "id": "C-01",
                            "criterion": "I4-CROSS-SYSTEM",
                            "rationale": ["impact-rationale-canary"],
                        }
                    ],
                },
                "calculated": {"score": 16, "rating": "high"},
                "residual": {
                    "status": "UNDETERMINED",
                    "reason": "residual-reason-canary",
                },
                "treatment": {
                    "strategy": "accept",
                    "owner": "owner",
                    "approval": {
                        "approver": "approver",
                        "role": "ciso-role-canary",
                        "rationale": "acceptance-rationale-canary",
                        "expires": "2026-12-31",
                    },
                },
                "evidence": [
                    {
                        "id": "EVID-01",
                        "method": "test_case",
                        "artifact": {"location": "internal-ci-artifact"},
                    }
                ],
            }
        ],
        "delta": {
            "new": [],
            "increased": ["T-01"],
            "decreased": [],
            "stale": [],
            "retired": [],
            "reopened": [],
            "expired_acceptance": [],
            "rating_distribution": {
                "previous": {"critical": 0, "high": 0, "medium": 1, "low": 0},
                "current": {"critical": 0, "high": 1, "medium": 0, "low": 0},
            },
        },
    }


def test_risk_register_contains_internal_assessment_and_delta_detail():
    rendered = risk.render_register(_risk_report_summary())

    for detail in (
        "scenario-internal-canary",
        "attack_path",
        "L4-PUBLIC-LOW-COMPLEXITY",
        "I4-CROSS-SYSTEM",
        "likelihood-rationale-canary",
        "high",
        "UNDETERMINED",
        "owner",
        "accept",
        "approver",
        "acceptance-rationale-canary",
        "EVID-01",
        "internal-ci-artifact",
        "2026-12-31",
        "active",
        "increased",
    ):
        assert detail in rendered


def test_public_risk_summary_is_strictly_opt_in_and_redacted():
    summary = _risk_report_summary()

    assert risk.render_public_summary(
        summary, {"publish_risk_summary": False}
    ) is None
    assert risk.render_public_summary(
        summary, {"publish_risk_summary": "true"}
    ) is None

    published = risk.render_public_summary(
        summary, {"publish_risk_summary": True}
    )

    assert published is not None
    assert "Overall | high" in published
    assert "high | 1" in published
    assert "Coverage | 1/1" in published
    for secret in (
        "scenario-internal-canary",
        "attack_path",
        "L4-PUBLIC-LOW-COMPLEXITY",
        "I4-CROSS-SYSTEM",
        "likelihood-rationale-canary",
        "residual-reason-canary",
        "owner",
        "accept",
        "approver",
        "ciso-role-canary",
        "acceptance-rationale-canary",
        "EVID-01",
        "internal-ci-artifact",
        "2026-12-31",
        "active",
        "increased",
    ):
        assert secret not in published


@pytest.mark.parametrize(
    "section",
    [
        {},
        {
            "overall": "low",
            "counts": {"critical": 0, "high": 1, "medium": 0, "low": 0},
            "coverage": "1/1",
        },
        {
            "overall": "UNDETERMINED",
            "counts": {"critical": 0, "high": 1, "medium": 0, "low": 0},
            "coverage": "1/2",
        },
        {
            "overall": "high",
            "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "coverage": "0/1",
        },
        {
            "overall": "high",
            "counts": {"critical": 0, "high": 1, "medium": 0, "low": 0},
            "coverage": "0/1",
        },
        {
            "overall": "high",
            "counts": {"critical": 0, "high": 1, "medium": 0, "low": 0},
            "coverage": "2/1",
        },
    ],
)
def test_impossible_public_risk_summary_is_rejected(section):
    with pytest.raises(risk.RiskValidationError, match="public risk summary"):
        risk.render_public_summary(
            {"inherent": section}, {"publish_risk_summary": True}
        )


@pytest.mark.parametrize("summary", [{}, {"inherent": []}])
def test_public_risk_summary_requires_a_valid_aggregate_section(summary):
    with pytest.raises(risk.RiskValidationError, match="public risk summary"):
        risk.render_public_summary(summary, {"publish_risk_summary": True})


def test_provisional_public_risk_summary_with_consistent_coverage_is_allowed():
    rendered = risk.render_public_summary(
        {
            "inherent": {
                "overall": "high",
                "counts": {"critical": 0, "high": 1, "medium": 0, "low": 0},
                "coverage": "1/2",
            }
        },
        {"publish_risk_summary": True},
    )

    assert rendered is not None
    assert "Overall | high" in rendered
    assert "Coverage | 1/2" in rendered


def test_acceptance_never_changes_rating(default_policy):
    """Changing acceptance handling must not remove accepted inherent risk."""
    threats_doc = {"version": "0.2.0", "threats": [threat_record("T-1")]}
    assessed = {
        "assessments": [
            {
                "threat_id": "T-1",
                "status": "CONFIRMED",
                "calculated": {"score": 16, "rating": "high"},
                "treatment": {
                    "strategy": "accept",
                    "owner": "platform",
                    "approval": {
                        "approver": "alice",
                        "role": "head-of-engineering",
                        "rationale": "migration window",
                        "expires": "2026-12-31",
                        "authority": "self_declared",
                    },
                },
            }
        ]
    }

    assert risk.validate_treatment(
        assessed["assessments"][0], default_policy, date(2026, 8, 13)
    ) == []
    assert risk.aggregate_risk(threats_doc, assessed)["overall"] == "high"


def test_expired_acceptance_is_unresolved(default_policy):
    record = {
        "treatment": {
            "strategy": "accept",
            "owner": "platform",
            "approval": {
                "approver": "alice",
                "role": "head-of-engineering",
                "rationale": "migration window",
                "expires": "2026-12-31",
                "authority": "self_declared",
            },
        }
    }

    assert "acceptance expired" in risk.validate_treatment(
        record, default_policy, date(2027, 1, 1)
    )


def test_expired_acceptance_makes_aggregate_provisional_without_lowering_rating():
    threats_doc = {"version": "0.2.0", "threats": [threat_record("T-1")]}
    assessed = {
        "assessments": [
            {
                "threat_id": "T-1",
                "status": "CONFIRMED",
                "calculated": {"rating": "high"},
                "treatment": {
                    "strategy": "accept",
                    "approval": {"expires": "2026-12-31"},
                },
            }
        ]
    }

    summary = risk.aggregate_risk(threats_doc, assessed, today=date(2027, 1, 1))

    assert summary["overall"] == "high"
    assert summary["status"] == "provisional"


def test_treatment_requires_known_strategy_and_owner(default_policy):
    assert risk.validate_treatment(
        {"treatment": {"strategy": "defer"}}, default_policy, date(2026, 8, 13)
    ) == ["treatment strategy is invalid", "treatment owner is required"]


def test_acceptance_role_is_checked_against_configured_allowlist(default_policy):
    policy = copy.deepcopy(default_policy)
    policy["approval_roles"] = ["ciso"]
    record = {
        "treatment": {
            "strategy": "accept",
            "owner": "platform",
            "approval": {
                "approver": "alice",
                "role": "head-of-engineering",
                "rationale": "migration window",
                "expires": "2026-12-31",
                "authority": "self_declared",
            },
        }
    }

    assert "acceptance role is not permitted by policy" in risk.validate_treatment(
        record, policy, date(2026, 8, 13)
    )


@pytest.mark.parametrize(
    "treatment,problem",
    [
        ({"strategy": "transfer"}, "T-01 treatment owner is required"),
        (
            {
                "strategy": "accept",
                "owner": "platform",
                "approval": {"approver": "alice"},
            },
            "T-01 acceptance role is required",
        ),
    ],
)
def test_assessment_validation_and_stamp_reject_invalid_treatment(
    risk_fixture, default_policy, treatment, problem
):
    """A confirmed record cannot bypass treatment governance through stamping."""
    risk_fixture.assessment["assessments"][0]["treatment"] = treatment
    risk_fixture._write_documents()
    proposed = copy.deepcopy(risk_fixture.assessment)
    proposed["assessments"][0]["status"] = "CONFIRMED"

    assert problem in risk.validate_assessment(
        risk_fixture.threats, proposed, default_policy
    )

    risk.stamp_policy(
        risk_fixture.paths,
        "risk-owner",
        "self_declared",
        confirmed_at="2026-08-13T00:00:00Z",
    )
    with pytest.raises(risk.RiskValidationError, match=problem):
        risk.stamp_assessment(
            risk_fixture.paths,
            "risk-owner",
            "self_declared",
            confirmed_at="2026-08-13T00:01:00Z",
        )


def _history_snapshot(assessed_at, assessments):
    return {
        "assessed_at": assessed_at,
        "policy_digest": "sha256:policy",
        "threat_digest": "sha256:threats",
        "assessment_digest": "sha256:assessment",
        "inherent": {"overall": "high"},
        "residual": {"overall": "UNDETERMINED"},
        "treatment": {"strategy": "mitigate", "owner": "platform"},
        "evidence_refs": [],
        "assessments": assessments,
    }


def test_append_snapshot_is_append_only_and_copies_the_record():
    snapshot = _history_snapshot("2026-08-13T00:00:00Z", [])
    state = {"snapshots": []}

    updated = risk.append_snapshot(state, snapshot)
    snapshot["inherent"]["overall"] = "critical"

    assert state == {"snapshots": []}
    assert updated["snapshots"] == [_history_snapshot("2026-08-13T00:00:00Z", [])]


def test_risk_delta_reports_lifecycle_and_distribution_changes():
    previous = _history_snapshot(
        "2026-12-31T00:00:00Z",
        [
            {"threat_id": "T-up", "status": "CONFIRMED", "calculated": {"rating": "high"}},
            {"threat_id": "T-down", "status": "CONFIRMED", "calculated": {"rating": "high"}},
            {"threat_id": "T-stale", "status": "CONFIRMED", "calculated": {"rating": "medium"}},
            {"threat_id": "T-retired", "status": "CONFIRMED", "calculated": {"rating": "low"}, "lifecycle": {"status": "active"}},
            {"threat_id": "T-reopened", "status": "CONFIRMED", "calculated": {"rating": "low"}, "lifecycle": {"status": "retired"}},
            {"threat_id": "T-accepted", "status": "CONFIRMED", "calculated": {"rating": "medium"}},
        ],
    )
    current = _history_snapshot(
        "2027-01-01T00:00:00Z",
        [
            {"threat_id": "T-up", "status": "CONFIRMED", "calculated": {"rating": "critical"}},
            {"threat_id": "T-down", "status": "CONFIRMED", "calculated": {"rating": "low"}},
            {"threat_id": "T-stale", "status": "STALE", "calculated": {"rating": "medium"}},
            {"threat_id": "T-retired", "status": "CONFIRMED", "calculated": {"rating": "low"}, "lifecycle": {"status": "retired"}},
            {"threat_id": "T-reopened", "status": "CONFIRMED", "calculated": {"rating": "low"}, "lifecycle": {"status": "active"}},
            {"threat_id": "T-accepted", "status": "CONFIRMED", "calculated": {"rating": "medium"}, "treatment": {"strategy": "accept", "approval": {"expires": "2026-12-31"}}},
            {"threat_id": "T-new", "status": "CONFIRMED", "calculated": {"rating": "medium"}},
        ],
    )

    delta = risk.risk_delta(previous, current)

    assert delta["new"] == ["T-new"]
    assert delta["increased"] == ["T-up"]
    assert delta["decreased"] == ["T-down"]
    assert delta["stale"] == ["T-stale"]
    assert delta["retired"] == ["T-retired"]
    assert delta["reopened"] == ["T-reopened"]
    assert delta["expired_acceptance"] == ["T-accepted"]
    assert delta["rating_distribution"] == {
        "previous": {"critical": 0, "high": 2, "medium": 2, "low": 1},
        "current": {"critical": 1, "high": 0, "medium": 2, "low": 2},
    }


def test_risk_delta_reports_only_newly_expired_acceptances():
    previous = _history_snapshot(
        "2027-01-01T00:00:00Z",
        [
            {
                "threat_id": "T-already-expired",
                "status": "CONFIRMED",
                "calculated": {"rating": "high"},
                "treatment": {
                    "strategy": "accept",
                    "approval": {"expires": "2026-12-31"},
                },
            },
            {
                "threat_id": "T-newly-expired",
                "status": "CONFIRMED",
                "calculated": {"rating": "high"},
                "treatment": {
                    "strategy": "accept",
                    "approval": {"expires": "2027-01-31"},
                },
            },
        ],
    )
    current = _history_snapshot(
        "2027-02-01T00:00:00Z", copy.deepcopy(previous["assessments"])
    )

    assert risk.risk_delta(previous, current)["expired_acceptance"] == [
        "T-newly-expired"
    ]


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
            "--requirements",
            str(risk_fixture.paths["requirements"]),
            "--evidence",
            str(risk_fixture.paths["evidence"]),
            "--state",
            str(risk_fixture.paths["state"]),
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
            "--requirements",
            str(risk_fixture.paths["requirements"]),
            "--evidence",
            str(risk_fixture.paths["evidence"]),
            "--state",
            str(risk_fixture.paths["state"]),
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


def test_evidence_and_residual_cli_validate_project_documents(
    risk_fixture, default_policy
):
    requirements = _requirement_document()
    evidence = {"evidence": [_evidence_record(requirements)]}
    requirements_path = (
        risk_fixture.paths["project_root"]
        / ".security-requirements"
        / "requirements.yaml"
    )
    evidence_path = (
        risk_fixture.paths["project_root"]
        / ".security-requirements"
        / "risk-evidence.yaml"
    )
    requirements_path.write_text(
        yaml.safe_dump(requirements, sort_keys=False), encoding="utf-8"
    )
    risk_fixture._write_documents()
    risk_fixture.confirm_all()
    evidence_path.write_text(
        yaml.safe_dump(evidence, sort_keys=False), encoding="utf-8"
    )
    risk.refresh_persisted_assessment(risk_fixture.paths)
    assessment = yaml.safe_load(
        risk_fixture.paths["assessment"].read_text(encoding="utf-8")
    )
    assessment["assessments"][0]["residual"] = {
        "proposed": _residual_proposal(
            "L3-AUTHENTICATED",
            "I4-CROSS-SYSTEM",
            likelihood_refs=["EVID-AUTHZ-INTEGRATION-01"],
        )
    }
    risk_fixture.paths["assessment"].write_text(
        yaml.safe_dump(assessment, sort_keys=False), encoding="utf-8"
    )
    command = [sys.executable, "-I", str(PLUGIN_ROOT / "scripts" / "risk.py")]

    evidence_result = subprocess.run(
        [
            *command,
            "evidence",
            "--project-root",
            str(risk_fixture.paths["project_root"]),
            "--requirements",
            str(requirements_path),
            "--evidence",
            str(evidence_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    residual_result = subprocess.run(
        [
            *command,
            "residual",
            "--project-root",
            str(risk_fixture.paths["project_root"]),
            "--policy",
            str(risk_fixture.paths["policy"]),
            "--threats",
            str(risk_fixture.paths["threats"]),
            "--assessment",
            str(risk_fixture.paths["assessment"]),
            "--requirements",
            str(requirements_path),
            "--evidence",
            str(evidence_path),
            "--state",
            str(risk_fixture.paths["state"]),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert evidence_result.returncode == 0, evidence_result.stderr
    assert "validated 1 current implementation evidence record(s)" in evidence_result.stdout
    assert residual_result.returncode == 0, residual_result.stderr
    assert "T-01 residual risk: high (score 12)" in residual_result.stdout
    assert "internal-ci-artifact" not in evidence_result.stdout + evidence_result.stderr
    assert "internal-ci-artifact" not in residual_result.stdout + residual_result.stderr


def test_residual_cli_renders_undetermined_without_a_traceback(risk_fixture):
    requirements = _requirement_document()
    evidence = {"evidence": [_evidence_record(requirements)]}
    root = risk_fixture.paths["project_root"] / ".security-requirements"
    requirements_path = root / "requirements.yaml"
    evidence_path = root / "risk-evidence.yaml"
    requirements_path.write_text(
        yaml.safe_dump(requirements, sort_keys=False), encoding="utf-8"
    )
    evidence_path.write_text(
        yaml.safe_dump(evidence, sort_keys=False), encoding="utf-8"
    )
    risk_fixture.assessment["assessments"][0]["residual"] = {}
    risk_fixture._write_documents()
    risk_fixture.confirm_all()

    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(PLUGIN_ROOT / "scripts" / "risk.py"),
            "residual",
            "--project-root",
            str(risk_fixture.paths["project_root"]),
            "--policy",
            str(risk_fixture.paths["policy"]),
            "--threats",
            str(risk_fixture.paths["threats"]),
            "--assessment",
            str(risk_fixture.paths["assessment"]),
            "--requirements",
            str(requirements_path),
            "--evidence",
            str(evidence_path),
            "--state",
            str(risk_fixture.paths["state"]),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "T-01 residual risk: UNDETERMINED (residual proposal is required)" in result.stdout
    assert "Traceback" not in result.stderr


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


def test_legacy_migration_proposes_without_confirmed_numbers_or_input_mutation():
    legacy_threats = {
        "version": "0.1.0",
        "threats": [
            {
                "id": "T-LEGACY-01",
                "boundary": "TB-1",
                "category": "STRIDE:T",
                "novelty": "service_specific",
                "persona": "anonymous_external",
                "scenario": "anonymous callers can alter movie ratings",
                "affected_assets": ["movie_ratings"],
                "related_controls": ["AC-3"],
            }
        ],
    }
    requirements = {
        "requirements": [
            {
                "id": "REQ-RATING-AUTHZ-01",
                "managed": {"statement": "Only authorised users change ratings."},
                "human": {
                    "status": "exception",
                    "owner": "movie-team",
                    "exception": {
                        "approver": "risk-owner",
                        "role": "risk_manager",
                        "reason": "legacy launch exception",
                        "expires": "2026-12-31",
                        "authority": "self_declared",
                    },
                },
                "threat_refs": ["T-LEGACY-01"],
            }
        ]
    }
    before_threats = copy.deepcopy(legacy_threats)
    before_requirements = copy.deepcopy(requirements)

    result = risk.migrate(legacy_threats, requirements)

    assert result["status"] == "legacy_unassessed"
    assert result["source_schema"] == "0.1.0"
    assert result["active_legacy_threats"] == 1
    assert result["threats"] == before_threats
    assert result["threats"]["version"] == "0.1.0"
    assert result["assessments"] == [
        {"threat_id": "T-LEGACY-01", "status": "PROPOSED"}
    ]
    assert all(
        set(row).isdisjoint({"calculated", "confirmed", "confirmation", "approval"})
        for row in result["assessments"]
    )
    assert result["pending_requirement_migrations"][0]["threat_refs"] == [
        "T-LEGACY-01"
    ]
    assert legacy_threats == before_threats
    assert requirements == before_requirements


@pytest.mark.parametrize("version", ["0.2.0", "1.0.0", None])
def test_migration_accepts_only_legacy_threat_schema(version):
    threats = {"version": version, "threats": []}

    with pytest.raises(risk.RiskValidationError, match="legacy threat schema must be 0.1.0"):
        risk.migrate(threats, {"requirements": []})


def test_legacy_migration_rejects_duplicate_threat_ids():
    duplicate = {
        "version": "0.1.0",
        "threats": [
            {"id": "T-01", "scenario": "first"},
            {"id": "T-01", "scenario": "second"},
        ],
    }

    with pytest.raises(risk.RiskValidationError, match="duplicate legacy threat id: T-01"):
        risk.migrate(duplicate, {"requirements": []})


def _confirmed_refresh_assessment():
    return {
        "confirmation": {"status": "confirmed", "assessment_digest": "sha256:old"},
        "assessments": [
            {
                "threat_id": "T-01",
                "status": "CONFIRMED",
                "proposed": proposal(
                    "L4-PUBLIC-LOW-COMPLEXITY", "I4-CROSS-SYSTEM"
                ),
                "calculated": {
                    "likelihood": 4,
                    "impact": 4,
                    "score": 16,
                    "rating": "high",
                },
                "treatment": {
                    "strategy": "mitigate",
                    "owner": "movie-team",
                    "requirement_refs": ["REQ-RATING-AUTHZ-01"],
                },
                "residual": {
                    "status": "CONFIRMED",
                    "calculated": {
                        "likelihood": 3,
                        "impact": 4,
                        "score": 12,
                        "rating": "high",
                    },
                    "evidence_refs": ["EVID-RATING-AUTHZ-01"],
                },
            }
        ],
    }


@pytest.mark.parametrize(
    "changes",
    [
        {"scenario": "bulk movie-rating manipulation"},
        {"boundary": "TB-2"},
        {"persona": "authenticated_viewer"},
        {"attack_path": "bulk_rating_write"},
        {"affected_assets": ["movie_ratings", "recommendations"]},
    ],
)
def test_refresh_invalidates_inherent_confirmation_only_for_inherent_inputs(changes):
    previous = {"version": "0.2.0", "threats": [threat_record("T-01")]}
    current_record = threat_record("T-01")
    current_record.update(changes)
    current = {"version": "0.2.0", "threats": [current_record]}
    assessment = _confirmed_refresh_assessment()
    before_human = copy.deepcopy(assessment["assessments"][0]["treatment"])

    refreshed = risk.refresh_assessment(previous, current, assessment)

    record = refreshed["assessments"][0]
    assert record["status"] == "STALE"
    assert record["residual"]["status"] == "CONFIRMED"
    assert record["treatment"] == before_human
    assert record["calculated"]["score"] == 16
    assert "confirmation" not in refreshed


def test_related_control_change_invalidates_residual_but_not_inherent_confirmation():
    previous = {"version": "0.2.0", "threats": [threat_record("T-01")]}
    current = {
        "version": "0.2.0",
        "threats": [threat_record("T-01", related_controls=["AC-3", "AC-4"])],
    }

    refreshed = risk.refresh_assessment(
        previous, current, _confirmed_refresh_assessment()
    )

    record = refreshed["assessments"][0]
    assert record["status"] == "CONFIRMED"
    assert record["residual"]["status"] == "STALE"
    assert "confirmation" not in refreshed


@pytest.mark.parametrize("change_kind", ["requirement", "evidence"])
def test_related_requirement_or_evidence_change_invalidates_only_residual(
    change_kind,
):
    threats = {"version": "0.2.0", "threats": [threat_record("T-01")]}
    old_requirements = {
        "requirements": [
            {
                "id": "REQ-RATING-AUTHZ-01",
                "managed": {
                    "statement": "Authorise movie-rating writes.",
                    "risk_refs": ["T-01"],
                },
            }
        ]
    }
    new_requirements = copy.deepcopy(old_requirements)
    old_evidence = {
        "evidence": [
            {
                "id": "EVID-RATING-AUTHZ-01",
                "requirement_id": "REQ-RATING-AUTHZ-01",
                "artifact": {"digest": "sha256:" + "a" * 64},
            }
        ]
    }
    new_evidence = copy.deepcopy(old_evidence)
    if change_kind == "requirement":
        new_requirements["requirements"][0]["managed"]["statement"] = (
            "Authorise every movie-rating write."
        )
    else:
        new_evidence["evidence"][0]["artifact"]["digest"] = "sha256:" + "b" * 64

    refreshed = risk.refresh_assessment(
        threats,
        copy.deepcopy(threats),
        _confirmed_refresh_assessment(),
        previous_requirements=old_requirements,
        current_requirements=new_requirements,
        previous_evidence=old_evidence,
        current_evidence=new_evidence,
    )

    record = refreshed["assessments"][0]
    assert record["status"] == "CONFIRMED"
    assert record["residual"]["status"] == "STALE"
    assert "confirmation" not in refreshed


def test_refresh_reuses_stable_ids_but_never_resurrects_reopened_approval():
    previous = {
        "version": "0.2.0",
        "threats": [threat_record("T-01", status="retired")],
    }
    current = {"version": "0.2.0", "threats": [threat_record("T-01")]}
    assessment = _confirmed_refresh_assessment()

    refreshed = risk.refresh_assessment(previous, current, assessment)

    assert [row["threat_id"] for row in refreshed["assessments"]] == ["T-01"]
    assert refreshed["assessments"][0]["status"] == "PROPOSED"
    assert refreshed["assessments"][0]["residual"]["status"] == "STALE"
    assert refreshed["assessments"][0]["treatment"] == assessment["assessments"][0][
        "treatment"
    ]
    assert "confirmation" not in refreshed


def test_refresh_adds_new_proposals_and_retains_retired_or_superseded_history():
    previous = {
        "version": "0.2.0",
        "threats": [
            threat_record("T-OLD"),
            threat_record(
                "T-SUPERSEDED",
                status="superseded",
                lifecycle={"status": "superseded", "superseded_by": ["T-OLD"]},
            ),
        ],
    }
    current = {
        "version": "0.2.0",
        "threats": [
            threat_record("T-OLD", status="retired"),
            previous["threats"][1],
            threat_record("T-NEW"),
        ],
    }
    historical = {
        "threat_id": "T-SUPERSEDED",
        "status": "CONFIRMED",
        "calculated": {"rating": "medium", "score": 9},
    }
    assessment = {
        "confirmation": {"status": "confirmed"},
        "assessments": [
            {
                "threat_id": "T-OLD",
                "status": "CONFIRMED",
                "calculated": {"rating": "high", "score": 16},
            },
            copy.deepcopy(historical),
        ],
    }

    refreshed = risk.refresh_assessment(previous, current, assessment)

    by_id = {row["threat_id"]: row for row in refreshed["assessments"]}
    assert by_id["T-SUPERSEDED"] == historical
    assert by_id["T-OLD"]["status"] == "CONFIRMED"
    assert by_id["T-NEW"] == {"threat_id": "T-NEW", "status": "PROPOSED"}
    assert "confirmation" not in refreshed


def test_new_threat_cannot_reuse_an_orphaned_confirmed_assessment():
    previous = {"version": "0.2.0", "threats": []}
    current = {"version": "0.2.0", "threats": [threat_record("T-NEW")]}
    orphaned = _confirmed_refresh_assessment()
    orphaned["assessments"][0]["threat_id"] = "T-NEW"

    refreshed = risk.refresh_assessment(previous, current, orphaned)

    record = refreshed["assessments"][0]
    assert record["status"] == "PROPOSED"
    assert record["residual"]["status"] == "STALE"
    assert "confirmation" not in refreshed


def _seed_legacy_migration_project(project: Path):
    internal = project / ".security-requirements"
    public = project / "docs" / "security"
    internal.mkdir(parents=True)
    public.mkdir(parents=True)
    threats = {
        "version": "0.1.0",
        "threats": [
            {
                "id": "T-LEGACY-01",
                "boundary": "TB-1",
                "category": "STRIDE:T",
                "novelty": "service_specific",
                "persona": "anonymous_external",
                "attack_path": "anonymous_rating_write",
                "scenario": "anonymous callers can alter movie ratings",
                "affected_assets": ["movie_ratings"],
                "related_controls": ["AC-3"],
                "lifecycle": {"status": "active", "superseded_by": []},
            }
        ],
    }
    requirements = {
        "requirements": [
            {
                "id": "REQ-RATING-AUTHZ-01",
                "managed": {
                    "statement": "Authorise movie-rating writes.",
                    "risk_refs": ["T-LEGACY-01"],
                },
                "human": {},
            }
        ]
    }
    threats_path = internal / "threats.yaml"
    requirements_path = internal / "requirements.yaml"
    threats_path.write_text(
        yaml.safe_dump(threats, sort_keys=False), encoding="utf-8"
    )
    requirements_path.write_text(
        yaml.safe_dump(requirements, sort_keys=False), encoding="utf-8"
    )
    for name, content in {
        "security-requirements.md": "previous requirements\n",
        "traceability.md": "previous traceability\n",
        "risk-summary.md": "previous approved public aggregate\n",
    }.items():
        (public / name).write_text(content, encoding="utf-8")
    return threats_path, requirements_path


def _run_migration_cli(project: Path, threats_path: Path, requirements_path: Path):
    internal = project / ".security-requirements"
    return subprocess.run(
        [
            sys.executable,
            "-I",
            str(PLUGIN_ROOT / "scripts" / "risk.py"),
            "migrate",
            "--project-root",
            str(project),
            "--threats",
            str(threats_path),
            "--requirements",
            str(requirements_path),
            "--policy",
            str(internal / "risk-policy.yaml"),
            "--assessment",
            str(internal / "risk-assessment.yaml"),
            "--state",
            str(internal / "risk-state.yaml"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def test_migration_cli_scaffolds_internal_proposals_without_publishing(tmp_path):
    project = tmp_path / "legacy movie app 한글"
    threats_path, requirements_path = _seed_legacy_migration_project(project)
    public = project / "docs" / "security"
    public_before = {path.name: path.read_bytes() for path in public.iterdir()}
    threats_before = threats_path.read_bytes()
    requirements_before = requirements_path.read_bytes()

    result = _run_migration_cli(project, threats_path, requirements_path)

    assert result.returncode == 0, result.stderr
    assert "1 active legacy threat(s)" in result.stdout
    assert "legacy_unassessed" in result.stdout
    assert "Prior published documents were not modified." in result.stdout
    assert threats_path.read_bytes() == threats_before
    assert requirements_path.read_bytes() == requirements_before
    assert {path.name: path.read_bytes() for path in public.iterdir()} == public_before
    assessment = yaml.safe_load(
        (project / ".security-requirements" / "risk-assessment.yaml").read_text(
            encoding="utf-8"
        )
    )
    assert assessment["assessments"] == [
        {"threat_id": "T-LEGACY-01", "status": "PROPOSED"}
    ]
    assert "confirmation" not in assessment
    state = yaml.safe_load(
        (project / ".security-requirements" / "risk-state.yaml").read_text(
            encoding="utf-8"
        )
    )
    assert state["migration"]["source_schema"] == "0.1.0"
    assert [snapshot["event"] for snapshot in state["snapshots"]] == ["migrated"]
    assert state["snapshots"][0]["assessments"][0]["status"] == "PROPOSED"


def test_failed_migration_preserves_public_bytes_and_creates_no_scaffolding(tmp_path):
    project = tmp_path / "invalid legacy app"
    threats_path, requirements_path = _seed_legacy_migration_project(project)
    threats = yaml.safe_load(threats_path.read_text(encoding="utf-8"))
    threats["threats"].append(copy.deepcopy(threats["threats"][0]))
    threats_path.write_text(
        yaml.safe_dump(threats, sort_keys=False), encoding="utf-8"
    )
    public = project / "docs" / "security"
    public_before = {path.name: path.read_bytes() for path in public.iterdir()}

    result = _run_migration_cli(project, threats_path, requirements_path)

    assert result.returncode == 1
    assert "duplicate legacy threat id" in result.stderr
    assert {path.name: path.read_bytes() for path in public.iterdir()} == public_before
    internal = project / ".security-requirements"
    assert not (internal / "risk-policy.yaml").exists()
    assert not (internal / "risk-assessment.yaml").exists()
    assert not (internal / "risk-state.yaml").exists()


def test_migration_cli_rejects_public_output_alias_without_modifying_it(tmp_path):
    project = tmp_path / "legacy alias app"
    threats_path, requirements_path = _seed_legacy_migration_project(project)
    public_summary = project / "docs" / "security" / "risk-summary.md"
    before = public_summary.read_bytes()
    internal = project / ".security-requirements"

    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(PLUGIN_ROOT / "scripts" / "risk.py"),
            "migrate",
            "--project-root",
            str(project),
            "--threats",
            str(threats_path),
            "--requirements",
            str(requirements_path),
            "--policy",
            str(public_summary),
            "--assessment",
            str(internal / "risk-assessment.yaml"),
            "--state",
            str(internal / "risk-state.yaml"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert "canonical migration path" in result.stderr
    assert public_summary.read_bytes() == before
    assert not (internal / "risk-assessment.yaml").exists()
    assert not (internal / "risk-state.yaml").exists()


def test_migration_cli_refuses_to_overwrite_existing_review_scaffolding(tmp_path):
    project = tmp_path / "legacy existing review"
    threats_path, requirements_path = _seed_legacy_migration_project(project)
    internal = project / ".security-requirements"
    policy_path = internal / "risk-policy.yaml"
    policy_path.write_text("human-owned review proposal\n", encoding="utf-8")
    before = policy_path.read_bytes()

    result = _run_migration_cli(project, threats_path, requirements_path)

    assert result.returncode == 1
    assert "migration output already exists" in result.stderr
    assert policy_path.read_bytes() == before
    assert not (internal / "risk-assessment.yaml").exists()
    assert not (internal / "risk-state.yaml").exists()


def test_migration_scaffolding_rolls_back_all_outputs_on_write_failure(
    tmp_path, monkeypatch
):
    project = tmp_path / "legacy interrupted migration"
    threats_path, requirements_path = _seed_legacy_migration_project(project)
    internal = project / ".security-requirements"
    real_write = risk.safe_write_text
    writes = 0

    def fail_second_write(*args, **kwargs):
        nonlocal writes
        writes += 1
        if writes == 2:
            real_write(*args, **kwargs)
            raise OSError("injected migration write failure")
        return real_write(*args, **kwargs)

    monkeypatch.setattr(risk, "safe_write_text", fail_second_write)
    paths = {
        "project_root": project,
        "threats": threats_path,
        "requirements": requirements_path,
        "policy": internal / "risk-policy.yaml",
        "assessment": internal / "risk-assessment.yaml",
        "state": internal / "risk-state.yaml",
    }

    with pytest.raises(OSError, match="injected migration write failure"):
        risk.write_migration(paths)

    assert not paths["policy"].exists()
    assert not paths["assessment"].exists()
    assert not paths["state"].exists()


def test_migration_rollback_continues_after_transient_unlink_failure(
    tmp_path, monkeypatch
):
    project = tmp_path / "legacy rollback cleanup"
    threats_path, requirements_path = _seed_legacy_migration_project(project)
    internal = project / ".security-requirements"
    paths = {
        "project_root": project,
        "threats": threats_path,
        "requirements": requirements_path,
        "policy": internal / "risk-policy.yaml",
        "assessment": internal / "risk-assessment.yaml",
        "state": internal / "risk-state.yaml",
    }
    real_write = risk.safe_write_text
    writes = 0

    def fail_state_write(*args, **kwargs):
        nonlocal writes
        writes += 1
        if writes == 3:
            raise OSError("injected migration state failure")
        return real_write(*args, **kwargs)

    real_unlink = Path.unlink
    failed_unlink = False

    def fail_first_assessment_unlink(path, *args, **kwargs):
        nonlocal failed_unlink
        if Path(path) == paths["assessment"] and not failed_unlink:
            failed_unlink = True
            raise OSError("injected transient unlink failure")
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(risk, "safe_write_text", fail_state_write)
    monkeypatch.setattr(Path, "unlink", fail_first_assessment_unlink)

    with pytest.raises(OSError, match="injected migration state failure"):
        risk.write_migration(paths)

    assert failed_unlink is True
    assert not paths["policy"].exists()
    assert not paths["assessment"].exists()
    assert not paths["state"].exists()


def test_legacy_schema_advances_only_inside_successful_human_confirmation(
    risk_fixture,
):
    risk_fixture.threats["version"] = "0.1.0"
    risk_fixture._write_documents()
    risk.stamp_policy(
        risk_fixture.paths,
        "risk-owner",
        "self_declared",
        confirmed_at="2026-08-13T00:00:00Z",
    )
    assert yaml.safe_load(
        risk_fixture.paths["threats"].read_text(encoding="utf-8")
    )["version"] == "0.1.0"

    risk.stamp_assessment(
        risk_fixture.paths,
        "risk-owner",
        "self_declared",
        confirmed_at="2026-08-13T00:01:00Z",
    )

    promoted = yaml.safe_load(
        risk_fixture.paths["threats"].read_text(encoding="utf-8")
    )
    assert promoted["version"] == "0.2.0"
    assert promoted["threats"][0]["id"] == "T-01"
    assert promoted["threats"][0]["scenario"] == "anonymous mutation"
    assert risk.check_assessment(risk_fixture.paths) == []


def test_failed_legacy_confirmation_does_not_advance_schema(risk_fixture):
    risk_fixture.threats["version"] = "0.1.0"
    risk_fixture.assessment["assessments"][0].pop("proposed")
    risk_fixture._write_documents()
    risk.stamp_policy(risk_fixture.paths, "risk-owner", "self_declared")
    before = risk_fixture.paths["threats"].read_bytes()

    with pytest.raises(risk.RiskValidationError, match="assessment proposal is required"):
        risk.stamp_assessment(
            risk_fixture.paths, "risk-owner", "self_declared"
        )

    assert risk_fixture.paths["threats"].read_bytes() == before
    assert yaml.safe_load(before)["version"] == "0.1.0"


def test_legacy_confirmation_rolls_back_schema_and_assessment_on_write_failure(
    risk_fixture, monkeypatch
):
    risk_fixture.threats["version"] = "0.1.0"
    risk_fixture._write_documents()
    risk.stamp_policy(risk_fixture.paths, "risk-owner", "self_declared")
    before_threats = risk_fixture.paths["threats"].read_bytes()
    before_assessment = risk_fixture.paths["assessment"].read_bytes()
    real_write = risk.safe_write_text
    failed = False

    def fail_threat_promotion(path, *args, **kwargs):
        nonlocal failed
        if Path(path) == risk_fixture.paths["threats"] and not failed:
            failed = True
            raise OSError("injected schema promotion failure")
        return real_write(path, *args, **kwargs)

    monkeypatch.setattr(risk, "safe_write_text", fail_threat_promotion)

    with pytest.raises(OSError, match="injected schema promotion failure"):
        risk.stamp_assessment(
            risk_fixture.paths, "risk-owner", "self_declared"
        )

    assert risk_fixture.paths["threats"].read_bytes() == before_threats
    assert risk_fixture.paths["assessment"].read_bytes() == before_assessment
    assert not risk.confirmation_state_path(
        risk_fixture.paths["project_root"], "assessment"
    ).exists()


def test_b2b_golden_declares_and_meets_legacy_risk_migration_coverage():
    golden = REPO_ROOT / "golden" / "b2b-saas-aws"
    expected = yaml.safe_load(
        (golden / "expected-coverage.yaml").read_text(encoding="utf-8")
    )["risk_migration"]
    threats = yaml.safe_load(
        (golden / "threats.yaml").read_text(encoding="utf-8")
    )
    threats["version"] = "0.1.0"

    migrated = risk.migrate(threats, {"requirements": []})

    assert {
        "source_schema": migrated["source_schema"],
        "target_schema": migrated["target_schema"],
        "status": migrated["status"],
        "active_threats": migrated["active_legacy_threats"],
        "confirmed_assessments": sum(
            row["status"] == "CONFIRMED" for row in migrated["assessments"]
        ),
        "published_documents_modified": False,
    } == expected


def _risk_cli_document_args(risk_fixture):
    return [
        "--project-root",
        str(risk_fixture.paths["project_root"]),
        "--policy",
        str(risk_fixture.paths["policy"]),
        "--threats",
        str(risk_fixture.paths["threats"]),
        "--assessment",
        str(risk_fixture.paths["assessment"]),
        "--requirements",
        str(risk_fixture.paths["requirements"]),
        "--evidence",
        str(risk_fixture.paths["evidence"]),
        "--state",
        str(risk_fixture.paths["state"]),
    ]


def _risk_authority_bytes(risk_fixture):
    trusted = risk.confirmation_state_path(
        risk_fixture.paths["project_root"], "assessment"
    )
    return {
        path: path.read_bytes()
        for path in (
            risk_fixture.paths["assessment"],
            risk_fixture.paths["state"],
            trusted,
        )
    }


def _run_risk_command(risk_fixture, command, *extra):
    return subprocess.run(
        [
            sys.executable,
            "-I",
            str(PLUGIN_ROOT / "scripts" / "risk.py"),
            command,
            *_risk_cli_document_args(risk_fixture),
            *extra,
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def _prepare_first_residual_review(risk_fixture, *, evidence=True):
    risk_fixture.confirm_all()
    if evidence:
        document = {"evidence": [_evidence_record(risk_fixture.requirements)]}
        risk_fixture.paths["evidence"].write_text(
            yaml.safe_dump(document, sort_keys=False), encoding="utf-8"
        )
    else:
        risk_fixture.change_threat(
            "T-01", related_controls=["AC-3", "AC-4"]
        )
    refreshed, _messages = risk.refresh_persisted_assessment(risk_fixture.paths)
    assert "confirmation" not in refreshed
    refreshed["assessments"][0]["residual"] = {
        "proposed": _residual_proposal(
            "L3-AUTHENTICATED",
            "I4-CROSS-SYSTEM",
            likelihood_refs=["EVID-AUTHZ-INTEGRATION-01"],
        )
    }
    risk_fixture.paths["assessment"].write_text(
        yaml.safe_dump(refreshed, sort_keys=False), encoding="utf-8"
    )
    return refreshed


def _add_confirmed_residual(risk_fixture):
    """Create confirmed residual state through the production transition."""

    risk_fixture.assessment["assessments"][0]["treatment"] = {
        "strategy": "mitigate",
        "owner": "movie-team",
        "requirement_refs": ["REQ-WRITE-AUTHORIZATION-01"],
    }
    risk_fixture._write_documents()
    _prepare_first_residual_review(risk_fixture)
    result = _run_risk_command(
        risk_fixture,
        "residual-confirm",
        "--by",
        "risk-reviewer",
        "--authority",
        "self_declared",
    )
    assert result.returncode == 0, result.stderr
    risk_fixture.assessment = yaml.safe_load(
        risk_fixture.paths["assessment"].read_text(encoding="utf-8")
    )


def _prepare_refresh_bound_residual_review(risk_fixture):
    _add_confirmed_residual(risk_fixture)
    evidence = {"evidence": [_evidence_record(risk_fixture.requirements)]}
    evidence["evidence"][0]["artifact"]["digest"] = "sha256:" + "b" * 64
    risk_fixture.paths["evidence"].write_text(
        yaml.safe_dump(evidence, sort_keys=False), encoding="utf-8"
    )
    refreshed, messages = risk.refresh_persisted_assessment(risk_fixture.paths)
    assert "T-01 residual risk is STALE" in messages
    assert "confirmation" not in refreshed
    refreshed["assessments"][0]["residual"]["proposed"] = _residual_proposal(
        "L3-AUTHENTICATED",
        "I4-CROSS-SYSTEM",
        likelihood_refs=["EVID-AUTHZ-INTEGRATION-01"],
    )
    risk_fixture.paths["assessment"].write_text(
        yaml.safe_dump(refreshed, sort_keys=False), encoding="utf-8"
    )
    return refreshed


def test_residual_cli_previews_proposal_from_externally_bound_refresh(
    risk_fixture,
):
    _prepare_refresh_bound_residual_review(risk_fixture)

    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(PLUGIN_ROOT / "scripts" / "risk.py"),
            "residual",
            *_risk_cli_document_args(risk_fixture),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "T-01 residual risk: high (score 12)" in result.stdout


def test_residual_cli_previews_first_proposal_after_evidence_refresh(risk_fixture):
    _prepare_first_residual_review(risk_fixture)

    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(PLUGIN_ROOT / "scripts" / "risk.py"),
            "residual",
            *_risk_cli_document_args(risk_fixture),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "T-01 residual risk: high (score 12)" in result.stdout


def test_residual_confirm_calculates_and_persists_first_evidenced_result(
    risk_fixture,
):
    _prepare_first_residual_review(risk_fixture)
    preview = _run_risk_command(risk_fixture, "residual")
    before_state = yaml.safe_load(
        risk_fixture.paths["state"].read_text(encoding="utf-8")
    )

    result = _run_risk_command(
        risk_fixture,
        "residual-confirm",
        "--by",
        "risk-reviewer",
        "--authority",
        "self_declared",
    )

    assert preview.returncode == 0, preview.stderr
    assert "T-01 residual risk: high (score 12)" in preview.stdout
    assert result.returncode == 0, result.stderr
    assert "confirmed residual risk assessment" in result.stdout
    assessment = yaml.safe_load(
        risk_fixture.paths["assessment"].read_text(encoding="utf-8")
    )
    residual = assessment["assessments"][0]["residual"]
    assert residual == {
        "proposed": _residual_proposal(
            "L3-AUTHENTICATED",
            "I4-CROSS-SYSTEM",
            likelihood_refs=["EVID-AUTHZ-INTEGRATION-01"],
        ),
        "status": "CONFIRMED",
        "calculated": {
            "likelihood": 3,
            "impact": 4,
            "score": 12,
            "rating": "high",
        },
        "evidence_refs": ["EVID-AUTHZ-INTEGRATION-01"],
    }
    trusted = yaml.safe_load(
        risk.confirmation_state_path(
            risk_fixture.paths["project_root"], "assessment"
        ).read_text(encoding="utf-8")
    )
    state = yaml.safe_load(
        risk_fixture.paths["state"].read_text(encoding="utf-8")
    )
    assert assessment["confirmation"] == trusted
    assert trusted["confirmed_by"] == "risk-reviewer"
    assert trusted["risk_state_digest"] == risk.canonical_digest(state)
    assert len(state["snapshots"]) == len(before_state["snapshots"]) + 1
    assert state["snapshots"][-1]["event"] == "residual_confirmed"
    assert risk.check_assessment(risk_fixture.paths) == []
    check = _run_risk_command(risk_fixture, "check")
    assert check.returncode == 0, check.stderr


@pytest.mark.parametrize(
    "likelihood,impact,expected",
    [
        (
            "L4-PUBLIC-LOW-COMPLEXITY",
            "I4-CROSS-SYSTEM",
            {"likelihood": 4, "impact": 4, "score": 16, "rating": "high"},
        ),
        (
            "L5-DIRECT-AUTOMATABLE",
            "I5-ORGANISATION-IRREVERSIBLE",
            {"likelihood": 5, "impact": 5, "score": 25, "rating": "critical"},
        ),
    ],
)
def test_residual_confirm_allows_unchanged_or_increased_risk_without_evidence(
    risk_fixture, likelihood, impact, expected
):
    assessment = _prepare_first_residual_review(risk_fixture, evidence=False)
    assessment["assessments"][0]["residual"]["proposed"] = _residual_proposal(
        likelihood,
        impact,
    )
    risk_fixture.paths["assessment"].write_text(
        yaml.safe_dump(assessment, sort_keys=False), encoding="utf-8"
    )

    preview = _run_risk_command(risk_fixture, "residual")
    result = _run_risk_command(
        risk_fixture,
        "residual-confirm",
        "--by",
        "risk-reviewer",
        "--authority",
        "self_declared",
    )

    assert preview.returncode == 0, preview.stderr
    assert f"{expected['rating']} (score {expected['score']})" in preview.stdout
    assert result.returncode == 0, result.stderr
    confirmed = yaml.safe_load(
        risk_fixture.paths["assessment"].read_text(encoding="utf-8")
    )["assessments"][0]["residual"]
    assert confirmed["status"] == "CONFIRMED"
    assert confirmed["calculated"] == expected
    assert confirmed["evidence_refs"] == []


def test_residual_confirm_requires_evidence_only_for_the_decreased_axis(
    risk_fixture,
):
    assessment = _prepare_first_residual_review(risk_fixture)
    assessment["assessments"][0]["residual"]["proposed"] = _residual_proposal(
        "L3-AUTHENTICATED",
        "I5-ORGANISATION-IRREVERSIBLE",
        likelihood_refs=["EVID-AUTHZ-INTEGRATION-01"],
    )
    risk_fixture.paths["assessment"].write_text(
        yaml.safe_dump(assessment, sort_keys=False), encoding="utf-8"
    )

    preview = _run_risk_command(risk_fixture, "residual")
    result = _run_risk_command(
        risk_fixture,
        "residual-confirm",
        "--by",
        "risk-reviewer",
        "--authority",
        "self_declared",
    )

    assert preview.returncode == 0, preview.stderr
    assert "high (score 15)" in preview.stdout
    assert result.returncode == 0, result.stderr
    confirmed = yaml.safe_load(
        risk_fixture.paths["assessment"].read_text(encoding="utf-8")
    )["assessments"][0]["residual"]
    assert confirmed["calculated"] == {
        "likelihood": 3,
        "impact": 5,
        "score": 15,
        "rating": "high",
    }
    assert confirmed["evidence_refs"] == ["EVID-AUTHZ-INTEGRATION-01"]


def test_mixed_residual_cannot_use_increased_axis_evidence_for_a_reduction(
    risk_fixture,
):
    assessment = _prepare_first_residual_review(risk_fixture)
    assessment["assessments"][0]["residual"]["proposed"] = _residual_proposal(
        "L3-AUTHENTICATED",
        "I5-ORGANISATION-IRREVERSIBLE",
        impact_refs=["EVID-AUTHZ-INTEGRATION-01"],
    )
    risk_fixture.paths["assessment"].write_text(
        yaml.safe_dump(assessment, sort_keys=False), encoding="utf-8"
    )
    before = _risk_authority_bytes(risk_fixture)

    preview = _run_risk_command(risk_fixture, "residual")
    result = _run_risk_command(
        risk_fixture,
        "residual-confirm",
        "--by",
        "risk-reviewer",
        "--authority",
        "self_declared",
    )

    assert preview.returncode == 1
    assert "current passing evidence for likelihood" in preview.stderr
    assert result.returncode == 1
    assert "current passing evidence for likelihood" in result.stderr
    assert _risk_authority_bytes(risk_fixture) == before


@pytest.mark.parametrize(
    "forgery",
    [
        {"status": "CONFIRMED"},
        {"calculated": {"likelihood": 1, "impact": 1, "score": 1, "rating": "low"}},
        {"evidence_refs": ["EVID-FORGED"]},
    ],
)
def test_residual_confirm_rejects_model_authored_authoritative_fields_atomically(
    risk_fixture, forgery
):
    assessment = _prepare_first_residual_review(risk_fixture)
    assessment["assessments"][0]["residual"].update(forgery)
    risk_fixture.paths["assessment"].write_text(
        yaml.safe_dump(assessment, sort_keys=False), encoding="utf-8"
    )
    before = _risk_authority_bytes(risk_fixture)

    result = _run_risk_command(
        risk_fixture,
        "residual-confirm",
        "--by",
        "risk-reviewer",
        "--authority",
        "self_declared",
    )

    assert result.returncode == 1
    assert "changed outside residual proposals" in result.stderr
    assert _risk_authority_bytes(risk_fixture) == before


def test_generic_confirm_cannot_legitimize_residual_proposal(risk_fixture):
    _prepare_first_residual_review(risk_fixture)
    before = _risk_authority_bytes(risk_fixture)

    result = _run_risk_command(
        risk_fixture,
        "confirm",
        "--by",
        "risk-reviewer",
        "--authority",
        "self_declared",
    )

    assert result.returncode == 1
    assert "residual proposals require residual-confirm" in result.stderr
    assert _risk_authority_bytes(risk_fixture) == before


def test_residual_confirm_keeps_missing_evidence_undetermined_and_atomic(
    risk_fixture,
):
    _prepare_first_residual_review(risk_fixture, evidence=False)
    preview = _run_risk_command(risk_fixture, "residual")
    before = _risk_authority_bytes(risk_fixture)

    result = _run_risk_command(
        risk_fixture,
        "residual-confirm",
        "--by",
        "risk-reviewer",
        "--authority",
        "self_declared",
    )

    assert preview.returncode == 0, preview.stderr
    assert "T-01 residual risk: UNDETERMINED" in preview.stdout
    assert result.returncode == 1
    assert "valid implementation evidence" in result.stderr
    assert _risk_authority_bytes(risk_fixture) == before


def test_stale_evidence_previews_undetermined_and_cannot_be_confirmed(
    risk_fixture,
):
    _prepare_first_residual_review(risk_fixture)
    evidence = yaml.safe_load(
        risk_fixture.paths["evidence"].read_text(encoding="utf-8")
    )
    evidence["evidence"][0]["valid_until"] = "2026-08-12"
    risk_fixture.paths["evidence"].write_text(
        yaml.safe_dump(evidence, sort_keys=False), encoding="utf-8"
    )
    # Rebind the changed input without allowing the proposal to become authority.
    refreshed, _messages = risk.refresh_persisted_assessment(risk_fixture.paths)
    refreshed["assessments"][0]["residual"]["proposed"] = _residual_proposal(
        "L3-AUTHENTICATED",
        "I4-CROSS-SYSTEM",
        likelihood_refs=["EVID-AUTHZ-INTEGRATION-01"],
    )
    risk_fixture.paths["assessment"].write_text(
        yaml.safe_dump(refreshed, sort_keys=False), encoding="utf-8"
    )
    before = _risk_authority_bytes(risk_fixture)

    preview = _run_risk_command(risk_fixture, "residual")
    result = _run_risk_command(
        risk_fixture,
        "residual-confirm",
        "--by",
        "risk-reviewer",
        "--authority",
        "self_declared",
    )

    assert preview.returncode == 1
    assert "T-01 residual risk: UNDETERMINED" in preview.stdout
    assert "evidence expired" in preview.stderr
    assert result.returncode == 1
    assert "evidence expired" in result.stderr
    assert _risk_authority_bytes(risk_fixture) == before


def test_residual_confirm_rolls_back_all_authority_files_on_write_failure(
    risk_fixture, monkeypatch
):
    _prepare_first_residual_review(risk_fixture)
    before = _risk_authority_bytes(risk_fixture)
    confirmation_path = risk.confirmation_state_path(
        risk_fixture.paths["project_root"], "assessment"
    )
    real_write = risk.safe_write_text
    failed = False

    def fail_confirmation_once(path, *args, **kwargs):
        nonlocal failed
        if Path(path) == confirmation_path and not failed:
            failed = True
            raise OSError("injected external authority write failure")
        return real_write(path, *args, **kwargs)

    monkeypatch.setattr(risk, "safe_write_text", fail_confirmation_once)

    with pytest.raises(OSError, match="injected external authority write failure"):
        risk.stamp_residual_assessment(
            risk_fixture.paths,
            "risk-reviewer",
            "self_declared",
        )

    assert _risk_authority_bytes(risk_fixture) == before


def test_residual_confirm_rechecks_exact_evidence_loaded_after_review(
    risk_fixture, monkeypatch
):
    _prepare_first_residual_review(risk_fixture)
    before = _risk_authority_bytes(risk_fixture)
    real_documents = risk._validated_evidence_documents

    def substitute_valid_but_unbound_evidence(paths, evaluation_date):
        requirements, evidence, problems = real_documents(paths, evaluation_date)
        evidence = copy.deepcopy(evidence)
        evidence["evidence"][0]["artifact"]["digest"] = "sha256:" + "c" * 64
        return requirements, evidence, problems

    monkeypatch.setattr(
        risk, "_validated_evidence_documents", substitute_valid_but_unbound_evidence
    )

    with pytest.raises(
        risk.RiskValidationError,
        match="evidence changed after refreshed state was bound",
    ):
        risk.stamp_residual_assessment(
            risk_fixture.paths,
            "risk-reviewer",
            "self_declared",
        )

    assert _risk_authority_bytes(risk_fixture) == before


def test_residual_confirm_rechecks_exact_assessment_loaded_after_review(
    risk_fixture, monkeypatch
):
    _prepare_first_residual_review(risk_fixture)
    before = _risk_authority_bytes(risk_fixture)
    assessment_path = risk_fixture.paths["assessment"]
    real_load = risk._load_mapping
    assessment_loads = 0

    def substitute_unbound_treatment(path, label):
        nonlocal assessment_loads
        document = real_load(path, label)
        if Path(path) == assessment_path:
            assessment_loads += 1
            if assessment_loads == 2:
                document = copy.deepcopy(document)
                document["assessments"][0]["rationale"] = "attacker-authored"
        return document

    monkeypatch.setattr(risk, "_load_mapping", substitute_unbound_treatment)

    with pytest.raises(
        risk.RiskValidationError,
        match="changed outside residual proposals",
    ):
        risk.stamp_residual_assessment(
            risk_fixture.paths,
            "risk-reviewer",
            "self_declared",
        )

    assert _risk_authority_bytes(risk_fixture) == before


@pytest.mark.parametrize(
    "forgery",
    [
        {
            "proposed": _residual_proposal(
                "L1-EXCEPTIONAL", "I1-LOCAL-RECOVERABLE"
            )
        },
        {"status": "CONFIRMED"},
        {
            "calculated": {
                "likelihood": 1,
                "impact": 1,
                "score": 1,
                "rating": "low",
            }
        },
        {"evidence_refs": ["EVID-FORGED"]},
    ],
)
@pytest.mark.parametrize("inactive_status", ["retired", "superseded"])
def test_residual_confirm_rejects_inactive_residual_mutations_atomically(
    risk_fixture, forgery, inactive_status
):
    inactive = threat_record("T-INACTIVE", status=inactive_status)
    if inactive_status == "superseded":
        inactive["lifecycle"]["superseded_by"] = ["T-01"]
    risk_fixture.threats["threats"].append(inactive)
    risk_fixture.assessment["assessments"].append(
        {
            "threat_id": "T-INACTIVE",
            "status": "PROPOSED",
            "proposed": proposal(
                "L4-PUBLIC-LOW-COMPLEXITY", "I4-CROSS-SYSTEM"
            ),
        }
    )
    risk_fixture._write_documents()
    assessment = _prepare_first_residual_review(risk_fixture)
    inactive_record = next(
        record
        for record in assessment["assessments"]
        if record["threat_id"] == "T-INACTIVE"
    )
    inactive_record["residual"] = copy.deepcopy(forgery)
    risk_fixture.paths["assessment"].write_text(
        yaml.safe_dump(assessment, sort_keys=False), encoding="utf-8"
    )
    before = _risk_authority_bytes(risk_fixture)

    result = _run_risk_command(
        risk_fixture,
        "residual-confirm",
        "--by",
        "risk-reviewer",
        "--authority",
        "self_declared",
    )

    assert result.returncode == 1
    assert "changed outside residual proposals" in result.stderr
    assert _risk_authority_bytes(risk_fixture) == before


def test_residual_cli_rejects_non_residual_change_during_bound_review(
    risk_fixture,
):
    assessment = _prepare_refresh_bound_residual_review(risk_fixture)
    assessment["assessments"][0]["treatment"]["owner"] = "attacker"
    risk_fixture.paths["assessment"].write_text(
        yaml.safe_dump(assessment, sort_keys=False), encoding="utf-8"
    )

    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(PLUGIN_ROOT / "scripts" / "risk.py"),
            "residual",
            *_risk_cli_document_args(risk_fixture),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert "refreshed assessment changed outside residual proposals" in result.stderr
    assert "T-01 residual risk" not in result.stdout


def test_residual_cli_rejects_forged_refresh_assessment_digest(risk_fixture):
    _prepare_refresh_bound_residual_review(risk_fixture)
    trusted_path = risk.confirmation_state_path(
        risk_fixture.paths["project_root"], "assessment"
    )
    trusted = yaml.safe_load(trusted_path.read_text(encoding="utf-8"))
    trusted["refreshed_assessment_digest"] = "sha256:forged"
    trusted_path.write_text(
        yaml.safe_dump(trusted, sort_keys=False), encoding="utf-8"
    )

    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(PLUGIN_ROOT / "scripts" / "risk.py"),
            "residual",
            *_risk_cli_document_args(risk_fixture),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert "externally bound refreshed assessment digest changed" in result.stderr
    assert "T-01 residual risk" not in result.stdout


def test_residual_cli_rejects_top_level_change_during_bound_review(risk_fixture):
    assessment = _prepare_refresh_bound_residual_review(risk_fixture)
    assessment["migration"] = {"status": "forged"}
    risk_fixture.paths["assessment"].write_text(
        yaml.safe_dump(assessment, sort_keys=False), encoding="utf-8"
    )

    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(PLUGIN_ROOT / "scripts" / "risk.py"),
            "residual",
            *_risk_cli_document_args(risk_fixture),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert "refreshed assessment top-level material changed" in result.stderr
    assert "T-01 residual risk" not in result.stdout


def test_refresh_cli_persists_requirement_staleness_before_review(risk_fixture):
    _add_confirmed_residual(risk_fixture)
    requirements = yaml.safe_load(
        risk_fixture.paths["requirements"].read_text(encoding="utf-8")
    )
    requirements["requirements"][0]["managed"]["statement"] = (
        "Every movie-rating write requires explicit authorisation."
    )
    risk_fixture.paths["requirements"].write_text(
        yaml.safe_dump(requirements, sort_keys=False), encoding="utf-8"
    )

    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(PLUGIN_ROOT / "scripts" / "risk.py"),
            "refresh",
            *_risk_cli_document_args(risk_fixture),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "T-01 residual risk is STALE" in result.stdout
    assessment = yaml.safe_load(
        risk_fixture.paths["assessment"].read_text(encoding="utf-8")
    )
    assert assessment["assessments"][0]["status"] == "CONFIRMED"
    assert assessment["assessments"][0]["residual"]["status"] == "STALE"
    assert "confirmation" not in assessment
    state = yaml.safe_load(
        risk_fixture.paths["state"].read_text(encoding="utf-8")
    )
    assert state["refresh_baseline"]["requirements"] == requirements


def test_refresh_transaction_restores_all_prior_bytes_after_replace_then_raise(
    risk_fixture, monkeypatch
):
    _add_confirmed_residual(risk_fixture)
    requirements = yaml.safe_load(
        risk_fixture.paths["requirements"].read_text(encoding="utf-8")
    )
    requirements["requirements"][0]["managed"]["statement"] = "Changed."
    risk_fixture.paths["requirements"].write_text(
        yaml.safe_dump(requirements, sort_keys=False), encoding="utf-8"
    )
    assessment_before = risk_fixture.paths["assessment"].read_bytes()
    state_before = risk_fixture.paths["state"].read_bytes()
    trusted_path = risk.confirmation_state_path(
        risk_fixture.paths["project_root"], "assessment"
    )
    trusted_before = trusted_path.read_bytes()
    real_write = risk.safe_write_text
    failed = False

    def replace_state_then_fail(path, *args, **kwargs):
        nonlocal failed
        result = real_write(path, *args, **kwargs)
        if Path(path) == risk_fixture.paths["state"] and not failed:
            failed = True
            raise OSError("injected refresh state failure")
        return result

    monkeypatch.setattr(risk, "safe_write_text", replace_state_then_fail)

    with pytest.raises(OSError, match="injected refresh state failure"):
        risk.refresh_persisted_assessment(risk_fixture.paths)

    assert risk_fixture.paths["assessment"].read_bytes() == assessment_before
    assert risk_fixture.paths["state"].read_bytes() == state_before
    assert trusted_path.read_bytes() == trusted_before


@pytest.mark.parametrize("tamper", ["delete", "rewrite"])
def test_reconfirm_rejects_tampered_externally_bound_refresh_history(
    risk_fixture, tamper
):
    risk_fixture.confirm_all()
    risk_fixture.change_threat("T-01", scenario="changed after confirmation")
    risk.refresh_persisted_assessment(risk_fixture.paths)
    trusted_path = risk.confirmation_state_path(
        risk_fixture.paths["project_root"], "assessment"
    )
    trusted = yaml.safe_load(trusted_path.read_text(encoding="utf-8"))
    assert trusted["status"] == "refresh_bound"
    trusted_before = trusted_path.read_bytes()

    state = yaml.safe_load(risk_fixture.paths["state"].read_text(encoding="utf-8"))
    if tamper == "delete":
        state["snapshots"] = []
    else:
        state["snapshots"][0]["event"] = "forged"
    risk_fixture.paths["state"].write_text(
        yaml.safe_dump(state, sort_keys=False), encoding="utf-8"
    )

    with pytest.raises(
        risk.RiskValidationError, match="externally bound refreshed state changed"
    ):
        risk.stamp_assessment(
            risk_fixture.paths,
            "risk-owner",
            "self_declared",
            confirmed_at="2026-08-13T00:02:00Z",
        )

    assert trusted_path.read_bytes() == trusted_before


def test_untampered_refresh_reconfirmation_preserves_bound_history(risk_fixture):
    risk_fixture.confirm_all()
    risk_fixture.change_threat("T-01", scenario="changed after confirmation")
    refreshed, _messages = risk.refresh_persisted_assessment(risk_fixture.paths)
    assert "confirmation" not in refreshed
    trusted_path = risk.confirmation_state_path(
        risk_fixture.paths["project_root"], "assessment"
    )
    binding = yaml.safe_load(trusted_path.read_text(encoding="utf-8"))
    state_before = yaml.safe_load(
        risk_fixture.paths["state"].read_text(encoding="utf-8")
    )
    assert binding["status"] == "refresh_bound"
    assert binding["risk_state_digest"] == risk.canonical_digest(state_before)
    assert [snapshot["event"] for snapshot in state_before["snapshots"]] == [
        "confirmed",
        "refreshed",
    ]

    risk.stamp_assessment(
        risk_fixture.paths,
        "risk-owner",
        "self_declared",
        confirmed_at="2026-08-13T00:02:00Z",
    )

    state_after = yaml.safe_load(
        risk_fixture.paths["state"].read_text(encoding="utf-8")
    )
    assert state_after["snapshots"][:2] == state_before["snapshots"]
    assert [snapshot["event"] for snapshot in state_after["snapshots"]] == [
        "confirmed",
        "refreshed",
        "confirmed",
    ]


def test_bound_refresh_can_advance_after_another_material_input_change(risk_fixture):
    risk_fixture.confirm_all()
    risk_fixture.change_threat("T-01", scenario="first changed scenario")
    risk.refresh_persisted_assessment(risk_fixture.paths)
    requirements = yaml.safe_load(
        risk_fixture.paths["requirements"].read_text(encoding="utf-8")
    )
    requirements["requirements"][0]["managed"]["statement"] = "Changed again."
    risk_fixture.paths["requirements"].write_text(
        yaml.safe_dump(requirements, sort_keys=False), encoding="utf-8"
    )

    risk.refresh_persisted_assessment(risk_fixture.paths)

    state = yaml.safe_load(risk_fixture.paths["state"].read_text(encoding="utf-8"))
    trusted = yaml.safe_load(
        risk.confirmation_state_path(
            risk_fixture.paths["project_root"], "assessment"
        ).read_text(encoding="utf-8")
    )
    assert [snapshot["event"] for snapshot in state["snapshots"]] == [
        "confirmed",
        "refreshed",
        "refreshed",
    ]
    assert trusted["risk_state_digest"] == risk.canonical_digest(state)


def _change_and_confirm_policy(risk_fixture, confirmed_at):
    policy = yaml.safe_load(risk_fixture.paths["policy"].read_text(encoding="utf-8"))
    policy["publish_risk_summary"] = not policy.get("publish_risk_summary", False)
    risk_fixture.paths["policy"].write_text(
        yaml.safe_dump(policy, sort_keys=False), encoding="utf-8"
    )
    return risk.stamp_policy(
        risk_fixture.paths,
        "risk-owner",
        "self_declared",
        confirmed_at=confirmed_at,
    )


def test_confirmed_policy_change_refresh_stales_all_active_risk_and_reconfirms(
    risk_fixture,
):
    _add_confirmed_residual(risk_fixture)
    changed_policy = _change_and_confirm_policy(
        risk_fixture, "2026-08-13T00:02:00Z"
    )

    refreshed, _messages = risk.refresh_persisted_assessment(risk_fixture.paths)

    record = refreshed["assessments"][0]
    assert record["status"] == "STALE"
    assert record["residual"]["status"] == "STALE"
    assert "confirmation" not in refreshed
    state = yaml.safe_load(risk_fixture.paths["state"].read_text(encoding="utf-8"))
    trusted = yaml.safe_load(
        risk.confirmation_state_path(
            risk_fixture.paths["project_root"], "assessment"
        ).read_text(encoding="utf-8")
    )
    assert state["refresh_baseline"]["policy_digest"] == risk.policy_digest(
        changed_policy
    )
    assert [snapshot["event"] for snapshot in state["snapshots"]] == [
        "confirmed",
        "refreshed",
        "residual_confirmed",
        "refreshed",
    ]
    assert trusted["status"] == "refresh_bound"
    assert trusted["policy_digest"] == risk.policy_digest(changed_policy)

    risk.stamp_assessment(
        risk_fixture.paths,
        "risk-owner",
        "self_declared",
        confirmed_at="2026-08-13T00:03:00Z",
    )

    assert risk.check_assessment(risk_fixture.paths) == []


def test_refresh_bound_policy_change_advances_binding_before_reconfirmation(
    risk_fixture,
):
    _add_confirmed_residual(risk_fixture)
    risk_fixture.change_threat("T-01", scenario="first changed scenario")
    first_refresh, _messages = risk.refresh_persisted_assessment(risk_fixture.paths)
    assert first_refresh["assessments"][0]["status"] == "STALE"
    assert first_refresh["assessments"][0]["residual"]["status"] == "CONFIRMED"
    changed_policy = _change_and_confirm_policy(
        risk_fixture, "2026-08-13T00:02:00Z"
    )

    second_refresh, _messages = risk.refresh_persisted_assessment(risk_fixture.paths)

    assert second_refresh["assessments"][0]["residual"]["status"] == "STALE"
    state_before = yaml.safe_load(
        risk_fixture.paths["state"].read_text(encoding="utf-8")
    )
    trusted = yaml.safe_load(
        risk.confirmation_state_path(
            risk_fixture.paths["project_root"], "assessment"
        ).read_text(encoding="utf-8")
    )
    assert state_before["refresh_baseline"]["policy_digest"] == risk.policy_digest(
        changed_policy
    )
    assert [snapshot["event"] for snapshot in state_before["snapshots"]] == [
        "confirmed",
        "refreshed",
        "residual_confirmed",
        "refreshed",
        "refreshed",
    ]
    assert trusted["risk_state_digest"] == risk.canonical_digest(state_before)
    assert trusted["policy_digest"] == risk.policy_digest(changed_policy)

    risk.stamp_assessment(
        risk_fixture.paths,
        "risk-owner",
        "self_declared",
        confirmed_at="2026-08-13T00:03:00Z",
    )

    state_after = yaml.safe_load(
        risk_fixture.paths["state"].read_text(encoding="utf-8")
    )
    assert state_after["snapshots"][:5] == state_before["snapshots"]
    assert state_after["snapshots"][-1]["event"] == "confirmed"


def test_unchanged_policy_refresh_is_a_byte_preserving_noop(risk_fixture):
    risk_fixture.confirm_all()
    trusted_path = risk.confirmation_state_path(
        risk_fixture.paths["project_root"], "assessment"
    )
    before = {
        "assessment": risk_fixture.paths["assessment"].read_bytes(),
        "state": risk_fixture.paths["state"].read_bytes(),
        "trusted": trusted_path.read_bytes(),
    }

    assessment, messages = risk.refresh_persisted_assessment(risk_fixture.paths)

    assert messages == []
    assert assessment["confirmation"]["status"] == "confirmed"
    assert risk_fixture.paths["assessment"].read_bytes() == before["assessment"]
    assert risk_fixture.paths["state"].read_bytes() == before["state"]
    assert trusted_path.read_bytes() == before["trusted"]


def test_refresh_external_binding_failure_restores_repository_and_trusted_bytes(
    risk_fixture, monkeypatch
):
    risk_fixture.confirm_all()
    risk_fixture.change_threat("T-01", scenario="changed after confirmation")
    trusted_path = risk.confirmation_state_path(
        risk_fixture.paths["project_root"], "assessment"
    )
    assessment_before = risk_fixture.paths["assessment"].read_bytes()
    state_before = risk_fixture.paths["state"].read_bytes()
    trusted_before = trusted_path.read_bytes()
    real_write = risk.safe_write_text
    failed = False

    def replace_binding_then_fail(path, *args, **kwargs):
        nonlocal failed
        result = real_write(path, *args, **kwargs)
        if Path(path) == trusted_path and not failed:
            failed = True
            raise OSError("injected external binding failure")
        return result

    monkeypatch.setattr(risk, "safe_write_text", replace_binding_then_fail)

    with pytest.raises(OSError, match="injected external binding failure"):
        risk.refresh_persisted_assessment(risk_fixture.paths)

    assert risk_fixture.paths["assessment"].read_bytes() == assessment_before
    assert risk_fixture.paths["state"].read_bytes() == state_before
    assert trusted_path.read_bytes() == trusted_before


def test_check_blocks_changed_requirement_while_residual_remains_confirmed(
    risk_fixture,
):
    _add_confirmed_residual(risk_fixture)
    requirements = yaml.safe_load(
        risk_fixture.paths["requirements"].read_text(encoding="utf-8")
    )
    requirements["requirements"][0]["managed"]["statement"] = "Changed."
    risk_fixture.paths["requirements"].write_text(
        yaml.safe_dump(requirements, sort_keys=False), encoding="utf-8"
    )

    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(PLUGIN_ROOT / "scripts" / "risk.py"),
            "check",
            *_risk_cli_document_args(risk_fixture),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert "risk refresh required" in result.stderr
    assert "T-01 residual risk would become STALE" in result.stderr


def test_publisher_blocks_changed_requirement_before_public_bytes_change(
    risk_fixture, tmp_path
):
    _add_confirmed_residual(risk_fixture)
    requirements = yaml.safe_load(
        risk_fixture.paths["requirements"].read_text(encoding="utf-8")
    )
    requirements["requirements"][0]["managed"]["statement"] = "Changed."
    risk_fixture.paths["requirements"].write_text(
        yaml.safe_dump(requirements, sort_keys=False), encoding="utf-8"
    )
    public = risk_fixture.paths["project_root"] / "docs" / "security"
    public.mkdir(parents=True)
    (public / "requirements.md").write_text("old requirements\n", encoding="utf-8")
    before = (public / "requirements.md").read_bytes()
    generated = tmp_path / "generated"
    generated.mkdir()
    for name in ("requirements.md", "traceability.md", "responsibility.md"):
        (generated / name).write_text(f"new {name}\n", encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(PLUGIN_ROOT / "scripts" / "publish.py"),
            "--project-root",
            str(risk_fixture.paths["project_root"]),
            "--generated",
            str(generated),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert "risk refresh required" in result.stderr
    assert (public / "requirements.md").read_bytes() == before


def test_risk_history_records_migrate_confirm_refresh_and_reconfirm(
    tmp_path, monkeypatch
):
    project = tmp_path / "legacy history project"
    monkeypatch.setenv("SECURITY_REQUIREMENTS_DATA", str(tmp_path / "trusted"))
    monkeypatch.delenv("CLAUDE_PLUGIN_DATA", raising=False)
    threats_path, requirements_path = _seed_legacy_migration_project(project)
    internal = project / ".security-requirements"
    evidence_path = internal / "risk-evidence.yaml"
    evidence_path.write_text("evidence: []\n", encoding="utf-8")
    migration = _run_migration_cli(project, threats_path, requirements_path)
    assert migration.returncode == 0, migration.stderr

    assessment_path = internal / "risk-assessment.yaml"
    assessment = yaml.safe_load(assessment_path.read_text(encoding="utf-8"))
    assessment["assessments"][0]["proposed"] = proposal(
        "L4-PUBLIC-LOW-COMPLEXITY", "I3-CORE-SERVICE"
    )
    assessment["assessments"][0]["treatment"] = {
        "strategy": "mitigate",
        "owner": "movie-team",
    }
    assessment_path.write_text(
        yaml.safe_dump(assessment, sort_keys=False), encoding="utf-8"
    )
    command = [sys.executable, "-I", str(PLUGIN_ROOT / "scripts" / "risk.py")]
    policy_path = internal / "risk-policy.yaml"
    state_path = internal / "risk-state.yaml"
    policy = subprocess.run(
        [
            *command,
            "policy-confirm",
            "--project-root",
            str(project),
            "--policy",
            str(policy_path),
            "--by",
            "risk-owner",
            "--authority",
            "self_declared",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    common = [
        "--project-root",
        str(project),
        "--policy",
        str(policy_path),
        "--threats",
        str(threats_path),
        "--assessment",
        str(assessment_path),
        "--requirements",
        str(requirements_path),
        "--evidence",
        str(evidence_path),
        "--state",
        str(state_path),
    ]
    confirmed = subprocess.run(
        [
            *command,
            "confirm",
            *common,
            "--by",
            "risk-owner",
            "--authority",
            "self_declared",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert policy.returncode == 0, policy.stderr
    assert confirmed.returncode == 0, confirmed.stderr

    threats = yaml.safe_load(threats_path.read_text(encoding="utf-8"))
    threats["threats"][0]["scenario"] = "anonymous bulk rating manipulation"
    threats_path.write_text(
        yaml.safe_dump(threats, sort_keys=False), encoding="utf-8"
    )
    refreshed = subprocess.run(
        [*command, "refresh", *common],
        capture_output=True,
        text=True,
        check=False,
    )
    reconfirmed = subprocess.run(
        [
            *command,
            "confirm",
            *common,
            "--by",
            "risk-owner",
            "--authority",
            "self_declared",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert refreshed.returncode == 0, refreshed.stderr
    assert reconfirmed.returncode == 0, reconfirmed.stderr

    state = yaml.safe_load(state_path.read_text(encoding="utf-8"))
    snapshots = state["snapshots"]
    assert [row["event"] for row in snapshots] == [
        "migrated",
        "confirmed",
        "refreshed",
        "confirmed",
    ]
    assert [row["assessments"][0]["status"] for row in snapshots] == [
        "PROPOSED",
        "CONFIRMED",
        "STALE",
        "CONFIRMED",
    ]
    for snapshot in snapshots:
        declared = snapshot["snapshot_digest"]
        material = copy.deepcopy(snapshot)
        material.pop("snapshot_digest")
        assert declared == risk.canonical_digest(material)
        assert snapshot["assessments"][0]["lifecycle"]["status"] == "active"
    repository = yaml.safe_load(assessment_path.read_text(encoding="utf-8"))
    trusted = yaml.safe_load(
        risk.confirmation_state_path(project, "assessment").read_text(
            encoding="utf-8"
        )
    )
    assert repository["confirmation"] == trusted
    assert trusted["risk_state_digest"] == risk.canonical_digest(state)
