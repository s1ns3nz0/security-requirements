"""Shared test data constructors for the threat-risk feature."""

from __future__ import annotations

import copy
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import yaml


def consequence(id: str, criterion: str) -> dict:
    return {
        "id": id,
        "asset": "movie_records",
        "axis": "integrity",
        "criterion": criterion,
        "rationale": ["catalogue records are affected"],
    }


def proposal(likelihood: str, impact: str) -> dict:
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
        "consequences": [consequence("C-01", impact)],
        "impact": {"selected_from": "C-01"},
    }


def threat_record(id: str, status: str = "active", **changes) -> dict:
    record = {
        "id": id,
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


def assessment_record(
    threat_id: str, status: str, rating: str | None = None, **changes
) -> dict:
    record = {"threat_id": threat_id, "status": status}
    if rating is not None:
        record["calculated"] = {"rating": rating}
    record.update(changes)
    return record


def _external_confirmation(
    data_root: Path, project_root: Path, kind: str
) -> dict:
    key = hashlib.sha256(str(project_root.resolve()).encode()).hexdigest()
    path = data_root / "risk" / kind / f"{key}.yaml"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _run_confirmation_cli(command: list[str], env: dict[str, str]) -> dict:
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    return {
        "returncode": completed.returncode,
        "stdout": completed.stdout.strip(),
        "stderr": completed.stderr.strip(),
    }


def _confirm_golden_variant(
    case: Path,
    workspace: Path,
    plugin_root: Path,
    *,
    name: str,
    publish_risk_summary: bool,
) -> dict:
    """Confirm one exact golden batch through the public isolated CLI."""

    import risk

    project_root = workspace / f"{name} movie project 한글"
    documents = project_root / ".security-requirements"
    data_root = workspace / f"{name} external authority Ω"
    documents.mkdir(parents=True)
    paths = {
        "project_root": project_root,
        "policy": documents / "risk-policy.yaml",
        "threats": documents / "threats.yaml",
        "assessment": documents / "risk-assessment.yaml",
        "requirements": documents / "requirements.yaml",
        "evidence": documents / "risk-evidence.yaml",
        "state": documents / "risk-state.yaml",
    }
    paths["threats"].write_bytes((case / "threats.yaml").read_bytes())
    paths["assessment"].write_bytes((case / "risk-assessment.yaml").read_bytes())
    paths["state"].write_bytes((case / "risk-state.yaml").read_bytes())
    paths["requirements"].write_text("requirements: []\n", encoding="utf-8")
    paths["evidence"].write_text("evidence: []\n", encoding="utf-8")
    policy = risk.load_policy(plugin_root / "risk" / "default-policy.yaml")
    policy["publish_risk_summary"] = publish_risk_summary
    paths["policy"].write_text(
        yaml.safe_dump(policy, allow_unicode=True, sort_keys=False), encoding="utf-8"
    )

    script = plugin_root / "scripts" / "risk.py"
    common = [
        "--project-root",
        str(project_root),
        "--policy",
        str(paths["policy"]),
    ]
    assessment_paths = [
        *common,
        "--threats",
        str(paths["threats"]),
        "--assessment",
        str(paths["assessment"]),
        "--requirements",
        str(paths["requirements"]),
        "--evidence",
        str(paths["evidence"]),
        "--state",
        str(paths["state"]),
    ]
    env = os.environ.copy()
    env["SECURITY_REQUIREMENTS_DATA"] = str(data_root)
    env.pop("CLAUDE_PLUGIN_DATA", None)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    base = [sys.executable, "-I", str(script)]
    policy_result = _run_confirmation_cli(
        [
            *base,
            "policy-confirm",
            *common,
            "--by",
            "movie-rating-risk-owner",
            "--authority",
            "self_declared",
        ],
        env,
    )
    if policy_result["returncode"] != 0:
        raise AssertionError(f"golden policy confirmation failed: {policy_result}")
    confirm_result = _run_confirmation_cli(
        [
            *base,
            "confirm",
            *assessment_paths,
            "--by",
            "movie-rating-risk-owner",
            "--authority",
            "self_declared",
        ],
        env,
    )
    if confirm_result["returncode"] != 0:
        raise AssertionError(f"golden batch confirmation failed: {confirm_result}")
    check_result = _run_confirmation_cli(
        [*base, "check", *assessment_paths], env
    )
    if check_result["returncode"] != 0:
        raise AssertionError(f"golden authority check failed: {check_result}")

    policy = yaml.safe_load(paths["policy"].read_text(encoding="utf-8"))
    threats = yaml.safe_load(paths["threats"].read_text(encoding="utf-8"))
    assessment = yaml.safe_load(paths["assessment"].read_text(encoding="utf-8"))
    state = yaml.safe_load(paths["state"].read_text(encoding="utf-8"))
    repository_policy = policy["confirmation"]
    repository_assessment = assessment["confirmation"]
    external_policy = _external_confirmation(data_root, project_root, "policy")
    external_assessment = _external_confirmation(
        data_root, project_root, "assessment"
    )
    return {
        "paths": paths,
        "policy_document": policy,
        "threat_document": threats,
        "assessment_document": assessment,
        "state_document": state,
        "publish_risk_summary": publish_risk_summary,
        "policy_confirm": policy_result,
        "confirm": confirm_result,
        "confirm_invocations": 1,
        "confirmed_threat_ids": [row["threat_id"] for row in assessment["assessments"]],
        "check": check_result,
        "policy": {
            "repository": repository_policy,
            "external": external_policy,
        },
        "assessment": {
            "repository": repository_assessment,
            "external": external_assessment,
        },
        "binding_matches": {
            "policy": repository_policy.get("policy_digest")
            == risk.policy_digest(policy),
            "threats": repository_assessment.get("threat_digest")
            == risk.aggregate_threat_digest(threats),
            "assessment": repository_assessment.get("assessment_digest")
            == risk.assessment_digest(assessment),
            "state": repository_assessment.get("risk_state_digest")
            == risk.canonical_digest(state),
        },
    }


def _golden_report(risk, threats: dict, assessment: dict, policy: dict) -> dict:
    """Build deterministic aggregates from one authority-checked batch."""

    threat_by_id = {record["id"]: record for record in threats["threats"]}
    assessed: list[dict] = []
    report_records: list[dict] = []
    undetermined = 0
    for record in assessment["assessments"]:
        calculated = risk.calculate_inherent(policy, record["proposed"])
        if record.get("calculated") != calculated:
            raise AssertionError(
                f"{record['threat_id']} golden calculation is not engine-derived"
            )
        residual = risk.calculate_residual(
            calculated,
            {"evidence": []},
            policy,
        )
        if residual.get("status") == "UNDETERMINED":
            undetermined += 1
        assessed.append(
            {
                "threat_id": record["threat_id"],
                **calculated,
                "residual": residual["status"],
            }
        )
        threat = threat_by_id[record["threat_id"]]
        report_records.append(
            {
                **copy.deepcopy(threat),
                **copy.deepcopy(record),
                "residual": residual,
            }
        )

    inherent = risk.aggregate_risk(threats, assessment)
    residual = {
        "overall": "UNDETERMINED",
        "status": "provisional",
        "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "coverage": f"0/{len(assessed)}",
        "confirmed": 0,
        "undetermined": undetermined,
    }
    report_summary = {
        "inherent": inherent,
        "residual": residual,
        "risks": report_records,
    }
    return {
        "inherent": inherent,
        "residual": residual,
        "coverage": inherent["coverage"],
        "assessments": assessed,
        "internal_register": risk.render_register(report_summary),
        "public_summary": risk.render_public_summary(report_summary, policy),
    }


def run_risk_golden(case: Path) -> dict:
    """Confirm and render the golden batch through public engine boundaries."""

    import risk

    plugin_root = Path(__file__).resolve().parent.parent / "plugins" / "security-requirements"
    temporary_root: Path | None = None
    with tempfile.TemporaryDirectory(prefix="security requirements golden 확인-") as raw:
        temporary_root = Path(raw)
        default = _confirm_golden_variant(
            case,
            temporary_root,
            plugin_root,
            name="default",
            publish_risk_summary=False,
        )
        opt_in = _confirm_golden_variant(
            case,
            temporary_root,
            plugin_root,
            name="opt-in",
            publish_risk_summary=True,
        )
        for variant in (default, opt_in):
            problems = risk.validate_assessment(
                variant["threat_document"],
                variant["assessment_document"],
                variant["policy_document"],
            )
            if problems:
                raise AssertionError(
                    "invalid confirmed golden risk assessment: " + "; ".join(problems)
                )
        default_report = _golden_report(
            risk,
            default["threat_document"],
            default["assessment_document"],
            default["policy_document"],
        )
        opt_in_report = _golden_report(
            risk,
            opt_in["threat_document"],
            opt_in["assessment_document"],
            opt_in["policy_document"],
        )
        result = {
            **{key: value for key, value in default_report.items() if key != "public_summary"},
            "default_public_summary": default_report["public_summary"],
            "opt_in_public_summary": opt_in_report["public_summary"],
            "confirmation_evidence": {
                name: {
                    key: value
                    for key, value in variant.items()
                    if key
                    not in {
                        "paths",
                        "policy_document",
                        "threat_document",
                        "assessment_document",
                        "state_document",
                    }
                }
                for name, variant in (("default", default), ("opt_in", opt_in))
            },
        }
    result["temporary_root_removed"] = not temporary_root.exists()
    return result
