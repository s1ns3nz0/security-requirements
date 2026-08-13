"""Shared test data constructors for the threat-risk feature."""

from __future__ import annotations

import copy
from pathlib import Path

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


def run_risk_golden(case: Path) -> dict:
    """Execute a golden assessment through the real deterministic risk engine."""

    import risk

    plugin_root = Path(__file__).resolve().parent.parent / "plugins" / "security-requirements"
    policy = risk.load_policy(plugin_root / "risk" / "default-policy.yaml")
    threats = yaml.safe_load((case / "threats.yaml").read_text(encoding="utf-8"))
    assessment = yaml.safe_load(
        (case / "risk-assessment.yaml").read_text(encoding="utf-8")
    )

    problems = risk.validate_assessment(threats, assessment, policy)
    if problems:
        raise AssertionError("invalid golden risk assessment: " + "; ".join(problems))

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
    opt_in_policy = copy.deepcopy(policy)
    opt_in_policy["publish_risk_summary"] = True
    return {
        "inherent": inherent,
        "residual": residual,
        "coverage": inherent["coverage"],
        "assessments": assessed,
        "internal_register": risk.render_register(report_summary),
        "default_public_summary": risk.render_public_summary(report_summary, policy),
        "opt_in_public_summary": risk.render_public_summary(
            report_summary, opt_in_policy
        ),
    }
