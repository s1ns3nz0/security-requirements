#!/usr/bin/env python3
"""Deterministic risk-policy and inherent-risk calculation primitives."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml


class RiskValidationError(ValueError):
    """Raised when policy or assessment data cannot be evaluated safely."""


THREAT_DIGEST_FIELDS = (
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
RATINGS = ("critical", "high", "medium", "low")
ASSESSMENT_STATUSES = {"CONFIRMED", "UNDETERMINED", "PROPOSED", "STALE"}
LIFELIHOOD_EVIDENCE_FIELDS = (
    "exposure",
    "access_required",
    "exploit_complexity",
    "preconditions",
    "observed_controls",
)


def load_policy(path: Path) -> dict:
    """Load a YAML policy and require its document to be a mapping."""

    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RiskValidationError("risk policy must be a mapping")
    return value


def criterion_score(policy: dict, axis: str, criterion: str) -> int:
    """Resolve a criterion ID to its bounded five-point score."""

    try:
        score = policy[axis][criterion]["score"]
    except (KeyError, TypeError) as exc:
        raise RiskValidationError(f"unknown {axis} criterion: {criterion}") from exc
    if isinstance(score, bool) or not isinstance(score, int) or not 1 <= score <= 5:
        raise RiskValidationError(f"{axis} criterion {criterion} has invalid score")
    return score


def rating_for_score(policy: dict, score: int) -> str:
    """Resolve a numeric score, requiring exactly one matching threshold."""

    if isinstance(score, bool) or not isinstance(score, int):
        raise RiskValidationError(f"score {score} matches 0 thresholds")
    try:
        matches = [
            row["rating"]
            for row in policy["thresholds"]
            if row["min"] <= score <= row["max"]
        ]
    except (KeyError, TypeError) as exc:
        raise RiskValidationError("risk policy thresholds are invalid") from exc
    if len(matches) != 1:
        raise RiskValidationError(f"score {score} matches {len(matches)} thresholds")
    return matches[0]


def _require_rationale(value: Any, label: str) -> None:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)) or not value:
        raise RiskValidationError(f"{label} rationale is required")
    if any(not isinstance(item, str) or not item.strip() for item in value):
        raise RiskValidationError(f"{label} rationale is required")


def calculate_inherent(policy: dict, proposed: dict) -> dict:
    """Calculate inherent risk from criterion IDs and explicit consequences."""

    if not isinstance(proposed, Mapping):
        raise RiskValidationError("assessment proposal must be a mapping")
    likelihood_data = proposed.get("likelihood")
    if not isinstance(likelihood_data, Mapping):
        raise RiskValidationError("likelihood proposal is required")
    _require_rationale(likelihood_data.get("rationale"), "likelihood")
    try:
        likelihood_criterion = likelihood_data["criterion"]
    except KeyError as exc:
        raise RiskValidationError("likelihood criterion is required") from exc
    likelihood = criterion_score(policy, "likelihood", likelihood_criterion)

    consequences = proposed.get("consequences")
    if not isinstance(consequences, Sequence) or isinstance(consequences, (str, bytes)):
        raise RiskValidationError("at least one consequence is required")
    if not consequences:
        raise RiskValidationError("at least one consequence is required")

    impacts: list[int] = []
    consequence_ids: set[str] = set()
    for item in consequences:
        if not isinstance(item, Mapping):
            raise RiskValidationError("consequence must be a mapping")
        consequence_id = item.get("id")
        if not isinstance(consequence_id, str) or not consequence_id:
            raise RiskValidationError("consequence id is required")
        consequence_ids.add(consequence_id)
        _require_rationale(item.get("rationale"), "consequence")
        try:
            criterion = item["criterion"]
        except KeyError as exc:
            raise RiskValidationError("consequence criterion is required") from exc
        impacts.append(criterion_score(policy, "impact", criterion))

    impact_data = proposed.get("impact")
    if not isinstance(impact_data, Mapping):
        raise RiskValidationError("impact selection is required")
    selected_from = impact_data.get("selected_from")
    if selected_from not in consequence_ids:
        raise RiskValidationError("impact selected_from must identify a consequence")
    selected_index = next(
        index for index, item in enumerate(consequences) if item["id"] == selected_from
    )
    impact = max(impacts)
    if impacts[selected_index] != impact:
        raise RiskValidationError("impact selected_from must identify the highest consequence")

    score = likelihood * impact
    return {
        "likelihood": likelihood,
        "impact": impact,
        "score": score,
        "rating": rating_for_score(policy, score),
    }


def canonical_digest(value: object) -> str:
    """Return a stable SHA-256 digest for JSON-compatible structured data."""

    try:
        canonical = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise RiskValidationError("value cannot be canonically digested") from exc
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def threat_digest(threat: dict) -> str:
    """Digest the material threat identity, excluding lifecycle state."""

    if not isinstance(threat, Mapping):
        raise RiskValidationError("threat must be a mapping")
    material = {key: threat.get(key) for key in THREAT_DIGEST_FIELDS}
    return canonical_digest(material)


def _lifecycle_status(threat: Mapping) -> str:
    lifecycle = threat.get("lifecycle") or {}
    if not isinstance(lifecycle, Mapping):
        raise RiskValidationError(f"{threat.get('id', '<unknown>')} lifecycle must be a mapping")
    status = lifecycle.get("status") or "active"
    if not isinstance(status, str):
        raise RiskValidationError(f"{threat.get('id', '<unknown>')} lifecycle status is invalid")
    normalized = status.lower()
    if normalized not in {"active", "retired", "superseded"}:
        raise RiskValidationError(
            f"{threat.get('id', '<unknown>')} has unknown lifecycle status: {status}"
        )
    return normalized


def active_threats(threats_doc: dict) -> list[dict]:
    """Return current threats, retaining retired records only as history."""

    if not isinstance(threats_doc, Mapping):
        raise RiskValidationError("threat document must be a mapping")
    threats = threats_doc.get("threats") or []
    if not isinstance(threats, Sequence) or isinstance(threats, (str, bytes)):
        raise RiskValidationError("threats must be a list")

    result = []
    for threat in threats:
        if not isinstance(threat, Mapping):
            raise RiskValidationError("threat must be a mapping")
        threat_id = threat.get("id")
        if not isinstance(threat_id, str) or not threat_id:
            raise RiskValidationError("threat id is required")
        status = _lifecycle_status(threat)
        if status == "active":
            result.append(dict(threat))
        elif status == "superseded":
            lifecycle = threat.get("lifecycle") or {}
            replacements = lifecycle.get("superseded_by")
            if (
                not isinstance(replacements, Sequence)
                or isinstance(replacements, (str, bytes))
                or not replacements
                or any(not isinstance(value, str) or not value for value in replacements)
            ):
                raise RiskValidationError(
                    f"{threat_id} is superseded without replacement IDs"
                )
    return result


def _is_nonempty_text_list(value: Any) -> bool:
    return (
        isinstance(value, Sequence)
        and not isinstance(value, (str, bytes))
        and bool(value)
        and all(isinstance(item, str) and item.strip() for item in value)
    )


def _validate_threats(threats_doc: dict) -> tuple[list[str], list[dict]]:
    problems: list[str] = []
    if not isinstance(threats_doc, Mapping):
        return ["threat document must be a mapping"], []
    if threats_doc.get("version") != "0.2.0":
        problems.append("threat schema version must be 0.2.0")
    threats = threats_doc.get("threats")
    if not isinstance(threats, Sequence) or isinstance(threats, (str, bytes)):
        return problems + ["threats must be a list"], []

    seen_ids: set[str] = set()
    for threat in threats:
        if not isinstance(threat, Mapping):
            problems.append("threat must be a mapping")
            continue
        threat_id = threat.get("id")
        label = threat_id if isinstance(threat_id, str) and threat_id else "<unknown>"
        if not isinstance(threat_id, str) or not threat_id:
            problems.append("threat id is required")
        elif threat_id in seen_ids:
            problems.append(f"duplicate threat id: {threat_id}")
        else:
            seen_ids.add(threat_id)
        for field in (
            "boundary",
            "category",
            "novelty",
            "persona",
            "attack_path",
            "scenario",
        ):
            if not isinstance(threat.get(field), str) or not threat[field].strip():
                problems.append(f"{label} {field} is required")
        for field in ("affected_assets", "related_controls"):
            value = threat.get(field)
            if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
                problems.append(f"{label} {field} must be a list")
        if not isinstance(threat.get("lifecycle"), Mapping):
            problems.append(f"{label} lifecycle is required")

    try:
        active = active_threats(threats_doc)
    except RiskValidationError as exc:
        problems.append(str(exc))
        active = []
    return problems, active


def _validate_likelihood_evidence(threat_id: str, proposed: Mapping) -> list[str]:
    problems: list[str] = []
    likelihood = proposed.get("likelihood")
    if not isinstance(likelihood, Mapping):
        return [f"{threat_id} likelihood proposal is required"]
    evidence = likelihood.get("evidence")
    if not isinstance(evidence, Mapping):
        return [f"{threat_id} likelihood evidence is required"]
    for field in LIFELIHOOD_EVIDENCE_FIELDS[:3]:
        if not isinstance(evidence.get(field), str) or not evidence[field].strip():
            problems.append(f"{threat_id} likelihood evidence {field} is required")
    for field in LIFELIHOOD_EVIDENCE_FIELDS[3:]:
        value = evidence.get(field)
        if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
            problems.append(f"{threat_id} likelihood evidence {field} must be a list")
    return problems


def _validate_scope_expansion(threat_id: str, proposed: Mapping) -> list[str]:
    problems: list[str] = []
    consequences = proposed.get("consequences")
    if not isinstance(consequences, Sequence) or isinstance(consequences, (str, bytes)):
        return problems
    for consequence in consequences:
        if not isinstance(consequence, Mapping) or "scope_expansion" not in consequence:
            continue
        consequence_id = consequence.get("id", "<unknown>")
        expansion = consequence["scope_expansion"]
        if not isinstance(expansion, Mapping) or not _is_nonempty_text_list(
            expansion.get("evidence")
        ):
            problems.append(
                f"{threat_id} consequence {consequence_id} scope_expansion evidence is required"
            )
    return problems


def _validated_calculation(
    threat_id: str, record: Mapping, policy: dict
) -> list[str]:
    proposed = record.get("proposed")
    if not isinstance(proposed, Mapping):
        return [f"{threat_id} assessment proposal is required"]

    problems = _validate_likelihood_evidence(threat_id, proposed)
    problems.extend(_validate_scope_expansion(threat_id, proposed))
    try:
        calculated = calculate_inherent(policy, dict(proposed))
    except RiskValidationError as exc:
        problems.append(f"{threat_id} {exc}")
        return problems

    declared = record.get("calculated")
    if declared is not None:
        if not isinstance(declared, Mapping):
            problems.append(f"{threat_id} calculated result must be a mapping")
        else:
            for field in ("score", "rating"):
                if field in declared and declared[field] != calculated[field]:
                    problems.append(f"{threat_id} calculated {field} disagrees with policy")
    return problems


def validate_assessment(threats: dict, assessment: dict, policy: dict) -> list[str]:
    """Return deterministic validation problems for a threat assessment document."""

    problems, active = _validate_threats(threats)
    if not isinstance(assessment, Mapping):
        return problems + ["assessment document must be a mapping"]
    records = assessment.get("assessments")
    if not isinstance(records, Sequence) or isinstance(records, (str, bytes)):
        return problems + ["assessments must be a list"]
    if not isinstance(threats, Mapping):
        return problems

    known_ids = {
        threat["id"]
        for threat in threats.get("threats", [])
        if isinstance(threat, Mapping) and isinstance(threat.get("id"), str)
    }
    records_by_id: dict[str, Mapping] = {}
    for record in records:
        if not isinstance(record, Mapping):
            problems.append("assessment record must be a mapping")
            continue
        threat_id = record.get("threat_id")
        if not isinstance(threat_id, str) or not threat_id:
            problems.append("assessment threat_id is required")
            continue
        if threat_id in records_by_id:
            problems.append(f"duplicate assessment for threat: {threat_id}")
            continue
        records_by_id[threat_id] = record
        if threat_id not in known_ids:
            problems.append(f"assessment references unknown threat: {threat_id}")
        status = record.get("status")
        if status not in ASSESSMENT_STATUSES:
            problems.append(f"{threat_id} assessment status is invalid")
        if status == "CONFIRMED":
            problems.extend(_validated_calculation(threat_id, record, policy))

    for threat in active:
        threat_id = threat["id"]
        record = records_by_id.get(threat_id)
        if record is None:
            problems.append(f"{threat_id} assessment is missing")
        elif record.get("status") != "CONFIRMED":
            problems.append(f"{threat_id} assessment is not confirmed")
    return problems


def aggregate_risk(threats: dict, assessment: dict) -> dict:
    """Summarise active inherent-risk ratings without averaging independent risks."""

    active = active_threats(threats)
    if not isinstance(assessment, Mapping):
        raise RiskValidationError("assessment document must be a mapping")
    records = assessment.get("assessments")
    if not isinstance(records, Sequence) or isinstance(records, (str, bytes)):
        raise RiskValidationError("assessments must be a list")

    records_by_id: dict[str, Mapping] = {}
    for record in records:
        if not isinstance(record, Mapping):
            raise RiskValidationError("assessment record must be a mapping")
        threat_id = record.get("threat_id")
        if not isinstance(threat_id, str) or not threat_id:
            raise RiskValidationError("assessment threat_id is required")
        if threat_id in records_by_id:
            raise RiskValidationError(f"duplicate assessment for threat: {threat_id}")
        records_by_id[threat_id] = record

    counts = {rating: 0 for rating in RATINGS}
    confirmed = 0
    unresolved = False
    for threat in active:
        record = records_by_id.get(threat["id"])
        if record is None or record.get("status") != "CONFIRMED":
            unresolved = True
            continue
        calculated = record.get("calculated")
        rating = calculated.get("rating") if isinstance(calculated, Mapping) else None
        if rating not in counts:
            raise RiskValidationError(f"{threat['id']} confirmed rating is invalid")
        counts[rating] += 1
        confirmed += 1

    overall = next((rating for rating in RATINGS if counts[rating]), "UNDETERMINED")
    return {
        "overall": overall,
        "status": "provisional" if unresolved else "confirmed",
        "counts": counts,
        "coverage": f"{confirmed}/{len(active)}",
    }
