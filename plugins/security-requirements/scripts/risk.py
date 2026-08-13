#!/usr/bin/env python3
"""Deterministic risk-policy and inherent-risk calculation primitives."""

from __future__ import annotations

import argparse
import copy
from datetime import date, datetime, timezone
import hashlib
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
import sys
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from runtime_paths import confirmation_state_path, plugin_data_root
from safe_paths import UnsafePathError, preflight_output_paths, safe_path, safe_write_text


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
TREATMENT_STRATEGIES = {"mitigate", "avoid", "transfer", "accept"}
SNAPSHOT_FIELDS = (
    "assessed_at",
    "policy_digest",
    "threat_digest",
    "assessment_digest",
    "inherent",
    "residual",
    "treatment",
    "evidence_refs",
)
ASSESSMENT_STATUSES = {"CONFIRMED", "UNDETERMINED", "PROPOSED", "STALE"}
LIFELIHOOD_EVIDENCE_FIELDS = (
    "exposure",
    "access_required",
    "exploit_complexity",
    "preconditions",
    "observed_controls",
)
AUTHORITIES = {"self_declared", "externally_attested"}
EVIDENCE_METHODS = {
    "iac_inspect",
    "config_api",
    "code_grep",
    "test_case",
    "artifact_review",
    "manual",
}
EVIDENCE_SUPPORTS = {"likelihood", "impact", "attack_path_removal"}
MINIMUM_PYTHON = (3, 12)


class RiskArgumentError(ValueError):
    """Raised when the risk CLI does not match its strict grammar."""


class _StrictArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise RiskArgumentError(message)


class _StoreOnce(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None) -> None:
        if getattr(namespace, self.dest, None) is not None:
            raise argparse.ArgumentError(
                self, f"{option_string or self.dest} may be specified only once"
            )
        setattr(namespace, self.dest, values)


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
        if consequence_id in consequence_ids:
            raise RiskValidationError(f"duplicate consequence id: {consequence_id}")
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


def _document_records(document: object, field: str, label: str) -> list:
    if not isinstance(document, Mapping):
        return []
    records = document.get(field, [])
    if not isinstance(records, Sequence) or isinstance(records, (str, bytes)):
        raise RiskValidationError(f"{label} must be a list")
    return list(records)


def _requirement_index(requirements: object) -> tuple[dict[str, Mapping], list[str]]:
    problems: list[str] = []
    if not isinstance(requirements, Mapping):
        return {}, ["requirements document must be a mapping"]
    try:
        records = _document_records(requirements, "requirements", "requirements")
    except RiskValidationError as exc:
        return {}, [str(exc)]
    result: dict[str, Mapping] = {}
    for record in records:
        if not isinstance(record, Mapping):
            problems.append("requirement must be a mapping")
            continue
        requirement_id = record.get("id")
        if not _nonempty_text(requirement_id):
            problems.append("requirement id is required")
            continue
        if requirement_id in result:
            problems.append(f"duplicate requirement id: {requirement_id}")
            continue
        result[requirement_id] = record
    return result, problems


def _parse_observed_at(value: object) -> datetime | None:
    if not _nonempty_text(value):
        return None
    try:
        observed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return observed if observed.tzinfo is not None else None


def _parse_expiry(value: object) -> date | None:
    if not _nonempty_text(value):
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def _artifact_digest_is_valid(value: object) -> bool:
    if not _nonempty_text(value) or not value.startswith("sha256:"):
        return False
    digest = value.removeprefix("sha256:")
    return len(digest) == 64 and all(character in "0123456789abcdef" for character in digest)


def _evidence_record_problems(
    record: object,
    *,
    today: date,
    requirement: Mapping | None = None,
) -> list[str]:
    if not isinstance(record, Mapping):
        return ["evidence record must be a mapping"]
    evidence_id = record.get("id")
    label = evidence_id if _nonempty_text(evidence_id) else "<unknown evidence>"
    problems: list[str] = []
    if not _nonempty_text(evidence_id):
        problems.append("evidence id is required")
    requirement_id = record.get("requirement_id")
    if not _nonempty_text(requirement_id):
        problems.append(f"{label} requirement_id is required")
    method = record.get("method")
    if method not in EVIDENCE_METHODS:
        problems.append(f"{label} method is not supported")
    if record.get("result") != "pass":
        problems.append(f"{label} result must be pass")
    observed_at = _parse_observed_at(record.get("observed_at"))
    if observed_at is None:
        problems.append(f"{label} observed_at must be a timezone-aware ISO timestamp")
    elif observed_at.date() > today:
        problems.append(f"{label} observed_at is in the future")
    if not _nonempty_text(record.get("observed_by")):
        problems.append(f"{label} observed_by is required")

    artifact = record.get("artifact")
    if not isinstance(artifact, Mapping):
        problems.append(f"{label} artifact is required")
    else:
        for field in ("kind", "location"):
            if not _nonempty_text(artifact.get(field)):
                problems.append(f"{label} artifact {field} is required")
        if not _artifact_digest_is_valid(artifact.get("digest")):
            problems.append(f"{label} artifact digest is required")

    supports = record.get("supports", [])
    if supports is not None and (
        not isinstance(supports, Sequence) or isinstance(supports, (str, bytes))
    ):
        problems.append(f"{label} supports must be a list")
    elif any(value not in EVIDENCE_SUPPORTS for value in supports or []):
        problems.append(f"{label} supports contains an unknown residual effect")

    if "valid_until" in record:
        expiry = _parse_expiry(record.get("valid_until"))
        if expiry is None:
            problems.append(f"{label} valid_until must be an ISO date")
        elif expiry < today:
            problems.append(f"{label} is stale because its evidence expired")

    if requirement is not None:
        managed = requirement.get("managed")
        if not isinstance(managed, Mapping):
            problems.append(f"{label} linked requirement has no managed block")
        elif record.get("requirement_digest") != canonical_digest(managed):
            problems.append(
                f"{label} is stale because requirement {requirement_id} changed"
            )
        verification = managed.get("verification") if isinstance(managed, Mapping) else None
        expected_method = verification.get("method") if isinstance(verification, Mapping) else None
        if expected_method in EVIDENCE_METHODS and method != expected_method:
            problems.append(f"{label} method does not match the linked requirement")
    elif not _nonempty_text(record.get("requirement_digest")):
        problems.append(f"{label} requirement_digest is required")
    return problems


def validate_evidence(evidence: dict, requirements: dict, today: date) -> list[str]:
    """Validate implementation evidence and bind it to managed requirements."""

    requirement_by_id, problems = _requirement_index(requirements)
    if not isinstance(evidence, Mapping):
        return problems + ["evidence document must be a mapping"]
    try:
        records = _document_records(evidence, "evidence", "evidence")
    except RiskValidationError as exc:
        return problems + [str(exc)]
    seen_ids: set[str] = set()
    for record in records:
        if not isinstance(record, Mapping):
            problems.append("evidence record must be a mapping")
            continue
        evidence_id = record.get("id")
        if _nonempty_text(evidence_id):
            if evidence_id in seen_ids:
                problems.append(f"duplicate evidence id: {evidence_id}")
            seen_ids.add(evidence_id)
        requirement_id = record.get("requirement_id")
        requirement = requirement_by_id.get(requirement_id)
        if _nonempty_text(requirement_id) and requirement is None:
            label = evidence_id if _nonempty_text(evidence_id) else "<unknown evidence>"
            problems.append(
                f"{label} references unknown requirement: {requirement_id}"
            )
        problems.extend(
            _evidence_record_problems(record, today=today, requirement=requirement)
        )
    return problems


def _evidence_index(evidence: object) -> dict[str, Mapping]:
    if not isinstance(evidence, Mapping):
        return {}
    records = evidence.get("evidence", evidence)
    if isinstance(records, Mapping):
        values = records.values()
    elif isinstance(records, Sequence) and not isinstance(records, (str, bytes)):
        values = records
    else:
        return {}
    return {
        record["id"]: record
        for record in values
        if isinstance(record, Mapping) and _nonempty_text(record.get("id"))
    }


def _current_passing_evidence(
    evidence: object, requirements: object, today: date
) -> dict[str, Mapping]:
    requirement_by_id, requirement_problems = _requirement_index(requirements)
    if requirement_problems:
        return {}
    current: dict[str, Mapping] = {}
    for evidence_id, record in _evidence_index(evidence).items():
        requirement = requirement_by_id.get(record.get("requirement_id"))
        if requirement is not None and not _evidence_record_problems(
            record, today=today, requirement=requirement
        ):
            current[evidence_id] = record
    return current


def _reduction_evidence(
    proposed: Mapping,
    axis: str,
    current: Mapping[str, Mapping],
) -> list[Mapping]:
    axis_data = proposed.get(axis)
    if not isinstance(axis_data, Mapping):
        raise RiskValidationError(f"residual {axis} proposal is required")
    change_field = (
        "changed_attack_condition" if axis == "likelihood" else "changed_consequence"
    )
    if not _nonempty_text(axis_data.get(change_field)):
        raise RiskValidationError(
            f"residual {axis} reduction must name the changed "
            + ("attack condition" if axis == "likelihood" else "consequence")
        )
    refs = axis_data.get("evidence_refs")
    if (
        not isinstance(refs, Sequence)
        or isinstance(refs, (str, bytes))
        or not refs
        or any(not _nonempty_text(reference) for reference in refs)
    ):
        raise RiskValidationError(
            f"residual reduction requires current passing evidence for {axis}"
        )
    records: list[Mapping] = []
    for reference in refs:
        record = current.get(reference)
        if record is None:
            raise RiskValidationError(
                f"residual reduction requires current passing evidence: {reference}"
            )
        if axis not in (record.get("supports") or []):
            raise RiskValidationError(f"evidence {reference} does not support {axis}")
        records.append(record)
    return records


def calculate_residual(
    inherent: dict,
    evidence: dict,
    policy: dict,
    proposed: dict | None = None,
    *,
    requirements: dict | None = None,
    today: date | None = None,
) -> dict:
    """Calculate a fresh residual proposal, allowing only evidenced reductions."""

    evaluation_date = today or date.today()
    current = _current_passing_evidence(evidence, requirements, evaluation_date)
    if proposed is None:
        reason = (
            "residual proposal is required"
            if current
            else "linked requirements have no valid implementation evidence"
        )
        return {"status": "UNDETERMINED", "reason": reason}
    if not isinstance(inherent, Mapping):
        raise RiskValidationError("inherent risk must be a mapping")
    for axis in ("likelihood", "impact"):
        score = inherent.get(axis)
        if isinstance(score, bool) or not isinstance(score, int) or not 1 <= score <= 5:
            raise RiskValidationError(f"inherent {axis} score is invalid")

    calculated = calculate_inherent(policy, proposed)
    used_evidence: list[Mapping] = []
    warnings: list[str] = []
    for axis in ("likelihood", "impact"):
        decrease = inherent[axis] - calculated[axis]
        if decrease > 0:
            used_evidence.extend(_reduction_evidence(proposed, axis, current))
        if decrease >= 2:
            warnings.append(
                f"{axis} decreases by {decrease} levels; independent review is recommended"
            )

    if calculated["score"] == 1 and not any(
        "attack_path_removal" in (record.get("supports") or [])
        for record in used_evidence
    ):
        raise RiskValidationError(
            "residual score 1 requires attack-path-removal evidence"
        )

    result = {"status": "PROPOSED", **calculated}
    if warnings:
        result["warnings"] = warnings
    return result


def _without_confirmation(value: Mapping) -> dict:
    payload = copy.deepcopy(dict(value))
    payload.pop("confirmation", None)
    return payload


def policy_digest(policy: dict) -> str:
    """Digest policy content without its reviewable confirmation copy."""
    if not isinstance(policy, Mapping):
        raise RiskValidationError("risk policy must be a mapping")
    return canonical_digest(_without_confirmation(policy))


def assessment_digest(assessment: dict) -> str:
    """Digest assessment content without its reviewable confirmation copy."""
    if not isinstance(assessment, Mapping):
        raise RiskValidationError("assessment document must be a mapping")
    return canonical_digest(_without_confirmation(assessment))


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

    stable_threat_ids = {
        threat.get("id")
        for threat in threats
        if isinstance(threat, Mapping)
        and isinstance(threat.get("id"), str)
        and threat["id"]
    }
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
            for replacement_id in replacements:
                if replacement_id not in stable_threat_ids:
                    raise RiskValidationError(
                        f"{threat_id} superseded_by references unknown threat ID: "
                        f"{replacement_id}"
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
            if "treatment" in record:
                problems.extend(
                    f"{threat_id} {problem}"
                    for problem in validate_treatment(record, policy, date.today())
                )

    for threat in active:
        threat_id = threat["id"]
        record = records_by_id.get(threat_id)
        if record is None:
            problems.append(f"{threat_id} assessment is missing")
        elif record.get("status") != "CONFIRMED":
            problems.append(f"{threat_id} assessment is not confirmed")
    return problems


def aggregate_risk(
    threats: dict, assessment: dict, *, today: date | None = None
) -> dict:
    """Summarise active inherent-risk ratings without averaging independent risks."""

    active = active_threats(threats)
    if today is None:
        today = date.today()
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
        if _expired_acceptance(record, today):
            unresolved = True

    overall = next((rating for rating in RATINGS if counts[rating]), "UNDETERMINED")
    return {
        "overall": overall,
        "status": "provisional" if unresolved else "confirmed",
        "counts": counts,
        "coverage": f"{confirmed}/{len(active)}",
    }


UNRESOLVED_RISK_STATUSES = ("UNDETERMINED", "STALE", "PROPOSED")
REQUIREMENT_PRIORITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def derive_risk_links(
    threat_refs: object,
    assessment: dict,
    threats: dict,
    *,
    today: date | None = None,
) -> dict:
    """Derive requirement risk links and display exposure from assessments.

    ``risk_refs`` are stable citations copied from the requirement's threat
    references. ``risk_exposure`` is presentation metadata: only an active,
    confirmed assessment contributes a rating. An unresolved linked assessment
    is displayed as unresolved only when no confirmed linked rating exists.
    """

    if not isinstance(threat_refs, Sequence) or isinstance(threat_refs, (str, bytes)):
        raise RiskValidationError("requirement threat_refs must be a list")
    active_ids = {threat["id"] for threat in active_threats(threats)}
    refs = sorted(
        {
            reference
            for reference in threat_refs
            if _nonempty_text(reference) and reference in active_ids
        }
    )
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
        if not _nonempty_text(threat_id):
            raise RiskValidationError("assessment threat_id is required")
        if threat_id in records_by_id:
            raise RiskValidationError(f"duplicate assessment for threat: {threat_id}")
        records_by_id[threat_id] = record

    result: dict[str, object] = {"risk_refs": refs}
    if not refs:
        return result
    if today is None:
        today = date.today()

    confirmed_ratings: list[str] = []
    unresolved: set[str] = set()
    for reference in refs:
        record = records_by_id.get(reference)
        if record is None:
            unresolved.add("UNDETERMINED")
            continue
        status = record.get("status")
        if status != "CONFIRMED":
            unresolved.add(status if status in UNRESOLVED_RISK_STATUSES else "UNDETERMINED")
            continue
        if _expired_acceptance(record, today):
            unresolved.add("STALE")
            continue
        rating = _snapshot_rating(record)
        if rating is None:
            unresolved.add("UNDETERMINED")
        else:
            confirmed_ratings.append(rating)

    if confirmed_ratings:
        result["risk_exposure"] = min(confirmed_ratings, key=RATINGS.index)
    elif unresolved:
        result["risk_exposure"] = next(
            status for status in UNRESOLVED_RISK_STATUSES if status in unresolved
        )
    return result


def order_requirements(requirements: object) -> list[dict]:
    """Return requirements in deterministic risk, priority, and ID order."""

    if not isinstance(requirements, Sequence) or isinstance(requirements, (str, bytes)):
        raise RiskValidationError("requirements must be a list")

    def ordering_key(record: object) -> tuple[int, int, str]:
        if not isinstance(record, Mapping):
            raise RiskValidationError("requirement must be a mapping")
        managed = record.get("managed")
        managed = managed if isinstance(managed, Mapping) else {}
        exposure = record.get("risk_exposure", managed.get("risk_exposure"))
        if exposure == "critical":
            exposure_rank = 0
        elif exposure in UNRESOLVED_RISK_STATUSES:
            exposure_rank = 1
        elif exposure == "high":
            exposure_rank = 2
        elif exposure == "medium":
            exposure_rank = 3
        elif exposure == "low":
            exposure_rank = 4
        else:
            exposure_rank = 5
        priority = managed.get("priority")
        priority_rank = (
            REQUIREMENT_PRIORITY_ORDER.get(priority, 3)
            if isinstance(priority, str)
            else 3
        )
        requirement_id = record.get("id")
        if not isinstance(requirement_id, str):
            requirement_id = ""
        return exposure_rank, priority_rank, requirement_id

    return sorted(list(requirements), key=ordering_key)


def _report_text(value: object) -> str:
    if value is None or value == "":
        return "not recorded"
    if isinstance(value, Mapping):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return "; ".join(_report_text(item) for item in value)
    return str(value)


def _report_cell(value: object) -> str:
    return (
        _report_text(value)
        .replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("\r\n", "<br>")
        .replace("\r", "<br>")
        .replace("\n", "<br>")
    )


def _assessment_criteria(proposed: object) -> object:
    if not isinstance(proposed, Mapping):
        return None
    criteria: dict[str, object] = {}
    likelihood = proposed.get("likelihood")
    if isinstance(likelihood, Mapping):
        criteria["likelihood"] = likelihood.get("criterion")
    consequences = proposed.get("consequences")
    if isinstance(consequences, Sequence) and not isinstance(consequences, (str, bytes)):
        criteria["impact"] = [
            consequence.get("criterion")
            for consequence in consequences
            if isinstance(consequence, Mapping)
        ]
    return criteria or None


def _assessment_rationale(proposed: object) -> list[object]:
    if not isinstance(proposed, Mapping):
        return []
    rationale: list[object] = []
    likelihood = proposed.get("likelihood")
    if isinstance(likelihood, Mapping) and likelihood.get("rationale") is not None:
        rationale.append(likelihood.get("rationale"))
    consequences = proposed.get("consequences")
    if isinstance(consequences, Sequence) and not isinstance(consequences, (str, bytes)):
        rationale.extend(
            consequence.get("rationale")
            for consequence in consequences
            if isinstance(consequence, Mapping) and consequence.get("rationale") is not None
        )
    return rationale


def render_register(summary: dict) -> str:
    """Render the sensitive internal register from canonical report data."""

    if not isinstance(summary, Mapping):
        raise RiskValidationError("risk report summary must be a mapping")
    records = summary.get("risks", summary.get("assessments", []))
    if not isinstance(records, Sequence) or isinstance(records, (str, bytes)):
        raise RiskValidationError("risk report records must be a list")

    out = [
        "# Internal risk register",
        "",
        "> Sensitive internal record. Do not publish.",
        "",
    ]
    for record in sorted(
        (item for item in records if isinstance(item, Mapping)),
        key=lambda item: str(item.get("threat_id", item.get("id", ""))),
    ):
        threat_id = record.get("threat_id", record.get("id", "<unknown risk>"))
        proposed = record.get("proposed")
        treatment = record.get("treatment")
        treatment = treatment if isinstance(treatment, Mapping) else {}
        acceptance = treatment.get("approval", treatment.get("acceptance"))
        acceptance = acceptance if isinstance(acceptance, Mapping) else {}
        residual = record.get("residual")
        if isinstance(residual, Mapping) and isinstance(residual.get("calculated"), Mapping):
            residual = residual["calculated"]
        evidence = record.get("evidence", record.get("evidence_refs"))
        rows = (
            ("Scenario", record.get("scenario")),
            ("Attack path", record.get("attack_path")),
            ("Criteria", _assessment_criteria(proposed)),
            ("Rationale", _assessment_rationale(proposed)),
            ("Inherent", record.get("inherent", record.get("calculated"))),
            ("Residual", residual),
            ("Owner", treatment.get("owner")),
            ("Treatment", treatment.get("strategy")),
            ("Acceptance", acceptance),
            ("Evidence", evidence),
            ("Expiry", acceptance.get("expires")),
            ("Lifecycle", record.get("lifecycle", record.get("status"))),
        )
        out += [f"## {_report_text(threat_id)}", "", "| Field | Value |", "|---|---|"]
        out.extend(f"| {label} | {_report_cell(value)} |" for label, value in rows)
        out.append("")

    delta = summary.get("delta")
    if isinstance(delta, Mapping):
        out += ["## Delta", "", "| Change | Risks |", "|---|---|"]
        for field in (
            "new",
            "increased",
            "decreased",
            "stale",
            "retired",
            "reopened",
            "expired_acceptance",
            "rating_distribution",
        ):
            out.append(f"| {field} | {_report_cell(delta.get(field))} |")
        out.append("")
    return "\n".join(out)


def _public_summary_sections(summary: Mapping) -> list[tuple[str, Mapping]]:
    sections = [
        (name, value)
        for name in ("inherent", "residual")
        if isinstance((value := summary.get(name)), Mapping)
    ]
    if not sections and any(field in summary for field in ("overall", "counts", "coverage")):
        sections.append(("inherent", summary))
    return sections


def _validated_public_section(section: Mapping) -> tuple[str, dict[str, int], str]:
    missing = [field for field in ("overall", "counts", "coverage") if field not in section]
    if missing:
        raise RiskValidationError(
            "public risk summary is missing " + ", ".join(missing)
        )
    overall = section["overall"]
    if overall not in (*RATINGS, "UNDETERMINED"):
        raise RiskValidationError("public risk summary overall rating is invalid")
    raw_counts = section["counts"]
    if not isinstance(raw_counts, Mapping):
        raise RiskValidationError("public risk summary counts must be a mapping")
    if any(rating not in RATINGS for rating in raw_counts):
        raise RiskValidationError("public risk summary contains an unknown rating count")
    counts: dict[str, int] = {}
    for rating in RATINGS:
        value = raw_counts.get(rating, 0)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise RiskValidationError("public risk summary count is invalid")
        counts[rating] = value
    coverage = section["coverage"]
    if (
        not isinstance(coverage, str)
        or len(coverage.split("/")) != 2
        or any(not part.isdigit() for part in coverage.split("/"))
    ):
        raise RiskValidationError("public risk summary coverage is invalid")
    confirmed, total = (int(part) for part in coverage.split("/"))
    if confirmed > total:
        raise RiskValidationError("public risk summary coverage exceeds active risks")
    if sum(counts.values()) != confirmed:
        raise RiskValidationError("public risk summary counts do not match coverage")
    expected_overall = next(
        (rating for rating in RATINGS if counts[rating]), "UNDETERMINED"
    )
    if overall != expected_overall:
        raise RiskValidationError(
            "public risk summary overall does not match its rating counts"
        )
    return overall, counts, coverage


def render_public_summary(summary: dict, policy: dict) -> str | None:
    """Render only approved opt-in aggregate fields, never internal details."""

    if not isinstance(policy, Mapping) or policy.get("publish_risk_summary") is not True:
        return None
    if not isinstance(summary, Mapping):
        raise RiskValidationError("risk report summary must be a mapping")

    out = ["# Public risk summary", ""]
    for name, section in _public_summary_sections(summary):
        overall, counts, coverage = _validated_public_section(section)
        out += [f"## {name.title()}", "", "| Measure | Value |", "|---|---|"]
        out.append(f"| Overall | {overall} |")
        out.append(f"| Coverage | {coverage} |")
        out += ["", "| Rating | Count |", "|---|---:|"]
        out.extend(f"| {rating} | {counts[rating]} |" for rating in RATINGS)
        out.append("")
    return "\n".join(out)


def _nonempty_text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _approval_role_allowlist(policy: Mapping) -> object:
    for name in ("approval_roles", "approved_roles", "permitted_approval_roles"):
        if name in policy:
            return policy[name]
    return None


def validate_treatment(record: dict, policy: dict, today: date) -> list[str]:
    """Return deterministic problems with a threat's treatment decision.

    An authority records how an approval was asserted; it is deliberately not
    treated as authenticated identity by this local validator.
    """

    if not isinstance(record, Mapping):
        return ["treatment record must be a mapping"]
    if not isinstance(policy, Mapping):
        return ["risk policy must be a mapping"]
    if not isinstance(today, date):
        return ["treatment validation date is invalid"]

    treatment = record.get("treatment")
    if not isinstance(treatment, Mapping):
        return ["treatment is required"]
    problems: list[str] = []
    strategy = treatment.get("strategy")
    if strategy not in TREATMENT_STRATEGIES:
        problems.append("treatment strategy is invalid")
    if not _nonempty_text(treatment.get("owner")):
        problems.append("treatment owner is required")
    if strategy != "accept":
        return problems

    approval = treatment.get("approval", treatment.get("acceptance"))
    if not isinstance(approval, Mapping):
        return problems + ["acceptance approval is required"]
    for field in ("approver", "role", "rationale", "expires", "authority"):
        if not _nonempty_text(approval.get(field)):
            problems.append(f"acceptance {field} is required")

    authority = approval.get("authority")
    if _nonempty_text(authority) and authority not in AUTHORITIES:
        problems.append("acceptance authority is invalid")

    allowed_roles = _approval_role_allowlist(policy)
    if allowed_roles is not None:
        if (
            not isinstance(allowed_roles, Sequence)
            or isinstance(allowed_roles, (str, bytes))
            or any(not _nonempty_text(role) for role in allowed_roles)
        ):
            problems.append("policy approval role allowlist is invalid")
        elif approval.get("role") not in allowed_roles:
            problems.append("acceptance role is not permitted by policy")

    expiry = approval.get("expires")
    if _nonempty_text(expiry):
        try:
            expiry_date = date.fromisoformat(expiry)
        except ValueError:
            problems.append("acceptance expiry is invalid")
        else:
            if expiry_date < today:
                problems.append("acceptance expired")
    return problems


def append_snapshot(state: dict, snapshot: dict) -> dict:
    """Return a copied state with one immutable historical snapshot appended."""

    if not isinstance(state, Mapping):
        raise RiskValidationError("risk state must be a mapping")
    if not isinstance(snapshot, Mapping):
        raise RiskValidationError("risk snapshot must be a mapping")
    missing = [field for field in SNAPSHOT_FIELDS if field not in snapshot]
    if missing:
        raise RiskValidationError("risk snapshot is incomplete: " + ", ".join(missing))
    snapshots = state.get("snapshots", [])
    if not isinstance(snapshots, Sequence) or isinstance(snapshots, (str, bytes)):
        raise RiskValidationError("risk state snapshots must be a list")
    result = copy.deepcopy(dict(state))
    result["snapshots"] = copy.deepcopy(list(snapshots)) + [copy.deepcopy(dict(snapshot))]
    return result


def _snapshot_records(snapshot: Mapping) -> dict[str, Mapping]:
    records = snapshot.get("assessments", snapshot.get("risks", []))
    if not isinstance(records, Sequence) or isinstance(records, (str, bytes)):
        raise RiskValidationError("risk snapshot assessments must be a list")
    result: dict[str, Mapping] = {}
    for record in records:
        if not isinstance(record, Mapping):
            raise RiskValidationError("risk snapshot assessment must be a mapping")
        threat_id = record.get("threat_id", record.get("id"))
        if not _nonempty_text(threat_id):
            raise RiskValidationError("risk snapshot assessment threat_id is required")
        if threat_id in result:
            raise RiskValidationError(f"duplicate snapshot assessment for threat: {threat_id}")
        result[threat_id] = record
    return result


def _snapshot_lifecycle(record: Mapping) -> str:
    lifecycle = record.get("lifecycle", {})
    if isinstance(lifecycle, Mapping):
        status = lifecycle.get("status", "active")
    else:
        status = lifecycle
    return status.lower() if isinstance(status, str) else "active"


def _snapshot_rating(record: Mapping) -> str | None:
    calculated = record.get("calculated", record.get("inherent", {}))
    rating = calculated.get("rating") if isinstance(calculated, Mapping) else None
    return rating if rating in RATINGS else None


def _snapshot_assessed_date(snapshot: Mapping) -> date | None:
    assessed_at = snapshot.get("assessed_at")
    if not _nonempty_text(assessed_at):
        return None
    try:
        return datetime.fromisoformat(assessed_at.replace("Z", "+00:00")).date()
    except ValueError:
        return None


def _expired_acceptance(record: Mapping, today: date | None) -> bool:
    treatment = record.get("treatment")
    if not isinstance(treatment, Mapping) or treatment.get("strategy") != "accept":
        return False
    approval = treatment.get("approval", treatment.get("acceptance"))
    if not isinstance(approval, Mapping) or today is None:
        return False
    expiry = approval.get("expires")
    if not _nonempty_text(expiry):
        return False
    try:
        return date.fromisoformat(expiry) < today
    except ValueError:
        return False


def _rating_distribution(records: Mapping[str, Mapping]) -> dict[str, int]:
    counts = {rating: 0 for rating in RATINGS}
    for record in records.values():
        if record.get("status", "CONFIRMED") != "CONFIRMED":
            continue
        if _snapshot_lifecycle(record) != "active":
            continue
        rating = _snapshot_rating(record)
        if rating is not None:
            counts[rating] += 1
    return counts


def risk_delta(previous: dict, current: dict) -> dict:
    """Compare immutable snapshots without inventing totals or average risk."""

    if not isinstance(previous, Mapping) or not isinstance(current, Mapping):
        raise RiskValidationError("risk snapshots must be mappings")
    old_records = _snapshot_records(previous)
    new_records = _snapshot_records(current)
    previous_date = _snapshot_assessed_date(previous)
    current_date = _snapshot_assessed_date(current)
    result = {
        "new": [],
        "increased": [],
        "decreased": [],
        "stale": [],
        "retired": [],
        "reopened": [],
        "expired_acceptance": [],
        "rating_distribution": {
            "previous": _rating_distribution(old_records),
            "current": _rating_distribution(new_records),
        },
    }
    for threat_id in sorted(new_records):
        record = new_records[threat_id]
        old_record = old_records.get(threat_id)
        if old_record is None:
            result["new"].append(threat_id)
        else:
            old_lifecycle = _snapshot_lifecycle(old_record)
            lifecycle = _snapshot_lifecycle(record)
            if old_lifecycle == "active" and lifecycle != "active":
                result["retired"].append(threat_id)
            elif old_lifecycle != "active" and lifecycle == "active":
                result["reopened"].append(threat_id)
            if record.get("status") == "STALE" and old_record.get("status") != "STALE":
                result["stale"].append(threat_id)
            old_rating = _snapshot_rating(old_record)
            rating = _snapshot_rating(record)
            if (
                old_lifecycle == lifecycle == "active"
                and old_record.get("status", "CONFIRMED") == "CONFIRMED"
                and record.get("status", "CONFIRMED") == "CONFIRMED"
                and old_rating is not None
                and rating is not None
            ):
                if RATINGS.index(rating) < RATINGS.index(old_rating):
                    result["increased"].append(threat_id)
                elif RATINGS.index(rating) > RATINGS.index(old_rating):
                    result["decreased"].append(threat_id)
        if _expired_acceptance(record, current_date) and not (
            old_record is not None and _expired_acceptance(old_record, previous_date)
        ):
            result["expired_acceptance"].append(threat_id)
    return result


def propose_exception_migration(requirements: dict) -> dict:
    """Propose, without activating, threat treatment for legacy exceptions."""

    if not isinstance(requirements, Mapping):
        raise RiskValidationError("requirements document must be a mapping")
    records = requirements.get("requirements")
    if not isinstance(records, Sequence) or isinstance(records, (str, bytes)):
        raise RiskValidationError("requirements must be a list")

    result = copy.deepcopy(dict(requirements))
    for record in result["requirements"]:
        if not isinstance(record, dict):
            continue
        human = record.get("human")
        threat_refs = record.get("threat_refs")
        if (
            not isinstance(human, Mapping)
            or human.get("status") not in {"accepted_risk", "exception"}
            or not isinstance(threat_refs, Sequence)
            or isinstance(threat_refs, (str, bytes))
        ):
            continue
        refs = sorted({reference for reference in threat_refs if _nonempty_text(reference)})
        if not refs:
            continue
        pending = record.get("pending_review", {})
        if not isinstance(pending, Mapping) or "risk_treatment" in pending:
            continue

        exception = human.get("exception")
        approval: dict[str, object] = {}
        if isinstance(exception, Mapping):
            for field in ("approver", "role", "authority", "expires"):
                if field in exception:
                    approval[field] = copy.deepcopy(exception[field])
            rationale = exception.get("rationale", exception.get("reason"))
            if rationale is not None:
                approval["rationale"] = copy.deepcopy(rationale)
        treatment: dict[str, object] = {"strategy": "accept"}
        owner = human.get("owner")
        if owner is None and isinstance(exception, Mapping):
            owner = exception.get("owner")
        if owner is not None:
            treatment["owner"] = copy.deepcopy(owner)
        if approval:
            treatment["approval"] = approval

        updated_pending = copy.deepcopy(dict(pending))
        updated_pending["risk_treatment"] = {
            "migration": "requirement_exception_to_threat_treatment",
            "threat_refs": refs,
            "treatment": treatment,
        }
        record["pending_review"] = updated_pending
    return result


def aggregate_threat_digest(threats: dict) -> str:
    """Digest the material identity of the active threat set."""
    material = sorted(
        (
            {"id": threat["id"], "digest": threat_digest(threat)}
            for threat in active_threats(threats)
        ),
        key=lambda item: (item["id"], item["digest"]),
    )
    return canonical_digest(material)


def _path_from(paths: Mapping | object, name: str) -> Path:
    try:
        value = paths[name] if isinstance(paths, Mapping) else getattr(paths, name)
    except (KeyError, AttributeError) as exc:
        raise ValueError(f"risk paths are missing {name}") from exc
    if not isinstance(value, Path):
        value = Path(value)
    return value


def _project_document_path(paths: Mapping | object, name: str) -> tuple[Path, Path]:
    project_root = _path_from(paths, "project_root")
    document_path = _path_from(paths, name)
    validated_path = safe_path(document_path, project_root=project_root)
    return project_root, validated_path


def _load_mapping(path: Path, label: str) -> dict:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RiskValidationError(f"{label} must be a mapping")
    return value


def _state_target(project_root: Path, kind: str) -> tuple[Path, Path]:
    state_root = plugin_data_root(project_root=project_root)
    state_path = confirmation_state_path(project_root, kind)
    safe_path(state_path, project_root=state_root)
    return state_root, state_path


def _read_trusted_confirmation(project_root: Path, kind: str) -> dict | None:
    _state_root, state_path = _state_target(project_root, kind)
    if not state_path.exists():
        return None
    value = yaml.safe_load(state_path.read_text(encoding="utf-8"))
    return value if isinstance(value, dict) else None


def _confirmation_metadata(
    project_root: Path,
    confirmed_by: str,
    authority: str,
    confirmed_at: str | None,
    **digests: str,
) -> dict:
    if not isinstance(confirmed_by, str) or not confirmed_by.strip():
        raise RiskValidationError("confirmer identity is required")
    if authority not in AUTHORITIES:
        raise RiskValidationError(f"unknown confirmation authority: {authority}")
    return {
        "status": "confirmed",
        "project": str(project_root.resolve()),
        **digests,
        "confirmed_by": confirmed_by,
        "confirmed_at": confirmed_at
        or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "authority": authority,
    }


def _write_confirmation(
    document_path: Path,
    document: dict,
    state_path: Path,
    state_root: Path,
    project_root: Path,
) -> None:
    preflight_output_paths([document_path], project_root=project_root)
    safe_path(state_path, project_root=state_root)
    safe_write_text(
        document_path,
        yaml.safe_dump(document, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
        project_root=project_root,
    )
    safe_write_text(
        state_path,
        yaml.safe_dump(document["confirmation"], allow_unicode=True, sort_keys=False),
        encoding="utf-8",
        project_root=state_root,
        create_parents=True,
    )


def stamp_policy(
    paths: Mapping | object,
    confirmed_by: str,
    authority: str,
    *,
    confirmed_at: str | None = None,
) -> dict:
    """Persist matching repository and external policy confirmations."""
    project_root, policy_path = _project_document_path(paths, "policy")
    state_root, state_path = _state_target(project_root, "policy")
    policy = _load_mapping(policy_path, "risk policy")
    policy["confirmation"] = _confirmation_metadata(
        project_root,
        confirmed_by,
        authority,
        confirmed_at,
        policy_digest=policy_digest(policy),
    )
    _write_confirmation(policy_path, policy, state_path, state_root, project_root)
    return policy


def _base_confirmation_problems(
    kind: str, repository: object, trusted: object, project_root: Path
) -> list[str]:
    if not isinstance(trusted, dict):
        return [f"plugin-owned risk {kind} confirmation is missing"]
    if repository != trusted:
        return [
            f"repository risk {kind} confirmation does not match plugin-owned state"
        ]
    required = ("status", "project", "confirmed_by", "confirmed_at", "authority")
    missing = [name for name in required if not trusted.get(name)]
    if missing:
        return [f"risk {kind} confirmation is incomplete: " + ", ".join(missing)]
    problems: list[str] = []
    if trusted["status"] != "confirmed":
        problems.append(f"risk {kind} confirmation status is not confirmed")
    if trusted["project"] != str(project_root.resolve()):
        problems.append("project identity changed")
    if trusted["authority"] not in AUTHORITIES:
        problems.append("risk confirmation authority is invalid")
    return problems


def check_policy(paths: Mapping | object) -> list[str]:
    """Return problems with the repository policy and its external approval."""
    project_root, policy_path = _project_document_path(paths, "policy")
    policy = _load_mapping(policy_path, "risk policy")
    trusted = _read_trusted_confirmation(project_root, "policy")
    problems = _base_confirmation_problems(
        "policy", policy.get("confirmation"), trusted, project_root
    )
    if problems:
        return problems
    if trusted.get("policy_digest") != policy_digest(policy):
        problems.append("policy digest changed")
    return problems


def _calculate_confirmed_assessment(
    threats: dict, assessment: dict, policy: dict
) -> dict:
    result = _without_confirmation(assessment)
    records = result.get("assessments")
    if not isinstance(records, Sequence) or isinstance(records, (str, bytes)):
        raise RiskValidationError("assessments must be a list")
    active_ids = {threat["id"] for threat in active_threats(threats)}
    for record in records:
        if not isinstance(record, dict):
            continue
        if record.get("threat_id") not in active_ids:
            continue
        proposed = record.get("proposed")
        if not isinstance(proposed, dict):
            continue
        record["status"] = "CONFIRMED"
        record["calculated"] = calculate_inherent(policy, proposed)
    problems = validate_assessment(threats, result, policy)
    if problems:
        raise RiskValidationError("; ".join(problems))
    return result


def stamp_assessment(
    paths: Mapping | object,
    confirmed_by: str,
    authority: str,
    *,
    confirmed_at: str | None = None,
) -> dict:
    """Calculate scores and persist digest-bound assessment confirmation."""
    policy_problems = check_policy(paths)
    if policy_problems:
        raise RiskValidationError("; ".join(policy_problems))
    project_root, assessment_path = _project_document_path(paths, "assessment")
    _unused_root, policy_path = _project_document_path(paths, "policy")
    _unused_root, threats_path = _project_document_path(paths, "threats")
    state_root, state_path = _state_target(project_root, "assessment")
    policy = _load_mapping(policy_path, "risk policy")
    threats = _load_mapping(threats_path, "threat document")
    assessment = _load_mapping(assessment_path, "assessment document")
    calculated = _calculate_confirmed_assessment(threats, assessment, policy)
    calculated["confirmation"] = _confirmation_metadata(
        project_root,
        confirmed_by,
        authority,
        confirmed_at,
        policy_digest=policy_digest(policy),
        threat_digest=aggregate_threat_digest(threats),
        assessment_digest=assessment_digest(calculated),
    )
    _write_confirmation(
        assessment_path, calculated, state_path, state_root, project_root
    )
    return calculated


def check_assessment(paths: Mapping | object) -> list[str]:
    """Return problems with assessment validation or its external approval."""
    project_root, assessment_path = _project_document_path(paths, "assessment")
    _unused_root, policy_path = _project_document_path(paths, "policy")
    _unused_root, threats_path = _project_document_path(paths, "threats")
    policy = _load_mapping(policy_path, "risk policy")
    threats = _load_mapping(threats_path, "threat document")
    assessment = _load_mapping(assessment_path, "assessment document")
    trusted = _read_trusted_confirmation(project_root, "assessment")
    problems = _base_confirmation_problems(
        "assessment", assessment.get("confirmation"), trusted, project_root
    )
    if problems:
        return problems
    required_digests = ("policy_digest", "threat_digest", "assessment_digest")
    missing = [name for name in required_digests if not trusted.get(name)]
    if missing:
        return ["risk assessment confirmation is incomplete: " + ", ".join(missing)]
    if trusted["policy_digest"] != policy_digest(policy):
        problems.append("policy digest changed")
    if trusted["threat_digest"] != aggregate_threat_digest(threats):
        problems.append("threat digest changed")
    if trusted["assessment_digest"] != assessment_digest(assessment):
        problems.append("assessment digest changed")
    problems.extend(validate_assessment(threats, assessment, policy))
    return problems


def _add_path_argument(parser: argparse.ArgumentParser, name: str) -> None:
    parser.add_argument(name, type=Path, required=True, action=_StoreOnce)


def argument_parser() -> argparse.ArgumentParser:
    """Return the strict risk confirmation command grammar."""
    parser = _StrictArgumentParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)

    policy_confirm = commands.add_parser("policy-confirm", allow_abbrev=False)
    _add_path_argument(policy_confirm, "--project-root")
    _add_path_argument(policy_confirm, "--policy")
    policy_confirm.add_argument("--by", required=True, action=_StoreOnce)
    policy_confirm.add_argument(
        "--authority", choices=sorted(AUTHORITIES), required=True, action=_StoreOnce
    )

    for name in ("confirm", "check"):
        command = commands.add_parser(name, allow_abbrev=False)
        _add_path_argument(command, "--project-root")
        _add_path_argument(command, "--policy")
        _add_path_argument(command, "--threats")
        _add_path_argument(command, "--assessment")
        if name == "confirm":
            command.add_argument("--by", required=True, action=_StoreOnce)
            command.add_argument(
                "--authority",
                choices=sorted(AUTHORITIES),
                required=True,
                action=_StoreOnce,
            )

    evidence_command = commands.add_parser("evidence", allow_abbrev=False)
    _add_path_argument(evidence_command, "--project-root")
    _add_path_argument(evidence_command, "--requirements")
    _add_path_argument(evidence_command, "--evidence")

    residual_command = commands.add_parser("residual", allow_abbrev=False)
    for name in (
        "--project-root",
        "--policy",
        "--threats",
        "--assessment",
        "--requirements",
        "--evidence",
    ):
        _add_path_argument(residual_command, name)
    return parser


def _validated_evidence_documents(
    paths: Mapping | object, evaluation_date: date
) -> tuple[dict, dict, list[str]]:
    _project_root, requirements_path = _project_document_path(paths, "requirements")
    _project_root, evidence_path = _project_document_path(paths, "evidence")
    requirements = _load_mapping(requirements_path, "requirements document")
    evidence = _load_mapping(evidence_path, "evidence document")
    return (
        requirements,
        evidence,
        validate_evidence(evidence, requirements, evaluation_date),
    )


def _residual_results(
    threats: dict,
    assessment: dict,
    requirements: dict,
    evidence: dict,
    policy: dict,
    evaluation_date: date,
) -> tuple[list[tuple[str, dict]], list[str]]:
    active_ids = {threat["id"] for threat in active_threats(threats)}
    records = assessment.get("assessments")
    if not isinstance(records, Sequence) or isinstance(records, (str, bytes)):
        return [], ["assessments must be a list"]
    results: list[tuple[str, dict]] = []
    problems: list[str] = []
    for record in records:
        if not isinstance(record, Mapping) or record.get("threat_id") not in active_ids:
            continue
        threat_id = record["threat_id"]
        residual = record.get("residual")
        if residual is None:
            continue
        if not isinstance(residual, Mapping):
            problems.append(f"{threat_id} residual assessment must be a mapping")
            continue
        proposed = residual.get("proposed")
        if proposed is None and residual.get("status") == "UNDETERMINED":
            continue
        inherent = record.get("calculated")
        try:
            result = calculate_residual(
                inherent,
                evidence,
                policy,
                proposed,
                requirements=requirements,
                today=evaluation_date,
            )
        except RiskValidationError as exc:
            problems.append(f"{threat_id} {exc}")
            continue
        results.append((threat_id, result))
    return results, problems


def main(argv: list[str] | None = None) -> int:
    """Confirm or check risk policy and assessment state."""
    if sys.version_info < MINIMUM_PYTHON:
        print(
            "error: security-requirements requires Python 3.12 or newer",
            file=sys.stderr,
        )
        return 2
    try:
        args = argument_parser().parse_args(argv)
        paths = {
            name: getattr(args, name)
            for name in (
                "project_root",
                "policy",
                "threats",
                "assessment",
                "requirements",
                "evidence",
            )
            if hasattr(args, name)
        }
        if args.command == "policy-confirm":
            policy = stamp_policy(paths, args.by, args.authority)
            print(f"confirmed risk policy ({policy['confirmation']['policy_digest']})")
            return 0
        if args.command == "confirm":
            assessment = stamp_assessment(paths, args.by, args.authority)
            print(
                "confirmed risk assessment "
                f"({assessment['confirmation']['assessment_digest']})"
            )
            return 0
        if args.command == "evidence":
            _requirements, evidence, problems = _validated_evidence_documents(
                paths, date.today()
            )
            for problem in problems:
                print(f"ERROR: {problem}", file=sys.stderr)
            if problems:
                return 1
            print(
                "validated "
                f"{len(_evidence_index(evidence))} current implementation evidence record(s)"
            )
            return 0
        if args.command == "residual":
            problems = check_policy(paths)
            for problem in check_assessment(paths):
                if problem not in problems:
                    problems.append(problem)
            requirements, evidence, evidence_problems = _validated_evidence_documents(
                paths, date.today()
            )
            problems.extend(
                problem for problem in evidence_problems if problem not in problems
            )
            _project_root, policy_path = _project_document_path(paths, "policy")
            _project_root, threats_path = _project_document_path(paths, "threats")
            _project_root, assessment_path = _project_document_path(paths, "assessment")
            policy = _load_mapping(policy_path, "risk policy")
            threats = _load_mapping(threats_path, "threat document")
            assessment = _load_mapping(assessment_path, "assessment document")
            results, residual_problems = _residual_results(
                threats,
                assessment,
                requirements,
                evidence,
                policy,
                date.today(),
            )
            problems.extend(
                problem for problem in residual_problems if problem not in problems
            )
            for problem in problems:
                print(f"ERROR: {problem}", file=sys.stderr)
            if problems:
                return 1
            for threat_id, result in results:
                if result.get("status") == "UNDETERMINED":
                    print(
                        f"{threat_id} residual risk: UNDETERMINED "
                        f"({result['reason']})"
                    )
                    continue
                print(
                    f"{threat_id} residual risk: {result['rating']} "
                    f"(score {result['score']})"
                )
                for warning in result.get("warnings", []):
                    print(f"WARN: {threat_id} {warning}")
            return 0

        problems = check_policy(paths)
        for problem in check_assessment(paths):
            if problem not in problems:
                problems.append(problem)
        for problem in problems:
            print(f"ERROR: {problem}", file=sys.stderr)
        return 1 if problems else 0
    except RiskArgumentError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (OSError, RuntimeError, UnsafePathError, ValueError, yaml.YAMLError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
