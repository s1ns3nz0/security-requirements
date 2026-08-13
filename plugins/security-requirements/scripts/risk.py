#!/usr/bin/env python3
"""Deterministic risk-policy and inherent-risk calculation primitives."""

from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
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
ASSESSMENT_STATUSES = {"CONFIRMED", "UNDETERMINED", "PROPOSED", "STALE"}
LIFELIHOOD_EVIDENCE_FIELDS = (
    "exposure",
    "access_required",
    "exploit_complexity",
    "preconditions",
    "observed_controls",
)
AUTHORITIES = {"self_declared", "externally_attested"}
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
    return parser


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
            for name in ("project_root", "policy", "threats", "assessment")
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
