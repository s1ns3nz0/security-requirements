#!/usr/bin/env python3
"""Deterministic risk-policy and inherent-risk calculation primitives."""

from __future__ import annotations

import argparse
import copy
from datetime import date, datetime, timezone
import hashlib
import json
import re
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
# The CIA axis a consequence lands on. Long form, matching what the golden
# fixtures and tests/risk_helpers.py already write. Deliberately not named
# AXES: overlays/soc2/meta.yaml uses the same key name for a different
# vocabulary, and every `axis` parameter elsewhere in this module names the
# likelihood/impact scoring dimension instead.
CONSEQUENCE_AXES = {"confidentiality", "integrity", "availability"}
# Authored long form in, report short form out. The report contract (plan §4.2)
# keys the cia block by letter; the documents on disk spell the axis out.
CIA_OUTPUT_KEYS = {"confidentiality": "c", "integrity": "i", "availability": "a"}
# Evidence provenance, a separate axis from ASSESSMENT_STATUSES above.
# CONFIRMED + inferred is a legal record.
EVIDENCE_STATUSES = {"observed", "inferred", "unverified"}
LIFELIHOOD_EVIDENCE_FIELDS = (
    "exposure",
    "access_required",
    "exploit_complexity",
    "preconditions",
    "observed_controls",
)
AUTHORITIES = {"self_declared", "externally_attested"}
#: Interview depth for a design review. `quick` takes the architecture as
#: given; `guided` asks. Closed, because a third value would have to mean
#: something to every stage that reads it.
REVIEW_MODES = {"guided", "quick"}
#: The appetites under `risk/appetite/`. One file per name, so a value outside
#: this set names a policy that does not exist.
RISK_APPETITES = {"conservative", "standard", "tolerant"}
EVIDENCE_METHODS = {
    "iac_inspect",
    "config_api",
    "code_grep",
    "test_case",
    "artifact_review",
    "manual",
}
EVIDENCE_SUPPORTS = {"likelihood", "impact", "attack_path_removal"}

# Key material, as data rather than branches (plan §9 change point 6). A new
# credential form is a row here, never an `if` somewhere in the scan.
#
# The existing publish-boundary scan in lint.py knows shapes and hosts:
# INSTANCE_FORMS, CITATION_HOSTS, SIGNED_PARAM_NAMES. None of them knows what a
# credential is, so a password beside an unremarkable hostname published clean.
KEY_MATERIAL_PATTERNS: tuple[tuple[str, Any], ...] = (
    # AKIA plus exactly sixteen. Bounded on both sides so a longer run of the
    # same characters is not sliced into a false match.
    (
        "an AWS access key id",
        re.compile(r"(?<![A-Za-z0-9])AKIA[0-9A-Z]{16}(?![A-Za-z0-9])"),
    ),
    (
        "a private key block",
        re.compile(r"-----BEGIN(?: [A-Z]+)* PRIVATE KEY-----"),
    ),
    # `user:password@host`, with no scheme required. Keying on the scheme is
    # what let a DSN through the moment its host stopped looking internal, and
    # the credential is in the userinfo either way.
    (
        "a credential embedded in a connection string",
        re.compile(r"[^\s:@/]+:[^\s@/]+@"),
    ),
    (
        "a signed token",
        re.compile(r"eyJ[A-Za-z0-9_\-]{3,}"),
    ),
)

# A forty-character base64-ish run: the AWS secret access key shape. Handled
# separately from the table because it needs a mixed-case test that a regex
# alone states badly -- a forty-character lowercase run is a sha1 digest, which
# is published deliberately and must not be flagged.
_OPAQUE_SECRET = re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])")


def key_material_fingerprint(value: str) -> str:
    """Identify a secret without carrying it.

    A report that quotes the secret has copied it somewhere new. This is what
    lets two findings be told apart, and the same finding be recognised across
    runs, without the report becoming a second disclosure.
    """

    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def key_material_problems(text: str) -> list[tuple[str, str]]:
    """Return (label, fingerprint) for every distinct credential in ``text``.

    Deduplicated by fingerprint so one secret quoted twice is one problem, and
    ordered by first appearance so the report is deterministic.
    """

    problems: list[tuple[str, str]] = []
    seen: set[str] = set()

    def record(label: str, value: str) -> None:
        fingerprint = key_material_fingerprint(value)
        if fingerprint in seen:
            return
        seen.add(fingerprint)
        problems.append((label, fingerprint))

    for label, pattern in KEY_MATERIAL_PATTERNS:
        for match in pattern.finditer(text):
            record(label, match.group(0))
    for match in _OPAQUE_SECRET.finditer(text):
        candidate = match.group(0)
        if not any(c.islower() for c in candidate):
            continue
        if not any(c.isupper() for c in candidate):
            continue
        record("an opaque secret", candidate)
    return problems
MINIMUM_PYTHON = (3, 12)
LEGACY_THREAT_SCHEMA_VERSION = "0.1.0"
CURRENT_THREAT_SCHEMA_VERSION = "0.2.0"
RISK_SCHEMA_VERSION = "0.2.0"


def _current_threat_schema_problems(threats_doc: dict) -> list[str]:
    problems: list[str] = []
    if not isinstance(threats_doc, Mapping):
        problems.append("threat document must be a mapping")
        return problems
    if threats_doc.get("version") != CURRENT_THREAT_SCHEMA_VERSION:
        problems.append("threat schema version must be 0.2.0")
    return problems


def _require_legacy_threat_schema(threats: dict) -> None:
    if (
        not isinstance(threats, Mapping)
        or threats.get("version") != LEGACY_THREAT_SCHEMA_VERSION
    ):
        raise RiskValidationError("legacy threat schema must be 0.1.0")


class RiskArgumentError(ValueError):
    """Raised when the risk CLI does not match its strict grammar."""


#: Flags that were removed, mapped to the flag that replaced them. `--profile`
#: collided with the service `profile.yaml` the tool already reads, so the
#: design-review appetite selector is spelled `--risk-appetite`.
#:
#: Data rather than a branch: a retired flag is rejected by the closed grammar
#: like any other unknown flag, and this table only decides what the message
#: says. A bare "unrecognized arguments: --profile" sends the reader to the
#: docs to find out what to type instead.
RETIRED_FLAGS: dict[str, str] = {
    "--profile": "--risk-appetite",
}


class _StrictArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        hints = [
            f"{retired} was replaced by {successor}"
            for retired, successor in RETIRED_FLAGS.items()
            if retired in message
        ]
        if hints:
            message = f"{message} ({'; '.join(hints)})"
        raise RiskArgumentError(message)


class _StoreOnce(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None) -> None:
        if getattr(namespace, self.dest, None) is not None:
            raise argparse.ArgumentError(
                self, f"{option_string or self.dest} may be specified only once"
            )
        setattr(namespace, self.dest, values)


def appetite_policy(name: str, *, plugin_root: Path | None = None) -> dict:
    """The base risk policy overlaid with one appetite.

    An appetite file is an *overlay*, not a policy. It carries `thresholds`,
    `impact_floor`, `release_threshold_rating` and `publish_risk_summary`; the
    `likelihood` and `impact` criterion tables live only in
    `default-policy.yaml` and are the same under every appetite — an appetite
    changes what a score *means*, not how it is derived.

    Shallow merge, overlay wins per top-level key. Deep-merging `thresholds`
    would let an appetite silently inherit a band it did not restate, so a
    conservative file that lists three bands would quietly keep the base
    file's fourth.
    """

    if name not in RISK_APPETITES:
        raise RiskValidationError(
            f"unknown risk appetite {name!r}; expected one of "
            f"{', '.join(sorted(RISK_APPETITES))}"
        )
    root = plugin_root or Path(__file__).resolve().parent.parent
    policy = load_policy(root / "risk" / "default-policy.yaml")
    overlay = load_policy(root / "risk" / "appetite" / f"{name}.yaml")
    policy.update(overlay)
    return policy


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


def impact_floor(policy: dict, level: str) -> int:
    """Resolve a FIPS 199 impact level to its bounded consequence floor."""

    floors = policy.get("impact_floor")
    if not isinstance(floors, Mapping):
        raise RiskValidationError("policy impact_floor is required")
    try:
        value = floors[level]
    except (KeyError, TypeError) as exc:
        raise RiskValidationError(f"unknown impact level: {level}") from exc
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 5:
        raise RiskValidationError(f"impact floor for {level} is invalid")
    return value


def _profile_impact_level(profile_impact: Mapping, axis: str) -> str | None:
    """Read one axis level out of the derived FIPS 199 impact block."""

    entry = profile_impact.get(axis)
    if isinstance(entry, Mapping):
        entry = entry.get("level")
    return entry if isinstance(entry, str) and entry else None


def _scored_consequences(
    policy: dict, consequences: Sequence, profile_impact: Mapping | None = None
) -> list[dict]:
    """Validate and score every consequence exactly once.

    The single walk behind both the overall impact and the per-axis CIA block,
    so there is one scorer rather than two that can drift apart.
    """

    rows: list[dict] = []
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
        score = criterion_score(policy, "impact", criterion)
        # A consequence written before the field existed carries no axis; its
        # absence stays legal, an unrecognised value never does.
        axis = item.get("axis")
        if axis is not None and axis not in CONSEQUENCE_AXES:
            raise RiskValidationError(f"unknown consequence axis: {axis}")
        if profile_impact is not None and axis is not None:
            level = _profile_impact_level(profile_impact, axis)
            if level is not None:
                floor = impact_floor(policy, level)
                if score < floor:
                    raise RiskValidationError(
                        f"consequence {consequence_id} {axis} score {score} is below "
                        f"the {level} floor {floor}"
                    )
                if score > floor:
                    _require_rationale(
                        item.get("raise_reason"), "raise above the floor"
                    )
        rows.append({"id": consequence_id, "axis": axis, "score": score})
    return rows


def _require_consequences(proposed: dict) -> Sequence:
    if not isinstance(proposed, Mapping):
        raise RiskValidationError("assessment proposal must be a mapping")
    consequences = proposed.get("consequences")
    if not isinstance(consequences, Sequence) or isinstance(consequences, (str, bytes)):
        raise RiskValidationError("at least one consequence is required")
    if not consequences:
        raise RiskValidationError("at least one consequence is required")
    return consequences


def cia_scores(
    policy: dict, proposed: dict, *, profile_impact: Mapping | None = None
) -> dict:
    """Derive the per-axis CIA block from axis-tagged consequences.

    A sibling of the ``calculated`` block, not a member of it — see plan §4.2,
    where ``cia`` and ``calculated`` sit side by side on the finding. Keeping
    it out of ``calculate_inherent``'s return is what lets the stored
    ``calculated`` contract stay at four keys.

    Input axes are long form; output keys are the short form the report
    contract uses. Axes with no consequence are absent rather than zero.
    """

    scored = _scored_consequences(
        policy, _require_consequences(proposed), profile_impact
    )
    block: dict = {}
    for row in scored:
        if row["axis"] is None:
            continue
        key = CIA_OUTPUT_KEYS[row["axis"]]
        block[key] = max(block.get(key, 0), row["score"])
    return block


def calculate_inherent(
    policy: dict, proposed: dict, *, profile_impact: Mapping | None = None
) -> dict:
    """Calculate inherent risk from criterion IDs and explicit consequences.

    ``profile_impact`` is the derived FIPS 199 block ``select_baseline.py``
    emits. When supplied, each axis-tagged consequence is held to the policy's
    ``impact_floor``: below it is rejected rather than clamped, and above it
    requires a written ``raise_reason``. Omitted, the arithmetic is unchanged.
    """

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

    scored = _scored_consequences(
        policy, _require_consequences(proposed), profile_impact
    )
    impacts = [row["score"] for row in scored]
    consequence_ids = {row["id"] for row in scored}

    impact_data = proposed.get("impact")
    if not isinstance(impact_data, Mapping):
        raise RiskValidationError("impact selection is required")
    selected_from = impact_data.get("selected_from")
    if selected_from not in consequence_ids:
        raise RiskValidationError("impact selected_from must identify a consequence")
    selected_index = next(
        index for index, row in enumerate(scored) if row["id"] == selected_from
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
    decreases = any(
        inherent[axis] > calculated[axis] for axis in ("likelihood", "impact")
    )
    if not current and decreases:
        if requirements is None:
            return {
                "status": "UNDETERMINED",
                "reason": "linked requirements have no valid implementation evidence",
            }
        raise RiskValidationError(
            "residual reduction requires current passing evidence"
        )
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


# The same fields with the identifier removed. `threat_digest` binds a
# confirmation to one record and therefore includes `id`, which makes it useless
# for spotting the same threat entered twice: two ids always give two digests.
# Deduplication and binding are different jobs and need different keys.
MATERIAL_THREAT_FIELDS = tuple(
    field for field in THREAT_DIGEST_FIELDS if field != "id"
)


def threat_material_digest(threat: dict) -> str:
    """Digest what a threat *says*, ignoring which id it was filed under."""

    if not isinstance(threat, Mapping):
        raise RiskValidationError("threat must be a mapping")
    return canonical_digest(
        {key: threat.get(key) for key in MATERIAL_THREAT_FIELDS}
    )


def _duplicate_threat_pairs(threats: Sequence) -> list[tuple[str, str]]:
    """(first_id, duplicate_id) for every record repeating an earlier one.

    Ordered by appearance so the report is deterministic.
    """

    first_seen: dict[str, str] = {}
    duplicates: list[tuple[str, str]] = []
    for threat in threats:
        if not isinstance(threat, Mapping):
            continue
        threat_id = threat.get("id")
        if not isinstance(threat_id, str) or not threat_id:
            continue
        # Active records only. Superseding a threat routinely produces a
        # replacement identical in every material field -- that is the
        # supersede pattern working, not a document saying the same thing
        # twice -- and retired records are history the register keeps on
        # purpose.
        if _lifecycle_status(threat) != "active":
            continue
        digest = threat_material_digest(threat)
        if digest in first_seen:
            duplicates.append((first_seen[digest], threat_id))
        else:
            first_seen[digest] = threat_id
    return duplicates


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
    problems = _current_threat_schema_problems(threats_doc)
    if not isinstance(threats_doc, Mapping):
        return problems, []
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
        # Provenance is optional on a record that predates the field, and closed
        # to three values when present. Independent of the lifecycle status.
        evidence_status = threat.get("evidence_status")
        if evidence_status is not None and evidence_status not in EVIDENCE_STATUSES:
            problems.append(f"{label} evidence_status is invalid")

    # After the per-record loop, not inside it. The same threat filed twice
    # under two ids is a property of the document, not of either record.
    for first_id, duplicate_id in _duplicate_threat_pairs(threats):
        problems.append(
            f"{duplicate_id} duplicates {first_id}: identical in every "
            f"material field except id"
        )

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
    # The cia block is derived from axis-tagged consequences. A declared one is
    # the same class of claim as a declared score, and is refused the same way.
    for carrier in (record, proposed):
        if carrier.get("cia") is not None:
            problems.append(f"{threat_id} cia is derived, not declared")
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


def validate_assessment(
    threats: dict, assessment: dict, policy: dict, today: date | None = None
) -> list[str]:
    """Return deterministic validation problems for a threat assessment document.

    `today` decides which acceptances have expired. It is a parameter (plan
    §11.2 N40) because a verdict a reviewer cannot reproduce is not a verdict:
    without it, the same document validates clean one day and reports an
    expired acceptance the next, with no way to pin which answer was given.

    Defaulting to the calendar is the correct default — an expiry that ignores
    the date is not an expiry — but the default is now the caller's to override.
    """

    today = today or date.today()

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
                    for problem in validate_treatment(record, policy, today)
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
    # Refused here rather than in active_threats, which digesting and validation
    # also call: a document that says the same thing twice can still be read and
    # digested, it just cannot be *scored*. Counting both inflates the register,
    # and an inflated register reads as assessed, so nobody goes looking.
    duplicates = _duplicate_threat_pairs(active)
    if duplicates:
        first_id, duplicate_id = duplicates[0]
        raise RiskValidationError(
            f"duplicate threat: {duplicate_id} repeats {first_id}"
        )
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
    refs = sorted({reference for reference in threat_refs if _nonempty_text(reference)})
    active_refs = [reference for reference in refs if reference in active_ids]
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
    if not active_refs:
        return result
    if today is None:
        today = date.today()

    confirmed_ratings: list[str] = []
    unresolved: set[str] = set()
    for reference in active_refs:
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


def output_allowed(
    problems: Sequence[str], evidence_problems: Sequence[str]
) -> bool:
    """Whether a run may render anything at all.

    Invalid or stale evidence may still render an UNDETERMINED preview: the
    reader learns the evidence expired, which is the answer. Any *binding or
    document-integrity* error suppresses all output, so untrusted assessment
    material is never presented as a calculated result.

    One function with two callers rather than the rule written twice. The
    residual preview and the design review reach it by different routes and
    must agree; two copies agree on the day they are written and diverge on
    the day one of them is fixed (plan §11.2 N29).
    """

    return not problems or (
        bool(evidence_problems)
        and all(problem in evidence_problems for problem in problems)
    )


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

    # The data-flow diagram is sensitive by construction: it names components,
    # stores, and internal boundaries, which is the "where does the data live"
    # answer the publish boundary exists to refuse. It reaches this document and
    # no other -- render_public_summary must never grow an equivalent block.
    architecture = summary.get("architecture")
    if isinstance(architecture, Mapping):
        import sdr_mermaid

        diagram = sdr_mermaid.render_dfd(architecture)
        if diagram.strip():
            out += [
                "## Data flows",
                "",
                "```mermaid",
                diagram,
                "```",
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
    sections: list[tuple[str, Mapping]] = []
    for name in ("inherent", "residual"):
        if name not in summary:
            continue
        value = summary[name]
        if not isinstance(value, Mapping):
            raise RiskValidationError(
                f"public risk summary {name} aggregate must be a mapping"
            )
        sections.append((name, value))
    if not sections and any(field in summary for field in ("overall", "counts", "coverage")):
        sections.append(("inherent", summary))
    if not sections:
        raise RiskValidationError("public risk summary has no aggregate section")
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
    declared_digest = snapshot.get("snapshot_digest")
    if declared_digest is not None:
        digest_material = copy.deepcopy(dict(snapshot))
        digest_material.pop("snapshot_digest", None)
        if declared_digest != canonical_digest(digest_material):
            raise RiskValidationError("risk snapshot digest is invalid")
    snapshots = state.get("snapshots", [])
    if not isinstance(snapshots, Sequence) or isinstance(snapshots, (str, bytes)):
        raise RiskValidationError("risk state snapshots must be a list")
    result = copy.deepcopy(dict(state))
    result["snapshots"] = copy.deepcopy(list(snapshots)) + [copy.deepcopy(dict(snapshot))]
    return result


def _risk_snapshot(
    event: str,
    threats: dict,
    assessment: dict,
    policy: dict,
    requirements: dict,
    evidence: dict,
    assessed_at: str,
    today: date | None = None,
) -> dict:
    """Build a digest-bound immutable view of one risk lifecycle transition.

    `today` decides which acceptances have expired, and that verdict reaches
    `snapshot_digest` through `inherent`. It defaults to the date in
    `assessed_at` rather than to the calendar (plan §11.2 N40): a snapshot is a
    view of one moment, so it must be scored as of that moment. Reading the
    process clock instead made `snapshot_digest` a function of the day the
    command ran — and that digest is what `risk_state_digest` binds, so a
    confirmation silently stopped matching on a date nobody chose.
    """

    if today is None:
        # The same parse `_snapshot_assessed_date` already does for a built
        # snapshot, applied to the timestamp before the snapshot exists.
        today = _snapshot_assessed_date({"assessed_at": assessed_at})
    if today is None:
        # No clock fallback. Substituting the calendar here would put the
        # process date back inside `snapshot_digest` for exactly the inputs
        # that are already malformed — the quietest possible version of the
        # bug this parameter exists to close.
        raise RiskValidationError(
            f"snapshot assessed_at is not a parseable timestamp: {assessed_at!r}"
        )

    threat_by_id = {
        threat.get("id"): threat
        for threat in threats.get("threats", [])
        if isinstance(threat, Mapping) and _nonempty_text(threat.get("id"))
    }
    records: list[dict] = []
    residual: dict[str, object] = {}
    treatment: dict[str, object] = {}
    evidence_refs: set[str] = set()
    for source in assessment.get("assessments", []):
        if not isinstance(source, Mapping):
            continue
        record = copy.deepcopy(dict(source))
        threat_id = record.get("threat_id")
        threat = threat_by_id.get(threat_id)
        lifecycle = threat.get("lifecycle") if isinstance(threat, Mapping) else None
        record["lifecycle"] = copy.deepcopy(
            lifecycle if isinstance(lifecycle, Mapping) else {"status": "active"}
        )
        records.append(record)
        if _nonempty_text(threat_id):
            residual[threat_id] = copy.deepcopy(record.get("residual"))
            treatment[threat_id] = copy.deepcopy(record.get("treatment"))
        evidence_refs.update(_residual_evidence_refs(record))

    snapshot = {
        "event": event,
        "assessed_at": assessed_at,
        "policy_digest": policy_digest(policy),
        "threat_digest": aggregate_threat_digest(threats),
        "assessment_digest": assessment_digest(assessment),
        "requirements_digest": canonical_digest(requirements),
        "evidence_digest": canonical_digest(evidence),
        "inherent": aggregate_risk(threats, assessment, today=today),
        "residual": residual,
        "treatment": treatment,
        "evidence_refs": sorted(evidence_refs),
        "assessments": records,
    }
    snapshot["snapshot_digest"] = canonical_digest(snapshot)
    return snapshot


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


def migrate(threats: dict, requirements: dict) -> dict:
    """Create review-only risk scaffolding for a legacy threat document.

    Migration is intentionally pure: callers receive candidate internal
    documents, while the legacy threat document and human-owned requirements
    remain unchanged.  Criterion choices, numeric results, and confirmation
    metadata belong to the later human review and are never inferred here.
    """

    _require_legacy_threat_schema(threats)
    records = threats.get("threats")
    if not isinstance(records, Sequence) or isinstance(records, (str, bytes)):
        raise RiskValidationError("legacy threats must be a list")

    seen_ids: set[str] = set()
    active_ids: list[str] = []
    for record in records:
        if not isinstance(record, Mapping):
            raise RiskValidationError("legacy threat must be a mapping")
        threat_id = record.get("id")
        if not _nonempty_text(threat_id):
            raise RiskValidationError("legacy threat id is required")
        if threat_id in seen_ids:
            raise RiskValidationError(f"duplicate legacy threat id: {threat_id}")
        seen_ids.add(threat_id)
        if _lifecycle_status(record) == "active":
            active_ids.append(threat_id)

    migrated_requirements = propose_exception_migration(requirements)
    pending_requirement_migrations: list[dict] = []
    for record in migrated_requirements["requirements"]:
        if not isinstance(record, Mapping):
            continue
        pending = record.get("pending_review")
        proposal = pending.get("risk_treatment") if isinstance(pending, Mapping) else None
        if isinstance(proposal, Mapping):
            pending_requirement_migrations.append(
                {
                    "requirement_id": record.get("id"),
                    **copy.deepcopy(dict(proposal)),
                }
            )

    assessments = [
        {"threat_id": threat_id, "status": "PROPOSED"}
        for threat_id in active_ids
    ]
    migration = {
        "status": "legacy_unassessed",
        "source_schema": LEGACY_THREAT_SCHEMA_VERSION,
        "target_schema": CURRENT_THREAT_SCHEMA_VERSION,
        "active_legacy_threats": len(active_ids),
    }
    policy = load_policy(
        Path(__file__).resolve().parent.parent / "risk" / "default-policy.yaml"
    )
    evidence = {"evidence": []}
    refresh_baseline = {
        "threats": copy.deepcopy(dict(threats)),
        "requirements": copy.deepcopy(dict(requirements)),
        "evidence": evidence,
        "policy_digest": policy_digest(policy),
    }
    return {
        **migration,
        "threats": copy.deepcopy(dict(threats)),
        "policy": policy,
        "assessment": {
            "version": RISK_SCHEMA_VERSION,
            "migration": copy.deepcopy(migration),
            "assessments": copy.deepcopy(assessments),
        },
        "assessments": assessments,
        "state": {
            "version": RISK_SCHEMA_VERSION,
            "migration": copy.deepcopy(migration),
            "snapshots": [],
            "refresh_baseline": refresh_baseline,
            "pending_requirement_migrations": copy.deepcopy(
                pending_requirement_migrations
            ),
        },
        "pending_requirement_migrations": pending_requirement_migrations,
    }


INHERENT_REFRESH_FIELDS = (
    "scenario",
    "boundary",
    "persona",
    "attack_path",
    "affected_assets",
)


def _records_by_identity(
    document: object, field: str, identity: str, label: str
) -> dict[str, Mapping]:
    records = _document_records(document, field, label)
    indexed: dict[str, Mapping] = {}
    for record in records:
        if not isinstance(record, Mapping):
            raise RiskValidationError(f"{label[:-1]} must be a mapping")
        record_id = record.get(identity)
        if not _nonempty_text(record_id):
            raise RiskValidationError(f"{label[:-1]} {identity} is required")
        if record_id in indexed:
            raise RiskValidationError(f"duplicate {label[:-1]} {identity}: {record_id}")
        indexed[record_id] = record
    return indexed


def _changed_record_ids(
    previous: object,
    current: object,
    *,
    field: str,
    identity: str,
    label: str,
    material: str | None = None,
) -> tuple[set[str], dict[str, Mapping], dict[str, Mapping]]:
    previous_by_id = _records_by_identity(previous, field, identity, label)
    current_by_id = _records_by_identity(current, field, identity, label)
    changed: set[str] = set()
    for record_id in previous_by_id.keys() | current_by_id.keys():
        old = previous_by_id.get(record_id)
        new = current_by_id.get(record_id)
        old_value = old.get(material) if old is not None and material else old
        new_value = new.get(material) if new is not None and material else new
        if canonical_digest(old_value) != canonical_digest(new_value):
            changed.add(record_id)
    return changed, previous_by_id, current_by_id


def _risk_refs_for_requirement(record: Mapping | None) -> set[str]:
    if record is None:
        return set()
    values: list[object] = [record.get("risk_refs")]
    managed = record.get("managed")
    if isinstance(managed, Mapping):
        values.append(managed.get("risk_refs"))
    return {
        reference
        for refs in values
        if isinstance(refs, Sequence) and not isinstance(refs, (str, bytes))
        for reference in refs
        if _nonempty_text(reference)
    }


def _record_refs(record: Mapping, container: str, field: str) -> set[str]:
    value = record.get(container)
    if not isinstance(value, Mapping):
        return set()
    refs = value.get(field)
    if not isinstance(refs, Sequence) or isinstance(refs, (str, bytes)):
        return set()
    return {reference for reference in refs if _nonempty_text(reference)}


def _residual_evidence_refs(record: Mapping) -> set[str]:
    residual = record.get("residual")
    if not isinstance(residual, Mapping):
        return set()
    refs = residual.get("evidence_refs")
    result = (
        {reference for reference in refs if _nonempty_text(reference)}
        if isinstance(refs, Sequence) and not isinstance(refs, (str, bytes))
        else set()
    )
    proposed = residual.get("proposed")
    if isinstance(proposed, Mapping):
        for axis in ("likelihood", "impact"):
            axis_data = proposed.get(axis)
            axis_refs = axis_data.get("evidence_refs") if isinstance(axis_data, Mapping) else None
            if isinstance(axis_refs, Sequence) and not isinstance(axis_refs, (str, bytes)):
                result.update(
                    reference for reference in axis_refs if _nonempty_text(reference)
                )
    return result


def _mark_residual_stale(record: dict) -> bool:
    residual = record.get("residual")
    if not isinstance(residual, dict) or residual.get("status") != "CONFIRMED":
        return False
    residual["status"] = "STALE"
    return True


def refresh_assessment(
    previous_threats: dict,
    current_threats: dict,
    assessment: dict,
    *,
    previous_requirements: dict | None = None,
    current_requirements: dict | None = None,
    previous_evidence: dict | None = None,
    current_evidence: dict | None = None,
    policy_changed: bool = False,
) -> dict:
    """Reuse unchanged risk records and stale only refresh-affected decisions."""

    if not isinstance(assessment, Mapping):
        raise RiskValidationError("assessment document must be a mapping")
    old_threats = _records_by_identity(
        previous_threats, "threats", "id", "threats"
    )
    new_threats = _records_by_identity(current_threats, "threats", "id", "threats")
    _records_by_identity(
        assessment, "assessments", "threat_id", "assessments"
    )
    result = copy.deepcopy(dict(assessment))
    result_records = result.get("assessments")
    if not isinstance(result_records, list):
        raise RiskValidationError("assessments must be a list")
    result_by_id = {
        record["threat_id"]: record
        for record in result_records
        if isinstance(record, dict) and _nonempty_text(record.get("threat_id"))
    }
    changed = False

    affected_requirement_ids: set[str] = set()
    old_requirements: dict[str, Mapping] = {}
    new_requirements: dict[str, Mapping] = {}
    if previous_requirements is not None or current_requirements is not None:
        affected_requirement_ids, old_requirements, new_requirements = (
            _changed_record_ids(
                previous_requirements or {"requirements": []},
                current_requirements or {"requirements": []},
                field="requirements",
                identity="id",
                label="requirements",
                material="managed",
            )
        )

    affected_evidence_ids: set[str] = set()
    old_evidence: dict[str, Mapping] = {}
    new_evidence: dict[str, Mapping] = {}
    if previous_evidence is not None or current_evidence is not None:
        affected_evidence_ids, old_evidence, new_evidence = _changed_record_ids(
            previous_evidence or {"evidence": []},
            current_evidence or {"evidence": []},
            field="evidence",
            identity="id",
            label="evidence",
        )

    requirement_affected_threats: set[str] = set()
    for requirement_id in affected_requirement_ids:
        requirement_affected_threats.update(
            _risk_refs_for_requirement(old_requirements.get(requirement_id))
        )
        requirement_affected_threats.update(
            _risk_refs_for_requirement(new_requirements.get(requirement_id))
        )
    for evidence_id in affected_evidence_ids:
        for evidence_record in (old_evidence.get(evidence_id), new_evidence.get(evidence_id)):
            requirement_id = (
                evidence_record.get("requirement_id")
                if isinstance(evidence_record, Mapping)
                else None
            )
            if _nonempty_text(requirement_id):
                requirement_affected_threats.update(
                    _risk_refs_for_requirement(old_requirements.get(requirement_id))
                )
                requirement_affected_threats.update(
                    _risk_refs_for_requirement(new_requirements.get(requirement_id))
                )

    for threat_id, current in new_threats.items():
        current_status = _lifecycle_status(current)
        previous = old_threats.get(threat_id)
        previous_status = _lifecycle_status(previous) if previous is not None else None
        record = result_by_id.get(threat_id)

        if current_status == "active" and record is None:
            record = {"threat_id": threat_id, "status": "PROPOSED"}
            result_records.append(record)
            result_by_id[threat_id] = record
            changed = True
        if record is None:
            continue

        if current_status == "active" and policy_changed:
            if record.get("status") == "CONFIRMED":
                record["status"] = "STALE"
                changed = True
            changed = _mark_residual_stale(record) or changed

        if current_status == "active" and previous is None:
            if record.get("status") != "PROPOSED":
                record["status"] = "PROPOSED"
                changed = True
            changed = _mark_residual_stale(record) or changed
        elif current_status == "active" and previous_status != "active":
            if record.get("status") != "PROPOSED":
                record["status"] = "PROPOSED"
                changed = True
            changed = _mark_residual_stale(record) or changed
        elif current_status == "active" and previous is not None and any(
            canonical_digest(previous.get(field)) != canonical_digest(current.get(field))
            for field in INHERENT_REFRESH_FIELDS
        ):
            if record.get("status") == "CONFIRMED":
                record["status"] = "STALE"
                changed = True

        if (
            current_status == "active"
            and previous is not None
            and canonical_digest(previous.get("related_controls"))
            != canonical_digest(current.get("related_controls"))
        ):
            changed = _mark_residual_stale(record) or changed

        treatment_requirement_refs = _record_refs(
            record, "treatment", "requirement_refs"
        )
        if (
            current_status == "active"
            and (
                threat_id in requirement_affected_threats
                or bool(treatment_requirement_refs & affected_requirement_ids)
                or bool(_residual_evidence_refs(record) & affected_evidence_ids)
            )
        ):
            changed = _mark_residual_stale(record) or changed

        if previous is None or previous_status != current_status or any(
            canonical_digest(previous.get(field)) != canonical_digest(current.get(field))
            for field in THREAT_DIGEST_FIELDS
        ):
            changed = True

    if set(old_threats) != set(new_threats):
        changed = True
    if changed:
        result.pop("confirmation", None)
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
    try:
        document_path = _path_from(paths, name)
    except ValueError:
        canonical_names = {
            "requirements": "requirements.yaml",
            "evidence": "risk-evidence.yaml",
            "state": "risk-state.yaml",
        }
        if name not in canonical_names:
            raise
        document_path = (
            project_root / ".security-requirements" / canonical_names[name]
        )
    validated_path = safe_path(document_path, project_root=project_root)
    return project_root, validated_path


def _load_mapping(path: Path, label: str) -> dict:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RiskValidationError(f"{label} must be a mapping")
    return value


def _load_optional_mapping(path: Path, label: str, empty: dict) -> dict:
    if not path.exists():
        return copy.deepcopy(empty)
    return _load_mapping(path, label)


def _refresh_documents(paths: Mapping | object) -> tuple[dict, dict, dict]:
    _unused_root, threats_path = _project_document_path(paths, "threats")
    _unused_root, requirements_path = _project_document_path(paths, "requirements")
    _unused_root, evidence_path = _project_document_path(paths, "evidence")
    return (
        _load_mapping(threats_path, "threat document"),
        _load_optional_mapping(
            requirements_path, "requirements document", {"requirements": []}
        ),
        _load_optional_mapping(evidence_path, "evidence document", {"evidence": []}),
    )


def _refresh_baseline(
    threats: dict, requirements: dict, evidence: dict, policy: dict
) -> dict:
    return {
        "threats": copy.deepcopy(threats),
        "requirements": copy.deepcopy(requirements),
        "evidence": copy.deepcopy(evidence),
        "policy_digest": policy_digest(policy),
    }


def _load_validated_risk_state(paths: Mapping | object) -> tuple[Path, Path, dict]:
    project_root, state_path = _project_document_path(paths, "state")
    state = _load_optional_mapping(
        state_path,
        "risk state",
        {"version": RISK_SCHEMA_VERSION, "snapshots": []},
    )
    if not isinstance(state, Mapping) or state.get("version") != RISK_SCHEMA_VERSION:
        raise RiskValidationError("risk state version must be 0.2.0")
    if not isinstance(state.get("snapshots"), Sequence) or isinstance(
        state.get("snapshots"), (str, bytes)
    ):
        raise RiskValidationError("risk state snapshots must be a list")
    return project_root, state_path, state


def _load_risk_state(paths: Mapping | object) -> tuple[Path, Path, dict]:
    return _load_validated_risk_state(paths)


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


def _refresh_binding_metadata(
    project_root: Path,
    trusted: object,
    policy: dict,
    threats: dict,
    requirements: dict,
    evidence: dict,
    assessment: dict,
    risk_state: dict,
    bound_at: str,
) -> dict:
    """Bind an unconfirmed refreshed view to plugin-owned authoritative state."""

    return {
        "status": "refresh_bound",
        "project": str(project_root.resolve()),
        "policy_digest": policy_digest(policy),
        "threat_document_digest": canonical_digest(threats),
        "requirements_digest": canonical_digest(requirements),
        "evidence_digest": canonical_digest(evidence),
        "refreshed_assessment_digest": assessment_digest(assessment),
        "risk_state_digest": canonical_digest(risk_state),
        "previous_binding_digest": canonical_digest(trusted),
        "bound_at": bound_at,
    }


def _refresh_binding_problems(
    binding: object,
    project_root: Path,
    policy: dict,
    threats: dict,
    requirements: dict,
    evidence: dict,
    risk_state: dict,
    *,
    require_matching_inputs: bool = True,
) -> list[str]:
    if not isinstance(binding, Mapping) or binding.get("status") != "refresh_bound":
        return ["plugin-owned refreshed risk binding is missing"]
    required = (
        "project",
        "policy_digest",
        "threat_document_digest",
        "requirements_digest",
        "evidence_digest",
        "risk_state_digest",
        "previous_binding_digest",
        "bound_at",
    )
    missing = [field for field in required if not binding.get(field)]
    if missing:
        return ["refreshed risk binding is incomplete: " + ", ".join(missing)]
    problems: list[str] = []
    if binding["project"] != str(project_root.resolve()):
        problems.append("project identity changed")
    if binding["risk_state_digest"] != canonical_digest(risk_state):
        problems.append("externally bound refreshed state changed")
    if require_matching_inputs:
        if binding["policy_digest"] != policy_digest(policy):
            problems.append("policy changed after refreshed state was bound")
        if binding["threat_document_digest"] != canonical_digest(threats):
            problems.append("threats changed after refreshed state was bound")
        if binding["requirements_digest"] != canonical_digest(requirements):
            problems.append("requirements changed after refreshed state was bound")
        if binding["evidence_digest"] != canonical_digest(evidence):
            problems.append("evidence changed after refreshed state was bound")
    return problems


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


def _write_text_transaction(
    entries: Sequence[tuple[Path, Path, str, bool]],
    *,
    require_absent: bool = False,
) -> None:
    """Write a complete document set and restore every target on failure."""

    targets: list[tuple[Path, Path, str, bool, bytes | None]] = []
    seen: set[Path] = set()
    for path, root, content, create_parents in entries:
        # Refused before a single byte is written, not rolled back after. A
        # rollback still put the credential on disk, where a backup, an editor
        # swap file, or a filesystem snapshot may already have it.
        leaked = key_material_problems(content)
        if leaked:
            raise RiskValidationError(
                "refusing to write key material to "
                f"{Path(path).name}: "
                + ", ".join(
                    f"{label} (fingerprint {fingerprint})"
                    for label, fingerprint in leaked
                )
            )
        validated = safe_path(path, project_root=root)
        if validated in seen:
            raise RiskValidationError(f"duplicate transaction target: {validated}")
        seen.add(validated)
        prior = validated.read_bytes() if validated.exists() else None
        if require_absent and prior is not None:
            raise RiskValidationError(f"transaction target already exists: {validated}")
        targets.append((validated, root, content, create_parents, prior))

    try:
        for path, root, content, create_parents, _prior in targets:
            safe_write_text(
                path,
                content,
                encoding="utf-8",
                project_root=root,
                create_parents=create_parents,
            )
    except BaseException as write_error:
        rollback_errors: list[str] = []

        def restore(target: tuple[Path, Path, str, bool, bytes | None]) -> None:
            path, root, _content, _create_parents, prior = target
            if prior is None:
                safe_path(path, project_root=root).unlink(missing_ok=True)
            else:
                # Byte-for-byte, via `surrogateescape` in both directions. The
                # prior contents were read as bytes and need not be valid
                # UTF-8; a strict decode here raises, the restore fails, and
                # the target keeps the *failed run's* content — a partial write
                # from the one code path whose whole purpose is to prevent one.
                safe_write_text(
                    path,
                    prior.decode("utf-8", "surrogateescape"),
                    encoding="utf-8",
                    errors="surrogateescape",
                    project_root=root,
                    create_parents=True,
                )

        def matches(target: tuple[Path, Path, str, bool, bytes | None]) -> bool:
            path, _root, _content, _create_parents, prior = target
            if prior is None:
                return not path.exists()
            return path.exists() and path.read_bytes() == prior

        # Restore the entire declared set, including a target whose writer
        # replaced the file before raising. A second pass handles transient
        # cleanup failures without preventing restoration of later targets.
        for target in reversed(targets):
            try:
                restore(target)
            except BaseException as rollback_error:
                rollback_errors.append(f"{target[0]}: {rollback_error}")
        for target in reversed(targets):
            if matches(target):
                continue
            try:
                restore(target)
            except BaseException as rollback_error:
                rollback_errors.append(f"{target[0]}: {rollback_error}")

        mismatched = [str(target[0]) for target in targets if not matches(target)]
        if mismatched:
            details = rollback_errors + [
                "state not restored: " + ", ".join(mismatched)
            ]
            raise RuntimeError(
                "document transaction failed and rollback was incomplete: "
                + "; ".join(details)
            ) from write_error
        raise


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
            raise RiskValidationError(
                f"{record.get('threat_id', '<unknown>')} assessment proposal is required"
            )
        record["status"] = "CONFIRMED"
        record["calculated"] = calculate_inherent(policy, proposed)
    problems = validate_assessment(threats, result, policy)
    if problems:
        raise RiskValidationError("; ".join(problems))
    return result


def _residual_blocks(records: object, *, snapshot: bool = False) -> object:
    """Return canonical threat/residual pairs for approval-bound comparison."""

    if not isinstance(records, Sequence) or isinstance(records, (str, bytes)):
        return records
    result = []
    for record in records:
        if not isinstance(record, Mapping):
            result.append(record)
            continue
        result.append(
            {
                "threat_id": record.get("threat_id"),
                "residual": copy.deepcopy(record.get("residual")),
            }
        )
    return result


def _has_residual_proposal(assessment: Mapping) -> bool:
    records = assessment.get("assessments")
    if not isinstance(records, Sequence) or isinstance(records, (str, bytes)):
        return False
    return any(
        isinstance(record, Mapping)
        and isinstance(record.get("residual"), Mapping)
        and record["residual"].get("proposed") is not None
        for record in records
    )


def _reject_unbound_authoritative_residual(assessment: Mapping) -> None:
    records = assessment.get("assessments")
    if not isinstance(records, Sequence) or isinstance(records, (str, bytes)):
        return
    for record in records:
        if not isinstance(record, Mapping):
            continue
        residual = record.get("residual")
        if not isinstance(residual, Mapping):
            continue
        if residual.get("proposed") is not None:
            raise RiskValidationError("residual proposals require residual-confirm")
        if any(field in residual for field in ("calculated", "evidence_refs")) or (
            residual.get("status") not in (None, "UNDETERMINED")
        ):
            raise RiskValidationError(
                "authoritative residual risk requires residual-confirm"
            )


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
    state_root, confirmation_state_path = _state_target(project_root, "assessment")
    _unused_root, risk_state_path, risk_state = _load_risk_state(paths)
    policy = _load_mapping(policy_path, "risk policy")
    threats, requirements, evidence = _refresh_documents(paths)
    assessment = _load_mapping(assessment_path, "assessment document")
    trusted = _read_trusted_confirmation(project_root, "assessment")
    repository_confirmation = assessment.get("confirmation")
    if isinstance(trusted, Mapping) and trusted.get("status") == "refresh_bound":
        if repository_confirmation is not None:
            raise RiskValidationError(
                "refreshed assessment must remain unconfirmed before review"
            )
        binding_problems = _refresh_binding_problems(
            trusted,
            project_root,
            policy,
            threats,
            requirements,
            evidence,
            risk_state,
        )
        if binding_problems:
            raise RiskValidationError("; ".join(binding_problems))
        snapshots = risk_state.get("snapshots")
        snapshot = snapshots[-1] if isinstance(snapshots, list) and snapshots else None
        if not isinstance(snapshot, Mapping) or snapshot.get("event") != "refreshed":
            raise RiskValidationError(
                "externally bound refreshed assessment snapshot is missing"
            )
        if canonical_digest(_residual_blocks(assessment.get("assessments"))) != (
            canonical_digest(_residual_blocks(snapshot.get("assessments"), snapshot=True))
        ):
            if _has_residual_proposal(assessment):
                raise RiskValidationError(
                    "residual proposals require residual-confirm"
                )
            raise RiskValidationError(
                "refreshed residual assessment changed outside residual-confirm"
            )
    elif repository_confirmation is not None or trusted is not None:
        confirmation_problems = check_assessment(paths)
        if confirmation_problems:
            raise RiskValidationError("; ".join(confirmation_problems))
    elif any(
        isinstance(snapshot, Mapping)
        and snapshot.get("event") in {"confirmed", "refreshed"}
        for snapshot in risk_state.get("snapshots", [])
    ):
        raise RiskValidationError(
            "plugin-owned risk assessment confirmation is missing"
        )
    elif trusted is None:
        _reject_unbound_authoritative_residual(assessment)
    legacy = threats.get("version") == LEGACY_THREAT_SCHEMA_VERSION
    confirmed_threats = copy.deepcopy(threats)
    if legacy:
        confirmed_threats["version"] = CURRENT_THREAT_SCHEMA_VERSION
    calculated = _calculate_confirmed_assessment(
        confirmed_threats, assessment, policy
    )
    transition_at = confirmed_at or datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    next_risk_state = copy.deepcopy(risk_state)
    next_risk_state["refresh_baseline"] = _refresh_baseline(
        confirmed_threats, requirements, evidence, policy
    )
    next_risk_state = append_snapshot(
        next_risk_state,
        _risk_snapshot(
            "confirmed",
            confirmed_threats,
            calculated,
            policy,
            requirements,
            evidence,
            transition_at,
        ),
    )
    calculated["confirmation"] = _confirmation_metadata(
        project_root,
        confirmed_by,
        authority,
        transition_at,
        policy_digest=policy_digest(policy),
        threat_digest=aggregate_threat_digest(confirmed_threats),
        assessment_digest=assessment_digest(calculated),
        risk_state_digest=canonical_digest(next_risk_state),
    )
    entries = [
        (
            assessment_path,
            project_root,
            yaml.safe_dump(calculated, allow_unicode=True, sort_keys=False),
            False,
        ),
        (
            confirmation_state_path,
            state_root,
            yaml.safe_dump(
                calculated["confirmation"], allow_unicode=True, sort_keys=False
            ),
            True,
        ),
        (
            risk_state_path,
            project_root,
            yaml.safe_dump(next_risk_state, allow_unicode=True, sort_keys=False),
            True,
        ),
    ]
    if legacy:
        entries.insert(
            2,
            (
                threats_path,
                project_root,
                yaml.safe_dump(
                    confirmed_threats, allow_unicode=True, sort_keys=False
                ),
                False,
            ),
        )
    _write_text_transaction(entries)
    return calculated


def check_assessment(paths: Mapping | object) -> list[str]:
    """Return problems with assessment validation or its external approval."""
    project_root, assessment_path = _project_document_path(paths, "assessment")
    _unused_root, policy_path = _project_document_path(paths, "policy")
    _unused_root, threats_path = _project_document_path(paths, "threats")
    policy = _load_mapping(policy_path, "risk policy")
    threats, requirements, evidence = _refresh_documents(paths)
    _unused_root, _risk_state_path, risk_state = _load_risk_state(paths)
    assessment = _load_mapping(assessment_path, "assessment document")
    trusted = _read_trusted_confirmation(project_root, "assessment")
    problems = _base_confirmation_problems(
        "assessment", assessment.get("confirmation"), trusted, project_root
    )
    if problems:
        return problems
    required_digests = (
        "policy_digest",
        "threat_digest",
        "assessment_digest",
        "risk_state_digest",
    )
    missing = [name for name in required_digests if not trusted.get(name)]
    if missing:
        return ["risk assessment confirmation is incomplete: " + ", ".join(missing)]
    if trusted["policy_digest"] != policy_digest(policy):
        problems.append("policy digest changed")
    if trusted["threat_digest"] != aggregate_threat_digest(threats):
        problems.append("threat digest changed")
    if trusted["assessment_digest"] != assessment_digest(assessment):
        problems.append("assessment digest changed")
    if trusted["risk_state_digest"] != canonical_digest(risk_state):
        problems.append("risk state digest changed")
    baseline = risk_state.get("refresh_baseline")
    if not isinstance(baseline, Mapping):
        problems.append("risk refresh baseline is missing")
    elif trusted["risk_state_digest"] == canonical_digest(risk_state):
        previous_threats = baseline.get("threats")
        previous_requirements = baseline.get("requirements")
        previous_evidence = baseline.get("evidence")
        try:
            preview = refresh_assessment(
                previous_threats,
                threats,
                assessment,
                previous_requirements=previous_requirements,
                current_requirements=requirements,
                previous_evidence=previous_evidence,
                current_evidence=evidence,
                policy_changed=baseline.get("policy_digest")
                != policy_digest(policy),
            )
        except RiskValidationError as exc:
            problems.append(f"risk refresh baseline is invalid: {exc}")
        else:
            old_records = {
                row.get("threat_id"): row
                for row in assessment.get("assessments", [])
                if isinstance(row, Mapping)
            }
            for row in preview.get("assessments", []):
                if not isinstance(row, Mapping):
                    continue
                threat_id = row.get("threat_id")
                old = old_records.get(threat_id)
                if not isinstance(old, Mapping):
                    continue
                old_residual = old.get("residual")
                new_residual = row.get("residual")
                if (
                    isinstance(old_residual, Mapping)
                    and old_residual.get("status") == "CONFIRMED"
                    and isinstance(new_residual, Mapping)
                    and new_residual.get("status") == "STALE"
                ):
                    problems.append(
                        f"risk refresh required: {threat_id} residual risk "
                        "would become STALE"
                    )
    problems.extend(validate_assessment(threats, assessment, policy))
    return problems


def _without_active_residual_proposals(
    records: object, active_ids: set[str], *, snapshot: bool
) -> object:
    """Remove proposals only from active records eligible for this review."""

    if not isinstance(records, Sequence) or isinstance(records, (str, bytes)):
        return records
    result = copy.deepcopy(list(records))
    for record in result:
        if not isinstance(record, dict):
            continue
        if snapshot:
            record.pop("lifecycle", None)
        residual = record.get("residual")
        if isinstance(residual, dict) and record.get("threat_id") in active_ids:
            residual.pop("proposed", None)
            if not residual:
                record.pop("residual", None)
    return result


def _bound_residual_assessment_problems(
    trusted: Mapping,
    risk_state: Mapping,
    assessment: Mapping,
    threats: dict,
    policy: dict,
) -> list[str]:
    """Compare the exact assessment being used with its refresh snapshot."""

    problems: list[str] = []
    if not trusted.get("refreshed_assessment_digest"):
        problems.append(
            "refreshed risk binding is incomplete: refreshed_assessment_digest"
        )
    if assessment.get("confirmation") is not None:
        problems.append("refreshed assessment must remain unconfirmed before review")

    snapshots = risk_state.get("snapshots")
    snapshot = snapshots[-1] if isinstance(snapshots, list) and snapshots else None
    if not isinstance(snapshot, Mapping) or snapshot.get("event") != "refreshed":
        problems.append("externally bound refreshed assessment snapshot is missing")
    else:
        active_ids = {threat["id"] for threat in active_threats(threats)}
        if trusted.get("refreshed_assessment_digest") != snapshot.get(
            "assessment_digest"
        ):
            problems.append("externally bound refreshed assessment digest changed")
        bound_records = copy.deepcopy(snapshot.get("assessments"))
        if isinstance(bound_records, list):
            for record in bound_records:
                if isinstance(record, dict):
                    record.pop("lifecycle", None)
        bound_document = _without_confirmation(assessment)
        bound_document["assessments"] = bound_records
        if assessment_digest(bound_document) != snapshot.get("assessment_digest"):
            problems.append("refreshed assessment top-level material changed")
        current_records = _without_active_residual_proposals(
            assessment.get("assessments"), active_ids, snapshot=False
        )
        snapshot_records = _without_active_residual_proposals(
            snapshot.get("assessments"), active_ids, snapshot=True
        )
        if canonical_digest(current_records) != canonical_digest(snapshot_records):
            problems.append("refreshed assessment changed outside residual proposals")

    unexpected_top_level = set(assessment) - {
        "version",
        "migration",
        "assessments",
        "confirmation",
    }
    if unexpected_top_level:
        problems.append("refreshed assessment has unexpected top-level fields")
    if assessment.get("version") not in (None, RISK_SCHEMA_VERSION):
        problems.append("assessment version must be 0.2.0")
    problems.extend(validate_assessment(threats, dict(assessment), policy))
    return problems


def check_residual_review(paths: Mapping | object) -> list[str]:
    """Validate confirmed or externally bound state for residual preview.

    A refresh-bound assessment is deliberately unconfirmed while the reviewer
    adds residual proposals.  Only those proposal fields may differ from the
    exact digest-bound refresh snapshot; inherent risk, treatment, state, and
    every material input remain externally bound.
    """

    project_root, assessment_path = _project_document_path(paths, "assessment")
    trusted = _read_trusted_confirmation(project_root, "assessment")
    if not isinstance(trusted, Mapping) or trusted.get("status") != "refresh_bound":
        return check_assessment(paths)

    _unused_root, policy_path = _project_document_path(paths, "policy")
    policy = _load_mapping(policy_path, "risk policy")
    threats, requirements, evidence = _refresh_documents(paths)
    _unused_root, _state_path, risk_state = _load_risk_state(paths)
    assessment = _load_mapping(assessment_path, "assessment document")
    problems = _refresh_binding_problems(
        trusted,
        project_root,
        policy,
        threats,
        requirements,
        evidence,
        risk_state,
    )
    problems.extend(
        _bound_residual_assessment_problems(
            trusted, risk_state, assessment, threats, policy
        )
    )
    return list(dict.fromkeys(problems))


def _selected_evidence_refs(proposed: Mapping, threat_id: str) -> list[str]:
    """Return the canonical evidence selection from both proposed axes."""

    selected: set[str] = set()
    for axis in ("likelihood", "impact"):
        axis_data = proposed.get(axis)
        if not isinstance(axis_data, Mapping):
            raise RiskValidationError(
                f"{threat_id} residual {axis} proposal is required"
            )
        refs = axis_data.get("evidence_refs", [])
        if not isinstance(refs, Sequence) or isinstance(refs, (str, bytes)):
            raise RiskValidationError(
                f"{threat_id} residual {axis} evidence_refs must be a list"
            )
        if any(not _nonempty_text(reference) for reference in refs):
            raise RiskValidationError(
                f"{threat_id} residual {axis} evidence_refs are invalid"
            )
        selected.update(refs)
    return sorted(selected)


def _validate_selected_evidence(
    threat_id: str,
    selected: Sequence[str],
    current: Mapping[str, Mapping],
    requirements: dict,
) -> None:
    """Require every selected artifact to be current and linked to the threat."""

    requirement_records = _records_by_identity(
        requirements, "requirements", "id", "requirements"
    )
    for reference in selected:
        evidence = current.get(reference)
        if evidence is None:
            raise RiskValidationError(
                f"{threat_id} residual confirmation requires valid implementation "
                f"evidence that is current and passing: {reference}"
            )
        requirement_id = evidence.get("requirement_id")
        requirement = requirement_records.get(requirement_id)
        if threat_id not in _risk_refs_for_requirement(requirement):
            raise RiskValidationError(
                f"{threat_id} evidence {reference} is not linked through its requirement"
            )


def stamp_residual_assessment(
    paths: Mapping | object,
    confirmed_by: str,
    authority: str,
    *,
    confirmed_at: str | None = None,
    today: date | None = None,
) -> dict:
    """Calculate and atomically confirm refresh-bound residual proposals.

    `today` decides which evidence is still current, and that decision reaches
    a residual *rating* — so it reaches `assessment_digest` (plan §11.2 N40).
    One date is read once here and threaded through both the evidence
    validation and the residual calculation: reading the clock twice could
    straddle midnight and score a run against two different days.
    """

    today = today or date.today()

    policy_problems = check_policy(paths)
    if policy_problems:
        raise RiskValidationError("; ".join(policy_problems))
    project_root, assessment_path = _project_document_path(paths, "assessment")
    _unused_root, policy_path = _project_document_path(paths, "policy")
    _unused_root, threats_path = _project_document_path(paths, "threats")
    state_root, confirmation_path = _state_target(project_root, "assessment")
    _unused_root, risk_state_path, risk_state = _load_risk_state(paths)
    trusted = _read_trusted_confirmation(project_root, "assessment")
    if not isinstance(trusted, Mapping) or trusted.get("status") != "refresh_bound":
        raise RiskValidationError(
            "residual confirmation requires externally bound refreshed state"
        )
    review_problems = check_residual_review(paths)
    if review_problems:
        raise RiskValidationError("; ".join(review_problems))

    policy = _load_mapping(policy_path, "risk policy")
    threats = _load_mapping(threats_path, "threat document")
    requirements, evidence, evidence_problems = _validated_evidence_documents(
        paths, today
    )
    if evidence_problems:
        raise RiskValidationError("; ".join(evidence_problems))
    current_evidence = _current_passing_evidence(evidence, requirements, today)
    assessment = _load_mapping(assessment_path, "assessment document")
    exact_problems = _refresh_binding_problems(
        trusted,
        project_root,
        policy,
        threats,
        requirements,
        evidence,
        risk_state,
    )
    exact_problems.extend(
        _bound_residual_assessment_problems(
            trusted, risk_state, assessment, threats, policy
        )
    )
    if exact_problems:
        raise RiskValidationError("; ".join(dict.fromkeys(exact_problems)))
    result = _without_confirmation(assessment)
    records = result.get("assessments")
    if not isinstance(records, list):
        raise RiskValidationError("assessments must be a list")
    active_ids = {threat["id"] for threat in active_threats(threats)}
    confirmed_count = 0
    for record in records:
        if not isinstance(record, dict) or record.get("threat_id") not in active_ids:
            continue
        threat_id = record["threat_id"]
        if record.get("status") != "CONFIRMED":
            raise RiskValidationError(
                f"{threat_id} inherent risk must be confirmed before residual confirmation"
            )
        residual = record.get("residual")
        if not isinstance(residual, Mapping) or residual.get("proposed") is None:
            continue
        proposed = residual["proposed"]
        if not isinstance(proposed, Mapping):
            raise RiskValidationError(
                f"{threat_id} residual proposal must be a mapping"
            )
        try:
            calculated = calculate_residual(
                record.get("calculated"),
                evidence,
                policy,
                dict(proposed),
                requirements=requirements,
                today=today,
            )
        except RiskValidationError as exc:
            if "residual reduction requires current passing evidence" in str(exc):
                raise RiskValidationError(
                    f"{threat_id} residual confirmation requires valid "
                    f"implementation evidence: {exc}"
                ) from exc
            raise
        if calculated.get("status") == "UNDETERMINED":
            raise RiskValidationError(
                f"{threat_id} residual confirmation requires valid implementation evidence"
            )
        selected = _selected_evidence_refs(proposed, threat_id)
        _validate_selected_evidence(
            threat_id, selected, current_evidence, requirements
        )
        confirmed = {
            "proposed": copy.deepcopy(dict(proposed)),
            "status": "CONFIRMED",
            "calculated": {
                field: calculated[field]
                for field in ("likelihood", "impact", "score", "rating")
            },
            "evidence_refs": selected,
        }
        if calculated.get("warnings"):
            confirmed["warnings"] = copy.deepcopy(calculated["warnings"])
        record["residual"] = confirmed
        confirmed_count += 1
    if confirmed_count == 0:
        raise RiskValidationError("no residual proposals are ready for confirmation")

    transition_at = confirmed_at or datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    next_state = append_snapshot(
        risk_state,
        _risk_snapshot(
            "residual_confirmed",
            threats,
            result,
            policy,
            requirements,
            evidence,
            transition_at,
        ),
    )
    result["confirmation"] = _confirmation_metadata(
        project_root,
        confirmed_by,
        authority,
        transition_at,
        policy_digest=policy_digest(policy),
        threat_digest=aggregate_threat_digest(threats),
        assessment_digest=assessment_digest(result),
        risk_state_digest=canonical_digest(next_state),
    )
    _write_text_transaction(
        [
            (
                assessment_path,
                project_root,
                yaml.safe_dump(result, allow_unicode=True, sort_keys=False),
                False,
            ),
            (
                risk_state_path,
                project_root,
                yaml.safe_dump(next_state, allow_unicode=True, sort_keys=False),
                False,
            ),
            (
                confirmation_path,
                state_root,
                yaml.safe_dump(
                    result["confirmation"], allow_unicode=True, sort_keys=False
                ),
                True,
            ),
        ]
    )
    return result


def refresh_persisted_assessment(paths: Mapping | object) -> tuple[dict, list[str]]:
    """Apply selective refresh transitions to canonical project state."""

    project_root, assessment_path = _project_document_path(paths, "assessment")
    _unused_root, policy_path = _project_document_path(paths, "policy")
    _unused_root, risk_state_path, risk_state = _load_risk_state(paths)
    threats, requirements, evidence = _refresh_documents(paths)
    policy = _load_mapping(policy_path, "risk policy")
    assessment = _load_mapping(assessment_path, "assessment document")
    trusted = _read_trusted_confirmation(project_root, "assessment")
    state_root, trusted_path = _state_target(project_root, "assessment")
    repository_confirmation = assessment.get("confirmation")
    if isinstance(trusted, Mapping) and trusted.get("status") == "refresh_bound":
        if repository_confirmation is not None:
            raise RiskValidationError(
                "refreshed assessment must remain unconfirmed before review"
            )
        binding_problems = _refresh_binding_problems(
            trusted,
            project_root,
            policy,
            threats,
            requirements,
            evidence,
            risk_state,
            require_matching_inputs=False,
        )
        if binding_problems:
            raise RiskValidationError("; ".join(binding_problems))
    elif repository_confirmation is not None or trusted is not None:
        problems = _base_confirmation_problems(
            "assessment", repository_confirmation, trusted, project_root
        )
        if problems:
            raise RiskValidationError("; ".join(problems))
        if trusted.get("risk_state_digest") != canonical_digest(risk_state):
            raise RiskValidationError("risk state digest changed")

    baseline = risk_state.get("refresh_baseline")
    if not isinstance(baseline, Mapping):
        raise RiskValidationError("risk refresh baseline is missing")
    refreshed = refresh_assessment(
        baseline.get("threats"),
        threats,
        assessment,
        previous_requirements=baseline.get("requirements"),
        current_requirements=requirements,
        previous_evidence=baseline.get("evidence"),
        current_evidence=evidence,
        policy_changed=baseline.get("policy_digest") != policy_digest(policy),
    )
    next_baseline = _refresh_baseline(threats, requirements, evidence, policy)
    inputs_changed = canonical_digest(next_baseline) != canonical_digest(baseline)
    if inputs_changed:
        refreshed.pop("confirmation", None)
    assessment_changed = canonical_digest(refreshed) != canonical_digest(assessment)
    if not assessment_changed and not inputs_changed:
        return assessment, []

    messages: list[str] = []
    old_by_id = {
        row.get("threat_id"): row
        for row in assessment.get("assessments", [])
        if isinstance(row, Mapping)
    }
    for row in refreshed.get("assessments", []):
        if not isinstance(row, Mapping):
            continue
        threat_id = row.get("threat_id")
        old = old_by_id.get(threat_id)
        if not isinstance(old, Mapping):
            messages.append(f"{threat_id} inherent risk is PROPOSED")
            continue
        if old.get("status") != row.get("status"):
            messages.append(f"{threat_id} inherent risk is {row.get('status')}")
        old_residual = old.get("residual")
        new_residual = row.get("residual")
        if (
            isinstance(old_residual, Mapping)
            and isinstance(new_residual, Mapping)
            and old_residual.get("status") != new_residual.get("status")
        ):
            messages.append(
                f"{threat_id} residual risk is {new_residual.get('status')}"
            )

    transition_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    next_state = copy.deepcopy(risk_state)
    next_state["refresh_baseline"] = next_baseline
    next_state = append_snapshot(
        next_state,
        _risk_snapshot(
            "refreshed",
            threats,
            refreshed,
            policy,
            requirements,
            evidence,
            transition_at,
        ),
    )
    refresh_binding = _refresh_binding_metadata(
        project_root,
        trusted,
        policy,
        threats,
        requirements,
        evidence,
        refreshed,
        next_state,
        transition_at,
    )
    _write_text_transaction(
        [
            (
                assessment_path,
                project_root,
                yaml.safe_dump(refreshed, allow_unicode=True, sort_keys=False),
                False,
            ),
            (
                risk_state_path,
                project_root,
                yaml.safe_dump(next_state, allow_unicode=True, sort_keys=False),
                False,
            ),
            (
                trusted_path,
                state_root,
                yaml.safe_dump(
                    refresh_binding, allow_unicode=True, sort_keys=False
                ),
                True,
            ),
        ]
    )
    return refreshed, messages


def _add_path_argument(parser: argparse.ArgumentParser, name: str) -> None:
    parser.add_argument(name, type=Path, required=True, action=_StoreOnce)


def _add_confirmed_at_argument(parser: argparse.ArgumentParser) -> None:
    """Let a caller pin the confirmation clock.

    `stamp_policy`, `stamp_assessment` and `stamp_residual_assessment` all
    accept `confirmed_at` already, but nothing exposed it, so every CLI run
    stamped `datetime.now` into the confirmation and the state snapshot. That
    made `snapshot_digest` and `confirmation.risk_state_digest` differ between
    two otherwise identical runs — the same entrypoint disagreeing with itself
    — and put plan N39 ("two runs with `today` and `confirmed_at` pinned
    produce an identical digest") out of reach from a command line.

    Optional, unlike every path flag: omitting it means "stamp now", which is
    the ordinary case and must not become a required argument on a shipped
    command.
    """

    parser.add_argument("--confirmed-at", action=_StoreOnce)


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
    _add_confirmed_at_argument(policy_confirm)

    for name in ("confirm", "check"):
        command = commands.add_parser(name, allow_abbrev=False)
        for path_name in (
            "--project-root",
            "--policy",
            "--threats",
            "--assessment",
            "--requirements",
            "--evidence",
            "--state",
        ):
            _add_path_argument(command, path_name)
        if name == "confirm":
            command.add_argument("--by", required=True, action=_StoreOnce)
            command.add_argument(
                "--authority",
                choices=sorted(AUTHORITIES),
                required=True,
                action=_StoreOnce,
            )
            _add_confirmed_at_argument(command)

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
        "--state",
    ):
        _add_path_argument(residual_command, name)

    residual_confirm = commands.add_parser(
        "residual-confirm", allow_abbrev=False
    )
    for name in (
        "--project-root",
        "--policy",
        "--threats",
        "--assessment",
        "--requirements",
        "--evidence",
        "--state",
    ):
        _add_path_argument(residual_confirm, name)
    residual_confirm.add_argument("--by", required=True, action=_StoreOnce)
    residual_confirm.add_argument(
        "--authority",
        choices=sorted(AUTHORITIES),
        required=True,
        action=_StoreOnce,
    )
    _add_confirmed_at_argument(residual_confirm)

    migrate_command = commands.add_parser("migrate", allow_abbrev=False)
    for name in (
        "--project-root",
        "--threats",
        "--requirements",
        "--policy",
        "--assessment",
        "--state",
    ):
        _add_path_argument(migrate_command, name)

    refresh_command = commands.add_parser("refresh", allow_abbrev=False)
    for name in (
        "--project-root",
        "--policy",
        "--threats",
        "--assessment",
        "--requirements",
        "--evidence",
        "--state",
    ):
        _add_path_argument(refresh_command, name)

    # The design-review pair (plan §3, F21). Two subcommands rather than one
    # with a --confirm flag: no single run may both interview and emit an
    # authoritative artifact, and a flag is too easy to add to a script that
    # was only ever meant to preview.
    #
    # None of these carry a default. `_StoreOnce` refuses a second value by
    # testing the namespace for `None`, so a default would make the first use
    # of the flag look like a repeat. Defaults belong to the layer that runs
    # the review, not to the grammar that reads it.
    design_review = commands.add_parser("design-review", allow_abbrev=False)
    _add_path_argument(design_review, "--project-root")
    _add_path_argument(design_review, "--output")
    design_review.add_argument(
        "--mode", choices=sorted(REVIEW_MODES), action=_StoreOnce
    )
    design_review.add_argument(
        "--risk-appetite", choices=sorted(RISK_APPETITES), action=_StoreOnce
    )
    design_review.add_argument("--scope", action=_StoreOnce)
    # Pinnable for the same reason the confirm subcommands are: the report
    # carries a timestamp and is digested, so two runs of an unchanged store
    # must be able to agree (plan N39).
    _add_confirmed_at_argument(design_review)

    design_review_confirm = commands.add_parser(
        "design-review-confirm", allow_abbrev=False
    )
    _add_path_argument(design_review_confirm, "--project-root")
    _add_path_argument(design_review_confirm, "--output")
    # Appetite and scope, but not --mode: confirmation records a review that
    # already happened, and the two must describe the same run. Interview depth
    # is spent by then.
    design_review_confirm.add_argument(
        "--risk-appetite", choices=sorted(RISK_APPETITES), action=_StoreOnce
    )
    design_review_confirm.add_argument("--scope", action=_StoreOnce)
    _add_confirmed_at_argument(design_review_confirm)
    design_review_confirm.add_argument("--by", required=True, action=_StoreOnce)
    design_review_confirm.add_argument(
        "--authority", choices=sorted(AUTHORITIES), required=True, action=_StoreOnce
    )
    return parser


def write_migration(paths: Mapping | object) -> dict:
    """Write legacy migration scaffolding only to validated internal paths."""

    project_root, threats_path = _project_document_path(paths, "threats")
    _unused_root, requirements_path = _project_document_path(paths, "requirements")
    _unused_root, policy_path = _project_document_path(paths, "policy")
    _unused_root, assessment_path = _project_document_path(paths, "assessment")
    _unused_root, state_path = _project_document_path(paths, "state")

    canonical_outputs = {
        "policy": project_root / ".security-requirements" / "risk-policy.yaml",
        "assessment": project_root
        / ".security-requirements"
        / "risk-assessment.yaml",
        "state": project_root / ".security-requirements" / "risk-state.yaml",
    }
    for name, actual in (
        ("policy", policy_path),
        ("assessment", assessment_path),
        ("state", state_path),
    ):
        expected = safe_path(canonical_outputs[name], project_root=project_root)
        if actual != expected:
            raise RiskValidationError(
                f"{name} is not the canonical migration path: {expected}"
            )

    outputs = [policy_path, assessment_path, state_path]
    preflight_output_paths(outputs, project_root=project_root)
    existing = [path for path in outputs if path.exists()]
    if existing:
        raise RiskValidationError(
            "migration output already exists: "
            + ", ".join(str(path) for path in existing)
        )

    threats = _load_mapping(threats_path, "threat document")
    requirements = _load_mapping(requirements_path, "requirements document")
    result = migrate(threats, requirements)
    result["state"] = append_snapshot(
        result["state"],
        _risk_snapshot(
            "migrated",
            result["threats"],
            result["assessment"],
            result["policy"],
            requirements,
            {"evidence": []},
            datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        ),
    )
    _write_text_transaction(
        [
            (
                path,
                project_root,
                yaml.safe_dump(document, allow_unicode=True, sort_keys=False),
                True,
            )
            for path, document in (
                (policy_path, result["policy"]),
                (assessment_path, result["assessment"]),
                (state_path, result["state"]),
            )
        ],
        require_absent=True,
    )
    return result


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
        current = _current_passing_evidence(evidence, requirements, evaluation_date)
        try:
            result = calculate_residual(
                inherent,
                evidence,
                policy,
                proposed,
                # No-current-evidence previews still calculate unchanged or
                # increased risk, while calculate_residual returns
                # UNDETERMINED for any attempted reduction.
                requirements=requirements if current else None,
                today=evaluation_date,
            )
        except RiskValidationError as exc:
            problems.append(f"{threat_id} {exc}")
            continue
        results.append((threat_id, result))
    return results, problems


#: The store documents a design review reads, by the canonical names
#: `publish.py:_risk_paths` already writes. The design-review grammar declares
#: no document flags on purpose — an operator naming seven paths by hand is
#: seven chances to review one project's threats against another's assessment.
DESIGN_REVIEW_DOCUMENTS = {
    "threats": "threats.yaml",
    "assessment": "risk-assessment.yaml",
    "requirements": "requirements.yaml",
    "evidence": "risk-evidence.yaml",
    "architecture": "architecture.yaml",
    "attack_paths": "attack-paths.yaml",
}


def _load_design_review_documents(project_root: Path, appetite: str) -> dict:
    """Read the store. A document that is absent is `None`, not an error here.

    Absence is reported by the validators that know what each document is for,
    with a message naming it. Raising on the first missing file would report
    one gap at a time and make an empty project take six runs to diagnose.
    """

    store = project_root / ".security-requirements"
    documents: dict = {"policy": appetite_policy(appetite)}
    for name, filename in DESIGN_REVIEW_DOCUMENTS.items():
        path = safe_path(store / filename, project_root=project_root)
        documents[name] = (
            _load_mapping(path, f"{name} document") if path.is_file() else None
        )
    return documents


def _run_design_review(args: argparse.Namespace) -> int:
    """Preview or confirm a design review (plan §3, §4.1, N26-N29)."""

    import sdr_artifacts
    import sdr_entry
    import sdr_report
    import sdr_scope

    project_root = safe_path(args.project_root, project_root=args.project_root)
    output_root = safe_path(args.output, project_root=args.output)
    appetite = args.risk_appetite or "standard"
    mode = getattr(args, "mode", None) or sdr_entry.DEFAULT_MODE
    scope = getattr(args, "scope", None)
    confirming = args.command == "design-review-confirm"

    if not sdr_entry.store_present(project_root):
        # The wrapper invokes intake when there is no store, but only a caller
        # that can run the interview may supply it. From a bare CLI there is
        # nobody to answer the questions, so this reports rather than pretends.
        print(
            f"ERROR: {project_root} holds no model under .security-requirements/; "
            "run /sec-req-init and /sec-req-build first",
            file=sys.stderr,
        )
        return 1

    documents = _load_design_review_documents(project_root, appetite)
    entry = sdr_entry.design_review(project_root, mode=mode)
    scope_record = sdr_scope.resolve_scope(documents.get("architecture"), scope)

    stamped_at = getattr(args, "confirmed_at", None) or (
        datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    )
    # Derived from the stamp rather than read separately: a run must be scored
    # as of the moment it records, and two reads could straddle midnight.
    today = _snapshot_assessed_date({"assessed_at": stamped_at}) or date.today()
    problems = sdr_report.report_problems(
        documents, scope=scope, policy=documents["policy"], today=today
    )

    # Evidence is optional and validated only when it exists. It is produced by
    # a later workflow step, so a team may legitimately have none yet, and
    # treating its absence as a defect would fail every design review run
    # before the first evidence is written.
    #
    # Kept as its own list because `output_allowed` distinguishes the two:
    # stale evidence still renders a preview — the reader learns the evidence
    # expired, which is the answer — while a binding or integrity error
    # suppresses everything. Folding these into `problems` alone would make an
    # expired record indistinguishable from a corrupted document.
    evidence_problems: list[str] = []
    if documents.get("evidence") is not None:
        evidence_problems = validate_evidence(
            documents["evidence"], documents.get("requirements"), today
        )
        problems.extend(
            problem for problem in evidence_problems if problem not in problems
        )

    confirmation = _read_trusted_confirmation(project_root, "assessment")
    if confirming:
        # N27/N28. Presence at the plugin-owned path is not proof of a
        # binding. Testing `is not None` accepted two things it must not: a
        # confirmation whose digests no longer match the documents — the exact
        # condition confirmation exists to detect — and a file planted at that
        # path. `check_assessment` is what every other confirm path in this
        # module runs, and it verifies all four digests against disk.
        store = project_root / ".security-requirements"
        confirmation_problems = (
            ["design-review-confirm requires a trusted confirmation; none is "
             "bound for this project"]
            if confirmation is None
            else check_assessment(
                {
                    "project_root": project_root,
                    "assessment": store / "risk-assessment.yaml",
                    "policy": store / "risk-policy.yaml",
                    "threats": store / "threats.yaml",
                    "requirements": store / "requirements.yaml",
                    "evidence": store / "risk-evidence.yaml",
                    "state": store / "risk-state.yaml",
                }
            )
        )
        if confirmation_problems:
            for problem in confirmation_problems:
                print(f"ERROR: {problem}", file=sys.stderr)
            # A problem exit, not a usage error: the grammar was correct and
            # the operator can fix this by running the confirmation.
            return 1

    for problem in problems:
        print(f"ERROR: {problem}", file=sys.stderr)

    report = None
    if output_allowed(problems, evidence_problems):
        report = sdr_report.build_report(
            documents,
            entry=entry,
            scope_record=scope_record,
            confirmation=confirmation if confirming else None,
            risk_appetite=appetite,
            invocation={
                "plugin_version": None,
                "command": " ".join(sys.argv[1:]) or args.command,
                "timestamp": stamped_at,
            },
            today=today,
        )

    entries = sdr_artifacts.artifact_entries(
        report if report is not None else {},
        project_root=project_root,
        output_root=output_root,
        policy=documents["policy"],
        confirmed=confirming and confirmation is not None,
        problems=problems,
        evidence_problems=evidence_problems,
    )
    if entries:
        sdr_artifacts.write_artifacts(entries)
        for path, *_rest in entries:
            print(f"wrote {path}")
        # N21: a withheld summary is stated, never merely absent. The run names
        # each artifact it wrote, so saying nothing about the one it did not is
        # indistinguishable from having published it — and silence is the more
        # dangerous reading of the two. Naming the setting as well, because an
        # operator who wanted the summary has no other way to find out why they
        # did not get it.
        wrote_summary = any(
            Path(path).name == sdr_artifacts.PUBLISHABLE_ARTIFACT
            for path, *_rest in entries
        )
        if confirming and confirmation is not None and not wrote_summary:
            print(
                f"withheld {sdr_artifacts.PUBLISHABLE_ARTIFACT}: "
                "publish_risk_summary is not true under the "
                f"{appetite} appetite"
            )
    return 1 if problems else 0


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
                "state",
            )
            if hasattr(args, name)
        }
        if args.command == "migrate":
            migration = write_migration(paths)
            print(
                f"legacy_unassessed: {migration['active_legacy_threats']} "
                "active legacy threat(s); review and confirm risk proposals "
                "before publication."
            )
            print("Prior published documents were not modified.")
            return 0
        if args.command == "refresh":
            _assessment, messages = refresh_persisted_assessment(paths)
            if not messages:
                print("risk refresh: no assessment state transitions")
            else:
                for message in messages:
                    print(message)
            return 0
        if args.command == "policy-confirm":
            policy = stamp_policy(
                paths, args.by, args.authority, confirmed_at=args.confirmed_at
            )
            print(f"confirmed risk policy ({policy['confirmation']['policy_digest']})")
            return 0
        if args.command == "confirm":
            assessment = stamp_assessment(
                paths, args.by, args.authority, confirmed_at=args.confirmed_at
            )
            print(
                "confirmed risk assessment "
                f"({assessment['confirmation']['assessment_digest']})"
            )
            return 0
        if args.command == "residual-confirm":
            assessment = stamp_residual_assessment(
                paths, args.by, args.authority, confirmed_at=args.confirmed_at
            )
            print(
                "confirmed residual risk assessment "
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
            for problem in check_residual_review(paths):
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
            if output_allowed(problems, evidence_problems):
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
            for problem in problems:
                print(f"ERROR: {problem}", file=sys.stderr)
            if problems:
                return 1
            return 0

        if args.command in ("design-review", "design-review-confirm"):
            return _run_design_review(args)

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
