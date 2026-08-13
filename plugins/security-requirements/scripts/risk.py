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
