#!/usr/bin/env python3
"""Cross-threat attack paths (plan F11).

A threat record carries one `attack_path` string: the route to that single
threat. This module holds the other kind — a path *across* threats, where each
step is a threat the attacker chains through. Two medium findings that compose
into a critical one are the case a per-threat register cannot express, and the
case a reviewer most needs to see.

Membership lives in a separate document. `attack-paths.yaml` is a new file,
which plan §5.4 permits; a new top-level key on an existing document is what it
forbids. Membership reaches a threat as `attack_path_ids`, deliberately outside
both `THREAT_DIGEST_FIELDS` and `INHERENT_REFRESH_FIELDS`: a field inside either
tuple invalidates every existing confirmation on its first run.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import risk as risk_mod  # noqa: E402


def _records(document: object) -> list[dict]:
    """Attack-path records, tolerating a missing or malformed document."""

    if not isinstance(document, Mapping):
        return []
    paths = document.get("attack_paths")
    if not isinstance(paths, Sequence) or isinstance(paths, (str, bytes)):
        return []
    return [record for record in paths if isinstance(record, Mapping)]


def _steps(record: Mapping) -> list[str]:
    steps = record.get("steps")
    if not isinstance(steps, Sequence) or isinstance(steps, (str, bytes)):
        return []
    return [step for step in steps if isinstance(step, str) and step]


def validate_attack_paths(document: object, threats_doc: object) -> list[str]:
    """Return problems with the path document, in document order.

    House convention (plan §10.1): `validate_*` returns `list[str]` and never
    raises. Every offending step is reported, not the first — a document with
    three bad steps should take one round of review, not three.
    """

    problems: list[str] = []
    if document is not None and not isinstance(document, Mapping):
        return ["attack path document must be a mapping"]

    known: dict[str, dict] = {}
    if isinstance(threats_doc, Mapping):
        declared = threats_doc.get("threats")
        if isinstance(declared, Sequence) and not isinstance(declared, (str, bytes)):
            for record in declared:
                if isinstance(record, Mapping) and isinstance(record.get("id"), str):
                    known[record["id"]] = record
    try:
        active = {record["id"] for record in risk_mod.active_threats(threats_doc)}
    except (risk_mod.RiskValidationError, TypeError):
        # A threat document that will not load is reported by its own validator.
        # Reporting it a second time here would double every problem.
        active = set(known)

    seen_ids: set[str] = set()
    for record in _records(document):
        path_id = record.get("id")
        if not isinstance(path_id, str) or not path_id:
            problems.append("attack path id is required")
            continue
        if path_id in seen_ids:
            problems.append(f"duplicate attack path id: {path_id}")
            continue
        seen_ids.add(path_id)
        if not risk_mod._nonempty_text(record.get("title")):
            problems.append(f"{path_id} title is required")
        steps = _steps(record)
        if not steps:
            problems.append(f"{path_id} must name at least one step")
        for threat_id in steps:
            # Both ids in every message. "invalid path" names neither the path
            # to open nor the step to fix.
            if threat_id not in known:
                problems.append(
                    f"{path_id} step {threat_id} names an unknown threat"
                )
            elif threat_id not in active:
                status = risk_mod._lifecycle_status(known[threat_id])
                problems.append(
                    f"{path_id} step {threat_id} names a {status} threat"
                )
    return problems


class _PathLinks(dict):
    """A links mapping that reads `[]` for a threat in no path.

    A missing key would make every caller guess between "participates in no
    path" and "unknown threat". `__missing__` rather than `defaultdict` so a
    probe does not insert a phantom key that then appears in iteration.
    """

    def __missing__(self, key: str) -> list[str]:
        return []


def link_attack_paths(document: object) -> dict[str, list[str]]:
    """Map every threat named by a path to the sorted path ids it appears in.

    Sorted so the output is deterministic: no set iteration reaches a rendered
    artifact (plan §4.3).
    """

    links: dict[str, set[str]] = {}
    for record in _records(document):
        path_id = record.get("id")
        if not isinstance(path_id, str) or not path_id:
            continue
        for threat_id in _steps(record):
            links.setdefault(threat_id, set()).add(path_id)
    return _PathLinks(
        (threat_id, sorted(ids)) for threat_id, ids in links.items()
    )


def attack_path_ids(document: object, threat_id: str) -> list[str]:
    """Path membership for one threat: `[]` when it participates in none.

    An empty list rather than a missing key, so a caller reads the same shape
    for every threat and cannot mistake "in no path" for "not modelled".
    """

    return link_attack_paths(document).get(threat_id, [])


def combined_rating(
    path_id: str, document: object, assessment: object, policy: dict
) -> str:
    """The rating of a whole path: at least its highest participating rating.

    Chaining threats cannot make the result safer than its worst step, so this
    is a floor rather than an average. `RATINGS` is ordered most-severe-first,
    so the minimum index is the highest rating.
    """

    steps = []
    for record in _records(document):
        if record.get("id") == path_id:
            steps = _steps(record)
            break

    ratings: list[str] = []
    if isinstance(assessment, Mapping):
        records = assessment.get("assessments")
        if isinstance(records, Sequence) and not isinstance(records, (str, bytes)):
            for record in records:
                if not isinstance(record, Mapping):
                    continue
                if record.get("threat_id") not in steps:
                    continue
                calculated = record.get("calculated")
                if isinstance(calculated, Mapping):
                    rating = calculated.get("rating")
                    if rating in risk_mod.RATINGS:
                        ratings.append(rating)

    if not ratings:
        # Nothing scored yet. The engine's own word for that, rather than a
        # cheerful default that reads as "assessed and found low".
        return risk_mod.RATINGS[-1]
    return min(ratings, key=risk_mod.RATINGS.index)
