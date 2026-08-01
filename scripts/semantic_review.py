#!/usr/bin/env python3
"""Create and validate independent semantic-review records for requirements."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

import yaml


AI_REVIEWERS = {"ai", "assistant", "claude", "codex", "chatgpt", "model", "tool"}


def requirement_digest(requirement: dict) -> str:
    managed = requirement.get("managed") or {}
    canonical = json.dumps(
        managed, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def stamp(
    requirement: dict,
    reviewer: str,
    controls: list[str],
    clauses: list[str],
    verification_reviewed: bool,
    reviewed_at: str | None = None,
) -> dict:
    requirement.setdefault("human", {})["semantic_review"] = {
        "status": "approved",
        "reviewer": reviewer,
        "reviewed_at": reviewed_at
        or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "requirement_digest": requirement_digest(requirement),
        "control_links": sorted(set(controls)),
        "overlay_clauses": sorted(set(clauses)),
        "verification_reviewed": bool(verification_reviewed),
    }
    return requirement


def validate(requirement: dict) -> list[str]:
    review = (requirement.get("human") or {}).get("semantic_review")
    if not isinstance(review, dict):
        return ["no independent semantic review is recorded"]

    problems = []
    reviewer = str(review.get("reviewer") or "").strip()
    if not reviewer or reviewer.lower() in AI_REVIEWERS:
        problems.append("reviewer must identify an independent human")
    if review.get("status") != "approved":
        problems.append("semantic review status is not approved")
    if not review.get("reviewed_at"):
        problems.append("semantic review has no review timestamp")
    if review.get("requirement_digest") != requirement_digest(requirement):
        problems.append("semantic review is stale because the managed requirement changed")

    cited = set((requirement.get("managed") or {}).get("sources") or [])
    reviewed = set(review.get("control_links") or [])
    if cited and not (cited & reviewed):
        problems.append("semantic review does not validate any cited control link")
    if not review.get("verification_reviewed"):
        problems.append("semantic review did not validate the verification method")
    return problems


def clause_approved(requirement: dict, overlay_id: str, clause: str) -> bool:
    if validate(requirement):
        return False
    review = requirement["human"]["semantic_review"]
    return f"{overlay_id}:{clause}" in set(review.get("overlay_clauses") or [])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", required=True, type=Path, metavar="REQUIREMENTS")
    args = parser.parse_args(argv)
    document = yaml.safe_load(args.check.read_text(encoding="utf-8")) or {}
    failed = False
    for requirement in document.get("requirements") or []:
        status = str((requirement.get("human") or {}).get("status") or "").lower()
        if status in {"retired", "superseded"}:
            continue
        for problem in validate(requirement):
            failed = True
            print(f"ERROR {requirement.get('id', '<no id>')}: {problem}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
