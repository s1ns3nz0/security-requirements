#!/usr/bin/env python3
"""Persist and verify the human profile-confirmation gate."""

from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import sys

import yaml


def profile_digest(profile: dict) -> str:
    payload = copy.deepcopy(profile)
    payload.pop("confirmation", None)
    canonical = yaml.safe_dump(
        payload, allow_unicode=True, sort_keys=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def stamp(profile: dict, confirmed_by: str, confirmed_at: str | None = None) -> dict:
    profile["confirmation"] = {
        "status": "confirmed",
        "confirmed_by": confirmed_by,
        "confirmed_at": confirmed_at
        or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "profile_digest": profile_digest(profile),
    }
    return profile


def validate(profile: dict) -> list[str]:
    confirmation = profile.get("confirmation")
    if not isinstance(confirmation, dict):
        return ["profile has no persisted confirmation"]
    required = ("status", "confirmed_by", "confirmed_at", "profile_digest")
    missing = [key for key in required if not confirmation.get(key)]
    if missing:
        return ["profile confirmation is incomplete: " + ", ".join(missing)]
    if confirmation["status"] != "confirmed":
        return ["profile confirmation status is not confirmed"]
    if confirmation["profile_digest"] != profile_digest(profile):
        return ["profile changed after confirmation; run the confirmation gate again"]
    return []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", metavar="PROFILE", type=Path)
    action.add_argument("--stamp", metavar="PROFILE", type=Path)
    parser.add_argument("--by", default="user", help="identity recorded for --stamp")
    args = parser.parse_args(argv)
    path = args.check or args.stamp
    profile = yaml.safe_load(path.read_text(encoding="utf-8")) or {}

    if args.stamp:
        stamp(profile, args.by)
        path.write_text(
            yaml.safe_dump(profile, allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )
        print(f"confirmed {path} ({profile['confirmation']['profile_digest']})")
        return 0

    problems = validate(profile)
    for problem in problems:
        print(f"ERROR: {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
