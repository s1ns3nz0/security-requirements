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

from runtime_paths import plugin_data_root


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


def validate(profile: dict, trusted_confirmation: dict | None) -> list[str]:
    if not isinstance(trusted_confirmation, dict):
        return ["plugin-owned confirmation state is missing"]
    confirmation = profile.get("confirmation")
    if confirmation != trusted_confirmation:
        return ["repository confirmation does not match plugin-owned confirmation state"]
    confirmation = trusted_confirmation
    required = ("status", "confirmed_by", "confirmed_at", "profile_digest")
    missing = [key for key in required if not confirmation.get(key)]
    if missing:
        return ["profile confirmation is incomplete: " + ", ".join(missing)]
    if confirmation["status"] != "confirmed":
        return ["profile confirmation status is not confirmed"]
    if confirmation["profile_digest"] != profile_digest(profile):
        return ["profile changed after confirmation; run the confirmation gate again"]
    return []


def confirmation_state_path(profile_path: Path) -> Path:
    project_root = (
        profile_path.parent.parent
        if profile_path.parent.name == ".security-requirements"
        else profile_path.parent
    ).resolve()
    key = hashlib.sha256(str(project_root).encode("utf-8")).hexdigest()
    return plugin_data_root() / "confirmations" / f"{key}.yaml"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", metavar="PROFILE", type=Path)
    action.add_argument("--stamp", metavar="PROFILE", type=Path)
    parser.add_argument("--by", default="user", help="identity recorded for --stamp")
    args = parser.parse_args(argv)
    path = args.check or args.stamp
    profile = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    try:
        state_path = confirmation_state_path(path)
    except (RuntimeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if args.stamp:
        stamp(profile, args.by)
        path.write_text(
            yaml.safe_dump(profile, allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(
            yaml.safe_dump(profile["confirmation"], sort_keys=False),
            encoding="utf-8",
        )
        print(f"confirmed {path} ({profile['confirmation']['profile_digest']})")
        return 0

    trusted = (
        yaml.safe_load(state_path.read_text(encoding="utf-8"))
        if state_path.exists()
        else None
    )
    problems = validate(profile, trusted)
    for problem in problems:
        print(f"ERROR: {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
