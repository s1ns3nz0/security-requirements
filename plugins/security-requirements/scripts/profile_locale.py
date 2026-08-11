#!/usr/bin/env python3
"""Print the locale declared by a target project's security profile."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from safe_paths import UnsafePathError, safe_path  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", type=Path)
    args = parser.parse_args(argv)
    try:
        path = safe_path(args.profile)
        profile = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, UnsafePathError, yaml.YAMLError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    locale = profile.get("locale", "en")
    if not isinstance(locale, str) or not locale.strip():
        print("error: profile locale must be a non-empty string", file=sys.stderr)
        return 2
    print(locale.strip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
