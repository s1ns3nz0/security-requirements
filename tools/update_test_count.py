#!/usr/bin/env python3
"""Write the README's test count from a live collection.

`test_the_test_count_on_the_front_page_is_the_test_count` checks that the
number on the front page is the number the suite actually collects. That check
is worth keeping — a count moving unexpectedly is a real signal — but the number
was maintained by hand, so every branch that added a test edited the same line
and every pair of such branches conflicted on it.

This makes the number an output rather than an input. Run it after adding or
removing tests:

    python3 tools/update_test_count.py          # rewrite the line
    python3 tools/update_test_count.py --check  # fail if stale, change nothing

`--check` is for CI and for a pre-commit hook: it reports staleness without
touching the tree.

Resolving a merge conflict on this line means running this script, not choosing
between two numbers. Neither side is likely to be right — each branch counts
only its own tests, while the merged tree collects both.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import subprocess
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent
README = REPO_ROOT / "README.md"

# The same shape the test greps for. Kept as one pattern so the writer and the
# checker cannot drift apart.
CLAIM = re.compile(r"(deterministic layer, )([\d,]+)( tests)")
COLLECTED = re.compile(r"(\d+) tests collected")


def collect_count() -> int:
    """How many tests the suite collects right now."""

    completed = subprocess.run(
        [sys.executable, "-m", "pytest", str(REPO_ROOT / "tests"), "-q", "--collect-only"],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    match = COLLECTED.search(completed.stdout)
    if not match:
        # Collection failing is a real problem and must not be reported as a
        # count of zero, which would then be written to the front page.
        sys.stderr.write(completed.stdout[-2000:] + completed.stderr[-2000:])
        raise SystemExit("could not read a collected test count from pytest")
    return int(match.group(1))


def claimed_count(readme: str) -> int | None:
    match = CLAIM.search(readme)
    return int(match.group(2).replace(",", "")) if match else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero if the README is stale; do not modify it",
    )
    args = parser.parse_args()

    readme = README.read_text(encoding="utf-8")
    if CLAIM.search(readme) is None:
        raise SystemExit("README does not carry a 'deterministic layer, N tests' claim")

    collected = collect_count()
    claimed = claimed_count(readme)
    if claimed == collected:
        print(f"README test count is current: {collected:,}")
        return 0

    if args.check:
        print(
            f"README claims {claimed:,} tests, the suite collects {collected:,}. "
            f"Run: python3 tools/update_test_count.py",
            file=sys.stderr,
        )
        return 1

    README.write_text(CLAIM.sub(rf"\g<1>{collected:,}\g<3>", readme, count=1), encoding="utf-8")
    print(f"README test count updated: {claimed:,} -> {collected:,}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
