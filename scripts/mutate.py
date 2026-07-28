#!/usr/bin/env python3
"""Find the tests that prove nothing.

A test can execute a line and assert nothing about it. Coverage counts the
first and says nothing about the second, so a suite at 98 per cent can still
carry rules no test distinguishes from their opposite. Five such tests were
found by review in a single session -- a modifier sweep asserting invariants
that held without the modifier, a provider sweep that only proved a name was
echoed back, a locale witness satisfied by one statement out of eight -- and
each was found by a person noticing, which is not a method.

This flips one operator at a time and runs the suite. A mutant that dies means
some test distinguishes the behaviour. A mutant that lives means none does, and
the line is carried by nothing.

Scope
-----
The scripts that run on every derivation and decide what the reader gets. The
rebuild scripts are deliberately outside it: they run offline, once, and refuse
to publish when their own count assertions fail, so the failure they can have is
caught where it happens.

Survivors
---------
Not every survivor is a defect. Some mutations are semantically equivalent, and
some sit in code whose behaviour genuinely does not matter -- an ordering in a
message, a label nobody reads. So a survivor is either killed by a new test or
recorded in ``evidence/mutation-exemptions.yaml`` with the reason it cannot be.

A recorded exemption whose mutant now dies is stale, and stale exemptions are
the same drift this repository spends its time finding. `tests/` asserts against
that, so the list cannot quietly outlive the code it excuses.

Safety
------
Runs in a copy of the tree. The first version of this edited the working tree in
place, was interrupted, and left a mutated source behind that read as four real
regressions.

Usage
-----
    python3 scripts/mutate.py                    # the gate scripts
    python3 scripts/mutate.py --file lint.py     # one of them
    python3 scripts/mutate.py --sample 40        # a sample, to gauge the shape
"""

from __future__ import annotations

import argparse
import ast
import json
import random
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
EXEMPTIONS = REPO_ROOT / "evidence" / "mutation-exemptions.yaml"

# Every derivation runs these, and what they decide is what the reader gets.
GATE_SCRIPTS = [
    "lint.py", "select_baseline.py", "apply_overlay.py",
    "merge.py", "classify_resp.py", "render.py",
]

# One operator for its opposite. Arithmetic and constant mutations are left out:
# they mostly produce crashes, which every test kills, and a mutant that dies
# everywhere teaches nothing.
SWAP = {
    "Eq": "NotEq", "NotEq": "Eq",
    "In": "NotIn", "NotIn": "In",
    "Is": "IsNot", "IsNot": "Is",
    "Lt": "GtE", "GtE": "Lt", "Gt": "LtE", "LtE": "Gt",
    "And": "Or", "Or": "And",
}
TEXT = {
    "Eq": "==", "NotEq": "!=", "In": " in ", "NotIn": " not in ",
    "Is": " is ", "IsNot": " is not ", "Lt": "<", "GtE": ">=",
    "Gt": ">", "LtE": "<=", "And": " and ", "Or": " or ",
}


def mutation_points(path: Path) -> list[tuple[int, str]]:
    """Every operator in the file that has an opposite worth trying."""
    points = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Compare):
            for operator in node.ops:
                name = type(operator).__name__
                if name in SWAP:
                    points.append((node.lineno, name))
        elif isinstance(node, ast.BoolOp):
            name = type(node.op).__name__
            if name in SWAP:
                points.append((node.lineno, name))
    return sorted(set(points))


def load_exemptions() -> dict[str, str]:
    """Recorded survivors, keyed file:line:mutation, valued by the reason."""
    if not EXEMPTIONS.exists():
        return {}
    doc = yaml.safe_load(EXEMPTIONS.read_text(encoding="utf-8")) or {}
    return {entry["mutant"]: entry.get("because", "")
            for entry in (doc.get("exempt") or [])}


def run(work: Path) -> bool:
    """The suite against the copied tree. True when it passes -- the mutant lived."""
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "-qx", "--no-header",
         "-p", "no:cacheprovider"],
        cwd=work, capture_output=True)
    return result.returncode == 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--file", action="append", dest="files",
                    help="a script under scripts/ (default: the gate scripts)")
    ap.add_argument("--sample", type=int, help="run a random sample rather than all")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--json", type=Path)
    args = ap.parse_args(argv)

    names = args.files or GATE_SCRIPTS
    points = [(name, point)
              for name in names
              for point in mutation_points(REPO_ROOT / "scripts" / name)]
    if args.sample:
        random.seed(args.seed)
        points = random.sample(points, min(args.sample, len(points)))

    exempt = load_exemptions()
    survivors, killed, unapplied = [], 0, []

    with tempfile.TemporaryDirectory(prefix="mutate-") as tmp:
        work = Path(tmp) / "tree"
        shutil.copytree(REPO_ROOT, work,
                        ignore=shutil.ignore_patterns(".git", "__pycache__",
                                                      ".pytest_cache", "htmlcov"))
        for index, (name, (line, operator)) in enumerate(points, 1):
            source = REPO_ROOT / "scripts" / name
            original = source.read_text(encoding="utf-8")
            lines = original.splitlines(keepends=True)
            before, after = TEXT[operator], TEXT[SWAP[operator]]
            if before not in lines[line - 1]:
                # The operator is on a continuation line, or spelled in a way the
                # text swap cannot reach. Reported rather than skipped silently:
                # a point nothing tried is not a point that passed.
                unapplied.append(f"{name}:{line} {operator}")
                continue

            mutant = f"{name}:{line}:{operator}->{SWAP[operator]}"
            lines[line - 1] = lines[line - 1].replace(before, after, 1)
            (work / "scripts" / name).write_text("".join(lines), encoding="utf-8")
            lived = run(work)
            (work / "scripts" / name).write_text(original, encoding="utf-8")

            if lived:
                survivors.append({"mutant": mutant,
                                  "source": lines[line - 1].strip()[:110],
                                  "exempt": mutant in exempt,
                                  "because": exempt.get(mutant, "")})
            else:
                killed += 1
            status = "SURVIVED" if lived else "killed"
            if lived and mutant in exempt:
                status = "survived (exempt)"
            print(f"  {index:>4}/{len(points)}  {mutant:<52} {status}", flush=True)

    unrecorded = [s for s in survivors if not s["exempt"]]
    print(f"\n  {killed} killed, {len(survivors)} survived "
          f"({len(unrecorded)} of them unrecorded), {len(unapplied)} not applied")
    for survivor in unrecorded:
        print(f"    ! {survivor['mutant']}\n        {survivor['source']}")
    if unapplied:
        print(f"\n  not applied (the swap could not reach the operator):")
        for point in unapplied[:10]:
            print(f"    - {point}")

    if args.json:
        args.json.write_text(json.dumps(
            {"killed": killed, "survivors": survivors, "unapplied": unapplied},
            indent=2) + "\n", encoding="utf-8")

    # A survivor nobody has decided about is the finding. An exempt one is a
    # decision already made, and a killed one is a test doing its job.
    return 1 if unrecorded else 0


if __name__ == "__main__":
    raise SystemExit(main())
