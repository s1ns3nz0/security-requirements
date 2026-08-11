#!/usr/bin/env python3
"""Score a generated requirement set against a golden case.

The third verification layer. Scripts get unit tests, cited identifiers get a
build gate, and the parts that depend on model judgement -- threat modeling and
requirement authoring -- get scored here.

Scoring is by topic, never by wording. Phrasing changes every run; demanding a
string match would measure paraphrase instead of derivation. The question asked
of each topic is only "was this subject addressed at all?"

Keyword hints are an approximation of that question. A miss is a prompt to look,
not proof of a regression -- and widening hints so a failing run passes is how a
suite stops measuring anything.

Usage
-----
    python3 "${SECURITY_REQUIREMENTS_ROOT}/scripts/eval_golden.py" golden/b2b-saas-aws requirements.yaml
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml


def haystack(req: dict) -> str:
    managed = req.get("managed") or {}
    parts = [
        managed.get("statement", ""),
        managed.get("rationale", ""),
        managed.get("team_part", "") or "",
        managed.get("csp_part", "") or "",
    ]
    verification = managed.get("verification") or {}
    parts += [str(verification.get("target", "")), str(verification.get("expect", ""))]
    return " ".join(parts).lower()


def matches(text: str, hints) -> bool:
    """Whether any hint appears in the requirement text.

    A scalar `match_any: "tenant"` iterated to characters, so a topic matched
    whenever the statement contained the letter "t". A scoring suite that
    reports coverage it does not have is worse than none.
    """
    if isinstance(hints, str):
        raise ValueError(
            f"match_any must be a list of hints; {hints!r} was given as a single "
            f"string, which would be matched character by character"
        )
    return any(str(hint).strip().lower() in text for hint in hints or [])


def check_expectation(expected: dict) -> list[str]:
    """Problems in the expectation file itself, before anything is scored.

    Two of these only bite on the failing path, which is the worst place for a
    crash: a topic with no `description` scores fine and raises KeyError the
    moment it is reported as missed, and so does a must_not_cover rule with no
    `why`. The suite worked while it passed and broke while it failed.

    The third is quieter. Recall is computed over the topics marked
    `must_cover`, so a file with none has recall 1.0 whatever the document says
    -- a golden case that cannot fail. This module's own docstring says
    widening hints until a failing run passes is how a suite stops measuring
    anything; having nothing required is the same end by a shorter road.
    """
    problems = []
    topics = expected.get("topics") or []
    for topic in topics:
        tid = topic.get("id", "<unnamed>")
        if not topic.get("id"):
            problems.append("a topic has no id")
        if not topic.get("description"):
            problems.append(f"topic {tid}: no description -- it is printed when the topic "
                            f"is missed, which is the only time anyone reads it")
        hints = topic.get("match_any")
        if hints is None:
            problems.append(f"topic {tid}: no match_any hints")
        elif isinstance(hints, str):
            problems.append(f"topic {tid}: match_any is a single string, which would be "
                            f"matched character by character")
        elif not hints:
            problems.append(f"topic {tid}: match_any is empty, so the topic can never be "
                            f"covered by anything")
    for rule in expected.get("must_not_cover") or []:
        rid = rule.get("id", "<unnamed>")
        if not rule.get("match_any"):
            problems.append(f"must_not_cover {rid}: no match_any hints")
        if not rule.get("why"):
            problems.append(f"must_not_cover {rid}: no `why` -- it is printed when the rule "
                            f"fires, which is the only time anyone reads it")
    if topics and not [t for t in topics if t.get("must_cover")]:
        problems.append("no topic is marked must_cover, so recall is 1.0 whatever the "
                        "document contains and this case cannot fail")
    return problems


def score(expected: dict, doc: dict) -> dict:
    reqs = [
        r for r in (doc.get("requirements") or [])
        if (r.get("human") or {}).get("status") not in ("retired", "superseded")
    ]
    texts = {r["id"]: haystack(r) for r in reqs}

    covered, missed = [], []
    for topic in expected.get("topics", []):
        if "match_any" not in topic:
            raise ValueError(f"topic {topic.get('id', '<unnamed>')!r} has no `match_any` hints")
        hits = [rid for rid, text in texts.items() if matches(text, topic["match_any"])]
        record = {**topic, "hits": hits}
        (covered if hits else missed).append(record)

    violations = []
    for rule in expected.get("must_not_cover", []) or []:
        hits = [rid for rid, text in texts.items() if matches(text, rule["match_any"])]
        if hits:
            violations.append({**rule, "hits": hits})

    required = [t for t in expected.get("topics", []) if t.get("must_cover")]
    required_covered = [t for t in covered if t.get("must_cover")]
    recall = len(required_covered) / len(required) if required else 1.0

    critical_missing = [t for t in missed if t.get("critical")]

    return {
        "total_requirements": len(reqs),
        "covered": covered,
        "missed": missed,
        "violations": violations,
        "recall": recall,
        "critical_missing": critical_missing,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("golden_dir", type=Path)
    ap.add_argument("requirements", type=Path)
    args = ap.parse_args()

    expected = yaml.safe_load((args.golden_dir / "expected-coverage.yaml").read_text(encoding="utf-8"))
    doc = yaml.safe_load(args.requirements.read_text(encoding="utf-8")) or {}
    problems = check_expectation(expected)
    if problems:
        print("The expectation file cannot be scored against:", file=sys.stderr)
        for problem in problems:
            print(f"  ! {problem}", file=sys.stderr)
        return 2

    result = score(expected, doc)

    scoring = expected.get("scoring", {})
    threshold = scoring.get("recall_threshold", 0.85)

    print(f"Golden case: {expected.get('profile')}")
    print(f"{result['total_requirements']} requirements produced\n")

    for topic in result["covered"]:
        mark = "*" if topic.get("critical") else " "
        print(f"  ok {mark} {topic['id']:<28} {', '.join(topic['hits'][:2])}")
    for topic in result["missed"]:
        mark = "*" if topic.get("critical") else " "
        level = "MISS" if topic.get("must_cover") else "miss"
        print(f"  {level} {mark} {topic['id']:<28} {topic['description']}")

    print(f"\n  recall {result['recall']:.0%} (threshold {threshold:.0%})")

    failed = False
    if result["violations"]:
        print("\nExcluded subjects appeared:")
        for rule in result["violations"]:
            print(f"  ! {rule['id']}: {', '.join(rule['hits'])}")
            print(f"      {rule['why'].strip()}")
        failed = True

    if result["critical_missing"] and scoring.get("critical_required", True):
        print("\nCritical topics missing:")
        for topic in result["critical_missing"]:
            print(f"  ! {topic['id']}")
            print(f"      {topic['why'].strip()}")
        print("\nThese are the topics a baseline-only run cannot reach. Missing them means"
              "\nthe threat model returned generic material.")
        failed = True

    if result["recall"] < threshold:
        print(f"\nRecall below threshold.")
        failed = True

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
