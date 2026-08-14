#!/usr/bin/env python3
"""Rebuild the HIPAA Security Rule clause list from the authoritative source.

Unlike the ISMS-P overlay, whose criteria came from a third-party structuring
because the official endpoints did not respond, this one is derived from the
regulation itself: 45 CFR Part 164, fetched from the eCFR API. It is a work of
the United States Government and is in the public domain, so the clause text is
bundled as published.

That the source is reachable is the point. Anyone can re-run this and diff the
result rather than trusting a snapshot.

Usage
-----
    python3 -I "<absolute plugin root>/scripts/rebuild_overlay_hipaa.py"
    python3 -I "<absolute plugin root>/scripts/rebuild_overlay_hipaa.py" --offline --source path/to/title-45.xml
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = REPO_ROOT / "overlays" / "hipaa-security-rule"
ECFR = ("https://www.ecfr.gov/api/versioner/v1/full/{date}/title-45.xml?part=164")

# Subpart C, the Security Standards for the Protection of Electronic Protected
# Health Information. The privacy standards elsewhere in Part 164 are a separate
# regime and are not covered here.
SECTIONS = {
    "164.308": "Administrative safeguards",
    "164.310": "Physical safeguards",
    "164.312": "Technical safeguards",
    "164.314": "Organizational requirements",
    "164.316": "Policies and procedures and documentation requirements",
}

# Published shape of the Security Rule: nine administrative standards, four
# physical, five technical. Asserted rather than assumed, so that a change in
# the regulation or a regression in this parser fails loudly instead of
# producing a short clause list nobody counts.
EXPECTED_STANDARDS = {"164.308": 9, "164.310": 4, "164.312": 5, "164.314": 2, "164.316": 2}

# Every standard announces itself with "Standard:" except this one, which the
# regulation writes as a plain titled paragraph. An explicit exception is
# preferable to a heuristic that would guess at the others.
STANDARD_WITHOUT_LABEL = {"164.308(b)(1)"}

LEAD = re.compile(r"^((?:\([a-zA-Z0-9ivx]+\))+)\s*(.*)$", re.S)
SPEC = re.compile(
    r"^(?:Implementation specifications?:\s*)?(?:Standard:\s*)?(.+?)\s*\((Required|Addressable)\)\.\s*(.*)$",
    re.S,
)
STD = re.compile(r"^Standard:\s*(.+?)\.\s*(.*)$", re.S)
TITLED = re.compile(r"^(.+?)\.\s+(.*)$", re.S)
# 164.314 attaches the designation to a group heading and lists the individual
# specifications beneath it, joined by an em dash rather than a full stop.
GROUP = re.compile(r"^Implementation specifications?\s*\((Required|Addressable)\)\s*[—-]?\s*(.*)$", re.S)


def level_of(mark: str, path: list[str]) -> int:
    """CFR paragraph levels alternate (a) (1) (i) (A).

    ``i``, ``v``, and ``x`` are both letters and numerals; the depth reached so
    far disambiguates them.
    """
    if mark.isdigit():
        return 1
    if mark.isupper():
        return 3
    if re.fullmatch(r"[ivx]+", mark) and len(path) >= 2:
        return 2
    return 0


def extract(root: ET.Element) -> tuple[list[dict], int]:
    records, designations_seen = [], 0

    for sec_id, sec_name in SECTIONS.items():
        matches = [d for d in root.iter("DIV8") if d.get("N") == sec_id]
        if not matches:
            raise SystemExit(f"section {sec_id} not present in the source")
        path, inherited = [], None

        for el in matches[0].findall("P"):
            text = " ".join("".join(el.itertext()).split())
            if re.search(r"\((Required|Addressable)\)", text):
                designations_seen += 1
            lead = LEAD.match(text)
            if not lead:
                continue
            marks = re.findall(r"\(([a-zA-Z0-9ivx]+)\)", lead.group(1))
            body = lead.group(2)
            path = path[: level_of(marks[0], path)] + marks
            cite = sec_id + "".join(f"({p})" for p in path)

            def record(kind, title, designation, statement, source=None):
                records.append({
                    "clause": cite if kind != "inline_group" else cite,
                    "section": sec_id, "section_title": sec_name, "kind": kind,
                    "title": title.strip().rstrip("."), "designation": designation,
                    "designation_source": source, "statement": statement.strip(),
                })

            group = GROUP.match(body)
            if group:
                inherited = (group.group(1), len(path))
                rest = group.group(2).strip()
                inline = re.match(r"^\(([a-zA-Z0-9ivx]+)\)\s*(.+?)\.\s*(.*)$", rest, re.S)
                if inline:
                    # Descend into the captured specification. Without this the
                    # contract terms listed beneath it -- (A), (B), (C) -- sit at
                    # the same depth as a sibling specification and get recorded
                    # as though they were ones.
                    path = path + [inline.group(1)]
                    records.append({
                        "clause": sec_id + "".join(f"({p})" for p in path), "section": sec_id,
                        "section_title": sec_name, "kind": "implementation_specification",
                        "title": inline.group(2).strip(), "designation": group.group(1),
                        "designation_source": "group heading",
                        "statement": inline.group(3).strip()})
                continue

            spec, std = SPEC.match(body), STD.match(body)
            if spec and re.search(r"\((Required|Addressable)\)", body):
                record("implementation_specification", spec.group(1), spec.group(2),
                       spec.group(3), "inline")
            elif std:
                record("standard", std.group(1), None, std.group(2))
            elif cite in STANDARD_WITHOUT_LABEL and (titled := TITLED.match(body)):
                record("standard", titled.group(1), None, titled.group(2))
            elif inherited and len(path) == inherited[1] + 1:
                titled = TITLED.match(body)
                record("implementation_specification",
                       titled.group(1) if titled else body[:60],
                       inherited[0], titled.group(2) if titled else "", "group heading")

    return records, designations_seen


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--date", default="2026-01-01", help="eCFR point-in-time date")
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--source", type=Path, help="a previously downloaded title-45.xml")
    args = ap.parse_args()

    if args.offline:
        if not args.source:
            ap.error("--offline requires --source")
        root = ET.parse(args.source).getroot()
    else:
        url = ECFR.format(date=args.date)
        print(f"fetching {url}", file=sys.stderr)
        with urllib.request.urlopen(url, timeout=120) as resp:
            root = ET.fromstring(resp.read())

    records, designations_seen = extract(root)
    standards = [r for r in records if r["kind"] == "standard"]
    specs = [r for r in records if r["kind"] == "implementation_specification"]
    inline = [r for r in specs if r["designation_source"] == "inline"]
    grouped = [r for r in specs if r["designation_source"] == "group heading"]

    per_section = Counter(r["section"] for r in standards)
    for sec_id, expected in EXPECTED_STANDARDS.items():
        got = per_section.get(sec_id, 0)
        if got != expected:
            raise SystemExit(
                f"{sec_id}: expected {expected} standards, extracted {got}. "
                f"Either the regulation changed or this parser regressed; do not "
                f"ship a clause list nobody has counted."
            )
    # Two group headings carry a designation that belongs to the specifications
    # beneath them rather than to themselves.
    if designations_seen != len(inline) + 2:
        raise SystemExit(
            f"{designations_seen} paragraphs carry a designation but {len(inline)} were "
            f"captured inline; an implementation specification was dropped."
        )

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with (OUT_DIR / "criteria.jsonl").open("w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")

    meta = {
        "source": "https://www.ecfr.gov/api/versioner/v1/full/{date}/title-45.xml?part=164",
        "point_in_time": args.date,
        "publication": "45 CFR Part 164 Subpart C -- HIPAA Security Rule",
        "license": "US Government work, public domain",
        "standards": len(standards),
        "implementation_specifications": len(specs),
        "designations": dict(Counter(r["designation"] for r in specs)),
        "standards_per_section": dict(per_section),
    }
    (OUT_DIR / "source.json").write_text(
        json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(f"  {len(standards)} standards, {len(specs)} implementation specifications "
          f"({len(inline)} inline, {len(grouped)} inherited from a group heading)",
          file=sys.stderr)
    print(f"  designations: {dict(Counter(r['designation'] for r in specs))}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
