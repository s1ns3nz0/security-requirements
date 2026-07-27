#!/usr/bin/env python3
"""Rebuild the bundled reference catalogs from upstream sources.

Why this script exists
----------------------
Control identifiers and statement text are *reference data*, not something a
language model should recall. A single fabricated identifier -- ``SC-28(4)``
reads as plausibly as the three enhancements that do exist -- is enough to
discredit an entire compliance deliverable.
So the catalogs are bundled, derived mechanically from the upstream releases,
and every cited identifier is link-checked against them at build time.

Sources
-------
NIST SP 800-53 Rev 5 / SP 800-53B and the NIST Cybersecurity Framework 2.0, from
https://github.com/usnistgov/oscal-content. US Government works, public domain.

OWASP Application Security Verification Standard 5.0 from
https://github.com/OWASP/ASVS, licensed CC BY-SA 4.0. It is written to its own
directory carrying its own LICENSE and NOTICE, so the share-alike condition
stays confined to the adapted material.

Usage
-----
    python3 scripts/rebuild_catalogs.py                        # everything
    python3 scripts/rebuild_catalogs.py --catalog nist --families ac,au,sc
    python3 scripts/rebuild_catalogs.py --offline --source-dir path/to/downloads

Output
------
    catalogs/nist-800-53r5/<FAMILY>.jsonl   one control per line
    catalogs/nist-800-53r5/baselines.json   control ids per SP 800-53B baseline
    catalogs/nist-800-53r5/meta.json        provenance and counts
    catalogs/csf-2.0/subcategories.jsonl    106 subcategories under 22 categories
    catalogs/asvs-5/V<n>.jsonl              requirements per chapter, with level

No CSF-to-800-53 crosswalk is bundled
-------------------------------------
NIST publishes those mappings through the Cybersecurity and Privacy Reference
Tool rather than in OSCAL, and its JSON endpoints do not respond. Rather than
hand-author a mapping and present it as authoritative, requirements carry a CSF
subcategory chosen when they are written, and lint.py verifies that the cited
identifier exists in the bundled CSF catalog. That preserves the integrity
guarantee without inventing a correspondence NIST has not published here.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CATALOGS = REPO_ROOT / "catalogs"
OUT_DIR = CATALOGS / "nist-800-53r5"
CSF_OUT_DIR = CATALOGS / "csf-2.0"
ASVS_OUT_DIR = CATALOGS / "asvs-5"

UPSTREAM = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main"
    "/nist.gov/SP800-53/rev5/json"
)
CSF_UPSTREAM = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main"
    "/nist.gov/CSF/v2.0/json"
)
ASVS_UPSTREAM = (
    "https://raw.githubusercontent.com/OWASP/ASVS/master/5.0/docs_en"
)

CATALOG_FILE = "NIST_SP-800-53_rev5_catalog-min.json"
CSF_FILE = "NIST_CSF_v2.0_catalog-min.json"
ASVS_FILE = "OWASP_Application_Security_Verification_Standard_5.0.0_en.flat.json"
BASELINE_FILES = {
    "low": "NIST_SP-800-53_rev5_LOW-baseline_profile-min.json",
    "moderate": "NIST_SP-800-53_rev5_MODERATE-baseline_profile-min.json",
    "high": "NIST_SP-800-53_rev5_HIGH-baseline_profile-min.json",
    "privacy": "NIST_SP-800-53_rev5_PRIVACY-baseline_profile-min.json",
}

# Published structure of CSF 2.0. The OSCAL release carries CSF 1.1 material
# alongside 2.0 -- 185 subcategories across 34 categories -- with the retired
# 1.1 entries marked ``status: withdrawn``. Filtering those out yields exactly
# the 106 subcategories under 22 categories that NIST publishes, which is the
# assertion test_csf_matches_published_structure holds the extraction to.
CSF_20_CATEGORIES = {
    "GV.OC", "GV.RM", "GV.RR", "GV.PO", "GV.OV", "GV.SC",
    "ID.AM", "ID.RA", "ID.IM",
    "PR.AA", "PR.AT", "PR.DS", "PR.PS", "PR.IR",
    "DE.CM", "DE.AE",
    "RS.MA", "RS.AN", "RS.CO", "RS.MI",
    "RC.RP", "RC.CO",
}
CSF_FUNCTIONS = {
    "GV": "GOVERN", "ID": "IDENTIFY", "PR": "PROTECT",
    "DE": "DETECT", "RS": "RESPOND", "RC": "RECOVER",
}

PARAM_RE = re.compile(r"\{\{\s*insert:\s*param,\s*([^}\s]+)\s*\}\}")


# --------------------------------------------------------------------------
# fetching
# --------------------------------------------------------------------------

def load_json(name: str, source_dir: Path | None, base: str = UPSTREAM) -> dict:
    if source_dir is not None:
        return json.loads((source_dir / name).read_text(encoding="utf-8"))
    url = f"{base}/{name}"
    print(f"  fetching {name} ...", file=sys.stderr)
    with urllib.request.urlopen(url, timeout=180) as resp:
        return json.loads(resp.read().decode("utf-8"))


# --------------------------------------------------------------------------
# parsing
# --------------------------------------------------------------------------

def param_label(param: dict) -> str:
    """Human-readable text for an organisation-defined parameter.

    Three shapes appear in the OSCAL source and all three must be handled, or
    raw internal ids such as ``sc-28_odp.01`` leak into requirement text:

    * ``label``      -- a noun phrase, used directly
    * ``select``     -- a closed choice; render the options so the reader can pick
    * ``guidelines`` -- fallback prose describing what must be defined
    """
    if param.get("label"):
        return param["label"]

    select = param.get("select")
    if select:
        choices = [c if isinstance(c, str) else c.get("value", "") for c in select.get("choice", [])]
        how_many = select.get("how-many", "one")
        joiner = " and/or " if how_many == "one-or-more" else " or "
        return joiner.join(c for c in choices if c)

    guidelines = param.get("guidelines") or []
    if guidelines:
        return guidelines[0].get("prose", "").rstrip(";")

    return param["id"]


def collect_params(control: dict) -> dict[str, str]:
    """Map parameter id -> human label, for resolving assignment placeholders.

    Labels are resolved iteratively because ``select`` choices may themselves
    embed parameter references -- AC-7's lockout options nest two levels deep.
    Without this pass, raw ids such as ``ac-07_odp.04`` survive into the
    requirement text a reader is asked to act on.
    """
    out = {}
    for param in control.get("params", []):
        label = param_label(param)
        out[param["id"]] = label
        for prop in param.get("props", []):
            if prop.get("name") == "alt-identifier":
                out[prop["value"]] = label

    for _ in range(3):
        if not any(PARAM_RE.search(v) for v in out.values()):
            break
        out = {k: resolve_params(v, out) for k, v in out.items()}
    return out


def resolve_params(prose: str, params: dict[str, str]) -> str:
    """Replace ``{{ insert: param, x }}`` with ``[assignment: <label>]``.

    Keeping the placeholder visible matters: these are the points where an
    organisation must make a decision. A requirement derived from a control
    with an unfilled assignment is incomplete by construction, and the reader
    should be able to see that.
    """
    def sub(match: re.Match) -> str:
        key = match.group(1)
        return f"[assignment: {params.get(key, key)}]"

    return PARAM_RE.sub(sub, prose)


def flatten_parts(parts: list[dict], params: dict[str, str], depth: int = 0) -> list[str]:
    """Flatten nested statement items into labelled lines."""
    lines = []
    for part in parts:
        label = ""
        for prop in part.get("props", []):
            if prop.get("name") == "label":
                label = prop["value"]
                break
        prose = part.get("prose")
        if prose:
            indent = "  " * depth
            text = resolve_params(prose, params)
            lines.append(f"{indent}{label} {text}".strip() if label else f"{indent}{text}")
        if part.get("parts"):
            lines.extend(flatten_parts(part["parts"], params, depth + 1))
    return lines


def part_text(control: dict, name: str, params: dict[str, str]) -> str:
    for part in control.get("parts", []):
        if part.get("name") != name:
            continue
        if part.get("prose"):
            return resolve_params(part["prose"], params)
        if part.get("parts"):
            return "\n".join(flatten_parts(part["parts"], params))
    return ""


def display_id(oscal_id: str) -> str:
    """``ac-2.1`` -> ``AC-2(1)`` -- the form used in NIST prose and audits."""
    if "." in oscal_id:
        base, enh = oscal_id.split(".", 1)
        return f"{base.upper()}({enh})"
    return oscal_id.upper()


def implementation_level(control: dict) -> str | None:
    for prop in control.get("props", []):
        if prop.get("name") == "implementation-level":
            return prop.get("value")
    return None


def build_global_params(catalog: dict) -> dict[str, str]:
    """Parameter labels for the whole catalog.

    Some statements reference parameters declared on a *sibling* control --
    SC-42(2) uses one defined by SC-42(1). A control-local map cannot resolve
    those, so a catalog-wide map is built once and used as the fallback layer.
    """
    merged: dict[str, str] = {}

    def visit(controls: list[dict]) -> None:
        for control in controls:
            merged.update(collect_params(control))
            if control.get("controls"):
                visit(control["controls"])

    for group in catalog.get("groups", []):
        visit(group.get("controls", []))

    for _ in range(3):
        if not any(PARAM_RE.search(v) for v in merged.values()):
            break
        merged = {k: resolve_params(v, merged) for k, v in merged.items()}
    return merged


def walk_controls(
    controls: list[dict],
    family: str,
    global_params: dict[str, str],
    parent: str | None = None,
):
    for control in controls:
        params = {**global_params, **collect_params(control)}
        oscal_id = control["id"]
        yield {
            "id": display_id(oscal_id),
            "oscal_id": oscal_id,
            "family": family.upper(),
            "title": control.get("title", ""),
            "is_enhancement": parent is not None,
            "parent": display_id(parent) if parent else None,
            "implementation_level": implementation_level(control),
            "statement": part_text(control, "statement", params),
            "guidance": part_text(control, "guidance", params),
            "assignments": [
                {"id": p["id"], "label": params.get(p["id"], p["id"])}
                for p in control.get("params", [])
            ],
            "related": [
                display_id(link["href"].lstrip("#"))
                for link in control.get("links", [])
                if link.get("rel") == "related"
            ],
        }
        if control.get("controls"):
            yield from walk_controls(control["controls"], family, global_params, oscal_id)


def parse_baseline(profile: dict) -> list[str]:
    ids = []
    for imp in profile["profile"].get("imports", []):
        for inc in imp.get("include-controls", []):
            ids.extend(inc.get("with-ids", []))
    return [display_id(i) for i in ids]


# --------------------------------------------------------------------------
# CSF 2.0
# --------------------------------------------------------------------------

def prop(item: dict, name: str) -> str | None:
    for entry in item.get("props", []) or []:
        if entry.get("name") == name:
            return entry.get("value")
    return None


def statement_of(item: dict) -> str:
    for part in item.get("parts", []) or []:
        if part.get("name") == "statement":
            return part.get("prose", "")
    return ""


def build_csf(source_dir: Path | None) -> dict:
    print("Rebuilding NIST CSF 2.0", file=sys.stderr)
    catalog = load_json(CSF_FILE, source_dir, CSF_UPSTREAM)["catalog"]

    CSF_OUT_DIR.mkdir(parents=True, exist_ok=True)
    records, categories, skipped = [], [], 0

    for group in catalog.get("groups", []):
        function = group["id"].upper()
        for category in group.get("controls", []):
            if category.get("class") != "category":
                continue
            if category["id"] not in CSF_20_CATEGORIES:
                skipped += 1
                continue
            categories.append({
                "id": category["id"],
                "function": function,
                "function_name": CSF_FUNCTIONS.get(function, function),
                "title": category.get("title", ""),
                "statement": statement_of(category),
            })
            for sub in category.get("controls", []) or []:
                if sub.get("class") != "subcategory":
                    continue
                if prop(sub, "status") == "withdrawn":
                    skipped += 1
                    continue
                records.append({
                    "id": sub["id"],
                    "function": function,
                    "function_name": CSF_FUNCTIONS.get(function, function),
                    "category": category["id"],
                    "category_title": category.get("title", ""),
                    "statement": statement_of(sub),
                    "examples": [
                        part.get("prose", "")
                        for part in sub.get("parts", []) or []
                        if part.get("name") == "example"
                    ],
                    "risk_party": prop(sub, "risk-party"),
                })

    with (CSF_OUT_DIR / "subcategories.jsonl").open("w", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    (CSF_OUT_DIR / "categories.json").write_text(
        json.dumps(categories, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    meta = {
        "source": "https://github.com/usnistgov/oscal-content",
        "publication": "NIST Cybersecurity Framework 2.0",
        "oscal_version": catalog["metadata"].get("version"),
        "oscal_last_modified": catalog["metadata"].get("last-modified"),
        "license": "US Government work, public domain",
        "subcategory_count": len(records),
        "category_count": len(categories),
        "withdrawn_or_legacy_skipped": skipped,
        "note": (
            "The upstream OSCAL release carries CSF 1.1 material alongside 2.0. "
            "Entries marked status=withdrawn and categories outside the published "
            "CSF 2.0 set are excluded."
        ),
    }
    (CSF_OUT_DIR / "meta.json").write_text(
        json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(f"  {len(records)} subcategories / {len(categories)} categories "
          f"({skipped} legacy or withdrawn entries excluded)", file=sys.stderr)
    return meta


# --------------------------------------------------------------------------
# OWASP ASVS 5.0
# --------------------------------------------------------------------------

ASVS_LICENSE = """\
The files in this directory are derived from the OWASP Application Security
Verification Standard:

    https://github.com/OWASP/ASVS
    OWASP Application Security Verification Standard 5.0.0

The ASVS is licensed under the Creative Commons Attribution-ShareAlike 4.0
International licence (CC BY-SA 4.0):

    https://creativecommons.org/licenses/by-sa/4.0/

The transformation applied here -- the upstream flat JSON reshaped into one
JSON Lines file per chapter -- is an adaptation, so the contents of this
directory remain under CC BY-SA 4.0. Requirement text is reproduced verbatim.

This directory is a separate work included in a collection. The share-alike
condition applies to these files and does not extend to the rest of the
repository, which is licensed under Apache-2.0.
"""

ASVS_NOTICE = """\
OWASP Application Security Verification Standard 5.0.0
Copyright the OWASP Foundation and ASVS contributors.
Licensed under CC BY-SA 4.0.

Changes made:
  - The upstream flat JSON was split into one JSON Lines file per chapter.
  - Field names were normalised (req_id -> id, req_description -> statement,
    L -> level).
  - Requirement text itself was not altered.

Produced by scripts/rebuild_catalogs.py. OWASP does not endorse this project.
"""


def build_asvs(source_dir: Path | None) -> dict:
    print("Rebuilding OWASP ASVS 5.0", file=sys.stderr)
    payload = load_json(ASVS_FILE, source_dir, ASVS_UPSTREAM)
    requirements = payload["requirements"]

    ASVS_OUT_DIR.mkdir(parents=True, exist_ok=True)
    by_chapter: dict[str, list[dict]] = {}
    levels: dict[str, int] = {}

    for req in requirements:
        level_raw = (req.get("L") or "").strip()
        record = {
            "id": f"ASVS-{req['req_id']}",
            "req_id": req["req_id"],
            "chapter": req["chapter_id"],
            "chapter_name": req["chapter_name"],
            "section": req["section_id"],
            "section_name": req["section_name"],
            "statement": req["req_description"],
            "level": int(level_raw) if level_raw.isdigit() else None,
        }
        by_chapter.setdefault(req["chapter_id"], []).append(record)
        key = level_raw or "unspecified"
        levels[key] = levels.get(key, 0) + 1

    for chapter, records in sorted(by_chapter.items()):
        with (ASVS_OUT_DIR / f"{chapter}.jsonl").open("w", encoding="utf-8") as fh:
            for record in records:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    (ASVS_OUT_DIR / "LICENSE").write_text(ASVS_LICENSE, encoding="utf-8")
    (ASVS_OUT_DIR / "NOTICE").write_text(ASVS_NOTICE, encoding="utf-8")

    meta = {
        "source": "https://github.com/OWASP/ASVS",
        "publication": "OWASP Application Security Verification Standard 5.0.0",
        "license": "CC BY-SA 4.0",
        "requirement_count": len(requirements),
        "chapters": sorted(by_chapter),
        "level_counts": levels,
    }
    (ASVS_OUT_DIR / "meta.json").write_text(
        json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(f"  {len(requirements)} requirements across {len(by_chapter)} chapters "
          f"(levels: {levels})", file=sys.stderr)
    return meta


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def build_nist(src_dir: Path | None, wanted: set[str] | None) -> int:
    print("Rebuilding NIST SP 800-53 Rev 5 catalog", file=sys.stderr)
    catalog = load_json(CATALOG_FILE, src_dir)["catalog"]

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    global_params = build_global_params(catalog)

    counts = {}
    for group in catalog["groups"]:
        family = group["id"]
        if wanted and family not in wanted:
            continue
        records = list(walk_controls(group.get("controls", []), family, global_params))
        path = OUT_DIR / f"{family.upper()}.jsonl"
        with path.open("w", encoding="utf-8") as fh:
            for record in records:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        counts[family.upper()] = len(records)
        print(f"  {family.upper():<4} {len(records):>4} controls -> {path.name}", file=sys.stderr)

    baselines = {}
    for name, filename in BASELINE_FILES.items():
        baselines[name] = parse_baseline(load_json(filename, src_dir))
        print(f"  baseline {name:<9} {len(baselines[name]):>4} controls", file=sys.stderr)
    (OUT_DIR / "baselines.json").write_text(
        json.dumps(baselines, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    meta = {
        "source": "https://github.com/usnistgov/oscal-content",
        "publication": "NIST SP 800-53 Rev 5 / SP 800-53B",
        "oscal_catalog_uuid": catalog["uuid"],
        "oscal_last_modified": catalog["metadata"].get("last-modified"),
        "oscal_version": catalog["metadata"].get("version"),
        "license": "US Government work, public domain",
        # Every family the publication defines, not just the ones extracted.
        # lint.py needs this to tell "real family, not bundled yet" apart from
        # "not a family at all" -- otherwise a hallucinated identifier in an
        # invented family degrades to a warning and survives the gate.
        "all_families": sorted(g["id"].upper() for g in catalog["groups"]),
        "families_extracted": sorted(counts),
        # What is actually on disk, which is not the same thing. A partial
        # rebuild writes the families it was asked for and leaves the rest
        # where a previous run put them, so the directory can hold material
        # from two builds while the provenance names only the newer one. Every
        # consumer reads the directory, not this list, so the mismatch has to
        # be recorded and shouted about.
        "families_present": sorted(p.stem for p in OUT_DIR.glob("*.jsonl")),
        "control_counts": counts,
        "baseline_counts": {k: len(v) for k, v in baselines.items()},
        "partial": bool(wanted),
    }
    stale = sorted(set(meta["families_present"]) - set(meta["families_extracted"]))
    meta["families_stale"] = stale
    (OUT_DIR / "meta.json").write_text(
        json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    print(f"  wrote {sum(counts.values())} controls to {OUT_DIR}", file=sys.stderr)
    if stale:
        print(
            f"\n  WARNING: {len(stale)} families on disk were not written by this run:\n"
            f"    {', '.join(stale)}\n"
            f"  The directory now mixes output from more than one build, and every\n"
            f"  consumer reads the directory rather than the provenance. Run a full\n"
            f"  rebuild before relying on it.",
            file=sys.stderr,
        )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--catalog",
        choices=["all", "nist", "csf", "asvs"],
        default="all",
        help="which catalog to rebuild (default: all)",
    )
    ap.add_argument(
        "--families",
        help="comma separated 800-53 family ids to extract (default: all). "
             "Kept for working against a reduced set during development.",
    )
    ap.add_argument("--offline", action="store_true",
                    help="read from --source-dir instead of the network")
    ap.add_argument("--source-dir", "--oscal-dir", dest="source_dir", type=Path,
                    help="directory holding the downloaded upstream json files")
    args = ap.parse_args()

    if args.offline and not args.source_dir:
        ap.error("--offline requires --source-dir")
    src_dir = args.source_dir if args.offline else None

    wanted = None
    if args.families:
        wanted = {f.strip().lower() for f in args.families.split(",") if f.strip()}

    if args.catalog in ("all", "nist"):
        build_nist(src_dir, wanted)
    if args.catalog in ("all", "csf"):
        build_csf(src_dir)
    if args.catalog in ("all", "asvs"):
        build_asvs(src_dir)

    if wanted:
        print(
            "\n  NOTE: partial 800-53 extraction. baselines.json still lists the full\n"
            "  baseline, so select_baseline.py reports controls whose family is not\n"
            "  bundled as UNAVAILABLE rather than silently dropping them.",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
