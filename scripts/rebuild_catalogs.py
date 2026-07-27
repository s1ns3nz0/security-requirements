#!/usr/bin/env python3
"""Rebuild the bundled NIST SP 800-53 control catalog from upstream OSCAL content.

Why this script exists
----------------------
Control identifiers and statement text are *reference data*, not something a
language model should recall. A single fabricated identifier -- ``SC-28(4)``
reads as plausibly as the three enhancements that do exist -- is enough to
discredit an entire compliance deliverable.
So the catalog is bundled, derived mechanically from NIST's OSCAL release, and
every requirement's ``sources`` list is link-checked against it at build time.

Source
------
https://github.com/usnistgov/oscal-content (NIST SP 800-53 Rev 5)
US Government work -- public domain. See catalogs/nist-800-53r5/LICENSE.

Usage
-----
    python3 scripts/rebuild_catalogs.py                    # all 20 families
    python3 scripts/rebuild_catalogs.py --families ac,au,sc
    python3 scripts/rebuild_catalogs.py --offline --oscal-dir path/to/json

Output
------
    catalogs/nist-800-53r5/<FAMILY>.jsonl   one control per line
    catalogs/nist-800-53r5/baselines.json   control ids per SP 800-53B baseline
    catalogs/nist-800-53r5/meta.json        provenance and counts
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = REPO_ROOT / "catalogs" / "nist-800-53r5"

UPSTREAM = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main"
    "/nist.gov/SP800-53/rev5/json"
)
CATALOG_FILE = "NIST_SP-800-53_rev5_catalog-min.json"
BASELINE_FILES = {
    "low": "NIST_SP-800-53_rev5_LOW-baseline_profile-min.json",
    "moderate": "NIST_SP-800-53_rev5_MODERATE-baseline_profile-min.json",
    "high": "NIST_SP-800-53_rev5_HIGH-baseline_profile-min.json",
    "privacy": "NIST_SP-800-53_rev5_PRIVACY-baseline_profile-min.json",
}

PARAM_RE = re.compile(r"\{\{\s*insert:\s*param,\s*([^}\s]+)\s*\}\}")


# --------------------------------------------------------------------------
# fetching
# --------------------------------------------------------------------------

def load_json(name: str, oscal_dir: Path | None) -> dict:
    if oscal_dir is not None:
        return json.loads((oscal_dir / name).read_text(encoding="utf-8"))
    url = f"{UPSTREAM}/{name}"
    print(f"  fetching {name} ...", file=sys.stderr)
    with urllib.request.urlopen(url, timeout=120) as resp:
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
# main
# --------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--families",
        help="comma separated family ids to extract (default: all). "
             "Used by the week-1 tracer bullet to keep the working set small.",
    )
    ap.add_argument("--offline", action="store_true", help="read from --oscal-dir instead of network")
    ap.add_argument("--oscal-dir", type=Path, help="directory holding the OSCAL json files")
    args = ap.parse_args()

    if args.offline and not args.oscal_dir:
        ap.error("--offline requires --oscal-dir")
    src_dir = args.oscal_dir if args.offline else None

    wanted = None
    if args.families:
        wanted = {f.strip().lower() for f in args.families.split(",") if f.strip()}

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
        "control_counts": counts,
        "baseline_counts": {k: len(v) for k, v in baselines.items()},
        "partial": bool(wanted),
    }
    (OUT_DIR / "meta.json").write_text(
        json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    if wanted:
        print(
            "\n  NOTE: partial extraction. baselines.json still lists the full\n"
            "  baseline, so select_baseline.py will report controls whose family\n"
            "  is not bundled yet as UNAVAILABLE rather than silently dropping them.",
            file=sys.stderr,
        )
    print(f"\nWrote {sum(counts.values())} controls to {OUT_DIR}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
