#!/usr/bin/env python3
"""Attach a regulatory overlay to a derived requirement set.

An overlay answers a question the core derivation cannot: which clauses of a
named regime the derived controls already satisfy, and which they do not reach
at all. The second list is the point. A team asked to certify against ISMS-P
and handed a SP 800-53 derivation has to work out by hand which of the 101
clauses are covered; the clauses nothing covers are the ones that surprise them
in an audit.

The mapping is authored, not published -- NIST and KISA publish no crosswalk --
so every control identifier it cites is link-checked against the bundled
catalog on load. An overlay that cited a control that does not exist would
launder a fabricated identifier into the deliverable through the side door.

Usage
-----
    python3 scripts/apply_overlay.py pipa-isms-p PROFILE CONTROLS_JSON [--json OUT]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import yaml

from profile_schema import normalise

REPO_ROOT = Path(__file__).resolve().parent.parent
OVERLAYS = REPO_ROOT / "overlays"
CATALOG_DIR = REPO_ROOT / "catalogs" / "nist-800-53r5"


class OverlayError(Exception):
    pass


def catalog_ids() -> set[str]:
    ids = set()
    for path in CATALOG_DIR.glob("*.jsonl"):
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                ids.add(json.loads(line)["id"])
    return ids


def load(overlay_id: str) -> dict:
    root = OVERLAYS / overlay_id
    if not root.exists():
        available = sorted(p.name for p in OVERLAYS.iterdir() if p.is_dir())
        raise OverlayError(f"no overlay {overlay_id!r}; available: {', '.join(available) or 'none'}")

    meta = yaml.safe_load((root / "meta.yaml").read_text(encoding="utf-8"))
    criteria = {json.loads(l)["clause"]: json.loads(l)
                for l in (root / "criteria.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()}
    mappings = [json.loads(l) for l in
                (root / "mappings.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]

    known = catalog_ids()
    invented = sorted({c for m in mappings for c in m["controls"] if c not in known})
    if invented:
        raise OverlayError(
            f"overlay {overlay_id!r} cites controls that do not exist: {', '.join(invented)}. "
            f"An overlay is not a way round the catalog check."
        )

    unmapped = sorted(set(criteria) - {m["clause"] for m in mappings})
    if unmapped:
        raise OverlayError(f"overlay {overlay_id!r} leaves clauses unmapped: {', '.join(unmapped)}")

    return {"id": overlay_id, "meta": meta, "criteria": criteria, "mappings": mappings}


def applies(overlay: dict, profile: dict, derived: dict | None = None) -> tuple[bool, str, dict]:
    """Whether the overlay applies, and at which certification scope.

    Gating the whole overlay on personal data was wrong: ISMS-P has two scopes,
    and a service holding no personal data can still be ISMS-certified against
    the first eighty clauses.
    """
    meta = overlay["meta"]
    condition = meta.get("applies_when") or {}
    declared = profile.get("declared") or {}
    regions = {str(r).strip().upper() for r in declared.get("user_regions") or []}
    types = {e["id"] if isinstance(e, dict) else e for e in declared.get("data_types") or []}

    wanted_regions = {r.upper() for r in condition.get("user_regions_any") or []}
    if wanted_regions and regions and not (wanted_regions & regions):
        return False, f"no user region in {sorted(wanted_regions)}", {}

    wanted_types = set(condition.get("data_types_any") or [])
    if wanted_types and not (wanted_types & types):
        return False, "no declared data type this regime covers", {}

    # Only regimes that assess at more than one scope declare a selector, and
    # the axis differs by regime: ISMS-P splits on whether personal data is
    # processed, PCI DSS on whether account data is stored. The first version
    # named the ISMS-P axis in the machinery, which put a Korean certification
    # scope on a US health regulation. It is now stated by the overlay.
    selector = meta.get("scope_selector")
    if not selector:
        return True, "region and declared data types match", {"scope": "full", "areas": None}

    default = {"scope": "full", "areas": None}

    # Some regimes are assessed over a set of elective areas rather than at one
    # of two depths. SOC 2 is the case: the common criteria are mandatory and
    # the other four categories are included only if the service organisation
    # commits to them -- and the profile already holds what decides that.
    if selector.get("mode") == "categories":
        return True, *select_categories(selector, profile, derived)

    deciding = set(selector.get("data_types") or [])
    if deciding & types:
        scope = selector.get("when_present") or default
        reason = scope.get("reason", "the deciding data types are declared")
    else:
        scope = selector.get("when_absent") or default
        reason = scope.get("reason", "none of the deciding data types is declared")
    return True, reason, scope


LEVELS = ["low", "moderate", "high"]


def select_categories(selector: dict, profile: dict, derived: dict | None) -> tuple[str, dict]:
    """Choose the elective areas a profile puts in scope.

    Returns (reason, scope). Where the derivation has not been supplied the
    optional areas cannot be judged, so all of them are included and the reason
    says so -- narrowing scope on missing information would understate the
    assessment.
    """
    always = list(selector.get("always") or [])
    optional = selector.get("optional") or {}
    if derived is None:
        return ("no derivation supplied, so every elective area is left in scope",
                {"scope": "all categories", "areas": always + list(optional)})

    impact = (derived.get("impact") or {})
    chosen, why = list(always), []
    for area, rule in optional.items():
        axis = rule.get("axis")
        if axis == "personal_data":
            hit = bool(derived.get("personal_data_types"))
            note = "personal data is processed"
        else:
            level = (impact.get(axis) or {}).get("level")
            floor = rule.get("at_least", "moderate")
            hit = level in LEVELS and LEVELS.index(level) >= LEVELS.index(floor)
            note = f"{axis} is {level}"
        if hit:
            chosen.append(area)
            why.append(f"{area} ({note})")

    reason = "common criteria" + (f", plus {', '.join(why)}" if why else
                                  "; no elective category is indicated by the profile")
    return reason, {"scope": "+".join(chosen), "areas": chosen}


def evaluate(overlay: dict, derived_controls: list[str], scope: dict | None = None,
             privacy_controls: list[str] | None = None) -> dict:
    # The privacy baseline counts as derived. Judging a privacy regime only
    # against the security baseline reports its own blind spot as the service's
    # gap.
    baseline = set(derived_controls) | set(privacy_controls or [])
    areas = (scope or {}).get("areas")
    criteria = overlay["criteria"]
    covered, partial, uncovered, standalone = [], [], [], []

    for m in overlay["mappings"]:
        record = criteria[m["clause"]]
        if areas and (record.get("area") or record.get("category")) not in areas:
            continue
        row = {"clause": m["clause"], "title": m["title"],
               "controls": m["controls"],
               "responsibility_hint": m.get("responsibility_hint"),
               "notes": m.get("notes")}
        if m["standalone"]:
            standalone.append(row)
            continue
        present = [c for c in m["controls"] if c in baseline]
        row["controls_in_baseline"] = present
        row["controls_absent"] = [c for c in m["controls"] if c not in baseline]
        if not present:
            uncovered.append(row)
        elif row["controls_absent"]:
            partial.append(row)
        else:
            covered.append(row)

    return {
        "overlay": overlay["id"],
        "depth": overlay["meta"].get("depth") or {},
        "scope": (scope or {}).get("scope", "full"),
        "name": overlay["meta"]["name"],
        "version": overlay["meta"]["version"],
        "clause_count": len(covered) + len(partial) + len(uncovered) + len(standalone),
        "covered": covered,
        "partial": partial,
        "uncovered": uncovered,
        "standalone": standalone,
        "disclaimer": overlay["meta"]["disclaimer"],
    }


def render(result: dict, reason: str) -> str:
    scope = result["scope"]
    heading = f"  {reason}" if scope == "full" else f"  scope: {scope} -- {reason}"
    out = [f"{result['name']} ({result['version']})", heading, ""]

    # Where an overlay stops above the clause a reader is assessed against, a
    # coverage count reads as near-compliance unless it is qualified here rather
    # than in a disclaimer at the foot. "11 of 12 covered" is the single most
    # dangerous line this tool can print.
    coarse = result["depth"].get("sub_requirements_enumerated") is False
    if coarse:
        out += [f"  DEPTH: {result['depth'].get('level', 'summary level')} only. The counts below say",
                "  which areas the derivation reaches, not whether any requirement is met."]
        # Overlays are shallow for different reasons, and the reason matters:
        # PCI's numbering is part of a licensed standard, SOC 2 additionally has
        # no fixed control set to derive against at all.
        note = " ".join((result["depth"].get("note") or "").split())
        for sentence in re.split(r"(?<=\.)\s+", note)[:2]:
            if sentence:
                out.append(f"  {sentence}")
        out.append("")
    reached = "reached by the derived baseline" if coarse else "fully covered by the derived baseline"
    out.append(f"  {len(result['covered']):>4}  {reached}")
    out.append(f"  {len(result['partial']):>4}  partly {'reached' if coarse else 'covered'} -- some mapped controls are outside it")
    out.append(f"  {len(result['uncovered']):>4}  mapped, but no mapped control is in the baseline")
    out.append(f"  {len(result['standalone']):>4}  no control expresses them at all")
    out.append(f"  {'-' * 4}")
    out.append(f"  {result['clause_count']:>4}  clauses")

    if result["standalone"]:
        out += ["", "Clauses the derivation cannot produce -- these are the audit surprises:"]
        for row in result["standalone"]:
            out.append(f"  * {row['clause']}  {row['title']}")
            if row.get("notes"):
                out.append(f"      {row['notes']}")

    if result["uncovered"]:
        out += ["", "Mapped clauses whose controls fall outside this baseline:"]
        for row in result["uncovered"]:
            out.append(f"  ! {row['clause']}  {row['title']}  -> {', '.join(row['controls'])}")

    out += ["", f"  {result['disclaimer'].strip()}"]
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("overlay")
    ap.add_argument("profile", type=Path)
    ap.add_argument("controls", type=Path, help="select_baseline.py --json output")
    ap.add_argument("--json", type=Path)
    ap.add_argument("--force", action="store_true", help="evaluate even if the applicability test fails")
    args = ap.parse_args()

    profile, _ = normalise(yaml.safe_load(args.profile.read_text(encoding="utf-8")))
    derived = json.loads(args.controls.read_text(encoding="utf-8"))
    controls = derived["controls"]
    privacy = derived.get("privacy_controls") or []

    try:
        overlay = load(args.overlay)
    except OverlayError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    ok, reason, scope = applies(overlay, profile, derived)
    if not ok and not args.force:
        print(f"{overlay['meta']['name']} does not apply to this profile: {reason}")
        print("Pass --force to evaluate anyway.")
        return 0

    result = evaluate(overlay, controls, scope, privacy)
    print(render(result, reason))
    if args.json:
        args.json.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
