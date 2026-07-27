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
sys.path.insert(0, str(Path(__file__).resolve().parent))
import classify_resp  # noqa: E402
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

    # criteria_count is the published shape of the regime -- 46 GDPR articles in
    # Chapters II to V, 68 HIPAA specifications, 101 ISMS-P criteria. Declared
    # and never checked, it was a number that could drift away from the files
    # beside it and still be printed in a compliance document.
    declared_count = meta.get("criteria_count")
    if declared_count is not None and declared_count != len(criteria):
        raise OverlayError(
            f"overlay {overlay_id!r} declares criteria_count {declared_count} "
            f"but criteria.jsonl holds {len(criteria)}. One of them is wrong, and "
            f"the declared number is the one that reaches the reader."
        )

    # baseline_effect names a power the machinery does not have. Every overlay
    # declares it empty and one of them explains why -- the Regulation does not
    # itself raise the FIPS 199 categorisation -- which is worth keeping. What is
    # not acceptable is that a future overlay could write {raise_to: high} here
    # and have it silently ignored, so a value that means something is refused
    # rather than dropped.
    if meta.get("baseline_effect"):
        raise OverlayError(
            f"overlay {overlay_id!r} sets baseline_effect {meta['baseline_effect']!r}, "
            f"but nothing applies it: no regime yet needed to move the FIPS 199 "
            f"categorisation, so the machinery was never built. Implement it, or "
            f"state the effect in the framing where a reader will see it."
        )

    return {"id": overlay_id, "meta": meta, "criteria": criteria, "mappings": mappings}


def _personal_types(declared_ids: set[str]) -> set[str]:
    """Which of the declared types the classification table flags as personal.

    Used only when the overlay is run without a derivation; select_baseline
    normally supplies the same set as `personal_data_types`.
    """
    import yaml
    table = yaml.safe_load(
        (REPO_ROOT / "catalogs" / "data-types" / "classification.yaml").read_text(encoding="utf-8"))
    flagged = {e["id"] for e in table["types"] if e.get("personal_data")}
    return declared_ids & flagged


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

    # Some regimes are elective: nothing in the data triggers them, an
    # organisation chooses to be certified. Applying those to every profile
    # makes them noise, so they are matched against what the interview recorded
    # rather than against what the service holds.
    elective = meta.get("elective")
    if elective:
        aliases = [a.lower() for a in elective.get("aliases") or [meta["id"]]]
        stated = " ".join(str(x).lower() for x in declared.get("regulations_declared") or [])
        if not any(a in stated for a in aliases):
            return False, (f"{meta['name']} is elective and was not named in the profile "
                           f"(declared.regulations_declared)"), {}
        elective_reason = "named in the profile as a certification the organisation is pursuing"
    else:
        elective_reason = None

    wanted_regions = {r.upper() for r in condition.get("user_regions_any") or []}
    if wanted_regions and regions and not (wanted_regions & regions):
        return False, f"no user region in {sorted(wanted_regions)}", {}

    wanted_types = set(condition.get("data_types_any") or [])
    if wanted_types and not (wanted_types & types):
        return False, "no declared data type this regime covers", {}

    # A regime whose scope simply *is* personal data says so, rather than
    # restating the classification table's personal_data flag as a list. GDPR
    # did restate it, and the restatement was one type short: a service holding
    # EU users' own content was told the Regulation did not reach it.
    if condition.get("data_types_personal"):
        if derived is None:
            personal = _personal_types(types)
        else:
            personal = set(derived.get("personal_data_types") or [])
        if not personal:
            return False, "no declared data type is personal data", {}

    # Only regimes that assess at more than one scope declare a selector, and
    # the axis differs by regime: ISMS-P splits on whether personal data is
    # processed, PCI DSS on whether account data is stored. The first version
    # named the ISMS-P axis in the machinery, which put a Korean certification
    # scope on a US health regulation. It is now stated by the overlay.
    selector = meta.get("scope_selector")
    if not selector:
        return True, elective_reason or "region and declared data types match", {"scope": "full", "areas": None}

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


def all_baseline_controls() -> set[str]:
    path = CATALOG_DIR.parent / "nist-800-53r5" / "baselines.json"
    if not path.exists():
        return set()
    return set().union(*json.loads(path.read_text(encoding="utf-8")).values())


_LAYERS_CACHE: dict | None = None


def _layer_of(control_id: str, deployment_model: str | None, csp: str | None) -> str | None:
    """Which party owns a control, resolved the way the classifier resolves it.

    The first version of this function was a third hand-written copy of the
    resolution order -- after classify_resp and validate_overlays -- and it was
    wrong in two ways the copies could not help being wrong in: it ignored the
    deployment-model overrides, and it ignored the rule that collapses
    csp_claimed and shared when the profile names no provider. On a self-hosted
    profile that made it report clauses as the provider's when there is no
    provider. It now delegates, and the deployment model and provider have to be
    passed in rather than assumed away.
    """
    global _LAYERS_CACHE
    if _LAYERS_CACHE is None:
        import yaml
        _LAYERS_CACHE = yaml.safe_load(
            (REPO_ROOT / "responsibility" / "layers.yaml").read_text(encoding="utf-8"))
    resolved = classify_resp.resolve_layer(control_id, _LAYERS_CACHE, deployment_model)[0]
    if resolved is None:
        return None
    return classify_resp.apply_no_provider_rule(resolved, csp)


def evaluate(overlay: dict, derived_controls: list[str], scope: dict | None = None,
             profile: dict | None = None) -> dict:
    # The privacy baseline counts as derived, and so does the programme layer.
    # Both used to be passed in separately here, which proved this function
    # could use them and concealed that nothing else did: the derivation
    # published the impact baseline alone. They are now part of the derived list
    # itself, and the second route is gone rather than left to drift out of step
    # with the first.
    baseline = set(derived_controls)

    # Who owns a control depends on how the service is deployed and on whether
    # there is a provider at all. Passing None for both -- which is what an
    # overlay run without a profile does -- resolves to the family defaults,
    # which is the same answer this file used to hard-code.
    inferred = (profile or {}).get("inferred") or {}
    deployment_model = inferred.get("deployment_model")
    csp, _, _ = classify_resp.resolve_csp(inferred.get("csp")) if profile else (None, [], "none")
    areas = (scope or {}).get("areas")
    criteria = overlay["criteria"]
    # A clause whose every control sits outside all four baselines can never be
    # reported as reached, whatever the service does. Reporting it beside the
    # ones the service simply has not covered puts a property of this tool into
    # the reader's gap list.
    resolvable = all_baseline_controls()
    covered, partial, uncovered, standalone, unreachable = [], [], [], [], []

    for m in overlay["mappings"]:
        record = criteria[m["clause"]]
        if areas and (record.get("area") or record.get("category")) not in areas:
            continue
        # The whole mapping, not a hand-picked four fields. Picked by hand, a
        # field added to the files went nowhere: responsibility_note was written
        # into three overlays and required by the validator on the same day, and
        # never reached the report, so the report said "nothing the delivery
        # team builds touches this" about a clause whose own note explained
        # which half the team owns. Copying the record makes that unreachable
        # for the next field as well.
        row = dict(m)
        if m["standalone"]:
            standalone.append(row)
            continue
        present = [c for c in m["controls"] if c in baseline]
        row["controls_in_baseline"] = present
        row["controls_absent"] = [c for c in m["controls"] if c not in baseline]
        if not present and resolvable and not (set(m["controls"]) & resolvable):
            unreachable.append(row)
        elif not present:
            uncovered.append(row)
        elif row["controls_absent"]:
            partial.append(row)
        else:
            covered.append(row)

    return {
        "overlay": overlay["id"],
        "depth": overlay["meta"].get("depth") or {},
        "framing": overlay["meta"].get("framing"),
        "scope": (scope or {}).get("scope", "full"),
        "name": overlay["meta"]["name"],
        "version": overlay["meta"]["version"],
        "clause_count": len(covered) + len(partial) + len(uncovered)
                        + len(unreachable) + len(standalone),
        "covered": covered,
        # Of the clauses the report says are reached, the ones no delivery-team
        # control touches. Once the derived set grew broad enough that almost
        # every clause reads as reached, this is what restores the
        # discrimination the headline count lost: a clause reached only through
        # PM-1 and PS-3 is not a clause this repository can close.
        #
        # Partly-reached clauses are included. Leaving them out was an oversight
        # with a direction to it: a clause reached only through organisational
        # controls, some of them outside the baseline, is *more* clearly outside
        # the team's reach, not less.
        "org_only": [{**row, "layer": "csp_claimed" if "csp_claimed" in layers else "org"}
                     for row, layers in (
                         (r, {_layer_of(c, deployment_model, csp) for c in r["controls"]})
                         for r in covered + partial if r["controls"])
                     if layers <= {"org", "csp_claimed"}],
        "partial": partial,
        "uncovered": uncovered,
        "unreachable": unreachable,
        "standalone": standalone,
        "disclaimer": overlay["meta"]["disclaimer"],
    }


def _wrap(text: str, width: int = 74) -> list[str]:
    words, lines, current = " ".join(text.split()).split(), [], ""
    for word in words:
        if len(current) + len(word) + 1 > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return lines


def render(result: dict, reason: str) -> str:
    scope = result["scope"]
    heading = f"  {reason}" if scope == "full" else f"  scope: {scope} -- {reason}"
    out = [f"{result['name']} ({result['version']})", heading, ""]

    # Where an overlay stops above the clause a reader is assessed against, a
    # coverage count reads as near-compliance unless it is qualified here rather
    # than in a disclaimer at the foot. "11 of 12 covered" is the single most
    # dangerous line this tool can print.
    # Some regimes are routinely misread about what is actually assessed. Where
    # an overlay says so, that belongs above the numbers -- it changes how every
    # count below should be taken.
    if result.get("framing"):
        out += ["  " + line for line in _wrap(result["framing"])] + [""]

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
    # "covered" was always defined as "every control this repository maps to the
    # clause is in the derived requirement set" -- a statement about the mapping
    # and the baseline, not about the service. That was legible while the set was
    # a single impact baseline. Once the privacy and programme layers reached the
    # derivation as well, HIPAA read 68 of 68 and ISO 11 of 11, and no disclaimer
    # survives a number like that. The word has to carry its own definition.
    # A count that approaches the total has stopped discriminating. It says the
    # derived set is broad, which is a property of SP 800-53 and of this
    # service's categorisation, and says nothing about whether anything is
    # implemented. The first version of this warning printed below the table and
    # opened "READ THIS BEFORE THE NUMBERS ABOVE", which is an instruction a
    # page cannot give: by then the number has been read. It goes first.
    total = result["clause_count"] or 1
    if (len(result["covered"]) + len(result["partial"])) / total >= 0.85:
        out += ["  Before the counts: nearly every clause below is reached, which is what",
                "  a broad control set does, not what a compliant service looks like.",
                "  Reached means the controls this repository maps to the clause were",
                "  selected -- not written, not built, not assessed. At this density the",
                "  counts carry no information about the service. The rows further down",
                "  do: the clauses nothing reaches, and the clauses no delivery-team",
                "  control touches.",
                ""]

    reached = "reached by the derived requirement set"
    out.append(f"  {len(result['covered']):>4}  {reached}")
    out.append(f"  {len(result['partial']):>4}  partly {'reached' if coarse else 'covered'} -- some mapped controls are outside it")
    out.append(f"  {len(result['uncovered']):>4}  mapped, but no mapped control is in the baseline")
    if result.get("unreachable"):
        out.append(f"  {len(result['unreachable']):>4}  mapped only to controls outside every baseline "
                   f"this tool resolves")
    out.append(f"  {len(result['standalone']):>4}  no control expresses them at all")
    out.append(f"  {'-' * 4}")
    out.append(f"  {result['clause_count']:>4}  clauses")

    if result.get("org_only"):
        n = len(result["org_only"])
        owners = ("the organisation or the provider owns"
                  if any(r.get("layer") == "csp_claimed" for r in result["org_only"])
                  else "the organisation owns")
        out += ["",
                f"  {n} of the reached clause{'s' if n != 1 else ''} "
                f"{'are' if n != 1 else 'is'} reached only through",
                f"  controls {owners}, so no control in this",
                "  derivation closes them:"]
        for row in result["org_only"][:12]:
            out.append(f"  ~ {row['clause']}  {row['title'][:56]}")
            # Where the regime says the obligation is shared and the mapped
            # controls are all the organisation's, the team still owes
            # something that no control in the catalogue expresses. That is the
            # most useful line on the page, and printing the list without it
            # said the opposite of what the mapping says.
            note = " ".join((row.get("responsibility_note") or "").split())
            if row.get("responsibility_hint") == "shared" and note:
                out.append("      the regime treats this as shared, and the team's half is not")
                out.append("      expressed by any control here:")
                for chunk in _wrap(note, 66):
                    out.append(f"        {chunk}")
        if n > 12:
            out.append(f"  ~ ... and {n - 12} more")

    if result["standalone"]:
        out += ["", "Clauses the derivation cannot produce -- these are the audit surprises:"]
        for row in result["standalone"]:
            out.append(f"  * {row['clause']}  {row['title']}")
            if row.get("notes"):
                out.append(f"      {row['notes']}")

    if result.get("unreachable"):
        out += ["", "Beyond this tool's reach -- the mapped controls belong to no baseline it",
                "resolves, so these can never report as reached whatever the service does:"]
        for row in result["unreachable"]:
            out.append(f"  = {row['clause']}  {row['title'][:56]}  -> {', '.join(row['controls'])}")

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

    result = evaluate(overlay, controls, scope, profile)
    print(render(result, reason))
    if args.json:
        args.json.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
