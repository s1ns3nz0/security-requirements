#!/usr/bin/env python3
"""Which axes of the input space have ever been exercised.

Sixty-nine repositories were run with an empty threats file. On real input the
merge stage had therefore only ever produced `baseline_only` and
`forced_by_data_type`; threat-only, threat-and-baseline, priority raising, and
related-control resolution had been exercised by four synthetic profiles and
nothing else. Nobody noticed because the only thing being counted was
repositories, and repositories are not the axis that matters.

Adding a repository adds coverage only when it carries a value on an axis
nothing has carried before. This reports which axes are still empty, so the
next repository can be chosen rather than found.

A witness, not a declaration
----------------------------
An axis counts as exercised only when a result appears that could not have come
from anywhere else. A profile declaring `health_records` witnesses the data
type; it witnesses the HIPAA overlay only if the overlay actually evaluated and
returned clauses. Recording the declaration instead is the shape of the failure
above -- the input was there and the code never ran.

Not the same as code coverage
-----------------------------
Every catalogue value is swept through the derivation by the test suite, so a
value reported here as never exercised is not a value whose code has never run.
It is a value no realistic profile has ever carried, which is the harder and
more useful question: `minors_data` derives correctly in a two-line synthetic
profile and has never appeared beside the other types a service holding
children's data would actually declare. The sweep says the rule works. This says
nobody has met it in the wild.

Where the witnesses come from
-----------------------------
Golden cases are re-derived here, so they need no bookkeeping and cannot drift.
External runs cannot be re-derived, so they are recorded in
``evidence/axis-coverage.yaml`` as axis values only. The derived profile of a
third-party repository is not committed: publishing "this project is High impact
and here is where its data lives" is an assessment of someone else's system that
nobody asked for.

Usage
-----
    python3 "${SECURITY_REQUIREMENTS_ROOT}/scripts/axis_coverage.py"
    python3 "${SECURITY_REQUIREMENTS_ROOT}/scripts/axis_coverage.py" --strict   # empty axes fail
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import apply_overlay  # noqa: E402
import classify_resp  # noqa: E402
import merge  # noqa: E402
import select_baseline  # noqa: E402
from profile_schema import normalise  # noqa: E402

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = PLUGIN_ROOT.parent.parent
GOLDEN = REPO_ROOT / "golden"
OVERLAYS = PLUGIN_ROOT / "overlays"
MANIFEST = REPO_ROOT / "evidence" / "axis-coverage.yaml"

# The origins merge.cross can produce. `threat_only` and `threat_and_baseline`
# are the two this tool exists for, and the two the sweep had never run.
ORIGINS = {"baseline_only", "threat_only", "threat_and_baseline", "forced_by_data_type"}


def universe() -> dict[str, set[str]]:
    """Every value each axis can take, read from the catalogues rather than listed."""
    types_table = yaml.safe_load(
        (PLUGIN_ROOT / "catalogs" / "data-types" / "classification.yaml").read_text(encoding="utf-8"))
    layers = yaml.safe_load(
        (PLUGIN_ROOT / "responsibility" / "layers.yaml").read_text(encoding="utf-8"))
    import lint
    return {
        "locale": set(lint.VAGUE),
        "csp": set(classify_resp.KNOWN_PROVIDERS) | {"none"},
        "deployment_model": set(layers.get("deployment_models") or {}),
        "data_type": {t["id"] for t in types_table["types"]},
        "modifier": set(types_table.get("modifiers") or {}),
        "overlay": {p.name for p in OVERLAYS.iterdir() if (p / "meta.yaml").exists()},
        "origin": set(ORIGINS),
        "baseline": {"low", "moderate", "high"},
        "responsibility": {"team", "shared", "csp_claimed", "org"},
    }


def witnesses_of(case: Path) -> dict[str, set[str]]:
    """Run one golden case and record only what the run actually produced."""
    raw = yaml.safe_load((case / "profile.yaml").read_text(encoding="utf-8"))
    profile, _ = normalise(raw)
    derived = select_baseline.run(profile)
    split = classify_resp.classify(profile, derived["controls"])

    seen: dict[str, set[str]] = {axis: set() for axis in universe()}
    seen["baseline"].add(derived["baseline"].replace("nist-800-53b-", ""))

    # The locale is witnessed by rules running on text actually written in it,
    # not by the profile's `locale:` field. The first version of this file read
    # the field -- a declaration -- which is the exact failure the rest of the
    # file was written to prevent, made by the file itself. A profile can say
    # `locale: ko` and carry a document nothing Korean was ever checked against;
    # that is how the documented build came to block every Korean document while
    # the axis report called the locale exercised.
    declared_locale = raw.get("locale") or "en"
    draft_path = case / "draft.json"
    if draft_path.exists():
        import lint
        statements = [
            (item.get("managed") or {}).get("statement", "")
            for item in json.loads(draft_path.read_text(encoding="utf-8"))["requirements"]
        ]
        # Every statement, not any. One Korean sentence among seven English ones
        # would otherwise witness Korean, and the case would report a locale
        # covered while most of its document had never met that locale's rules.
        written_in = {lint.script_of(s) for s in statements if s}
        if statements and written_in == {declared_locale}:
            # And the rules have to accept it. A document in the language that
            # the language's own linter refuses is not a witness for the locale;
            # it is the defect this axis was added to find.
            errors = [
                f for s in statements
                for f in lint.check_statement("REQ-WITNESS-01", s, declared_locale)
                if f.level == "ERROR"
            ]
            if not errors:
                seen["locale"].add(declared_locale)

    inferred = profile.get("inferred") or {}
    csp, providers, _ = classify_resp.resolve_csp(inferred.get("csp"))
    seen["csp"].update(providers or ([csp] if csp else ["none"]))
    if inferred.get("deployment_model"):
        seen["deployment_model"].add(inferred["deployment_model"])

    for entry in (profile.get("declared") or {}).get("data_types") or []:
        seen["data_type"].add(entry["id"])
        seen["modifier"].update(entry.get("modifiers") or [])

    # The responsibility bucket is witnessed by a control landing in it, not by
    # the bucket existing.
    for control in split["controls"]:
        if control["responsibility"] != "undetermined":
            seen["responsibility"].add(control["responsibility"])

    # An overlay counts when it evaluated and returned clauses.
    for overlay_id in sorted(seen and universe()["overlay"]):
        overlay = apply_overlay.load(overlay_id)
        applies, _, scope = apply_overlay.applies(overlay, profile, derived)
        if not applies:
            continue
        result = apply_overlay.evaluate(overlay, derived["controls"], scope, profile)
        if result["clause_count"]:
            seen["overlay"].add(overlay_id)

    # An origin counts when the cross step emitted an item carrying it. Without a
    # threat file only two of the four can appear, which is the whole finding.
    threats_path = case / "threats.yaml"
    threats = yaml.safe_load(threats_path.read_text(encoding="utf-8")) if threats_path.exists() else {}
    crossed = merge.cross(derived, split, threats or {})
    for item in crossed["items"]:
        if item.get("origin") in ORIGINS:
            seen["origin"].add(item["origin"])

    return seen


def recorded() -> tuple[dict[str, set[str]], list[dict]]:
    """External runs, from the manifest. Axis values only, never a profile."""
    seen: dict[str, set[str]] = {axis: set() for axis in universe()}
    if not MANIFEST.exists():
        return seen, []
    doc = yaml.safe_load(MANIFEST.read_text(encoding="utf-8")) or {}
    entries = doc.get("runs") or []
    for entry in entries:
        for axis, values in (entry.get("witnessed") or {}).items():
            if axis in seen:
                seen[axis].update(values if isinstance(values, list) else [values])
    return seen, entries


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--strict", action="store_true",
                    help="an axis with an unexercised value fails")
    ap.add_argument("--json", type=Path)
    args = ap.parse_args(argv)

    space = universe()
    seen: dict[str, set[str]] = {axis: set() for axis in space}

    cases = sorted(p for p in GOLDEN.iterdir() if (p / "profile.yaml").exists())
    for case in cases:
        for axis, values in witnesses_of(case).items():
            seen[axis].update(values)
    external, entries = recorded()
    for axis, values in external.items():
        seen[axis].update(values)

    print(f"Input axis coverage — {len(cases)} golden cases, {len(entries)} recorded external runs\n")
    empty: dict[str, list[str]] = {}
    for axis in sorted(space):
        missing = sorted(space[axis] - seen[axis])
        hit = len(space[axis]) - len(missing)
        print(f"  {axis:18} {hit:>3}/{len(space[axis]):<3} "
              + (f"never exercised: {', '.join(missing)}" if missing else "complete"))
        if missing:
            empty[axis] = missing

    if empty:
        print("\n  These values have never been carried by a realistic profile. The test")
        print("  suite sweeps every one of them through the derivation, so this is not a")
        print("  claim that the code has never run -- it is a claim that no shape anyone")
        print("  would recognise has ever brought them together. Choose the next")
        print("  repository or golden case to carry one:")
        for axis, missing in empty.items():
            print(f"    {axis}: {', '.join(missing)}")

    if args.json:
        args.json.write_text(json.dumps(
            {"exercised": {a: sorted(v) for a, v in seen.items()},
             "never_exercised": empty,
             "golden_cases": [c.name for c in cases],
             "external_runs": len(entries)},
            indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    return 1 if (empty and args.strict) else 0


if __name__ == "__main__":
    raise SystemExit(main())
