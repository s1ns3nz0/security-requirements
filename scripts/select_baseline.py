#!/usr/bin/env python3
"""Derive FIPS 199 impact levels from a service profile and resolve the baseline.

This is pipeline step 4, and it is deliberately *not* a model task. "Which
controls are in the Moderate baseline" is a lookup, not a judgement. Asking a
model to answer it is slower, more expensive, non-reproducible across runs, and
prone to inventing identifiers. Everything here is a table join.

What is a judgement -- how sensitive the data is, how long the service may be
down -- was already collected during the interview and lives in the profile.

Usage
-----
    python3 scripts/select_baseline.py .security-requirements/profile.yaml
    python3 scripts/select_baseline.py profile.yaml --json controls.json

Exit codes
----------
    0  success
    2  profile is missing fields required to derive impact
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
CATALOG_DIR = REPO_ROOT / "catalogs" / "nist-800-53r5"
DATA_TYPES = REPO_ROOT / "catalogs" / "data-types" / "classification.yaml"
AVAILABILITY = REPO_ROOT / "catalogs" / "data-types" / "availability.yaml"

LEVELS = ["low", "moderate", "high"]

BASELINE_FOR_IMPACT = {
    "low": "nist-800-53b-low",
    "moderate": "nist-800-53b-moderate",
    "high": "nist-800-53b-high",
}
BASELINE_KEY = {
    "nist-800-53b-low": "low",
    "nist-800-53b-moderate": "moderate",
    "nist-800-53b-high": "high",
}

# ASVS level follows exposure and sensitivity rather than the FIPS high-water
# mark. L1 is not offered as an automatic outcome: any service holding personal
# data or serving authenticated users is at least L2 in practice.
ASVS_FOR_IMPACT = {"low": 1, "moderate": 2, "high": 3}


# --------------------------------------------------------------------------
# level arithmetic
# --------------------------------------------------------------------------

def bump(level: str, delta: int) -> str:
    idx = LEVELS.index(level) + delta
    return LEVELS[max(0, min(len(LEVELS) - 1, idx))]


def highest(levels: list[str]) -> str:
    return LEVELS[max((LEVELS.index(x) for x in levels), default=0)] if levels else "low"


# --------------------------------------------------------------------------
# impact derivation
# --------------------------------------------------------------------------

class ProfileError(Exception):
    pass


def derive_confidentiality_integrity(profile: dict, table: dict) -> tuple[dict, dict, list[str], list[str]]:
    types = {t["id"]: t for t in table["types"]}
    modifiers = table.get("modifiers", {})

    declared = (profile.get("declared") or {}).get("data_types")
    if not declared:
        raise ProfileError("declared.data_types is empty -- run the interview first (Q1)")

    selected = []
    for entry in declared:
        entry = {"id": entry} if isinstance(entry, str) else entry
        if entry["id"] not in types:
            raise ProfileError(f"unknown data type {entry['id']!r}; see {DATA_TYPES.name}")
        selected.append(entry)

    # inherit_max types (backups, ML training data) take the highest level
    # reached by any concrete type, so they are resolved in a second pass.
    concrete_c, concrete_i = [], []
    conf_why, integ_why, flags, triggers = [], [], [], []

    def evaluate(entry, allow_inherit):
        spec = types[entry["id"]]
        label = spec["label"]
        c_raw, i_raw = spec["confidentiality"], spec["integrity"]

        if c_raw == "inherit_max":
            if not allow_inherit:
                return None
            c = highest(concrete_c)
            note = f"inherits highest ({c})"
        else:
            c, note = c_raw, None

        applied = []
        for mod_id in entry.get("modifiers", []) or []:
            if mod_id not in modifiers:
                raise ProfileError(f"unknown modifier {mod_id!r}; see {DATA_TYPES.name}")
            mod = modifiers[mod_id]
            effect = mod.get("effect", {}).get("confidentiality")
            if isinstance(effect, str) and effect.startswith("="):
                c = effect[1:]
            elif isinstance(effect, int):
                c = bump(c, effect)
            applied.append(mod["label"])
            flags.extend(mod.get("flags", []) or [])

        i = i_raw if i_raw != "inherit_max" else highest(concrete_i)

        reason = label + (f" ({note})" if note else "")
        if applied:
            reason += " [" + "; ".join(applied) + "]"
        conf_why.append(f"{reason}: {c}")
        integ_why.append(f"{label}: {i}")
        triggers.extend(spec.get("regulatory_triggers", []) or [])
        flags.extend(spec.get("flags", []) or [])
        return c, i

    deferred, system_only = [], []
    for entry in selected:
        if types[entry["id"]].get("system_information"):
            # Categorisation follows the business information a system holds.
            # Credentials and secrets are present in nearly every service; if
            # they entered the high water mark, every consumer-facing
            # application would land on the High baseline and no team would act
            # on the result. They still force their own requirements.
            system_only.append(entry)
            continue
        result = evaluate(entry, allow_inherit=False)
        if result is None:
            deferred.append(entry)
            continue
        concrete_c.append(result[0])
        concrete_i.append(result[1])

    for entry in deferred:
        c, i = evaluate(entry, allow_inherit=True)
        concrete_c.append(c)
        concrete_i.append(i)

    for entry in system_only:
        spec = types[entry["id"]]
        conf_why.append(f"{spec['label']}: system information, excluded from the water mark")
        triggers.extend(spec.get("regulatory_triggers", []) or [])
        flags.extend(spec.get("flags", []) or [])

    confidentiality = {"level": highest(concrete_c), "because": conf_why}
    integrity = {"level": highest(concrete_i), "because": integ_why}
    return confidentiality, integrity, sorted(set(flags)), sorted(set(triggers))


def derive_availability(profile: dict, table: dict) -> dict:
    declared = (profile.get("declared") or {}).get("availability")
    if not declared:
        raise ProfileError("declared.availability is empty -- run the interview first (Q2)")

    rto = {b["id"]: b for b in table["rto_buckets"]}
    rpo = {b["id"]: b for b in table["rpo_buckets"]}
    amps = {a["id"]: a for a in table["amplifiers"]}

    levels, why, integrity_hint = [], [], None

    for key, lookup, label in (("rto", rto, "recovery time"), ("rpo", rpo, "recovery point")):
        value = declared.get(key)
        if not value:
            raise ProfileError(f"declared.availability.{key} is missing (Q2)")
        if value not in lookup:
            raise ProfileError(f"unknown {key} bucket {value!r}; see {AVAILABILITY.name}")
        spec = lookup[value]
        levels.append(spec["availability"])
        why.append(f"{spec['label']}: {spec['availability']}")
        if spec.get("integrity_hint"):
            integrity_hint = spec["integrity_hint"]

    for amp_id in declared.get("amplifiers", []) or []:
        if amp_id not in amps:
            raise ProfileError(f"unknown amplifier {amp_id!r}; see {AVAILABILITY.name}")
        spec = amps[amp_id]
        levels.append(spec["availability"])
        why.append(f"{spec['label']}: {spec['availability']}")

    return {"level": highest(levels), "because": why, "integrity_hint": integrity_hint}


# --------------------------------------------------------------------------
# jurisdiction
# --------------------------------------------------------------------------

# Country for the cloud regions seen most often. Deliberately partial: an
# unknown region yields no cross-border claim rather than a guessed one.
REGION_COUNTRY = {
    "ap-northeast-1": "JP", "ap-northeast-2": "KR", "ap-northeast-3": "JP",
    "ap-southeast-1": "SG", "ap-southeast-2": "AU", "ap-south-1": "IN",
    "us-east-1": "US", "us-east-2": "US", "us-west-1": "US", "us-west-2": "US",
    "ca-central-1": "CA", "sa-east-1": "BR",
    "eu-west-1": "IE", "eu-west-2": "UK", "eu-west-3": "FR",
    "eu-central-1": "DE", "eu-north-1": "SE", "eu-south-1": "IT",
    "koreacentral": "KR", "japaneast": "JP", "eastus": "US", "westeurope": "NL",
    "asia-northeast3": "KR", "asia-northeast1": "JP", "us-central1": "US",
    "europe-west1": "BE", "europe-west3": "DE",
}

EU_LIKE = {"EU", "EEA", "DE", "FR", "IE", "NL", "ES", "IT", "SE", "PL", "BE"}


def applies_in_jurisdiction(spec: dict, user_regions: set[str]) -> bool:
    """Whether a regulatory trigger is in scope for this service's users.

    Data type alone is not enough. A service holding contact details for Korean
    and Japanese users should not be told that GDPR applies -- a false trigger
    costs the reader's trust in every other finding.

    A trigger with no ``applies_when`` clause always fires; absent user regions
    also fire, because an unanswered question should surface rather than
    silently suppress a regulation.
    """
    condition = spec.get("applies_when")
    if not condition:
        return True
    if not user_regions:
        return True
    allowed = {r.upper() for r in condition.get("user_regions_any", [])}
    return bool(allowed & user_regions)


def detect_cross_border(profile: dict, user_regions: set[str]) -> dict | None:
    """Flag storage in a country other than where the users are.

    This is the point of interview Q7. v1 raises the question and generates a
    requirement; it does not make the legal determination.
    """
    region = (profile.get("inferred") or {}).get("region_storage")
    if not region or not user_regions:
        return None
    country = REGION_COUNTRY.get(region)
    if not country:
        return {"storage_region": region, "storage_country": None,
                "user_regions": sorted(user_regions), "undetermined": True}
    resident = country in user_regions or (country in EU_LIKE and EU_LIKE & user_regions)
    if resident and len(user_regions) == 1:
        return None
    return {
        "storage_region": region,
        "storage_country": country,
        "user_regions": sorted(user_regions),
        "undetermined": False,
        "offshore_for": sorted(r for r in user_regions if r != country),
    }


# --------------------------------------------------------------------------
# baseline resolution
# --------------------------------------------------------------------------

def load_catalog() -> dict[str, dict]:
    if not CATALOG_DIR.exists():
        raise ProfileError(f"catalog not built; run scripts/rebuild_catalogs.py")
    records = {}
    for path in sorted(CATALOG_DIR.glob("*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                rec = json.loads(line)
                records[rec["id"]] = rec
    return records


def resolve_baseline(baseline: str, catalog: dict) -> tuple[list[dict], list[str]]:
    """Return (bundled controls, identifiers whose family is not bundled).

    Missing families are reported rather than dropped. During the week-1 tracer
    bullet only AC/AU/SC are extracted, and a silent drop would make partial
    coverage look like complete coverage -- exactly the failure this tool is
    supposed to prevent in its own output.
    """
    baselines = json.loads((CATALOG_DIR / "baselines.json").read_text(encoding="utf-8"))
    key = BASELINE_KEY[baseline]
    resolved, unavailable = [], []
    for control_id in baselines[key]:
        if control_id in catalog:
            resolved.append(catalog[control_id])
        else:
            unavailable.append(control_id)
    return resolved, unavailable


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def run(profile: dict) -> dict:
    types_table = yaml.safe_load(DATA_TYPES.read_text(encoding="utf-8"))
    avail_table = yaml.safe_load(AVAILABILITY.read_text(encoding="utf-8"))

    confidentiality, integrity, flags, triggers = derive_confidentiality_integrity(profile, types_table)
    availability = derive_availability(profile, avail_table)

    if availability.pop("integrity_hint", None) == "high":
        integrity["level"] = highest([integrity["level"], "high"])
        integrity["because"].append("no tolerable data loss (RPO 0): high")

    system = highest([confidentiality["level"], integrity["level"], availability["level"]])

    override = (profile.get("derived") or {}).get("impact", {}).get("override")
    overridden = False
    if override:
        if override.get("system") not in LEVELS:
            raise ProfileError(f"invalid impact override {override.get('system')!r}")
        system = override["system"]
        overridden = True

    baseline = BASELINE_FOR_IMPACT[system]
    catalog = load_catalog()
    controls, unavailable = resolve_baseline(baseline, catalog)

    trigger_specs = types_table.get("regulatory_triggers", {})
    user_regions = {r.upper() for r in (profile.get("declared") or {}).get("user_regions", []) or []}

    uncovered = []
    for trigger in triggers:
        spec = trigger_specs.get(trigger, {})
        if spec.get("covered", False):
            continue
        if not applies_in_jurisdiction(spec, user_regions):
            continue
        label = spec.get("label", trigger)
        uncovered.append({
            "id": trigger,
            "label": label,
            "message": spec.get(
                "message",
                f"{label} appears to apply. Not supported by this tool; review separately.",
            ),
        })

    cross_border = detect_cross_border(profile, user_regions)

    return {
        "impact": {
            "confidentiality": confidentiality,
            "integrity": integrity,
            "availability": availability,
            "system": system,
            "overridden_by_user": overridden,
            "override_reason": (override or {}).get("reason"),
        },
        "baseline": baseline,
        "asvs_level": ASVS_FOR_IMPACT[system],
        "threat_flags": flags,
        "regulatory_flags": triggers,
        "uncovered_regulations": uncovered,
        "cross_border": cross_border,
        "controls": [c["id"] for c in controls],
        "controls_unavailable": unavailable,
        "control_count": len(controls),
    }


def render_gate(result: dict) -> str:
    imp = result["impact"]
    out = ["Impact derivation", ""]
    for axis, key in (("Confidentiality", "confidentiality"), ("Integrity", "integrity"), ("Availability", "availability")):
        out.append(f"  {axis:<16}{imp[key]['level'].upper()}")
        for reason in imp[key]["because"]:
            out.append(f"      <- {reason}")
        out.append("")
    out.append(f"  System impact: {imp['system'].upper()}  (high water mark)")
    if imp["overridden_by_user"]:
        out.append(f"  OVERRIDDEN by user: {imp['override_reason'] or 'no reason recorded'}")
    out.append(f"  Baseline: {result['baseline']}  ->  {result['control_count']} controls bundled")
    if result["controls_unavailable"]:
        n = len(result["controls_unavailable"])
        fams = sorted({c.split("-")[0] for c in result["controls_unavailable"]})
        out.append(f"  UNAVAILABLE: {n} baseline controls in families not yet bundled ({', '.join(fams)})")
    out.append(f"  ASVS level: L{result['asvs_level']}")
    if result["uncovered_regulations"]:
        out += ["", "Uncovered regulations detected"]
        for item in result["uncovered_regulations"]:
            out.append(f"  ! {item['message']}")
    cb = result.get("cross_border")
    if cb:
        out += ["", "Cross-border data transfer"]
        if cb["undetermined"]:
            out.append(f"  ? storage region {cb['storage_region']} not in the region map; country undetermined")
        else:
            out.append(
                f"  ! stored in {cb['storage_country']} ({cb['storage_region']}), "
                f"users in {', '.join(cb['offshore_for'])} -- transfer requirements apply"
            )
    if result["threat_flags"]:
        out += ["", f"Threat model flags: {', '.join(result['threat_flags'])}"]
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("profile", type=Path)
    ap.add_argument("--json", type=Path, help="write the full result as JSON")
    args = ap.parse_args()

    profile = yaml.safe_load(args.profile.read_text(encoding="utf-8"))
    try:
        result = run(profile)
    except ProfileError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(render_gate(result))
    if args.json:
        args.json.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"\nwrote {args.json}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
