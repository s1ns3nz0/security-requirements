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

from profile_schema import SchemaError, normalise

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

import re

# Two different questions, and conflating them was the defect.
#
#   shape        is this a running system at all, or a library, a tool, or a
#                set of definitions? Decided by what it is NOT, because the
#                things that are not services form a short closed list while
#                the protocols and languages a service can speak do not.
#   app_surface  does it expose an application surface ASVS is written for?
#                Decided on evidence, because ASVS is a web and API standard
#                and issuing a level for a Modbus gateway asserts an applicable
#                standard that is not.
#
# The first version asked only the first question, with an allow-list of web
# protocol keywords. An MQTT broker client, a Kafka consumer, and an endpoint
# described in Chinese all read as "not a service", which suppressed the ASVS
# level for the ones that deserved it and printed a note calling a running
# system a library.
NON_SERVICE_RE = re.compile(
    r"\blibrar(y|ies)\b|\bimport\b|\bcli\b|\bcommand[- ]line\b|\bsdk\b"
    r"|\bmodule\b|\bpackage\b|\bbinary\b|\bdefinitions?\b|\bmanifests?\b"
    r"|\bterraform\b|\bhelm chart\b|\bdocumentation\b",
    re.IGNORECASE,
)

# Evidence of an application surface: a protocol ASVS speaks about, or a web
# framework in the stack, which carries the same meaning when the entrypoints
# are written in a language this list does not cover.
APP_SURFACE_RE = re.compile(
    r"\bhttps?\b|\bwebhook\b|\bgraphql\b|\bgrpc\b|\bwebsocket\b|\brest\b"
    r"|\bapi\b|\bui\b|\bGET\b|\bPOST\b|\bPUT\b|\bDELETE\b|\broute\b|\bendpoint\b",
    re.IGNORECASE,
)
# Positive evidence that something is served: a transport, a port, a path, or a
# word describing a listener. Neither an allow-list of protocols nor a
# block-list of non-services is complete -- probing both showed each failing on
# ordinary input in opposite directions. Where neither fires, the derivation
# proceeds on the assumption of a service and says that it assumed.
SERVED_RE = re.compile(
    r"\bhttps?\b|\bgrpc\b|\bmqtt\b|\bamqp\b|\bkafka\b|\bwebsocket\b|\bsmtp\b"
    r"|\bsftp\b|\bftp\b|\bssh\b|\bsoap\b|\budp\b|\btcp\b|\bmodbus\b|\bcoap\b"
    r"|\bsip\b|\bwebhook\b|\bgraphql\b|\bqueue\b|\btopic\b|\bport\b|\bendpoint\b"
    r"|\blistens?\b|\bserver\b|\bscheduler\b|\bworker\b|\bdaemon\b|\bconsumer\b"
    r"|\bGET\b|\bPOST\b|\bPUT\b|\bDELETE\b|:\d{2,5}\b|\s/\S",
    re.IGNORECASE,
)

WEB_STACK = {
    "spring-boot", "spring", "django", "flask", "fastapi", "rails", "express",
    "nextjs", "next.js", "nuxt", "laravel", "gin", "echo", "aspnet", "asp.net",
    "phoenix", "actix", "axum", "rocket", "sinatra", "koa", "nestjs", "streamlit",
}


def detect_shape(profile: dict) -> dict:
    """Whether the profile describes a running system, and whether it has an
    application surface. Two questions, answered separately -- see above."""
    inferred = profile.get("inferred") or {}
    entrypoints = inferred.get("entrypoints") or []
    stack = {str(s).strip().lower() for s in inferred.get("stack") or []}

    if not entrypoints:
        shape = "no_entrypoints"
    elif all(NON_SERVICE_RE.search(str(e)) for e in entrypoints):
        # Every entrypoint names something that is not a served system. One
        # HTTP route alongside a CLI still makes it a service.
        shape = "non_service"
    elif any(SERVED_RE.search(str(e)) for e in entrypoints):
        shape = "service"
    else:
        # Nothing said it is not a service, and nothing said it is. Assume one,
        # because the alternative suppresses findings, but do not pretend the
        # question was answered.
        shape = "service_assumed"

    has_app_surface = (
        any(APP_SURFACE_RE.search(str(e)) for e in entrypoints)
        or bool(stack & WEB_STACK)
    )
    return {"shape": shape,
            "app_surface": has_app_surface and shape in ("service", "service_assumed")}


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
    modifier_forced = []

    def evaluate(entry, allow_inherit):
        spec = types[entry["id"]]
        label = spec["label"]
        c_raw, i_raw = spec["confidentiality"], spec["integrity"]

        if c_raw == "inherit_max":
            if not allow_inherit:
                return None
            # Two numbers for one store. `c` is what it actually holds, which is
            # what a requirement about protecting it must reflect. What it
            # contributes to categorisation is computed separately below, from
            # the water-mark pool only -- otherwise credentials launder through
            # a backup into the system level and defeat their exclusion.
            c = highest(content_c)
            categorised = highest(concrete_c)
            note = "inherits highest (" + c + ")"
            if categorised != c:
                note += (f"; categorised at {categorised}, the excess coming from "
                         f"system information")
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
            # Modifiers may demand a requirement of their own. `customer_owned`
            # is the case that motivated it: the level does not move, but the
            # duties owed to the owner are not reachable from any control keyed
            # on "we hold data of type X".
            for req_id in mod.get("forces_requirements", []) or []:
                modifier_forced.append({
                    "id": req_id,
                    "from_data_type": entry["id"],
                    "label": f"{label} [{mod['label']}]",
                    "note": (mod.get("note") or "").strip(),
                })

        i = i_raw if i_raw != "inherit_max" else highest(content_i)

        reason = label + (f" ({note})" if note else "")
        if applied:
            reason += " [" + "; ".join(applied) + "]"
        conf_why.append(f"{reason}: {c}")
        integ_why.append(f"{label}: {i}")
        triggers.extend(spec.get("regulatory_triggers", []) or [])
        flags.extend(spec.get("flags", []) or [])
        return c, i

    # Two pools, because they answer different questions.
    #
    #   concrete_*  what the system is categorised on. System information is
    #               excluded: credentials live in nearly every service, and
    #               counting them puts everything on the High baseline.
    #   content_*   what is actually inside a store. A backup of a system whose
    #               only content is secrets is as sensitive as those secrets,
    #               whatever the categorisation rule says.
    #
    # Collapsing them made `backups` alongside `config_secrets` derive Low: the
    # exclusion leaked out of categorisation and into inheritance.
    content_c, content_i = [], []

    deferred, system_only = [], []
    for entry in selected:
        if types[entry["id"]].get("system_information"):
            spec = types[entry["id"]]
            if spec["confidentiality"] != "inherit_max":
                content_c.append(spec["confidentiality"])
            if spec["integrity"] != "inherit_max":
                content_i.append(spec["integrity"])
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
        content_c.append(result[0])
        content_i.append(result[1])

    for entry in deferred:
        categorised_c, categorised_i = highest(concrete_c), highest(concrete_i)
        c, i = evaluate(entry, allow_inherit=True)
        content_c.append(c)
        content_i.append(i)
        # An inheriting store adds nothing new to categorisation: it holds a
        # copy of what is already counted. Appending its content level would
        # launder system information into the water mark.
        concrete_c.append(categorised_c)
        concrete_i.append(categorised_i)

    for entry in system_only:
        spec = types[entry["id"]]
        conf_why.append(f"{spec['label']}: system information, excluded from the water mark")
        triggers.extend(spec.get("regulatory_triggers", []) or [])
        flags.extend(spec.get("flags", []) or [])

    # Requirements a data type demands regardless of what the threat model
    # found. These address failures that are common and easy to miss, and they
    # are the only path by which system-information types reach the output at
    # all -- having been excluded from the water mark, they would otherwise
    # vanish entirely.
    forced = list(modifier_forced)
    for entry in selected:
        spec = types[entry["id"]]
        for req_id in spec.get("forces_requirements", []) or []:
            forced.append({
                "id": req_id,
                "from_data_type": entry["id"],
                "label": spec["label"],
                "note": (spec.get("note") or spec.get("rationale") or "").strip(),
            })

    confidentiality = {"level": highest(concrete_c), "because": conf_why}
    integrity = {"level": highest(concrete_i), "because": integ_why}
    return confidentiality, integrity, sorted(set(flags)), sorted(set(triggers)), forced


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
        # Either the storage region was never established or there are no user
        # regions to compare it against. Saying nothing is right: a transfer
        # question needs both ends.
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


def single_axis_driver(impact: dict, system: str) -> dict | None:
    """Identify a level set by one axis alone, and say what it costs.

    The high water mark is the rule, but it hides which answer did the work. A
    document store whose data is Low on both confidentiality and integrity can
    still land on Moderate because it should recover within the business day --
    and that single interview answer is the difference between 149 controls and
    287. The reader has to be told which answer to challenge, or the only
    reviewable thing about the categorisation is its conclusion.
    """
    axes = {
        "confidentiality": impact["confidentiality"]["level"],
        "integrity": impact["integrity"]["level"],
        "availability": impact["availability"]["level"],
    }
    at_system = [name for name, level in axes.items() if level == system]
    if len(at_system) != 1:
        return None

    driver = at_system[0]
    others = [level for name, level in axes.items() if name != driver]
    without = highest(others)
    if without == system:
        return None

    baselines = json.loads((CATALOG_DIR / "baselines.json").read_text(encoding="utf-8"))
    return {
        "axis": driver,
        "level": system,
        "level_without": without,
        "baseline_without": BASELINE_FOR_IMPACT[without],
        "control_count": len(baselines[BASELINE_KEY[BASELINE_FOR_IMPACT[system]]]),
        "control_count_without": len(baselines[BASELINE_KEY[BASELINE_FOR_IMPACT[without]]]),
        "reasons": impact[driver]["because"],
    }


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
    profile, schema_warnings = normalise(profile)
    types_table = yaml.safe_load(DATA_TYPES.read_text(encoding="utf-8"))
    avail_table = yaml.safe_load(AVAILABILITY.read_text(encoding="utf-8"))

    confidentiality, integrity, flags, triggers, forced = derive_confidentiality_integrity(profile, types_table)
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

    # A service holding personal data is inside a privacy regime, and the
    # controls that regime needs are allocated to the SP 800-53B privacy
    # baseline rather than to any security one. Resolved separately rather than
    # merged: it does not change the FIPS 199 categorisation, and folding it in
    # would inflate the security baseline count it is not part of.
    types_table_types = {t["id"]: t for t in types_table["types"]}
    personal = [e["id"] for e in (profile.get("declared") or {}).get("data_types", [])
                if types_table_types.get(e["id"] if isinstance(e, dict) else e, {}).get("personal_data")]
    # A trigger marked all_personal_data follows the classification table's
    # personal_data flag rather than waiting to be named by each type. Written
    # the other way round, the GDPR trigger reached three of the nine types the
    # table calls personal data, so a service holding user content, biometrics,
    # or health records went unrouted.
    if personal:
        for name, spec in (types_table.get("regulatory_triggers") or {}).items():
            if spec.get("all_personal_data") and name not in triggers:
                triggers.append(name)
        triggers = sorted(set(triggers))
    privacy_controls, privacy_unavailable = ([], [])
    if personal:
        baselines = json.loads((CATALOG_DIR / "baselines.json").read_text(encoding="utf-8"))
        for control_id in baselines["privacy"]:
            (privacy_controls if control_id in catalog else privacy_unavailable).append(control_id)

    trigger_specs = types_table.get("regulatory_triggers", {})
    user_regions = {r.upper() for r in (profile.get("declared") or {}).get("user_regions", []) or []}

    uncovered, overlays = [], []
    for trigger in triggers:
        spec = trigger_specs.get(trigger, {})
        if spec.get("covered", False):
            continue
        if not applies_in_jurisdiction(spec, user_regions):
            continue
        label = spec.get("label", trigger)
        # A trigger with an overlay is no longer an admission of no coverage.
        # Leaving it in the uncovered list after the overlay exists would keep
        # declaring a gap the repository has since closed.
        if spec.get("overlay"):
            overlays.append({"id": spec["overlay"], "trigger": trigger, "label": label})
            continue
        uncovered.append({
            "id": trigger,
            "label": label,
            "message": spec.get(
                "message",
                f"{label} appears to apply. Not supported by this tool; review separately.",
            ),
        })

    cross_border = detect_cross_border(profile, user_regions)

    impact = {
        "confidentiality": confidentiality,
        "integrity": integrity,
        "availability": availability,
        "system": system,
        "overridden_by_user": overridden,
        "override_reason": (override or {}).get("reason"),
    }
    impact["driver"] = None if overridden else single_axis_driver(impact, system)

    # A public repository whose source is declared confidential is a
    # contradiction the profile already contains the evidence for. Found on an
    # open-source training tool that derived a 370-control baseline because
    # nobody reached for the intended_public modifier.
    consistency = []
    visibility = str((profile.get("repo") or {}).get("visibility", "")).strip().upper()
    if visibility == "PUBLIC":
        for entry in (profile.get("declared") or {}).get("data_types", []):
            entry = {"id": entry} if isinstance(entry, str) else entry
            if entry.get("id") == "source_code_ip" and "intended_public" not in (entry.get("modifiers") or []):
                consistency.append(
                    "the repository is public, but its source is declared as confidential "
                    "intellectual property. Add the intended_public modifier, or say why the "
                    "published code is not the asset being protected.")

    shape = detect_shape(profile)

    return {
        "impact": impact,
        "baseline": baseline,
        "shape": shape,
        "asvs_level": ASVS_FOR_IMPACT[system] if shape["app_surface"] else None,
        "threat_flags": flags,
        "forced_requirements": forced,
        "schema_warnings": schema_warnings,
        "consistency_warnings": consistency,
        "regulatory_flags": triggers,
        "uncovered_regulations": uncovered,
        "applicable_overlays": sorted({o["id"] for o in overlays}),
        "overlay_triggers": overlays,
        "cross_border": cross_border,
        "controls": [c["id"] for c in controls],
        "privacy_controls": privacy_controls,
        "privacy_baseline_applies": bool(personal),
        "personal_data_types": personal,
        "controls_unavailable": unavailable,
        "control_count": len(controls),
    }


def render_gate(result: dict) -> str:
    imp = result["impact"]
    out = []
    for warning in result.get("schema_warnings", []):
        out.append(f"  NOTE: {warning}")
    for warning in result.get("consistency_warnings", []):
        out.append(f"  CHECK: {warning}")
    if out:
        out.append("")
    out += ["Impact derivation", ""]
    for axis, key in (("Confidentiality", "confidentiality"), ("Integrity", "integrity"), ("Availability", "availability")):
        out.append(f"  {axis:<16}{imp[key]['level'].upper()}")
        for reason in imp[key]["because"]:
            out.append(f"      <- {reason}")
        out.append("")
    out.append(f"  System impact: {imp['system'].upper()}  (high water mark)")
    if imp["overridden_by_user"]:
        out.append(f"  OVERRIDDEN by user: {imp['override_reason'] or 'no reason recorded'}")

    driver = imp.get("driver")
    if driver:
        # What to re-examine differs by axis, and saying "check that answer" for
        # confidentiality is misleading: nobody answered a question about the
        # level, they selected data types and the table did the rest.
        what = ("the recovery objectives you gave" if driver["axis"] == "availability"
                else "the data types you declared")
        out += [
            "",
            f"  Set by {driver['axis']} alone. The other two axes are lower.",
            f"  Without it the system would be {driver['level_without'].upper()} "
            f"-- {driver['control_count_without']} controls instead of {driver['control_count']}.",
            f"  Before confirming, re-examine {what}:",
        ]
        out += [f"      <- {reason}" for reason in driver["reasons"]]
    out.append(f"  Baseline: {result['baseline']}  ->  {result['control_count']} controls bundled")
    if result["controls_unavailable"]:
        n = len(result["controls_unavailable"])
        fams = sorted({c.split("-")[0] for c in result["controls_unavailable"]})
        out.append(f"  UNAVAILABLE: {n} baseline controls in families not yet bundled ({', '.join(fams)})")
    if result["asvs_level"] is not None:
        out.append(f"  ASVS level: L{result['asvs_level']}")
    else:
        out.append("  ASVS: not applicable -- no application surface in the entrypoints")

    if result.get("privacy_baseline_applies"):
        out.append(f"  Privacy baseline: {len(result['privacy_controls'])} controls "
                   f"(personal data declared: {', '.join(result['personal_data_types'])})")

    shape = result.get("shape", {})
    if shape.get("shape") == "service_assumed":
        out += [
            "",
            "  NOTE: nothing in the entrypoints says this is served, and nothing says",
            "  it is not. The derivation proceeds as though it were a service. If it is",
            "  a library, a set of fixtures, or a generator, say so in the entrypoints",
            "  and re-run -- most of the result will not apply.",
        ]
    elif shape.get("shape") != "service":
        reason = ("no entrypoints were found" if shape.get("shape") == "no_entrypoints"
                  else "the entrypoints describe a library, CLI, or definitions, not a served application")
        out += [
            "",
            f"  NOTE: this does not look like a running service -- {reason}.",
            "  The derivation is service-shaped; application-layer controls in the",
            "  result may not apply to this repository. Read it as the requirements",
            "  for the system this code defines or is embedded in, not for the",
            "  repository itself.",
        ]
    if result.get("applicable_overlays"):
        out += ["", "Regulatory overlays that apply"]
        for item in result["overlay_triggers"]:
            out.append(f"  + {item['label']}  ->  scripts/apply_overlay.py {item['id']}")
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

    if result.get("forced_requirements"):
        out += ["", "Requirements forced by the declared data types",
                "  (generated regardless of what the threat model finds)"]
        for item in result["forced_requirements"]:
            out.append(f"  * {item['id']}  <- {item['label']}")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("profile", type=Path)
    ap.add_argument("--json", type=Path, help="write the full result as JSON")
    args = ap.parse_args()

    profile = yaml.safe_load(args.profile.read_text(encoding="utf-8"))
    try:
        result = run(profile)
    except (ProfileError, SchemaError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(render_gate(result))
    if args.json:
        args.json.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"\nwrote {args.json}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
