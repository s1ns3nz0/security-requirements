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

from profile_schema import EEA_MEMBERS, SchemaError, expand_regions, normalise

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


def reads_as_personal(spec: dict, entry: dict, modifiers: dict) -> bool:
    """Whether this declared type counts as personal data here.

    The table's flag is a default and the profile can say it is wrong, the same
    way service_content says the exclusion is wrong. GDPR protects natural
    persons and says nothing about legal ones, so a purchase ledger holding only
    supplier company accounts is not processing personal data -- and the flag,
    set unconditionally, routed exactly that service into the Regulation.
    """
    if not spec.get("personal_data"):
        return False
    for mod_id in (entry.get("modifiers") or []) if isinstance(entry, dict) else []:
        if (modifiers.get(mod_id) or {}).get("not_personal"):
            return False
    return True


def excluded_from_water_mark(spec: dict, entry: dict, modifiers: dict) -> bool:
    """Whether this declared type stays out of the categorisation pools.

    One reader, because the rule has two callers and the repository has been
    caught more than once by a rule written down twice. The second caller is the
    authentication check: a credential store reachable without a caller is the
    worst version of that finding, not an exempt one.
    """
    if not spec.get("system_information"):
        return False
    for mod_id in entry.get("modifiers") or []:
        if (modifiers.get(mod_id) or {}).get("categorises"):
            return False
    return True


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
    # Counted apart from the pools, because the deferred pass writes a
    # categorisation *snapshot* into them for an inheriting axis. A snapshot
    # is a placeholder, not evidence, and counting it made an empty water
    # mark look like a reasoned one.
    evidence_c = evidence_i = 0
    conf_why, integ_why, flags, triggers = [], [], [], []
    modifier_forced = []
    inert_modifiers: list[str] = []

    trigger_specs_local = table.get("regulatory_triggers", {}) or {}

    def personhood_ok(trigger_id: str, entry: dict) -> bool:
        """A regime that protects people is not reached by an organisation's data."""
        if not trigger_specs_local.get(trigger_id, {}).get("requires_natural_person"):
            return True
        return reads_as_personal(types[entry["id"]], entry, modifiers)

    def evaluate(entry, allow_inherit):
        spec = types[entry["id"]]
        label = spec["label"]
        c_raw, i_raw = spec["confidentiality"], spec["integrity"]

        # Deferral is a property of the entry, not of one axis. The test lived
        # inside the confidentiality branch, so a type declaring
        # `integrity: inherit_max` beside a concrete confidentiality was
        # evaluated in the first pass and inherited from a content pool that was
        # not finished being built. No type in the table is shaped that way
        # today, which is why nothing had gone wrong yet -- the machinery simply
        # did not implement the rule it describes.
        if not allow_inherit and "inherit_max" in (c_raw, i_raw):
            return None

        if c_raw == "inherit_max":
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

        applied: list[str] = []
        relative = 0
        absolute: list[tuple[str, str]] = []
        for mod_id in entry.get("modifiers", []) or []:
            if mod_id not in modifiers:
                # The table records why some modifiers are refused, and the
                # reasons are the interesting part -- encryption is the outcome
                # of a requirement, not a property of the data, so accepting it
                # as grounds for reduction lets a requirement delete itself.
                # Read as "unknown", a deliberate refusal looks like a typo, and
                # the next thing the author tries is `encrypted`, then
                # `at_rest`, then a different data type.
                refused = {r["id"]: r["reason"] for r in (table.get("rejected_modifiers") or [])}
                if mod_id in refused:
                    raise ProfileError(
                        f"modifier {mod_id!r} is refused, not missing. "
                        f"{' '.join(refused[mod_id].split())} "
                        f"If the control is real, it belongs in the threat model or the "
                        f"existing_org_controls list, not in the classification."
                    )
                raise ProfileError(
                    f"unknown modifier {mod_id!r}; accepted: "
                    f"{', '.join(sorted(modifiers))}. See {DATA_TYPES.name}"
                )
            mod = modifiers[mod_id]
            # Some modifiers only mean something against a type with a
            # particular property -- service_content overrides the
            # system-information exclusion, legal_entity_only clears the
            # personal-data reading -- and applied elsewhere they did nothing
            # and said nothing. A declaration that has no effect is worth one
            # line, because the author wrote it expecting one.
            required = mod.get("requires")
            if required and not spec.get(required):
                inert_modifiers.append(
                    f"{mod_id} on {entry['id']}: the modifier applies to types marked "
                    f"{required}, and this one is not, so it changed nothing")
            effect = mod.get("effect", {}).get("confidentiality")
            # Collected, not applied here. Applied in order, the same two
            # statements about the same data gave different answers depending
            # on which was typed first: health records with an aggregation
            # modifier and a tokenisation modifier came out High one way and
            # Moderate the other, because a bump that saturates at High loses
            # the excess. And content declared as intended for publication came
            # out Moderate if the aggregation modifier was listed after it,
            # which is the opposite of what the declaration says.
            if isinstance(effect, str) and effect.startswith("="):
                absolute.append((mod_id, effect[1:]))
            elif isinstance(effect, int):
                relative += effect
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

        # The relative effects sum before anything is clamped, so the order they
        # were written in cannot change the total. An absolute assignment is a
        # statement about what the data *is* -- published content is public
        # whatever else is true of it -- so it is applied last and wins.
        if relative:
            c = bump(c, relative)
        if absolute:
            if len({value for _, value in absolute}) > 1:
                raise ProfileError(
                    f"{entry['id']}: {', '.join(m for m, _ in absolute)} each fix the "
                    f"confidentiality level and they disagree "
                    f"({', '.join(sorted({v for _, v in absolute}))}). Two absolute "
                    f"statements about one data type cannot both be true."
                )
            c = absolute[0][1]

        if i_raw == "inherit_max":
            i = highest(content_i)
            categorised_i_here = highest(concrete_i)
            i_note = "inherits highest (" + i + ")"
            if categorised_i_here != i:
                # Without this, the reason line printed a value the answer did
                # not contain -- "audit and access logs: high" under "Integrity
                # LOW" -- and a reader cannot tell whether the number or the
                # reason is the broken one. Confidentiality had explained
                # itself since the exclusion was introduced; integrity was left
                # bare, and the asymmetry was an oversight rather than a
                # distinction.
                i_note += (f"; categorised at {categorised_i_here}, the excess coming "
                           f"from system information")
        else:
            i, i_note = i_raw, None

        reason = label + (f" ({note})" if note else "")
        if applied:
            reason += " [" + "; ".join(applied) + "]"
        conf_why.append(f"{reason}: {c}")
        integ_why.append(f"{label}{f' ({i_note})' if i_note else ''}: {i}")
        triggers.extend(t for t in spec.get("regulatory_triggers", []) or []
                        if personhood_ok(t, entry))
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
        if excluded_from_water_mark(types[entry["id"]], entry, modifiers):
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
            # A deferred entry still knows one of its two answers. Deferral is
            # triggered by whichever axis inherits; the other is in the table and
            # belongs in both pools now, or the store that inherits from it will
            # be told the content is lower than it is. Freezing the pools without
            # this made the answer order-independent and wrong: a log holding
            # model training data inherited low integrity from a table that says
            # moderate.
            #
            # No modifier in the table has an integrity effect, so the integrity
            # value needs none applied. Confidentiality would; no type currently
            # inherits on integrity alone, and if one is added the assertion
            # below will say so rather than quietly using an unmodified value.
            spec = types[entry["id"]]
            if spec["integrity"] != "inherit_max":
                concrete_i.append(spec["integrity"])
                content_i.append(spec["integrity"])
                evidence_i += 1
            if spec["confidentiality"] != "inherit_max":
                raise ProfileError(
                    f"{entry['id']}: a type that inherits on integrity alone needs the "
                    f"modifier effects applied to its confidentiality before it can seed "
                    f"the pools, and that path has never been exercised. Add it to "
                    f"derive_confidentiality_integrity rather than letting the unmodified "
                    f"value through."
                )
            continue
        concrete_c.append(result[0])
        concrete_i.append(result[1])
        evidence_c += 1
        evidence_i += 1
        content_c.append(result[0])
        content_i.append(result[1])

    # The pools are frozen before the second pass rather than grown during it.
    # Grown during it, an inheriting store saw whichever inheriting stores
    # happened to be declared above it: `[audit_logs, ml_training_data]` had the
    # audit log inherit low and `[ml_training_data, audit_logs]` had it inherit
    # moderate. The system level came out the same either way, so nothing was
    # wrong with the answer -- but two people entering the same facts in a
    # different order got documents that explained them differently, and a
    # derivation nobody can reproduce is not evidence of anything.
    #
    # Freezing loses nothing: every deferred entry inherits the same maximum of
    # the concrete content, and a deferred entry that holds another deferred
    # entry's content would have inherited that same maximum anyway.
    frozen_content_c, frozen_content_i = list(content_c), list(content_i)
    frozen_concrete_c, frozen_concrete_i = list(concrete_c), list(concrete_i)
    content_c, content_i = frozen_content_c, frozen_content_i
    concrete_c, concrete_i = frozen_concrete_c, frozen_concrete_i

    resolved_deferred = []
    for entry in deferred:
        categorised_c, categorised_i = highest(concrete_c), highest(concrete_i)
        c, i = evaluate(entry, allow_inherit=True)
        resolved_deferred.append((entry, c, i, categorised_c, categorised_i))

    for entry, c, i, categorised_c, categorised_i in resolved_deferred:
        content_c.append(c)
        content_i.append(i)
        # An inheriting store adds nothing new to categorisation *on the axis it
        # inherits*: it holds a copy of what is already counted, and appending
        # its content level there would launder system information into the
        # water mark.
        #
        # On an axis it does not inherit, it adds exactly what the table says.
        # Applying the snapshot to both axes discarded that: a type is deferred
        # as soon as either axis reads inherit_max, so ml_training_data --
        # confidentiality inherit_max, integrity moderate -- had its declared
        # moderate integrity thrown away. A service holding nothing but model
        # training data derived LOW integrity from a table that says moderate,
        # and a high water mark that can be talked down by the axis next to it
        # is not a high water mark.
        spec = types[entry["id"]]
        concrete_c.append(categorised_c if spec["confidentiality"] == "inherit_max" else c)
        concrete_i.append(categorised_i if spec["integrity"] == "inherit_max" else i)

    # The concrete pools are complete by here: the first pass and the deferred
    # pass have both run, and system information never enters them. So these are
    # the levels the exclusion actually produced.
    derived_c, derived_i = highest(concrete_c), highest(concrete_i)

    for entry in system_only:
        spec = types[entry["id"]]
        # Both axes. Written to confidentiality alone, an identity provider's
        # "Integrity LOW" appeared with no trace of the two high-integrity types
        # that had been dropped to produce it -- the reader could not see the
        # thing that would make them reach for the modifier.
        # The cost belongs on the line, not in a warning somewhere else. A
        # separate check that fires whenever the exclusion mattered fires on
        # eleven of eighteen real profiles, which is noise; a check narrow
        # enough to be read misses a secrets manager entirely. Neither is
        # needed: the reader is already looking at this line, directly under the
        # number it produced, and it costs nothing to say what was dropped.
        for why, axis, level in ((conf_why, "confidentiality", derived_c),
                                 (integ_why, "integrity", derived_i)):
            line = f"{spec['label']}: system information, excluded from the water mark"
            if spec.get(axis) in LEVELS and level in LEVELS and \
                    LEVELS.index(spec[axis]) > LEVELS.index(level):
                line += (f" -- it is {spec[axis]} here, and without it this axis "
                         f"came out {level}")
            why.append(line)
        triggers.extend(t for t in spec.get("regulatory_triggers", []) or []
                        if personhood_ok(t, entry))
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

    # How many declared types the water mark is actually a mark of. `highest([])`
    # returns low, so a profile whose every type either inherits its level or is
    # excluded from categorisation derived LOW with the same confidence as one
    # that had been reasoned about -- and a Kubernetes backup tool, whose whole
    # job is holding copies of everything, is exactly that profile.
    confidentiality = {"level": highest(concrete_c), "because": conf_why,
                       "from_types": evidence_c}
    integrity = {"level": highest(concrete_i), "because": integ_why,
                 "from_types": evidence_i}
    # One requirement per requirement. Two data types can force the same one --
    # customer_owned on both the files and the contact details of a file-sync
    # service is the case that showed it -- and appending per source put the
    # identical obligation into the document twice, differing only in a field
    # the reader never sees. The team owes one set of processor obligations,
    # over both sets of data.
    #
    # Grouped on the whole source, not on the data type. A requirement can be
    # forced by a modifier *and* by the type the modifier sits on -- the two
    # arrive with the same from_data_type and different labels and notes -- and
    # keying on the type alone threw the second of each away.
    grouped: dict[str, dict] = {}
    for item in forced:
        source = {"data_type": item["from_data_type"], "label": item["label"],
                  "note": item.get("note") or ""}
        existing = grouped.get(item["id"])
        if existing is None:
            grouped[item["id"]] = {"id": item["id"], "sources": [source]}
        elif source not in existing["sources"]:
            existing["sources"].append(source)

    ordered = []
    for item in grouped.values():
        sources = item["sources"]
        ordered.append({
            "id": item["id"],
            "sources": sources,
            # Derived from `sources` every time rather than stored beside it.
            # Two writable copies of one fact is the defect this repository
            # keeps finding, and it was introduced here while fixing a
            # duplication problem.
            "from_data_types": list(dict.fromkeys(s["data_type"] for s in sources)),
            "label": "; ".join(dict.fromkeys(s["label"] for s in sources)),
            "note": "\n\n".join(n for n in dict.fromkeys(s["note"] for s in sources) if n),
        })

    return (confidentiality, integrity, sorted(set(flags)), sorted(set(triggers)),
            ordered, inert_modifiers)


def derive_availability(profile: dict, table: dict) -> dict:
    declared = (profile.get("declared") or {}).get("availability")
    if not declared:
        raise ProfileError("declared.availability is empty -- run the interview first (Q2)")

    rto = {b["id"]: b for b in table["rto_buckets"]}
    rpo = {b["id"]: b for b in table["rpo_buckets"]}
    amps = {a["id"]: a for a in table["amplifiers"]}

    levels, why, integrity_hint = [], [], None
    conflicts: list[str] = []

    for key, lookup, label in (("rto", rto, "recovery time"), ("rpo", rpo, "recovery point")):
        value = declared.get(key)
        if not value:
            raise ProfileError(
                f"declared.availability.{key} is missing (Q2); "
                f"accepted: {', '.join(lookup)}"
            )
        if value not in lookup:
            # Naming the file is not naming the answer. `rto_days` and
            # `rpo_none` are both things a person writes -- days is a real
            # recovery objective and an append-only log genuinely has no
            # recovery point -- and neither is a bucket. Sending the author to
            # open a catalogue to find that out costs a round trip for a
            # one-word fix, which is why the modifier check stopped doing it.
            raise ProfileError(
                f"unknown {key} bucket {value!r}; accepted: {', '.join(lookup)}. "
                f"See {AVAILABILITY.name}"
            )
        spec = lookup[value]
        levels.append(spec["availability"])
        why.append(f"{spec['label']}: {spec['availability']}")
        if spec.get("integrity_hint"):
            integrity_hint = spec["integrity_hint"]

    declared_amps = list(declared.get("amplifiers", []) or [])
    for amp_id in declared_amps:
        spec_alone = amps.get(amp_id) or {}
        if spec_alone.get("only_when_alone") and len(set(declared_amps)) > 1:
            others = ", ".join(sorted(set(declared_amps) - {amp_id}))
            # No claim about what the other amplifiers mean. Revenue, an SLA,
            # and a downstream dependency say nothing about whether a manual
            # fallback exists -- an internal tool can have one and still stop
            # revenue when it breaks. What is true is only that this answer
            # cannot lower anything while another raises it, and that the
            # reason list will show both.
            conflicts.append(
                f"{amp_id} contributed nothing: it lowers availability and {others} "
                f"raises it. The reason list below shows both, which is worth a look -- "
                f"an answer given early in the interview is sometimes not the one the "
                f"author would give at the end of it.")
    for amp_id in declared_amps:
        if amp_id not in amps:
            raise ProfileError(
                f"unknown amplifier {amp_id!r}; accepted: {', '.join(amps)}. "
                f"See {AVAILABILITY.name}"
            )
        spec = amps[amp_id]
        levels.append(spec["availability"])
        why.append(f"{spec['label']}: {spec['availability']}")

    return {"level": highest(levels), "because": why, "integrity_hint": integrity_hint,
            "conflicts": conflicts}


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

# The European Economic Area, in full. Written as a partial list it reported
# storage in Austria, Finland, or Estonia as an offshore transfer away from EU
# users -- the opposite of the free movement the Regulation establishes, and a
# requirement the reader would have spent money on.
EEA = EEA_MEMBERS
# The two placeholders a profile may write instead of naming a member state.
EU_LIKE = EEA | {"EU", "EEA"}

# Countries this tool will accept as a storage location. Deliberately a set
# rather than a shape test: `len(region) == 2 and region.isalpha()` turned "AP"
# -- an Asia Pacific abbreviation, not a country -- into a definite country, and
# turned an undetermined location into a positive transfer finding. Guessing in
# the direction of a finding is the failure this repository exists to prevent.
COUNTRY_CODES = EEA | {
    "GB", "CH", "US", "CA", "MX", "BR", "AR", "CL",
    "KR", "JP", "CN", "TW", "HK", "SG", "MY", "TH", "VN", "ID", "PH", "IN",
    "AU", "NZ", "ZA", "NG", "KE", "EG", "IL", "AE", "SA", "TR", "UA", "RU",
}
# Spellings people use for a country the standard codes something else.
COUNTRY_ALIASES = {"UK": "GB", "EL": "GR"}


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
    # Both sides expanded: a rule naming EEA must match a profile that says BE,
    # and a profile saying EU must match a rule that names member states.
    allowed = expand_regions(condition.get("user_regions_any", []))
    user_regions = expand_regions(user_regions)
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
    # A country code is the answer for anything not in a cloud region, and an
    # on-premise service has no cloud region to give. The map held provider
    # region codes only, so `region_storage: KR` -- exactly the vocabulary
    # `user_regions` uses two lines further down the same profile -- came back
    # "not in the region map" and switched cross-border detection off. Every
    # on-premise profile tested hit it.
    country = REGION_COUNTRY.get(region)
    if not country:
        candidate = COUNTRY_ALIASES.get(region.upper(), region.upper())
        if candidate in COUNTRY_CODES:
            country = candidate
    if not country:
        return {"storage_region": region, "storage_country": None,
                "user_regions": sorted(user_regions), "undetermined": True}
    # Storage inside the EEA is not a transfer for a user anywhere else in it.
    # Computed per user region rather than against the storage country alone:
    # with storage in Germany and users in France and Japan, only Japan is on
    # the far side of a border that matters, and the first version reported
    # France as well.
    def offshore(user_region: str) -> bool:
        if user_region == country:
            return False
        return not (country in EEA and user_region in EU_LIKE)

    offshore_for = sorted(r for r in user_regions if offshore(r))
    if not offshore_for:
        return None
    return {
        "storage_region": region,
        "storage_country": country,
        "user_regions": sorted(user_regions),
        "undetermined": False,
        "offshore_for": offshore_for,
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

    (confidentiality, integrity, flags, triggers, forced,
     inert_modifiers) = derive_confidentiality_integrity(profile, types_table)
    availability = derive_availability(profile, avail_table)

    # Whatever level the bucket declares, not only "high". The catalogue's one
    # hint says moderate -- losing committed records is a serious effect, not the
    # severe or catastrophic one FIPS 199 reserves for High -- and the comparison
    # against "high" dropped it, silently, on the systems that care most. The
    # note in availability.yaml said integrity was raised to Moderate and it was
    # not, which is worse than either behaviour on its own: the catalogue
    # documented an effect the derivation did not have.
    hint = availability.pop("integrity_hint", None)
    if hint in LEVELS:
        raised = highest([integrity["level"], hint])
        if raised != integrity["level"]:
            integrity["level"] = raised
            integrity["because"].append(
                f"no tolerable data loss (RPO 0): {hint}")

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
    personal = [
        (e["id"] if isinstance(e, dict) else e)
        for e in (profile.get("declared") or {}).get("data_types", [])
        if reads_as_personal(types_table_types.get(e["id"] if isinstance(e, dict) else e, {}),
                             e if isinstance(e, dict) else {},
                             types_table.get("modifiers", {}))
    ]
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
    baselines = json.loads((CATALOG_DIR / "baselines.json").read_text(encoding="utf-8"))
    if personal:
        for control_id in baselines["privacy"]:
            (privacy_controls if control_id in catalog else privacy_unavailable).append(control_id)

    # The programme layer applies to every derivation, at every impact level,
    # because SP 800-53B assigns the PM family to no baseline: it is
    # implemented once for the organisation rather than per system. It is kept
    # out of the baseline count deliberately -- these are not requirements the
    # delivery team takes on, and folding thirty-seven of them into a team's
    # list would bury the ones that are.
    program_controls = [c for c in baselines["program"] if c in catalog]
    program_unavailable = [c for c in baselines["program"] if c not in catalog]

    trigger_specs = types_table.get("regulatory_triggers", {})
    user_regions = {r.upper() for r in (profile.get("declared") or {}).get("user_regions", []) or []}

    uncovered, overlays, in_scope_triggers = [], [], []
    for trigger in triggers:
        spec = trigger_specs.get(trigger, {})
        # Jurisdiction first. `covered` says this repository already addresses
        # the regime, not that the regime stopped applying, and skipping before
        # the gate kept it out of the flag list the gate is supposed to define.
        if not applies_in_jurisdiction(spec, user_regions):
            continue
        in_scope_triggers.append(trigger)
        if spec.get("covered", False):
            continue
        label = spec.get("label", trigger)
        # A trigger with an overlay is no longer an admission of no coverage.
        # Leaving it in the uncovered list after the overlay exists would keep
        # declaring a gap the repository has since closed.
        if spec.get("overlay"):
            # One entry per overlay, not per trigger. Two triggers routing to the
            # same regime printed it twice under different names -- "GDPR" and
            # "GDPR Article 9 special category data" -- each pointing at the same
            # command. What the reader needs is one overlay and the reasons it
            # applies, not the same overlay twice.
            #
            # One list, not a list plus a singular first element beside it. The
            # first version kept `trigger`/`label` "for compatibility", which
            # made them a second writable copy that silently answered a question
            # -- which regimes reached this overlay -- with only part of the
            # truth.
            existing = next((o for o in overlays if o["id"] == spec["overlay"]), None)
            if existing is None:
                overlays.append({"id": spec["overlay"],
                                 "triggers": [{"id": trigger, "label": label}]})
            elif trigger not in [t["id"] for t in existing["triggers"]]:
                existing["triggers"].append({"id": trigger, "label": label})
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

    # The union of the three layers, not the impact baseline alone. Written as
    # the baseline alone, the other two were computed, printed, and then
    # dropped: a service processing EU users' personal data was told "Privacy
    # baseline: 96 controls" while the fifty-three privacy-only controls -- the
    # whole PT family among them -- never reached the responsibility split, the
    # merge, or any overlay. `control_count` below stays the impact baseline's
    # own count, because that is what it names.
    #
    # Built by appending rather than by sorting a set: set iteration order is
    # not stable across runs, and an unstable control order would make two
    # derivations of the same profile diff against each other.
    derived_controls = [c["id"] for c in controls]
    seen = set(derived_controls)
    for control_id in privacy_controls + program_controls:
        if control_id not in seen:
            seen.add(control_id)
            derived_controls.append(control_id)

    shape = detect_shape(profile)

    # The modifier only helps if somebody reaches for it, and the record here
    # says they do not: intended_public existed for months before a public
    # training repository derived a 370-control baseline because nobody used it.
    #
    # What the exclusion cost is now printed on the reason line for every
    # profile, beside the number it produced, so this is left as the one case
    # where the derived answer is most likely to be wrong and most expensive if
    # it is: account credentials excluded while an axis they are high on
    # collapsed all the way to low.
    #
    # A second rule was tried and removed. It fired when nothing but system
    # information survived categorisation, treating inheriting stores as
    # non-survivors -- which told a backup service that its secrets were what it
    # existed for. An inheriting store has no level of its own, but it can
    # certainly be the product, and no arrangement of the data types tells the
    # two apart.
    excluded_here = [
        e for e in (profile.get("declared") or {}).get("data_types", [])
        if isinstance(e, dict) and e.get("id") == "account_credentials"
        and excluded_from_water_mark(types_table_types.get(e["id"], {}), e,
                                     types_table.get("modifiers", {}))
    ]
    if excluded_here:
        spec = types_table_types["account_credentials"]
        for axis, level in (("confidentiality", confidentiality["level"]),
                            ("integrity", integrity["level"])):
            if spec.get(axis) == "high" and level == "low":
                consistency.append(
                    f"account credentials were excluded from the categorisation as "
                    f"incidental system information, and {axis} came out low without "
                    f"them. Holding credentials and existing for them are different "
                    f"services. If this is the second, add the service_content modifier "
                    f"and re-run -- the derivation is reading it as the first.")
                break

    # Q5 asks what regulation or contractual obligation is already fixed, and
    # the answer went nowhere. A profile naming SOC 2 and ISO 27001 listed
    # neither under the overlays that apply, because routing came only from the
    # data types -- and an elective regime has no data type to route from. That
    # is what elective means. The eighth field found in this repository that was
    # gathered, written down, and read by nobody.
    stated = (profile.get("declared") or {}).get("regulations_declared") or []
    if stated:
        import apply_overlay  # the matcher lives with the thing it matches
        for overlay_dir in sorted((REPO_ROOT / "overlays").iterdir()):
            meta_path = overlay_dir / "meta.yaml"
            if not meta_path.exists():
                continue
            meta = yaml.safe_load(meta_path.read_text(encoding="utf-8"))
            if apply_overlay.elective_declared(meta, stated) and \
                    meta["id"] not in {o["id"] for o in overlays}:
                declared_trigger = f"declared:{meta['id']}"
                overlays.append({"id": meta["id"],
                                 "triggers": [{"id": declared_trigger,
                                               "label": meta.get("name", meta["id"])}]})
                # An elective regime is in scope once it is named, and the flag
                # list said otherwise: a profile declaring SOC 2 had it in
                # applicable_overlays and nowhere in regulatory_flags.
                in_scope_triggers.append(declared_trigger)

    # A regime this tool does not model is not a regime that does not exist. The
    # overlay list is the tool's coverage, and printed alone it reads as the
    # answer: a microfinance platform holding national identifiers and
    # biometrics for Indian, Kenyan, and Philippine users was shown GDPR and
    # nothing else, with no sign that three of its four jurisdictions had simply
    # not been looked at.
    # Built from the general data-protection regimes only -- the ones that reach
    # any personal data, marked all_personal_data -- not from any trigger that
    # happens to name a country. Built the wide way, the United States counted
    # as modelled because HIPAA and COPPA mention it, so a service holding
    # ordinary contact details for American users got no overlay and no word
    # about why.
    modelled = set()
    for spec in (types_table.get("regulatory_triggers") or {}).values():
        if not spec.get("all_personal_data"):
            continue
        modelled |= expand_regions((spec.get("applies_when") or {}).get("user_regions_any") or [])
    modelled = expand_regions(modelled)
    # Country codes, not two-character strings. This file already records why
    # shape is not a country: "AP" is an Asia Pacific abbreviation, and telling
    # someone that most jurisdictions like AP have a data protection regime is
    # worse than saying nothing.
    unmodelled = sorted(r for r in expand_regions(user_regions)
                        if r not in modelled and r in COUNTRY_CODES)
    if personal and unmodelled:
        consistency.append(
            f"this tool models no data protection regime for {', '.join(unmodelled)}, and "
            f"personal data is declared for users there. The overlay list below is this "
            f"repository's coverage, not a finding that nothing applies -- most of these "
            f"jurisdictions have one.")

    consistency.extend(inert_modifiers)
    consistency.extend(availability.pop("conflicts", None) or [])

    # Per axis, not only when both are empty. A profile of nothing but model
    # training data has genuine integrity evidence and none at all for
    # confidentiality, and requiring both to be empty let that confidentiality
    # LOW go on presenting itself as an answer.
    unanswered = [name for name, axis in (("confidentiality", confidentiality),
                                          ("integrity", integrity))
                  if not axis["from_types"]]
    if unanswered:
        declared_ids = ", ".join(
            sorted(e["id"] if isinstance(e, dict) else str(e)
                   for e in (profile.get("declared") or {}).get("data_types", []))) or "nothing"
        axes = " and ".join(unanswered)
        consistency.append(
            f"nothing declared here carries a {axes} level of its own. {declared_ids} "
            f"either inherit theirs from content, or are system information kept out of "
            f"the water mark, so LOW on {'those axes' if len(unanswered) > 1 else 'that axis'} "
            f"is the absence of an answer rather than an answer. A backup of a High system "
            f"is a High system. Declare what is being held or copied and re-run.")

    # `auth_mechanism` was gathered by the interview, given a rule of its own in
    # the schema so that `none` would survive normalisation -- "the service has
    # no authentication, which is a finding rather than a gap in the interview"
    # -- and then read by nothing. The distinction was carefully preserved and
    # carefully discarded. It is the seventh field of this kind found here.
    #
    # Where a service is served and no authentication was recorded, that is
    # worth one line. It is not worth a control: whether the absence is right
    # depends on what the entrypoints do, which a profile cannot settle.
    auth = (profile.get("inferred") or {}).get("auth_mechanism")
    if shape["shape"] in ("service", "service_assumed"):
        if auth is None:
            consistency.append(
                "no auth_mechanism was recorded for a served entrypoint. Nothing below "
                "changes either way -- the field selects no control -- but an unanswered "
                "question and an answer of `none` are different facts, and only one of "
                "them is a finding. Write `auth_mechanism: none` if that is the answer.")
        elif str(auth).strip().lower() == "none":
            # `any(intended_public)` was the wrong quantifier and it failed in
            # the direction that reassures: a profile declaring published
            # documentation *alongside* health records derived HIGH
            # confidentiality and was told its unauthenticated reads were
            # consistent. The question is not whether something here is public,
            # it is whether anything here is not.
            #
            # Asked of the table it was still wrong, in the other direction: a
            # transparency log declares audit_logs, whose table value is
            # inherit_max, and inheriting from published content it comes out
            # low. The answer already exists -- it is the confidentiality this
            # derivation just produced, after modifiers, inheritance, and the
            # system-information exclusion. Anything else is a second opinion
            # that can disagree with the number on the page.
            declared_public = any(
                "intended_public" in (e.get("modifiers") or [])
                for e in (profile.get("declared") or {}).get("data_types", [])
                if isinstance(e, dict))
            # Both halves are needed and each was wrong on its own. The modifier
            # alone let one published document vouch for a service that also
            # holds health records. The derived level alone called internal
            # operational data "already declared as intended for publication",
            # which it is not -- low is not public.
            published = declared_public and confidentiality["level"] == "low"
            # Deliberately not the water-mark predicate. That one answers
            # "does this type decide the categorisation"; this one answers "is
            # this something a caller without a name could reach", and sharing
            # a predicate between them let incidental API keys drop out of a
            # finding about an unauthenticated endpoint -- which is one of the
            # ways secrets actually leak. Everything declared is assumed
            # reachable unless the profile says it is published.
            confidential = [
                e["id"] for e in (profile.get("declared") or {}).get("data_types", [])
                if isinstance(e, dict)
                and "intended_public" not in (e.get("modifiers") or [])
            ] if not published else []
            if published:
                # Telling an author to declare what they have already declared
                # is how a check teaches people to skim past it. A transparency
                # log reads without authentication by design; what it still
                # cannot do without one is tell two writers apart.
                consistency.append(
                    "no authentication, on content already declared as intended for "
                    "publication -- consistent, for reading. Any entrypoint that changes "
                    "state still needs a caller it can name, and the requirements below "
                    "cannot tell which of the entrypoints those are.")
            else:
                named = ", ".join(sorted(confidential))
                consistency.append(
                    "the service is served and declares no authentication. Every "
                    "requirement below that assumes an identified caller -- session "
                    "handling, least privilege, per-user audit -- has nothing to attach "
                    "to."
                    + (f" Not everything here is published: {named}."
                       " If those are not reachable without a caller, the profile is not"
                       " saying so." if named else
                       " If the entrypoints are genuinely public, say so against the"
                       " data types instead."))

    return {
        "impact": impact,
        "baseline": baseline,
        "shape": shape,
        "asvs_level": ASVS_FOR_IMPACT[system] if shape["app_surface"] else None,
        "threat_flags": flags,
        "forced_requirements": forced,
        "schema_warnings": schema_warnings,
        "consistency_warnings": consistency,
        # Only what survived the jurisdiction gate. Emitted raw, it listed the
        # Korean regimes against every service that holds personal data,
        # whatever country its users are in -- and nothing reads this field, so
        # nothing was ever going to correct the impression.
        "regulatory_flags": in_scope_triggers,
        "uncovered_regulations": uncovered,
        "applicable_overlays": sorted({o["id"] for o in overlays}),
        "overlay_triggers": overlays,
        "cross_border": cross_border,
        # The union, not the impact baseline alone. Written as the baseline
        # alone, the two other layers were computed, printed, and then dropped:
        # a service processing EU users' personal data was told "Privacy
        # baseline: 96 controls" while the fifty-three privacy-only controls --
        # the whole PT family among them -- never reached the responsibility
        # split, the merge, or any overlay. `control_count` below stays the
        # impact baseline's own count, because that is what it names.
        "controls": derived_controls,
        "privacy_controls": privacy_controls,
        "privacy_baseline_applies": bool(personal),
        "personal_data_types": personal,
        # Published so the merge can hold the threat model and the profile
        # against each other. They are two descriptions of one system, and
        # nothing compared them: this repository's own golden threat model names
        # an asset its golden profile does not declare.
        "declared_data_types": sorted(
            (e["id"] if isinstance(e, dict) else e)
            for e in (profile.get("declared") or {}).get("data_types", [])),
        "program_controls": program_controls,
        "program_unavailable": program_unavailable,
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

    if result.get("program_controls"):
        out.append(f"  Programme layer:  {len(result['program_controls'])} controls "
                   f"(PM family -- organisational, selected at every impact level)")

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
            reasons = item["triggers"]
            out.append(f"  + {reasons[0]['label']}  ->  scripts/apply_overlay.py {item['id']}")
            for extra in reasons[1:]:
                out.append(f"      also reached by: {extra['label']}")
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
                f"  ! stored in {cb['storage_country']}"
                + (f" ({cb['storage_region']})"
                   if cb["storage_region"].upper() != cb["storage_country"] else "") + ", "
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
