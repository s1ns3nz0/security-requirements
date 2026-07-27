#!/usr/bin/env python3
"""Normalise a service profile before anything reasons about it.

Why this exists
---------------
Every rule downstream compares a user-authored string against a fixed set:
`deployment_model` against the layer keys, `user_regions` against a trigger's
jurisdiction list, `region_storage` against the region map, modifier and control
identifiers against their catalogues. Each comparison was written as an exact
match, and each therefore failed on the spelling a person would naturally use.

Probing the value space turned up five at once, and three of them failed
silently in the dangerous direction:

    entrypoints: "http: api"     a string is iterable, so the shape detector saw
                                 characters and concluded the profile was not a
                                 service. ASVS suppressed for an HTTP API.
    user_regions: "KR"           became {"K", "R"}, matched no jurisdiction, and
                                 suppressed every regulatory trigger.
    region_storage: AP-NORTHEAST-2   missed the region map, so a cross-border
                                 transfer went unreported.
    deployment_model: IaaS       unrecognised, disabling the model layer.
    existing_org_controls: [SSO] unrecognised, losing the annotations that stop
                                 the tool demanding what the organisation has.

Scattering `.lower()` through the call sites would fix the five and leave the
sixth to be found later. Normalising once, here, makes the class of defect
unreachable.

A coercion is reported rather than performed quietly. A scalar where a list
belongs usually means the author misread the schema, and the next field they
filled in is probably wrong too.
"""

from __future__ import annotations


class SchemaError(ValueError):
    """A profile field holds something no amount of coercion can rescue.

    Raised rather than dropped: silently discarding a malformed data type
    changes the derivation, and the reader would never learn that it had.
    """

# Fields that are lists. A scalar is accepted and wrapped, with a warning.
LIST_FIELDS = [
    ("inferred", "entrypoints"),
    ("inferred", "managed_services"),
    ("inferred", "external_integrations"),
    ("inferred", "stack"),
    ("declared", "data_types"),
    ("declared", "users"),
    ("declared", "user_regions"),
    ("declared", "existing_org_controls"),
    ("declared", "regulations_declared"),
]

# Fields compared against a fixed lower-case vocabulary.
LOWER_FIELDS = [
    ("inferred", "deployment_model"),
    ("inferred", "region_storage"),
    ("inferred", "auth_mechanism"),
]

# `auth_mechanism: none` says the service has no authentication, which is a
# finding rather than a gap in the interview. Collapsing it into the same value
# as "we did not establish this" would lose the distinction.
SENTINEL_EXEMPT = {("inferred", "auth_mechanism")}

LOWER_LIST_FIELDS = [
    ("declared", "existing_org_controls"),
    ("declared", "users"),
]

# Region codes are conventionally upper case and are compared as such.
UPPER_LIST_FIELDS = [("declared", "user_regions")]

# Spellings people use for a deployment model that the layer file keys
# differently. Kept small and obvious; an unknown value still warns rather than
# being guessed at.
# The schema tells an author to write UNDETERMINED where inference failed and
# they do not know. Treating that as a value rather than as the absence of one
# produced messages like "region UNDETERMINED is not in the region map", which
# reads as though it were a place.
SENTINELS = {"undetermined", "unknown", "tbd", "n/a", "na", "none", "?", "-"}

MODEL_ALIASES = {
    "k8s": "kubernetes",
    "kube": "kubernetes",
    "eks": "kubernetes",
    "aks": "kubernetes",
    "gke": "kubernetes",
    "on-prem": "onprem",
    "on_prem": "onprem",
    "on-premise": "onprem",
    "on-premises": "onprem",
    "bare-metal": "onprem",
    "vm": "iaas",
    "ec2": "iaas",
    "lambda": "serverless",
    "faas": "serverless",
    "device": "embedded",
    "firmware": "embedded",
    "iot": "embedded",
}


def _get(profile: dict, section: str) -> dict | None:
    value = profile.get(section)
    return value if isinstance(value, dict) else None


def normalise(profile: dict) -> tuple[dict, list[str]]:
    """Return (profile, warnings). The profile is modified in place."""
    warnings: list[str] = []

    for section, field in LIST_FIELDS:
        block = _get(profile, section)
        if not block or field not in block:
            continue
        value = block[field]
        if value is None:
            block[field] = []
        elif not isinstance(value, list):
            block[field] = [value]
            warnings.append(
                f"{section}.{field} was a single value where a list belongs; "
                f"read as one item. Check the rest of the profile for the same slip."
            )

    for section, field in LOWER_FIELDS:
        block = _get(profile, section)
        if not block:
            continue
        value = block.get(field)
        if isinstance(value, str):
            cleaned = value.strip().lower()
            sentinel = cleaned in SENTINELS and (section, field) not in SENTINEL_EXEMPT
            block[field] = None if sentinel else cleaned

    for section, field in LOWER_LIST_FIELDS:
        block = _get(profile, section)
        if not block:
            continue
        value = block.get(field)
        if isinstance(value, list):
            block[field] = [v.strip().lower() if isinstance(v, str) else v for v in value]

    for section, field in UPPER_LIST_FIELDS:
        block = _get(profile, section)
        if not block:
            continue
        value = block.get(field)
        if isinstance(value, list):
            bad = [v for v in value if not isinstance(v, str)]
            if bad:
                raise SchemaError(
                    f"{section}.{field} contains {bad[0]!r} ({type(bad[0]).__name__}); "
                    f"region codes must be strings"
                )
            block[field] = [v.strip().upper() for v in value]

    inferred = _get(profile, "inferred")
    if inferred:
        model = inferred.get("deployment_model")
        if isinstance(model, str) and model in MODEL_ALIASES:
            inferred["deployment_model"] = MODEL_ALIASES[model]

        # Service identifiers become filenames under responsibility/services/.
        # Left as written, `AWS-S3` resolved to the curated file on a
        # case-insensitive filesystem and to nothing on a case-sensitive one, so
        # the same profile produced different responsibility splits on macOS and
        # on Linux. Trailing space lost the curation outright.
        services = inferred.get("managed_services")
        if isinstance(services, list):
            seen: set[str] = set()
            deduped = []
            for entry in services:
                if isinstance(entry, str):
                    entry = {"id": entry}
                elif isinstance(entry, dict):
                    entry = dict(entry)
                else:
                    raise SchemaError(
                        f"inferred.managed_services contains {entry!r} "
                        f"({type(entry).__name__}); each entry must be an identifier "
                        f"or a mapping with an `id`"
                    )
                if isinstance(entry.get("id"), str):
                    entry["id"] = entry["id"].strip().lower()
                if entry.get("id") in seen:
                    warnings.append(
                        f"managed service {entry['id']!r} was declared more than once; "
                        f"the duplicate was dropped."
                    )
                    continue
                seen.add(entry.get("id"))
                deduped.append(entry)
            inferred["managed_services"] = deduped

    declared = _get(profile, "declared")
    if declared:
        entries = declared.get("data_types")
        if isinstance(entries, list):
            rebuilt = []
            for entry in entries:
                if isinstance(entry, str):
                    entry = {"id": entry}
                elif isinstance(entry, dict):
                    entry = dict(entry)
                else:
                    raise SchemaError(
                        f"declared.data_types contains {entry!r} ({type(entry).__name__}); "
                        f"each entry must be an identifier or a mapping with an `id`"
                    )
                if isinstance(entry.get("id"), str):
                    entry["id"] = entry["id"].strip().lower()
                mods = entry.get("modifiers")
                if mods is not None and not isinstance(mods, list):
                    entry["modifiers"] = [mods]
                    warnings.append(
                        f"data type {entry['id']!r} had a single modifier where a list "
                        f"belongs; read as one item."
                    )
                if isinstance(entry.get("modifiers"), list):
                    entry["modifiers"] = [
                        m.strip().lower() if isinstance(m, str) else m
                        for m in entry["modifiers"]
                    ]
                rebuilt.append(entry)
            declared["data_types"] = rebuilt

        availability = declared.get("availability")
        if isinstance(availability, dict):
            for key in ("rto", "rpo"):
                if isinstance(availability.get(key), str):
                    availability[key] = availability[key].strip().lower()
            amps = availability.get("amplifiers")
            if amps is not None and not isinstance(amps, list):
                availability["amplifiers"] = [amps]
                warnings.append(
                    "declared.availability.amplifiers was a single value where a list "
                    "belongs; read as one item."
                )
            if isinstance(availability.get("amplifiers"), list):
                availability["amplifiers"] = [
                    a.strip().lower() if isinstance(a, str) else a
                    for a in availability["amplifiers"]
                ]

    return profile, warnings


# --------------------------------------------------------------------------
# jurisdiction vocabulary
# --------------------------------------------------------------------------
#
# Which countries are in the Union was written down three times -- the
# cross-border residency set, the GDPR trigger's region list, and the GDPR
# overlay's -- with thirty, eleven, and twenty members. A service with users in
# Belgium, Austria, Denmark, Finland, Portugal, Greece, Hungary, Romania, or
# Czechia was told the Regulation did not reach it, which is a false negative on
# a regulation for a third of the member states.
#
# The data files already write EEA and EU where they mean the bloc. They were
# being compared as literal strings, so they matched only a profile that wrote
# the bloc's name instead of a country. Expanding them here makes the three
# lists agree by construction rather than by maintenance.
EU_MEMBERS = {
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR",
    "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK",
    "SI", "ES", "SE",
}

# Iceland, Liechtenstein, and Norway are in the Area and not in the Union.
# Mapping both tokens to the same set made "EU" mean thirty states. Nothing
# depended on the difference today, because every rule naming EU also names
# EEA -- which is exactly the condition under which a wrong primitive sits
# quietly until the first rule that needs it.
EEA_MEMBERS = EU_MEMBERS | {"IS", "LI", "NO"}

REGION_GROUPS = {
    "EU": EU_MEMBERS,
    "EEA": EEA_MEMBERS,
}

# Spellings of one country. GB is the ISO 3166-1 code for the United Kingdom and
# UK is what people write; the rules were written with UK and the profiles with
# GB, so the correct code was the one that failed. It cost the United Kingdom's
# GDPR trigger on every profile that used it -- and the cross-border check had
# the alias already, which is how one half of the tool came to disagree with the
# other about which countries exist.
COUNTRY_SPELLINGS = {"UK": "GB", "GB": "UK", "EL": "GR", "GR": "EL"}


def expand_regions(regions) -> set[str]:
    """Resolve bloc names to their members, leaving country codes alone.

    Applied to both sides of a jurisdiction comparison: a rule that says EEA
    must match a profile that says BE, and a profile that says EU must match a
    rule that names only member states.
    """
    out: set[str] = set()
    for region in regions or []:
        code = str(region).strip().upper()
        out.add(code)
        out |= REGION_GROUPS.get(code, set())
    # Spellings applied after expansion, not during it. Applied only to what was
    # written, expanding EU produced GR without EL, so a Greek profile was told
    # no regime is modelled for EL -- a country it had just been matched as.
    for code in list(out):
        alias = COUNTRY_SPELLINGS.get(code)
        if alias:
            out.add(alias)
    return out
