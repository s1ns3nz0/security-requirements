#!/usr/bin/env python3
"""Assign responsibility for each baseline control.

Pipeline step 6. Deterministic: a lookup against responsibility/layers.yaml,
overridden by responsibility/services/*.yaml for the managed services the
profile actually uses.

The output is the filter that makes the deliverable usable. A Moderate baseline
is roughly 290 controls; a delivery team is typically responsible for a
fraction of that. Handing over the unfiltered list is how these documents get
discarded.

Two rules the classification must not break:

* Inheritance is a claim, not a fact. Anything marked csp_claimed carries the
  evidence a reader must obtain to substantiate it. The tool does not assert
  that the provider performs the control.
* Uncurated services are marked, not guessed silently. A service with no file
  under responsibility/services/ is reported as unverified so the reader knows
  which parts of the matrix to check.

Usage
-----
    python3 -I "<absolute plugin root>/scripts/classify_resp.py" PROFILE CONTROLS_JSON [--json OUT]

where CONTROLS_JSON is the output of select_baseline.py --json.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from profile_schema import normalise
from runtime_paths import inspected_project_root, plugin_data_root
from safe_paths import (
    UnsafePathError,
    preflight_output_paths,
    safe_path,
    safe_write_text,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
LAYERS = REPO_ROOT / "responsibility" / "layers.yaml"
SERVICES_DIR = REPO_ROOT / "responsibility" / "services"
SERVICE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

BUCKETS = ["team", "shared", "csp_claimed", "org", "undetermined"]

# Team involvement, most to least. Used when two services disagree about the
# same control: the more demanding answer wins, because under-assigning work to
# the team is the failure mode that leaves a gap unowned.
PRECEDENCE = {"team": 3, "shared": 2, "csp_claimed": 1, "org": 0}


def service_path(base: Path, service_id: str) -> Path:
    candidate = base / f"{service_id}.yaml"
    if candidate.exists():
        try:
            candidate.resolve().relative_to(base.resolve())
        except ValueError as exc:
            raise ValueError(
                f"{service_id!r} escapes service curation directory"
            ) from exc
    return candidate

# Organisational controls a profile may declare as already in place. Used to
# annotate, never to delete: the control still has to be answered at audit,
# it is simply answered by someone other than the delivery team.
# What interview question six actually puts in the profile. The question offers
# seven checkboxes and the coverage table below is keyed on five short names,
# and not one of the labels matched a key -- so a profile produced by following
# the documented interview had every answer silently discarded, and the tool
# went on demanding centralised authentication from teams that had said they run
# company-wide SSO. That is the one outcome the question exists to prevent.
ORG_CONTROL_ALIASES = {
    "company-wide sso / identity provider": "sso",
    "company-wide sso": "sso",
    "identity provider": "sso",
    "single sign-on": "sso",
    "centralised log collection": "central_logging",
    "centralized log collection": "central_logging",
    "centralised logging": "central_logging",
    "centralized logging": "central_logging",
    "information security policy set": "security_policy",
    "security policy": "security_policy",
    "periodic access review process": "access_review",
    "access review": "access_review",
    "incident response process": "incident_response",
    "dedicated security function": "security_function",
    "security team": "security_function",
    "none of these yet": None,
    "none": None,
}


def normalise_org_controls(declared: list) -> tuple[set[str], list[str]]:
    """Return (recognised keys, entries nothing could be made of).

    Unrecognised entries are reported rather than dropped. Dropped, a
    misspelling and a considered answer look identical, and the reader is told
    nothing about why the requirement they already satisfy is still on the list.
    """
    keys, unknown = set(), []
    for raw in declared or []:
        text = " ".join(str(raw).strip().lower().split())
        if text in ORG_CONTROL_ALIASES:
            mapped = ORG_CONTROL_ALIASES[text]
            if mapped:
                keys.add(mapped)
            continue
        if text.replace(" ", "_") in ORG_CONTROL_COVERAGE:
            keys.add(text.replace(" ", "_"))
            continue
        unknown.append(str(raw))
    return keys, unknown


ORG_CONTROL_COVERAGE = {
    # What a declared organisational capability actually discharges -- not what
    # it supports. The first version claimed company-wide SSO discharged AC-2
    # (account lifecycle), AC-7 (unsuccessful logon enforcement), and AC-12
    # (session termination), all of which the application still has to do. That
    # promoted a fact about the organisation into a finding about the service,
    # which is the failure this repository exists to prevent, and it did it by
    # deleting work from the delivery team's list.
    #
    # An entry belongs here only if the capability performs the control, not if
    # it makes the control easier.
    "sso": [
        # The identity provider performs identification and authentication. What
        # the application does with the resulting identity is its own problem
        # and stays on its list.
        "IA-2", "IA-2(1)", "IA-2(2)", "IA-8",
    ],
    "central_logging": [
        # Review and analysis are the collection platform's, and so is
        # correlation across sources. Protecting the application's own audit
        # records is not -- AU-9 stayed off this list deliberately.
        "AU-6", "AU-6(1)", "AU-6(3)",
    ],
    "access_review": [
        # A periodic review process is exactly AC-2(3) and AC-6(7). AC-2(4) is
        # automated auditing of account actions, which is the system's.
        "AC-2(3)", "AC-6(7)",
    ],
    "incident_response": [
        # The incident controls themselves. AU-5 was here and is not an incident
        # process -- it is the system's response to an audit processing failure.
        "IR-4", "IR-5", "IR-6", "IR-8",
    ],
    "security_policy": [
        # The policy controls of each family. A policy set is what they ask for.
        "AC-1", "AU-1", "SC-1",
    ],
    "security_function": [
        # A standing security function is the role PM-2 asks for. It is not the
        # programme plan (PM-1) and not risk-management leadership (PM-29):
        # having a team does not produce either document.
        "PM-2",
    ],
}


# ClassifyError was defined here and caught in main(), and raised nowhere. A
# handler for an exception nothing throws advertises a safety net that does not
# exist: a malformed profile surfaced as a KeyError with a traceback, past the
# except clause that looked like it was there to catch exactly that. Removed
# rather than given something to catch, because what should be an error here has
# not been decided, and inventing one to justify the handler is the wrong order.


# Providers whose shared responsibility model this repository can reason about.
KNOWN_PROVIDERS = {"aws", "azure", "gcp", "oci", "alibaba", "ibm", "tencent"}

# What a provider is called in the place the profile is inferred from. A
# Terraform block says `provider "azurerm"`, never `provider "azure"`, so the
# vocabulary that matters is the one in the source rather than the one in the
# shared responsibility documentation. Every name here was taken from a real
# repository: terragoat alone declares aws, azurerm, google, alicloud, and oci.
PROVIDER_ALIASES = {
    "azurerm": "azure", "azuread": "azure", "azurestack": "azure",
    "microsoft-azure": "azure", "az": "azure",
    "google": "gcp", "google-beta": "gcp", "googlecloud": "gcp",
    "google-cloud": "gcp", "gcloud": "gcp",
    "alicloud": "alibaba", "aliyun": "alibaba", "alibabacloud": "alibaba",
    "oraclecloud": "oci", "oracle": "oci",
    "amazon": "aws", "amazonaws": "aws", "aws-cn": "aws",
    "ibmcloud": "ibm", "tencentcloud": "tencent",
}

# Ways a person writes "there is no cloud provider". The first version of the
# no-provider rule matched the literal string "none" and nothing else, so every
# other spelling silently restored inheritance claims against a provider that
# does not exist -- the bug it had just been written to fix.
NO_PROVIDER = {
    "", "none", "no", "n/a", "na", "null", "nil", "-",
    "self-hosted", "selfhosted", "onprem", "on-prem", "on-premise",
    "on-premises", "bare-metal", "baremetal", "colo", "datacenter",
}


def resolve_csp(raw) -> tuple[str | None, list[str], str]:
    """Normalise the declared provider.

    Returns (provider, providers, status) where status is one of `single`,
    `multiple`, `none`, or `unrecognised`.

    An unrecognised value is treated as no provider rather than as a valid one.
    The rule elsewhere is that a claim needs a claimant: if the provider cannot
    be identified, no evidence can be named for it, so no inheritance can be
    asserted.
    """
    if raw is None:
        return None, [], "none"
    values = raw if isinstance(raw, (list, tuple)) else [raw]
    cleaned = [str(v).strip().lower() for v in values if str(v).strip() != ""]
    named = [PROVIDER_ALIASES.get(v, v) for v in cleaned if v not in NO_PROVIDER]
    if not named:
        return None, [], "none"

    # Keep what was recognised. Discarding the whole list because one member is
    # unknown throws away information the profile supplied -- a repository
    # declaring aws alongside an unfamiliar provider still has a shared
    # responsibility model for the aws half.
    recognised = [v for v in dict.fromkeys(named) if v in KNOWN_PROVIDERS]
    unknown = [v for v in dict.fromkeys(named) if v not in KNOWN_PROVIDERS]
    if not recognised:
        return None, named, "unrecognised"
    if unknown:
        return recognised[0], recognised, "partial"
    if len(recognised) > 1:
        return recognised[0], recognised, "multiple"
    return recognised[0], recognised, "single"


def load_services(
    profile: dict,
    csp: str | None = None,
    providers: list[str] | None = None,
    project_root: Path | None = None,
) -> tuple[dict, list[str], list[str], list[str]]:
    """Return (service specs, curated ids, uncurated ids, foreign ids).

    Each curated file records the provider it describes, and until now nothing
    compared that against the provider the profile names. A profile saying
    ``csp: gcp`` while listing ``aws-s3`` took AWS's split -- forty controls
    claimed by a provider, carrying AWS's evidence references -- and put them in
    a document about a Google deployment, with nothing said. Copied profiles and
    half-finished migrations both produce exactly that.

    Reported rather than dropped: the profile may be genuinely multi-cloud, and
    the curation is still the best answer for the service it describes. What is
    not acceptable is that nobody is told.
    """
    declared = (profile.get("inferred") or {}).get("managed_services", []) or []
    known = {p for p in (providers or []) if p} or ({csp} if csp else set())
    inspected_project = (project_root or Path.cwd()).resolve()
    state_root = (
        plugin_data_root(project_root=inspected_project) if declared else None
    )
    specs, curated, uncurated, foreign = {}, [], [], []
    for entry in declared:
        sid = entry["id"] if isinstance(entry, dict) else entry
        if not isinstance(sid, str) or not SERVICE_ID_RE.fullmatch(sid):
            raise ValueError(f"unsafe managed service identifier: {sid!r}")
        path = service_path(SERVICES_DIR, sid)
        generated = safe_path(
            state_root / "responsibility" / "services" / f"{sid}.yaml",
            project_root=state_root,
        )
        resolved_generated = generated.resolve()
        if resolved_generated == inspected_project or resolved_generated.is_relative_to(
            inspected_project
        ):
            raise ValueError("generated service curation must remain outside the project")
        if not path.exists() and generated and generated.exists():
            path = generated
        if not path.exists():
            uncurated.append(sid)
            continue
        spec = yaml.safe_load(path.read_text(encoding="utf-8"))
        specs[sid] = spec
        (curated if spec.get("reviewed") else uncurated).append(sid)
        owner = spec.get("provider")
        if known and owner and owner not in known:
            foreign.append(f"{sid} describes {owner}")
    return specs, curated, uncurated, foreign


def entry_applies(detail: dict, deployment_model: str | None) -> bool:
    """Whether a curated control entry holds for this deployment model.

    Several services answer differently depending on how they are run. ECS is
    the clearest: on Fargate the provider isolates tasks and patches the host,
    on the EC2 launch type it does neither. Encoding that only in a prose note
    means the classifier asserts provider inheritance for a deployment where it
    does not hold -- the exact failure this tool exists to prevent, committed by
    its own curation.

    An entry with no `applies_when` holds everywhere.
    """
    condition = detail.get("applies_when")
    if not condition:
        return True
    models = condition.get("deployment_model")
    if not models:
        return True
    if deployment_model is None:
        return False
    return deployment_model in models


def resolve_layer(control_id: str, layers: dict, deployment_model: str | None) -> tuple[str | None, str | None]:
    """Return (responsibility, source) for a control, most specific rule first.

    Family defaults carry the bulk of the mapping so that a new control in a
    known family resolves to something defensible rather than UNDETERMINED, and
    the override lists stay short enough to review.
    """
    models = layers.get("deployment_models", {})
    if deployment_model and deployment_model in models:
        overrides = models[deployment_model].get("overrides", {}) or {}
        if control_id in overrides:
            return overrides[control_id], f"layers.yaml:{deployment_model}"

    control_overrides = layers.get("control_overrides", {}) or {}
    if control_id in control_overrides:
        return control_overrides[control_id], "layers.yaml:control"

    # An enhancement with no rule of its own follows its base control.
    if "(" in control_id:
        base = control_id.split("(")[0]
        if deployment_model and deployment_model in models:
            overrides = models[deployment_model].get("overrides", {}) or {}
            if base in overrides:
                return overrides[base], f"layers.yaml:{deployment_model}"
        if base in control_overrides:
            return control_overrides[base], "layers.yaml:control"

    family_defaults = layers.get("family_defaults", {}) or {}
    family = control_id.split("-")[0]
    if family in family_defaults:
        return family_defaults[family], "layers.yaml:family"

    return None, None


def apply_no_provider_rule(responsibility: str, csp: str | None) -> str:
    """Collapse the two-party outcomes when there is no second party.

    Extracted so that it is a rule rather than a line inside one function.
    Anything that reasons about who owns a control -- the overlay report's
    org_only bucket among them -- has to apply it, or it will tell a
    self-hosted service that a provider owns something no provider is running.
    """
    if csp is not None:
        return responsibility
    if responsibility == "csp_claimed":
        return "org"
    if responsibility == "shared":
        return "team"
    return responsibility


def classify(
    profile: dict, controls: list[str], project_root: Path | None = None
) -> dict:
    profile, _ = normalise(profile)
    layers = yaml.safe_load(LAYERS.read_text(encoding="utf-8"))
    deployment_model = (profile.get("inferred") or {}).get("deployment_model")
    csp, providers, csp_status = resolve_csp((profile.get("inferred") or {}).get("csp"))

    specs, curated, uncurated, foreign = load_services(
        profile, csp, providers, project_root=project_root
    )
    org_controls, unknown_org_controls = normalise_org_controls(
        (profile.get("declared") or {}).get("existing_org_controls"))
    org_covered = {c for key in org_controls for c in ORG_CONTROL_COVERAGE.get(key, [])}

    results = []
    for control_id in controls:
        layer_answer, layer_source = resolve_layer(control_id, layers, deployment_model)
        entry = {
            "control": control_id,
            "responsibility": layer_answer or "undetermined",
            "source": layer_source,
            "services": [],
            "unverified": False,
        }

        for sid, spec in specs.items():
            detail = (spec.get("controls") or {}).get(control_id)
            if not detail:
                continue
            if not entry_applies(detail, deployment_model):
                # The service curates this control, but not for how it is being
                # deployed. Fall through to the layer rather than asserting an
                # inheritance that does not hold here.
                continue
            entry["services"].append({
                "service": sid,
                "display_name": spec.get("display_name", sid),
                "responsibility": detail["responsibility"],
                "csp_part": detail.get("csp_part"),
                "team_part": detail.get("team_part"),
                "evidence": detail.get("evidence", []),
                "verification": detail.get("verification"),
                "note": detail.get("note"),
                "reviewed": bool(spec.get("reviewed")),
            })
            if not spec.get("reviewed"):
                entry["unverified"] = True

        if entry["services"]:
            best = max(entry["services"], key=lambda s: PRECEDENCE.get(s["responsibility"], 0))
            entry["responsibility"] = best["responsibility"]
            entry["source"] = f"services/{best['service']}.yaml"

        if control_id in org_covered and entry["responsibility"] in ("org", "team", "shared"):
            # Annotated *and* reclassified, which is what the interview schema
            # has always said happens: "an existing control does not delete the
            # requirement. It is classified as org and annotated." Only the
            # annotation was ever applied, so a team running company-wide SSO
            # still got centralised authentication on its own list -- the exact
            # outcome question six exists to prevent.
            entry["org_control_declared"] = True
            # `shared` is never reclassified. A division has two parties, and an
            # organisational capability answers the organisation's half -- it
            # does not stand in for the team's. Moving the whole control erased
            # work that genuinely exists, and on a profile with no provider it
            # also jumped the rule that would otherwise have given the ownerless
            # half back to the team.
            if entry["responsibility"] == "team":
                entry["responsibility_before_org_control"] = "team"
                entry["responsibility"] = "org"
                entry["source"] = f"{entry['source']}+declared-org-control"

        # A claim needs a claimant, and a division needs two parties. With no
        # cloud provider in the profile neither csp_claimed nor shared is a
        # legal outcome: the facility, the hardware, and the media are the
        # organisation's own, and where a control was split between a provider
        # and the team, the team holds both halves.
        #
        # The csp_claimed half of this was fixed when an on-premise sweep found
        # fifteen controls assigned to a provider that does not exist. The
        # shared half survived, and a self-hosted Kubernetes profile carried
        # forty-eight controls shared with nobody.
        without_provider = apply_no_provider_rule(entry["responsibility"], csp)
        if without_provider != entry["responsibility"]:
            entry["responsibility"] = without_provider
            entry["source"] = f"{entry['source']}+no-csp"

        results.append(entry)

    counts = {b: 0 for b in BUCKETS}
    for entry in results:
        counts[entry["responsibility"]] = counts.get(entry["responsibility"], 0) + 1

    # An unrecognised deployment model silently disables every model override
    # and every applies_when condition -- a typo degrades the whole layer with
    # no visible symptom. Found by sweeping a profile that said "kubernetes",
    # which is not a model this map knows.
    known_models = set((layers.get("deployment_models") or {}).keys())
    unknown_model = (deployment_model is not None and deployment_model not in known_models)

    # A deployment model that presumes a provider, declared with no provider, is
    # incoherent -- and it resolves silently, because the no-csp rule then
    # converts every inherited control to organisational. Found on a static site
    # profile that said saas with csp: none and produced 156 organisational
    # controls without comment.
    # Kubernetes is not on this list. It runs on bare metal, on kind, on k3s in
    # a cupboard -- naming it alongside the models that genuinely presume a
    # provider told every self-hosted cluster its profile was incoherent.
    PROVIDER_MODELS = {"serverless", "paas", "saas"}
    inconsistent = (deployment_model in PROVIDER_MODELS and csp is None)

    return {
        "deployment_model": deployment_model,
        "deployment_model_recognised": not unknown_model,
        "csp": csp,
        "csp_status": csp_status,
        "csp_declared": providers,
        "csp_model_inconsistent": inconsistent,
        "known_deployment_models": sorted(known_models),
        "services_curated": sorted(curated),
        "services_uncurated": sorted(uncurated),
        "services_foreign": sorted(foreign),
        "org_controls_recognised": sorted(org_controls),
        "org_controls_unrecognised": unknown_org_controls,
        "counts": counts,
        "controls": results,
    }


def render(result: dict) -> str:
    counts = result["counts"]
    total = sum(counts.values())
    out = ["Responsibility split", ""]
    if result.get("csp_status") == "unrecognised":
        out += [
            f"  WARNING: provider {', '.join(result['csp_declared'])!r} is not one this repository",
            f"  reasons about ({', '.join(sorted(KNOWN_PROVIDERS))}). No inheritance was claimed,",
            f"  because a claim with no identifiable claimant carries no evidence.",
            "",
        ]
    elif result.get("csp_status") == "partial":
        out += [
            f"  WARNING: some declared providers are not ones this repository reasons about.",
            f"  Recognised: {', '.join(result['csp_declared'])}. The split below reflects",
            f"  {result['csp']} only, and nothing is claimed for the rest.",
            "",
        ]
    elif result.get("csp_status") == "multiple":
        out += [
            f"  WARNING: several providers declared ({', '.join(result['csp_declared'])}).",
            f"  The split below reflects {result['csp']} only. Shared responsibility differs",
            f"  per provider, so derive once per provider rather than reading this as covering all.",
            "",
        ]
    if result.get("csp_model_inconsistent"):
        out += [
            f"  WARNING: deployment model {result['deployment_model']!r} presumes a cloud provider,",
            f"  but the profile declares csp: {result.get('csp')!r}. Controls that would be",
            f"  inherited were reassigned to the organisation instead. Set the provider,",
            f"  or use a model that does not presume one.",
            "",
        ]
    if not result.get("deployment_model_recognised", True):
        out += [
            f"  WARNING: deployment model {result['deployment_model']!r} is not recognised.",
            f"  Model overrides and per-service conditions were NOT applied; the split",
            f"  below uses family defaults and control overrides only.",
            f"  Known models: {', '.join(result['known_deployment_models'])}.",
            "",
        ]
    labels = {
        "team": "team implements",
        "shared": "shared (both parties act)",
        "csp_claimed": "provider claimed (evidence required)",
        "org": "organisational control",
        "undetermined": "UNDETERMINED",
    }
    for bucket in BUCKETS:
        n = counts.get(bucket, 0)
        if n:
            out.append(f"  {n:>4}  {labels[bucket]}")
    out.append(f"  {'-' * 4}")
    out.append(f"  {total:>4}  total")

    declared_org = [e for e in result["controls"] if e.get("org_control_declared")]
    if declared_org:
        out += ["",
                f"  {len(declared_org)} controls moved to the organisation because the profile",
                "  says it already runs them. They are still answered at audit, by someone else:"]
        by_source: dict[str, list[str]] = {}
        for entry in declared_org:
            was = entry.get("responsibility_before_org_control", "org")
            by_source.setdefault(was, []).append(entry["control"])
        for was, controls in sorted(by_source.items()):
            shown = "  ".join(sorted(controls)[:14])
            more = f"  ... and {len(controls) - 14} more" if len(controls) > 14 else ""
            out.append(f"    was {was}: {shown}{more}")

    # An organisation that has declared nothing, holding most of the baseline.
    # The tool already had both numbers and printed neither, so a derivation
    # against a three-person clinic produced requirements demanding a second
    # approver and an approval process, and nothing in the output said the
    # profile had already answered that there were none. Two of eight
    # requirements written for a real repository were rejected for exactly that,
    # and the information that would have caught it was in the profile.
    org_count = result["counts"].get("org", 0)
    if org_count and not result.get("org_controls_recognised"):
        out += ["",
                f"  NOTE: {org_count} controls are the organisation's, and the profile declares",
                "  no organisational controls at all. Either the interview did not reach the",
                "  question, or the organisation genuinely has none -- and in the second case",
                "  a requirement assuming an approval step, a second approver, or a division",
                "  of duties cannot be carried out by anyone here. Write what this team can",
                "  do, and say plainly which controls need an organisation that does not yet",
                "  exist."]

    if result.get("org_controls_unrecognised"):
        out += ["",
                "  WARNING: these answers to \"what does the organisation already have\"",
                "  matched nothing, so the requirements they cover are still on the list:"]
        for entry in result["org_controls_unrecognised"]:
            out.append(f"    - {entry}")
        out.append(f"  Recognised: {', '.join(sorted(ORG_CONTROL_COVERAGE))}.")

    if result.get("services_foreign"):
        out += ["",
                "  WARNING: a declared service belongs to a provider this profile does",
                f"  not name. The profile says csp: {result.get('csp') or 'none'}, and:"]
        for line in result["services_foreign"]:
            out.append(f"    - {line}")
        out += ["  Its split and its evidence references were still applied, because the",
                "  curation is the best answer for the service it describes. If the",
                "  deployment really is multi-cloud, list every provider; if it is not,",
                "  one of the two is wrong and the claims below name the wrong company."]

    if result["services_uncurated"]:
        out += ["", "Unverified services (no curated responsibility file)"]
        fallback = ("the deployment model layer" if result.get("deployment_model_recognised", True)
                    else "family defaults only -- the deployment model was not recognised either")
        for sid in result["services_uncurated"]:
            out.append(f"  ? {sid} -- classification falls back to {fallback}")

    undetermined = [e["control"] for e in result["controls"] if e["responsibility"] == "undetermined"]
    if undetermined:
        fams = sorted({c.split("-")[0] for c in undetermined})
        out += ["", f"UNDETERMINED: {len(undetermined)} controls with no mapping ({', '.join(fams)})"]

    team = [e for e in result["controls"] if e["responsibility"] == "team"]
    shared = [e for e in result["controls"] if e["responsibility"] == "shared"]
    out += ["", f"Controls reaching the delivery team: {len(team) + len(shared)}"]
    out.append("  " + "  ".join(e["control"] for e in team + shared))
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("profile", type=Path)
    ap.add_argument("controls", type=Path, help="select_baseline.py --json output")
    ap.add_argument("--json", type=Path)
    args = ap.parse_args()

    if args.json:
        try:
            preflight_output_paths([args.json])
        except UnsafePathError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    profile = yaml.safe_load(args.profile.read_text(encoding="utf-8"))
    controls = json.loads(args.controls.read_text(encoding="utf-8"))["controls"]

    try:
        result = classify(
            profile, controls, project_root=inspected_project_root(args.profile)
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(render(result))
    if args.json:
        safe_write_text(
            args.json, json.dumps(result, indent=2, ensure_ascii=False) + "\n"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
