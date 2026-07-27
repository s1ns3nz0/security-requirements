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
    python3 scripts/classify_resp.py PROFILE CONTROLS_JSON [--json OUT]

where CONTROLS_JSON is the output of select_baseline.py --json.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
LAYERS = REPO_ROOT / "responsibility" / "layers.yaml"
SERVICES_DIR = REPO_ROOT / "responsibility" / "services"

BUCKETS = ["team", "shared", "csp_claimed", "org", "undetermined"]

# Team involvement, most to least. Used when two services disagree about the
# same control: the more demanding answer wins, because under-assigning work to
# the team is the failure mode that leaves a gap unowned.
PRECEDENCE = {"team": 3, "shared": 2, "csp_claimed": 1, "org": 0}

# Organisational controls a profile may declare as already in place. Used to
# annotate, never to delete: the control still has to be answered at audit,
# it is simply answered by someone other than the delivery team.
ORG_CONTROL_COVERAGE = {
    "sso": ["AC-2", "AC-2(1)", "AC-7", "AC-11", "AC-12"],
    "central_logging": ["AU-6", "AU-6(1)", "AU-6(3)", "AU-7", "AU-7(1)", "AU-9"],
    "access_review": ["AC-2(3)", "AC-2(4)", "AC-6(7)"],
    "incident_response": ["AU-6", "AU-5"],
    "security_policy": ["AC-1", "AU-1", "SC-1"],
}


class ClassifyError(Exception):
    pass


def load_services(profile: dict) -> tuple[dict, list[str], list[str]]:
    """Return (service specs, curated ids, uncurated ids)."""
    declared = (profile.get("inferred") or {}).get("managed_services", []) or []
    specs, curated, uncurated = {}, [], []
    for entry in declared:
        sid = entry["id"] if isinstance(entry, dict) else entry
        path = SERVICES_DIR / f"{sid}.yaml"
        if not path.exists():
            uncurated.append(sid)
            continue
        spec = yaml.safe_load(path.read_text(encoding="utf-8"))
        specs[sid] = spec
        (curated if spec.get("reviewed") else uncurated).append(sid)
    return specs, curated, uncurated


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


def classify(profile: dict, controls: list[str]) -> dict:
    layers = yaml.safe_load(LAYERS.read_text(encoding="utf-8"))
    deployment_model = (profile.get("inferred") or {}).get("deployment_model")
    csp = (profile.get("inferred") or {}).get("csp")

    specs, curated, uncurated = load_services(profile)
    org_controls = set((profile.get("declared") or {}).get("existing_org_controls", []) or [])
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
            entry["org_control_declared"] = True

        # A claim needs a claimant. With no cloud provider in the profile,
        # csp_claimed is not a legal outcome -- the facility, the hardware, and
        # the media are the organisation's own. Found by sweeping an on-premise
        # profile: fifteen controls were assigned to a provider that does not
        # exist, because the onprem override list enumerated some PE/MP
        # controls and missed the rest. A structural rule beats a longer list.
        if entry["responsibility"] == "csp_claimed" and csp in (None, "", "none"):
            entry["responsibility"] = "org"
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

    return {
        "deployment_model": deployment_model,
        "deployment_model_recognised": not unknown_model,
        "known_deployment_models": sorted(known_models),
        "services_curated": sorted(curated),
        "services_uncurated": sorted(uncurated),
        "counts": counts,
        "controls": results,
    }


def render(result: dict) -> str:
    counts = result["counts"]
    total = sum(counts.values())
    out = ["Responsibility split", ""]
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

    if result["services_uncurated"]:
        out += ["", "Unverified services (no curated responsibility file)"]
        for sid in result["services_uncurated"]:
            out.append(f"  ? {sid} -- classification falls back to the deployment model layer")

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

    profile = yaml.safe_load(args.profile.read_text(encoding="utf-8"))
    controls = json.loads(args.controls.read_text(encoding="utf-8"))["controls"]

    try:
        result = classify(profile, controls)
    except ClassifyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(render(result))
    if args.json:
        args.json.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
