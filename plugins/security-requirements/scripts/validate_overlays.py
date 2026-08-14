#!/usr/bin/env python3
"""Check every regulatory overlay for the defects structure alone does not catch.

Six overlays were added in succession, and each found a defect in machinery
written for the one before it. Structural checks -- identifiers exist, every
clause is mapped -- were already enforced at load time and all six pass them.
These are the checks that need a view across overlays and against the baselines.

Usage
-----
    python3 -I "<absolute plugin root>/scripts/validate_overlays.py"
    python3 -I "<absolute plugin root>/scripts/validate_overlays.py" --strict   # advisories fail too
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import apply_overlay as ov  # noqa: E402
import classify_resp  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
BASELINES = REPO_ROOT / "catalogs" / "nist-800-53r5" / "baselines.json"
LAYERS = REPO_ROOT / "responsibility" / "layers.yaml"
HINTS = {"team", "shared", "org", "csp_claimed"}


def overlay_ids() -> list[str]:
    return sorted(p.name for p in (REPO_ROOT / "overlays").iterdir()
                  if p.is_dir() and (p / "meta.yaml").exists())


def layer_of(control: str, layers: dict) -> str | None:
    """Delegates. This used to be a third hand-written copy of the resolution
    order, and it had already drifted: it knew nothing of the deployment-model
    overrides, so a control the real classifier moves under Kubernetes resolved
    here to whatever the family default said."""
    return classify_resp.resolve_layer(control, layers, None)[0]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--strict", action="store_true")
    args = ap.parse_args(argv)

    baselines = json.loads(BASELINES.read_text(encoding="utf-8"))
    in_any = set().union(*baselines.values())
    layers = yaml.safe_load(LAYERS.read_text(encoding="utf-8"))

    errors, advisories = [], []

    for oid in overlay_ids():
        try:
            overlay = ov.load(oid)
        except ov.OverlayError as exc:
            errors.append(f"{oid}: {exc}")
            continue
        meta, mappings = overlay["meta"], overlay["mappings"]

        # An authored mapping presented as anything else is the failure this
        # repository exists to prevent.
        if meta.get("mapping", {}).get("authored") is not True:
            errors.append(f"{oid}: mapping.authored must be true -- every mapping here is a reading")
        if not (meta.get("disclaimer") or "").strip():
            errors.append(f"{oid}: no disclaimer")

        # An overlay that stops above the assessed clause must say so, or a
        # coverage count reads as compliance.
        depth = meta.get("depth") or {}
        if depth and depth.get("sub_requirements_enumerated") is not False:
            errors.append(f"{oid}: depth block present but does not state the limit")

        for m in mappings:
            if m["standalone"] != (not m["controls"]):
                errors.append(f"{oid} {m['clause']}: standalone disagrees with the control list")
            if m.get("responsibility_hint") not in HINTS:
                errors.append(f"{oid} {m['clause']}: unknown responsibility_hint "
                              f"{m.get('responsibility_hint')!r}")
            if len(m["controls"]) != len(set(m["controls"])):
                errors.append(f"{oid} {m['clause']}: duplicate controls")

            # A clause whose every control sits outside all four baselines can
            # never be reported as reached, whatever the service does. That is a
            # property of the tool, and the reader has to be told which it is.
            if m["controls"] and not (set(m["controls"]) & in_any):
                advisories.append(
                    f"{oid} {m['clause']}: unreachable -- {', '.join(m['controls'])} "
                    f"are in no baseline this tool resolves")

            # The regime expects the delivery team to own something the
            # responsibility layer assigns to the organisation. Neither is
            # necessarily wrong; the disagreement is worth seeing.
            #
            # `shared` is often the honest answer to that disagreement -- and it
            # is also the edit that makes the advisory go away. Where the whole
            # mapping still resolves to the organisation, a shared hint has to
            # say which half is whose, or resolving the advisory and hiding it
            # are the same keystroke. Where the mapping reaches the team on its
            # own, `shared` is an ordinary value and needs no defence.
            if m["controls"]:
                resolved = {layer_of(c, layers) for c in m["controls"]}
                org_only = bool(resolved) and resolved <= {"org", "csp_claimed"}
                hint = m.get("responsibility_hint")
                if org_only and hint == "team":
                    advisories.append(
                        f"{oid} {m['clause']}: overlay says the team owns this, the layer "
                        f"resolves every mapped control to {'/'.join(sorted(resolved))}")
                elif org_only and hint == "shared" and not (m.get("responsibility_note") or "").strip():
                    errors.append(
                        f"{oid} {m['clause']}: hint is shared and every mapped control "
                        f"resolves to {'/'.join(sorted(resolved))}, but no "
                        f"responsibility_note says which half is the team's")

    for line in errors:
        print(f"  ERROR  {line}")
    for line in advisories:
        print(f"  note   {line}")
    print(f"\n{len(overlay_ids())} overlays: {len(errors)} error(s), {len(advisories)} advisory")

    if errors:
        return 1
    return 1 if (advisories and args.strict) else 0


if __name__ == "__main__":
    raise SystemExit(main())
