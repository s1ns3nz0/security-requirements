#!/usr/bin/env python3
"""Cross the baseline against the threat model, and merge drafts into the SSOT.

Two modes, both deterministic.

``--cross`` (pipeline step 7)
    Combines the resolved baseline, the responsibility split, and the threat
    model into a work list. Judgement already happened: the threat model states
    which controls relate to each threat. Crossing those sets is arithmetic.

``--apply`` (pipeline step 9)
    Merges newly authored requirements into requirements.yaml without
    destroying anything a person wrote, and reissues stable identifiers.

Why the merge is this careful
-----------------------------
The realistic sequence is: tool generates, security review rewrites a statement,
someone accepts a risk with a named approver and an expiry, the service changes
three months later, the tool runs again. If that last step overwrites the first
three, the tool is used exactly once.

So: ``human`` blocks are inviolate, competing ``managed`` changes land in
``pending_review``, and requirements are never removed -- only transitioned,
with a reason. An identifier, once issued, is reused forever; tickets and audit
evidence point at it.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
CATALOG_DIR = REPO_ROOT / "catalogs" / "nist-800-53r5"


# --------------------------------------------------------------------------
# cross
# --------------------------------------------------------------------------

CONTROL_RE = re.compile(r"^[A-Z]{2}-\d+(?:\(\d+\))?$")


def canonical_control(value: str) -> str:
    """Put a control identifier in the form the catalog uses.

    ``ac-3.1`` is the OSCAL identifier and appears in the bundled records, so it
    is what someone reading them copies. ``AC-3(1)`` is the form NIST prints and
    the form the catalog is keyed on. Accepting both costs nothing; accepting
    only one costs a false finding, see below.
    """
    text = value.strip().upper()
    if "." in text and "(" not in text:
        base, _, enh = text.partition(".")
        return f"{base}({enh})"
    return text


def load_catalog_ids() -> set[str]:
    ids = set()
    if CATALOG_DIR.exists():
        for path in CATALOG_DIR.glob("*.jsonl"):
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    ids.add(json.loads(line)["id"])
    return ids


# The values `novelty` may take. It decides whether a threat raises a control to
# high priority, and it was compared against one literal with nothing checking
# the field -- so a threat carrying a sentence where an enum belongs was quietly
# treated as generic and its controls stayed at medium. The author had written
# the most specific thing in the document.
NOVELTY_VALUES = {"service_specific", "generic", "unknown"}

def cross(controls_doc: dict, responsibility_doc: dict, threats_doc: dict) -> dict:
    baseline = set(controls_doc["controls"])
    declared_types = set(controls_doc.get("declared_data_types") or [])
    resp = {entry["control"]: entry for entry in responsibility_doc["controls"]}
    threats = threats_doc.get("threats", []) or []
    catalog = load_catalog_ids()

    # control -> threats that name it
    by_control: dict[str, list[str]] = {}
    threat_only = []
    outside_baseline: list[dict] = []
    problems: list[str] = []

    for position, threat in enumerate(threats):
        if not isinstance(threat, dict):
            raise ValueError(
                f"threats[{position}] is {threat!r}; each threat must be a mapping"
            )
        threat_id = threat.get("id")
        if not threat_id:
            raise ValueError(f"threats[{position}] has no `id`")

        # `threat_only` is the tool's central claim: a risk no control in the
        # baseline addresses. A mistyped identifier produces exactly the same
        # outcome as a genuine gap, so a spelling slip manufactures a finding
        # while also losing the priority raise on the control that was meant.
        # The two must be distinguishable, so unmatched identifiers are
        # reported rather than quietly promoted.
        novelty = threat.get("novelty")
        if novelty is None:
            problems.append(
                f"{threat_id}: no novelty. The threat-modelling schema lists it as "
                f"required, and its absence reads exactly like `generic` -- so a "
                f"service-specific risk keeps its controls at medium priority and "
                f"nothing says why.")
        elif novelty not in NOVELTY_VALUES:
            problems.append(
                f"{threat_id}: novelty {novelty!r} is not one of "
                f"{', '.join(sorted(NOVELTY_VALUES))}. It decides whether this threat "
                f"raises its controls to high priority, and an unrecognised value is "
                f"read as generic -- put the reasoning in `scenario` and the verdict here.")

        for asset in threat.get("affected_assets") or []:
            if declared_types and asset not in declared_types:
                problems.append(
                    f"{threat_id}: affects {asset!r}, which the profile does not declare. "
                    f"The threat model and the profile describe one system -- either the "
                    f"service holds it and question one missed it, or the threat names "
                    f"something it does not.")

        related = threat.get("related_controls")
        if related is None:
            related = []
        elif not isinstance(related, list):
            problems.append(f"{threat_id}: related_controls must be a list; read as one item")
            related = [related]

        resolved = []
        for raw in related:
            if not isinstance(raw, str):
                problems.append(f"{threat_id}: related control {raw!r} is not an identifier")
                continue
            control = canonical_control(raw)
            if not CONTROL_RE.match(control):
                problems.append(f"{threat_id}: {raw!r} is not a control identifier")
                continue
            if catalog and control not in catalog:
                problems.append(f"{threat_id}: {control} does not exist in the catalog")
                continue
            resolved.append(control)

        in_baseline = [c for c in resolved if c in baseline]
        # A control the author cited, that exists, and that this baseline does
        # not select was being dropped without a word -- so a threat citing
        # SR-3, SR-11, and CM-14 reported as fully addressed by two, and CM-14,
        # which is the control for the supply-chain threat that was written, was
        # never mentioned. The reader could not tell the difference between "we
        # cover this" and "we cover part of this".
        outside = [c for c in resolved if c not in baseline]
        for control in in_baseline:
            by_control.setdefault(control, []).append(threat_id)
        if outside:
            outside_baseline.append({"threat": threat_id, "controls": outside,
                                     "partly_covered": bool(in_baseline)})
        if not in_baseline:
            threat_only.append(threat)

    items = []

    for control in controls_doc["controls"]:
        entry = resp.get(control, {})
        bucket = entry.get("responsibility", "undetermined")
        if bucket in ("org", "csp_claimed"):
            # Still recorded -- an audit asks about every control -- but these
            # do not become delivery work.
            origin = "baseline_only"
            matched = by_control.get(control, [])
            priority = "low"
        else:
            matched = by_control.get(control, [])
            if matched:
                origin = "threat_and_baseline"
                service_specific = any(
                    t["id"] in matched and t.get("novelty") == "service_specific"
                    for t in threats
                )
                priority = "high" if service_specific else "medium"
            else:
                origin = "baseline_only"
                priority = "low"

        items.append({
            "origin": origin,
            "control": control,
            "responsibility": bucket,
            "threat_refs": matched,
            "priority": priority,
            "unverified": entry.get("unverified", False),
            "services": entry.get("services", []),
            "org_control_declared": entry.get("org_control_declared", False),
        })

    for threat in threat_only:
        items.append({
            "origin": "threat_only",
            "control": None,
            "responsibility": "team",
            "threat_refs": [threat["id"]],
            "priority": "high" if threat.get("novelty") == "service_specific" else "medium",
            "unverified": False,
            "services": [],
            "threat": threat,
        })

    # Data types that demand a requirement whatever the threat model found.
    # System-information types reach the output only through this path, having
    # been excluded from the high water mark; dropping it silently loses the
    # secret-handling requirements for every service that has secrets.
    for forced in controls_doc.get("forced_requirements", []) or []:
        items.append({
            "origin": "forced_by_data_type",
            "control": None,
            "responsibility": "team",
            "threat_refs": [],
            "priority": "high",
            "unverified": False,
            "services": [],
            "forced": forced,
        })

    counts = {}
    for item in items:
        counts[item["origin"]] = counts.get(item["origin"], 0) + 1

    return {"counts": counts, "items": items, "problems": problems,
            "outside_baseline": outside_baseline}


def render_cross(result: dict) -> str:
    counts = result["counts"]
    out = ["Baseline x threat model", ""]
    if result.get("problems"):
        out += ["  UNRESOLVED references in the threat model -- these did NOT match a",
                "  control, so the threats naming them were counted as threat-only.",
                "  A mistyped identifier and a genuine gap produce the same bucket:"]
        out += [f"    ! {p}" for p in result["problems"]]
        out.append("")
    for key, label in (
        ("threat_and_baseline", "threat and baseline (raised priority)"),
        ("threat_only", "threat only (ADDITIONAL requirements)"),
        ("forced_by_data_type", "forced by a declared data type"),
        ("baseline_only", "baseline only (retained, lower priority)"),
    ):
        out.append(f"  {counts.get(key, 0):>4}  {label}")

    if result.get("outside_baseline"):
        out += ["",
                "  Controls a threat names that this baseline does not select. They are",
                "  not requirements here, and the threat is less covered than its count",
                "  suggests:"]
        for row in result["outside_baseline"]:
            state = "partly covered without" if row["partly_covered"] else "reaches nothing without"
            out.append(f"    {row['threat']}: {state} {', '.join(row['controls'])}")

    if not counts.get("threat_only"):
        out += [
            "",
            "  WARNING: the threat-only bucket is empty.",
            "  Either this service genuinely has no risk the baseline misses, or the",
            "  threat model returned generic material. Check the novelty flags before",
            "  shipping -- a filtered baseline is not what this tool is for.",
        ]
    return "\n".join(out)


# --------------------------------------------------------------------------
# apply
# --------------------------------------------------------------------------

SLUG_RE = re.compile(r"^[A-Z0-9]+(?:-[A-Z0-9]+)*$")


def issue_id(slug: str, state: dict) -> str:
    """Return the stable identifier for a content slug, allocating if new."""
    issued = state.setdefault("issued", {})
    if slug in issued:
        return issued[slug]
    used = {v for v in issued.values() if v.startswith(f"REQ-{slug}-")}
    seq = len(used) + 1
    new_id = f"REQ-{slug}-{seq:02d}"
    issued[slug] = new_id
    return new_id


TERMINAL_STATUSES = ("retired", "superseded")


def retire(record: dict, reason: str) -> None:
    """Move a requirement out of the active set without destroying its history.

    The prior status is preserved. Overwriting it loses the fact that a risk was
    formally accepted: a report of exceptions approaching expiry queries
    `status == exception`, and a retirement that clobbers the field silently
    removes an approved exception from that list while leaving the approval
    record behind to contradict it.
    """
    human = record.setdefault("human", {})
    previous = human.get("status")
    if previous in TERMINAL_STATUSES:
        return
    if previous:
        human["previous_status"] = previous
    human["status"] = "retired"
    if previous == "exception":
        approver = (human.get("exception") or {}).get("approver", "unrecorded")
        reason = (f"{reason}. The exception approved by {approver} is closed by this "
                  f"retirement rather than by expiry, and is retained above.")
    human.setdefault("retired_reason", reason)


def apply_merge(draft: list[dict], existing: list[dict], state: dict) -> dict:
    by_id = {r["id"]: r for r in existing}
    seen = set()
    added, proposed, unchanged, updated, reopened = [], [], [], [], []

    for item in draft:
        slug = item.get("slug")
        if isinstance(slug, str):
            slug = slug.strip().upper().replace(" ", "-").replace("_", "-")
        if not slug or not SLUG_RE.match(slug):
            raise ValueError(
                f"draft item has an invalid slug: {item.get('slug')!r}. "
                f"Expected upper-case words joined by hyphens, derived from the "
                f"requirement's subject."
            )
        if "managed" not in item:
            raise ValueError(f"draft item {slug!r} has no `managed` block")
        req_id = issue_id(slug, state)
        seen.add(req_id)

        if req_id not in by_id:
            by_id[req_id] = {"id": req_id, "managed": item["managed"], "human": {}}
            added.append(req_id)
            continue

        current = by_id[req_id]

        # A requirement that was retired and now derives again is back in scope.
        # Leaving it retired would drop live work on the floor, so the return is
        # recorded rather than assumed either way.
        human = current.setdefault("human", {})
        if human.get("status") in TERMINAL_STATUSES:
            human["previous_status"] = human.get("status")
            human["status"] = "active"
            human.pop("retired_reason", None)
            human["reinstated_reason"] = "derives again from the current profile"
            reopened.append(req_id)

        if current["managed"] == item["managed"]:
            unchanged.append(req_id)
            continue

        if human:
            # A person has touched this requirement. Propose, do not overwrite.
            current["pending_review"] = {
                "managed": item["managed"],
                "why": item.get("change_reason", "re-derived from an updated profile"),
            }
            proposed.append(req_id)
        else:
            # Nobody has touched it, so applying the new text destroys nothing.
            # It is still reported: a silently rewritten requirement counted as
            # "unchanged" is the opposite of what a reviewer needs to see.
            current["managed"] = item["managed"]
            updated.append(req_id)

    retired = []
    for req_id, record in by_id.items():
        if req_id in seen:
            continue
        if (record.get("human") or {}).get("status") in TERMINAL_STATUSES:
            continue
        retire(record, "no longer derived from the current profile; retained for audit history")
        retired.append(req_id)

    return {
        "requirements": sorted(by_id.values(), key=lambda r: r["id"]),
        "added": added,
        "updated": updated,
        "proposed": proposed,
        "unchanged": unchanged,
        "retired": retired,
        "reopened": reopened,
    }


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def load_yaml(path: Path, default):
    if not path.exists():
        return default
    return yaml.safe_load(path.read_text(encoding="utf-8")) or default


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--cross", action="store_true")
    mode.add_argument("--apply", action="store_true")

    ap.add_argument("--controls", type=Path)
    ap.add_argument("--responsibility", type=Path)
    ap.add_argument("--threats", type=Path)
    ap.add_argument("--out", type=Path)

    ap.add_argument("--draft", type=Path)
    ap.add_argument("--existing", type=Path)
    ap.add_argument("--state", type=Path)
    args = ap.parse_args()

    if args.cross:
        for name in ("controls", "responsibility", "threats", "out"):
            if getattr(args, name) is None:
                ap.error(f"--cross requires --{name}")
        result = cross(
            json.loads(args.controls.read_text(encoding="utf-8")),
            json.loads(args.responsibility.read_text(encoding="utf-8")),
            load_yaml(args.threats, {"threats": []}),
        )
        args.out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(render_cross(result))
        return 0

    for name in ("draft", "existing", "state"):
        if getattr(args, name) is None:
            ap.error(f"--apply requires --{name}")

    draft = json.loads(args.draft.read_text(encoding="utf-8"))
    draft_items = draft["requirements"] if isinstance(draft, dict) else draft
    existing = load_yaml(args.existing, {"requirements": []}).get("requirements", [])
    state = load_yaml(args.state, {"issued": {}})

    try:
        result = apply_merge(draft_items, existing, state)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    args.existing.parent.mkdir(parents=True, exist_ok=True)
    args.existing.write_text(
        yaml.safe_dump({"requirements": result["requirements"]}, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    args.state.write_text(
        yaml.safe_dump(state, sort_keys=True, allow_unicode=True), encoding="utf-8"
    )

    print("Merge result\n")
    print(f"  added       {len(result['added']):>4}")
    print(f"  updated     {len(result['updated']):>4}   text replaced in place (no human edits to protect)")
    print(f"  proposed    {len(result['proposed']):>4}   pending_review, awaiting your decision")
    print(f"  unchanged   {len(result['unchanged']):>4}")
    print(f"  retired     {len(result['retired']):>4}")
    if result["reopened"]:
        print(f"  reopened    {len(result['reopened']):>4}   previously retired, derives again")
    for req_id in result["proposed"]:
        print(f"    ? {req_id} has human edits; the re-derived text is in pending_review")
    for req_id in result["reopened"]:
        record = next(r for r in result["requirements"] if r["id"] == req_id)
        print(f"    ! {req_id} was retired and is back in scope")
        if (record.get("human") or {}).get("exception"):
            # Reinstating an accepted risk is a decision for the approver, not
            # for a re-derivation. The record is left active with the prior
            # approval attached so the choice is visible rather than assumed.
            print(f"      it carries an exception closed by the earlier retirement;"
                  f" re-affirm or withdraw it")

    expiring = []
    for record in result["requirements"]:
        human = record.get("human") or {}
        exception = human.get("exception") or {}
        if exception.get("expires"):
            expiring.append((record["id"], exception["expires"], human.get("status", "")))
    if expiring:
        print("\n  accepted risks on record")
        for req_id, expires, status in sorted(expiring, key=lambda x: x[1]):
            note = "" if status == "exception" else f"  (status now: {status})"
            print(f"    {req_id}  expires {expires}{note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
