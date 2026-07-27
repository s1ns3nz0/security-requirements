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
# Two values, as the authoring contract states. "unknown" was added here and
# is in no document -- it would have fallen to medium priority with no
# diagnostic, which is the ambiguity this check exists to remove.
NOVELTY_VALUES = {"service_specific", "generic"}

def _known_data_types() -> set[str]:
    """Every data type the classification table defines."""
    import yaml
    table = yaml.safe_load((REPO_ROOT / "catalogs" / "data-types" /
                            "classification.yaml").read_text(encoding="utf-8"))
    return {t["id"] for t in table["types"]}


def cross(controls_doc: dict, responsibility_doc: dict, threats_doc: dict) -> dict:
    baseline = set(controls_doc["controls"])
    # None means the derivation did not publish the field -- an older artefact --
    # and an empty set means the profile declared nothing. Collapsing them made
    # the check vanish exactly where it could not be performed, silently.
    declared_raw = controls_doc.get("declared_data_types")
    declared_types = None if declared_raw is None else set(declared_raw)
    known_data_types = _known_data_types()
    resp = {entry["control"]: entry for entry in responsibility_doc["controls"]}
    threats = threats_doc.get("threats", []) or []
    catalog = load_catalog_ids()

    # control -> threats that name it
    by_control: dict[str, list[str]] = {}
    threat_only = []
    outside_baseline: list[dict] = []
    problems: list[str] = []

    # A string is iterable. Read as a list it produced "threats[0] is 'n'; each
    # threat must be a mapping" -- an error naming a character, which is the
    # shape of mistake this repository has now corrected in four places.
    if not isinstance(threats, list):
        raise ValueError(
            f"threats must be a list; {type(threats).__name__} was given"
            + (". A single threat still goes in a list." if isinstance(threats, dict)
               else f" ({threats!r})")
        )

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
            problems.append({"kind": "schema", "message":
                f"{threat_id}: no novelty. The threat-modelling schema lists it as "
                f"required, and its absence reads exactly like `generic` -- so a "
                f"service-specific risk keeps its controls at medium priority and "
                f"nothing says why."})
        elif novelty not in NOVELTY_VALUES:
            problems.append({"kind": "schema", "message":
                f"{threat_id}: novelty {novelty!r} is not one of "
                f"{', '.join(sorted(NOVELTY_VALUES))}. It decides whether this threat "
                f"raises its controls to high priority, and an unrecognised value is "
                f"read as generic -- put the reasoning in `scenario` and the verdict here."})

        # Only assets the classification table knows are checked. affected_assets
        # is not restricted to data types by the schema and should not be: a
        # threat crossing a boundary legitimately names an identity provider, a
        # build runner, a signing key, or a queue. What is worth reporting is the
        # narrow case where the author wrote a data type this table defines and
        # the profile did not declare it -- which is how the golden threat model
        # came to name account_credentials against a profile that omits it.
        for asset in threat.get("affected_assets") or []:
            if declared_types is None:
                continue
            if asset in known_data_types and asset not in declared_types:
                problems.append({"kind": "asset", "message":
                    f"{threat_id}: affects {asset!r}, a data type this tool classifies, "
                    f"and the profile does not declare it. Either question one missed it "
                    f"-- with whatever requirements it forces -- or the threat is about a "
                    f"neighbouring system and should say so in another word."})

        related = threat.get("related_controls")
        if related is None:
            related = []
        elif not isinstance(related, list):
            problems.append({"kind": "schema", "message": f"{threat_id}: related_controls must be a list; read as one item"})
            related = [related]

        resolved = []
        for raw in related:
            if not isinstance(raw, str):
                problems.append({"kind": "unresolved", "message": f"{threat_id}: related control {raw!r} is not an identifier"})
                continue
            control = canonical_control(raw)
            if not CONTROL_RE.match(control):
                problems.append({"kind": "unresolved", "message": f"{threat_id}: {raw!r} is not a control identifier"})
                continue
            if catalog and control not in catalog:
                problems.append({"kind": "unresolved", "message": f"{threat_id}: {control} does not exist in the catalog"})
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
    unresolved = [p for p in result.get("problems") or [] if p.get("kind") == "unresolved"]
    other = [p for p in result.get("problems") or [] if p.get("kind") != "unresolved"]
    if unresolved:
        out += ["  UNRESOLVED references in the threat model -- these did NOT match a",
                "  control, so the threats naming them were counted as threat-only.",
                "  A mistyped identifier and a genuine gap produce the same bucket:"]
        for row in unresolved:
            out.append(f"    ! {row['message']}")
        out.append("")
    if other:
        # Kept apart from the unresolved list. Printed under that heading, a
        # novelty or asset problem was announced as a reference that matched no
        # control and a threat counted as threat-only -- neither of which had
        # happened. The golden profile's T-08 matched AC-7 and was reported as
        # threat-only in the same breath.
        out += ["  Problems in the threat model itself. They do not change which",
                "  controls matched:"]
        for row in other:
            out.append(f"    ? {row['message']}")
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
    if not isinstance(issued, dict):
        raise ValueError(
            f"the state file's `issued` is a {type(issued).__name__}; it maps a content "
            f"slug to the identifier that was allocated for it."
        )
    # The state file is hand-editable and shared across a team, and a value that
    # is not an identifier produced a raw AttributeError from inside the
    # allocator. Every other input in this repository gets a sentence.
    wrong = {k: v for k, v in issued.items() if not isinstance(v, str)}
    if wrong:
        first = next(iter(wrong))
        raise ValueError(
            f"the state file maps {first!r} to {wrong[first]!r}, which is not an "
            f"identifier. Each entry is slug -> REQ-<SLUG>-NN, written by this tool; "
            f"editing it by hand is how the mapping stops being the one the document "
            f"was issued against."
        )
    if slug in issued:
        recorded = issued[slug]
        # The state file exists to keep an identifier attached to the same
        # requirement across refreshes, so an entry pointing at some other
        # slug's identifier is the one thing it must not do quietly. A merge
        # conflict in this file is all it takes, and the result is a document
        # whose identifiers no longer mean what a reader thinks.
        if not re.fullmatch(rf"REQ-{re.escape(slug)}-\d{{2}}", recorded):
            raise ValueError(
                f"the state file maps {slug!r} to {recorded!r}, which belongs to a "
                f"different requirement. Identifiers are how a reader follows one "
                f"requirement across versions of the document; this file no longer "
                f"describes the one it was issued against."
            )
        return recorded

    # Always 01. The slug is the key, so one slug has one identifier and the
    # sequence has never had anything to count -- the earlier `len(used) + 1`
    # read as collision handling and handled nothing. Kept explicit so that the
    # next person does not have to work that out from a dead branch.
    new_id = f"REQ-{slug}-01"
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
        # Total churn is never a real refresh. A run that retires everything it
        # had and issues a new identifier for everything it derived is the
        # signature of a matching failure -- a slug convention changed, an id
        # scheme moved, a draft assembled from the wrong field -- and the cost
        # is not cosmetic: the first time this fired, five requirements were
        # retired including one a human had marked accepted_risk, carrying a
        # note the tool is never supposed to touch.
        "total_churn": bool(existing) and bool(draft)
                       and not unchanged and not updated and not reopened
                       and len(retired) == len(existing) and len(added) == len(draft),
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
    ap.add_argument("--allow-full-rewrite", action="store_true",
                    help="proceed when the refresh matches nothing at all. A rewrite of the "
                         "whole requirement set is legitimate and looks identical to a broken "
                         "identifier scheme, so it has to be said out loud.")

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

        # A sentence, not a traceback. Every other input error in this
        # repository names the file and the flag; pointing --controls at the
        # wrong path produced a stack trace ending in FileNotFoundError.
        for name in ("controls", "responsibility"):
            path = getattr(args, name)
            if not path.exists():
                print(f"error: --{name} {path} does not exist. It is written by "
                      f"{'select_baseline.py --json' if name == 'controls' else 'classify_resp.py --json'}.",
                      file=sys.stderr)
                return 2

        # Absent and empty are different facts, and the difference is the one
        # that hid for a long time here: sixty-nine public repositories were
        # crossed against a threats file that did not exist, and the output was
        # indistinguishable from a threat model that found nothing.
        threats_doc = load_yaml(args.threats, None)
        if threats_doc is None:
            print(f"error: --threats {args.threats} does not exist. A crossing with no "
                  f"threat model is a filtered baseline, which is not what this tool is "
                  f"for -- write the model first, or pass a file with an empty `threats:` "
                  f"list to say the modelling was done and found nothing.", file=sys.stderr)
            return 2

        try:
            result = cross(
                json.loads(args.controls.read_text(encoding="utf-8")),
                json.loads(args.responsibility.read_text(encoding="utf-8")),
                threats_doc,
            )
        except ValueError as exc:
            # The --apply path already turns a validation failure into a
            # sentence and exit 2. This one let it out as a traceback, so the
            # improved message arrived wrapped in a stack.
            print(f"error: {exc}", file=sys.stderr)
            return 2
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
        try:
            result = apply_merge(draft_items, existing, state)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if result.get("total_churn") and not args.allow_full_rewrite:
        # Refused before the write, because the write is the damage. The file is
        # overwritten and the counts printed afterwards, so the first run that
        # hit this had already discarded a requirement a human marked
        # accepted_risk and the note they wrote against it.
        print("Refusing to write: this refresh matched nothing.", file=sys.stderr)
        print(f"  Every one of the {len(result['retired'])} existing requirements would be "
              f"retired and", file=sys.stderr)
        print(f"  all {len(result['added'])} derived ones issued under new identifiers. A real "
              f"change to a", file=sys.stderr)
        print("  service does not do that; a changed slug convention or an id scheme does.",
              file=sys.stderr)
        # Not "would be lost". The retired records keep their human blocks --
        # this file's own retire() preserves them and a test asserts it. What is
        # true is that every decision a human made now hangs on a retired
        # requirement while the live work carries new identifiers nobody has
        # looked at. Saying "lost" overstated it.
        print("  Every accepted risk, note, and owner would stay attached to a retired",
              file=sys.stderr)
        print("  requirement while the live work arrives under identifiers nobody has seen.",
              file=sys.stderr)
        print("  If the requirement set really was rewritten wholesale, pass "
              "--allow-full-rewrite.", file=sys.stderr)
        print(f"  Existing: {', '.join(r['id'] for r in existing[:3])}"
              f"{' ...' if len(existing) > 3 else ''}", file=sys.stderr)
        print(f"  Derived : {', '.join(result['added'][:3])}"
              f"{' ...' if len(result['added']) > 3 else ''}", file=sys.stderr)
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
