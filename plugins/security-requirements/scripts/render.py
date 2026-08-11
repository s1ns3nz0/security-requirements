#!/usr/bin/env python3
"""Render the requirements SSOT into documents for human readers.

Three outputs, because there are three audiences:

    requirements.md    the delivery team -- organised by CSF 2.0 function, so it
                       reads as work rather than as a control list
    traceability.md    the auditor -- control identifier to requirement, so the
                       question "how is AC-3 addressed?" has an answer
    responsibility.md  everyone -- who owns what, and what evidence substantiates
                       each inheritance claim

These are the publishable artefacts. Implementation status, the threat model, and
exception approvals stay in .security-requirements/ and are governed separately;
together they describe where the data is and which controls are not yet in place.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from safe_paths import (  # noqa: E402
    UnsafePathError,
    preflight_output_paths,
    safe_mkdir,
    safe_write_text,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
CATALOG_DIR = REPO_ROOT / "catalogs" / "nist-800-53r5"

DISCLAIMER = (
    "> This document is an automatically generated draft. It does not constitute\n"
    "> legal advice and does not substitute for compliance certification.\n"
    "> Qualified review is required.\n"
)

CSF_FUNCTIONS = {
    "GV": "GOVERN",
    "ID": "IDENTIFY",
    "PR": "PROTECT",
    "DE": "DETECT",
    "RS": "RESPOND",
    "RC": "RECOVER",
}
FUNCTION_ORDER = ["GV", "ID", "PR", "DE", "RS", "RC", "??"]

RESPONSIBILITY_LABEL = {
    "team": "team implements",
    "shared": "shared",
    "csp_claimed": "provider claimed",
    "org": "organisational",
    "undetermined": "UNDETERMINED",
}

PRIORITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def catalog_titles() -> dict[str, str]:
    titles = {}
    if CATALOG_DIR.exists():
        for path in CATALOG_DIR.glob("*.jsonl"):
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    rec = json.loads(line)
                    titles[rec["id"]] = rec["title"]
    return titles


def catalog_meta() -> dict:
    path = CATALOG_DIR / "meta.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def function_of(req: dict) -> str:
    """Which CSF function a requirement is filed under.

    A scalar `csf: "PR.DS-01"` indexed to the character "P", so the requirement
    dropped out of PROTECT into the unclassified bin at the foot of the
    document -- a silent misfiling, invisible unless someone counts.
    """
    csf = (req.get("managed") or {}).get("csf") or []
    if isinstance(csf, str):
        csf = [csf]
    for entry in csf:
        if isinstance(entry, str) and entry.strip():
            return entry.strip().split(".")[0].upper()
    return "??"


def active(req: dict) -> bool:
    """Whether a requirement belongs in the published document.

    The status comparison was case-sensitive, so `RETIRED` read as active and a
    requirement someone had deliberately retired reappeared as live work.
    """
    status = (req.get("human") or {}).get("status")
    if isinstance(status, str):
        status = status.strip().lower()
    return status not in ("retired", "superseded")


def provenance(meta: dict) -> str:
    lines = ["## Sources", ""]
    if meta:
        lines.append(
            f"- NIST SP 800-53 Rev 5 / SP 800-53B "
            f"(OSCAL version {meta.get('oscal_version', 'unknown')}, "
            f"last modified {meta.get('oscal_last_modified', 'unknown')})"
        )
        if meta.get("partial"):
            fams = ", ".join(meta.get("families_extracted", []))
            lines.append(
                f"- **Partial catalog.** Only the {fams} families are bundled. Controls in "
                "other families are reported as unavailable rather than omitted."
            )
    lines += [
        "- NIST Cybersecurity Framework 2.0 (structure)",
        "- OWASP Application Security Verification Standard (CC BY-SA 4.0)",
        "",
        "NIST does not endorse this output. Provider guidance is summarised in the "
        "authors' own words with links to the original; it is not reproduced.",
        "",
    ]
    return "\n".join(lines)


def prose(value) -> str:
    """A value safe to put in a published paragraph.

    Only the line endings, because a paragraph keeps its newlines -- what it
    must not keep is a carriage return. Those arrive from authored YAML edited
    on Windows, survive review because they are invisible, and then show up as a
    stray character in whatever renders the document next. `cell()` had been
    normalising them for table cells since the day a CRLF split a row in two;
    the statement and the rationale are published as prose and were reaching the
    file untouched.
    """
    return str(value or "").replace("\r\n", "\n").replace("\r", "\n")


def cell(value) -> str:
    """A value safe to put in a Markdown table cell.

    A pipe ends the column. Real verification targets contain them --
    `getSignedUrl|generate_presigned_url` is an ordinary code_grep target -- and
    so does evidence naming two artefacts. The statement was escaped and
    everything beside it was not, so a two-column row arrived carrying six
    separators and the table broke from that row down.

    Newlines end the row, which is worse: everything after one is read as a new
    table entirely.
    """
    text = ("; ".join(str(v) for v in value) if isinstance(value, (list, tuple))
            else str(value or ""))
    text = prose(text)
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("\n", "<br>")


def render_requirements(doc: dict, titles: dict, meta: dict) -> str:
    reqs = [r for r in doc.get("requirements", []) or [] if active(r)]
    grouped: dict[str, list[dict]] = {}
    for req in reqs:
        grouped.setdefault(function_of(req), []).append(req)

    out = ["# Security requirements", "", DISCLAIMER, ""]
    out.append(f"{len(reqs)} active requirements.")
    out.append("")

    for key in FUNCTION_ORDER:
        items = grouped.get(key)
        if not items:
            continue
        heading = CSF_FUNCTIONS.get(key, "UNCLASSIFIED")
        out += [f"## {heading}", ""]
        items.sort(key=lambda r: (
            PRIORITY_ORDER.get((r.get("managed") or {}).get("priority", "low"), 3),
            r["id"],
        ))
        for req in items:
            managed = req.get("managed") or {}
            human = req.get("human") or {}
            out.append(f"### {req['id']}")
            out.append("")
            out.append(prose(managed.get("statement", "")))
            out.append("")
            if managed.get("rationale"):
                out += [f"*{prose(managed['rationale']).strip()}*", ""]

            rows = []
            resp = managed.get("responsibility", "undetermined")
            rows.append(("Responsibility", RESPONSIBILITY_LABEL.get(resp, resp)))
            if managed.get("csp_part"):
                rows.append(("Provider", managed["csp_part"]))
            if managed.get("team_part"):
                rows.append(("Team", managed["team_part"]))
            if managed.get("evidence"):
                evidence = managed["evidence"]
                rows.append(("Evidence", evidence if isinstance(evidence, str) else "; ".join(evidence)))
            sources = managed.get("sources") or []
            if sources:
                rows.append(("Basis", ", ".join(sources)))
            rows.append(("Priority", managed.get("priority", "low")))

            verification = managed.get("verification") or {}
            if verification:
                check = f"`{verification.get('target', '')}` — expect {verification.get('expect', '')}"
                rows.append(("Verify", f"{verification.get('method', '')}: {check}"))
                if verification.get("fallback_manual"):
                    rows.append(("Verify (manual)", verification["fallback_manual"]))

            out.append("| | |")
            out.append("|---|---|")
            for label, value in rows:
                out.append(f"| {cell(label)} | {cell(value)} |")
            out.append("")

            # Neither the status nor the exception. The README draws the line
            # where this file is concerned: the internal side is a
            # reconnaissance document because it says "which controls are not
            # implemented, and which risks were accepted until when". Publishing
            # `Status: accepted_risk` is the first half of that sentence, and
            # the expiry -- removed a commit earlier -- was the second. Half a
            # disclosure is still a disclosure.
            #
            # This document holds the requirement definitions. Whether each one
            # is met yet is what .security-requirements/ is for, and it is
            # gitignored on a public repository for exactly this reason.
            # No note about a pending change either. It told a reader outside
            # the organisation that a requirement is in flux and named the
            # internal file to look in, which is process rather than
            # definition -- and it survived one commit past the removal of the
            # status field that says the same thing.

    # Retired requirements, and why. The merge preserves retired_reason and
    # previous_status with some care, and the published document showed
    # neither -- a requirement simply vanished between two versions of the
    # deliverable, which is the one place a reader is entitled to an
    # explanation. An auditor diffing last quarter's document against this one
    # finds an absence and no account of it.
    # The same normalisation `active()` uses. Compared raw, a status of
    # " RETIRED " fell out of the active sections and out of this ledger too --
    # excluded from the document twice and mentioned nowhere.
    retired = [r for r in doc.get("requirements", []) or [] if not active(r)]
    if retired:
        out += ["## No longer required", "",
                "These were in an earlier version of this document. They are listed so that",
                "their absence is an answer rather than a gap. The reason each was retired is",
                "part of the internal record and is not reproduced here.", "",
                "| Requirement | Was | Status |", "|---|---|---|"]
        for req in sorted(retired, key=lambda r: r["id"]):
            human = req.get("human") or {}
            statement = (req.get("managed") or {}).get("statement", "")
            # Not human.retired_reason. This file is publishable and `human` is
            # the internal record: a retirement reason can name the person who
            # approved an exception, and printing it verbatim moved governance
            # metadata across the boundary the repository is arranged around.
            # The fact of the retirement is public; the account of it stays where
            # the rest of the human decisions live.
            state = str(human.get("status") or "retired")
            recorded = "recorded internally" if human.get("retired_reason") else "not recorded"
            out.append(f"| {cell(req['id'])} | {cell(statement)} | {cell(state)}; reason {cell(recorded)} |")
        out.append("")

    out.append(provenance(meta))
    return "\n".join(out)


def render_traceability(doc: dict, titles: dict, meta: dict) -> str:
    reqs = [r for r in doc.get("requirements", []) or [] if active(r)]
    by_control: dict[str, list[str]] = {}
    for req in reqs:
        for source in (req.get("managed") or {}).get("sources", []) or []:
            by_control.setdefault(source, []).append(req["id"])

    out = ["# Traceability", "", DISCLAIMER, "",
           "Control to requirement. Use this to answer \"how is this control addressed?\"",
           "", "| Control | Title | Requirements |", "|---|---|---|"]
    for control in sorted(by_control, key=lambda c: (c.split("-")[0], c)):
        title = titles.get(control, "")
        out.append(f"| {cell(control)} | {cell(title)} | "
                   f"{cell(', '.join(sorted(by_control[control])))} |")

    # Requirements no control produced. This document is the auditor's, and it
    # listed only what a control maps to -- so a threat-only requirement, which
    # is the kind this tool exists to find and the kind no catalogue could have
    # given you, was absent from the one document an auditor reads for coverage.
    # The requirements document said five and this one showed four.
    # No control recorded, which is not the same claim as "the threat model
    # produced it". The linter permits a requirement with no sources and warns
    # only when it has no threat reference either, so an authoring omission
    # lands here too -- and the first version of this section asserted a
    # provenance those requirements did not have.
    #
    # The threat identifiers themselves are gone. They were in a `From` column,
    # which put the internal threat model's structure into the publishable
    # document -- the third time in one day that the private side leaked into
    # the public one through a field nobody thought of as private.
    unsourced = [r for r in reqs if not (r.get("managed") or {}).get("sources")]
    if unsourced:
        out += ["", "## No control recorded", "",
                "No control in the baseline is cited against these. Where that is because",
                "the threat model found something the catalogue has no answer for, this is",
                "the part of the document the catalogue could not have produced.", "",
                "| Requirement | Statement | Basis |", "|---|---|---|"]
        for req in sorted(unsourced, key=lambda r: r["id"]):
            managed = req.get("managed") or {}
            statement = managed.get("statement", "")
            basis = "threat model" if managed.get("threat_refs") else "not recorded"
            out.append(f"| {cell(req['id'])} | {cell(statement)} | {cell(basis)} |")

    out += ["", provenance(meta)]
    return "\n".join(out)


def render_responsibility(doc: dict, meta: dict) -> str:
    reqs = [r for r in doc.get("requirements", []) or [] if active(r)]
    buckets: dict[str, list[dict]] = {}
    for req in reqs:
        buckets.setdefault((req.get("managed") or {}).get("responsibility", "undetermined"), []).append(req)

    out = ["# Responsibility", "", DISCLAIMER, "",
           "Inheritance is a claim, not a fact. Every provider-claimed control lists the",
           "evidence an auditor will ask for.", ""]

    for bucket in ("team", "shared", "csp_claimed", "org", "undetermined"):
        items = buckets.get(bucket)
        if not items:
            continue
        out += [f"## {RESPONSIBILITY_LABEL[bucket]} ({len(items)})", ""]
        out += ["| Requirement | Statement | Evidence |", "|---|---|---|"]
        for req in sorted(items, key=lambda r: r["id"]):
            managed = req.get("managed") or {}
            evidence = managed.get("evidence") or ""
            if isinstance(evidence, list):
                evidence = "; ".join(evidence)
            marker = " ⚠ unverified" if managed.get("unverified") else ""
            statement = managed.get("statement", "")
            # The document exists to say who owns what, and it said only
            # "shared". The linter now requires both halves to be described; not
            # printing them left the requirement asserting a division it did not
            # publish.
            halves = " ".join(
                f"**{who}:** {cell(managed.get(key, '').strip())}"
                for who, key in (("provider", "csp_part"), ("team", "team_part"))
                if (managed.get(key) or "").strip()
            )
            body = f"{cell(statement)}<br>{halves}" if halves else cell(statement)
            out.append(f"| {cell(req['id'])}{marker} | {body} | {cell(evidence)} |")
        out.append("")

    out.append(provenance(meta))
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("requirements", type=Path)
    ap.add_argument("--out", type=Path, default=Path("docs/security"))
    args = ap.parse_args()

    doc = yaml.safe_load(args.requirements.read_text(encoding="utf-8")) or {}
    titles = catalog_titles()
    meta = catalog_meta()

    documents = (
        ("requirements.md", render_requirements(doc, titles, meta)),
        ("traceability.md", render_traceability(doc, titles, meta)),
        ("responsibility.md", render_responsibility(doc, meta)),
    )
    paths = [args.out / name for name, _ in documents]
    try:
        preflight_output_paths(paths)
        safe_mkdir(args.out)
    except UnsafePathError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    written = []
    for (name, content), path in zip(documents, paths):
        safe_write_text(path, content.rstrip() + "\n", encoding="utf-8")
        written.append(path)

    for path in written:
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
