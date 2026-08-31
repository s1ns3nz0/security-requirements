#!/usr/bin/env python3
"""The artifact set of one design-review run, and the publish boundary.

§4.1 is the table this module implements. It also records that `status`,
`exception`, `expiry`, threat ids, and `retired_reason` have *each* leaked
across the sensitive/publishable boundary once and been fixed — five separate
incidents on one seam. That is why this is its own module with its own tests:
so there is one obvious place to look when a sixth is suspected.

Three rules, none of them re-derived here:

**What may be rendered at all** is `risk.output_allowed`, the rule extracted
from `main`'s residual branch so the two callers share one copy. Two copies
agree on the day they are written and diverge on the day one is fixed.

**What may be published** is `risk.render_public_summary`, which returns `None`
unless the policy opts in. This module adds an entry when the return is not
`None` and asks no further questions — re-deciding publishability would give
the boundary a second opinion.

**How it reaches disk** is `risk._write_text_transaction`, in exactly one call.
§4.1: a partial write that leaves a published summary beside a missing
sensitive report is a disclosure bug, not an inconvenience. That function also
refuses key material before writing a byte, so this module inherits the refusal
rather than screening content itself.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import risk as risk_mod  # noqa: E402


#: `publish.py:1061` `_risk_paths` — the sensitive tree.
STORE_DIRNAME = ".security-requirements"
#: §4.1 — the publishable tree.
PUBLISH_DIRNAME = Path("docs") / "security"

#: §4.1, by disclosure class.
PREVIEW_ARTIFACT = "design-review.preview.md"
REPORT_ARTIFACT = "design-review.md"
JSON_ARTIFACT = "design-review.json"
PUBLISHABLE_ARTIFACT = "design-review-summary.md"

#: The word a preview must carry. A preview that reads like a finished review
#: is the disclosure failure: the reader cannot tell a scored draft from a
#: confirmed one, and acts on the draft.
UNCONFIRMED_MARKER = "UNCONFIRMED"


def _register_summary(report: Mapping) -> dict:
    """The §4.2 report, in the vocabulary `render_register` reads.

    The renderers predate the report and speak a different dialect:
    `render_register` looks for `risks`/`assessments` whose records key on
    `threat_id`, while §4.2 calls them `findings` keyed on `id`. Adapting here
    rather than renaming either side — §4.2 is the contract of record and
    `render_register` is `EXISTS` in §10, so neither gets to move.
    """

    findings = report.get("findings")
    findings = list(findings) if isinstance(findings, Sequence) and not isinstance(
        findings, (str, bytes)
    ) else []
    return {
        "risks": [
            {**dict(finding), "threat_id": finding.get("id")}
            for finding in findings
            if isinstance(finding, Mapping)
        ],
        "architecture": report.get("architecture"),
    }


def _public_summary(report: Mapping) -> dict:
    """The aggregate section `render_public_summary` validates.

    It expects `overall`, `counts` and `coverage` — the shape `aggregate_risk`
    returns — either at the top level or under `inherent`. §4.2 nests that
    aggregate one level deeper, under `verdict`.

    Deliberately *only* the aggregate. Handing the whole report to the public
    renderer and trusting it to omit the rest is how a field crosses this
    boundary: §4.1 lists five that already have. What is not passed cannot
    leak.
    """

    verdict = report.get("verdict")
    inherent = verdict.get("inherent") if isinstance(verdict, Mapping) else None
    return {"inherent": dict(inherent)} if isinstance(inherent, Mapping) else {}


def _render_markdown(report: Mapping, *, confirmed: bool) -> str:
    """The sensitive document. Everything the run knows, plainly."""

    heading = "Design review" if confirmed else f"Design review ({UNCONFIRMED_MARKER})"
    out = [f"# {heading}", ""]
    if not confirmed:
        out += [
            f"> **{UNCONFIRMED_MARKER}.** No trusted confirmation was supplied, "
            "so this is a preview. It is not an authoritative record and "
            "nothing here has been bound to a confirmation.",
            "",
        ]
    out += ["> Sensitive internal record. Do not publish.", ""]

    # What was reviewed, before what was found. A reader deciding whether this
    # document describes their service needs the commit and the scope first,
    # and until now both reached only the JSON — which an unconfirmed run never
    # writes, so the preview stated none of it.
    run = report.get("run")
    if isinstance(run, Mapping):
        repo = run.get("repo") if isinstance(run.get("repo"), Mapping) else {}
        scope = run.get("scope") if isinstance(run.get("scope"), Mapping) else {}
        rows = [
            ("Branch", repo.get("branch")),
            ("Commit", repo.get("commit")),
            ("Mode", run.get("mode")),
            ("Risk appetite", run.get("risk_appetite")),
            ("Scope", scope.get("scope_filter") or "whole model"),
            ("Plugin version", run.get("plugin_version")),
            ("Run at", run.get("timestamp")),
        ]
        out += ["## Run", "", "| Field | Value |", "|---|---|"]
        # "not recorded" rather than a blank cell: a blank reads as an oversight
        # and this one is a stated fact — the tree had no repository, or N36
        # forbade computing it.
        out += [f"| {label} | {value if value else 'not recorded'} |" for label, value in rows]
        out.append("")

    verdict = report.get("verdict")
    if isinstance(verdict, Mapping):
        out += ["## Verdict", "", str(verdict.get("statement", "")), ""]

    # The register itself is `render_register`'s job, and it already embeds the
    # data-flow diagram. Reproducing either here would give the sensitive
    # document two renderers that can disagree.
    out.append(risk_mod.render_register(_register_summary(report)))
    out.append("")

    # N17/N18. Fenced and labelled, so a reader can tell attacker prose from
    # the review's own words. The label is the whole point: the same sentence
    # unlabelled reads as a finding, which is exactly what an injection is for.
    quoted = report.get("untrusted_content")
    if isinstance(quoted, Sequence) and not isinstance(quoted, (str, bytes)) and quoted:
        out += [
            "## Untrusted content",
            "",
            "> The repository under review contains text addressed to the "
            "reviewer. It is **untrusted content**, quoted here so it can be "
            "judged, and it was not acted on. Nothing in the block below is a "
            "finding or an instruction.",
            "",
        ]
        for record in quoted:
            if not isinstance(record, Mapping):
                continue
            # The label repeats on every entry rather than sitting once under
            # the heading. A reader scrolling into the middle of a long list,
            # or a tool reading a window around one quote, has to be able to
            # tell what it is looking at without the heading in view — and a
            # section heading is exactly what scrolling loses first.
            out += [
                f"- Untrusted content from `{record.get('location')}` — "
                f"{record.get('why')}:",
                "",
                "```text",
                str(record.get("quoted", "")),
                "```",
                "",
            ]

    # F12/§8. Rendered only when the key exists: a service with no AI gets no
    # heading, no sentence, and no mention of the taxonomy at all.
    ai = report.get("ai_coverage")
    if isinstance(ai, Mapping):
        out += ["## AI threat taxonomy", ""]
        components = ai.get("components")
        if isinstance(components, Sequence) and not isinstance(components, (str, bytes)):
            out += [
                f"- `{record.get('component_id')}` — {record.get('why')}"
                for record in components
                if isinstance(record, Mapping)
            ]
            out.append("")
        uncovered = ai.get("uncovered")
        titles = {
            entry.get("id"): entry.get("title")
            for entry in ai.get("categories", [])
            if isinstance(entry, Mapping)
        }
        if isinstance(uncovered, Sequence) and not isinstance(uncovered, (str, bytes)):
            if uncovered:
                out += [
                    "No active threat addresses these categories. That is a gap "
                    "in the threat model, not a finding — the model belongs to "
                    "whoever ran the interview.",
                    "",
                ]
                out += [
                    f"- **{item}** {titles.get(item, '')}".rstrip()
                    for item in uncovered
                ]
            else:
                out.append("Every taxonomy category is addressed by an active threat.")
            out.append("")

    limitations = report.get("limitations")
    if isinstance(limitations, Sequence) and not isinstance(limitations, (str, bytes)):
        out += ["## Limitations", ""]
        out += [f"- {item}" for item in limitations]
        out.append("")
    return "\n".join(out)


def artifact_entries(
    report: Mapping,
    *,
    project_root: Path,
    output_root: Path | None = None,
    policy: Mapping | None = None,
    confirmed: bool = False,
    problems: Sequence[str] = (),
    evidence_problems: Sequence[str] = (),
) -> list[tuple]:
    """The `_write_text_transaction` tuples for one run.

    `[]` means write nothing, which is what N29 requires of a suppressed run —
    *all* rendered output, the preview included. A suppressed run that still
    writes a preview presents untrusted material as a calculated result, which
    is the failure the rule exists to prevent.
    """

    if not risk_mod.output_allowed(list(problems), list(evidence_problems)):
        return []

    root = Path(output_root) if output_root is not None else Path(project_root)
    policy = dict(policy) if isinstance(policy, Mapping) else {}
    store = root / STORE_DIRNAME
    entries: list[tuple] = []

    document = _render_markdown(report, confirmed=confirmed)
    if not confirmed:
        # N26. The preview is what an unconfirmed run produces *instead of* the
        # authoritative set, never alongside it: two documents describing one
        # run leaves a reader holding the stale one with no way to tell.
        entries.append((store / PREVIEW_ARTIFACT, root, document, True))
        return entries

    entries.append((store / REPORT_ARTIFACT, root, document, True))
    entries.append(
        (
            store / JSON_ARTIFACT,
            root,
            # The §4.2 record itself, not a rendering of it. `sort_keys` because
            # §4.3 requires the bytes to be stable across two identical runs.
            json.dumps(dict(report), indent=2, sort_keys=True) + "\n",
            True,
        )
    )

    # The publish decision belongs to `render_public_summary`: it returns None
    # unless `publish_risk_summary` is true, and a withheld summary is not
    # written at all rather than written redacted.
    summary = risk_mod.render_public_summary(_public_summary(report), policy)
    if summary is not None:
        entries.append((root / PUBLISH_DIRNAME / PUBLISHABLE_ARTIFACT, root, summary, True))
    return entries


def write_artifacts(entries: Sequence[tuple]) -> None:
    """Write the whole set as one unit, or write none of it.

    One call, always. §4.1: a partial write that leaves a published summary
    beside a missing sensitive report is a disclosure bug, and two calls is how
    that happens.
    """

    risk_mod._write_text_transaction(list(entries))
