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

    verdict = report.get("verdict")
    if isinstance(verdict, Mapping):
        out += ["## Verdict", "", str(verdict.get("statement", "")), ""]

    # The register itself is `render_register`'s job, and it already embeds the
    # data-flow diagram. Reproducing either here would give the sensitive
    # document two renderers that can disagree.
    out.append(risk_mod.render_register(_register_summary(report)))
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
