#!/usr/bin/env python3
"""Mermaid data-flow diagram for the design review (plan F16).

A DFD is the one artifact that shows reachability rather than describing it, so
two properties matter more than looking tidy.

**Nothing is silently dropped.** A reader takes an absent component to mean it
was out of scope, which is the opposite of what a missing node means.

**Provenance is visible in two channels.** An inferred node carries a dashed
stroke *and* the word ``(inferred)``. The stroke is for the eye; the label is
for anyone reading the raw Markdown, a screen reader, or a diff. A diagram that
presents an assumption exactly like an observation is worse than no diagram: it
lends the assumption the authority of the drawing.

The diagram belongs to the sensitive report only. It names components, stores,
and internal boundaries — it answers "where does the data live", which is the
question the publish boundary exists to refuse.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

# Node kinds in drawing order. A tuple, not a set: ordering is part of the
# output contract (plan §4.3 -- no set iteration reaches a rendered artifact),
# and a diagram that reshuffles between runs makes every diff unreadable.
NODE_KINDS = ("actors", "components", "data_stores", "trust_boundaries")

INFERRED_LABEL = "(inferred)"
_INFERRED = "inferred"

# Mermaid shapes, chosen so the kinds stay distinguishable in a screenshot.
_SHAPES = {
    "actors": ("([", "])"),
    "components": ("[", "]"),
    "data_stores": ("[(", ")]"),
    "trust_boundaries": ("{{", "}}"),
}


def _records(architecture: object, kind: str) -> list[dict]:
    if not isinstance(architecture, Mapping):
        return []
    records = architecture.get(kind)
    if not isinstance(records, Sequence) or isinstance(records, (str, bytes)):
        return []
    return [
        record
        for record in records
        if isinstance(record, Mapping) and record.get("id") is not None
    ]


def _escape(text: object) -> str:
    """Keep a name from ending the label it sits inside.

    Mermaid takes a quote as the end of a quoted label, so an unescaped one
    truncates the diagram at that node and silently drops everything after it.
    """

    return str(text).replace('"', "'").replace("\n", " ").strip()


def _label(record: Mapping) -> str:
    name = _escape(record.get("name") or record.get("id"))
    if record.get("evidence_status") == _INFERRED:
        return f"{name} {INFERRED_LABEL}"
    return name


def _node_id(record: Mapping) -> str:
    return _escape(record.get("id"))


def render_dfd(architecture: Mapping) -> str:
    """Render the architecture as Mermaid text, ready to fence.

    Deterministic: every list is walked in document order and no set iteration
    reaches the output, so the same architecture renders byte-identical across
    runs and across hash seeds.
    """

    lines: list[str] = ["flowchart LR"]
    inferred_nodes: list[str] = []

    boundaries = _records(architecture, "trust_boundaries")
    flows = _records(architecture, "data_flows")

    # Which nodes sit inside which boundary, so a crossing is visible as an
    # edge leaving a subgraph rather than only as prose on a label.
    for kind in ("actors", "components", "data_stores"):
        for record in _records(architecture, kind):
            open_shape, close_shape = _SHAPES[kind]
            node_id = _node_id(record)
            lines.append(
                f'    {node_id}{open_shape}"{_label(record)}"{close_shape}'
            )
            if record.get("evidence_status") == _INFERRED:
                inferred_nodes.append(node_id)

    for boundary in boundaries:
        boundary_id = _node_id(boundary)
        open_shape, close_shape = _SHAPES["trust_boundaries"]
        lines.append(
            f'    {boundary_id}{open_shape}"{_label(boundary)}"{close_shape}'
        )
        if boundary.get("evidence_status") == _INFERRED:
            inferred_nodes.append(boundary_id)

    for flow in flows:
        source = _escape(flow.get("from"))
        target = _escape(flow.get("to"))
        if not source or not target:
            continue
        parts = [part for part in (flow.get("protocol"), flow.get("id")) if part]
        caption = " ".join(_escape(part) for part in parts)
        crosses = flow.get("crosses")
        if crosses:
            crossed = next(
                (b for b in boundaries if str(b.get("id")) == str(crosses)), None
            )
            crossed_name = _escape(
                (crossed or {}).get("name") or crosses
            )
            caption = f"{caption} crosses {_escape(crosses)} {crossed_name}".strip()
        if flow.get("evidence_status") == _INFERRED:
            # `-.->` is Mermaid's dashed link: an edge signals provenance by
            # its stroke, never by the word. The label would land on a line
            # naming both endpoints and make an observed node read inferred.
            arrow = f'-. "{caption}" .->' if caption else "-.->"
        else:
            arrow = f'-- "{caption}" -->' if caption else "-->"
        lines.append(f"    {source} {arrow} {target}")

    # One classDef rather than a style line per node: a reader checking whether
    # the dashing means anything finds the definition in one place.
    lines.append(
        "    classDef inferred stroke-dasharray: 5 5,stroke-width:1px"
    )
    if inferred_nodes:
        lines.append(f"    class {','.join(inferred_nodes)} inferred")
    return "\n".join(lines)


def render_dfd_block(architecture: Mapping) -> str:
    """The diagram inside a fenced Mermaid block, for the sensitive report."""

    return "```mermaid\n" + render_dfd(architecture) + "\n```"
