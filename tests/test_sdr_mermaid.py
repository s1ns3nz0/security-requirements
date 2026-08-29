"""N11 / N12 — the Mermaid DFD (F16) and the publish boundary it sits behind.

Plan of record: `docs/security-design-review-plan.md` F16 (§6), §4.1 (artifact
disclosure table), §4.2 (the `architecture` block, verbatim input shape), §4.3
(ordering — "no set iteration reaches output"), §10 (`scripts/sdr_mermaid.py`,
status **NEW**), §11.2 N11 and N12.

Pinned contract under test — the module does **not** exist yet, so every test in
this file is RED by design. It is the specification, not a report:

    scripts/sdr_mermaid.py
        render_dfd(architecture: dict) -> str
            Mermaid diagram text, ready to embed in a fenced block.

Two things this file deliberately does *not* do:

* It never calls `pytest.importorskip`. A skipped test is invisible, and an
  invisible test for a disclosure boundary is worse than no test — the run goes
  green and the reader concludes the boundary is held.
* It never hardcodes the provenance vocabulary. `risk.EVIDENCE_STATUSES` already
  ships (`risk.py:62`) as the closed set `observed | inferred | unverified`; this
  file reads it and asserts the fixture exercises all three.

N12 note on where the renderers actually live. The plan's §10 row for F17 points
at `scripts/render.py`, but `render.py` renders the three *publishable* CSF
documents (`render_requirements`, `render_traceability`, `render_responsibility`)
and contains neither `render_register` nor `render_public_summary`. Those two are
in `risk.py` — `risk.py:1136` and `risk.py:1261` — and that is what
`tests/risk_helpers.py:287-288` drives. Source wins over plan, so N12 is written
against `risk.render_register` / `risk.render_public_summary`.

Builders are local on purpose: `tests/risk_helpers.py` is under concurrent edit
by sibling agents and this file must not depend on its shape.
"""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
PLUGIN_ROOT = REPO_ROOT / "plugins" / "security-requirements"
PLUGIN_SCRIPTS = PLUGIN_ROOT / "scripts"
if str(PLUGIN_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(PLUGIN_SCRIPTS))

import risk  # noqa: E402


MERMAID_MODULE_PATH = PLUGIN_SCRIPTS / "sdr_mermaid.py"

#: Plan §11.2 N11 — the label a human reading raw Markdown (or a screen reader
#: reading it aloud) must find. The dashed stroke is for the eye only.
INFERRED_LABEL = "(inferred)"

#: Mermaid spells a dashed edge with a dotted link operator, and a dashed node
#: outline with `stroke-dasharray` in a `classDef` or an inline `style`.
DASH_STYLE_MARKERS = ("stroke-dasharray", "stroke-dash")
DASHED_LINK_MARKER = "-."

#: Syntax that only ever appears in a diagram. N12 searches the public summary
#: for all of these, not just for one component name — a renderer that emits the
#: graph without the fence still discloses the topology.
MERMAID_SYNTAX_MARKERS = (
    "```mermaid",
    "flowchart",
    "graph TD",
    "graph LR",
    "subgraph",
    "-->",
    "-.->",
    "classDef",
)


# ---------------------------------------------------------------------------
# The module under specification. Imported through a helper rather than at
# module scope so a missing module reports as a FAILURE on each test, with a
# message that names the file that has to exist, instead of one collection error.
# ---------------------------------------------------------------------------


def _render_dfd():
    try:
        import sdr_mermaid
    except ImportError as exc:  # pragma: no cover - this is the RED path
        pytest.fail(
            f"{MERMAID_MODULE_PATH} does not exist yet (plan §10, F16, status NEW). "
            f"N11/N12 specify `render_dfd(architecture: dict) -> str` in that module. "
            f"import failed: {exc}"
        )
    renderer = getattr(sdr_mermaid, "render_dfd", None)
    assert callable(renderer), (
        "sdr_mermaid must expose `render_dfd(architecture: dict) -> str`; "
        f"found {renderer!r}"
    )
    return renderer


# ---------------------------------------------------------------------------
# Fixture architecture. Shape is plan §4.2 verbatim. Ids and names are chosen so
# that no id is a substring of another id or of any name — the assertions below
# search the diagram text, and a substring collision would let a dropped node
# pass by accident.
# ---------------------------------------------------------------------------

ARCHITECTURE = {
    "actors": [
        {"id": "act-customer", "name": "Customer", "evidence_status": "observed"},
        {"id": "act-partner-batch", "name": "Partner batch", "evidence_status": "inferred"},
    ],
    "components": [
        {
            "id": "cmp-checkout-api",
            "name": "checkout-api",
            "evidence_status": "observed",
            "trust_boundary": "tb-internet",
        },
        {
            "id": "cmp-pricing-worker",
            "name": "pricing-worker",
            "evidence_status": "inferred",
            "trust_boundary": "tb-payment-zone",
        },
        {
            "id": "cmp-admin-console",
            "name": "admin-console",
            "evidence_status": "unverified",
            "trust_boundary": "tb-payment-zone",
        },
    ],
    "data_stores": [
        {
            "id": "ds-orders",
            "name": "orders-db",
            "classification": "pii",
            "evidence_status": "observed",
        },
        {
            "id": "ds-session-cache",
            "name": "session-cache",
            "classification": "internal",
            "evidence_status": "inferred",
        },
    ],
    "data_flows": [
        {
            "id": "df-public-order",
            "from": "act-customer",
            "to": "cmp-checkout-api",
            "crosses": "tb-internet",
            "protocol": "https",
            "authenticated": False,
            "evidence_status": "observed",
        },
        {
            "id": "df-cache-read",
            "from": "cmp-checkout-api",
            "to": "ds-session-cache",
            "crosses": None,
            "protocol": "redis",
            "authenticated": True,
            "evidence_status": "inferred",
        },
        {
            "id": "df-batch-price",
            "from": "act-partner-batch",
            "to": "cmp-pricing-worker",
            "crosses": "tb-payment-zone",
            "protocol": "sftp",
            "authenticated": True,
            "evidence_status": "inferred",
        },
        {
            "id": "df-admin-write",
            "from": "cmp-admin-console",
            "to": "ds-orders",
            "crosses": "tb-payment-zone",
            "protocol": "postgres",
            "authenticated": True,
            "evidence_status": "unverified",
        },
    ],
    "trust_boundaries": [
        {"id": "tb-internet", "name": "Internet edge", "evidence_status": "observed"},
        {"id": "tb-payment-zone", "name": "Payment zone", "evidence_status": "inferred"},
    ],
}

NODE_KINDS = ("actors", "components", "data_stores", "trust_boundaries")


def _architecture() -> dict:
    """A fresh deep copy, so no test can leak a mutation into the next one."""

    return copy.deepcopy(ARCHITECTURE)


def _records(architecture: dict, kind: str) -> list[dict]:
    return list(architecture.get(kind) or [])


def _by_status(architecture: dict, kind: str, status: str) -> list[dict]:
    return [r for r in _records(architecture, kind) if r.get("evidence_status") == status]


def _all_nodes(architecture: dict) -> list[tuple[str, dict]]:
    return [(kind, record) for kind in NODE_KINDS for record in _records(architecture, kind)]


# ---------------------------------------------------------------------------
# Mermaid reading helpers. These describe what "dashed" and "labelled" mean in
# the rendered text without dictating which of Mermaid's two spellings the
# renderer picks (inline `style`, or a `classDef` plus a class assignment).
# ---------------------------------------------------------------------------


def _lines(diagram: str) -> list[str]:
    return diagram.splitlines()


def _lines_mentioning(diagram: str, token: str) -> list[str]:
    return [line for line in _lines(diagram) if token in line]


def _dashed_class_names(diagram: str) -> set[str]:
    """Class names whose `classDef` carries a dashed stroke."""

    names: set[str] = set()
    for line in _lines(diagram):
        stripped = line.strip()
        if not stripped.startswith("classDef"):
            continue
        if not any(marker in stripped for marker in DASH_STYLE_MARKERS):
            continue
        parts = stripped.split()
        if len(parts) >= 2:
            names.add(parts[1].rstrip(",").strip())
    return names


def _class_assignments(diagram: str) -> dict[str, set[str]]:
    """`class a,b dashed` and `id:::dashed`, collapsed to node id -> class names."""

    assigned: dict[str, set[str]] = {}
    for line in _lines(diagram):
        stripped = line.strip()
        if stripped.startswith("class "):
            parts = stripped.split()
            if len(parts) >= 3:
                for node_id in parts[1].split(","):
                    assigned.setdefault(node_id.strip(), set()).add(parts[2].strip())
            continue
        for node_id, class_name in re.findall(r"([A-Za-z0-9_.\-]+):::([A-Za-z0-9_\-]+)", stripped):
            assigned.setdefault(node_id, set()).add(class_name)
    return assigned


def _node_is_dashed(diagram: str, node_id: str) -> bool:
    """True when the node's own declaration or its class carries a dashed stroke."""

    for line in _lines_mentioning(diagram, node_id):
        if any(marker in line for marker in DASH_STYLE_MARKERS):
            return True
    dashed_classes = _dashed_class_names(diagram)
    return bool(dashed_classes & _class_assignments(diagram).get(node_id, set()))


def _edge_lines(diagram: str, flow: dict) -> list[str]:
    """Lines that draw this flow: both endpoints, or the flow id, on one line."""

    source, target = str(flow.get("from")), str(flow.get("to"))
    lines = [line for line in _lines(diagram) if source in line and target in line]
    return lines or _lines_mentioning(diagram, str(flow.get("id")))


def _flow_is_dashed(diagram: str, flow: dict) -> bool:
    for line in _edge_lines(diagram, flow):
        if DASHED_LINK_MARKER in line:
            return True
        if any(marker in line for marker in DASH_STYLE_MARKERS):
            return True
    return False


def _crossing_flows(architecture: dict) -> list[dict]:
    return [flow for flow in _records(architecture, "data_flows") if flow.get("crosses")]


# ---------------------------------------------------------------------------
# A. The fixture itself is honest about the vocabulary it exercises.
# ---------------------------------------------------------------------------


def test_the_fixture_architecture_exercises_every_shipped_evidence_status():
    """Read `risk.EVIDENCE_STATUSES` rather than restating the three values.

    It ships today at `risk.py:62`. If a fourth provenance value is ever added,
    this test says so at once instead of letting N11 quietly stop covering it.
    """

    assert set(risk.EVIDENCE_STATUSES) == {"observed", "inferred", "unverified"}, (
        "plan §7 constraint 9 pins the provenance vocabulary at three values; "
        f"risk.EVIDENCE_STATUSES is {sorted(risk.EVIDENCE_STATUSES)!r}"
    )
    used = {
        record.get("evidence_status")
        for kind in (*NODE_KINDS, "data_flows")
        for record in _records(ARCHITECTURE, kind)
    }
    assert used == set(risk.EVIDENCE_STATUSES), (
        "the N11 fixture must exercise every provenance value; missing "
        f"{sorted(set(risk.EVIDENCE_STATUSES) - used)!r}"
    )


def test_no_fixture_identifier_is_a_substring_of_another():
    """The N11 assertions search diagram text; a collision would hide a bug."""

    identifiers = [
        str(record["id"])
        for kind in (*NODE_KINDS, "data_flows")
        for record in _records(ARCHITECTURE, kind)
    ]
    assert len(identifiers) == len(set(identifiers)), "fixture ids must be unique"
    collisions = [
        (a, b) for a in identifiers for b in identifiers if a != b and a in b
    ]
    assert collisions == [], f"fixture ids collide by substring: {collisions!r}"


# ---------------------------------------------------------------------------
# B. N11 completeness — nothing is silently dropped.
#
# A diagram that omits a component is worse than no diagram at all: the reader
# concludes the component was out of scope, and never asks about it again.
# ---------------------------------------------------------------------------


def test_render_dfd_returns_diagram_text():
    render_dfd = _render_dfd()

    diagram = render_dfd(_architecture())

    assert isinstance(diagram, str), (
        f"render_dfd must return Mermaid text ready to fence, got {type(diagram)!r}"
    )
    assert diagram.strip(), "render_dfd returned an empty diagram"


@pytest.mark.parametrize("kind", NODE_KINDS)
def test_every_node_of_each_kind_appears_in_the_diagram(kind):
    """N11 — every component, data store, actor, and boundary is drawn."""

    render_dfd = _render_dfd()
    architecture = _architecture()

    diagram = render_dfd(architecture)

    missing = [
        record
        for record in _records(architecture, kind)
        if str(record["id"]) not in diagram and str(record.get("name", "")) not in diagram
    ]
    assert missing == [], (
        f"N11: the diagram silently dropped {len(missing)} {kind} record(s) "
        f"{[r['id'] for r in missing]!r}. A reader takes an absent node to mean "
        "the node was out of scope."
    )


def test_every_data_flow_appears_in_the_diagram():
    """N11 — a dropped edge hides the reachability the DFD exists to show."""

    render_dfd = _render_dfd()
    architecture = _architecture()

    diagram = render_dfd(architecture)

    missing = [flow for flow in _records(architecture, "data_flows") if not _edge_lines(diagram, flow)]
    assert missing == [], (
        f"N11: no edge drawn for {[f['id'] for f in missing]!r}; each flow must "
        "connect its `from` and `to` nodes in the rendered text"
    )


# ---------------------------------------------------------------------------
# C. N11 provenance marking — both channels, and the negative.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", NODE_KINDS)
def test_inferred_nodes_carry_the_dashed_style(kind):
    """N11 — the dashed stroke is the visual channel."""

    render_dfd = _render_dfd()
    architecture = _architecture()
    inferred = _by_status(architecture, kind, "inferred")
    assert inferred, f"fixture guard: no inferred {kind} to assert on"

    diagram = render_dfd(architecture)

    undashed = [r["id"] for r in inferred if not _node_is_dashed(diagram, str(r["id"]))]
    assert undashed == [], (
        f"N11: inferred {kind} {undashed!r} carry no dashed stroke. Expected either "
        "`stroke-dasharray` on the node's own style line or a dashed `classDef` "
        f"assigned to it.\n---\n{diagram}\n---"
    )


@pytest.mark.parametrize("kind", NODE_KINDS)
def test_inferred_nodes_carry_a_visible_inferred_label(kind):
    """N11 — the label is the channel for raw Markdown and for screen readers.

    Asserted separately from the stroke on purpose. A renderer that dashes the
    node and says nothing tells a reader of the Markdown source, or a reader
    using assistive technology, precisely nothing.
    """

    render_dfd = _render_dfd()
    architecture = _architecture()
    inferred = _by_status(architecture, kind, "inferred")
    assert inferred, f"fixture guard: no inferred {kind} to assert on"

    diagram = render_dfd(architecture)

    unlabelled = [
        r["id"]
        for r in inferred
        if not any(INFERRED_LABEL in line for line in _lines_mentioning(diagram, str(r["id"])))
    ]
    assert unlabelled == [], (
        f"N11: inferred {kind} {unlabelled!r} carry no visible {INFERRED_LABEL!r} "
        f"label on any line that names them.\n---\n{diagram}\n---"
    )


@pytest.mark.parametrize("kind", NODE_KINDS)
def test_observed_nodes_carry_neither_the_dashed_style_nor_the_label(kind):
    """N11, the negative — marking everything inferred tells the reader nothing.

    A renderer that dashes and labels every node passes both positive tests
    above and destroys the distinction they exist to carry.
    """

    render_dfd = _render_dfd()
    architecture = _architecture()
    observed = _by_status(architecture, kind, "observed")
    assert observed, f"fixture guard: no observed {kind} to assert on"

    diagram = render_dfd(architecture)

    dashed = [r["id"] for r in observed if _node_is_dashed(diagram, str(r["id"]))]
    labelled = [
        r["id"]
        for r in observed
        if any(INFERRED_LABEL in line for line in _lines_mentioning(diagram, str(r["id"])))
    ]
    assert dashed == [], (
        f"N11: observed {kind} {dashed!r} were drawn dashed. Observed evidence is "
        "the default and must be visually unmarked, or the marking means nothing."
    )
    assert labelled == [], (
        f"N11: observed {kind} {labelled!r} were labelled {INFERRED_LABEL!r}."
    )


def test_unverified_nodes_are_not_labelled_as_inferred():
    """`unverified` is its own provenance value, not a synonym for `inferred`.

    Not parametrized by kind: only `components` carries an `unverified` record in
    the fixture, and a per-kind parametrization would pass vacuously for the
    other three.
    """

    render_dfd = _render_dfd()
    architecture = _architecture()
    unverified = [
        record
        for kind in NODE_KINDS
        for record in _by_status(architecture, kind, "unverified")
    ]
    assert unverified, "fixture guard: no unverified node to assert on"

    diagram = render_dfd(architecture)

    mislabelled = [
        r["id"]
        for r in unverified
        if any(INFERRED_LABEL in line for line in _lines_mentioning(diagram, str(r["id"])))
    ]
    assert mislabelled == [], (
        f"N11: unverified nodes {mislabelled!r} were labelled {INFERRED_LABEL!r}. "
        "risk.EVIDENCE_STATUSES keeps `unverified` and `inferred` distinct."
    )


def test_inferred_flows_carry_the_dashed_style():
    """N11 — plan §11.2 says "inferred nodes **and flows**", not nodes alone."""

    render_dfd = _render_dfd()
    architecture = _architecture()
    inferred = [f for f in _records(architecture, "data_flows") if f["evidence_status"] == "inferred"]
    assert inferred, "fixture guard: no inferred data_flows to assert on"

    diagram = render_dfd(architecture)

    undashed = [f["id"] for f in inferred if not _flow_is_dashed(diagram, f)]
    assert undashed == [], (
        f"N11: inferred flows {undashed!r} were drawn as solid edges. Mermaid "
        "spells a dashed edge with a dotted link operator (`-.->`).\n"
        f"---\n{diagram}\n---"
    )


def test_observed_flows_are_not_drawn_dashed():
    """N11, the negative, on edges."""

    render_dfd = _render_dfd()
    architecture = _architecture()
    observed = [f for f in _records(architecture, "data_flows") if f["evidence_status"] == "observed"]
    assert observed, "fixture guard: no observed data_flows to assert on"

    diagram = render_dfd(architecture)

    dashed = [f["id"] for f in observed if _flow_is_dashed(diagram, f)]
    assert dashed == [], (
        f"N11: observed flows {dashed!r} were drawn dashed. If every edge is "
        "dashed the style carries no information."
    )


# ---------------------------------------------------------------------------
# D. N11 trust boundaries — a crossing must be visible, not merely recorded.
# ---------------------------------------------------------------------------


def test_a_flow_that_crosses_a_boundary_is_visibly_associated_with_it():
    """N11 — `crosses` is the whole point of a DFD; it may not be invisible.

    Two renderings satisfy this and the test accepts either, because the choice
    belongs to the implementation: a Mermaid `subgraph` per boundary that the
    edge visibly leaves, or the boundary named on the edge label itself. What is
    not acceptable is a diagram in which the crossing appears nowhere.
    """

    render_dfd = _render_dfd()
    architecture = _architecture()
    boundaries = {str(b["id"]): b for b in _records(architecture, "trust_boundaries")}

    diagram = render_dfd(architecture)

    subgraph_lines = [line for line in _lines(diagram) if line.strip().startswith("subgraph")]
    unassociated = []
    for flow in _crossing_flows(architecture):
        boundary_id = str(flow["crosses"])
        boundary_name = str(boundaries.get(boundary_id, {}).get("name", ""))
        on_edge = any(
            boundary_id in line or (boundary_name and boundary_name in line)
            for line in _edge_lines(diagram, flow)
        )
        in_subgraph = any(
            boundary_id in line or (boundary_name and boundary_name in line)
            for line in subgraph_lines
        )
        if not (on_edge or in_subgraph):
            unassociated.append((flow["id"], boundary_id))
    assert unassociated == [], (
        "N11: these flows cross a trust boundary that the diagram never shows "
        f"them crossing: {unassociated!r}. Draw the boundary as a `subgraph` the "
        "edge leaves, or name it on the edge label.\n"
        f"---\n{diagram}\n---"
    )


def test_every_trust_boundary_that_a_flow_crosses_is_itself_drawn():
    """A `crosses` reference to a boundary the diagram omits is a dangling edge."""

    render_dfd = _render_dfd()
    architecture = _architecture()

    diagram = render_dfd(architecture)

    boundaries = {str(b["id"]): b for b in _records(architecture, "trust_boundaries")}
    missing = [
        str(flow["crosses"])
        for flow in _crossing_flows(architecture)
        if str(flow["crosses"]) not in diagram
        and str(boundaries.get(str(flow["crosses"]), {}).get("name", "\0")) not in diagram
    ]
    assert missing == [], f"N11: crossed boundaries absent from the diagram: {missing!r}"


# ---------------------------------------------------------------------------
# E. N11 determinism — plan §4.3, "no set iteration reaches output".
# ---------------------------------------------------------------------------


def test_the_same_architecture_renders_byte_identical_twice():
    render_dfd = _render_dfd()

    first = render_dfd(_architecture())
    second = render_dfd(_architecture())

    assert first == second, (
        "N11 / plan §4.3: render_dfd is not deterministic within one process. "
        "Two renders of the same architecture differed."
    )


def test_render_dfd_does_not_mutate_the_architecture_it_is_given():
    """A renderer that sorts its input in place makes the caller's next read lie."""

    render_dfd = _render_dfd()
    architecture = _architecture()
    before = copy.deepcopy(architecture)

    render_dfd(architecture)

    assert architecture == before, "render_dfd mutated the architecture mapping it was passed"


def test_the_diagram_is_stable_across_python_hash_seeds():
    """Plan §4.3 — "no set iteration reaches output", asserted the only real way.

    Set and frozenset iteration order is seeded per process. Rendering twice in
    one process cannot catch it; two processes with different `PYTHONHASHSEED`
    values can, and this is the same technique the repository already relies on
    for digest stability.
    """

    _render_dfd()  # fail here, with the module-missing message, before forking

    probe = (
        "import json, sys\n"
        "sys.path.insert(0, sys.argv[1])\n"
        "import sdr_mermaid\n"
        "sys.stdout.write(sdr_mermaid.render_dfd(json.loads(sys.stdin.read())))\n"
    )
    payload = json.dumps(ARCHITECTURE, ensure_ascii=False, sort_keys=True)

    outputs = {}
    for seed in ("0", "1", "42"):
        env = os.environ.copy()
        env["PYTHONHASHSEED"] = seed
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        completed = subprocess.run(
            [sys.executable, "-c", probe, str(PLUGIN_SCRIPTS)],
            input=payload,
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )
        assert completed.returncode == 0, (
            f"render_dfd failed under PYTHONHASHSEED={seed}: {completed.stderr.strip()}"
        )
        outputs[seed] = completed.stdout

    assert len(set(outputs.values())) == 1, (
        "N11 / plan §4.3: the diagram changed with PYTHONHASHSEED, so set or dict "
        "iteration over an unordered collection is reaching the output. "
        f"seeds rendered {len(set(outputs.values()))} distinct diagrams."
    )


# ---------------------------------------------------------------------------
# F. N12 — the diagram is embedded only in the sensitive report.
#
# A DFD names components, data stores, and internal trust boundaries. It answers
# "where does the data live and what talks to it", which is exactly the question
# the publish boundary exists to refuse. `render.py` documents that boundary at
# length: status, exception expiry, threat ids, and `retired_reason` have each
# crossed it once and each been fixed.
# ---------------------------------------------------------------------------


def _report_summary(diagram: str | None = None) -> dict:
    """A report summary shaped the way `risk_helpers._golden_report` builds one.

    `inherent` / `residual` must survive `risk._validated_public_section`: counts
    sum to the confirmed half of `coverage`, and `overall` is the highest rating
    with a nonzero count.
    """

    summary = {
        "architecture": _architecture(),
        "inherent": {
            "overall": "high",
            "status": "confirmed",
            "counts": {"critical": 0, "high": 1, "medium": 1, "low": 0},
            "coverage": "2/2",
        },
        "residual": {
            "overall": "medium",
            "status": "provisional",
            "counts": {"critical": 0, "high": 0, "medium": 1, "low": 1},
            "coverage": "2/2",
        },
        "risks": [
            {
                "threat_id": "T-09",
                "scenario": "Anonymous caller POSTs an order and alters line items.",
                "attack_path": "public_write_route",
                "lifecycle": "active",
                "calculated": {"likelihood": 4, "impact": 4, "score": 16, "rating": "high"},
            },
            {
                "threat_id": "T-11",
                "scenario": "Batch price file is trusted without origin authentication.",
                "attack_path": "partner_batch",
                "lifecycle": "active",
                "calculated": {"likelihood": 2, "impact": 3, "score": 6, "rating": "medium"},
            },
        ],
    }
    if diagram is not None:
        summary["diagram"] = diagram
    return summary


def test_the_register_and_public_summary_renderers_live_where_this_file_expects():
    """Guard on the pinned surface, so N12's failure is never a typo in a name.

    Recorded because the plan and the source disagree: plan §10 files report
    rendering under `scripts/render.py`, but `render.py` holds only the three
    publishable CSF documents. `render_register` is `risk.py:1136` and
    `render_public_summary` is `risk.py:1261`.
    """

    assert callable(getattr(risk, "render_register", None)), (
        "risk.render_register(summary: dict) -> str is the sensitive-register renderer"
    )
    assert callable(getattr(risk, "render_public_summary", None)), (
        "risk.render_public_summary(summary: dict, policy: dict) -> str | None is the "
        "publishable renderer"
    )
    render_py = (PLUGIN_SCRIPTS / "render.py").read_text(encoding="utf-8")
    assert "def render_register" not in render_py, (
        "if render_register moved into render.py, N12 must be repointed at it"
    )


def test_the_public_summary_is_unreachable_unless_the_policy_opts_in():
    """§4.1 — with `publish_risk_summary: false` nothing publishable is written.

    Recorded here because it changes how N12's negative half must be read: the
    default policy produces `None`, so a test that only checked the default would
    prove nothing about what a *published* summary contains.
    """

    summary = _report_summary()

    assert risk.render_public_summary(summary, {"publish_risk_summary": False}) is None
    assert risk.render_public_summary(summary, {}) is None
    published = risk.render_public_summary(summary, {"publish_risk_summary": True})
    assert isinstance(published, str) and published.strip(), (
        "with publish_risk_summary: true a summary must actually render"
    )


def test_the_diagram_is_embedded_in_the_sensitive_register():
    """N12, the positive half. RED because nothing wires the renderer in yet.

    This asserts wiring, not diagram correctness: `risk.render_register` — the
    renderer of the sensitive internal record — must contain the Mermaid diagram
    for the architecture in the report summary.
    """

    render_dfd = _render_dfd()
    diagram = render_dfd(_architecture())
    summary = _report_summary(diagram=diagram)

    register = risk.render_register(summary)

    body = "\n".join(line for line in _lines(diagram) if line.strip())
    assert body and body in register, (
        "N12: the sensitive register does not embed the Mermaid DFD. This is a "
        "MISSING WIRING failure, not a wrong rule: risk.render_register "
        "(risk.py:1136) never calls any mermaid renderer, and no caller passes "
        "the rendered diagram through to it. F16 requires the DFD to reach the "
        "sensitive report."
    )


def test_the_sensitive_register_names_the_architecture_it_diagrams():
    """N12 — the register is the artifact allowed to say where the data lives."""

    render_dfd = _render_dfd()
    summary = _report_summary(diagram=render_dfd(_architecture()))

    register = risk.render_register(summary)

    architecture = _architecture()
    absent = [
        record["id"]
        for kind, record in _all_nodes(architecture)
        if str(record["id"]) not in register and str(record.get("name", "")) not in register
    ]
    assert absent == [], (
        "N12: the sensitive register mentions none of "
        f"{absent!r}. The DFD is supposed to be embedded here — this is the "
        "missing wiring between sdr_mermaid.render_dfd and risk.render_register."
    )


def test_no_mermaid_syntax_reaches_the_published_summary():
    """N12, the negative half — asserted on syntax, not on one component name.

    Searching for a single component name would pass against a renderer that
    emitted the graph with the names elided but the topology intact. The
    diagram's *syntax* is the thing that must be absent.
    """

    render_dfd = _render_dfd()
    summary = _report_summary(diagram=render_dfd(_architecture()))

    published = risk.render_public_summary(summary, {"publish_risk_summary": True})

    assert published is not None, "publish_risk_summary: true must render a summary"
    leaked = [marker for marker in MERMAID_SYNTAX_MARKERS if marker in published]
    assert leaked == [], (
        "N12: Mermaid syntax reached the publishable summary "
        f"({leaked!r}). A DFD answers \"where does the data live\", which is "
        "exactly what docs/security/ may not say.\n"
        f"---\n{published}\n---"
    )


def test_no_architecture_identifier_reaches_the_published_summary():
    """N12 — no component, data store, boundary, actor, or flow id or name."""

    render_dfd = _render_dfd()
    summary = _report_summary(diagram=render_dfd(_architecture()))
    architecture = _architecture()

    published = risk.render_public_summary(summary, {"publish_risk_summary": True})

    assert published is not None, "publish_risk_summary: true must render a summary"
    leaked = sorted(
        {
            token
            for kind in (*NODE_KINDS, "data_flows")
            for record in _records(architecture, kind)
            for token in (str(record["id"]), str(record.get("name", "")))
            if token and token in published
        }
    )
    assert leaked == [], (
        f"N12: architecture identifiers reached the publishable summary: {leaked!r}. "
        "The publish boundary carries bands, counts, verdict, scope, and "
        "limitations — never the topology."
    )
