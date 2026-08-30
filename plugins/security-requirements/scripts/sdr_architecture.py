#!/usr/bin/env python3
"""The architecture document (plan §4.2, §10).

`.security-requirements/architecture.yaml` is what a design review scores
against: the actors, components, stores, flows and boundaries the review
believes exist. It is a new file, which §5.4 permits; a new top-level key on
`threats.yaml` is what it forbids, and would move every `threat_digest`
besides.

The document arrived late. §4.2 specified this block key by key while naming no
file for it, and both `render_register` (which embeds the Mermaid DFD) and
`sdr_scope.resolve_scope` were already consuming an architecture mapping — the
consumers shipped before the producer. This module is the producer's validator.

Two decisions worth stating, because both had a plausible alternative:

`cia_relevance` carries the **authored long form** (`confidentiality`), not the
rendered letter (`c`). §4.2's example shows the letter, but that example is the
*report*, and §5.3 is a decision of record: long form in, short form out, with
`risk.CIA_OUTPUT_KEYS` as the map. Accepting letters on input would need a
`migrate()` path, which §5.4 forbids, and would make this the only authored CIA
field in the tree spelled unlike every other.

The version key is `version`, not `schema_version`. Every document the store
already writes spells it `version` — `threats.yaml`, `profile.yaml`, and the
closed key set `_bound_residual_assessment_problems` enforces on
`risk-assessment.yaml`. `schema_version` is the *report's* top-level key, an
output field. A new document spelling its version key unlike its three siblings
is a papercut forever.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import risk as risk_mod  # noqa: E402


#: The seven kinds of §4.2, in the order they are reported. Fixed rather than
#: derived from the document, so a missing kind is an empty list rather than an
#: absent key and the output is byte-stable (§4.3).
#:
#: Wider than `sdr_scope.ARCHITECTURE_KINDS`, which partitions five: an asset
#: and a dependency are not reviewable elements and never appear in
#: `run.scope`. Uniqueness is still enforced across all seven, because an id
#: colliding outside the partition is no less ambiguous to a reader.
KINDS = (
    "actors",
    "components",
    "data_stores",
    "data_flows",
    "trust_boundaries",
    "assets",
    "dependencies",
)

#: Kinds whose records state how the fact was established. An asset and a
#: dependency are authored claims rather than observations of the running
#: system, so neither carries `evidence_status`.
EVIDENCE_STATUS_KINDS = (
    "actors",
    "components",
    "data_stores",
    "data_flows",
    "trust_boundaries",
)

#: `risk.CIA_OUTPUT_KEYS` maps authored long form to rendered letter, so its
#: keys are the vocabulary a document may use and its values are what must not
#: appear on input.
CIA_LONG_FORM = frozenset(risk_mod.CIA_OUTPUT_KEYS)
CIA_RENDERED_LETTERS = frozenset(risk_mod.CIA_OUTPUT_KEYS.values())

#: Reference fields, by kind: the field, and the kinds its value may name.
#: A table rather than a chain of `if`s (policy-as-data, §10.1) — adding a kind
#: means adding a row.
REFERENCE_FIELDS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("components", "trust_boundary", ("trust_boundaries",)),
    # A flow runs between any two modelled things; `crosses` names a boundary.
    ("data_flows", "from", KINDS),
    ("data_flows", "to", KINDS),
    ("data_flows", "crosses", ("trust_boundaries",)),
)


def _records(document: object, kind: str) -> list:
    """Records of one kind, tolerating a missing or malformed document.

    Returns the raw entries rather than only the mappings: a non-mapping entry
    is a problem to report, and dropping it here would report nothing.
    """

    if not isinstance(document, Mapping):
        return []
    entries = document.get(kind)
    if not isinstance(entries, Sequence) or isinstance(entries, (str, bytes)):
        return []
    return list(entries)


def _record_id(record: object) -> str | None:
    """The usable id of a record, or `None` when it has none."""

    if not isinstance(record, Mapping):
        return None
    record_id = record.get("id")
    if not isinstance(record_id, str) or not record_id.strip():
        return None
    return record_id


def architecture_ids(document: object) -> dict[str, list[str]]:
    """Every declared id, by kind, in document order.

    Every kind is present even when the document models none of it. A caller
    reading `ids["assets"]` gets `[]` rather than a `KeyError`, so "modelled
    nothing" and "unknown kind" stay distinguishable.
    """

    listed: dict[str, list[str]] = {}
    for kind in KINDS:
        seen: set[str] = set()
        ordered: list[str] = []
        for record in _records(document, kind):
            record_id = _record_id(record)
            if record_id is not None and record_id not in seen:
                seen.add(record_id)
                ordered.append(record_id)
        listed[kind] = ordered
    return listed


def _declared(document: object) -> dict[str, str]:
    """Every declared id mapped to the kind that declared it."""

    owner: dict[str, str] = {}
    for kind, ids in architecture_ids(document).items():
        for record_id in ids:
            owner.setdefault(record_id, kind)
    return owner


def _validate_ids(document: object, problems: list[str]) -> None:
    """Every record has a usable id, and no id is claimed twice.

    Uniqueness is document-wide, not per kind. A `data_flow` and a `component`
    sharing an id makes `resolve_scope`'s partition ambiguous — the same string
    would land on one side as a flow and the other as a component, and the two
    halves of the record would disagree about the same id.
    """

    owner: dict[str, str] = {}
    for kind in KINDS:
        for position, record in enumerate(_records(document, kind)):
            if not isinstance(record, Mapping):
                problems.append(
                    f"{kind} entry {position} must be a mapping"
                )
                continue
            record_id = _record_id(record)
            if record_id is None:
                problems.append(f"{kind} entry {position} id is required")
                continue
            if record_id in owner:
                problems.append(
                    f"{kind} id {record_id} is already declared "
                    f"by {owner[record_id]}"
                )
                continue
            owner[record_id] = kind


def _validate_references(document: object, problems: list[str]) -> None:
    """Every reference names an id the document declares, under a usable kind."""

    declared = _declared(document)
    for kind, field, permitted in REFERENCE_FIELDS:
        for record in _records(document, kind):
            if not isinstance(record, Mapping):
                continue
            record_id = _record_id(record)
            value = record.get(field)
            if value is None:
                # A component in no boundary, or a flow that crosses none.
                # Absence is a legitimate statement, not an omission.
                continue
            if not isinstance(value, str) or not value.strip():
                problems.append(
                    f"{kind} {record_id} {field} must be an id"
                )
                continue
            owner = declared.get(value)
            if owner is None:
                problems.append(
                    f"{kind} {record_id} {field} names an undeclared id: {value}"
                )
            elif owner not in permitted:
                # Named something real, of the wrong kind. Worth its own
                # message: the id resolves, so "undeclared" would send the
                # author looking for a typo that is not there.
                problems.append(
                    f"{kind} {record_id} {field} names a {owner} id, "
                    f"expected one of {', '.join(permitted)}: {value}"
                )


def _validate_evidence_status(document: object, problems: list[str]) -> None:
    """`evidence_status` is stated, and drawn from the closed set."""

    for kind in EVIDENCE_STATUS_KINDS:
        for record in _records(document, kind):
            if not isinstance(record, Mapping):
                continue
            record_id = _record_id(record)
            status = record.get("evidence_status")
            if status is None:
                # Required rather than defaulted. "We did not record how we
                # know this" and "we observed it" are different claims, and a
                # default would render the first as the second.
                problems.append(
                    f"{kind} {record_id} evidence_status is required"
                )
                continue
            if status not in risk_mod.EVIDENCE_STATUSES:
                problems.append(
                    f"{kind} {record_id} evidence_status is not one of "
                    f"{', '.join(sorted(risk_mod.EVIDENCE_STATUSES))}: {status}"
                )


def _validate_assets(document: object, problems: list[str]) -> None:
    """`cia_relevance` carries the authored long form, never the letter."""

    for record in _records(document, "assets"):
        if not isinstance(record, Mapping):
            continue
        record_id = _record_id(record)
        relevance = record.get("cia_relevance")
        if relevance is None:
            continue
        if relevance in CIA_RENDERED_LETTERS:
            # Named precisely, because the author wrote something meaningful
            # in the wrong vocabulary. "not one of confidentiality, integrity,
            # availability" alone reads as a typo rather than as a spelling
            # rule they can look up.
            long_form = next(
                key
                for key, letter in risk_mod.CIA_OUTPUT_KEYS.items()
                if letter == relevance
            )
            problems.append(
                f"assets {record_id} cia_relevance {relevance} is the rendered "
                f"letter; documents carry the authored long form: {long_form}"
            )
            continue
        if relevance not in CIA_LONG_FORM:
            problems.append(
                f"assets {record_id} cia_relevance is not one of "
                f"{', '.join(sorted(CIA_LONG_FORM))}: {relevance}"
            )


#: What a threat's `boundary` field may name.
#:
#: Both, and the reason is a namespace collision the register already carries.
#: `threats.yaml` has its own top-level `boundaries:` block whose records are
#: `{id, from, to}` with `TB-n` ids — structurally a *flow*, named a boundary.
#: §4.2 splits those into `trust_boundaries` (`{id, name}` zones, `tb-internet`)
#: and `data_flows` (`{id, from, to, crosses}`, `df-3`). Intake maps the
#: register's entries into `data_flows`, since that is what they are; a
#: §4.2-native document spells the same field against `trust_boundaries`.
#: Accepting either resolves both without a migration.
#:
#: Still not a flat bag of every id: a component under the field that means
#: boundary must not resolve, or the record renders a boundary column naming
#: something that is not one.
BOUNDARY_REFERENCE_KINDS = ("trust_boundaries", "data_flows")

#: `target.kind` spells a kind in the singular; `architecture_ids` keys it in
#: the plural.
TARGET_KIND_ALIASES = {kind.rstrip("s"): kind for kind in KINDS}
TARGET_KIND_ALIASES.update({kind: kind for kind in KINDS})


def _threat_references(threat: Mapping) -> list[tuple[str, str, tuple[str, ...]]]:
    """`(field, value, permitted kinds)` for every reference on one threat.

    §7.13 names "a component, boundary, or flow id". The stored record carries
    one of the three — `boundary`. The other two appear only on §4.2's report
    `target` block, so that is the vocabulary used here rather than a field
    name invented for the occasion. The `target` rows are inert against every
    fixture on disk and go live the moment a record carries the key.
    """

    references: list[tuple[str, str, tuple[str, ...]]] = []
    boundary = threat.get("boundary")
    if isinstance(boundary, str) and boundary.strip():
        references.append(("boundary", boundary, BOUNDARY_REFERENCE_KINDS))

    target = threat.get("target")
    if not isinstance(target, Mapping):
        return references

    component = target.get("component")
    if isinstance(component, str) and component.strip():
        references.append(("target.component", component, ("components",)))

    trust_boundary = target.get("trust_boundary")
    if isinstance(trust_boundary, str) and trust_boundary.strip():
        references.append(
            ("target.trust_boundary", trust_boundary, BOUNDARY_REFERENCE_KINDS)
        )

    ref = target.get("ref")
    if isinstance(ref, str) and ref.strip():
        # §4.2 pairs `ref` with an explicit `kind`. With no kind, or one this
        # module does not know, there is nothing to be strict about, and
        # rejecting an id the architecture genuinely declares would be a false
        # problem the operator has no way to fix.
        kind = target.get("kind")
        permitted = KINDS
        if isinstance(kind, str):
            resolved = TARGET_KIND_ALIASES.get(kind.strip())
            if resolved is not None:
                permitted = (resolved,)
        references.append(("target.ref", ref, permitted))
    return references


def _active_threats(threats_doc: object) -> list[Mapping]:
    """Active threat records, skipping history and never raising.

    `risk._duplicate_threat_pairs` already establishes both the rule and the
    mechanism, so this reuses `_lifecycle_status` rather than inventing a
    second notion of "active". A retired threat is history the register keeps
    on purpose, and a superseded one routinely points at architecture that was
    decommissioned alongside it; reporting either would make retirement
    generate permanent noise the operator could only silence by deleting the
    history.

    `_lifecycle_status` raises on a malformed status. `_validate_threats`
    already reports that record, and §8's "run completes" forbids a second
    reporter from taking the process down over it.
    """

    if not isinstance(threats_doc, Mapping):
        return []
    declared = threats_doc.get("threats")
    if not isinstance(declared, Sequence) or isinstance(declared, (str, bytes)):
        return []

    active: list[Mapping] = []
    for record in declared:
        if not isinstance(record, Mapping):
            continue
        try:
            status = risk_mod._lifecycle_status(record)
        except (risk_mod.RiskValidationError, TypeError, AttributeError):
            continue
        if status == "active":
            active.append(record)
    return active


def unknown_architecture_refs(
    threats_doc: object, architecture: object
) -> list[str]:
    """Threat references naming ids the architecture does not declare.

    §7.13 is an *edge case*, not a loud failure: §8 says the problem is
    reported, the run completes, and the limitation is recorded. A review that
    aborts because one threat names a stale component id is strictly less
    useful than one that scores the other seven and says which reference it
    could not resolve. So this returns problems and never raises.
    """

    declared = _declared(architecture)
    references = [
        (record.get("id"), field, value, permitted)
        for record in _active_threats(threats_doc)
        for field, value, permitted in _threat_references(record)
    ]
    if not references:
        return []

    if not declared:
        # Every reference in the register is unresolvable at once. One problem
        # per reference turns a single missing document into a wall of
        # identical lines, each naming a different threat and none naming the
        # cause. The cause is one thing, so it is one problem.
        return [
            "architecture declares no ids, so no threat reference resolves: "
            f"{len(references)} reference(s) across the register"
        ]

    problems: list[str] = []
    for threat_id, field, value, permitted in references:
        owner = declared.get(value)
        if owner is None:
            # Both ids in every message. "invalid reference" names neither the
            # record to open nor the id to fix.
            problems.append(
                f"{threat_id} {field} names an id absent from the "
                f"architecture: {value}"
            )
        elif owner not in permitted:
            problems.append(
                f"{threat_id} {field} names a {owner} id, expected one of "
                f"{', '.join(permitted)}: {value}"
            )
    return problems


def validate_architecture(document: object) -> list[str]:
    """Return problems with the architecture document, in document order.

    House convention (§10.1): returns `list[str]` and never raises. Every
    offending record is reported rather than the first — a document with three
    bad references should take one round of review, not three.

    An architecture that models nothing is a valid document. A project may
    genuinely have nothing modelled yet, and refusing that would make the
    first run of a new repository an error.
    """

    if document is None:
        return ["architecture document must be a mapping"]
    if not isinstance(document, Mapping):
        return ["architecture document must be a mapping"]

    problems: list[str] = []
    for kind in KINDS:
        # Absent and present-but-malformed are different documents. A kind the
        # author never wrote is "not modelled"; `actors: null` is something
        # they wrote wrong, and `sdr_scope._records` would read it as an empty
        # model and review nothing without saying so.
        if kind not in document:
            continue
        entries = document[kind]
        if not isinstance(entries, Sequence) or isinstance(entries, (str, bytes)):
            problems.append(f"{kind} must be a list")

    _validate_ids(document, problems)
    _validate_references(document, problems)
    _validate_evidence_status(document, problems)
    _validate_assets(document, problems)
    return problems
