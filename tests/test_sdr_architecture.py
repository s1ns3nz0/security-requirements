"""The architecture document (plan §4.2) — the block that had no producer.

Plan of record: `docs/security-design-review-plan.md` §4.2 (the `architecture`
block, spelled out in full at lines 206-231), §4.3 (ordering — "no set iteration
reaches output"), §5.3 (CIA vocabulary — "long form in, short form out"), §5.4
(new documents are allowed; new top-level keys on existing documents are not),
§7.13 ("Threat referencing a component, boundary, or flow id absent from the
architecture"), §8 (malformed and empty inputs), §10.1 (the house error
convention: `validate_*` returns `list[str]`, never raises).
Contract of record: `docs/design-review-runner-contract.md` §7, Gap 1.

**Why this file exists.** §4.2 specifies the largest block of the report in
full, and then the plan names no file for it, gives it no producer, and §10 has
no row for it. Both consumers shipped anyway: `risk.render_register`
(`risk.py:1362`) reads `summary["architecture"]` to embed the Mermaid DFD, and
`sdr_scope.resolve_scope` takes an architecture mapping as its first argument.
Every existing test for either one builds that mapping locally, so nothing in
the tree has ever said what a *valid* architecture is. Gap 1 is now decided:
the document is `.security-requirements/architecture.yaml`, a new file written
by intake. §5.4 permits it — it forbids new top-level keys on existing
documents, not new documents.

Pinned contract under specification. The module does **not** exist yet, so
every test in this file is RED by design. This file is the specification, not a
report:

    scripts/sdr_architecture.py
        validate_architecture(document) -> list[str]
            House convention (`risk.validate_evidence`, `risk.validate_treatment`,
            `risk.validate_assessment`, `sdr_scope.scope_problems`): returns
            problems, never raises, and reports *every* offending record rather
            than the first.
        architecture_ids(document) -> dict[str, list[str]]
            Kind -> ids in document order. Kinds are exactly:
            actors, components, data_stores, data_flows, trust_boundaries,
            assets, dependencies.

**Why referential integrity is this module's job and not `resolve_scope`'s.**
`sdr_scope` is deliberately tolerant: `_records` drops anything that is not a
mapping and `_ids` drops anything without a string id, so a flow pointing at a
component nobody declared partitions cleanly into `excluded` and the report
reads as if the model were coherent. Tolerance is right for a reader and wrong
for a validator — the dangling reference is exactly the failure `resolve_scope`
cannot detect, because dropping it *is* how it stays deterministic. Someone has
to look, and §7.13 says the run must report it.

**Why whole-document uniqueness and not per-kind.** `resolve_scope` builds one
flat id space: `_all_ids` walks the kinds in order and `_selected_ids` returns a
single `set`, so an id shared by a `data_flow` and a `component` cannot be told
apart once it is in there. A scoped run would pull in the flow because the
component matched, or exclude the component because the flow did not, and the
`included`/`excluded` partition — the thing §4.2 exists to make honest — would
be reporting on a record the operator never named.

Three things this file deliberately does *not* do:

* It never calls `pytest.importorskip` or `pytest.skip`. A skipped test for a
  referential-integrity boundary reads as a held one: the run goes green and
  the reader concludes the boundary is enforced. Every accessor below fails by
  name instead, with a message saying what has to exist.
* It never restates a vocabulary that lives in source. `evidence_status` is
  read from `risk.EVIDENCE_STATUSES` (`risk.py:63`) and the CIA vocabulary from
  `risk.CIA_OUTPUT_KEYS` (`risk.py:59`). A copied literal here is a second
  opinion that agrees on the day it is written.
* It never asserts a *sorted* order for `architecture_ids`. §4.3 requires
  determinism, not a particular collation; document order is a legitimate
  deterministic choice and is what both existing readers already use.

Builders are local on purpose: `tests/risk_helpers.py` and `tests/conftest.py`
are under concurrent edit by sibling agents and this file must not depend on
their shape. The fixture ids are chosen so that no id is a substring of another
id or of any name — the assertions below search problem text for ids, and a
substring collision would let a missing report pass by accident.

---

Recorded for the reviewer, not silently resolved here:

**(a) `version` vs `schema_version`.** The pinned document shape opens with
`schema_version: "0.1.0"`. Every document the store already writes spells that
key `version`: `golden/movie-rating-aws/threats.yaml:4` (`version: "0.2.0"`),
`profile.yaml:7` (`version: "0.1.0"`), and `_bound_residual_assessment_problems`
restricts `risk-assessment.yaml` to `{version, migration, assessments,
confirmation}`. `schema_version` appears in the plan only as the *report's*
top-level key (§4.2 line 181, `"1.0.0"`), which is an output field, not a
document field. The fixture below carries `schema_version` as pinned and no
test asserts anything about its value, so either spelling can be adopted
without touching this file. Flagged because a new document that spells the
version key differently from its three siblings is a papercut forever.

**(b) `cia_relevance`: the §4.2 example contradicts §5.3.** The example writes
`{"id": "as-card-token", "name": "Card token", "cia_relevance": "c"}` — the
short letter. §5.3 is a decision of record: "long form in, short form out",
with `risk.CIA_OUTPUT_KEYS` as the map from the authored long form to the
rendered letter. The §4.2 example is the *report*, where `c` is correct
output-side spelling. The document on disk is input-side and must therefore
carry `confidentiality | integrity | availability`, exactly as the eight golden
consequences and `tests/risk_helpers.py:20` already do. Asserted that way in
`test_cia_relevance_carries_the_authored_long_form_not_the_rendered_letter`.
The alternative reading — that `assets[].cia_relevance` is an output-side field
because §4.2 shows it in the report — cannot hold: §5.3's reason for keeping
long form in is that short letters on input would need a `migrate()` path,
which §5.4 forbids, and that reason applies to a brand-new document as much as
an old one. Enforcing the letters here would also make this the only authored
CIA field in the tree spelled differently from every other.

**(c) `sdr_scope.ARCHITECTURE_KINDS` holds five kinds; this contract holds
seven.** `assets` and `dependencies` are absent from the scope partition
(`sdr_scope.py:34-41`), so no asset or dependency id ever appears in
`run.scope.included` or `run.scope.excluded`. That is defensible — an asset is
not a reviewable element — but it means whole-document uniqueness is enforced
over a wider id space than `resolve_scope` walks. Asserted as a containment
relation in `test_every_kind_sdr_scope_partitions_is_one_of_the_seven_kinds`
rather than as equality, so narrowing or widening either list stays a
deliberate act.

**(d) Packaging.** `scripts/sdr_architecture.py` ships inside
`plugins/security-requirements/`, so it needs a row in `APPROVED_PAYLOAD_FILES`
(`scripts/validate_distribution.py:37`) beside `scripts/sdr_scope.py:163`. The
row is *not* added here: `test_distribution_docs.py` builds its archive from
`git stash create` and so sees only tracked files, which makes a
listed-but-untracked path fail the clean-clone check. The row and the module
have to land in the same commit.

**(e) Untested holes, left open on purpose.** Whether `cia_relevance` may be a
*list* of axes (an asset relevant to both C and I is ordinary), whether
`assumptions[]` entries must be non-empty strings, whether `components[]
.trust_boundary` is required rather than merely valid when present, and whether
`data_flows[].crosses` must name a *trust boundary* specifically rather than
any declared id. The last one is the interesting one: the pinned contract says
"must name ids that exist in the document", so that is what is asserted, but a
flow declaring it crosses a data store is nonsense that this file lets through.
Narrowing it is a one-line change to `test_a_data_flow_crossing_an_undeclared_
boundary_is_reported`'s sibling — it is left undone because the contract did
not say so, not because it was missed.
"""

from __future__ import annotations

import copy
from pathlib import Path
import sys

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
PLUGIN_ROOT = REPO_ROOT / "plugins" / "security-requirements"
PLUGIN_SCRIPTS = PLUGIN_ROOT / "scripts"
if str(PLUGIN_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(PLUGIN_SCRIPTS))

import risk  # noqa: E402  - vocabularies are read from source, never restated
import sdr_mermaid  # noqa: E402
import sdr_scope  # noqa: E402


ARCHITECTURE_MODULE_PATH = PLUGIN_SCRIPTS / "sdr_architecture.py"

#: Plan §4.2, in the order the block spells them. A tuple, not a set: §4.3
#: forbids set iteration reaching output, and `architecture_ids` is output.
KINDS = (
    "actors",
    "components",
    "data_stores",
    "data_flows",
    "trust_boundaries",
    "assets",
    "dependencies",
)


# ---------------------------------------------------------------------------
# The module under specification. Imported through accessors rather than at
# module scope so a missing module reports as a FAILURE on each test, naming
# the file that has to exist, instead of one opaque collection error.
# ---------------------------------------------------------------------------


def _sdr_architecture():
    try:
        import sdr_architecture
    except ImportError as exc:  # pragma: no cover - this is the RED path
        pytest.fail(
            f"{ARCHITECTURE_MODULE_PATH} does not exist yet. Plan §4.2 specifies "
            f"the `architecture` block in full; the runner contract's Gap 1 gives "
            f"it a home at `.security-requirements/architecture.yaml`. That module "
            f"must expose `validate_architecture(document) -> list[str]` and "
            f"`architecture_ids(document) -> dict[str, list[str]]`. import failed: {exc}"
        )
    return sdr_architecture


def _validate():
    module = _sdr_architecture()
    validator = getattr(module, "validate_architecture", None)
    assert callable(validator), (
        "sdr_architecture must expose `validate_architecture(document) -> list[str]`, "
        "following the house `validate_*` convention (plan §10.1) of returning "
        f"problems rather than raising; found {validator!r}"
    )
    return validator


def _ids():
    module = _sdr_architecture()
    lister = getattr(module, "architecture_ids", None)
    assert callable(lister), (
        "sdr_architecture must expose `architecture_ids(document) -> dict[str, list[str]]` "
        f"keyed by the seven §4.2 kinds {KINDS}; found {lister!r}"
    )
    return lister


# ---------------------------------------------------------------------------
# Fixture. Shape is plan §4.2. Every kind is populated because an assertion
# about "the whole document" cannot be trusted against a document that models
# only half of it, and no id is a substring of another id or of any name.
# ---------------------------------------------------------------------------

ARCHITECTURE = {
    "schema_version": "0.1.0",
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
            # A flow wholly inside one boundary crosses nothing. `None` here is
            # the shape `tests/test_sdr_scope.py` already builds, so it is a
            # legal document, not an omission — see the sibling test.
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
            "evidence_status": "unverified",
        },
    ],
    "trust_boundaries": [
        {"id": "tb-internet", "name": "Internet edge", "evidence_status": "observed"},
        {"id": "tb-payment-zone", "name": "Payment zone", "evidence_status": "inferred"},
    ],
    "assets": [
        {"id": "as-card-token", "name": "Card token", "cia_relevance": "confidentiality"},
        {"id": "as-order-ledger", "name": "Order ledger", "cia_relevance": "integrity"},
    ],
    "dependencies": [
        {
            "id": "dep-stripe",
            "name": "Stripe",
            "kind": "saas",
            "shared_responsibility": "provider owns the PCI vault; we own key custody",
        },
    ],
    "assumptions": ["Ingress terminates TLS at the ALB (not observed in scope)"],
}

#: Ids that nothing in `ARCHITECTURE` declares. Shaped so they cannot collide
#: with a real id as a substring, and so a problem quoting one is unambiguous.
GHOST_TARGET = "ghost-target-nobody-declares"
GHOST_SOURCE = "ghost-source-nobody-declares"
GHOST_BOUNDARY = "ghost-boundary-nobody-declares"

#: A value outside `risk.EVIDENCE_STATUSES`. Shaped like a plausible authoring
#: mistake rather than obvious garbage, because that is the case that ships.
BAD_EVIDENCE_STATUS = "observed-ish"


def _architecture() -> dict:
    """A private deep copy, so one test can never poison another."""

    return copy.deepcopy(ARCHITECTURE)


def _record(document: dict, kind: str, record_id: str) -> dict:
    for record in document[kind]:
        if record.get("id") == record_id:
            return record
    raise AssertionError(
        f"fixture drift: no {kind} record with id {record_id!r}; "
        f"present ids are {[item.get('id') for item in document[kind]]}"
    )


def _problems(document) -> list[str]:
    problems = _validate()(document)
    assert isinstance(problems, list), (
        "validate_architecture must return a list of problem strings (house "
        "convention: `risk.validate_treatment`, `risk.validate_evidence`, "
        f"`sdr_scope.scope_problems`); got {type(problems)!r}"
    )
    for problem in problems:
        assert isinstance(problem, str), (
            f"every architecture problem must be a human-readable string; got {problem!r}"
        )
    return problems


def _kind_aliases(kind: str) -> tuple[str, ...]:
    """Spellings of a kind name a problem message may reasonably use.

    Generous on purpose: the wording of a message is the implementation's
    business, but *which record it is about* is the contract's.
    """

    spaced = kind.replace("_", " ")
    return tuple(
        {kind, kind.rstrip("s"), spaced, spaced.rstrip("s")}
    )


def _mentioning(problems: list[str], *needles: str) -> list[str]:
    """Problems whose text names every needle, case-insensitively."""

    return [
        problem
        for problem in problems
        if all(needle.lower() in problem.lower() for needle in needles)
    ]


def _mentioning_kind(problems: list[str], kind: str, *needles: str) -> list[str]:
    candidates = _mentioning(problems, *needles)
    return [
        problem
        for problem in candidates
        if any(alias.lower() in problem.lower() for alias in _kind_aliases(kind))
    ]


# ---------------------------------------------------------------------------
# The house error convention (plan §10.1) — returns, never raises.
# ---------------------------------------------------------------------------


def test_a_well_formed_architecture_reports_no_problems():
    problems = _problems(_architecture())

    assert problems == [], (
        "the plan §4.2 architecture, spelled exactly as the plan spells it, must "
        f"validate clean; validate_architecture reported {problems}"
    )


@pytest.mark.parametrize(
    "document",
    [
        None,
        {},
        [],
        "actors",
        7,
        {"components": None},
        {"components": "cmp-checkout-api"},
        {"components": {"id": "cmp-checkout-api"}},
        {"components": ["not-a-record"]},
        {"components": [None]},
        {"data_flows": [{"from": "act-customer"}]},
        {"assets": [{"id": "as-card-token", "cia_relevance": None}]},
        {"actors": [{"id": None}]},
    ],
    ids=[
        "none",
        "empty-mapping",
        "list",
        "string",
        "integer",
        "kind-is-none",
        "kind-is-a-string",
        "kind-is-a-mapping",
        "record-is-a-string",
        "record-is-none",
        "flow-without-an-id",
        "asset-with-a-null-axis",
        "record-with-a-null-id",
    ],
)
def test_malformed_input_is_reported_and_never_raises(document):
    """Plan §10.1: `validate_*` returns problems. A raise here is a crash in a
    run whose whole job is to report what is wrong with the model."""

    try:
        problems = _validate()(document)
    except Exception as exc:  # noqa: BLE001 - the failure under test
        raise AssertionError(
            "validate_architecture must return problems rather than raise on "
            f"malformed input (plan §10.1); {document!r} raised "
            f"{type(exc).__name__}: {exc}"
        ) from exc

    assert isinstance(problems, list) and all(
        isinstance(problem, str) for problem in problems
    ), (
        "validate_architecture must return a list of problem strings even for "
        f"malformed input; {document!r} produced {problems!r}"
    )


def test_a_document_that_is_not_a_mapping_is_reported_rather_than_read_as_empty():
    """`sdr_scope._records` returns `[]` for a non-mapping architecture, which
    is right for a reader and wrong for a validator: silence there means "this
    model has nothing in it", and a YAML file that parsed to a list is not an
    empty model."""

    for document in (None, [], "actors", 7):
        problems = _problems(document)
        assert problems, (
            "a non-mapping architecture document must be reported, not treated as "
            f"an empty model; validate_architecture({document!r}) returned []"
        )


def test_an_architecture_that_models_nothing_is_a_valid_document():
    """§8 has no row making an empty model an error, and a project that has
    genuinely modelled nothing yet must be able to run: `resolve_scope` against
    it returns two empty lists rather than failing."""

    problems = _problems({})

    assert problems == [], (
        "an empty architecture is a valid document — a project may have nothing "
        f"modelled yet; validate_architecture({{}}) reported {problems}"
    )


def test_a_document_carrying_only_the_version_key_is_valid():
    problems = _problems({"schema_version": "0.1.0"})

    assert problems == [], (
        "a document that declares its version and models nothing must validate "
        f"clean; got {problems}"
    )


def test_validate_architecture_does_not_mutate_the_document_it_is_given():
    document = _architecture()
    before = copy.deepcopy(document)

    _validate()(document)

    assert document == before, (
        "validate_architecture must not modify its input — the same mapping is "
        "handed on to resolve_scope and render_register; it changed from "
        f"{before} to {document}"
    )


# ---------------------------------------------------------------------------
# Uniqueness across the whole document, not merely within a kind.
# ---------------------------------------------------------------------------


def test_an_id_reused_across_two_kinds_is_reported():
    """`resolve_scope` flattens every kind into one id space (`_all_ids`, then a
    single `set` in `_selected_ids`), so a `data_flow` and a `component` sharing
    an id make the included/excluded partition ambiguous — the scope record
    would be describing a record the operator never named."""

    document = _architecture()
    collision = "cmp-checkout-api"
    _record(document, "data_flows", "df-public-order")["id"] = collision

    problems = _problems(document)

    assert _mentioning(problems, collision), (
        f"an id reused across two kinds must be reported by id; {collision!r} is "
        f"declared by both a component and a data_flow and the problems were {problems}"
    )
    assert _mentioning_kind(problems, "data_flows", collision), (
        f"the duplicate-id problem for {collision!r} must name the data_flows kind "
        f"so the author can find the second declaration; problems were {problems}"
    )
    assert _mentioning_kind(problems, "components", collision), (
        f"the duplicate-id problem for {collision!r} must name the components kind "
        f"so the author can find the first declaration; problems were {problems}"
    )


def test_an_id_reused_between_an_asset_and_a_component_is_reported():
    """Uniqueness spans all seven kinds, including the two `sdr_scope` does not
    partition. A collision `resolve_scope` never walks is still a collision for
    every other consumer of the document."""

    document = _architecture()
    collision = "cmp-pricing-worker"
    _record(document, "assets", "as-card-token")["id"] = collision

    problems = _problems(document)

    assert _mentioning(problems, collision), (
        f"ids must be unique across the whole document, including assets and "
        f"dependencies; {collision!r} is declared by both a component and an asset "
        f"and the problems were {problems}"
    )


def test_an_id_reused_within_one_kind_is_reported():
    document = _architecture()
    collision = "act-customer"
    _record(document, "actors", "act-partner-batch")["id"] = collision

    problems = _problems(document)

    assert _mentioning(problems, collision), (
        f"an id declared twice inside one kind must be reported; {collision!r} is "
        f"declared by two actors and the problems were {problems}"
    )


def test_every_offending_record_is_reported_not_only_the_first():
    """House convention: a validator that stops at the first problem turns one
    review into N reviews. `risk.validate_assessment` and
    `sdr_scope.scope_problems` both collect."""

    document = _architecture()
    _record(document, "actors", "act-partner-batch")["id"] = "act-customer"
    _record(document, "data_flows", "df-batch-price")["to"] = GHOST_TARGET
    _record(document, "components", "cmp-pricing-worker")["trust_boundary"] = GHOST_BOUNDARY

    problems = _problems(document)

    for needle, why in (
        ("act-customer", "the duplicated actor id"),
        (GHOST_TARGET, "the dangling data_flow target"),
        (GHOST_BOUNDARY, "the undeclared trust boundary on a component"),
    ):
        assert _mentioning(problems, needle), (
            f"validate_architecture must report every offending record, not the "
            f"first: {why} ({needle!r}) is missing from {problems}"
        )


# ---------------------------------------------------------------------------
# Referential integrity — the failure `resolve_scope` cannot detect.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("field", "ghost"),
    [("from", GHOST_SOURCE), ("to", GHOST_TARGET), ("crosses", GHOST_BOUNDARY)],
)
def test_a_data_flow_naming_an_id_no_record_declares_is_reported(field, ghost):
    """§7.13 makes a reference to an absent id a reported problem. `sdr_scope`
    cannot catch it: `_selected_ids` adds whatever string it finds on the flow
    and `_all_ids` never lists it, so the dangling id silently disappears from
    both sides of the partition and the report reads as coherent."""

    document = _architecture()
    _record(document, "data_flows", "df-public-order")[field] = ghost

    problems = _problems(document)

    assert _mentioning(problems, ghost), (
        f"a data_flow whose `{field}` names an id no record declares must be "
        f"reported by that id; `df-public-order.{field}` is {ghost!r} and the "
        f"problems were {problems}"
    )
    assert _mentioning(problems, ghost, "df-public-order"), (
        f"the dangling-reference problem must also name the flow that carries it, "
        f"or the author cannot find it; problems mentioning {ghost!r} were "
        f"{_mentioning(problems, ghost)}"
    )


def test_a_data_flow_that_crosses_no_boundary_is_not_a_problem():
    """A flow wholly inside one boundary crosses nothing. `crosses: None` is the
    shape `tests/test_sdr_scope.py` already builds and `sdr_scope._selected_ids`
    already skips (it adds only non-empty strings), so treating null as a
    dangling reference would make every internal flow an error."""

    document = _architecture()
    internal = _record(document, "data_flows", "df-cache-read")
    assert internal["crosses"] is None, "fixture drift: df-cache-read must cross nothing"

    problems = _problems(document)

    assert not _mentioning(problems, "df-cache-read"), (
        "a data_flow that crosses no trust boundary must not be reported; "
        f"df-cache-read carries `crosses: None` and produced {_mentioning(problems, 'df-cache-read')}"
    )

    document = _architecture()
    _record(document, "data_flows", "df-cache-read").pop("crosses")

    problems = _problems(document)

    assert not _mentioning(problems, "df-cache-read"), (
        "a data_flow that omits `crosses` entirely must not be reported as a "
        f"dangling reference; got {_mentioning(problems, 'df-cache-read')}"
    )


def test_a_component_naming_an_undeclared_trust_boundary_is_reported():
    document = _architecture()
    _record(document, "components", "cmp-checkout-api")["trust_boundary"] = GHOST_BOUNDARY

    problems = _problems(document)

    assert _mentioning(problems, GHOST_BOUNDARY, "cmp-checkout-api"), (
        "a component whose `trust_boundary` names no declared boundary must be "
        f"reported, naming both the component and the boundary; cmp-checkout-api "
        f"points at {GHOST_BOUNDARY!r} and the problems were {problems}"
    )


def test_a_component_whose_trust_boundary_names_a_non_boundary_id_is_reported():
    """"Declared" is not enough: the id has to be a *trust boundary*. A component
    placed inside a data store is not a modelling opinion, it is a typo, and
    `sdr_scope._selected_ids` would happily pull that store into scope as if it
    were the component's boundary."""

    document = _architecture()
    _record(document, "components", "cmp-checkout-api")["trust_boundary"] = "ds-orders"

    problems = _problems(document)

    assert _mentioning(problems, "ds-orders", "cmp-checkout-api"), (
        "`components[].trust_boundary` must name a declared trust boundary, not "
        "merely any declared id; cmp-checkout-api points at the data store "
        f"'ds-orders' and the problems were {problems}"
    )


def test_a_component_that_declares_no_trust_boundary_is_not_reported_for_that():
    """Left deliberately permissive — see note (e) in the module docstring. The
    assertion exists so that tightening it later is a visible decision rather
    than an accident."""

    document = _architecture()
    _record(document, "components", "cmp-pricing-worker").pop("trust_boundary")

    problems = _problems(document)

    assert not _mentioning(problems, "cmp-pricing-worker"), (
        "a component with no `trust_boundary` is not currently an error (the "
        "pinned contract does not require the field); cmp-pricing-worker produced "
        f"{_mentioning(problems, 'cmp-pricing-worker')}"
    )


# ---------------------------------------------------------------------------
# Closed vocabularies, read from source rather than restated.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status", sorted(risk.EVIDENCE_STATUSES))
def test_every_value_in_the_evidence_status_vocabulary_is_accepted(status):
    document = _architecture()
    _record(document, "components", "cmp-checkout-api")["evidence_status"] = status

    problems = _problems(document)

    assert not _mentioning(problems, "cmp-checkout-api"), (
        f"`{status}` is in risk.EVIDENCE_STATUSES ({sorted(risk.EVIDENCE_STATUSES)}) "
        f"and must be accepted on an architecture record; got "
        f"{_mentioning(problems, 'cmp-checkout-api')}"
    )


@pytest.mark.parametrize("kind", ["actors", "components", "data_stores", "data_flows", "trust_boundaries"])
def test_an_evidence_status_outside_the_closed_set_is_reported_on_every_kind(kind):
    """§7.9: `evidence_status` outside `observed | inferred | unverified` is an
    invalid state. The set is `risk.EVIDENCE_STATUSES` (`risk.py:63`) and is read
    from there rather than copied, so widening it there widens it here."""

    document = _architecture()
    record = document[kind][0]
    record["evidence_status"] = BAD_EVIDENCE_STATUS

    problems = _problems(document)

    assert _mentioning(problems, record["id"]), (
        f"`evidence_status: {BAD_EVIDENCE_STATUS!r}` on a {kind} record is outside "
        f"risk.EVIDENCE_STATUSES ({sorted(risk.EVIDENCE_STATUSES)}) and must be "
        f"reported against {record['id']!r}; the problems were {problems}"
    )
    assert _mentioning(problems, record["id"], BAD_EVIDENCE_STATUS), (
        "the problem must quote the offending value so the author can see what "
        f"they wrote; problems naming {record['id']!r} were "
        f"{_mentioning(problems, record['id'])}"
    )


@pytest.mark.parametrize("kind", ["actors", "components", "data_stores", "data_flows", "trust_boundaries"])
def test_a_record_that_omits_evidence_status_is_reported(kind):
    """An absent `evidence_status` is not neutral — it renders as an observation.
    `sdr_mermaid._label` adds the `(inferred)` marker only when the field equals
    `"inferred"` (`sdr_mermaid.py:65`), and `_INFERRED_STYLE` is applied on the
    same test, so a record with no provenance at all draws with a solid stroke
    and an unqualified name: identical to something the reviewer actually saw.
    That module's own docstring calls presenting an assumption exactly like an
    observation "worse than no diagram", so the document must not be able to
    leave the field out. §4.2 gives all five of these kinds the field."""

    document = _architecture()
    record = document[kind][0]
    record.pop("evidence_status")

    problems = _problems(document)

    assert _mentioning(problems, record["id"]), (
        f"a {kind} record with no `evidence_status` must be reported: "
        f"sdr_mermaid renders it exactly like `observed`, which lends an "
        f"unrecorded assumption the authority of an observation. "
        f"{record['id']!r} produced {problems}"
    )


def test_the_long_form_cia_vocabulary_is_exactly_the_keys_of_the_output_map():
    """Guards the two constants this file leans on against drift. §5.3 makes
    `CONSEQUENCE_AXES` the authored vocabulary and `CIA_OUTPUT_KEYS` the map
    from it to the rendered letter; if those ever disagree, "long form in, short
    form out" has two answers and the assertions below are testing neither."""

    assert set(risk.CIA_OUTPUT_KEYS) == risk.CONSEQUENCE_AXES, (
        "risk.CIA_OUTPUT_KEYS must be keyed by the authored long-form axes "
        f"(plan §5.3); its keys are {sorted(risk.CIA_OUTPUT_KEYS)} and "
        f"risk.CONSEQUENCE_AXES is {sorted(risk.CONSEQUENCE_AXES)}"
    )


@pytest.mark.parametrize("axis", sorted(risk.CIA_OUTPUT_KEYS))
def test_cia_relevance_carries_the_authored_long_form_not_the_rendered_letter(axis):
    """§5.3, decision of record: long form in, short form out. The §4.2 example
    shows `"cia_relevance": "c"` because §4.2 is the *report*; `c | i | a` is
    output-side spelling applied through `risk.CIA_OUTPUT_KEYS`. The document on
    disk is input-side and spells the axis out, exactly as the eight golden
    consequences and `tests/risk_helpers.py:20` already do."""

    document = _architecture()
    _record(document, "assets", "as-card-token")["cia_relevance"] = axis

    problems = _problems(document)

    assert not _mentioning(problems, "as-card-token"), (
        f"`cia_relevance: {axis!r}` is the authored long form (plan §5.3) and must "
        f"be accepted; got {_mentioning(problems, 'as-card-token')}"
    )


@pytest.mark.parametrize("letter", sorted(risk.CIA_OUTPUT_KEYS.values()))
def test_the_rendered_cia_letter_is_reported_when_it_appears_in_the_document(letter):
    document = _architecture()
    _record(document, "assets", "as-card-token")["cia_relevance"] = letter

    problems = _problems(document)

    assert _mentioning(problems, "as-card-token"), (
        f"`cia_relevance: {letter!r}` is output-side spelling (plan §5.3: long "
        f"form in, short form out; risk.CIA_OUTPUT_KEYS maps "
        f"{sorted(risk.CIA_OUTPUT_KEYS)} to {sorted(risk.CIA_OUTPUT_KEYS.values())}) "
        f"and must be reported when authored into the document; problems were {problems}"
    )


def test_a_cia_relevance_outside_the_vocabulary_entirely_is_reported():
    document = _architecture()
    _record(document, "assets", "as-order-ledger")["cia_relevance"] = "confidentialty"

    problems = _problems(document)

    assert _mentioning(problems, "as-order-ledger", "confidentialty"), (
        "a `cia_relevance` outside the vocabulary must be reported, quoting the "
        f"offending value; the authored value was 'confidentialty' (a typo for a "
        f"real axis) and the problems were {problems}"
    )


# ---------------------------------------------------------------------------
# Record shape — a malformed record is reported, never dropped.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", list(KINDS))
def test_a_kind_whose_value_is_not_a_list_is_reported(kind):
    document = _architecture()
    document[kind] = None

    problems = _problems(document)

    assert _mentioning_kind(problems, kind), (
        f"`{kind}: None` is not an empty model — it is a malformed one, and "
        f"`sdr_scope._records` would read it as empty. It must be reported; the "
        f"problems were {problems}"
    )


@pytest.mark.parametrize("kind", list(KINDS))
def test_a_record_that_is_not_a_mapping_is_reported_rather_than_dropped(kind):
    """`sdr_scope._records` filters non-mappings out and `sdr_mermaid._records`
    does the same. Both are right to: a reader must stay deterministic. But
    dropping is how a mistyped record vanishes from the model without a word,
    and the validator is the one place that has to notice."""

    document = _architecture()
    document[kind] = list(document[kind]) + ["not-a-record"]

    problems = _problems(document)

    assert _mentioning_kind(problems, kind), (
        f"a {kind} entry that is not a mapping must be reported, not silently "
        f"dropped the way `sdr_scope._records` drops it; the problems were {problems}"
    )


@pytest.mark.parametrize("kind", list(KINDS))
def test_a_record_without_a_usable_id_is_reported(kind):
    """Every referential-integrity check in this file, and the whole
    `resolve_scope` partition, is keyed on `id`. A record without one cannot be
    referenced, cannot be scoped, and cannot be excluded — it is invisible."""

    document = _architecture()
    document[kind] = list(document[kind]) + [{"name": "nameless"}]

    problems = _problems(document)

    assert _mentioning_kind(problems, kind), (
        f"a {kind} record with no `id` must be reported: it can never be "
        f"referenced by a flow, scoped, or listed in `run.scope.excluded`; the "
        f"problems were {problems}"
    )


@pytest.mark.parametrize("empty_id", ["", "   "])
def test_a_record_whose_id_is_empty_or_whitespace_is_reported(empty_id):
    """`sdr_scope._ids` keeps only ids that are non-empty strings, so a
    whitespace id is dropped from `_all_ids` while `_selected_ids` may still add
    it — the two sides of the partition would disagree about the same record."""

    document = _architecture()
    _record(document, "components", "cmp-pricing-worker")["id"] = empty_id

    problems = _problems(document)

    assert problems, (
        f"a component whose id is {empty_id!r} must be reported; "
        "`sdr_scope._ids` drops it from the model while `_selected_ids` does not, "
        "so the included/excluded partition stops covering it. Got no problems"
    )


# ---------------------------------------------------------------------------
# `architecture_ids` — the inventory, and §4.3 determinism.
# ---------------------------------------------------------------------------


def test_architecture_ids_returns_exactly_the_seven_kinds_in_a_fixed_order():
    listed = _ids()(_architecture())

    assert isinstance(listed, dict), (
        f"architecture_ids must return a mapping of kind -> ids; got {type(listed)!r}"
    )
    assert list(listed) == list(KINDS), (
        f"architecture_ids must be keyed by exactly the seven plan §4.2 kinds, in "
        f"a fixed order (§4.3: no set iteration reaches output). Expected "
        f"{list(KINDS)}, got {list(listed)}"
    )


def test_architecture_ids_lists_ids_in_document_order():
    document = _architecture()

    listed = _ids()(document)

    for kind in KINDS:
        expected = [record["id"] for record in document[kind]]
        assert listed[kind] == expected, (
            f"architecture_ids['{kind}'] must list ids in document order (§4.3 "
            f"forbids set iteration reaching output). Expected {expected}, got "
            f"{listed[kind]}"
        )


def test_architecture_ids_of_a_document_that_models_nothing_has_every_kind_present_and_empty():
    """A caller reaching for `ids["assets"]` must not have to guess whether the
    key is there. Absent-versus-empty is the distinction that turns an empty
    model into a `KeyError` in the runner."""

    listed = _ids()({})

    assert list(listed) == list(KINDS), (
        "architecture_ids must return all seven kinds even for a document that "
        f"models nothing, so a caller can index any kind unconditionally; got "
        f"{list(listed)}"
    )
    assert all(listed[kind] == [] for kind in KINDS), (
        f"every kind of an empty architecture must map to an empty list; got {listed}"
    )


def test_architecture_ids_is_stable_across_repeat_calls_and_across_deep_copies():
    """§4.3 buys determinism, not a particular collation. Asserted the way
    `test_sdr_scope.py` asserts it: same input twice, and an equal-but-distinct
    object, must give byte-identical output."""

    document = _architecture()

    first = _ids()(document)
    second = _ids()(document)
    third = _ids()(copy.deepcopy(document))

    assert first == second == third, (
        "architecture_ids must be deterministic (§4.3: no set iteration reaches "
        f"output). Two calls on the same document gave {first} and {second}; a "
        f"deep copy gave {third}"
    )
    for listed in (second, third):
        assert list(listed) == list(first), (
            f"architecture_ids key order must be stable across calls; {list(first)} "
            f"then {list(listed)}"
        )


@pytest.mark.parametrize(
    "document",
    [None, {}, [], "actors", {"components": None}, {"components": ["not-a-record"]}],
    ids=["none", "empty-mapping", "list", "string", "kind-is-none", "record-is-a-string"],
)
def test_architecture_ids_tolerates_malformed_input_without_raising(document):
    """The inventory is read on the reporting path, including the path that runs
    *because* the document is malformed. It must survive what it is describing."""

    try:
        listed = _ids()(document)
    except Exception as exc:  # noqa: BLE001 - the failure under test
        raise AssertionError(
            "architecture_ids must tolerate a malformed document rather than "
            f"raise — it is read while reporting on that document; {document!r} "
            f"raised {type(exc).__name__}: {exc}"
        ) from exc

    assert list(listed) == list(KINDS), (
        "architecture_ids must return all seven kinds even for malformed input; "
        f"{document!r} produced {list(listed)}"
    )
    for kind in KINDS:
        assert isinstance(listed[kind], list) and all(
            isinstance(value, str) for value in listed[kind]
        ), (
            f"architecture_ids['{kind}'] must be a list of id strings even for "
            f"malformed input; {document!r} produced {listed[kind]!r}"
        )


# ---------------------------------------------------------------------------
# Coherence with the two consumers that shipped before the producer.
# ---------------------------------------------------------------------------


def test_every_kind_sdr_scope_partitions_is_one_of_the_seven_kinds():
    """`sdr_scope.ARCHITECTURE_KINDS` holds five of the seven: `assets` and
    `dependencies` are deliberately outside the scope partition, so no asset or
    dependency id ever reaches `run.scope.included` or `.excluded`. Asserted as
    containment, not equality, so narrowing or widening either list stays a
    deliberate act rather than a silent divergence."""

    unknown = [kind for kind in sdr_scope.ARCHITECTURE_KINDS if kind not in KINDS]

    assert not unknown, (
        "every kind sdr_scope partitions must be a kind the architecture document "
        f"declares; sdr_scope.ARCHITECTURE_KINDS is {list(sdr_scope.ARCHITECTURE_KINDS)} "
        f"and the plan §4.2 kinds are {list(KINDS)}; unexpected: {unknown}"
    )


def test_a_document_that_validates_clean_partitions_and_renders():
    """The point of the whole file. A document this module calls valid has to be
    usable by the two consumers that shipped first — `resolve_scope`'s partition
    and `render_register`'s DFD — without either of them raising or dropping a
    modelled element."""

    document = _architecture()
    assert _problems(document) == [], "fixture must validate clean for this test to mean anything"

    record = sdr_scope.resolve_scope(document, "cmp-checkout-api")
    partitioned = set(record["included"]) | set(record["excluded"])

    scoped_ids = {
        record_id
        for kind in sdr_scope.ARCHITECTURE_KINDS
        for record_id in (item["id"] for item in document[kind])
    }
    assert partitioned == scoped_ids, (
        "a valid architecture must partition exactly: every id sdr_scope walks "
        "lands on one side and no other id appears. Missing from the partition: "
        f"{sorted(scoped_ids - partitioned)}; unexpected in it: "
        f"{sorted(partitioned - scoped_ids)}"
    )
    assert not (set(record["included"]) & set(record["excluded"])), (
        "no id may appear on both sides of the scope partition; both sides were "
        f"included={record['included']} excluded={record['excluded']}"
    )

    diagram = sdr_mermaid.render_dfd(document)
    for kind in ("actors", "components", "data_stores", "trust_boundaries"):
        for item in document[kind]:
            assert item["id"] in diagram, (
                f"a valid architecture must render without dropping a modelled "
                f"element; {item['id']!r} ({kind}) is absent from the DFD:\n{diagram}"
            )


def test_an_empty_architecture_still_partitions_into_two_empty_lists():
    """Checked against the shipped `sdr_scope` rather than assumed: an empty
    model is not an error there either. `resolve_scope` returns the §4.2 record
    with both sides empty, and `scope_problems` reports only when a filter was
    actually given."""

    record = sdr_scope.resolve_scope({}, None)

    assert record == {"included": [], "excluded": [], "scope_filter": None}, (
        "an architecture that models nothing must still produce the §4.2 "
        f"run.scope record with both sides empty; got {record}"
    )
    assert sdr_scope.scope_problems({}, None) == [], (
        "a run with no `--scope` against an empty model is not a scope problem; "
        f"got {sdr_scope.scope_problems({}, None)}"
    )


def test_a_scope_filter_against_an_empty_architecture_is_reported_as_matching_nothing():
    """§8: "`--scope` matches nothing → fail with the list of known component
    ids. Never silently review everything." With nothing modelled there is no
    list to give, so the message says that instead of listing nothing."""

    problems = sdr_scope.scope_problems({}, "cmp-checkout-api")

    assert problems, (
        "a `--scope` filter against a model with no components must be reported "
        "(§8: never silently review everything); got no problems"
    )
    assert any("cmp-checkout-api" in problem for problem in problems), (
        "the problem must quote the filter the operator supplied so a typo is "
        f"fixable from the message alone; got {problems}"
    )
