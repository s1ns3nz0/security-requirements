"""§7.13 / §8 — a threat pointing at an id the architecture never declared.

Plan of record: `docs/security-design-review-plan.md` §7 constraint 13 (line 503,
"Threat referencing a component, boundary, or flow id absent from the
architecture"), §8 (line 537, "Threat pointing at a missing component → Reported
as a problem, run completes, limitation recorded"), §4.2 (the `architecture`
block and the `findings[].target` block), §4.3 (ordering — "no set iteration
reaches output").

**This is not a hard failure.** §8 puts this row in the *edge cases* table, not in
§7's "fails loudly" list, and spells the behaviour out: the problem is reported,
**the run completes**, and the limitation is recorded. A review that aborts
because one threat names a stale component id is strictly less useful than one
that scores the other seven threats and says which reference it could not
resolve. Every test below asserts a *returned problem*; none asserts a raise.

Pinned contract under specification — the module does **not** exist yet, so every
test in this file is RED by design. This file is the specification, not a report:

    scripts/sdr_architecture.py
        unknown_architecture_refs(threats_doc, architecture) -> list[str]
            Every threat reference naming an id the architecture does not
            declare. Returns problems, never raises (house convention, plan
            §10.1: `risk.validate_evidence`, `risk.validate_treatment`,
            `sdr_scope.scope_problems`, `sdr_attack_paths.validate_attack_paths`).
        architecture_ids(document) -> dict[str, list[str]]
            Kind -> ids in document order.


The resolution rule, stated once
-------------------------------

A reference resolves when the architecture declares that id **under the kind the
reference names**:

* a threat's `boundary` resolves against `trust_boundaries`;
* a finding target's `component` resolves against `components`;
* a finding target's `ref` resolves against the kind `target.kind` names, or
  against any declared kind when `kind` is absent or unrecognised.

Kind-aware rather than a flat id bag, because a flat bag silently accepts
`boundary: cmp-checkout-api` — a threat filed against a component under the
field that means "trust boundary". That record loads, scores, and renders with a
boundary column naming something that is not a boundary, which is exactly the
class of error §7.13 exists to catch. `target.ref` is the one deliberately loose
case: §4.2 pairs it with an explicit `kind`, so when the kind is missing there is
nothing to be strict about and refusing a real id would be a false problem.


Why the empty architecture aggregates
-------------------------------------

When the architecture declares no ids at all — absent file, empty mapping,
malformed document — *every* reference in the register is unresolvable. Emitting
one problem per reference would turn a single missing document into a hundred
identical lines, each naming a different threat and none naming the actual
cause. That is noise wearing disclosure's clothes: the reader scrolls a wall of
"unknown id" and never learns that one file failed to load.

So the empty case collapses to **one** aggregate problem that names the cause.
The rule is narrow on purpose: aggregation applies only when the architecture
declares *nothing*. An architecture that declares some ids and is merely missing
the one a threat names is a stale reference, not a missing document, and gets the
per-reference treatment — see
`test_an_architecture_declaring_only_other_kinds_still_reports_per_reference`.


Lifecycle-inactive records are skipped
--------------------------------------

`risk._duplicate_threat_pairs` (`risk.py:797`) already establishes the precedent
and the mechanism: it filters on `risk._lifecycle_status(threat) != "active"`.
The same rule applies here rather than a new one. A retired threat is history the
register keeps on purpose, and a superseded one routinely points at architecture
that was decommissioned alongside it — reporting either would make retirement
generate permanent noise, and the operator's only way to silence it would be to
delete the history.

Because `_lifecycle_status` *raises* on a malformed or unknown status, this
module has to catch it: `_validate_threats` already reports that record, and
§8's "run completes" forbids a second reporter from taking the process down over
it. See `test_a_threat_whose_lifecycle_status_is_unknown_does_not_raise`.


Plan/source contradiction recorded for the reviewer, not silently resolved
-------------------------------------------------------------------------

§7.13 names three kinds of reference — "a component, boundary, or flow id". The
threat record on disk carries **one** of them.

Every threat key across every golden fixture (`golden/movie-rating-aws`,
`golden/b2b-saas-aws`) is:

    affected_assets, attack_path, boundary, category, id, lifecycle, novelty,
    persona, related_controls, risk_family, scenario

`boundary` is the only architecture-shaped reference. `attack_path` is a slug
(`deployment_archive_static_credentials`), not an id; `affected_assets` are asset
slugs (`aws_credentials`); `related_controls` are NIST control ids. And §5.2 —
the section that says what this plan *adds* to `threats.yaml` — adds exactly
`evidence_status`, `confidence`, and `attack_path_ids`. None of the three is a
component or a flow reference.

The only place the plan spells a component reference and a flow reference on a
threat-shaped record is the §4.2 report finding:

    "target": { "kind": "data_flow", "ref": "df-3",
                "component": "cmp-checkout-api", "trust_boundary": "tb-internet" }

That is the report projection rather than the stored record, but it is the plan's
own vocabulary, so this file specifies `target` rather than inventing a field
name. The `target` tests are inert against every fixture on disk — no golden
threat carries the key — and become live the moment a record does.

There is a second, sharper edge to the same contradiction, and it is not this
file's to fix. The golden threat records spell `boundary` as `TB-4` and resolve
it against `threats.yaml`'s *own* top-level `boundaries:` block; §4.2's
architecture spells the same concept `tb-internet` under `trust_boundaries`.
Two namespaces for one idea. Until the architecture document reproduces the
register's boundary ids, every golden threat is unresolvable against it —
which is precisely why the empty/aggregate rule above matters and why
`test_the_golden_threats_resolve_against_an_architecture_built_from_their_own_boundaries`
builds the architecture from the fixture's own `boundaries:` list.

Builders are local on purpose: `tests/risk_helpers.py` is under concurrent edit
by sibling agents and this file must not depend on its shape. The architecture
fixture is plan §4.2 and is kept deliberately consistent with the ones in
`tests/test_sdr_scope.py` and `tests/test_sdr_mermaid.py` — same ids, same shape
— without importing either.

`tests/test_sdr_architecture.py` owns the architecture document's own schema,
including the full shape of `architecture_ids` (its exact key set, document
order, the empty document, determinism, malformed tolerance). This file does not
import from it and does not restate it: two files asserting the same contract
disagree the first time either is revised. What is kept here is the slice
reference resolution stands on — which ids a reference has to match, what does
not count as an id to match against, and that the two pinned functions agree
about which ids exist.

Packaging is deliberately untouched here for the same reason that file gives:
`scripts/sdr_architecture.py` needs a row in `APPROVED_PAYLOAD_FILES`
(`scripts/validate_distribution.py:37`), but `test_distribution_docs.py` builds
its archive from `git stash create` and therefore sees only tracked files, so a
listed-but-untracked path fails the clean-clone check. The row and the module
have to land in the same commit.
"""

from __future__ import annotations

import copy
from pathlib import Path
import sys

import pytest
import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
PLUGIN_ROOT = REPO_ROOT / "plugins" / "security-requirements"
PLUGIN_SCRIPTS = PLUGIN_ROOT / "scripts"
if str(PLUGIN_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(PLUGIN_SCRIPTS))

import risk as risk_mod  # noqa: E402


ARCHITECTURE_MODULE_PATH = PLUGIN_SCRIPTS / "sdr_architecture.py"

GOLDEN_THREATS_PATH = REPO_ROOT / "golden" / "movie-rating-aws" / "threats.yaml"

# ---------------------------------------------------------------------------
# The module under specification. Imported through helpers rather than at module
# scope so a missing module reports as a FAILURE on each test, with a message
# naming the file that has to exist, instead of one opaque collection error.
# No `pytest.importorskip`: a skipped test is invisible, and an invisible test
# for a reference boundary is worse than no test — the run goes green and the
# reader concludes the boundary is held.
# ---------------------------------------------------------------------------


def _sdr_architecture():
    try:
        import sdr_architecture
    except ImportError as exc:  # pragma: no cover - this is the RED path
        pytest.fail(
            f"{ARCHITECTURE_MODULE_PATH} does not exist yet (plan §7.13, §8). "
            "It must expose `unknown_architecture_refs(threats_doc, architecture) "
            "-> list[str]` and `architecture_ids(document) -> dict[str, list[str]]`. "
            f"import failed: {exc}"
        )
    return sdr_architecture


def _unknown_refs():
    module = _sdr_architecture()
    reporter = getattr(module, "unknown_architecture_refs", None)
    assert callable(reporter), (
        "sdr_architecture must expose `unknown_architecture_refs(threats_doc, "
        "architecture) -> list[str]`, following the house `validate_*` convention "
        "of returning problems rather than raising (plan §10.1); found "
        f"{reporter!r}"
    )
    return reporter


def _architecture_ids():
    module = _sdr_architecture()
    reader = getattr(module, "architecture_ids", None)
    assert callable(reader), (
        "sdr_architecture must expose `architecture_ids(document) -> "
        f"dict[str, list[str]]`, kind -> ids in document order; found {reader!r}"
    )
    return reader


# ---------------------------------------------------------------------------
# Fixtures. Ids are chosen so that no id is a substring of another id or of any
# name: the assertions below search problem text for a specific id, and a
# substring collision would let a missing id pass by accident.
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
    ],
    "data_stores": [
        {
            "id": "ds-orders",
            "name": "orders-db",
            "classification": "pii",
            "evidence_status": "observed",
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
            "id": "df-admin-write",
            "from": "cmp-pricing-worker",
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

#: Ids the architecture declares, by kind. Used to build resolvable references.
DECLARED_BOUNDARY = "tb-internet"
DECLARED_COMPONENT = "cmp-checkout-api"
DECLARED_FLOW = "df-public-order"
DECLARED_STORE = "ds-orders"

#: Ids the architecture does not declare. Shaped like ids that once existed and
#: were removed — the stale-reference case that actually reaches production —
#: rather than obvious garbage.
MISSING_BOUNDARY = "tb-decommissioned-dmz"
MISSING_COMPONENT = "cmp-legacy-billing"
MISSING_FLOW = "df-retired-export"


def _architecture() -> dict:
    """A private deep copy, so one test can never poison another."""

    return copy.deepcopy(ARCHITECTURE)


def _threat(
    threat_id: str,
    *,
    boundary: object = DECLARED_BOUNDARY,
    target: object = None,
    lifecycle: object = None,
) -> dict:
    """One threat record in the shape `risk._validate_threats` requires.

    Every required field is present so that nothing in this file's fixtures is
    reported by the *threats* validator; the only variable is the reference under
    test. `boundary=None` drops the key entirely, which is the "field absent"
    case rather than the "field wrong" case.
    """

    record = {
        "id": threat_id,
        "risk_family": f"RF-{threat_id}",
        "category": "STRIDE:T",
        "novelty": "service_specific",
        "persona": "anonymous_external",
        "attack_path": "unauthenticated_write_across_boundary",
        "scenario": "An anonymous caller writes across the boundary.",
        "affected_assets": ["order_records"],
        "related_controls": ["AC-3"],
        "lifecycle": {"status": "active", "superseded_by": []},
    }
    if boundary is not None:
        record["boundary"] = boundary
    if target is not None:
        record["target"] = target
    if lifecycle is not None:
        record["lifecycle"] = lifecycle
    return record


def _threats_doc(*threats: object) -> dict:
    return {
        "version": "0.2.0",
        "profile": "checkout",
        "threats": list(threats),
    }


def _as_text(problems: object) -> str:
    assert isinstance(problems, list), (
        "unknown_architecture_refs must return a list of problem strings (house "
        "convention: `risk.validate_treatment`, `sdr_scope.scope_problems`); got "
        f"{type(problems)!r}"
    )
    for problem in problems:
        assert isinstance(problem, str), (
            f"every problem must be a human-readable string; got {problem!r}"
        )
    return "\n".join(problems)


def _golden_threats_doc() -> dict:
    assert GOLDEN_THREATS_PATH.is_file(), (
        f"{GOLDEN_THREATS_PATH} is the real threat shape this module has to "
        "resolve; without it these tests assert against an invented record."
    )
    return yaml.safe_load(GOLDEN_THREATS_PATH.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# §7.13 — the plan names three kinds of reference. The record carries one.
# A tripwire, not a wish: it fails the day someone adds the missing field, which
# is exactly when the resolution rule above has to be revisited.
# ---------------------------------------------------------------------------


def test_the_threat_record_carries_a_boundary_reference_and_no_component_or_flow_field():
    fields = set(risk_mod.THREAT_DIGEST_FIELDS)

    assert "boundary" in fields, (
        "`boundary` is the reference §7.13 can actually resolve today; if it left "
        f"THREAT_DIGEST_FIELDS this module is resolving a field that no longer "
        f"identifies a threat. THREAT_DIGEST_FIELDS={risk_mod.THREAT_DIGEST_FIELDS!r}"
    )
    unexpected = fields & {"component", "components", "flow", "data_flow", "data_flows"}
    assert not unexpected, (
        "§7.13 names 'a component, boundary, or flow id', but the threat record on "
        "disk carries only `boundary` — §5.2 adds evidence_status, confidence, and "
        "attack_path_ids, none of which is a component or flow reference. This test "
        f"is the tripwire for that gap closing: {sorted(unexpected)} now exists, so "
        "the resolution rule in this file's docstring must be re-read before the "
        "new field is trusted."
    )


# ---------------------------------------------------------------------------
# `architecture_ids` — only the slice reference resolution stands on.
#
# The document's own schema — the exact key set, document order, the empty
# document, determinism, malformed tolerance — is specified in
# `tests/test_sdr_architecture.py`, which owns that function's shape. Repeating
# it here would mean two files disagreeing the first time either is revised. The
# three tests below are the ones that are *this* file's concern: what a
# reference has to match, what does not count as something to match against, and
# that the two pinned functions agree about which ids exist.
# ---------------------------------------------------------------------------


def test_architecture_ids_reports_the_ids_a_reference_has_to_match():
    mapping = _architecture_ids()(_architecture())

    assert isinstance(mapping, dict), (
        f"architecture_ids returns a kind -> ids mapping; got {type(mapping)!r}"
    )
    for kind, expected in (
        ("components", ["cmp-checkout-api", "cmp-pricing-worker"]),
        ("trust_boundaries", ["tb-internet", "tb-payment-zone"]),
        ("data_flows", ["df-public-order", "df-admin-write"]),
    ):
        assert list(mapping[kind]) == expected, (
            f"resolution is kind-aware, so `{kind}` has to hold that kind's ids and "
            "nothing else. A kind that leaks ids from a neighbour makes "
            f"`boundary: cmp-checkout-api` resolve; got {mapping.get(kind)!r}"
        )


def test_architecture_ids_declares_nothing_for_a_record_without_a_usable_id():
    document = {
        "components": [
            {"id": DECLARED_COMPONENT},
            {"name": "unnamed"},
            {"id": ""},
            {"id": 17},
            "not-a-record",
        ]
    }

    mapping = _architecture_ids()(document)

    assert list(mapping["components"]) == [DECLARED_COMPONENT], (
        "a record with no id, an empty id, a non-string id, or no mapping at all "
        "declares nothing a threat could reference. Admitting `''` or `17` here "
        "would let an unresolvable reference resolve against junk, which is §7.13 "
        f"failing quietly rather than reporting; got {mapping['components']!r}"
    )


def test_a_reference_resolves_exactly_against_what_architecture_ids_reports():
    architecture = _architecture()
    declared = _architecture_ids()(architecture)["trust_boundaries"]
    assert declared, "the fixture must declare boundaries for this test to mean anything"

    reporter = _unknown_refs()
    for boundary_id in declared:
        problems = reporter(
            _threats_doc(_threat("T-01", boundary=boundary_id)), _architecture()
        )
        assert _as_text(problems) == "", (
            f"{boundary_id!r} is in what architecture_ids reports, so a reference to "
            f"it must resolve; got {problems!r}"
        )

    text = _as_text(
        reporter(_threats_doc(_threat("T-01", boundary=MISSING_BOUNDARY)), architecture)
    )
    assert MISSING_BOUNDARY in text, (
        "the two pinned functions must agree about which ids exist. If "
        "`unknown_architecture_refs` resolves against a wider set than "
        "`architecture_ids` reports, the report and the problem list describe "
        f"different models; message was:\n{text}"
    )


# ---------------------------------------------------------------------------
# The clean paths. A reference that resolves is not a problem, and a field the
# record simply does not carry is not this module's problem either.
# ---------------------------------------------------------------------------


def test_a_threat_naming_a_declared_boundary_reports_nothing():
    problems = _unknown_refs()(
        _threats_doc(_threat("T-01", boundary=DECLARED_BOUNDARY)), _architecture()
    )

    assert _as_text(problems) == "", (
        f"{DECLARED_BOUNDARY!r} is declared under `trust_boundaries`; got {problems!r}"
    )


def test_a_threat_naming_declared_component_and_flow_targets_reports_nothing():
    threat = _threat(
        "T-01",
        target={
            "kind": "data_flow",
            "ref": DECLARED_FLOW,
            "component": DECLARED_COMPONENT,
            "trust_boundary": DECLARED_BOUNDARY,
        },
    )

    problems = _unknown_refs()(_threats_doc(threat), _architecture())

    assert _as_text(problems) == "", (
        "every id in the §4.2 target block is declared by the architecture, so "
        f"there is nothing to report; got {problems!r}"
    )


def test_a_threat_document_declaring_no_threats_reports_nothing():
    problems = _unknown_refs()(_threats_doc(), _architecture())

    assert _as_text(problems) == "", (
        "§8: an empty `threats.yaml` is a valid run with zero findings. Zero "
        f"threats reference zero ids; got {problems!r}"
    )


def test_a_threat_that_omits_its_boundary_entirely_is_left_to_the_threats_validator():
    problems = _unknown_refs()(
        _threats_doc(_threat("T-01", boundary=None)), _architecture()
    )

    assert _as_text(problems) == "", (
        "`risk._validate_threats` already reports 'T-01 boundary is required'. A "
        "missing field is not a dangling reference, and reporting it twice makes "
        "the operator fix one problem and see the count drop by two; got "
        f"{problems!r}"
    )


def test_a_resolvable_reference_beside_an_unresolvable_one_is_not_itself_reported():
    threat = _threat(
        "T-01",
        boundary=DECLARED_BOUNDARY,
        target={"kind": "component", "ref": DECLARED_COMPONENT, "component": MISSING_COMPONENT},
    )

    text = _as_text(_unknown_refs()(_threats_doc(threat), _architecture()))

    assert MISSING_COMPONENT in text, (
        f"the one dangling reference must be reported; message was:\n{text}"
    )
    for resolvable in (DECLARED_BOUNDARY, DECLARED_COMPONENT):
        assert resolvable not in text, (
            f"{resolvable!r} is declared by the architecture and must not appear as "
            "a problem. Flagging the whole record because one of its references is "
            "stale sends the operator hunting through ids that are already "
            f"correct; message was:\n{text}"
        )


# ---------------------------------------------------------------------------
# §7.13 / §8 — the dangling reference is reported, and the message is actionable.
# ---------------------------------------------------------------------------


def test_a_threat_naming_an_undeclared_boundary_is_reported():
    problems = _unknown_refs()(
        _threats_doc(_threat("T-01", boundary=MISSING_BOUNDARY)), _architecture()
    )

    assert problems, (
        f"§7.13: {MISSING_BOUNDARY!r} is absent from the architecture. A run that "
        "scores this threat silently attributes it to a boundary nothing models, "
        "and the report reads as if the reference were verified."
    )
    _as_text(problems)


def test_the_problem_names_both_the_threat_id_and_the_missing_reference():
    text = _as_text(
        _unknown_refs()(
            _threats_doc(_threat("T-01", boundary=MISSING_BOUNDARY)), _architecture()
        )
    )

    assert "T-01" in text, (
        "'invalid reference' names neither the record to open nor the id to fix. "
        f"The threat id is how the operator finds the record; message was:\n{text}"
    )
    assert MISSING_BOUNDARY in text, (
        "the missing id is how the operator knows what to fix once the record is "
        f"open. `sdr_attack_paths.validate_attack_paths` sets the precedent — both "
        f"ids in every message; message was:\n{text}"
    )


def test_a_threat_naming_an_undeclared_component_is_reported_with_both_ids():
    threat = _threat("T-02", target={"kind": "component", "component": MISSING_COMPONENT})

    text = _as_text(_unknown_refs()(_threats_doc(threat), _architecture()))

    assert "T-02" in text and MISSING_COMPONENT in text, (
        "§8's row is literally 'Threat pointing at a missing component'. The "
        "problem must name the threat and the component; message was:\n" + text
    )


def test_a_threat_naming_an_undeclared_flow_is_reported_with_both_ids():
    threat = _threat("T-03", target={"kind": "data_flow", "ref": MISSING_FLOW})

    text = _as_text(_unknown_refs()(_threats_doc(threat), _architecture()))

    assert "T-03" in text and MISSING_FLOW in text, (
        "§7.13 names flow ids alongside component and boundary ids; message "
        "was:\n" + text
    )


def test_a_boundary_field_naming_a_declared_component_id_does_not_resolve():
    threat = _threat("T-04", boundary=DECLARED_COMPONENT)

    text = _as_text(_unknown_refs()(_threats_doc(threat), _architecture()))

    assert DECLARED_COMPONENT in text, (
        "resolution is kind-aware. A flat bag of every declared id would accept "
        f"`boundary: {DECLARED_COMPONENT}` — a threat filed against a component "
        "under the field that means trust boundary. That record loads, scores, and "
        "renders a boundary column naming something that is not a boundary, which "
        f"is the class of error §7.13 exists to catch; message was:\n{text}"
    )


def test_a_target_component_naming_a_declared_data_store_id_does_not_resolve():
    threat = _threat("T-05", target={"kind": "component", "component": DECLARED_STORE})

    text = _as_text(_unknown_refs()(_threats_doc(threat), _architecture()))

    assert DECLARED_STORE in text, (
        f"{DECLARED_STORE!r} is declared, but under `data_stores`, and the field "
        "asking for it is `component`. Accepting it makes the target block's own "
        f"vocabulary meaningless; message was:\n{text}"
    )


def test_a_target_ref_with_no_kind_resolves_against_any_declared_id():
    threat = _threat("T-06", target={"ref": DECLARED_STORE})

    problems = _unknown_refs()(_threats_doc(threat), _architecture())

    assert _as_text(problems) == "", (
        "§4.2 pairs `ref` with an explicit `kind`. With no kind there is nothing "
        "to be strict about, and rejecting an id the architecture genuinely "
        f"declares would be a false problem the operator cannot fix; got {problems!r}"
    )


# ---------------------------------------------------------------------------
# One problem per offending reference — not one per threat, and not just the
# first. A document with three stale ids should take one round of review.
# ---------------------------------------------------------------------------


def test_every_offending_reference_on_one_threat_is_reported_not_only_the_first():
    threat = _threat(
        "T-01",
        boundary=MISSING_BOUNDARY,
        target={"kind": "data_flow", "ref": MISSING_FLOW, "component": MISSING_COMPONENT},
    )

    text = _as_text(_unknown_refs()(_threats_doc(threat), _architecture()))

    absent = [
        missing
        for missing in (MISSING_BOUNDARY, MISSING_FLOW, MISSING_COMPONENT)
        if missing not in text
    ]
    assert not absent, (
        "stopping at the first dangling reference on a record turns one review "
        "round into three: the operator fixes the boundary, re-runs, and meets the "
        f"flow. Not reported: {absent}. Message was:\n{text}"
    )


def test_every_offending_threat_is_reported_not_only_the_first():
    document = _threats_doc(
        _threat("T-01", boundary=MISSING_BOUNDARY),
        _threat("T-02", boundary=DECLARED_BOUNDARY),
        _threat("T-03", target={"kind": "component", "component": MISSING_COMPONENT}),
    )

    text = _as_text(_unknown_refs()(document, _architecture()))

    assert "T-01" in text and "T-03" in text, (
        "both offending records must be named. Reporting only the first hides how "
        f"stale the register is; message was:\n{text}"
    )
    assert "T-02" not in text, (
        f"T-02 resolves cleanly and must not appear; message was:\n{text}"
    )


def test_the_problem_count_is_one_per_reference_rather_than_one_per_threat():
    threat = _threat(
        "T-01",
        boundary=MISSING_BOUNDARY,
        target={"kind": "component", "component": MISSING_COMPONENT},
    )

    problems = _unknown_refs()(_threats_doc(threat), _architecture())

    assert len(problems) == 2, (
        "two dangling references on one record are two things to fix. Collapsing "
        "them into a single per-threat problem loses one of the two ids the "
        f"operator has to change; got {problems!r}"
    )


# ---------------------------------------------------------------------------
# Lifecycle. Same rule as `risk._duplicate_threat_pairs` (`risk.py:816`), not a
# new one: active records only.
# ---------------------------------------------------------------------------


def test_a_retired_threat_naming_a_missing_boundary_is_not_reported():
    threat = _threat(
        "T-01",
        boundary=MISSING_BOUNDARY,
        lifecycle={"status": "retired"},
    )

    problems = _unknown_refs()(_threats_doc(threat), _architecture())

    assert _as_text(problems) == "", (
        "a retired threat is history the register keeps on purpose, and the "
        "architecture it named was very likely decommissioned with it. Reporting "
        "it makes retirement generate permanent noise whose only cure is deleting "
        "the history. `risk._duplicate_threat_pairs` skips non-active records for "
        f"the same reason; got {problems!r}"
    )


def test_a_superseded_threat_naming_a_missing_boundary_is_not_reported():
    document = _threats_doc(
        _threat(
            "T-01",
            boundary=MISSING_BOUNDARY,
            lifecycle={"status": "superseded", "superseded_by": ["T-02"]},
        ),
        _threat("T-02", boundary=DECLARED_BOUNDARY),
    )

    problems = _unknown_refs()(document, _architecture())

    assert _as_text(problems) == "", (
        "the replacement T-02 carries the current reference; the superseded record "
        f"is kept for provenance, not for scoring; got {problems!r}"
    )


def test_an_active_threat_beside_a_retired_one_is_still_reported():
    document = _threats_doc(
        _threat("T-01", boundary=MISSING_BOUNDARY, lifecycle={"status": "retired"}),
        _threat("T-02", boundary=MISSING_BOUNDARY),
    )

    text = _as_text(_unknown_refs()(document, _architecture()))

    assert "T-02" in text, (
        "skipping inactive records must not become skipping the document; the "
        f"active T-02 has the same dangling reference; message was:\n{text}"
    )
    assert "T-01" not in text, (
        f"the retired record is still skipped; message was:\n{text}"
    )


def test_a_threat_whose_lifecycle_status_is_unknown_does_not_raise():
    document = _threats_doc(
        _threat("T-01", boundary=MISSING_BOUNDARY, lifecycle={"status": "mothballed"})
    )

    try:
        problems = _unknown_refs()(document, _architecture())
    except Exception as exc:  # noqa: BLE001 - the point of the test
        pytest.fail(
            "`risk._lifecycle_status` raises RiskValidationError on an unknown "
            "status, and `risk._validate_threats` already reports that record. §8 "
            "says the run completes, so this module must catch it rather than take "
            f"the review down over a problem another validator owns; raised {exc!r}"
        )
    _as_text(problems)


def test_a_threat_whose_lifecycle_is_not_a_mapping_does_not_raise():
    document = _threats_doc(_threat("T-01", boundary=MISSING_BOUNDARY, lifecycle="active"))

    try:
        problems = _unknown_refs()(document, _architecture())
    except Exception as exc:  # noqa: BLE001 - the point of the test
        pytest.fail(
            "`risk._lifecycle_status` raises on a non-mapping lifecycle; "
            f"`{__name__}` must survive it and let the threats validator report it. "
            f"raised {exc!r}"
        )
    _as_text(problems)


# ---------------------------------------------------------------------------
# The empty or absent architecture. One aggregate problem, not one per
# reference — see the docstring for why.
# ---------------------------------------------------------------------------


def test_an_absent_architecture_reports_one_aggregate_problem_not_one_per_reference():
    document = _threats_doc(
        _threat("T-01", boundary="tb-one"),
        _threat("T-02", boundary="tb-two"),
        _threat("T-03", boundary="tb-three"),
    )

    problems = _unknown_refs()(document, None)

    _as_text(problems)
    assert len(problems) == 1, (
        "with no architecture at all, every reference in the register is "
        "unresolvable. One problem per reference turns a single missing document "
        "into a wall of identical lines, each naming a different threat and none "
        "naming the cause — noise wearing disclosure's clothes. The cause is one "
        f"thing, so it is one problem; got {problems!r}"
    )


def test_the_aggregate_problem_says_the_architecture_declares_nothing():
    problems = _unknown_refs()(
        _threats_doc(_threat("T-01", boundary="tb-one")), {}
    )

    text = _as_text(problems)
    assert "architecture" in text.lower(), (
        "the aggregate problem replaces the per-reference detail, so it has to "
        "carry the one fact the detail would have obscured anyway: the "
        f"architecture is what is missing; message was:\n{text}"
    )


def test_an_empty_architecture_and_no_threat_references_reports_nothing():
    problems = _unknown_refs()(_threats_doc(), {})

    assert _as_text(problems) == "", (
        "a missing architecture with nothing referencing it resolves nothing and "
        "breaks nothing. §8's empty-`threats.yaml` row is a valid run; got "
        f"{problems!r}"
    )


def test_an_architecture_declaring_only_other_kinds_still_reports_per_reference():
    architecture = {"actors": [{"id": "act-customer", "name": "Customer"}]}
    document = _threats_doc(
        _threat("T-01", boundary=MISSING_BOUNDARY),
        _threat("T-02", boundary="tb-second-missing"),
    )

    problems = _unknown_refs()(document, architecture)

    text = _as_text(problems)
    assert len(problems) == 2, (
        "aggregation is narrow on purpose: it applies only when the architecture "
        "declares *nothing*. This one declares an actor, so the document loaded "
        "and the references are stale rather than unresolvable-in-principle — "
        f"which is the per-reference case; got {problems!r}"
    )
    for missing in (MISSING_BOUNDARY, "tb-second-missing"):
        assert missing in text, (
            f"{missing!r} must be named so the operator can fix it; message "
            f"was:\n{text}"
        )


# ---------------------------------------------------------------------------
# Malformed input never raises. §8: the run completes.
# ---------------------------------------------------------------------------


def test_unknown_architecture_refs_never_raises_on_malformed_inputs():
    reporter = _unknown_refs()
    good_threats = _threats_doc(_threat("T-01"))

    cases = (
        (None, None),
        ({}, {}),
        (None, _architecture()),
        (good_threats, None),
        (good_threats, []),
        (good_threats, "architecture.yaml"),
        (good_threats, {"components": None}),
        ({"threats": None}, _architecture()),
        ({"threats": "T-01"}, _architecture()),
        ([], _architecture()),
        ("threats.yaml", _architecture()),
    )
    for threats_doc, architecture in cases:
        try:
            problems = reporter(threats_doc, architecture)
        except Exception as exc:  # noqa: BLE001 - the point of the test
            pytest.fail(
                "the house convention is `list[str]`, never a raise (plan §10.1), "
                "and §8 requires the run to complete even when a reference cannot "
                f"be resolved; ({threats_doc!r}, {architecture!r}) raised {exc!r}"
            )
        _as_text(problems)


def test_a_threat_entry_that_is_not_a_mapping_is_skipped_rather_than_raising():
    document = _threats_doc("T-01", None, 17, _threat("T-02", boundary=MISSING_BOUNDARY))

    try:
        problems = _unknown_refs()(document, _architecture())
    except Exception as exc:  # noqa: BLE001 - the point of the test
        pytest.fail(
            "`risk._validate_threats` reports 'threat must be a mapping' and keeps "
            f"going; this module must do the same. raised {exc!r}"
        )
    text = _as_text(problems)
    assert "T-02" in text, (
        "the junk entries must not stop the scan before it reaches the real record "
        f"behind them; message was:\n{text}"
    )


def test_a_non_string_reference_is_not_reported_as_a_missing_id():
    document = _threats_doc(
        _threat("T-01", boundary=17),
        _threat("T-02", boundary=["tb-internet"]),
        _threat("T-03", target={"kind": "component", "component": {"id": "cmp-x"}}),
    )

    problems = _unknown_refs()(document, _architecture())

    assert _as_text(problems) == "", (
        "`risk._validate_threats` already reports a non-string `boundary` as "
        "'boundary is required'. A wrong *type* is a schema problem, not a "
        "dangling reference, and rendering `17` into an 'unknown id' message "
        f"sends the operator looking for an id that was never an id; got {problems!r}"
    )


def test_unknown_architecture_refs_does_not_mutate_either_input():
    document = _threats_doc(_threat("T-01", boundary=MISSING_BOUNDARY))
    architecture = _architecture()
    documents_before = copy.deepcopy(document)
    architecture_before = copy.deepcopy(architecture)

    _unknown_refs()(document, architecture)

    assert document == documents_before, (
        "the reporter reads the register; dropping the offending record in place "
        "would make the run score a silently truncated threat model."
    )
    assert architecture == architecture_before, (
        "the reporter reads the model; normalising it in place would leave later "
        "stages resolving against a rewritten architecture."
    )


# ---------------------------------------------------------------------------
# §4.3 — determinism. "All serialization is key-stable; no set iteration reaches
# output."
# ---------------------------------------------------------------------------


def test_the_problem_list_comes_back_in_the_same_order_across_two_calls():
    reporter = _unknown_refs()
    document = _threats_doc(
        _threat("T-01", boundary=MISSING_BOUNDARY),
        _threat("T-02", target={"kind": "component", "component": MISSING_COMPONENT}),
        _threat("T-03", target={"kind": "data_flow", "ref": MISSING_FLOW}),
    )

    first = reporter(document, _architecture())
    second = reporter(copy.deepcopy(document), _architecture())

    assert list(first) == list(second), (
        "§4.3: no set iteration reaches output. Two runs over the same register "
        "must produce the same problem list in the same order, or the report is "
        f"not byte-stable.\nfirst={first!r}\nsecond={second!r}"
    )


def test_the_problems_are_an_ordered_list_of_strings():
    problems = _unknown_refs()(
        _threats_doc(_threat("T-01", boundary=MISSING_BOUNDARY)), _architecture()
    )

    assert isinstance(problems, list), (
        "a set has no stable serialization (§4.3) and the house convention is "
        f"`list[str]`; got {type(problems)!r}"
    )
    _as_text(problems)


# ---------------------------------------------------------------------------
# The real threat shape. These run against `golden/movie-rating-aws/threats.yaml`
# rather than a builder, so the resolution rule is pinned to the record that
# actually ships.
# ---------------------------------------------------------------------------


def test_the_golden_threats_resolve_against_an_architecture_built_from_their_own_boundaries():
    threats_doc = _golden_threats_doc()
    architecture = {
        "trust_boundaries": [
            {"id": record["id"], "name": f"{record['from']} -> {record['to']}"}
            for record in threats_doc["boundaries"]
        ]
    }

    problems = _unknown_refs()(threats_doc, architecture)

    assert _as_text(problems) == "", (
        "every golden threat names a boundary its own document declares (TB-1 "
        "through TB-5). When the architecture reproduces those ids, nothing "
        "dangles. Note the namespace split this exposes: the register spells "
        "boundaries `TB-4` while plan §4.2 spells them `tb-internet` under "
        "`trust_boundaries`. Until the architecture document carries the "
        "register's ids, every shipped threat is unresolvable against it. Got "
        f"{problems!r}"
    )


def test_the_golden_threats_against_an_empty_architecture_report_one_problem_not_eight():
    threats_doc = _golden_threats_doc()
    active = risk_mod.active_threats(threats_doc)
    assert len(active) > 1, (
        "this test only means something with several active threats in the "
        f"fixture; found {len(active)}"
    )

    problems = _unknown_refs()(threats_doc, {})

    _as_text(problems)
    assert len(problems) == 1, (
        f"{len(active)} active threats each naming a boundary, against an "
        "architecture that declares nothing, is one missing document — not "
        f"{len(active)} stale ids. §8 wants the limitation recorded, and one line "
        f"naming the cause records it better than {len(active)} naming symptoms; "
        f"got {problems!r}"
    )


def test_the_golden_threats_report_a_stale_boundary_against_a_partial_architecture():
    threats_doc = _golden_threats_doc()
    declared = [record["id"] for record in threats_doc["boundaries"]]
    assert len(declared) > 1, (
        f"the fixture must declare more than one boundary to drop one; got {declared!r}"
    )
    dropped = declared[-1]
    architecture = {
        "trust_boundaries": [{"id": boundary_id} for boundary_id in declared[:-1]]
    }
    referencing = [
        record["id"]
        for record in risk_mod.active_threats(threats_doc)
        if record.get("boundary") == dropped
    ]
    assert referencing, (
        f"no active golden threat references {dropped!r}, so this test would pass "
        "vacuously"
    )

    text = _as_text(_unknown_refs()(threats_doc, architecture))

    assert dropped in text, (
        f"{dropped!r} was removed from the architecture and is still referenced by "
        f"{referencing}. §7.13 is exactly this: a boundary id absent from the "
        f"architecture; message was:\n{text}"
    )
    for threat_id in referencing:
        assert threat_id in text, (
            f"{threat_id} is the record the operator has to open; message "
            f"was:\n{text}"
        )
