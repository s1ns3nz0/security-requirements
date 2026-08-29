"""N32 — `--scope` (F5): narrow the review, and say what was left out.

Plan of record: `docs/security-design-review-plan.md` §3 (the command surface,
line 125: "`--scope` narrows to a subset of modelled components. It is not an
evidence selector."), §4.2 (the `run.scope` block), §4.3 (ordering — "no set
iteration reaches output"), §6 F5 ("Filter to `--scope`; record included/excluded
either way"), §8 ("`--scope` matches nothing → Fail with the list of known
component ids. Never silently review everything."), §10 (`scripts/sdr_scope.py`,
status **NEW**), §11.2 N32.

Pinned contract under specification — the module does **not** exist yet, so every
test in this file is RED by design. This file is the specification, not a report:

    scripts/sdr_scope.py
        resolve_scope(architecture: dict, scope: str | None) -> dict
            The §4.2 `run.scope` record:
            {"included": [...], "excluded": [...], "scope_filter": scope}
        scope_problems(architecture: dict, scope: str | None) -> list[str]
            House convention (`risk.validate_evidence`, `risk.validate_treatment`,
            `risk.validate_assessment`): a list of problem strings, never a raise.

Why the excluded side is load-bearing. A record that lists only inclusions makes
a narrow review indistinguishable from a complete one once it reaches the report:
the reader sees three components reviewed and cannot tell whether three were
modelled or thirty. F5 says "record included/excluded **either way**" for that
reason, and §4.2 gives both lists a slot.

Why the no-match case is the dangerous one. If a filter that matched nothing
falls through to reviewing everything, the operator believes they scoped a
subset while the report describes the whole system — the two disagree and
nothing in the run says so. §8 rules that out in the strongest available terms
("Never silently review everything"), so this file asserts both halves: the
problem is raised **and** the result does not widen to full coverage.

Two things this file deliberately does *not* do:

* It never calls `pytest.importorskip`. A skipped test is invisible, and an
  invisible test for a scope boundary is worse than no test — the run goes green
  and the reader concludes the boundary is held.
* It never asserts a *sorted* order for `included` / `excluded`. §4.3 requires
  determinism ("no set iteration reaches output"), not a particular collation;
  document order is a legitimate deterministic choice. Determinism is asserted by
  resolving twice and by resolving a deep copy, which is exactly the property
  §4.3 buys and no more.

Plan/source note recorded for the reviewer, not silently resolved here. The
§4.2 *example* spells the scope record with path globs —
`"included": ["services/checkout/**"], "excluded": ["**/node_modules/**"]` beside
`"scope_filter": "checkout-api"` (plan lines 185-189). That example contradicts
§3 line 125 and §8 line 530, which both make `--scope` a filter over *modelled
component ids* and make the failure message a list of *component ids*. The
normative prose is asserted here; the example's path globs are treated as
illustrative filler, since a path selector is precisely the "evidence selector"
line 125 forbids. See `test_the_scope_record_holds_architecture_ids_not_file_paths`.

Builders are local on purpose: `tests/risk_helpers.py` is under concurrent edit
by sibling agents and this file must not depend on its shape. The architecture
fixture below is plan §4.2 and is kept deliberately consistent with the one in
`tests/test_sdr_mermaid.py` — same ids, same shape — without importing it.
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


SCOPE_MODULE_PATH = PLUGIN_SCRIPTS / "sdr_scope.py"

#: Plan §4.2 — the three keys of the `run.scope` block, and only these three.
SCOPE_RECORD_KEYS = {"included", "excluded", "scope_filter"}


# ---------------------------------------------------------------------------
# The module under specification. Imported through helpers rather than at module
# scope so a missing module reports as a FAILURE on each test, with a message
# naming the file that has to exist, instead of one opaque collection error.
# ---------------------------------------------------------------------------


def _sdr_scope():
    try:
        import sdr_scope
    except ImportError as exc:  # pragma: no cover - this is the RED path
        pytest.fail(
            f"{SCOPE_MODULE_PATH} does not exist yet (plan §10, F5, status NEW). "
            f"N32 specifies `resolve_scope(architecture: dict, scope: str | None) -> dict` "
            f"and `scope_problems(architecture: dict, scope: str | None) -> list[str]` "
            f"in that module. import failed: {exc}"
        )
    return sdr_scope


def _resolve_scope():
    module = _sdr_scope()
    resolver = getattr(module, "resolve_scope", None)
    assert callable(resolver), (
        "sdr_scope must expose `resolve_scope(architecture: dict, scope: str | None) -> dict` "
        f"returning the plan §4.2 run.scope record; found {resolver!r}"
    )
    return resolver


def _scope_problems():
    module = _sdr_scope()
    reporter = getattr(module, "scope_problems", None)
    assert callable(reporter), (
        "sdr_scope must expose `scope_problems(architecture: dict, scope: str | None) "
        "-> list[str]`, following the house `validate_*` convention of returning "
        f"problems rather than raising; found {reporter!r}"
    )
    return reporter


# ---------------------------------------------------------------------------
# Fixture architecture. Shape is plan §4.2. Ids are chosen so that no id is a
# substring of another id or of any name: the N32 assertions search the problem
# text for ids, and a substring collision would let a missing id pass by
# accident. `cmp-pricing-worker` and `cmp-admin-console` exist so that a scope
# naming one component has something real to exclude — a single-component
# fixture cannot tell narrowing apart from full coverage.
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

#: The component the happy-path tests scope to, and the two it must leave out.
SCOPED_COMPONENT = "cmp-checkout-api"
OUT_OF_SCOPE_COMPONENTS = ("cmp-pricing-worker", "cmp-admin-console")

#: Every modelled component id, in document order. §8's failure message must
#: name all of these — that is the whole point of N32.
ALL_COMPONENT_IDS = tuple(record["id"] for record in ARCHITECTURE["components"])

#: A scope string that matches no modelled component. Shaped like a plausible
#: typo of a real id rather than obvious garbage, because the typo is the case
#: that actually reaches production.
NO_MATCH_SCOPE = "cmp-checkout-apis"


def _architecture() -> dict:
    """A private deep copy, so one test can never poison another."""

    return copy.deepcopy(ARCHITECTURE)


def _as_text(problems) -> str:
    assert isinstance(problems, list), (
        "scope_problems must return a list of problem strings (house convention: "
        f"`risk.validate_treatment`, `risk.validate_evidence`); got {type(problems)!r}"
    )
    for problem in problems:
        assert isinstance(problem, str), (
            f"every scope problem must be a human-readable string; got {problem!r}"
        )
    return "\n".join(problems)


# ---------------------------------------------------------------------------
# F5 / §4.2 — the record shape, and both of its sides.
# ---------------------------------------------------------------------------


def test_the_scope_record_carries_exactly_the_three_keys_of_plan_section_4_2():
    record = _resolve_scope()(_architecture(), SCOPED_COMPONENT)

    assert isinstance(record, dict), (
        f"resolve_scope must return the §4.2 run.scope mapping; got {type(record)!r}"
    )
    assert set(record) == SCOPE_RECORD_KEYS, (
        "the §4.2 run.scope block is exactly {included, excluded, scope_filter}; "
        f"got keys {sorted(record)}"
    )


def test_a_scope_naming_a_real_component_narrows_the_review_to_that_component():
    record = _resolve_scope()(_architecture(), SCOPED_COMPONENT)

    included = record["included"]
    assert SCOPED_COMPONENT in included, (
        f"scoping to {SCOPED_COMPONENT!r} must include it; included={included!r}"
    )
    for component_id in OUT_OF_SCOPE_COMPONENTS:
        assert component_id not in included, (
            f"{component_id!r} is outside the {SCOPED_COMPONENT!r} scope and must not "
            f"be reviewed; included={included!r}"
        )


def test_the_scope_record_reports_what_was_excluded_and_not_only_what_was_included():
    record = _resolve_scope()(_architecture(), SCOPED_COMPONENT)

    excluded = record["excluded"]
    assert excluded, (
        "F5 records included/excluded either way. With two of three components "
        "filtered out, an empty `excluded` list makes a narrow review read in the "
        "report exactly like a complete one — the reader cannot tell three "
        f"components reviewed from three modelled. record={record!r}"
    )
    for component_id in OUT_OF_SCOPE_COMPONENTS:
        assert component_id in excluded, (
            f"{component_id!r} was filtered out and must be named in `excluded`, so "
            f"the report states the limitation; excluded={excluded!r}"
        )


def test_the_scope_record_echoes_back_the_filter_it_was_given():
    record = _resolve_scope()(_architecture(), SCOPED_COMPONENT)

    assert record["scope_filter"] == SCOPED_COMPONENT, (
        "§4.2 stores the operator's filter verbatim in `scope_filter` so the report "
        f"can quote what was asked for; got {record['scope_filter']!r}"
    )


# ---------------------------------------------------------------------------
# F5 — the unscoped run. "Record included/excluded either way."
# ---------------------------------------------------------------------------


def test_no_scope_includes_every_component_and_excludes_nothing():
    record = _resolve_scope()(_architecture(), None)

    included = record["included"]
    for component_id in ALL_COMPONENT_IDS:
        assert component_id in included, (
            f"an unscoped run reviews the whole model, so {component_id!r} must be "
            f"included; included={included!r}"
        )
    assert list(record["excluded"]) == [], (
        "an unscoped run leaves nothing out, so `excluded` must be empty rather than "
        f"absent or populated; excluded={record['excluded']!r}"
    )


def test_no_scope_records_a_null_scope_filter():
    record = _resolve_scope()(_architecture(), None)

    assert record["scope_filter"] is None, (
        "with no `--scope` the §4.2 record carries `scope_filter: null`, which is how "
        "the report distinguishes 'reviewed everything' from 'a filter happened to "
        f"select everything'; got {record['scope_filter']!r}"
    )


def test_an_unscoped_run_reports_no_scope_problems():
    problems = _scope_problems()(_architecture(), None)

    assert _as_text(problems) == "", (
        f"omitting `--scope` is the default, not an error; got {problems!r}"
    )


def test_a_scope_naming_a_real_component_reports_no_scope_problems():
    problems = _scope_problems()(_architecture(), SCOPED_COMPONENT)

    assert _as_text(problems) == "", (
        f"{SCOPED_COMPONENT!r} is a modelled component id; got {problems!r}"
    )


# ---------------------------------------------------------------------------
# N32 / §8 — "`--scope` matches nothing → Fail with the list of known component
# ids. Never silently review everything."
# ---------------------------------------------------------------------------


def test_a_scope_matching_nothing_is_reported_as_a_problem():
    problems = _scope_problems()(_architecture(), NO_MATCH_SCOPE)

    assert problems, (
        f"§8: `--scope {NO_MATCH_SCOPE}` matches no modelled component and must fail. "
        "A run that accepts an unmatched filter leaves the operator believing they "
        "scoped a subset while the report describes something else."
    )


def test_the_no_match_problem_lists_the_known_component_ids():
    text = _as_text(_scope_problems()(_architecture(), NO_MATCH_SCOPE))

    missing = [
        component_id for component_id in ALL_COMPONENT_IDS if component_id not in text
    ]
    assert not missing, (
        "§8 and N32 require the failure to carry *the list of known component ids*, "
        "so the operator can correct the typo from the message alone without "
        f"re-reading the model. Absent from the message: {missing}. Message was:\n{text}"
    )


def test_the_no_match_problem_names_the_ids_rather_than_only_counting_them():
    text = _as_text(_scope_problems()(_architecture(), NO_MATCH_SCOPE))

    # A count is welcome in the message; it is not a substitute for the list.
    named = [component_id for component_id in ALL_COMPONENT_IDS if component_id in text]
    assert len(named) == len(ALL_COMPONENT_IDS), (
        "'3 known components' tells the operator nothing they can act on. N32 asks "
        "for the actual ids; a count that stands in for the list fails this test. "
        f"Named {len(named)} of {len(ALL_COMPONENT_IDS)}. Message was:\n{text}"
    )


def test_the_no_match_problem_quotes_the_filter_that_failed_to_match():
    text = _as_text(_scope_problems()(_architecture(), NO_MATCH_SCOPE))

    assert NO_MATCH_SCOPE in text, (
        "the message must quote the filter the operator actually typed, or a run "
        "with several problems gives no way to tell which flag was wrong. "
        f"Message was:\n{text}"
    )


def test_a_scope_matching_nothing_does_not_widen_to_full_coverage():
    record = _resolve_scope()(_architecture(), NO_MATCH_SCOPE)

    included = set(record["included"])
    assert not set(ALL_COMPONENT_IDS).issubset(included), (
        "§8: 'Never silently review everything.' A filter that matched nothing must "
        "not fall through to full coverage — that is the failure where the operator "
        "believes the review was narrow and the report says it was complete. "
        f"included={record['included']!r}"
    )


def test_a_scope_matching_nothing_does_not_silently_narrow_to_nothing_either():
    record = _resolve_scope()(_architecture(), NO_MATCH_SCOPE)
    problems = _scope_problems()(_architecture(), NO_MATCH_SCOPE)

    assert problems, (
        "an empty review is not a clean review. If `included` comes back empty for an "
        "unmatched filter, `scope_problems` must still report it, or a zero-finding "
        f"report reads as a passing one. record={record!r}"
    )


def test_a_scope_matching_nothing_still_echoes_the_filter_in_the_record():
    record = _resolve_scope()(_architecture(), NO_MATCH_SCOPE)

    assert record["scope_filter"] == NO_MATCH_SCOPE, (
        "even on the failing path the record must state which filter was applied, so "
        "the suppressed run is explainable after the fact; got "
        f"{record['scope_filter']!r}"
    )


# ---------------------------------------------------------------------------
# §3 line 125 — "narrows to a subset of modelled components. It is not an
# evidence selector."
# ---------------------------------------------------------------------------


def test_scoping_narrows_the_flows_and_stores_that_reference_the_component():
    record = _resolve_scope()(_architecture(), SCOPED_COMPONENT)

    included = set(record["included"])
    for flow_id in ("df-public-order", "df-cache-read"):
        assert flow_id in included, (
            f"{flow_id!r} has {SCOPED_COMPONENT!r} at one end, so it is inside the "
            f"scope; a component reviewed without its flows has no threats to find. "
            f"included={record['included']!r}"
        )
    assert "ds-session-cache" in included, (
        "ds-session-cache is reached by the in-scope flow df-cache-read and is part "
        f"of what the scoped component touches; included={record['included']!r}"
    )
    for out_of_scope_id in ("df-batch-price", "df-admin-write"):
        assert out_of_scope_id not in included, (
            f"neither end of {out_of_scope_id!r} is in scope, so it must not be "
            f"reviewed; included={record['included']!r}"
        )


def test_the_scope_record_holds_architecture_ids_not_file_paths():
    record = _resolve_scope()(_architecture(), SCOPED_COMPONENT)

    known_ids = {
        record_["id"]
        for kind in ("actors", "components", "data_stores", "data_flows", "trust_boundaries")
        for record_ in ARCHITECTURE[kind]
    }
    for side in ("included", "excluded"):
        for entry in record[side]:
            assert isinstance(entry, str), (
                f"`{side}` holds architecture ids; got {entry!r}"
            )
            assert entry in known_ids, (
                "§3 line 125: `--scope` is a component filter, not an evidence "
                f"selector. `{side}` must name modelled architecture ids, not paths "
                f"or globs; got {entry!r}. (The §4.2 example's path globs contradict "
                "the normative prose in §3 and §8; the prose wins.)"
            )


def test_a_file_path_scope_matches_no_component_and_fails_with_the_known_ids():
    text = _as_text(_scope_problems()(_architecture(), "services/checkout/handlers.py"))

    assert text, (
        "a path is not a modelled component id. `--scope` selects components, not "
        "evidence (§3 line 125), so a path must fail rather than quietly filter "
        "the evidence set."
    )
    missing = [
        component_id for component_id in ALL_COMPONENT_IDS if component_id not in text
    ]
    assert not missing, (
        "the path case takes the same §8 exit as any other non-match, and must name "
        f"the known component ids. Absent: {missing}. Message was:\n{text}"
    )


def test_a_glob_scope_is_not_expanded_against_component_ids():
    record = _resolve_scope()(_architecture(), "cmp-*")

    included = set(record["included"])
    assert not set(ALL_COMPONENT_IDS).issubset(included), (
        "`--scope` is an exact component filter, not a glob. Treating `cmp-*` as a "
        "wildcard is the silent-widening failure of §8 wearing different clothes: "
        f"the operator thinks they narrowed and got everything. included="
        f"{record['included']!r}"
    )


# ---------------------------------------------------------------------------
# Partition — the two sides must account for the model exactly once.
# ---------------------------------------------------------------------------


def test_nothing_appears_in_both_included_and_excluded():
    record = _resolve_scope()(_architecture(), SCOPED_COMPONENT)

    both = set(record["included"]) & set(record["excluded"])
    assert not both, (
        "an id on both sides makes the record self-contradictory: the report would "
        f"claim the same element was reviewed and not reviewed. Overlap: {sorted(both)}"
    )


def test_every_component_id_lands_on_exactly_one_side_of_the_record():
    record = _resolve_scope()(_architecture(), SCOPED_COMPONENT)

    included = set(record["included"])
    excluded = set(record["excluded"])
    unaccounted = [
        component_id
        for component_id in ALL_COMPONENT_IDS
        if (component_id in included) == (component_id in excluded)
    ]
    assert not unaccounted, (
        "F5 records included/excluded either way, so the union of the two sides "
        "covers every modelled component. A component in neither list is invisible "
        "to the reader — it was neither reviewed nor declared out of scope. "
        f"Unaccounted for: {unaccounted}"
    )


def test_neither_side_of_the_record_repeats_an_id():
    record = _resolve_scope()(_architecture(), SCOPED_COMPONENT)

    for side in ("included", "excluded"):
        entries = list(record[side])
        assert len(entries) == len(set(entries)), (
            f"`{side}` must not repeat an id; a duplicate inflates coverage counts "
            f"in the report. got {entries!r}"
        )


# ---------------------------------------------------------------------------
# §4.3 — determinism. "All serialization is key-stable; no set iteration reaches
# output."
# ---------------------------------------------------------------------------


def test_resolving_the_same_scope_twice_returns_the_same_record():
    resolver = _resolve_scope()

    first = resolver(_architecture(), SCOPED_COMPONENT)
    second = resolver(_architecture(), SCOPED_COMPONENT)

    assert first == second, (
        "§4.3: no set iteration reaches output. Two resolutions of the same input "
        f"must be identical.\nfirst={first!r}\nsecond={second!r}"
    )


def test_included_and_excluded_come_back_in_a_stable_order():
    resolver = _resolve_scope()

    first = resolver(_architecture(), SCOPED_COMPONENT)
    second = resolver(_architecture(), SCOPED_COMPONENT)

    for side in ("included", "excluded"):
        assert isinstance(first[side], list), (
            f"`{side}` must be an ordered list, not a set — a set has no stable "
            f"serialization (§4.3); got {type(first[side])!r}"
        )
        assert list(first[side]) == list(second[side]), (
            f"`{side}` changed order between two identical resolutions, so the JSON "
            f"report is not byte-stable.\nfirst={first[side]!r}\nsecond={second[side]!r}"
        )


def test_the_unscoped_record_is_stable_across_resolutions_too():
    resolver = _resolve_scope()

    assert resolver(_architecture(), None) == resolver(_architecture(), None), (
        "the unscoped path lists every component and is the one most likely to be "
        "built from a set; §4.3 forbids that reaching output."
    )


def test_resolve_scope_does_not_mutate_the_architecture_it_was_given():
    architecture = _architecture()
    before = copy.deepcopy(architecture)

    _resolve_scope()(architecture, SCOPED_COMPONENT)

    assert architecture == before, (
        "resolve_scope reads the model; filtering in place would leave later stages "
        "scoring a silently truncated architecture."
    )


# ---------------------------------------------------------------------------
# House convention — `scope_problems` reports, it never raises.
# ---------------------------------------------------------------------------


def test_scope_problems_reports_a_whitespace_only_scope_rather_than_matching_it():
    problems = _scope_problems()(_architecture(), "   ")

    assert problems, (
        "the house `_nonempty_text` rule (`risk.py:1444`) treats a whitespace-only "
        "string as absent. An all-spaces `--scope` is an operator mistake, not a "
        "request to review everything."
    )
    _as_text(problems)


def test_scope_problems_reports_an_empty_scope_rather_than_raising():
    problems = _scope_problems()(_architecture(), "")

    _as_text(problems)
    assert problems, (
        "`--scope ''` matches no component and must be reported, not treated as an "
        "unscoped run."
    )


def test_scope_problems_returns_problems_for_an_empty_architecture_and_never_raises():
    problems = _scope_problems()({"components": []}, SCOPED_COMPONENT)

    _as_text(problems)
    assert problems, (
        "with no modelled components, any `--scope` matches nothing. The house "
        "convention is to return the problem (`risk.validate_assessment`), so the "
        "caller can collect it alongside the others and exit 1 once."
    )


def test_scope_problems_tolerates_a_malformed_architecture_without_raising():
    reporter = _scope_problems()

    for architecture in ({}, {"components": None}, {"components": ["not-a-record"]}):
        try:
            problems = reporter(architecture, SCOPED_COMPONENT)
        except Exception as exc:  # noqa: BLE001 - the point of the test
            pytest.fail(
                "scope_problems follows the house `validate_*` convention and returns "
                f"problems rather than raising; {architecture!r} raised {exc!r}"
            )
        _as_text(problems)
