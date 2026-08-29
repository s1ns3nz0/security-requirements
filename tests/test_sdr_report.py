"""§4.2 — the JSON report record, assembled.

Plan of record: `docs/security-design-review-plan.md` §4.2 (the contract of
record, given as a complete worked example), §4.3 (ordering and determinism),
and `docs/design-review-runner-contract.md` §7, which is a key-by-key table of
which §4.2 keys already have a producer and which do not.

Pinned contract under specification. `scripts/sdr_report.py` does **not** exist,
so every test here is RED by construction and fails by *name*:

    build_report(documents, *, entry, scope_record, confirmation,
                 risk_appetite, invocation, today) -> dict
        The §4.2 record. Pure: no I/O, no writes. Raises RiskValidationError.

    report_problems(documents, *, scope, policy, today) -> list[str]
        Returns problems, never raises (house convention, plan §10.1).

`documents` carries `policy`, `threats`, `assessment`, `requirements`,
`evidence`, `architecture`. `entry` is a `sdr_entry.design_review(...)` result.
`scope_record` is a `sdr_scope.resolve_scope(...)` result. `invocation` carries
the caller-supplied `platform`, `model`, `plugin_version`, `command`,
`timestamp`.

Three things §4.2 is emphatic about, each asserted below
-------------------------------------------------------

**`cia` is a sibling of `calculated`, never a member of it.**
`calculate_inherent` returns four keys and only four. §4.2 spells this out as
load-bearing rather than stylistic: `risk_helpers._golden_report` compares a
stored `calculated` block against the engine result by exact equality, so
nesting `cia` inside it breaks R2 and every fixture that records a calculation.

**An axis no consequence claims is absent from the `cia` block, not zero.**
"Not assessed" and "assessed as none" must not render alike.

**The `cia` keys are output-side spelling.** Documents on disk spell the axis
in full; `risk.CIA_OUTPUT_KEYS` is the map. §5.3 is the decision of record:
long form in, short form out.

Three keys with no producer
---------------------------

Per the runner contract §7, and asserted here so the gaps stay visible:

* `run.platform` and `run.model` are caller knowledge. Nothing in the
  repository knows which host or model is running; they arrive through
  `invocation` or they are `null`. Detecting them would mean guessing.
* `run.repo.dirty` cannot be computed. It means "the worktree differs from the
  index", which needs a stat-and-hash of every tracked file; N36 bans
  subprocess execution, so `git status` is unavailable. It is `null` with a
  stated reason rather than an approximation — a report claiming
  `"dirty": false` on a dirty tree is worse than one declining to answer,
  because that field is how a reader decides whether the commit id means
  anything at all.

Builders are local. `tests/risk_helpers.py` and `tests/conftest.py` are shared
and are not depended on here.
"""

from __future__ import annotations

import copy
from datetime import date
from pathlib import Path
import sys

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
PLUGIN_ROOT = REPO_ROOT / "plugins" / "security-requirements"
PLUGIN_SCRIPTS = PLUGIN_ROOT / "scripts"
if str(PLUGIN_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(PLUGIN_SCRIPTS))

import risk as risk_mod  # noqa: E402

REPORT_MODULE_PATH = PLUGIN_SCRIPTS / "sdr_report.py"

#: Pinned so no test reads a clock (§4.3).
PINNED_TODAY = date(2026, 5, 1)
PINNED_TIMESTAMP = "2026-08-29T05:57:00Z"

#: §4.2 line 181 — the report's own top-level key. Distinct from a *document's*
#: `version`, which is what `architecture.yaml` and `threats.yaml` carry.
SCHEMA_VERSION_KEY = "schema_version"


# ---------------------------------------------------------------------------
# The module under specification, reached through accessors so a missing module
# fails each test by name rather than as one opaque collection error.
# ---------------------------------------------------------------------------


def _sdr_report():
    try:
        import sdr_report
    except ImportError as exc:  # pragma: no cover - the RED path
        pytest.fail(
            f"{REPORT_MODULE_PATH} does not exist yet. Plan §4.2 is the contract "
            "of record for the report; the runner contract §3 puts its assembly "
            "in `sdr_report.build_report(documents, *, entry, scope_record, "
            "confirmation, risk_appetite, invocation, today)` and its input "
            f"validation in `report_problems`. import failed: {exc}"
        )
    return sdr_report


def _build():
    module = _sdr_report()
    builder = getattr(module, "build_report", None)
    assert callable(builder), (
        "sdr_report must expose `build_report(...) -> dict` returning the §4.2 "
        f"record; found {builder!r}"
    )
    return builder


def _problems_fn():
    module = _sdr_report()
    reporter = getattr(module, "report_problems", None)
    assert callable(reporter), (
        "sdr_report must expose `report_problems(...) -> list[str]`, following "
        "the house `validate_*` convention of returning problems rather than "
        f"raising; found {reporter!r}"
    )
    return reporter


# ---------------------------------------------------------------------------
# Fixtures. Shape is plan §4.2, ids chosen so none is a substring of another.
# ---------------------------------------------------------------------------

ARCHITECTURE = {
    "version": "0.1.0",
    "actors": [
        {"id": "act-customer", "name": "Customer", "evidence_status": "observed"},
    ],
    "components": [
        {
            "id": "cmp-checkout-api",
            "name": "checkout-api",
            "evidence_status": "observed",
            "trust_boundary": "tb-internet",
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
    ],
    "trust_boundaries": [
        {"id": "tb-internet", "name": "Internet edge", "evidence_status": "observed"},
    ],
    "assets": [
        {
            "id": "as-card-token",
            "name": "Card token",
            # Long form: §5.3 is long form in, short form out.
            "cia_relevance": "confidentiality",
        },
    ],
    "dependencies": [],
    "assumptions": ["Ingress terminates TLS at the ALB (not observed in scope)"],
}

THREAT_ID = "T-09"

THREATS = {
    "version": "0.2.0",
    "profile": "checkout",
    "boundaries": [
        {"id": "tb-internet", "from": "internet", "to": "checkout-api"},
    ],
    "threats": [
        {
            "id": THREAT_ID,
            "risk_family": "RF-09",
            "category": "STRIDE:T",
            "novelty": "service_specific",
            "persona": "anonymous_external",
            "attack_path": "unauthenticated_write_across_boundary",
            "scenario": "Anonymous caller POSTs /orders/{id} and alters line items.",
            "affected_assets": ["order_records"],
            "related_controls": ["AC-3"],
            "boundary": "tb-internet",
            "lifecycle": {"status": "active", "superseded_by": []},
        },
    ],
}

#: One consequence, on the integrity axis only. Deliberately *not* all three:
#: the absent-axis rule below can only be asserted against a finding that
#: leaves an axis unclaimed.
PROPOSED = {
    "likelihood": {
        "criterion": "L4-PUBLIC-LOW-COMPLEXITY",
        "rationale": ["Reachable from the internet with a known order id."],
        "evidence": {
            "exposure": "internet",
            "access_required": "none",
            "exploit_complexity": "low",
            "preconditions": ["known order id"],
            "observed_controls": ["rate limit"],
        },
    },
    "consequences": [
        {
            "id": "c-tamper",
            "axis": "integrity",
            "criterion": "I4-CROSS-SYSTEM",
            "rationale": ["Direct financial record mutation."],
        },
    ],
    "impact": {"selected_from": "c-tamper"},
}

REQUIREMENTS = {
    "version": "0.1.0",
    "requirements": [
        {
            "id": "REQ-1",
            "statement": (
                "checkout-api MUST reject unauthenticated requests to "
                "POST /orders/{id} with 401."
            ),
            "rationale": "Unauthenticated write across the internet boundary.",
            "csf": ["PR.AA-05"],
            "sources": ["AC-3"],
            "threat_refs": [THREAT_ID],
            "responsibility": "team",
            "priority": "high",
            "verification": {
                "method": "test_case",
                "expect": "unauthenticated POST returns 401",
            },
        },
    ],
}

EVIDENCE = {"version": "0.1.0", "evidence": []}

INVOCATION = {
    "platform": "claude",
    "model": "claude-opus-5",
    "plugin_version": "0.2.0",
    "command": "/security-design-review ./services/checkout --mode quick",
    "timestamp": PINNED_TIMESTAMP,
}


def _policy(appetite: str = "standard") -> dict:
    """The base policy overlaid with one appetite.

    An appetite file is an overlay, not a whole policy: it restates
    `thresholds`, `impact_floor` and `release_threshold_rating`, while the
    `likelihood` and `impact` criterion tables live only in
    `default-policy.yaml`. Reading the overlay alone gives a policy with no
    criteria, and `criterion_score` raises `KeyError` on it.
    """

    return risk_mod.appetite_policy(appetite)


def _assessment() -> dict:
    policy = _policy()
    calculated = risk_mod.calculate_inherent(policy, copy.deepcopy(PROPOSED))
    return {
        "version": "0.2.0",
        "assessments": [
            {
                "threat_id": THREAT_ID,
                "status": "CONFIRMED",
                "proposed": copy.deepcopy(PROPOSED),
                "calculated": calculated,
            },
        ],
    }


def _documents() -> dict:
    return {
        "policy": _policy(),
        "threats": copy.deepcopy(THREATS),
        "assessment": _assessment(),
        "requirements": copy.deepcopy(REQUIREMENTS),
        "evidence": copy.deepcopy(EVIDENCE),
        "architecture": copy.deepcopy(ARCHITECTURE),
    }


def _entry() -> dict:
    return {
        "run": {
            "mode": "quick",
            "interview_depth": "five_critical_unknowns",
            "evidence_source": "./services/checkout",
            "intake_invoked": False,
            "profile": {
                "stale_vs_head": True,
                "compared_against": "main",
                "unconfirmed_critical_facts": ["isolation", "privileged_access"],
            },
            "critical_facts": [
                {
                    "fact": "isolation",
                    "evidence_status": "inferred",
                    "confidence": "low",
                },
                {
                    "fact": "privileged_access",
                    "evidence_status": "inferred",
                    "confidence": "low",
                },
            ],
        },
    }


def _scope_record() -> dict:
    import sdr_scope

    return sdr_scope.resolve_scope(copy.deepcopy(ARCHITECTURE), None)


def _report(**overrides):
    kwargs = {
        "entry": _entry(),
        "scope_record": _scope_record(),
        "confirmation": None,
        "risk_appetite": "standard",
        "invocation": dict(INVOCATION),
        "today": PINNED_TODAY,
    }
    kwargs.update(overrides)
    documents = kwargs.pop("documents", None) or _documents()
    return _build()(documents, **kwargs)


def _findings(report) -> list:
    assert isinstance(report, dict), f"build_report must return a dict; got {report!r}"
    findings = report.get("findings")
    assert isinstance(findings, list), (
        f"the §4.2 record carries a `findings` list; got {findings!r}"
    )
    return findings


def _finding(report, threat_id: str = THREAT_ID) -> dict:
    for finding in _findings(report):
        if isinstance(finding, dict) and finding.get("id") == threat_id:
            return finding
    raise AssertionError(
        f"no finding with id {threat_id!r}; ids were "
        f"{[f.get('id') for f in _findings(report) if isinstance(f, dict)]}"
    )


def _run(report) -> dict:
    assert isinstance(report, dict), f"build_report must return a dict; got {report!r}"
    run = report.get("run")
    assert isinstance(run, dict), (
        f"the §4.2 record carries a `run` block; got {report!r}"
    )
    return run


# ---------------------------------------------------------------------------
# §4.2 — `cia` is a sibling of `calculated`, never a member of it.
# ---------------------------------------------------------------------------


def test_the_calculated_block_carries_exactly_the_four_engine_keys():
    finding = _finding(_report())

    calculated = finding.get("calculated")
    assert isinstance(calculated, dict), (
        f"the finding carries a `calculated` block; got {calculated!r}"
    )
    assert set(calculated) == {"likelihood", "impact", "score", "rating"}, (
        "`calculate_inherent` returns four keys and only four. "
        "`risk_helpers._golden_report` compares a stored `calculated` block "
        "against the engine result by exact equality, so an extra key here "
        f"breaks R2 and every fixture that records a calculation; got "
        f"{sorted(calculated)}"
    )


def test_the_cia_block_is_a_sibling_of_calculated_and_not_nested_inside_it():
    finding = _finding(_report())

    assert "cia" in finding, (
        "§4.2 puts `cia` and `calculated` side by side on the finding; the "
        f"finding held {sorted(finding)}"
    )
    assert "cia" not in finding["calculated"], (
        "`cia` nested inside `calculated` is the R2 break §4.2 warns about "
        "explicitly. It is a sibling, never a member."
    )


def test_the_calculated_block_equals_what_the_engine_returns_for_the_same_input():
    finding = _finding(_report())

    expected = risk_mod.calculate_inherent(_policy(), copy.deepcopy(PROPOSED))

    assert finding["calculated"] == expected, (
        "the report must carry the engine's own calculation verbatim; a report "
        "that recomputes or reshapes it is a second opinion that can drift. "
        f"engine: {expected!r}, report: {finding['calculated']!r}"
    )


# ---------------------------------------------------------------------------
# §4.2 — an unclaimed axis is absent, not zero.
# ---------------------------------------------------------------------------


def test_an_axis_no_consequence_claims_is_absent_from_the_cia_block():
    finding = _finding(_report())

    cia = finding["cia"]
    assert isinstance(cia, dict), f"the `cia` block is a mapping; got {cia!r}"

    integrity_letter = risk_mod.CIA_OUTPUT_KEYS["integrity"]
    assert integrity_letter in cia, (
        f"the fixture claims the integrity axis, so {integrity_letter!r} must be "
        f"scored; the block held {sorted(cia)}"
    )
    for unclaimed in ("confidentiality", "availability"):
        letter = risk_mod.CIA_OUTPUT_KEYS[unclaimed]
        assert letter not in cia, (
            f"no consequence claims the {unclaimed} axis, so {letter!r} must be "
            "absent rather than zero. 'Not assessed' and 'assessed as none' "
            f"must not render alike (§4.2); the block held {cia!r}"
        )


def test_the_cia_block_is_keyed_by_the_rendered_letter_through_the_output_map():
    finding = _finding(_report())

    cia = finding["cia"]
    scored = set(cia) - {"floor", "raised"}
    assert scored, f"the `cia` block scored no axis at all; got {cia!r}"
    assert scored <= set(risk_mod.CIA_OUTPUT_KEYS.values()), (
        "§5.3 is long form in, short form out, with `risk.CIA_OUTPUT_KEYS` as "
        "the map. The report is output-side, so its axis keys are the rendered "
        f"letters; got {sorted(scored)}"
    )
    assert not (scored & set(risk_mod.CIA_OUTPUT_KEYS)), (
        "the long form belongs on the document, not in the report. Emitting "
        f"both spellings gives a reader two keys for one axis; got {sorted(scored)}"
    )


def test_the_cia_block_matches_what_cia_scores_returns_for_the_same_input():
    finding = _finding(_report())

    expected = risk_mod.cia_scores(_policy(), copy.deepcopy(PROPOSED))

    assert finding["cia"] == expected, (
        "the `cia` block is `risk.cia_scores` output, not a second derivation. "
        f"engine: {expected!r}, report: {finding['cia']!r}"
    )


# ---------------------------------------------------------------------------
# §4.2 — the run header.
# ---------------------------------------------------------------------------


def test_the_run_scope_block_is_the_scope_record_verbatim():
    scope_record = _scope_record()

    run = _run(_report(scope_record=copy.deepcopy(scope_record)))

    assert run.get("scope") == scope_record, (
        "`sdr_scope.resolve_scope` owns the `run.scope` shape; reshaping it "
        "here gives the report a second opinion about what was reviewed. "
        f"expected {scope_record!r}, got {run.get('scope')!r}"
    )


def test_the_run_profile_block_carries_the_unconfirmed_critical_facts_from_intake():
    run = _run(_report())

    profile = run.get("profile")
    assert isinstance(profile, dict), (
        f"§4.2 puts a `profile` block in the run header; got {profile!r}"
    )
    assert profile.get("unconfirmed_critical_facts") == [
        "isolation",
        "privileged_access",
    ], (
        "`sdr_entry` already computes which critical unknowns went unanswered; "
        "the report carries that list rather than recomputing it. §4.2 line 193 "
        f"places it under `run.profile`; got {profile!r}"
    )


def test_the_run_header_carries_the_appetite_it_was_scored_under():
    run = _run(_report(risk_appetite="conservative"))

    assert run.get("risk_appetite") == "conservative", (
        "a rating means nothing without the appetite it was judged against; "
        f"got {run.get('risk_appetite')!r}"
    )


def test_the_run_header_carries_the_policy_digest_the_engine_computes():
    run = _run(_report())

    assert run.get("policy_digest") == risk_mod.policy_digest(_policy()), (
        "the policy digest binds the report to the thresholds that produced it; "
        f"got {run.get('policy_digest')!r}"
    )


def test_an_unconfirmed_run_says_so_in_the_run_header():
    run = _run(_report(confirmation=None))

    assert run.get("confirmed") is False, (
        "N26: with no trusted confirmation the run is unconfirmed, and the "
        "header states it as `False` rather than omitting it. An absent key "
        f"reads as confirmed to anything that uses `.get`; got {run!r}"
    )


def test_a_confirmed_run_says_so_in_the_run_header():
    confirmation = {"status": "confirmed", "confirmed_by": "user"}

    run = _run(_report(confirmation=confirmation))

    assert run.get("confirmed") is True, (
        f"a run carrying a trusted confirmation is confirmed; got {run!r}"
    )


# ---------------------------------------------------------------------------
# Runner contract §7 — the three keys with no producer.
# ---------------------------------------------------------------------------


def test_the_platform_and_model_come_from_the_caller_and_are_never_detected():
    invocation = dict(INVOCATION, platform="codex", model="some-other-model")

    run = _run(_report(invocation=invocation))

    assert run.get("platform") == "codex", (
        "nothing in this repository knows which host is running; `platform` is "
        f"caller knowledge and is carried through verbatim. got {run.get('platform')!r}"
    )
    assert run.get("model") == "some-other-model", (
        "`model` is caller knowledge too. Detecting it would mean guessing; "
        f"got {run.get('model')!r}"
    )


def test_an_absent_platform_is_null_rather_than_a_guess():
    invocation = {key: value for key, value in INVOCATION.items() if key != "platform"}

    run = _run(_report(invocation=invocation))

    assert run.get("platform", "MISSING") is None, (
        "with no platform supplied the honest answer is `null`. Substituting a "
        "default would put a fact in the report that nobody established; got "
        f"{run.get('platform', 'MISSING')!r}"
    )


def test_the_repo_dirty_flag_is_null_because_it_cannot_be_computed_here():
    run = _run(_report())

    repo = run.get("repo")
    assert isinstance(repo, dict), (
        f"§4.2 puts a `repo` block in the run header; got {repo!r}"
    )
    assert "dirty" in repo, (
        "`dirty` is stated as unknown rather than omitted — an absent key and "
        f"a null one are different claims; the repo block held {sorted(repo)}"
    )
    assert repo["dirty"] is None, (
        "`dirty` means the worktree differs from the index, which needs a "
        "stat-and-hash of every tracked file; N36 bans the subprocess that "
        "would answer it. A report claiming `\"dirty\": false` on a dirty tree "
        "is worse than one declining to answer, because that field is how a "
        f"reader decides whether the commit id means anything; got {repo['dirty']!r}"
    )


def test_the_run_timestamp_is_the_injected_one_and_no_clock_is_read():
    run = _run(_report())

    assert run.get("timestamp") == PINNED_TIMESTAMP, (
        "§4.3 and N39: every date the report depends on is injected. A clock "
        f"read here makes two identical runs disagree; got {run.get('timestamp')!r}"
    )


# ---------------------------------------------------------------------------
# §4.2 — findings, verdict, ordering.
# ---------------------------------------------------------------------------


def test_a_finding_id_is_the_existing_stable_threat_id():
    finding = _finding(_report())

    assert finding["id"] == THREAT_ID, (
        "finding IDs are the existing author-assigned threat IDs, carried "
        "unchanged across runs (§4.2). Minting applies only to description "
        f"mode, where no ID exists yet; got {finding['id']!r}"
    )


def test_the_verdict_inherent_block_is_what_aggregate_risk_returns():
    report = _report()
    documents = _documents()

    expected = risk_mod.aggregate_risk(
        documents["threats"], documents["assessment"], today=PINNED_TODAY
    )
    verdict = report.get("verdict")
    assert isinstance(verdict, dict), (
        f"§4.2 carries a `verdict` block; got {verdict!r}"
    )
    assert verdict.get("inherent") == expected, (
        "`aggregate_risk` owns the aggregate; the report carries it rather "
        f"than recomputing. engine: {expected!r}, report: {verdict.get('inherent')!r}"
    )


def test_the_verdict_names_the_release_threshold_from_the_appetite_policy():
    report = _report()

    verdict = report["verdict"]
    assert verdict.get("release_threshold_rating") == _policy()[
        "release_threshold_rating"
    ], (
        "the threshold is policy-as-data, read from the appetite file rather "
        f"than branched on in code; got {verdict.get('release_threshold_rating')!r}"
    )


def test_the_verdict_says_whether_the_threshold_was_exceeded():
    report = _report()

    verdict = report["verdict"]
    assert isinstance(verdict.get("exceeds_threshold"), bool), (
        "`exceeds_threshold` is a stated fact, not an absence; got "
        f"{verdict.get('exceeds_threshold')!r}"
    )


def test_the_verdict_never_asserts_the_service_is_secure():
    report = _report()

    statement = report["verdict"].get("statement", "")
    assert isinstance(statement, str) and statement, (
        f"§4.2 carries a verdict `statement`; got {statement!r}"
    )
    lowered = statement.lower()

    # The disclaimer itself contains the phrase "the service is secure", inside
    # a negation. A substring scan cannot tell an assertion from its denial, so
    # this asserts the denial is *present* and then forbids only phrasings that
    # cannot occur inside one.
    assert "not an approval" in lowered, (
        "F14: the verdict carries the disclaimer that it is not an approval, "
        f"attestation, or claim that the service is secure; got {statement!r}"
    )
    for forbidden in (
        "approved for release",
        "no security issues",
        "we attest",
    ):
        assert forbidden not in lowered, (
            "F14: the verdict is never an approval, attestation, or claim that "
            f"the service is secure. The statement said {statement!r}"
        )


# ---------------------------------------------------------------------------
# §4.3 — determinism, and no mutation of the caller's documents.
# ---------------------------------------------------------------------------


def test_two_builds_over_identical_inputs_produce_equal_records():
    first = _report()
    second = _report()

    assert first == second, (
        "§4.3: two runs with `today` and the timestamp pinned produce an "
        "identical record. A difference here means something read a clock or "
        "iterated a set."
    )


def test_two_builds_over_identical_inputs_produce_an_identical_digest():
    first = risk_mod.canonical_digest(_report())
    second = risk_mod.canonical_digest(_report())

    assert first == second, (
        "N39 states the property over the digest, which is what a confirmation "
        f"binds. {first} vs {second}"
    )


def test_build_report_does_not_mutate_the_documents_it_is_given():
    documents = _documents()
    before = copy.deepcopy(documents)

    _report(documents=documents)

    assert documents == before, (
        "`build_report` reads its inputs. Mutating them would leave later "
        "stages scoring a document the caller never wrote."
    )


def test_build_report_does_not_mutate_the_entry_or_scope_record():
    entry = _entry()
    scope_record = _scope_record()
    entry_before = copy.deepcopy(entry)
    scope_before = copy.deepcopy(scope_record)

    _report(entry=entry, scope_record=scope_record)

    assert entry == entry_before, "`entry` was mutated by build_report"
    assert scope_record == scope_before, "`scope_record` was mutated by build_report"


def test_the_report_carries_its_own_schema_version():
    report = _report()

    assert SCHEMA_VERSION_KEY in report, (
        "§4.2 line 181 gives the report a top-level `schema_version`. It is the "
        "*report's* key; documents on disk spell their own version `version`. "
        f"The record held {sorted(report)}"
    )


# ---------------------------------------------------------------------------
# `report_problems` — the house convention, and the architecture it now checks.
# ---------------------------------------------------------------------------


def test_report_problems_returns_a_list_and_never_raises_on_malformed_input():
    reporter = _problems_fn()

    for documents in ({}, {"architecture": None}, {"threats": "not-a-mapping"}):
        try:
            problems = reporter(
                documents, scope=None, policy=_policy(), today=PINNED_TODAY
            )
        except Exception as exc:  # noqa: BLE001 - the point of the test
            pytest.fail(
                "report_problems follows the house `validate_*` convention and "
                f"returns problems rather than raising; {documents!r} raised {exc!r}"
            )
        assert isinstance(problems, list), (
            f"report_problems returns a list of strings; got {type(problems)!r}"
        )
        for problem in problems:
            assert isinstance(problem, str), (
                f"every problem is a human-readable string; got {problem!r}"
            )


def test_a_clean_document_set_reports_no_problems():
    problems = _problems_fn()(
        _documents(), scope=None, policy=_policy(), today=PINNED_TODAY
    )

    assert problems == [], (
        f"the fixture set is well formed and must report nothing; got {problems!r}"
    )


def test_report_problems_reports_a_threat_naming_an_undeclared_architecture_id():
    documents = _documents()
    documents["threats"]["threats"][0]["boundary"] = "tb-nobody-declares"

    problems = _problems_fn()(
        documents, scope=None, policy=_policy(), today=PINNED_TODAY
    )

    text = "\n".join(problems)
    assert "tb-nobody-declares" in text, (
        "§7.13: a threat referencing an id absent from the architecture is "
        "reported. `sdr_architecture.unknown_architecture_refs` already does "
        f"this; the report collects it. Problems were {problems!r}"
    )


def test_report_problems_reports_a_scope_that_matches_nothing():
    problems = _problems_fn()(
        _documents(),
        scope="cmp-nobody-declares",
        policy=_policy(),
        today=PINNED_TODAY,
    )

    text = "\n".join(problems)
    assert "cmp-nobody-declares" in text, (
        "§8: a `--scope` matching nothing fails with the known component ids. "
        f"`sdr_scope.scope_problems` already does this; got {problems!r}"
    )


def test_report_problems_reports_a_malformed_architecture_document():
    documents = _documents()
    documents["architecture"]["components"][0]["evidence_status"] = "observed-ish"

    problems = _problems_fn()(
        documents, scope=None, policy=_policy(), today=PINNED_TODAY
    )

    assert problems, (
        "`sdr_architecture.validate_architecture` rejects an evidence_status "
        "outside the closed set; the report collects that problem rather than "
        "scoring against a document it knows is malformed"
    )
