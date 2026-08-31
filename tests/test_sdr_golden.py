"""The design-review golden: one input, one hand-reviewed expected output.

Every other test in this suite asserts a *property* — that ordering is stable,
that an absence is stated, that a digest does not move. None of them asserts
"this register produces this report". That is a different class of guarantee
and it catches a different class of regression: a field quietly dropped from
the record, a rating that shifts one band, a limitation that stops being
emitted, an ordering that reverts. Each of those satisfies every property this
suite checks while changing what a reader is told.

`golden/movie-rating-aws/expected-design-review.yaml` is the baseline, written
by hand after reading the output rather than by dumping it. CONTRIBUTING's rule
for the existing goldens applies here too: **widening the expectation so a
failing run passes is how the suite stops measuring anything.** Investigate the
run first.

The baseline is decision-level rather than a byte dump. Pinning the whole
record would churn on every field added and would teach the next person to
regenerate the file without reading it — at which point the golden has stopped
being a review and become a snapshot.

`inherent` is asserted against **both** this file and `expected-risk.yaml`. The
design review and the risk pipeline score the same register through different
code, and the day they disagree one of them is wrong.
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
import sdr_report  # noqa: E402
import sdr_scope  # noqa: E402

GOLDEN = REPO_ROOT / "golden"

#: Every case that ships an expected design review. Parametrised rather than
#: written twice: a second case is only worth having if it runs the same
#: assertions, and copying them would let the two drift.
#:
#: `movie-rating-aws` is the small one — no critical band, five flows, one
#: third party. `b2b-saas-aws` is the one that exercises what the first cannot:
#: a critical finding, two id tie-breaks at two different scores, and two flows
#: that leave the organisation. A regression in how `critical` aggregates or
#: orders is invisible against the first case alone.
CASES = sorted(
    path.parent.name
    for path in GOLDEN.glob("*/expected-design-review.yaml")
)

#: Pinned, so nothing in the comparison is a function of when it ran.
PINNED_TIMESTAMP = "2026-01-01T00:00:00Z"


def _load(path: Path) -> dict:
    assert path.is_file(), f"{path} is missing; the golden case is incomplete"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _report(case: str) -> dict:
    """One design review of a golden case, through the real assembler."""

    root = GOLDEN / case
    architecture = _load(root / "architecture.yaml")
    documents = {
        "policy": risk_mod.appetite_policy("standard"),
        "threats": _load(root / "threats.yaml"),
        "assessment": _load(root / "risk-assessment.yaml"),
        "requirements": None,
        "evidence": None,
        "architecture": architecture,
    }
    return sdr_report.build_report(
        documents,
        entry={
            "run": {
                "mode": "quick",
                "profile": {"stale_vs_head": False, "unconfirmed_critical_facts": []},
            }
        },
        scope_record=sdr_scope.resolve_scope(copy.deepcopy(architecture), None),
        confirmation=None,
        risk_appetite="standard",
        invocation={"timestamp": PINNED_TIMESTAMP},
        today=None,
    )


@pytest.fixture(params=CASES)
def case(request) -> str:
    return request.param


@pytest.fixture
def report(case) -> dict:
    return _report(case)


@pytest.fixture
def expected(case) -> dict:
    return _load(GOLDEN / case / "expected-design-review.yaml")


def test_more_than_one_case_is_pinned():
    """One golden pins one shape. The rules are general; the data is not."""

    assert len(CASES) >= 2, (
        "a single case cannot exercise a band, a tie-break, or a boundary "
        f"shape it does not contain; pinned cases are {CASES}"
    )


# ---------------------------------------------------------------------------
# The case itself must stay reviewable.
# ---------------------------------------------------------------------------


def test_the_golden_case_ships_an_architecture_to_review(case):
    """Without one there is nothing to score against and no golden to keep."""

    architecture = _load(GOLDEN / case / "architecture.yaml")

    problems = sdr_report.report_problems(
        {
            "threats": _load(GOLDEN / case / "threats.yaml"),
            "architecture": architecture,
            "assessment": _load(GOLDEN / case / "risk-assessment.yaml"),
        },
        scope=None,
        policy=risk_mod.appetite_policy("standard"),
        today=None,
    )

    assert problems == [], (
        "the golden case must review cleanly, or every expectation below is "
        f"pinned against a broken run; got {problems}"
    )


def test_every_threat_resolves_against_the_shipped_architecture(case):
    """The `TB-n` mapping, on real data rather than an invented fixture."""

    import sdr_architecture

    dangling = sdr_architecture.unknown_architecture_refs(
        _load(GOLDEN / case / "threats.yaml"),
        _load(GOLDEN / case / "architecture.yaml"),
    )

    assert dangling == [], (
        "this case's threats reference `TB-1`..`TB-5`, and the architecture "
        "carries those ids as data flows for exactly that reason. A dangling "
        f"reference means the mapping was broken; got {dangling}"
    )


# ---------------------------------------------------------------------------
# The verdict and the aggregate.
# ---------------------------------------------------------------------------


def test_the_verdict_matches_the_hand_reviewed_expectation(report, expected):
    verdict = report["verdict"]

    assert verdict["release_threshold_rating"] == expected["verdict"][
        "release_threshold_rating"
    ]
    assert verdict["exceeds_threshold"] == expected["verdict"]["exceeds_threshold"], (
        "the release decision changed. Overall `high` against a `high` "
        "threshold exceeds it — at or above, not strictly above; got "
        f"{verdict['exceeds_threshold']}"
    )


def test_the_aggregate_matches_the_hand_reviewed_expectation(report, expected):
    inherent = report["verdict"]["inherent"]

    for field in ("overall", "status", "counts", "coverage"):
        assert inherent[field] == expected["inherent"][field], (
            f"`inherent.{field}` moved. Investigate the run before widening "
            f"this expectation; expected {expected['inherent'][field]!r}, got "
            f"{inherent[field]!r}"
        )


def test_the_design_review_and_the_risk_pipeline_agree_on_the_aggregate(case, report):
    """Two paths, one register. The day they disagree, one of them is wrong.

    Skipped where the case ships no `expected-risk.yaml` — not every golden
    was built for the risk pipeline, and asserting against a file that does not
    exist would fail for the wrong reason. Where one exists, it is checked.
    """

    risk_path = GOLDEN / case / "expected-risk.yaml"
    if not risk_path.is_file():
        return
    risk_expected = _load(risk_path)["inherent"]
    inherent = report["verdict"]["inherent"]

    for field in ("overall", "counts", "coverage"):
        assert inherent[field] == risk_expected[field], (
            f"the design review reports `{field}` as {inherent[field]!r} and "
            f"`expected-risk.yaml` says {risk_expected[field]!r}. These score "
            "the same threats through different code; a divergence is a defect "
            "in one of them, not a reason to update this file"
        )


# ---------------------------------------------------------------------------
# The findings, in order. The regression a property test cannot see.
# ---------------------------------------------------------------------------


def test_the_findings_match_the_expectation_in_order_rating_and_score(
    report, expected
):
    actual = [
        {
            "id": finding["id"],
            "rating": finding.get("calculated", {}).get("rating"),
            "score": finding.get("calculated", {}).get("score"),
        }
        for finding in report["findings"]
    ]

    assert actual == expected["findings"], (
        "the findings list changed. §4.3 orders by rating rank, then score "
        "descending, then id — a renderer that re-sorted or an ordering that "
        "reverted to document order changes this list and nothing else, which "
        "is precisely what the property tests cannot see.\n"
        f"expected: {expected['findings']}\nactual:   {actual}"
    )


def test_the_expectation_actually_exercises_the_ordering_rule(expected):
    """A baseline in document order would pin nothing about ordering."""

    findings = expected["findings"]
    scores = [item["score"] for item in findings]

    assert scores == sorted(scores, reverse=True), (
        f"the expected findings are not in descending score order: {scores}"
    )
    assert findings != sorted(findings, key=lambda item: item["id"]), (
        "the expected order is the same as sorting by id, so this baseline "
        "would pass for a renderer that sorts by id — which is the bug §4.3 "
        f"was corrected for; got {[item['id'] for item in findings]}"
    )


# ---------------------------------------------------------------------------
# Scope and disclosure.
# ---------------------------------------------------------------------------


def test_the_scope_record_matches_the_expectation(report, expected):
    scope = report["run"]["scope"]

    assert len(scope["included"]) == expected["scope"]["included"], (
        "the number of reviewed elements changed. Either the architecture "
        "grew, or `resolve_scope` stopped partitioning a kind; got "
        f"{len(scope['included'])} against {expected['scope']['included']}"
    )
    assert len(scope["excluded"]) == expected["scope"]["excluded"]
    assert scope["scope_filter"] == expected["scope"]["filter"]


def test_the_ai_taxonomy_is_absent_for_this_case(report, expected):
    """§8, on real data — and this fixture is the interesting case.

    Its `assumptions` block contains the sentence "No AI, LLM, or retrieval
    component is present in this service". Detection reads ids and names and
    never prose, so that sentence must not trigger the taxonomy. A false
    positive here would be invisible to a unit test using invented data.
    """

    assert expected["disclosure"]["ai_coverage_present"] is False, (
        "fixture check: this case is expected to have no AI component"
    )
    assert "ai_coverage" not in report, (
        "§8: with no AI component the taxonomy is not applied *and not "
        "mentioned*. The key is absent, not empty. This case names AI in its "
        f"assumptions prose, which must not count; the record held "
        f"{sorted(report)}"
    )


def test_the_disclosure_blocks_match_the_expectation(report, expected):
    disclosure = expected["disclosure"]

    assert len(report["untrusted_content"]) == disclosure["untrusted_content"]
    assert len(report["disclosures_blocked"]) == disclosure["disclosures_blocked"]
    assert len(report["limitations"]) == disclosure["limitations"], (
        "a limitation appeared or vanished. A limitation that stops being "
        "emitted is the quietest regression this tool can have: the report "
        "gets shorter and reads as more confident. expected "
        f"{disclosure['limitations']}, got {report['limitations']}"
    )


# ---------------------------------------------------------------------------
# Determinism, over the golden rather than a fixture.
# ---------------------------------------------------------------------------


def test_two_reviews_of_the_golden_case_are_byte_identical(case):
    assert risk_mod.canonical_digest(_report(case)) == risk_mod.canonical_digest(
        _report(case)
    ), (
        "§4.3 / N39: with the timestamp pinned, two reviews of an unchanged "
        "case must digest identically"
    )


def test_the_report_satisfies_its_published_schema(report):
    import sdr_schema

    problems = sdr_schema.validate_report(report)

    assert problems == [], (
        "the golden report must satisfy the contract consumers read it "
        f"against; got {problems}"
    )
