"""N19 / N20 — where a design review's artifacts land, and what the published one says.

Plan of record: `docs/security-design-review-plan.md` §4.1 (the artifact table
and the disclosure classes) and §11.2:

    **N19** Technical report and JSON land under `.security-requirements/`; the
    summary under `docs/security/`. Routing the technical report to
    `docs/security/` raises `UnsafePathError` via the existing
    `preflight_output_paths`.
    **N20** The summary contains no evidence excerpt, repository path,
    attack-path detail, or accepted-risk detail — asserted by pattern.

`test_sdr_artifacts.py` and `test_sdr_runner.py` already assert *which paths* a
run writes. Nothing yet asserts what the published file **says**. A summary
written to the right path with an evidence excerpt inside it is still a leak,
and §4.1 records that `status`, `exception`, `expiry`, threat ids, and
`retired_reason` have each crossed this seam once already — five incidents on
one boundary. Every field named there gets a named regression test below.

How the leak is detected
------------------------

By planting sentinels, not by eyeballing. Each sentinel is a distinctive string
put into an authored document, and each is asserted **twice**: absent from
`docs/security/design-review-summary.md`, and *present* in the sensitive set
under `.security-requirements/`. The pair is the test. "Absent from the summary"
alone is also true of a pipeline that wrote nothing, or of a fixture whose
sentinel never reached any artifact — neither of which says anything about the
boundary.

Why the boundary is driven through `sdr_artifacts` and not only `risk.main`
--------------------------------------------------------------------------

The publishable summary is gated on `policy["publish_risk_summary"] is True`.
The runner's policy comes from `risk.appetite_policy(appetite)`, and **all three
shipped appetite files set it `false`** — see
`test_no_shipped_appetite_enables_the_publishable_summary` below, which pins
that fact rather than leaving it as a surprise. So no invocation of `risk.main`
can produce a published summary today, and N20 has to build the report through
the same `sdr_report.build_report` the runner uses and hand it to the real
`sdr_artifacts.artifact_entries`/`write_artifacts` with a policy that opts in.
The bytes asserted below are bytes written to disk by
`risk._write_text_transaction` at the real publish path.

Two results worth reading before the tests
------------------------------------------

**One test here is deliberately red: `findings[].evidence` has no producer.**
`test_the_published_summary_contains_no_evidence_excerpt` fails on its *paired*
half, never on its leaking half. §4.2 declares an `evidence` block of
`{kind, location, excerpt}` on every finding — repository evidence that the
threat exists — and nothing anywhere collects one. The summary is clean, but it
is clean because no excerpt reaches any artifact, so the absence proves nothing.

This is **not** a matter of reading `risk-evidence.yaml`. That document is
*implementation* evidence that a **requirement** is met — a test run, an
observation date, an artifact digest, a `requirement_digest`. §4.2's block is
*repository* evidence that a **threat** exists — a file, a position, the line of
source showing the defect. Wiring the former in would not produce the latter. The
block has no producer, the same shape of gap as `architecture.yaml` before §4.2's
fourteenth correction of record named a file for it.

`findings[].treatment` was in exactly this state when these tests were written —
`_finding` emitted no `treatment` key, so `render_register`'s Owner, Treatment,
Acceptance and Expiry rows printed "not recorded" for every finding in every run.
`_finding` now carries `treatment`, `residual` and `owner` from the assessment
record, so the two tests below that cover it are green and are live regression
guards. `Attack path` remains an unfilled register row, read off a `attack_path`
key the §4.2 finding does not carry.

**N19's second sentence does not hold.**
`preflight_output_paths` is a containment check — it refuses an escape, a parent
segment and a symlink, and it accepts *any* contained path, including
`docs/security/design-review.md`. Nothing in `safe_paths` knows about the
sensitive/publishable split, so routing is asserted structurally on the entry set
instead. See `test_the_containment_check_does_not_by_itself_refuse_a_misrouted_report`.

Fixtures are local to this file by house convention: `tests/risk_helpers.py` and
`tests/conftest.py` are shared and are not depended on here.
"""

from __future__ import annotations

from datetime import date
import json
from pathlib import Path
import re
import shutil
import sys

import pytest
import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
PLUGIN_ROOT = REPO_ROOT / "plugins" / "security-requirements"
PLUGIN_SCRIPTS = PLUGIN_ROOT / "scripts"
if str(PLUGIN_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(PLUGIN_SCRIPTS))

import risk as risk_mod  # noqa: E402
import safe_paths  # noqa: E402
import sdr_artifacts  # noqa: E402
import sdr_entry  # noqa: E402
import sdr_report  # noqa: E402
import sdr_scope  # noqa: E402

GOLDEN_CASE = REPO_ROOT / "golden" / "movie-rating-aws"

STORE_DIRNAME = ".security-requirements"
PUBLISH_DIRNAME = Path("docs") / "security"

REPORT_ARTIFACT = "design-review.md"
JSON_ARTIFACT = "design-review.json"
SUMMARY_ARTIFACT = "design-review-summary.md"

#: `--confirmed-at`, so nothing here reads a clock (§4.3).
PINNED_STAMP = "2026-05-01T00:00:00Z"
PINNED_TODAY = date(2026, 5, 1)


# ---------------------------------------------------------------------------
# Sentinels. Each one is planted in an authored document, travels into the
# sensitive set, and must not reach the published summary.
#
# Deliberately unguessable substrings: a short word like "expiry" appears in
# ordinary prose, so an assertion on it would fail for reasons that are not
# leaks. Each also carries the shape of the thing it stands for, so a leak of
# the *shape* without the token still trips the pattern assertions below.
# ---------------------------------------------------------------------------

#: A repository path, in the place a design review really learns one: the
#: `code_grep` verification target of a managed requirement. Shaped like §4.2's
#: own evidence location (`services/checkout/src/api/orders.ts:42-58`) so it
#: carries all four shapes `PATH_SHAPED_PATTERNS` looks for at once — a
#: `services/` prefix, a `src/` segment, a source-file name, and a position.
SENTINEL_REPO_PATH = "services/checkout/src/api/zqx7pay.py:42:9"

#: The architecture's answer to "where does the data live" — a component name.
#: `render_register` embeds the Mermaid DFD and no other document does.
SENTINEL_COMPONENT = "cmp-zqx7-ledger-writer"

#: An evidence excerpt: the artifact location and the observed text of one
#: implementation-evidence record.
SENTINEL_EVIDENCE_LOCATION = "ci/run/zqx7-evidence-artifact"
SENTINEL_EVIDENCE_EXCERPT = "zqx7 excerpt: assert response.status_code == 401"

#: Attack-path detail: the human-written title of a cross-threat path.
SENTINEL_ATTACK_PATH = "zqx7 chain: anonymous write then credential theft"

#: Accepted-risk detail on the *requirement* side. `human` is the internal
#: record: `human.status` is one of `accepted_risk`/`exception`,
#: `human.exception` is a mapping of approver, role, authority, expires and
#: rationale, and `human.retired_reason` is the account of a retirement. These
#: are the fields `render.py`'s boundary comment is written about.
SENTINEL_ACCEPTED_STATUS = "accepted_risk"
SENTINEL_EXCEPTION = "zqx7 exception: signed off pending Q3 platform work"
SENTINEL_EXCEPTION_EXPIRES = "2027-09-30"
SENTINEL_RETIRED_REASON = "zqx7 retired: superseded by the zqx7 gateway policy"

#: Accepted-risk detail on the *threat* side: an assessment record whose
#: treatment strategy is `accept`, with the approval block `validate_treatment`
#: requires. `render_register` renders Owner, Treatment, Acceptance and Expiry
#: rows from exactly this block.
SENTINEL_ACCEPTANCE_OWNER = "zqx7 platform risk owner"
SENTINEL_ACCEPTANCE_APPROVER = "zqx7 approver"
SENTINEL_ACCEPTANCE_RATIONALE = (
    "zqx7 acceptance: carried until the zqx7 gateway ships"
)
SENTINEL_ACCEPTANCE_EXPIRES = "2027-11-15"

#: A threat id. §4.1 names threat ids as a field that has already crossed.
SENTINEL_THREAT_ID = "T-09"

#: Path-shaped things a publishable document must never contain, N20's first
#: bullet. `line:column` is spelled as a pair of integers after a colon, which
#: is how every tool this project shells out to prints one.
PATH_SHAPED_PATTERNS = (
    (r"(?<![\w.])src/[\w./-]+", "a `src/...` repository path"),
    (r"(?<![\w.])services/[\w./-]+", "a `services/...` repository path"),
    (r"[\w./-]+\.(?:py|ts|tsx|js|yaml|yml|json)\b", "a source-file name"),
    (r"\b\d+:\d+\b", "a `line:column` position"),
)


# ---------------------------------------------------------------------------
# Fixture. A repository with a complete store, built here rather than imported:
# `tests/risk_helpers.py`, `tests/conftest.py` and `test_sdr_runner.py` are
# other files' fixtures and this one plants sentinels they must not carry.
# ---------------------------------------------------------------------------


def _architecture(threats: dict) -> dict:
    """The modelled system, carrying the component-name sentinel.

    Boundary ids are the golden threat document's own (`TB-n`). A fixture using
    §4.2's `tb-internet` spelling would leave every threat dangling and the run
    would be measuring that mismatch rather than the publish boundary.
    """

    boundaries = [
        {
            "id": record["id"],
            "name": f"{record.get('from')} -> {record.get('to')}",
            "evidence_status": "inferred",
        }
        for record in threats.get("boundaries", [])
    ]
    first_boundary = boundaries[0]["id"] if boundaries else None
    return {
        "version": "0.1.0",
        "trust_boundaries": boundaries,
        "actors": [
            {
                "id": "act-anonymous",
                "name": "anonymous internet user",
                "evidence_status": "inferred",
            }
        ],
        "components": [
            {
                "id": SENTINEL_COMPONENT,
                "name": SENTINEL_COMPONENT,
                "trust_boundary": first_boundary,
                "evidence_status": "inferred",
            }
        ],
        "data_stores": [
            {
                "id": "ds-zqx7-ledger",
                "name": "zqx7 ledger table",
                "evidence_status": "inferred",
            }
        ],
        "data_flows": [
            {
                "id": "df-zqx7-write",
                "from": "act-anonymous",
                "to": SENTINEL_COMPONENT,
                "protocol": "https",
                "crosses": first_boundary,
                "evidence_status": "inferred",
            }
        ],
        "assets": [],
        "dependencies": [],
    }


def _requirements() -> dict:
    """One managed requirement carrying the five fields §4.1 says have leaked.

    `human` is the internal record — `render.py`'s boundary comment is about
    exactly this block: status, exception, expiry and retired_reason each
    crossed into a published document once. `verification.target` is where a
    repository path legitimately lives.
    """

    managed = {
        "statement": "checkout-api MUST reject unauthenticated writes.",
        "verification": {
            "method": "code_grep",
            "target": SENTINEL_REPO_PATH,
            "expect": "an authorizer on every mutating route",
        },
    }
    return {
        "version": "0.1.0",
        "requirements": [
            {
                "id": "REQ-1",
                "statement": managed["statement"],
                "rationale": "Unauthenticated write across the internet boundary.",
                "sources": ["AC-3"],
                "responsibility": "team",
                "priority": "high",
                "threat_refs": ["T-01"],
                "managed": managed,
                "verification": managed["verification"],
                "human": {
                    "status": SENTINEL_ACCEPTED_STATUS,
                    "retired_reason": SENTINEL_RETIRED_REASON,
                    "exception": {
                        "approver": SENTINEL_ACCEPTANCE_APPROVER,
                        "role": "zqx7 head of platform",
                        "authority": "self_declared",
                        "expires": SENTINEL_EXCEPTION_EXPIRES,
                        "rationale": SENTINEL_EXCEPTION,
                    },
                },
            }
        ],
    }


def _evidence(requirements: dict) -> dict:
    """One valid, unexpired evidence record carrying an excerpt sentinel.

    Valid on purpose: an invalid record produces an evidence problem, and a run
    that reported a problem would be testing `output_allowed` rather than the
    publish boundary.
    """

    managed = requirements["requirements"][0]["managed"]
    return {
        "version": "0.1.0",
        "evidence": [
            {
                "id": "EV-1",
                "requirement_id": "REQ-1",
                "method": "code_grep",
                "result": "pass",
                "observed_at": "2026-04-01T00:00:00Z",
                "observed_by": "ci",
                "note": SENTINEL_EVIDENCE_EXCERPT,
                "artifact": {
                    "kind": "code_grep",
                    "location": SENTINEL_EVIDENCE_LOCATION,
                    "excerpt": SENTINEL_EVIDENCE_EXCERPT,
                    "digest": risk_mod.canonical_digest({"run": "zqx7"}),
                },
                "requirement_digest": risk_mod.canonical_digest(managed),
                "valid_until": "2027-01-01",
            }
        ],
    }


def _accept_the_first_risk(assessment: dict) -> dict:
    """Turn one golden assessment into an accepted risk with a real approval.

    `validate_treatment` requires an owner and an approval carrying approver,
    role, rationale, expires and a known authority, and refuses an expiry in the
    past — so this is the shape an operator would actually author, not a stub
    that would be reported as a problem before it could be published.
    """

    records = assessment["assessments"]
    records[0]["treatment"] = {
        "strategy": "accept",
        "owner": SENTINEL_ACCEPTANCE_OWNER,
        "approval": {
            "approver": SENTINEL_ACCEPTANCE_APPROVER,
            "role": "zqx7 head of platform",
            "rationale": SENTINEL_ACCEPTANCE_RATIONALE,
            "expires": SENTINEL_ACCEPTANCE_EXPIRES,
            "authority": "self_declared",
        },
    }
    return assessment


def _attack_paths() -> dict:
    return {
        "version": "0.1.0",
        "attack_paths": [
            {
                "id": "AP-1",
                "title": SENTINEL_ATTACK_PATH,
                "steps": ["T-01", "T-02"],
            }
        ],
    }


@pytest.fixture
def project(tmp_path: Path) -> Path:
    """A repository with a complete store, every sentinel planted."""

    root = tmp_path / "inspected project"
    store = root / STORE_DIRNAME
    store.mkdir(parents=True)
    for name in (
        "profile.yaml",
        "threats.yaml",
        "risk-assessment.yaml",
        "risk-state.yaml",
    ):
        shutil.copyfile(GOLDEN_CASE / name, store / name)
    shutil.copyfile(
        PLUGIN_ROOT / "risk" / "default-policy.yaml", store / "risk-policy.yaml"
    )

    threats = yaml.safe_load((store / "threats.yaml").read_text(encoding="utf-8"))
    assessment = yaml.safe_load(
        (store / "risk-assessment.yaml").read_text(encoding="utf-8")
    )
    (store / "risk-assessment.yaml").write_text(
        yaml.safe_dump(_accept_the_first_risk(assessment), sort_keys=True),
        encoding="utf-8",
    )

    requirements = _requirements()
    documents = {
        "architecture.yaml": _architecture(threats),
        "requirements.yaml": requirements,
        "risk-evidence.yaml": _evidence(requirements),
        "attack-paths.yaml": _attack_paths(),
    }
    for name, document in documents.items():
        (store / name).write_text(
            yaml.safe_dump(document, sort_keys=True), encoding="utf-8"
        )
    return root


def _publishing_policy() -> dict:
    """The standard appetite, with the publish opt-in §4.1 requires turned on.

    Not a hand-written policy: `render_public_summary` and `build_report` both
    read fields the real policy carries, and a stub would let the summary pass
    for a shape the runner never produces.
    """

    policy = risk_mod.appetite_policy("standard")
    policy["publish_risk_summary"] = True
    return policy


def _documents(project_root: Path, policy: dict) -> dict:
    store = project_root / STORE_DIRNAME
    documents: dict = {"policy": policy}
    for name, filename in risk_mod.DESIGN_REVIEW_DOCUMENTS.items():
        path = store / filename
        documents[name] = (
            yaml.safe_load(path.read_text(encoding="utf-8")) if path.is_file() else None
        )
    return documents


def _report(project_root: Path, policy: dict) -> dict:
    """The §4.2 record, assembled exactly as `_run_design_review` assembles it."""

    documents = _documents(project_root, policy)
    problems = sdr_report.report_problems(
        documents, scope=None, policy=policy, today=PINNED_TODAY
    )
    evidence_problems = risk_mod.validate_evidence(
        documents["evidence"], documents.get("requirements"), PINNED_TODAY
    )
    assert problems == [] and evidence_problems == [], (
        "the fixture store must be clean, or these tests measure `output_allowed` "
        "rather than the publish boundary; problems were "
        f"{problems} and evidence problems {evidence_problems}"
    )
    return sdr_report.build_report(
        documents,
        entry=sdr_entry.design_review(project_root, mode=sdr_entry.DEFAULT_MODE),
        scope_record=sdr_scope.resolve_scope(documents.get("architecture"), None),
        confirmation={"status": "confirmed"},
        risk_appetite="standard",
        invocation={
            "plugin_version": None,
            "command": "design-review-confirm",
            "timestamp": PINNED_STAMP,
        },
        today=PINNED_TODAY,
    )


@pytest.fixture
def published(project: Path) -> dict[str, str]:
    """Run the confirmed artifact set to disk and return each document's text.

    Written through the real `write_artifacts`, so the bytes read back are the
    bytes `risk._write_text_transaction` put at the real publish path.
    """

    policy = _publishing_policy()
    entries = sdr_artifacts.artifact_entries(
        _report(project, policy),
        project_root=project,
        output_root=project,
        policy=policy,
        confirmed=True,
        problems=[],
        evidence_problems=[],
    )
    sdr_artifacts.write_artifacts(entries)

    summary_path = project / PUBLISH_DIRNAME / SUMMARY_ARTIFACT
    report_path = project / STORE_DIRNAME / REPORT_ARTIFACT
    json_path = project / STORE_DIRNAME / JSON_ARTIFACT
    for path in (summary_path, report_path, json_path):
        assert path.is_file(), (
            "§4.1: a confirmed run with `publish_risk_summary: true` writes the "
            f"technical report, the JSON record and the summary; {path} is missing "
            f"and the tree held {sorted(p.name for p in project.rglob('*') if p.is_file())}"
        )
    return {
        "summary": summary_path.read_text(encoding="utf-8"),
        "report": report_path.read_text(encoding="utf-8"),
        "json": json_path.read_text(encoding="utf-8"),
    }


def _sensitive(published: dict[str, str]) -> str:
    """The whole sensitive set as one string.

    §4.1 classifies by *tree*, not by file: `design-review.md` and
    `design-review.json` are both sensitive and both live under
    `.security-requirements/`. A sentinel that reaches either has been shown to
    travel, which is all the paired assertion needs.
    """

    return published["report"] + "\n" + published["json"]


def _bind_a_real_confirmation(project_root: Path) -> None:
    """Stamp a genuine digest-bound assessment confirmation for this store.

    Not a file planted at the state path: `design-review-confirm` runs
    `check_assessment`, which verifies `policy_digest`, `threat_digest`,
    `assessment_digest` and `risk_state_digest` against the documents on disk.
    A planted record is exactly what N28 forbids, so this drives the real
    `policy-confirm` → `confirm` pair the operator would run.
    """

    store = project_root / STORE_DIRNAME
    common = ["--project-root", str(project_root), "--policy", str(store / "risk-policy.yaml")]
    identity = ["--by", "risk owner", "--authority", "self_declared"]

    policy_exit = risk_mod.main(["policy-confirm", *common, *identity])
    assert policy_exit == 0, (
        "the fixture policy must confirm before the assessment can bind to it; "
        f"`policy-confirm` exited {policy_exit}"
    )
    confirm_exit = risk_mod.main(
        [
            "confirm",
            *common,
            "--threats", str(store / "threats.yaml"),
            "--assessment", str(store / "risk-assessment.yaml"),
            "--requirements", str(store / "requirements.yaml"),
            "--evidence", str(store / "risk-evidence.yaml"),
            "--state", str(store / "risk-state.yaml"),
            *identity,
        ]
    )
    assert confirm_exit == 0, (
        "the fixture store must produce a digest-bound assessment confirmation, "
        f"or the design review under test is refused for the wrong reason; "
        f"`confirm` exited {confirm_exit}"
    )


def _relative(entries, root: Path) -> list[str]:
    return [
        Path(path).resolve().relative_to(root.resolve()).as_posix()
        for path, _root, _content, _create in entries
    ]


# ---------------------------------------------------------------------------
# N19 — routing. Sensitive under `.security-requirements/`, publishable under
# `docs/security/`.
# ---------------------------------------------------------------------------


def test_the_technical_report_and_the_json_record_land_in_the_sensitive_tree(project):
    policy = _publishing_policy()
    entries = sdr_artifacts.artifact_entries(
        _report(project, policy),
        project_root=project,
        output_root=project,
        policy=policy,
        confirmed=True,
    )

    written = _relative(entries, project)
    for name in (REPORT_ARTIFACT, JSON_ARTIFACT):
        assert f"{STORE_DIRNAME}/{name}" in written, (
            f"N19: {name} is sensitive and belongs under {STORE_DIRNAME}/; "
            f"the run wrote {written}"
        )


def test_the_publishable_summary_lands_in_the_publishable_tree(project):
    policy = _publishing_policy()
    entries = sdr_artifacts.artifact_entries(
        _report(project, policy),
        project_root=project,
        output_root=project,
        policy=policy,
        confirmed=True,
    )

    written = _relative(entries, project)
    expected = (PUBLISH_DIRNAME / SUMMARY_ARTIFACT).as_posix()
    assert expected in written, (
        f"N19: the summary is the only publishable artifact and belongs at "
        f"{expected}; the run wrote {written}"
    )


def test_no_sensitive_artifact_is_routed_into_the_publishable_tree(project):
    policy = _publishing_policy()
    entries = sdr_artifacts.artifact_entries(
        _report(project, policy),
        project_root=project,
        output_root=project,
        policy=policy,
        confirmed=True,
    )

    published_tree = PUBLISH_DIRNAME.as_posix()
    misrouted = [
        path
        for path in _relative(entries, project)
        if path.startswith(f"{published_tree}/")
        and Path(path).name != SUMMARY_ARTIFACT
    ]
    assert misrouted == [], (
        "N19: only the summary may be written under "
        f"{published_tree}/. Routing the technical report or the JSON record "
        "there publishes the whole review; found "
        f"{misrouted}"
    )


def test_no_publishable_artifact_is_routed_into_the_sensitive_tree(project):
    policy = _publishing_policy()
    entries = sdr_artifacts.artifact_entries(
        _report(project, policy),
        project_root=project,
        output_root=project,
        policy=policy,
        confirmed=True,
    )

    misrouted = [
        path
        for path in _relative(entries, project)
        if path.startswith(f"{STORE_DIRNAME}/")
        and Path(path).name == SUMMARY_ARTIFACT
    ]
    assert misrouted == [], (
        f"N19: {SUMMARY_ARTIFACT} is the publishable artifact and belongs under "
        f"{PUBLISH_DIRNAME.as_posix()}/. Filing it in the sensitive tree makes it "
        f"invisible to whoever publishes; found {misrouted}"
    )


def test_the_runner_files_the_confirmed_artifacts_under_the_sensitive_tree(
    project, monkeypatch, tmp_path
):
    """The same routing, end to end through `risk.main`.

    A trusted confirmation is plugin-owned state held outside the repository;
    `SECURITY_REQUIREMENTS_DATA` is the documented way to relocate that root, so
    the test binds one without reaching outside `tmp_path`.
    """

    monkeypatch.setenv("SECURITY_REQUIREMENTS_DATA", str(tmp_path / "plugin state"))
    _bind_a_real_confirmation(project)

    exit_code = risk_mod.main(
        [
            "design-review-confirm",
            "--project-root",
            str(project),
            "--output",
            str(project),
            "--confirmed-at",
            PINNED_STAMP,
            "--by",
            "test",
            "--authority",
            "self_declared",
        ]
    )

    assert exit_code == 0, (
        f"§3: the fixture store is complete, so a confirmed run exits 0; got {exit_code}"
    )
    for name in (REPORT_ARTIFACT, JSON_ARTIFACT):
        assert (project / STORE_DIRNAME / name).is_file(), (
            f"N19: the runner files {name} under {STORE_DIRNAME}/; the tree held "
            f"{sorted(p.relative_to(project).as_posix() for p in project.rglob('*') if p.is_file())}"
        )
    assert not (project / PUBLISH_DIRNAME / REPORT_ARTIFACT).exists(), (
        f"N19: {REPORT_ARTIFACT} is sensitive and must never appear under "
        f"{PUBLISH_DIRNAME.as_posix()}/"
    )


def test_no_shipped_appetite_enables_the_publishable_summary():
    """Why N20 is exercised through `sdr_artifacts` rather than `risk.main`.

    §5.5 makes `publish_risk_summary` appetite policy data, and the runner's
    policy is `appetite_policy(--risk-appetite)` alone — the store's
    `risk-policy.yaml` is never consulted by `design-review`. With every shipped
    appetite set `false`, `docs/security/design-review-summary.md` is
    unreachable from the command line. Pinned so the day one appetite opts in,
    this test says so and the boundary tests below become reachable end to end.
    """

    enabled = sorted(
        name
        for name in risk_mod.RISK_APPETITES
        if risk_mod.appetite_policy(name).get("publish_risk_summary") is True
    )
    assert enabled == [], (
        "if an appetite now enables publishing, the runner can publish and N20 "
        "must be asserted over `risk.main`'s output as well as over "
        f"`artifact_entries`; appetites enabling it: {enabled}"
    )


# ---------------------------------------------------------------------------
# N19, second clause — what `preflight_output_paths` actually refuses.
#
# The plan says routing the technical report to `docs/security/` "raises
# `UnsafePathError` via the existing `preflight_output_paths`". It does not:
# `safe_paths.safe_path` is a *containment* check. It refuses a path that
# escapes the project root, a parent segment, and a symlink or junction on the
# way in. `docs/security/design-review.md` is inside the project root and is
# accepted. The tests below pin what the function really enforces, and the
# routing invariant N19 is actually about is asserted structurally above.
# ---------------------------------------------------------------------------


def test_the_containment_check_refuses_a_path_that_escapes_the_project(project):
    escaping = project.parent / "elsewhere" / REPORT_ARTIFACT

    with pytest.raises(safe_paths.UnsafePathError):
        safe_paths.preflight_output_paths([escaping], project_root=project)


def test_the_containment_check_refuses_a_parent_segment(project):
    with pytest.raises(safe_paths.UnsafePathError):
        safe_paths.preflight_output_paths(
            [project / PUBLISH_DIRNAME / ".." / ".." / REPORT_ARTIFACT],
            project_root=project,
        )


def test_the_containment_check_refuses_a_symlinked_publishable_tree(project):
    outside = project.parent / "outside docs"
    outside.mkdir(parents=True, exist_ok=True)
    (project / "docs").mkdir(parents=True, exist_ok=True)
    try:
        (project / PUBLISH_DIRNAME).symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:  # pragma: no cover
        pytest.fail(f"the fixture could not create a symlink to test against: {exc}")

    with pytest.raises(safe_paths.UnsafePathError):
        safe_paths.preflight_output_paths(
            [project / PUBLISH_DIRNAME / SUMMARY_ARTIFACT], project_root=project
        )


def test_the_containment_check_does_not_by_itself_refuse_a_misrouted_report(project):
    """Plan correction, recorded as a test rather than as a comment.

    N19 attributes the refusal of a misrouted technical report to
    `preflight_output_paths`. That function decides *containment*, not
    *disclosure class*: it cannot tell `design-review.md` from
    `design-review-summary.md`, and both are inside the project root. Nothing in
    `safe_paths` knows about the sensitive/publishable split, so the routing
    invariant has to be — and is — asserted on the entry set that
    `artifact_entries` returns.

    If a disclosure-class check is ever added to `safe_paths`, this test is the
    one that fails, and N19's sentence becomes true.
    """

    misrouted = project / PUBLISH_DIRNAME / REPORT_ARTIFACT
    (project / PUBLISH_DIRNAME).mkdir(parents=True, exist_ok=True)

    validated = safe_paths.preflight_output_paths([misrouted], project_root=project)

    assert validated == [misrouted], (
        "`preflight_output_paths` is a containment check and accepts any "
        "contained path, including a sensitive artifact filed in the "
        "publishable tree. N19 says it raises `UnsafePathError` here; it does "
        f"not, and the plan sentence needs correcting. It returned {validated}"
    )


# ---------------------------------------------------------------------------
# N20 — the published summary carries no internal detail.
#
# Every assertion below is a pair: absent from the summary, present in the
# sensitive set. Without the second half the test also passes when the pipeline
# writes nothing, or when the sentinel never entered the run at all.
# ---------------------------------------------------------------------------


def test_the_published_summary_is_not_empty(published):
    """The floor every other N20 assertion rests on."""

    assert published["summary"].strip(), (
        "an empty published file would satisfy every 'does not contain' "
        "assertion below while telling us nothing about the boundary"
    )


def test_the_published_summary_contains_no_repository_path(published):
    assert SENTINEL_REPO_PATH not in published["summary"], (
        "N20: the summary carries no repository path. "
        f"{SENTINEL_REPO_PATH!r} is a managed requirement's `code_grep` target "
        "and reached the published document"
    )
    assert SENTINEL_REPO_PATH in _sensitive(published), (
        "the repository-path sentinel must be shown to travel into the "
        "sensitive set, or its absence from the summary proves nothing about "
        f"the boundary; {SENTINEL_REPO_PATH!r} reached neither document"
    )


def test_the_published_summary_contains_nothing_path_shaped(published):
    for pattern, description in PATH_SHAPED_PATTERNS:
        found = re.findall(pattern, published["summary"])
        assert found == [], (
            f"N20: the summary must contain no path-shaped string; it contains "
            f"{description}: {found}"
        )


def test_the_path_shaped_patterns_match_the_sensitive_set(published):
    """The detector's own test. A pattern that matches nothing proves nothing.

    The sensitive set genuinely holds repository paths and source-file names, so
    each pattern must fire here. A pattern that has silently stopped matching —
    a bad escape, a `(?<!...)` that swallowed every case — would make the
    assertion above vacuous, which is the failure mode of every
    absence-asserting test.
    """

    sensitive = _sensitive(published)
    silent = [
        description
        for pattern, description in PATH_SHAPED_PATTERNS
        if not re.search(pattern, sensitive)
    ]
    assert silent == [], (
        "every path pattern must be shown to match something in the sensitive "
        "set, or its absence from the summary is a property of the regex rather "
        f"than of the document; these matched nothing: {silent}"
    )


def test_the_published_summary_contains_no_evidence_excerpt(published):
    """RED, and the red half is the *sensitive* half. `findings[].evidence` has
    no producer.

    §4.2 gives every finding an `evidence` block —
    `[{"kind": "repo", "location": "services/checkout/src/api/orders.ts:42-58",
    "excerpt": "router.post('/orders/:id', updateOrder)  // no auth middleware"}]`
    — the excerpt-and-location pair this boundary must never publish. Nothing
    emits it. `_finding` has no `evidence` key and `render_register`'s
    `Evidence` row prints "not recorded" for every finding in every run.

    **This is not a wiring job on `risk-evidence.yaml`, and reading that document
    would not produce it.** The two are different kinds of evidence:
    `risk-evidence.yaml` is *implementation* evidence that a **requirement** is
    met — a test run, an observation date, an artifact digest, a
    `requirement_digest` binding it to the requirement it satisfies. §4.2's block
    is *repository* evidence that a **threat** exists — a file, a position in it,
    and the line of source that shows the defect. No repository evidence is
    collected anywhere in this pipeline, by any module, from any document. The
    block has no producer, the same shape of gap as `architecture.yaml` before
    §4.2's fourteenth correction of record named a file for it.

    So the summary does not publish an excerpt only because the run never has
    one. Asserting the absent half alone would bank a passing boundary test for a
    pipeline with nothing to leak. Left red deliberately.

    What turns it green: a producer for `findings[].evidence` — the design review
    records where in the repository it saw the threat — and `_register_summary`
    passing the block through so the `Evidence` row renders. This test then
    becomes a live guard on that excerpt never being published.

    The sentinel below is planted in `risk-evidence.yaml` because that is the
    only evidence document the store has. It is the *wrong* document for this
    field, and that is the finding.
    """

    for sentinel in (SENTINEL_EVIDENCE_LOCATION, SENTINEL_EVIDENCE_EXCERPT):
        assert sentinel not in published["summary"], (
            f"N20: the summary carries no evidence excerpt; {sentinel!r} reached "
            "the published document"
        )
    assert SENTINEL_EVIDENCE_EXCERPT in _sensitive(published), (
        "§4.2's `findings[].evidence` block — `{kind, location, excerpt}`, "
        "repository evidence that the threat exists — has no producer. No "
        "module collects a repo excerpt from any document, so the register's "
        "`Evidence` row is always 'not recorded'. Note this is NOT a matter of "
        "reading `risk-evidence.yaml`: that document is implementation evidence "
        "that a *requirement* is met and carries no repository excerpt to give. "
        f"{SENTINEL_EVIDENCE_EXCERPT!r} is in the store and in neither artifact, "
        "so the assertion above passes for a pipeline with no excerpt to leak "
        "rather than for a boundary that refuses one"
    )


def test_the_published_summary_contains_no_criterion_evidence(published):
    """The evidence material that *does* travel today, paired both ways.

    `proposed.likelihood.evidence` is the assessment's own evidence block —
    exposure, access required, exploit complexity, preconditions, observed
    controls. `_finding` copies `proposed` wholesale, so it reaches the JSON
    record and the register's Criteria and Rationale rows. Until the §4.2
    `evidence` block above exists, this is the only evidence material the
    boundary can actually be tested against.
    """

    criterion_evidence = "deployment artifact or developer workspace"

    assert criterion_evidence not in published["summary"], (
        f"N20: {criterion_evidence!r} is the likelihood criterion's evidence — "
        "how exposed the thing is and what an attacker needs. It reached the "
        "published document"
    )
    assert criterion_evidence in _sensitive(published), (
        "the criterion-evidence sentinel must be shown to travel into the "
        f"sensitive set; {criterion_evidence!r} reached no artifact and the "
        "fixture has drifted from `golden/movie-rating-aws/risk-assessment.yaml`"
    )


def test_the_published_summary_contains_no_attack_path_detail(published):
    assert SENTINEL_ATTACK_PATH not in published["summary"], (
        f"N20: the summary carries no attack-path detail; {SENTINEL_ATTACK_PATH!r} "
        "is a cross-threat path title and reached the published document"
    )
    assert SENTINEL_ATTACK_PATH in _sensitive(published), (
        "the attack-path sentinel must be shown to travel into the sensitive "
        f"set; {SENTINEL_ATTACK_PATH!r} reached no artifact"
    )


def test_the_published_summary_contains_no_accepted_risk_detail(published):
    """The requirement side of an accepted risk: `human.exception`."""

    assert SENTINEL_EXCEPTION not in published["summary"], (
        f"N20: the summary carries no accepted-risk detail; {SENTINEL_EXCEPTION!r} "
        "is the rationale on a managed requirement's internal exception and "
        "reached the published document"
    )
    assert SENTINEL_EXCEPTION in _sensitive(published), (
        "the accepted-risk sentinel must be shown to travel into the sensitive "
        f"set; {SENTINEL_EXCEPTION!r} reached no artifact"
    )


def test_the_published_summary_contains_no_treatment_or_acceptance_detail(published):
    """The threat side of an accepted risk: `treatment.approval`.

    §4.2 declares `treatment` on every finding, and `render_register` renders
    four rows straight off it — Owner from `treatment.owner`, Treatment from
    `treatment.strategy`, Acceptance from `treatment.approval`, Expiry from
    `treatment.approval.expires`. This fixture's first assessment record carries
    a fully valid `strategy: accept` with an approval `validate_treatment`
    accepts, so all four have something real to render.

    Written red: `_finding` emitted no `treatment` key, so every one of those
    rows printed "not recorded" (Acceptance printed `{}`) for every finding in
    every run, and the absence half below was vacuous. `_finding` now carries
    `treatment`, `residual` and `owner` from the assessment record, so the pair
    holds and this is a live guard. If a future change drops that carry, the
    *second* assertion fails and says so rather than this test quietly going
    green-for-nothing.
    """

    for sentinel in (
        SENTINEL_ACCEPTANCE_OWNER,
        SENTINEL_ACCEPTANCE_APPROVER,
        SENTINEL_ACCEPTANCE_RATIONALE,
    ):
        assert sentinel not in published["summary"], (
            f"N20: the summary carries no accepted-risk detail; {sentinel!r} is "
            "part of a threat's acceptance approval and reached the published "
            "document"
        )
    assert SENTINEL_ACCEPTANCE_RATIONALE in _sensitive(published), (
        "the finding `treatment` block §4.2 declares has no producer: "
        "`sdr_report._finding` emits no `treatment` key, so the register's "
        "Owner, Treatment, Acceptance and Expiry rows print 'not recorded' for "
        "every finding even when the assessment record carries a valid accepted "
        f"risk. {SENTINEL_ACCEPTANCE_RATIONALE!r} is in "
        "`risk-assessment.yaml` and in neither artifact, so the assertion above "
        "passes for a pipeline with no acceptance to leak"
    )


def test_the_published_summary_contains_no_component_or_data_store_name(published):
    """The DFD names components, stores and internal boundaries.

    `render_register` embeds it and `render_public_summary` must never grow an
    equivalent block — that is the "where does the data live" answer the publish
    boundary exists to refuse.
    """

    assert SENTINEL_COMPONENT not in published["summary"], (
        f"N20: {SENTINEL_COMPONENT!r} is an architecture component name. The "
        "data-flow diagram reaches the internal register and no other document"
    )
    assert SENTINEL_COMPONENT in published["report"], (
        "the component sentinel must be shown to travel into the internal "
        f"register's Mermaid block; {SENTINEL_COMPONENT!r} is not in "
        f"{REPORT_ARTIFACT}"
    )


def test_the_published_summary_names_no_threat_id(published):
    """§4.1: threat ids have crossed this boundary once already."""

    assert SENTINEL_THREAT_ID not in published["summary"], (
        f"N20: the summary names no threat id; {SENTINEL_THREAT_ID!r} reached the "
        "published document"
    )
    found = re.findall(r"\bT-\d{2,}\b", published["summary"])
    assert found == [], (
        "N20: the summary names no threat id at all — the internal threat "
        f"model's structure is not publishable; it named {sorted(set(found))}"
    )
    assert re.search(r"\bT-\d{2,}\b", _sensitive(published)), (
        "the sensitive set must name threat ids, or the assertion above passes "
        "for a run that scored no threat"
    )


def test_the_published_summary_carries_no_retired_reason(published):
    """§4.1: `retired_reason` has crossed this boundary once already."""

    assert SENTINEL_RETIRED_REASON not in published["summary"], (
        f"N20: {SENTINEL_RETIRED_REASON!r} is `human.retired_reason`, the "
        "internal account of a retirement. The fact of a retirement is public; "
        "the account of it is not"
    )
    assert SENTINEL_RETIRED_REASON in _sensitive(published), (
        "the retired_reason sentinel must be shown to travel into the sensitive "
        f"set; {SENTINEL_RETIRED_REASON!r} reached no artifact"
    )


def test_the_published_summary_carries_no_exception(published):
    """§4.1: `exception` has crossed this boundary once already."""

    assert SENTINEL_EXCEPTION not in published["summary"], (
        f"N20: {SENTINEL_EXCEPTION!r} is an approved exception. Publishing it "
        "tells a reader outside the organisation which control is not in place"
    )
    assert SENTINEL_EXCEPTION in _sensitive(published), (
        f"the exception sentinel must be shown to travel; {SENTINEL_EXCEPTION!r} "
        "reached no artifact"
    )


def test_the_published_summary_carries_no_requirement_exception_expiry(published):
    """§4.1: `expiry` has crossed this boundary once already.

    Half a disclosure is still a disclosure: `status: accepted_risk` says a
    control is not in place and the expiry says until when. `render.py` records
    that the status was removed one commit before the expiry was, and that the
    expiry on its own was still a disclosure.
    """

    assert SENTINEL_EXCEPTION_EXPIRES not in published["summary"], (
        f"N20: {SENTINEL_EXCEPTION_EXPIRES!r} is `human.exception.expires`, the "
        "date a requirement's exception runs out, and it reached the published "
        "document"
    )
    assert SENTINEL_EXCEPTION_EXPIRES in _sensitive(published), (
        "the requirement-expiry sentinel must be shown to travel; "
        f"{SENTINEL_EXCEPTION_EXPIRES!r} reached no artifact"
    )


def test_the_published_summary_carries_no_acceptance_expiry(published):
    """The threat-side expiry: `treatment.approval.expires`.

    Named separately from
    `test_the_published_summary_contains_no_treatment_or_acceptance_detail`
    because §4.1 names `expiry` as its own prior incident, and because "expiry"
    has two halves that travel by different routes — `human.exception.expires`
    on the requirement above, and the acceptance's own `expires` here. Both need
    guarding; a fix to either route leaves the other unwatched.
    """

    assert SENTINEL_ACCEPTANCE_EXPIRES not in published["summary"], (
        f"N20: {SENTINEL_ACCEPTANCE_EXPIRES!r} is the expiry of an accepted risk "
        "and reached the published document"
    )
    assert SENTINEL_ACCEPTANCE_EXPIRES in _sensitive(published), (
        "`treatment.approval.expires` reaches no artifact: `_finding` emits no "
        "`treatment` key, so the register's Expiry row is always 'not recorded'. "
        f"{SENTINEL_ACCEPTANCE_EXPIRES!r} is in `risk-assessment.yaml` and in "
        "neither artifact, so the assertion above passes for a pipeline with no "
        "expiry to leak"
    )


def test_the_published_summary_carries_no_implementation_status(published):
    """§4.1: `status` has crossed this boundary once already."""

    assert SENTINEL_ACCEPTED_STATUS not in published["summary"], (
        f"N20: {SENTINEL_ACCEPTED_STATUS!r} is a requirement's internal "
        "implementation status. Publishing it is the first half of 'which "
        "controls are not implemented, and which risks were accepted until when'"
    )
    assert SENTINEL_ACCEPTED_STATUS in _sensitive(published), (
        f"the status sentinel must be shown to travel; "
        f"{SENTINEL_ACCEPTED_STATUS!r} reached no artifact"
    )


def test_the_published_summary_carries_no_mermaid_diagram(published):
    """The DFD reaches the register and no other document."""

    assert "```mermaid" not in published["summary"], (
        "N20: a data-flow diagram in the published summary answers 'where does "
        "the data live', which is the question this boundary exists to refuse"
    )
    assert "```mermaid" in published["report"], (
        "the internal register embeds the DFD; if it does not, the assertion "
        "above passes for a run that rendered no diagram anywhere"
    )


def test_the_published_summary_is_a_strict_subset_of_what_the_report_publishes(
    published,
):
    """A whitelist, not a blacklist.

    Every previous incident on this seam was a field nobody thought to blacklist.
    `render_public_summary` reads three keys — `overall`, `counts`, `coverage` —
    so the published document's vocabulary is closed and can be pinned as such.
    A line carrying anything else is the sixth incident.
    """

    allowed = {"", "# Public risk summary", "| Measure | Value |", "|---|---|",
               "| Rating | Count |", "|---|---:|"}
    allowed |= {f"## {name}" for name in ("Inherent", "Residual")}

    unexpected = []
    for line in published["summary"].splitlines():
        stripped = line.rstrip()
        if stripped in allowed:
            continue
        if re.fullmatch(r"\| Overall \| [A-Za-z]+ \|", stripped):
            continue
        if re.fullmatch(r"\| Coverage \| \d+/\d+ \|", stripped):
            continue
        if re.fullmatch(r"\| [a-z]+ \| \d+ \|", stripped):
            continue
        unexpected.append(stripped)

    assert unexpected == [], (
        "N20: the published summary's vocabulary is closed — a heading, an "
        "overall rating, a coverage fraction and a count per rating. A line "
        "outside that set is a field that crossed the boundary; found "
        f"{unexpected}"
    )
