"""N21 and N22 — the one-unit write, and the summary that is withheld out loud.

Plan of record: `docs/security-design-review-plan.md` §4.1 (the artifact table
and the one-transaction rule) and §11.2:

    **N21** With `publish_risk_summary: false`, no publishable summary is
    written at all and the run says so.
    **N22** All artifacts go through `_write_text_transaction` as one unit:
    inject a failure on the last write and assert the earlier ones are rolled
    back.

§4.1 states the rule these two notes serve:

    All artifacts in a run are written through `_write_text_transaction` as
    **one unit**. A partial write that leaves a published summary beside a
    missing sensitive report is a disclosure bug, not an inconvenience.

**Why this file exists beside `test_sdr_artifacts.py`.** That file proves
`write_artifacts` makes *exactly one* `_write_text_transaction` call. A call
count is not atomicity: one call that half-succeeds and leaves the debris on
disk satisfies it. N22 asks for the other half — that the earlier writes are
*undone* — and nothing asserted it until now. Every rollback test below reads
the bytes on disk before and after, because "an exception was raised" is also
true of a transaction that raised and kept everything it had written.

`test_sdr_artifacts.py` also owns the "nothing is written" half of N21. This
file owns the other half, at the runner, where the operator is standing: a run
that withholds the publishable summary and prints only its `wrote` lines has
told the reader nothing, and silence about a withheld summary reads as a
summary that was published.

How the failure is injected
---------------------------

`risk._write_text_transaction` reaches disk through the module-global
`risk.safe_write_text`, and so does its rollback. The injector below therefore
keys on *content* as well as target: it refuses the new bytes and lets the
restored prior bytes through, so the rollback path is exercised rather than
sabotaged. Two shapes are injected, because the transaction claims to handle
both:

* **before the replace** — `safe_write_text` is atomic (`os.replace` last), so
  the target still holds its prior bytes when the exception is raised.
* **after the replace** — the writer replaced the file and *then* failed. The
  transaction's own comment says it restores "the entire declared set,
  including a target whose writer replaced the file before raising", which is
  a claim only an after-the-replace injection can test.

What `restore` actually does, read from `risk.py`, not assumed: a target that
did not exist before the run is `unlink`ed; a target that did is rewritten from
the bytes captured before the first write. The tests assert those two
behaviours separately because they are two different code paths.

Where the runner is involved, the confirmation is a real one: `stamp_policy`
and `stamp_assessment` bind it to the store, in a `tmp_path` plugin state root
via `SECURITY_REQUIREMENTS_DATA`. `design-review-confirm` runs
`check_assessment`, and a record planted at the state path is precisely what
that gate exists to reject.

The unit-level rollback tests do not go through the runner at all. They call
`artifact_entries(..., confirmed=True)` directly, because for N22 the
transaction is the subject and the confirmation gate is not: routing them
through `main` would make every rollback assertion depend on a binding that
has nothing to do with whether a failed write is undone.

No clock and no network. `--confirmed-at` and the stamp arguments pin the one
timestamp that reaches a digest.
"""

from __future__ import annotations

import copy
from pathlib import Path
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
import sdr_artifacts  # noqa: E402
from runtime_paths import confirmation_state_path  # noqa: E402

GOLDEN_CASE = REPO_ROOT / "golden" / "movie-rating-aws"

#: `publish.py` `_risk_paths` — the sensitive tree.
STORE_DIRNAME = ".security-requirements"
#: §4.1 — the publishable tree.
PUBLISH_DIRNAME = Path("docs") / "security"

REPORT_ARTIFACT = "design-review.md"
JSON_ARTIFACT = "design-review.json"
PUBLISHABLE_ARTIFACT = "design-review-summary.md"

OK = 0

#: The stamp every run in this file is pinned to.
PINNED_STAMP = "2026-05-01T00:00:00Z"

#: Bytes a prior run left behind, distinctive enough that finding them after a
#: rollback means the rollback restored them rather than never having written.
PRIOR_REPORT = "# Design review\n\nThe report from the run before this one.\n"
PRIOR_SUMMARY = "# Public risk summary\n\nThe summary from the run before this one.\n"


class InjectedWriteFailure(OSError):
    """Raised by the injector, so no real I/O error can be mistaken for it."""


# ---------------------------------------------------------------------------
# Builders. Local to this file on purpose: a shared fixture that another test
# module can retune is a rollback test that silently stops covering the set it
# was written for.
# ---------------------------------------------------------------------------

REPORT = {
    "schema_version": "1.0.0",
    "run": {
        "mode": "quick",
        "confirmed": True,
        "risk_appetite": "standard",
        "scope": {
            "included": ["cmp-checkout-api"],
            "excluded": [],
            "scope_filter": None,
        },
        "profile": {"stale_vs_head": False, "unconfirmed_critical_facts": []},
    },
    "findings": [
        {
            "id": "T-09",
            "calculated": {
                "likelihood": 4,
                "impact": 4,
                "score": 16,
                "rating": "high",
            },
        },
    ],
    "verdict": {
        "release_threshold_rating": "high",
        "exceeds_threshold": True,
        "inherent": {
            "overall": "high",
            "status": "confirmed",
            "counts": {"critical": 0, "high": 1, "medium": 0, "low": 0},
            "coverage": "1/1",
        },
        "statement": "1 finding at or above the standard release threshold (high).",
    },
    "limitations": ["Static, local, read-only analysis."],
}


def _report() -> dict:
    return copy.deepcopy(REPORT)


def _publishing_policy() -> dict:
    """The one policy under which all four §4.1 rows are in play at once.

    `publish_risk_summary: true` is what makes the publishable summary the
    *last* entry of the set, which is the entry N22 asks to fail.
    """

    return {
        "version": "0.1.0",
        "release_threshold_rating": "high",
        "publish_risk_summary": True,
        "thresholds": {},
    }


@pytest.fixture
def output_root(tmp_path: Path) -> Path:
    root = tmp_path / "inspected project"
    root.mkdir()
    (root / STORE_DIRNAME).mkdir()
    return root


def _confirmed_publishing_entries(root: Path) -> list[tuple]:
    """The full §4.1 set: sensitive report, JSON record, publishable summary."""

    entries = sdr_artifacts.artifact_entries(
        _report(),
        project_root=root,
        output_root=root,
        policy=_publishing_policy(),
        confirmed=True,
        problems=[],
        evidence_problems=[],
    )
    names = [Path(path).name for path, *_rest in entries]
    assert names == [REPORT_ARTIFACT, JSON_ARTIFACT, PUBLISHABLE_ARTIFACT], (
        "N22 injects a failure on the *last* write, so these tests need the "
        "publishable summary to be the last entry of a confirmed publishing "
        f"run; the set was {names}"
    )
    return entries


def _content_for(entries, name: str) -> str:
    for path, _root, content, _create in entries:
        if Path(path).name == name:
            return content
    raise AssertionError(
        f"no entry named {name!r}; entries were {[Path(p).name for p, *_r in entries]}"
    )


def _inject_failure(
    monkeypatch, entries, name: str, *, after_writing: bool = False
) -> None:
    """Fail the write of `name`, and only that write.

    Keyed on the *new* content as well as the artifact name so the rollback's
    own `safe_write_text` calls — which carry the prior bytes — pass through.
    An injector that refused the target unconditionally would break the
    rollback and then report the breakage as a finding.
    """

    real_write = risk_mod.safe_write_text
    doomed = _content_for(entries, name)

    def _spy(path, text, **kwargs):
        if Path(path).name == name and text == doomed:
            if after_writing:
                real_write(path, text, **kwargs)
            raise InjectedWriteFailure(f"injected failure writing {name}")
        return real_write(path, text, **kwargs)

    monkeypatch.setattr(risk_mod, "safe_write_text", _spy)


def _artifact_files(root: Path) -> list[str]:
    names = {REPORT_ARTIFACT, JSON_ARTIFACT, PUBLISHABLE_ARTIFACT}
    return sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name in names
    )


# ---------------------------------------------------------------------------
# N22 — the set lands, so a rollback test cannot pass because nothing was tried.
# ---------------------------------------------------------------------------


def test_a_confirmed_publishing_run_writes_the_whole_artifact_set(output_root):
    """The control. Every rollback assertion below is 'these files are absent
    or unchanged', which is trivially true of a run that never wrote anything.
    """

    sdr_artifacts.write_artifacts(_confirmed_publishing_entries(output_root))

    assert _artifact_files(output_root) == [
        f"{STORE_DIRNAME}/{JSON_ARTIFACT}",
        f"{STORE_DIRNAME}/{REPORT_ARTIFACT}",
        (PUBLISH_DIRNAME / PUBLISHABLE_ARTIFACT).as_posix(),
    ], (
        "with no failure injected the confirmed publishing run writes all "
        f"three §4.1 artifacts; it wrote {_artifact_files(output_root)}"
    )


# ---------------------------------------------------------------------------
# N22 — a failure on the last write rolls the earlier ones back.
# ---------------------------------------------------------------------------


def test_a_failure_on_the_last_write_restores_an_artifact_that_existed_before_the_run(
    output_root, monkeypatch
):
    """The rewrite-the-prior-bytes half of `restore`."""

    prior_target = output_root / STORE_DIRNAME / REPORT_ARTIFACT
    prior_target.write_text(PRIOR_REPORT, encoding="utf-8")

    entries = _confirmed_publishing_entries(output_root)
    _inject_failure(monkeypatch, entries, PUBLISHABLE_ARTIFACT)

    with pytest.raises(InjectedWriteFailure):
        sdr_artifacts.write_artifacts(entries)

    assert prior_target.read_text(encoding="utf-8") == PRIOR_REPORT, (
        "§4.1: the run is one unit. A target that held a prior run's report "
        "must hold exactly that report again after the transaction fails — "
        "not the new report, which no completed run ever produced; "
        f"{prior_target.name} held {prior_target.read_text(encoding='utf-8')!r}"
    )


def test_a_failure_on_the_last_write_removes_an_artifact_that_did_not_exist_before(
    output_root, monkeypatch
):
    """The unlink half of `restore`, which is a different code path."""

    created_target = output_root / STORE_DIRNAME / JSON_ARTIFACT
    assert not created_target.exists(), "fixture drift: the JSON record must be new"

    entries = _confirmed_publishing_entries(output_root)
    _inject_failure(monkeypatch, entries, PUBLISHABLE_ARTIFACT)

    with pytest.raises(InjectedWriteFailure):
        sdr_artifacts.write_artifacts(entries)

    assert not created_target.exists(), (
        "a target with no prior contents is restored by being removed, not by "
        "being left holding the failed run's bytes. §4.2 makes this record the "
        "contract of record, so a survivor is a record of a run that did not "
        f"happen; {created_target} exists"
    )


def test_a_failure_on_the_last_write_leaves_no_artifact_of_the_failed_run_at_all(
    output_root, monkeypatch
):
    """§4.1's actual claim, stated over the whole set rather than one file."""

    (output_root / STORE_DIRNAME / REPORT_ARTIFACT).write_text(
        PRIOR_REPORT, encoding="utf-8"
    )

    entries = _confirmed_publishing_entries(output_root)
    _inject_failure(monkeypatch, entries, PUBLISHABLE_ARTIFACT)

    with pytest.raises(InjectedWriteFailure):
        sdr_artifacts.write_artifacts(entries)

    assert _artifact_files(output_root) == [f"{STORE_DIRNAME}/{REPORT_ARTIFACT}"], (
        "after a failed transaction the only artifact on disk is the one that "
        "was there before it started. Anything else is the partial write §4.1 "
        f"calls a disclosure bug; found {_artifact_files(output_root)}"
    )


def test_a_failure_writing_the_summary_leaves_no_published_file_behind(
    output_root, monkeypatch
):
    """The disclosure direction: nothing reaches `docs/security/`."""

    entries = _confirmed_publishing_entries(output_root)
    _inject_failure(monkeypatch, entries, PUBLISHABLE_ARTIFACT)

    with pytest.raises(InjectedWriteFailure):
        sdr_artifacts.write_artifacts(entries)

    published = [
        path.relative_to(output_root).as_posix()
        for path in (output_root / PUBLISH_DIRNAME).rglob("*")
        if path.is_file()
    ] if (output_root / PUBLISH_DIRNAME).exists() else []
    assert published == [], (
        "asserted by path, not by content: a truncated or half-written file "
        f"under {PUBLISH_DIRNAME.as_posix()}/ is still a published file; "
        f"found {published}"
    )


def test_the_injected_failure_reaches_the_caller_rather_than_being_swallowed(
    output_root, monkeypatch
):
    """A silent rollback is a run that reports success and wrote nothing."""

    entries = _confirmed_publishing_entries(output_root)
    _inject_failure(monkeypatch, entries, PUBLISHABLE_ARTIFACT)

    with pytest.raises(InjectedWriteFailure) as excinfo:
        sdr_artifacts.write_artifacts(entries)

    assert PUBLISHABLE_ARTIFACT in str(excinfo.value), (
        "the write failure propagates unchanged so the runner can report it. "
        "Swallowing it would leave a run that exits 0 having written none of "
        f"its artifacts; the raised error was {excinfo.value!r}"
    )


# ---------------------------------------------------------------------------
# N22 — a target whose writer replaced the file and *then* failed.
#
# `_write_text_transaction` restores "the entire declared set, including a
# target whose writer replaced the file before raising". `safe_write_text` is
# atomic, so only an injection that writes first can reach that claim.
# ---------------------------------------------------------------------------


def test_a_target_replaced_before_the_failure_is_restored_to_its_prior_contents(
    output_root, monkeypatch
):
    published = output_root / PUBLISH_DIRNAME / PUBLISHABLE_ARTIFACT
    published.parent.mkdir(parents=True)
    published.write_text(PRIOR_SUMMARY, encoding="utf-8")

    entries = _confirmed_publishing_entries(output_root)
    _inject_failure(monkeypatch, entries, PUBLISHABLE_ARTIFACT, after_writing=True)

    with pytest.raises(InjectedWriteFailure):
        sdr_artifacts.write_artifacts(entries)

    assert published.read_text(encoding="utf-8") == PRIOR_SUMMARY, (
        "the failing target is part of the declared set too. Its writer had "
        "already replaced the file, so leaving the new bytes there publishes "
        "a summary from a run that failed; the published file held "
        f"{published.read_text(encoding='utf-8')!r}"
    )


def test_the_earlier_writes_roll_back_even_when_the_last_target_was_replaced(
    output_root, monkeypatch
):
    prior_target = output_root / STORE_DIRNAME / REPORT_ARTIFACT
    prior_target.write_text(PRIOR_REPORT, encoding="utf-8")
    published = output_root / PUBLISH_DIRNAME / PUBLISHABLE_ARTIFACT
    published.parent.mkdir(parents=True)
    published.write_text(PRIOR_SUMMARY, encoding="utf-8")

    entries = _confirmed_publishing_entries(output_root)
    _inject_failure(monkeypatch, entries, PUBLISHABLE_ARTIFACT, after_writing=True)

    with pytest.raises(InjectedWriteFailure):
        sdr_artifacts.write_artifacts(entries)

    assert prior_target.read_text(encoding="utf-8") == PRIOR_REPORT, (
        "a target that got as far as being replaced must not stop the "
        "restoration of the targets before it; the sensitive report held "
        f"{prior_target.read_text(encoding='utf-8')!r}"
    )
    assert not (output_root / STORE_DIRNAME / JSON_ARTIFACT).exists(), (
        "and the JSON record, which had no prior contents, is still removed"
    )


# ---------------------------------------------------------------------------
# Prior contents that are not UTF-8 — a property of the transaction, not of
# the artifact set.
#
# `_write_text_transaction` captures the prior state with `read_bytes()` and
# restores it with `safe_write_text(..., prior.decode("utf-8"))`. It has the
# bytes and throws them away, so a target it cannot decode is a target it
# cannot restore, and the failed run's content stays on disk in its place.
#
# **Stated plainly: no design-review run produces this.** All four §4.1
# artifacts are written by this tool as UTF-8 text, so reaching it takes
# something outside the tool leaving non-UTF-8 bytes at one of those paths —
# a corrupted file, a checked-in binary, a merge artifact. It is a real defect
# in a function documented as restoring *every* target on failure, and the fix
# is one line, but it is not an N22 finding and nothing about the design
# review depends on it. This test is here because this file owns the
# transaction's rollback; delete it if the ceiling is acceptable.
# ---------------------------------------------------------------------------


NON_UTF8_PRIOR = b"\xff\xfe not a UTF-8 document\n"


def test_a_prior_target_that_is_not_utf_8_is_still_restored(output_root, monkeypatch):
    prior_target = output_root / STORE_DIRNAME / REPORT_ARTIFACT
    prior_target.write_bytes(NON_UTF8_PRIOR)

    entries = _confirmed_publishing_entries(output_root)
    _inject_failure(monkeypatch, entries, PUBLISHABLE_ARTIFACT)

    # Either error is a failed transaction: `InjectedWriteFailure` once the
    # restore can write the bytes back, and today the `RuntimeError` the
    # transaction raises when its own rollback could not finish.
    with pytest.raises((InjectedWriteFailure, RuntimeError)):
        sdr_artifacts.write_artifacts(entries)

    assert prior_target.read_bytes() == NON_UTF8_PRIOR, (
        "§4.1 says the run is one unit, without an exception for what the "
        "target happened to hold. The prior state was captured as bytes and "
        "can be written back as bytes; decoding it as UTF-8 to restore it "
        "means a target the transaction cannot restore keeps the failed run's "
        f"content instead; it held {prior_target.read_bytes()!r}"
    )


# ---------------------------------------------------------------------------
# N22 through the runner, so the composition is covered and not just the unit.
# ---------------------------------------------------------------------------


def _architecture_for(threats: dict) -> dict:
    """Boundaries spelled with the golden register's own ids.

    A fixture that used §4.2's `tb-internet` ids would leave every golden
    threat dangling, the run would suppress all output under N29, and the
    rollback would never be reached.
    """

    return {
        "version": "0.1.0",
        "trust_boundaries": [
            {
                "id": record["id"],
                "name": f"{record.get('from')} -> {record.get('to')}",
                "evidence_status": "inferred",
            }
            for record in threats.get("boundaries", [])
        ],
        "components": [],
        "actors": [],
        "data_stores": [],
        "data_flows": [],
        "assets": [],
        "dependencies": [],
    }


@pytest.fixture
def confirmed_project(tmp_path: Path, monkeypatch) -> Path:
    """A complete store with a *genuinely bound* confirmation.

    `design-review-confirm` runs `check_assessment`, which verifies
    `policy_digest`, `threat_digest`, `assessment_digest` and
    `risk_state_digest` against the documents on disk. A record planted at the
    plugin-owned state path is exactly what that gate exists to reject, so the
    binding here is produced by `stamp_policy` and `stamp_assessment` — the
    same two functions `main` calls for the `policy-confirm` and `confirm`
    subcommands — rather than written by hand.

    In-process rather than through the CLI helpers in `tests/risk_helpers.py`
    because those build a different store layout for a different purpose. The
    binding they produce and the binding these two calls produce are the same
    record written by the same code; the fixture asserts `check_assessment`
    returns nothing, so a drift in either would fail here rather than silently
    turn the confirmed tests below into unconfirmed ones.
    """

    monkeypatch.setenv("SECURITY_REQUIREMENTS_DATA", str(tmp_path / "plugin state"))

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
    (store / "architecture.yaml").write_text(
        yaml.safe_dump(_architecture_for(threats), sort_keys=True), encoding="utf-8"
    )
    # `check_assessment` reads both, and an absent document is not the same as
    # an empty one to `_refresh_documents`.
    (store / "requirements.yaml").write_text("requirements: []\n", encoding="utf-8")
    (store / "risk-evidence.yaml").write_text("evidence: []\n", encoding="utf-8")

    paths = {
        "project_root": root,
        "policy": store / "risk-policy.yaml",
        "threats": store / "threats.yaml",
        "assessment": store / "risk-assessment.yaml",
        "requirements": store / "requirements.yaml",
        "evidence": store / "risk-evidence.yaml",
        "state": store / "risk-state.yaml",
    }
    risk_mod.stamp_policy(paths, "tester", "self_declared", confirmed_at=PINNED_STAMP)
    risk_mod.stamp_assessment(
        paths, "tester", "self_declared", confirmed_at=PINNED_STAMP
    )

    bound = risk_mod._read_trusted_confirmation(root, "assessment")
    assert bound is not None, (
        "the confirmation must land at "
        f"{confirmation_state_path(root, 'assessment')}, or every confirmed "
        "test below is silently testing an unconfirmed run"
    )
    assert risk_mod.check_assessment(paths) == [], (
        "the gate `design-review-confirm` runs is `check_assessment`. If the "
        "fixture's binding does not satisfy it the run is refused before any "
        "artifact is written, and the rollback tests pass because nothing was "
        f"attempted; it reported {risk_mod.check_assessment(paths)}"
    )
    return root


def _confirm_argv(root: Path) -> list[str]:
    return [
        "design-review-confirm",
        "--project-root",
        str(root),
        "--output",
        str(root),
        "--confirmed-at",
        PINNED_STAMP,
        "--by",
        "tester",
        "--authority",
        "self_declared",
    ]


def test_a_confirmed_run_writes_its_artifact_set(confirmed_project):
    """The control for the runner-level rollback test below."""

    assert risk_mod.main(_confirm_argv(confirmed_project)) == OK, (
        "the fixture must produce a clean confirmed run, or the rollback test "
        "below passes because the run wrote nothing"
    )
    assert _artifact_files(confirmed_project) == [
        f"{STORE_DIRNAME}/{JSON_ARTIFACT}",
        f"{STORE_DIRNAME}/{REPORT_ARTIFACT}",
    ], (
        "every appetite ships `publish_risk_summary: false`, so a confirmed "
        "run writes the two sensitive artifacts and no summary; it wrote "
        f"{_artifact_files(confirmed_project)}"
    )


def test_a_runner_level_failure_rolls_the_whole_run_back(
    confirmed_project, monkeypatch, capsys
):
    """The rollback the operator actually gets, not the one the unit gets."""

    prior_target = confirmed_project / STORE_DIRNAME / REPORT_ARTIFACT
    prior_target.write_text(PRIOR_REPORT, encoding="utf-8")

    real_write = risk_mod.safe_write_text

    def _spy(path, text, **kwargs):
        # The JSON record is the last write of a non-publishing confirmed run.
        # Keyed on content so the rollback's own writes pass through.
        if Path(path).name == JSON_ARTIFACT and text.lstrip().startswith("{"):
            raise InjectedWriteFailure(f"injected failure writing {JSON_ARTIFACT}")
        return real_write(path, text, **kwargs)

    monkeypatch.setattr(risk_mod, "safe_write_text", _spy)

    exit_code = risk_mod.main(_confirm_argv(confirmed_project))

    output = _run_output(capsys)
    assert exit_code != OK, (
        "`main` catches OSError and reports it, so the failure surfaces as a "
        f"non-zero exit rather than a traceback; it exited {exit_code} with "
        f"output {output!r}"
    )
    assert JSON_ARTIFACT in output, (
        "the run must say which write failed, or the operator is told only "
        f"that something did; the output was {output!r}"
    )
    assert "wrote " not in output, (
        "the runner prints one `wrote <path>` line per artifact *after* the "
        "transaction returns. A rolled-back run that still announces its "
        "writes sends the operator looking for files the rollback removed; "
        f"the output was {output!r}"
    )
    assert prior_target.read_text(encoding="utf-8") == PRIOR_REPORT, (
        "the runner writes its artifacts through the same transaction, so a "
        "failure part-way leaves the prior report exactly as it was; it held "
        f"{prior_target.read_text(encoding='utf-8')!r}"
    )
    assert _artifact_files(confirmed_project) == [
        f"{STORE_DIRNAME}/{REPORT_ARTIFACT}"
    ], (
        "and no artifact of the failed run survives anywhere under the output "
        f"root; found {_artifact_files(confirmed_project)}"
    )


# ---------------------------------------------------------------------------
# N21 — the withheld summary is stated, not merely omitted.
#
# `_run_design_review` prints one `wrote <path>` line per artifact and says
# nothing about the summary it withheld. A reader who knows the policy can
# publish sees two `wrote` lines and no mention of `docs/security/`, which
# reads exactly like a run whose summary went out.
# ---------------------------------------------------------------------------


def _run_output(capsys) -> str:
    captured = capsys.readouterr()
    return captured.out + captured.err


def test_a_confirmed_run_that_withholds_the_publishable_summary_says_so(
    confirmed_project, capsys
):
    exit_code = risk_mod.main(_confirm_argv(confirmed_project))
    output = _run_output(capsys)

    # Paired with the disk check, so this cannot pass for a run that published
    # the summary and merely mentioned it in passing.
    assert not (confirmed_project / PUBLISH_DIRNAME / PUBLISHABLE_ARTIFACT).exists(), (
        "N21: with `publish_risk_summary: false` the summary is not written at "
        "all — not redacted, not empty. If it exists this test is measuring "
        "the wrong run"
    )
    assert exit_code == OK, f"the confirmed run failed: {exit_code}, output {output!r}"
    assert PUBLISHABLE_ARTIFACT in output, (
        "N21: 'no publishable summary is written at all **and the run says "
        "so**'. The run names its artifacts one `wrote` line at a time and "
        "never mentions the one it withheld, so silence is the only signal a "
        "reader gets — and silence is what a published summary looks like "
        f"too. The whole output was {output!r}"
    )


def test_the_withheld_summary_is_never_announced_as_written(
    confirmed_project, capsys
):
    """The statement N21 asks for must not be confusable with a `wrote` line."""

    risk_mod.main(_confirm_argv(confirmed_project))
    output = _run_output(capsys)

    announced = [
        line
        for line in output.splitlines()
        if PUBLISHABLE_ARTIFACT in line and line.strip().startswith("wrote ")
    ]
    assert announced == [], (
        "a withheld summary reported on a `wrote` line is worse than silence: "
        "the operator goes looking for a file that §4.1 says was never "
        f"created; the lines were {announced}"
    )
    assert PUBLISHABLE_ARTIFACT in output, (
        "and the run must still name it, or the assertion above holds "
        f"vacuously; the whole output was {output!r}"
    )


def test_the_run_says_which_policy_setting_withheld_the_summary(
    confirmed_project, capsys
):
    """'Says so' has to be actionable, or the operator cannot tell a policy
    decision from a missing feature."""

    risk_mod.main(_confirm_argv(confirmed_project))
    output = _run_output(capsys)

    assert "publish_risk_summary" in output, (
        "§4.1 makes publication opt-in through `publish_risk_summary`, and it "
        "is false under all three appetites. A run that withholds the summary "
        "without naming the setting leaves the operator no way to find out "
        f"why; the whole output was {output!r}"
    )
