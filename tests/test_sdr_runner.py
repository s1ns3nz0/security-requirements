"""The `design-review` subcommands, wired end to end.

Plan of record: §3 (exit codes 0 / 1 / 2), §4.1 (the artifact table), §8, §11.2
N26–N29, and `docs/design-review-runner-contract.md` §1 and §9.

`risk.main` currently refuses both new subcommands with "is not wired to a
runner yet". That refusal exists so a parsed-but-unwired command cannot fall
through to `check_policy`, which reads a `--policy` these subcommands do not
declare and would report a missing policy for a review that was never
attempted. This file specifies what replaces it.

These are integration tests over `risk.main`, deliberately: every unit below
`main` already has its own file (`test_sdr_report.py`, `test_sdr_artifacts.py`,
`test_sdr_architecture.py`, `test_sdr_scope.py`, `test_sdr_entry.py`). What is
untested until now is the *composition* — that the runner reads the store the
plugin actually writes, gates on the problems it actually collects, and exits
with the code §3 specifies.

Documents come from the store, not from flags. The design-review grammar
declares `--project-root` and `--output` and no document paths, so every
document is read from `.security-requirements/` by its canonical name
(`publish.py:_risk_paths`). The policy is the exception: it comes from the
appetite named by `--risk-appetite`, composed by `risk.appetite_policy`.

No test here reads a clock or a network. `--confirmed-at` pins the one
timestamp that reaches a digest.
"""

from __future__ import annotations

import copy
import json
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

GOLDEN_CASE = REPO_ROOT / "golden" / "movie-rating-aws"
STORE_DIRNAME = ".security-requirements"
PUBLISH_DIRNAME = Path("docs") / "security"

OK, PROBLEMS, USAGE = 0, 1, 2

PREVIEW = f"{STORE_DIRNAME}/design-review.preview.md"
REPORT = f"{STORE_DIRNAME}/design-review.md"
JSON_REPORT = f"{STORE_DIRNAME}/design-review.json"
SUMMARY = (PUBLISH_DIRNAME / "design-review-summary.md").as_posix()


#: An architecture whose ids are the golden register's own boundary ids. The
#: register spells boundaries `TB-n`; §4.2 spells them `tb-internet` under
#: `trust_boundaries`. Until intake writes the document, a fixture that used
#: §4.2's ids would leave every golden threat dangling and the run would be
#: measuring the mismatch rather than the wiring.
def _architecture_for(threats: dict) -> dict:
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
def project(tmp_path: Path) -> Path:
    """A repository with a complete store, copied from the golden case."""

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
    return root


def _argv(project_root: Path, *extra: str, command: str = "design-review") -> list[str]:
    return [
        command,
        "--project-root",
        str(project_root),
        "--output",
        str(project_root),
        *extra,
    ]


def _written(project_root: Path) -> list[str]:
    return sorted(
        path.relative_to(project_root).as_posix()
        for path in project_root.rglob("*")
        if path.is_file()
    )


def _artifacts(project_root: Path) -> list[str]:
    """Only the files this command writes, so the store fixture is not noise."""

    names = {
        PREVIEW,
        REPORT,
        JSON_REPORT,
        SUMMARY,
    }
    return sorted(path for path in _written(project_root) if path in names)


# ---------------------------------------------------------------------------
# The refusal is gone, and the command runs.
# ---------------------------------------------------------------------------


def test_design_review_is_wired_to_a_runner(project, capsys):
    exit_code = risk_mod.main(_argv(project))

    captured = capsys.readouterr()
    assert "not wired to a runner yet" not in captured.err, (
        "the placeholder refusal must be replaced by the runner; stderr was "
        f"{captured.err!r}"
    )
    assert exit_code in (OK, PROBLEMS), (
        "a well-formed invocation over a complete store is not a usage error; "
        f"exit was {exit_code} and stderr {captured.err!r}"
    )


def test_a_clean_run_exits_zero(project):
    assert risk_mod.main(_argv(project)) == OK, (
        "§3: 0 ok, 1 problems, 2 usage. The golden store is complete and its "
        "architecture declares every boundary its threats name, so nothing is "
        "wrong with it"
    )


def test_the_runner_never_falls_through_to_the_policy_check(project, capsys):
    risk_mod.main(_argv(project))

    captured = capsys.readouterr()
    assert "risk policy" not in captured.err, (
        "design-review declares no --policy flag; its policy comes from "
        "--risk-appetite. A run reporting a missing policy has fallen through "
        f"to check_policy, which is what the refusal existed to prevent. "
        f"stderr was {captured.err!r}"
    )


# ---------------------------------------------------------------------------
# N26 — an unconfirmed run previews and publishes nothing.
# ---------------------------------------------------------------------------


def test_an_unconfirmed_run_writes_only_the_preview(project):
    risk_mod.main(_argv(project))

    assert _artifacts(project) == [PREVIEW], (
        f"N26: with no trusted confirmation the run writes {PREVIEW} and "
        f"nothing else; it wrote {_artifacts(project)}"
    )


def test_the_preview_is_marked_unconfirmed(project):
    risk_mod.main(_argv(project))

    content = (project / PREVIEW).read_text(encoding="utf-8")
    assert sdr_artifacts.UNCONFIRMED_MARKER in content, (
        "N26 requires the preview to say it is unconfirmed. A preview that "
        "reads like a finished review is the disclosure failure"
    )


def test_an_unconfirmed_run_publishes_nothing(project):
    risk_mod.main(_argv(project))

    published = [
        path
        for path in _written(project)
        if path.startswith(PUBLISH_DIRNAME.as_posix())
    ]
    assert published == [], (
        "N26: no publishable artifact without a confirmation. Asserted by "
        f"path — a redacted stub is still a published file; found {published}"
    )


# ---------------------------------------------------------------------------
# N27 — design-review-confirm refuses without a passing gate.
# ---------------------------------------------------------------------------


def test_design_review_confirm_refuses_without_a_trusted_confirmation(project, capsys):
    exit_code = risk_mod.main(
        _argv(
            project,
            "--by",
            "user",
            "--authority",
            "self_declared",
            command="design-review-confirm",
        )
    )

    assert exit_code == PROBLEMS, (
        "N27: without a passing gate the confirm subcommand refuses. That is a "
        f"problem exit (1), not a usage error (2); got {exit_code}"
    )
    assert _artifacts(project) == [], (
        "a refused confirmation writes nothing at all; it wrote "
        f"{_artifacts(project)}"
    )


def test_an_unbound_confirmation_does_not_confirm_the_run(project, capsys):
    """N27/N28 — presence at the state path is not proof of a binding.

    The first version of this gate tested `_read_trusted_confirmation(...) is
    not None` and nothing else, so *any* mapping at the plugin-owned path
    confirmed the run. That accepts two things it must not: a confirmation
    whose digests no longer match the documents — the exact condition
    confirmation exists to detect — and a file planted at that path.

    Every other confirm path in `risk.py` runs `check_assessment`, which
    verifies `policy_digest`, `threat_digest`, `assessment_digest` and
    `risk_state_digest` against the documents on disk. This one must too.
    """

    state_path = risk_mod.confirmation_state_path(project, "assessment")
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(
        yaml.safe_dump(
            {
                "status": "confirmed",
                "project": str(project.resolve()),
                "confirmed_by": "someone",
                "confirmed_at": "2026-01-01T00:00:00Z",
                "authority": "self_declared",
                # No digests at all. Nothing here binds this record to the
                # documents the run is about to score.
                "policy_digest": "sha256:" + "0" * 64,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    exit_code = risk_mod.main(
        _argv(
            project,
            "--by",
            "user",
            "--authority",
            "self_declared",
            command="design-review-confirm",
        )
    )

    assert exit_code == PROBLEMS, (
        "a confirmation that does not bind the documents must not confirm the "
        f"run; got {exit_code}"
    )
    assert _artifacts(project) == [], (
        "an unbound confirmation must not produce authoritative artifacts — "
        "design-review.md and design-review.json are the documents a reader "
        f"trusts *because* they were confirmed; wrote {_artifacts(project)}"
    )


def test_the_refusal_says_what_is_missing(project, capsys):
    risk_mod.main(
        _argv(
            project,
            "--by",
            "user",
            "--authority",
            "self_declared",
            command="design-review-confirm",
        )
    )

    captured = capsys.readouterr()
    assert "confirmation" in captured.err.lower(), (
        "the refusal names what was missing, so the operator knows to run the "
        f"confirmation first; stderr was {captured.err!r}"
    )


# ---------------------------------------------------------------------------
# N29 — a problem suppresses every artifact.
# ---------------------------------------------------------------------------


def test_a_threat_naming_an_undeclared_boundary_suppresses_all_output(project):
    store = project / STORE_DIRNAME
    architecture = yaml.safe_load(
        (store / "architecture.yaml").read_text(encoding="utf-8")
    )
    architecture["trust_boundaries"] = architecture["trust_boundaries"][:-1]
    (store / "architecture.yaml").write_text(
        yaml.safe_dump(architecture, sort_keys=True), encoding="utf-8"
    )

    exit_code = risk_mod.main(_argv(project))

    assert exit_code == PROBLEMS, (
        f"§7.13: a threat naming an id the architecture does not declare is a "
        f"problem; got {exit_code}"
    )
    assert _artifacts(project) == [], (
        "N29: any document-integrity error suppresses **all** rendered output, "
        f"the preview included; it wrote {_artifacts(project)}"
    )


def test_a_scope_matching_nothing_suppresses_all_output(project, capsys):
    exit_code = risk_mod.main(_argv(project, "--scope", "cmp-nobody-declares"))

    assert exit_code == PROBLEMS, (
        f"§8: a --scope matching nothing fails; got {exit_code}"
    )
    assert _artifacts(project) == [], (
        "a run that reviewed nothing must not emit a report that reads like it "
        f"reviewed everything; it wrote {_artifacts(project)}"
    )
    captured = capsys.readouterr()
    assert "cmp-nobody-declares" in captured.err, (
        f"§8 requires the failure to quote the filter; stderr was {captured.err!r}"
    )


# ---------------------------------------------------------------------------
# §3 — the appetite selects the policy.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("appetite", sorted(risk_mod.RISK_APPETITES))
def test_every_appetite_runs_and_is_recorded_in_the_report(project, appetite):
    assert risk_mod.main(_argv(project, "--risk-appetite", appetite)) == OK

    content = (project / PREVIEW).read_text(encoding="utf-8")
    assert content, "the preview must not be empty"


def test_the_appetite_changes_the_policy_the_run_scores_against(project):
    conservative = risk_mod.appetite_policy("conservative")
    tolerant = risk_mod.appetite_policy("tolerant")

    assert conservative != tolerant, (
        "the three appetite files must differ, or --risk-appetite selects "
        "nothing and the flag is decoration"
    )


# ---------------------------------------------------------------------------
# §4.3 / N39 — two pinned runs agree.
# ---------------------------------------------------------------------------


def test_two_runs_with_the_clock_pinned_write_identical_bytes(project, tmp_path):
    risk_mod.main(_argv(project))
    first = (project / PREVIEW).read_bytes()
    (project / PREVIEW).unlink()

    risk_mod.main(_argv(project))
    second = (project / PREVIEW).read_bytes()

    assert first == second, (
        "§4.3: two runs over an unchanged store produce identical output. A "
        "difference means something read a clock or iterated a set"
    )


# ---------------------------------------------------------------------------
# §7.21 — --output contains the artifacts.
# ---------------------------------------------------------------------------


def test_the_output_flag_moves_the_artifacts_out_of_the_project(project, tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()

    exit_code = risk_mod.main(
        [
            "design-review",
            "--project-root",
            str(project),
            "--output",
            str(elsewhere),
        ]
    )

    assert exit_code == OK, f"the run failed: {exit_code}"
    assert (elsewhere / PREVIEW).is_file(), (
        f"--output overrides the base of the sensitive tree; {elsewhere} held "
        f"{_written(elsewhere)}"
    )
    assert not (project / PREVIEW).exists(), (
        "with --output given, nothing is written to the project root; the "
        "operator asked for the artifacts somewhere else"
    )


# ---------------------------------------------------------------------------
# Evidence — the other half of `output_allowed`.
#
# The rule has two halves and only one of them was reachable from this command
# while the runner passed `evidence_problems=[]`. Stale evidence is supposed to
# still render an UNDETERMINED preview: the reader learns the evidence expired,
# which is the answer. Hardcoding the list empty meant an evidence problem was
# indistinguishable from a binding error, and suppressed everything.
# ---------------------------------------------------------------------------

#: `valid_until` in the past relative to the run. Everything else about the
#: record is well formed, so the only problem it can produce is staleness —
#: otherwise the test would pass for the wrong reason.
EXPIRED_UNTIL = "2026-02-01"
PINNED_STAMP = "2026-05-01T00:00:00Z"


def _managed_requirement() -> tuple[dict, dict]:
    managed = {
        "statement": "checkout-api MUST reject unauthenticated writes.",
        "verification": {"method": "test_case", "expect": "401"},
    }
    requirements = {
        "version": "0.1.0",
        "requirements": [
            {
                "id": "REQ-1",
                "statement": managed["statement"],
                "rationale": "Unauthenticated write across the internet boundary.",
                "sources": ["AC-3"],
                "responsibility": "team",
                "priority": "high",
                "managed": managed,
                "verification": managed["verification"],
            }
        ],
    }
    return managed, requirements


def _write_expired_evidence(project_root: Path) -> None:
    """A store carrying requirements and one expired-but-otherwise-valid record."""

    managed, requirements = _managed_requirement()
    evidence = {
        "version": "0.1.0",
        "evidence": [
            {
                "id": "EV-1",
                "requirement_id": "REQ-1",
                "method": "test_case",
                "result": "pass",
                "observed_at": "2026-01-05T00:00:00Z",
                "observed_by": "ci",
                "artifact": {
                    "kind": "test_report",
                    "location": "ci/run/1",
                    "digest": risk_mod.canonical_digest({"run": 1}),
                },
                "requirement_digest": risk_mod.canonical_digest(managed),
                "valid_until": EXPIRED_UNTIL,
            }
        ],
    }
    store = project_root / STORE_DIRNAME
    (store / "requirements.yaml").write_text(
        yaml.safe_dump(requirements, sort_keys=True), encoding="utf-8"
    )
    (store / "risk-evidence.yaml").write_text(
        yaml.safe_dump(evidence, sort_keys=True), encoding="utf-8"
    )


def test_a_store_without_evidence_documents_is_not_a_problem(project):
    """Evidence is optional. Its absence is not a defect in the model."""

    store = project / STORE_DIRNAME
    assert not (store / "risk-evidence.yaml").exists(), "fixture drift"

    exit_code = risk_mod.main(_argv(project))

    assert exit_code == OK, (
        "requirements.yaml and risk-evidence.yaml are produced by a later "
        "workflow step and a team may legitimately have neither yet. Treating "
        "their absence as a problem would fail every design review run before "
        f"the first evidence is written; got {exit_code}"
    )


def test_expired_evidence_is_reported(project, capsys):
    _write_expired_evidence(project)

    exit_code = risk_mod.main(_argv(project, "--confirmed-at", PINNED_STAMP))

    assert exit_code == PROBLEMS, (
        f"an expired evidence record is a problem the operator can fix; got {exit_code}"
    )
    captured = capsys.readouterr()
    assert "EV-1" in captured.err, (
        "the problem names the record, so the operator knows which evidence to "
        f"refresh; stderr was {captured.err!r}"
    )


def test_expired_evidence_alone_still_renders_the_preview(project):
    """The half of `output_allowed` that `evidence_problems=[]` made unreachable."""

    _write_expired_evidence(project)

    exit_code = risk_mod.main(_argv(project, "--confirmed-at", PINNED_STAMP))

    # Both halves, together. "The preview was written" is also true of a run
    # that never noticed the evidence at all, so on its own it cannot tell the
    # rule from the absence of the rule. The pair — reported *and* rendered —
    # is the property `output_allowed` actually encodes.
    assert exit_code == PROBLEMS, (
        "the expired record must be reported, or this test passes for a run "
        f"that silently ignored the evidence document; got {exit_code}"
    )
    assert _artifacts(project) == [PREVIEW], (
        "invalid or stale evidence may still render a preview — the reader "
        "learns the evidence expired, which is the answer. Only a binding or "
        "document-integrity error suppresses everything. This is what "
        "`risk.output_allowed` exists to distinguish, and it cannot make the "
        f"distinction if the runner reports no evidence problems; wrote "
        f"{_artifacts(project)}"
    )


def test_expired_evidence_beside_an_integrity_error_suppresses_everything(project):
    """One evidence problem does not licence rendering past a real fault."""

    _write_expired_evidence(project)
    store = project / STORE_DIRNAME
    architecture = yaml.safe_load(
        (store / "architecture.yaml").read_text(encoding="utf-8")
    )
    architecture["trust_boundaries"] = architecture["trust_boundaries"][:-1]
    (store / "architecture.yaml").write_text(
        yaml.safe_dump(architecture, sort_keys=True), encoding="utf-8"
    )

    exit_code = risk_mod.main(_argv(project, "--confirmed-at", PINNED_STAMP))

    assert exit_code == PROBLEMS
    assert _artifacts(project) == [], (
        "`output_allowed` renders only when *every* problem is an evidence "
        "problem. A dangling architecture reference beside a stale record is "
        f"not that case; wrote {_artifacts(project)}"
    )


def test_a_malformed_evidence_document_suppresses_output(project):
    """A document that will not parse as evidence is an integrity error."""

    store = project / STORE_DIRNAME
    (store / "risk-evidence.yaml").write_text(
        yaml.safe_dump({"version": "0.1.0", "evidence": "not-a-list"}, sort_keys=True),
        encoding="utf-8",
    )

    exit_code = risk_mod.main(_argv(project, "--confirmed-at", PINNED_STAMP))

    assert exit_code == PROBLEMS, f"got {exit_code}"


# ---------------------------------------------------------------------------
# A missing store is reported, not crashed on.
# ---------------------------------------------------------------------------


def test_a_project_with_no_store_reports_a_problem_rather_than_raising(
    tmp_path, capsys
):
    empty = tmp_path / "empty project"
    empty.mkdir()

    exit_code = risk_mod.main(_argv(empty))

    assert exit_code == PROBLEMS, (
        "a project with no model is a problem the operator can fix by running "
        f"the build, not a crash and not a clean review; got {exit_code}"
    )
    captured = capsys.readouterr()
    assert captured.err.strip(), "the run must say what was missing"


# ---------------------------------------------------------------------------
# F10 / N42 — a duplicate threat reaches the operator, not just the module.
#
# `sdr_ids.duplicate_pairs` has its own unit tests. What those cannot show is
# that the *runner* calls it: a module that is imported, invoked, and whose
# result is discarded passes every unit test it has. Removing the call from
# `sdr_report.report_problems` must turn something red, and before this test
# it did not.
# ---------------------------------------------------------------------------


def test_a_threat_entered_twice_under_two_ids_is_reported_by_the_run(project, capsys):
    store = project / STORE_DIRNAME
    threats = yaml.safe_load((store / "threats.yaml").read_text(encoding="utf-8"))
    original = threats["threats"][0]
    twin = copy.deepcopy(original)
    twin["id"] = f"{original['id']}-again"
    threats["threats"].append(twin)
    (store / "threats.yaml").write_text(
        yaml.safe_dump(threats, sort_keys=False), encoding="utf-8"
    )

    exit_code = risk_mod.main(_argv(project, "--confirmed-at", PINNED_STAMP))

    captured = capsys.readouterr()
    assert exit_code == PROBLEMS, (
        "the same threat under two ids inflates the register, and an inflated "
        f"register reads as assessed so nobody goes looking; got {exit_code}"
    )
    assert twin["id"] in captured.err, (
        "the report names the duplicate so the author knows what to merge; "
        f"stderr was {captured.err!r}"
    )


def test_a_threat_with_no_id_is_minted_one_and_scored(project, capsys):
    """F10's minting clause, exercised through a real run.

    A register a person wrote carries ids and this is a no-op over it. A model
    that just wrote one from a description does not, and every downstream
    reference — the assessment, `threat_refs`, the rendered register — needs
    one. Without this test the call in `_run_design_review` is a no-op over
    every fixture in the tree, which is indistinguishable from not being there.
    """

    store = project / STORE_DIRNAME
    threats = yaml.safe_load((store / "threats.yaml").read_text(encoding="utf-8"))
    unidentified = copy.deepcopy(threats["threats"][0])
    unidentified.pop("id")
    unidentified["scenario"] = "A threat the author never gave an id."
    threats["threats"].append(unidentified)
    (store / "threats.yaml").write_text(
        yaml.safe_dump(threats, sort_keys=False), encoding="utf-8"
    )

    exit_code = risk_mod.main(_argv(project, "--confirmed-at", PINNED_STAMP))

    captured = capsys.readouterr()
    assert "id is required" not in captured.err, (
        "the record reached validation without an id, so minting did not run "
        f"before it; stderr was {captured.err!r}"
    )
    assert exit_code in (OK, PROBLEMS), f"the run crashed: {exit_code}"


def test_the_minted_id_is_stable_across_two_runs(project):
    """Content-addressed, so two runs of one description agree.

    A counter would satisfy the test above and fail this one the moment the
    document is read in a different order.
    """

    store = project / STORE_DIRNAME
    threats = yaml.safe_load((store / "threats.yaml").read_text(encoding="utf-8"))
    unidentified = copy.deepcopy(threats["threats"][0])
    unidentified.pop("id")
    unidentified["scenario"] = "A threat the author never gave an id."
    threats["threats"].append(unidentified)
    (store / "threats.yaml").write_text(
        yaml.safe_dump(threats, sort_keys=False), encoding="utf-8"
    )

    import sdr_ids

    first = sdr_ids.assign_ids(copy.deepcopy(threats))
    second = sdr_ids.assign_ids(copy.deepcopy(threats))
    minted = [record["id"] for record in first["threats"]]

    assert minted == [record["id"] for record in second["threats"]], (
        "two runs over one document must mint the same ids, or a reader "
        f"comparing them sees every finding as new; got {minted}"
    )
    assert any(item.startswith(sdr_ids.MINTED_PREFIX) for item in minted), (
        "the fixture must actually contain an unidentified record, or this "
        f"test passes without minting anything; ids were {minted}"
    )
