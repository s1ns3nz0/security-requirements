"""Verdict wording, the empty model, the confirmation source, and ordering.

Plan of record `docs/security-design-review-plan.md` §11.2 — N28, N37, N38, N41.
Four claims that share one property: each is about what the run must *not* do,
and each is invisible to a test that only checks the happy path.

**N28** — a confirmation written into the repository is not a confirmation. The
only trusted source is plugin-owned state under `runtime_paths.plugin_data_root`,
reached through `risk._state_target`. A run that honoured a repository block
would let anyone who can edit `risk-assessment.yaml` promote a preview into an
authoritative, publishable record. The claim is believed already satisfied and
was never tested; these tests establish it rather than assume it.

**N37** — with findings at or above the release threshold the verdict says so,
and *no* artifact asserts the service is secure, safe, compliant or approved.
The scan covers all four §4.1 artifacts, not one string.

  The trap, recorded so it is not re-derived: the required disclaimer reads
  "...or claim that the service is secure", so a naive substring scan for
  "the service is secure" flags the correct text and a test written that way
  can only be made green by deleting the disclaimer. The assertion is therefore
  two-sided — the denial must be *present*, and only phrasings that cannot
  occur inside a denial are forbidden.

**N38** — an empty `threats.yaml` is a valid run, not an error. A project that
has modelled no threats yet must get a report that says so: `UNDETERMINED`
overall, `0/0` coverage, and a recorded limitation. The failure this guards
against is not a crash; it is a preview that reads like a clean review.

**N41** — proving a negative. §4.3 puts every ordering decision in
`risk.order_requirements` and states "No renderer sorts". A renderer that
quietly sorts makes that guarantee false and lets one run present its findings
in two different orders. The only way to see it is to feed the renderers a
deliberately unordered model and check the disorder survives.

Builders are local to this file. `tests/risk_helpers.py`, `tests/conftest.py`
and `tests/test_sdr_runner.py` are not imported from.

No test here reads a clock, a network, or the real plugin state root:
`--confirmed-at` pins the one timestamp that reaches a digest, and an autouse
fixture redirects `SECURITY_REQUIREMENTS_DATA` into `tmp_path`.
"""

from __future__ import annotations

import copy
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
import runtime_paths  # noqa: E402
import sdr_artifacts  # noqa: E402
import sdr_report  # noqa: E402

GOLDEN_CASE = REPO_ROOT / "golden" / "movie-rating-aws"
STORE_DIRNAME = sdr_artifacts.STORE_DIRNAME
PUBLISH_DIRNAME = sdr_artifacts.PUBLISH_DIRNAME

OK, PROBLEMS = 0, 1

PREVIEW = f"{STORE_DIRNAME}/{sdr_artifacts.PREVIEW_ARTIFACT}"
REPORT = f"{STORE_DIRNAME}/{sdr_artifacts.REPORT_ARTIFACT}"
JSON_REPORT = f"{STORE_DIRNAME}/{sdr_artifacts.JSON_ARTIFACT}"
SUMMARY = (PUBLISH_DIRNAME / sdr_artifacts.PUBLISHABLE_ARTIFACT).as_posix()

#: Pins the one timestamp that reaches a digest (§4.3, N39).
PINNED_STAMP = "2026-05-01T00:00:00Z"

#: The appetite the fixtures score against. `standard` puts the release
#: threshold at `high`, and the golden case carries five `high` findings, so
#: N37's "with findings above the threshold" precondition is really met.
APPETITE = "standard"


# ---------------------------------------------------------------------------
# Local builders.
# ---------------------------------------------------------------------------


def _architecture_for(threats: dict) -> dict:
    """An architecture declaring exactly the boundaries the threats name.

    The register spells boundaries `TB-n`; §4.2 spells them `tb-internet`. A
    fixture using §4.2's ids would leave every golden threat dangling and every
    run would be measuring that mismatch rather than the property under test.
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


@pytest.fixture(autouse=True)
def plugin_state_root(tmp_path, monkeypatch) -> Path:
    """Redirect plugin-owned state into `tmp_path`.

    Without this every run resolves the *real* per-user state root. Two reasons
    that is unacceptable here: N28 turns on which root a confirmation is read
    from, so the test must own that root rather than hope it is empty; and a
    test suite has no business reading or writing a developer's home directory.
    """

    state = tmp_path / "plugin-state"
    monkeypatch.setenv("SECURITY_REQUIREMENTS_DATA", str(state))
    monkeypatch.delenv("CLAUDE_PLUGIN_DATA", raising=False)
    return state


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

    threats = _read_document(store / "threats.yaml")
    _write_document(store / "architecture.yaml", _architecture_for(threats))
    return root


def _read_document(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _write_document(path: Path, document: dict) -> None:
    path.write_text(yaml.safe_dump(document, sort_keys=True), encoding="utf-8")


def _argv(project_root: Path, *extra: str, command: str = "design-review") -> list[str]:
    return [
        command,
        "--project-root",
        str(project_root),
        "--output",
        str(project_root),
        "--risk-appetite",
        APPETITE,
        "--confirmed-at",
        PINNED_STAMP,
        *extra,
    ]


def _confirm_argv(project_root: Path) -> list[str]:
    return _argv(
        project_root,
        "--by",
        "reviewer",
        "--authority",
        "self_declared",
        command="design-review-confirm",
    )


def _artifacts(project_root: Path) -> list[str]:
    """Only the four §4.1 artifacts, so the store fixture is not noise."""

    names = {PREVIEW, REPORT, JSON_REPORT, SUMMARY}
    return sorted(
        path.relative_to(project_root).as_posix()
        for path in project_root.rglob("*")
        if path.is_file() and path.relative_to(project_root).as_posix() in names
    )


def _repository_confirmation(project_root: Path) -> dict:
    """A confirmation block that is *shaped* right and sourced wrong.

    Every field `risk._base_confirmation_problems` requires is present and
    internally consistent, including the project identity. Nothing about the
    content is wrong; the only thing wrong with it is where it lives. A weaker
    block would let the run reject it for some incidental defect and the test
    would pass without exercising the source rule at all.
    """

    return {
        "status": "confirmed",
        "project": str(project_root.resolve()),
        "confirmed_by": "attacker-with-write-access",
        "confirmed_at": PINNED_STAMP,
        "authority": "self_declared",
    }


def _plant_repository_only_confirmation(project_root: Path) -> dict:
    """Write the confirmation into the repository and nowhere else.

    `risk.stamp_assessment` reads the repository side from
    `risk-assessment.yaml:confirmation`, so that is the key an operator or an
    attacker with repository write access would set.
    """

    store = project_root / STORE_DIRNAME
    block = _repository_confirmation(project_root)
    assessment = _read_document(store / "risk-assessment.yaml")
    assessment["confirmation"] = copy.deepcopy(block)
    _write_document(store / "risk-assessment.yaml", assessment)
    return block


def _bind_a_real_confirmation(project_root: Path) -> Path:
    """Confirm the store for real, through the module's own confirm subcommands.

    Not a planted file. `design-review-confirm` runs `check_assessment`, which
    verifies `policy_digest`, `threat_digest`, `assessment_digest` and
    `risk_state_digest` against the documents on disk — so a hand-written record
    at the plugin-owned path is refused, exactly as it should be. Only the real
    gate produces a record those four digests match.

    Called *after* any edit to the store, never before: the whole point of the
    binding is that it stops matching when a document changes.

    `policy-confirm` first, because `stamp_assessment` runs `check_policy` and
    refuses an unconfirmed policy. In-process rather than by subprocess (N36),
    and `--confirmed-at` pinned so nothing here reaches a clock.
    """

    store = project_root / STORE_DIRNAME
    # Required path flags on `confirm`, and produced by a later workflow step
    # that these fixtures do not run. Empty is the honest content: the golden
    # case declares neither.
    for name, empty in (("requirements.yaml", "requirements: []\n"),
                        ("risk-evidence.yaml", "evidence: []\n")):
        if not (store / name).is_file():
            (store / name).write_text(empty, encoding="utf-8")

    common = ["--project-root", str(project_root), "--policy", str(store / "risk-policy.yaml")]
    identity = [
        "--by", "reviewer",
        "--authority", "self_declared",
        "--confirmed-at", PINNED_STAMP,
    ]
    policy_exit = risk_mod.main(["policy-confirm", *common, *identity])
    assert policy_exit == OK, (
        "the fixture must confirm the policy before the assessment; "
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
    assert confirm_exit == OK, (
        f"the fixture must bind a real confirmation; `confirm` exited {confirm_exit}"
    )
    return runtime_paths.confirmation_state_path(project_root, "assessment")


def _empty_threat_model(project_root: Path) -> None:
    """A store whose model is well formed and holds nothing.

    Not a malformed document and not a missing one: `version` is the required
    `0.2.0` and both lists are present and empty. That is the shape a project
    has after intake runs and before any threat is written.
    """

    store = project_root / STORE_DIRNAME
    _write_document(
        store / "threats.yaml",
        {"version": "0.2.0", "profile": "movie-rating-aws", "boundaries": [], "threats": []},
    )
    _write_document(store / "risk-assessment.yaml", {"assessments": []})
    _write_document(store / "architecture.yaml", _architecture_for({"boundaries": []}))


def _reverse_threat_order(project_root: Path) -> list[str]:
    """Put the store's threats in an order that is not their id order.

    Reversal, not a shuffle: the disorder must be reproducible across runs, or
    a determinism failure elsewhere would surface here as a flake.
    """

    store = project_root / STORE_DIRNAME
    threats = _read_document(store / "threats.yaml")
    threats["threats"] = list(reversed(threats["threats"]))
    _write_document(store / "threats.yaml", threats)
    return [record["id"] for record in threats["threats"]]


def _threat_ids_in_order(text: str) -> list[str]:
    """The golden threat ids, in the order the text first mentions each."""

    seen: list[str] = []
    for match in re.findall(r"\bT-\d{2}\b", text):
        if match not in seen:
            seen.append(match)
    return seen


# ---------------------------------------------------------------------------
# N28 — a repository-only confirmation is not a confirmation.
#
# `risk._read_trusted_confirmation` reads only through `_state_target`, which
# resolves under `runtime_paths.plugin_data_root` and passes `safe_path`. The
# repository is not on that path, so a block planted there has no matching
# plugin-owned record. These tests establish that end to end rather than by
# reading the call graph.
# ---------------------------------------------------------------------------


def test_a_repository_only_confirmation_leaves_the_run_unconfirmed(project):
    _plant_repository_only_confirmation(project)

    exit_code = risk_mod.main(_argv(project))

    assert exit_code == OK, (
        "a repository confirmation block is ignored, not a document defect; the "
        f"store is otherwise complete so the run is clean. Got exit {exit_code}"
    )
    assert _artifacts(project) == [PREVIEW], (
        "N28: a confirmation with no matching plugin-owned state is rejected, so "
        "the run is still unconfirmed and N26 applies — the preview and nothing "
        f"else. It wrote {_artifacts(project)}"
    )


def test_a_repository_only_confirmation_does_not_clear_the_unconfirmed_marker(project):
    _plant_repository_only_confirmation(project)

    risk_mod.main(_argv(project))

    content = (project / PREVIEW).read_text(encoding="utf-8")
    assert sdr_artifacts.UNCONFIRMED_MARKER in content, (
        "N28: the preview still says UNCONFIRMED. A reader who cannot tell a "
        "scored draft from a confirmed record acts on the draft, and repository "
        "write access must not be able to remove that word"
    )


def test_a_repository_only_confirmation_publishes_nothing(project):
    _plant_repository_only_confirmation(project)

    risk_mod.main(_argv(project))

    published = [
        path.relative_to(project).as_posix()
        for path in project.rglob("*")
        if path.is_file()
        and path.relative_to(project).as_posix().startswith(PUBLISH_DIRNAME.as_posix())
    ]
    assert published == [], (
        "N28: editing a file inside the repository must not be enough to publish "
        "a risk summary. Asserted by path, because a redacted stub is still a "
        f"published file; found {published}"
    )


def test_design_review_confirm_refuses_a_repository_only_confirmation(project, capsys):
    _plant_repository_only_confirmation(project)

    exit_code = risk_mod.main(_confirm_argv(project))

    assert exit_code == PROBLEMS, (
        "N28: the confirm subcommand needs trusted plugin-owned state. A "
        "repository block is not it, so this refuses with a problem exit (1); "
        f"got {exit_code}"
    )
    assert _artifacts(project) == [], (
        f"a refused confirmation writes nothing at all; it wrote {_artifacts(project)}"
    )
    captured = capsys.readouterr()
    assert "confirmation" in captured.err.lower(), (
        "the refusal names what was missing, so the operator learns the "
        f"repository block was never the source; stderr was {captured.err!r}"
    )


def test_a_properly_bound_confirmation_does_confirm_the_run(project):
    """The contrast case, or the four tests above prove only that nothing works.

    If this run were also unconfirmed, every assertion above would hold for a
    run that simply cannot confirm, and none of them would be about the
    *source* of the confirmation.

    The contrast used to be location alone — the same hand-written block, moved
    to the plugin-owned path. It no longer is: `design-review-confirm` runs
    `check_assessment`, so a planted record is refused for a second, independent
    reason. Reaching a confirmed run now means running the real gate, which
    makes the four N28 negatives strictly stronger: a repository-only
    confirmation is rejected both for its source and for its binding.
    """

    _bind_a_real_confirmation(project)

    exit_code = risk_mod.main(_confirm_argv(project))

    assert exit_code == OK, (
        f"the golden store with trusted state bound is a clean run; got {exit_code}"
    )
    assert _artifacts(project) == [JSON_REPORT, REPORT], (
        "N27: a confirmation in plugin-owned state writes the authoritative set. "
        "This is the difference the four N28 tests above are measuring; it wrote "
        f"{_artifacts(project)}"
    )


def test_the_trusted_confirmation_is_read_from_outside_the_project(project):
    """The rule stated directly against the path, not inferred from behaviour."""

    _plant_repository_only_confirmation(project)
    target = runtime_paths.confirmation_state_path(project, "assessment")

    assert not target.is_relative_to(project.resolve()), (
        "F21/§7.17: plugin-owned confirmation state lives outside the inspected "
        f"project, so the project cannot write it. It resolved to {target}"
    )
    assert risk_mod._read_trusted_confirmation(project, "assessment") is None, (
        "N28: with a confirmation block in the repository and no plugin-owned "
        "record, the trusted read returns None. Anything else means the "
        "repository is being treated as a confirmation source"
    )


# ---------------------------------------------------------------------------
# N37 — the verdict states the threshold comparison and no artifact overclaims.
# ---------------------------------------------------------------------------

#: Phrasings that cannot occur inside a denial of themselves. "the service is
#: secure" is deliberately absent: it is a substring of the required
#: disclaimer, so forbidding it would make the correct text fail and could only
#: be satisfied by deleting the disclaimer. The denial is asserted separately,
#: by presence, below.
FORBIDDEN_CLAIMS = (
    "approved for release",
    "cleared for release",
    "no security issues",
    "no security findings",
    "poses no risk",
    "risk-free",
    "we attest",
    "we certify",
    "certified",
    "is compliant",
    "fully compliant",
    "meets all security requirements",
    "signed off",
    "sign-off",
    "passed the security review",
    "safe to deploy",
    "safe to release",
)


@pytest.fixture
def artifacts(project, tmp_path) -> dict[str, str]:
    """All four §4.1 artifacts of one golden run, by name.

    The preview comes from an unconfirmed run and the report and JSON from a
    confirmed one, because §4.1 makes those mutually exclusive — an unconfirmed
    run writes the preview *instead of* the authoritative set.

    The publishable summary is assembled through `sdr_artifacts.artifact_entries`
    with `publish_risk_summary` forced on. Every shipped appetite sets it false,
    so no CLI invocation can produce that artifact and a scan driven only
    through `main` would silently cover three artifacts while claiming four.
    """

    risk_mod.main(_argv(project))
    preview = (project / PREVIEW).read_text(encoding="utf-8")

    (project / PREVIEW).unlink()
    _bind_a_real_confirmation(project)
    assert risk_mod.main(_confirm_argv(project)) == OK, "the confirmed run failed"

    published_root = tmp_path / "published"
    published_root.mkdir()
    report = json.loads((project / JSON_REPORT).read_text(encoding="utf-8"))
    entries = sdr_artifacts.artifact_entries(
        report,
        project_root=project,
        output_root=published_root,
        policy={**risk_mod.appetite_policy(APPETITE), "publish_risk_summary": True},
        confirmed=True,
    )
    sdr_artifacts.write_artifacts(entries)
    summary_path = published_root / SUMMARY
    assert summary_path.is_file(), (
        "N37 scans the published summary, so the fixture must actually produce "
        f"one; {published_root} held {sorted(p.name for p in published_root.rglob('*'))}"
    )

    return {
        PREVIEW: preview,
        REPORT: (project / REPORT).read_text(encoding="utf-8"),
        JSON_REPORT: (project / JSON_REPORT).read_text(encoding="utf-8"),
        SUMMARY: summary_path.read_text(encoding="utf-8"),
    }


def test_the_golden_run_really_has_findings_above_the_release_threshold(artifacts):
    """N37's precondition, asserted rather than assumed.

    Every assertion below is about a run with findings over the line. Against a
    clean model they would all pass while testing nothing.
    """

    report = json.loads(artifacts[JSON_REPORT])
    verdict = report["verdict"]

    assert verdict.get("exceeds_threshold") is True, (
        "N37 is about a run that exceeds the release threshold. The golden case "
        f"carries five `high` findings against a `{APPETITE}` threshold; the "
        f"verdict reported {verdict.get('exceeds_threshold')!r}"
    )
    counts = verdict["inherent"]["counts"]
    assert counts["high"] > 0, (
        f"the fixture must carry findings at or above the threshold; counts were {counts}"
    )


def test_the_verdict_states_how_many_findings_are_above_the_threshold(artifacts):
    report = json.loads(artifacts[JSON_REPORT])
    verdict = report["verdict"]
    statement = verdict.get("statement", "")
    counts = verdict["inherent"]["counts"]
    expected = counts["critical"] + counts["high"]

    assert f"{expected} finding(s)" in statement, (
        "N37: with findings above the threshold the verdict says so, and says "
        f"how many. Expected {expected} at or above `{verdict.get('release_threshold_rating')}`; "
        f"the statement read {statement!r}"
    )
    assert str(verdict.get("release_threshold_rating")) in statement, (
        "the verdict names the threshold it compared against, so the number "
        f"means something; the statement read {statement!r}"
    )


@pytest.mark.parametrize("artifact", [PREVIEW, REPORT, JSON_REPORT])
def test_every_artifact_carrying_a_verdict_carries_the_disclaimer(artifacts, artifact):
    """The presence half of N37.

    Forbidding "the service is secure" outright is the trap: it is a substring
    of the disclaimer, so the scan flags the correct text. The denial is
    asserted by presence instead, and only unambiguous claims are forbidden.
    """

    text = artifacts[artifact]

    assert sdr_report.NEVER_ASSERT_SECURE in text, (
        f"F14/N37: {artifact} carries the verdict, so it carries "
        f"{sdr_report.NEVER_ASSERT_SECURE!r}. Without it the reader has a rating "
        "and no statement of what the rating is not"
    )


def test_no_artifact_asserts_the_service_is_approved_secure_or_compliant(artifacts):
    """The forbidden half of N37, over all four §4.1 artifacts at once.

    Collected rather than asserted one at a time: a per-phrase `assert` reports
    the first violation and hides the rest, and the question a reviewer asks is
    "what does this run claim", not "what is the alphabetically first thing it
    claims".
    """

    violations = [
        (artifact, phrase)
        for artifact, text in sorted(artifacts.items())
        for phrase in FORBIDDEN_CLAIMS
        if phrase in text.lower()
    ]

    assert violations == [], (
        "N37: no artifact may assert the service is secure, safe, compliant or "
        "approved. This run has findings above the release threshold, so every "
        "phrase below is a claim the evidence does not support. Found "
        f"{violations}"
    )


def test_the_published_summary_carries_the_never_assert_secure_disclaimer(artifacts):
    """RED — a gap N37 does not demand, in the artifact that most needs it.

    N37 as written asks only for the forbidden-word scan here, and the scan
    passes: the published summary claims nothing. But it is the one artifact
    that leaves the building, and the only one a non-security reader ever sees
    — a rating table headed "Public risk summary" with `Overall | high` and no
    statement of what it is not.

    Silence is not neutral on that page. The three sensitive artifacts each say
    "This is not an approval, attestation, or claim that the service is secure"
    to a reader who already knows; the summary says it to nobody, and a
    published document from a security review, carrying a rating and no
    disclaimer, is read as the review's verdict on whether to ship.

    Left red deliberately. `render_public_summary` is `EXISTS` in §10 and N37
    does not reach this far, so closing it is a decision, not a bug fix — but
    an untested gap in the publish boundary is how §4.1's five prior leaks got
    there.
    """

    assert sdr_report.NEVER_ASSERT_SECURE in artifacts[SUMMARY], (
        "F14/F15: the publishable artifact carries the same disclaimer as the "
        "sensitive ones. It is the only artifact its readers will see, and it "
        f"currently states a rating and nothing else. It read:\n{artifacts[SUMMARY]}"
    )


def test_the_published_summary_states_the_overall_rating_it_measured(artifacts):
    """The publishable artifact reports the finding, not an absence of findings."""

    report = json.loads(artifacts[JSON_REPORT])
    overall = report["verdict"]["inherent"]["overall"]

    assert overall in artifacts[SUMMARY], (
        "F15/N37: the artifact that leaves the building states the aggregate it "
        f"measured. Expected the overall rating {overall!r} in the published "
        f"summary; it read {artifacts[SUMMARY]!r}"
    )


# ---------------------------------------------------------------------------
# N38 — an empty threat model is a valid run with an honest report.
# ---------------------------------------------------------------------------


@pytest.fixture
def empty_model_report(project) -> dict:
    """The §4.2 record of a confirmed run over a store with no threats.

    Confirmed, because the JSON artifact is where `overall` and `coverage` are
    legible; an unconfirmed run writes only the preview.
    """

    _empty_threat_model(project)
    _bind_a_real_confirmation(project)
    assert risk_mod.main(_confirm_argv(project)) == OK, (
        "N38: an empty threat model is a valid run. If this fails the remaining "
        "assertions cannot distinguish a missing report from a wrong one"
    )
    return json.loads((project / JSON_REPORT).read_text(encoding="utf-8"))


def test_an_empty_threat_model_is_a_valid_run_and_not_an_error(project, capsys):
    _empty_threat_model(project)

    exit_code = risk_mod.main(_argv(project))

    captured = capsys.readouterr()
    assert exit_code == OK, (
        "N38: a project that has modelled no threats yet is not a broken "
        "project. Exiting non-zero would make the design review unusable at the "
        f"exact moment a team most needs it; got {exit_code} with stderr "
        f"{captured.err!r}"
    )
    assert _artifacts(project) == [PREVIEW], (
        "N38: the run produces a report rather than nothing, so the reader "
        f"learns that nothing was modelled; it wrote {_artifacts(project)}"
    )


def test_an_empty_threat_model_produces_zero_findings(empty_model_report):
    assert empty_model_report["findings"] == [], (
        "N38: zero threats means zero findings. A finding with no threat behind "
        f"it would be invented; got {empty_model_report['findings']!r}"
    )


def test_an_empty_threat_model_is_undetermined_rather_than_clean(empty_model_report):
    inherent = empty_model_report["verdict"]["inherent"]

    assert inherent.get("overall") == "UNDETERMINED", (
        "N38: with nothing modelled the overall rating is UNDETERMINED. Any "
        "rating on the scale would claim the review measured something; got "
        f"{inherent.get('overall')!r}"
    )


def test_an_empty_threat_model_reports_zero_of_zero_coverage(empty_model_report):
    inherent = empty_model_report["verdict"]["inherent"]

    assert inherent.get("coverage") == "0/0", (
        "N38: coverage is `0/0` — nothing assessed out of nothing modelled. A "
        "blank or absent coverage reads as 'not applicable' rather than 'not "
        f"done'; got {inherent.get('coverage')!r}"
    )


def test_an_empty_threat_model_records_that_nothing_was_modelled(empty_model_report):
    """The limitation N38 requires, and the one that is not boilerplate.

    Every run records "static, local, read-only analysis" whatever it found, so
    asserting only that `limitations` is non-empty passes for every run ever
    made and tests nothing. N38 asks for a limitation about *this* run: the
    model was empty. Without it the reader of an empty-model review sees a
    verdict reading "0 finding(s) at or above the release threshold" and a
    register with no rows — which is indistinguishable from a service that was
    reviewed thoroughly and found clean.
    """

    limitations = empty_model_report["limitations"]
    assert isinstance(limitations, list) and limitations, (
        f"§4.2 carries a `limitations` list; got {limitations!r}"
    )

    matched = [
        item
        for item in limitations
        if isinstance(item, str)
        and any(
            token in item.lower()
            for token in ("no threats", "empty threat", "threat model is empty",
                          "nothing was modelled", "no threat was modelled",
                          "zero threats", "no threat model")
        )
    ]
    assert matched, (
        "N38 requires a limitation recorded for the empty model. None of the "
        f"{len(limitations)} limitation(s) says the model held no threats: "
        f"{limitations!r}. The generic static-analysis disclaimer is present on "
        "every run and cannot carry this meaning"
    )


def test_the_empty_model_preview_does_not_read_like_a_clean_review(project):
    """The reader-facing half. The JSON says UNDETERMINED; the preview must too.

    `overall` and `coverage` live in the JSON record, which an unconfirmed run
    never writes. The preview is the only artifact an unconfirmed run produces,
    so if it does not carry the UNDETERMINED verdict, the entire N38 guarantee
    is invisible to the person who reads the output.
    """

    _empty_threat_model(project)
    risk_mod.main(_argv(project))

    content = (project / PREVIEW).read_text(encoding="utf-8")

    assert "UNDETERMINED" in content or "0/0" in content, (
        "N38: the preview of an empty model states that the review is "
        "undetermined or that coverage is 0/0. As written it reports "
        "'0 finding(s) at or above the release threshold', which is the same "
        "sentence a thoroughly-reviewed clean service gets. The preview read:\n"
        f"{content}"
    )


# ---------------------------------------------------------------------------
# N41 — ordering is `order_requirements` and nothing else.
#
# §4.3: "Delegated to `risk.py:order_requirements` ... No renderer sorts."
# Two halves. The delegation is asserted positively; the absence of a second
# orderer can only be asserted by feeding a renderer disorder and watching
# whether it survives.
# ---------------------------------------------------------------------------


def _unordered_requirements() -> dict:
    """Two requirements for one threat, in an order `order_requirements` reverses.

    `REQ-A` is first in the document and ranks second, because
    `order_requirements` reads `managed.priority` and `high` outranks `low`.
    A caller that took the document order would pick `REQ-A`; one that delegates
    picks `REQ-B`. Any tie between them would make the test undecidable.
    """

    return {
        "version": "0.1.0",
        "requirements": [
            {
                "id": "REQ-A",
                "statement": "movie-service MUST rate-limit anonymous reads.",
                "rationale": "Document order, low priority.",
                "sources": ["SC-5"],
                "threat_refs": ["T-01"],
                "responsibility": "team",
                "managed": {"priority": "low"},
                "verification": {"method": "test_case", "expect": "429"},
            },
            {
                "id": "REQ-B",
                "statement": "movie-service MUST reject unauthenticated writes.",
                "rationale": "Ranks first, listed second.",
                "sources": ["AC-3"],
                "threat_refs": ["T-01"],
                "responsibility": "team",
                "managed": {"priority": "high"},
                "verification": {"method": "test_case", "expect": "401"},
            },
        ],
    }


def test_the_report_delegates_requirement_ordering_to_order_requirements(project):
    """The positive half of N41: the choke point is actually called."""

    store = project / STORE_DIRNAME
    requirements = _unordered_requirements()
    documents = {
        "policy": risk_mod.appetite_policy(APPETITE),
        "threats": _read_document(store / "threats.yaml"),
        "assessment": _read_document(store / "risk-assessment.yaml"),
        "requirements": requirements,
        "architecture": _read_document(store / "architecture.yaml"),
        "attack_paths": None,
    }
    expected = risk_mod.order_requirements(requirements["requirements"])[0]["id"]
    assert expected == "REQ-B", (
        "fixture drift: the two requirements must rank in the opposite order to "
        f"the document, or nothing is being measured; order_requirements led with {expected!r}"
    )

    report = sdr_report.build_report(
        documents,
        entry={"run": {"mode": "quick", "profile": {}, "critical_facts": []}},
        scope_record={},
        risk_appetite=APPETITE,
        invocation={"timestamp": PINNED_STAMP},
    )

    chosen = next(
        finding["requirement"]["id"]
        for finding in report["findings"]
        if finding["id"] == "T-01" and "requirement" in finding
    )
    assert chosen == expected, (
        "§4.3/N41: the requirement a finding carries is the first one "
        "`order_requirements` returns, not the first one the document lists. "
        f"Expected {expected!r}, got {chosen!r} — which is document order, so "
        "the ordering choke point was bypassed"
    )


def test_the_rendered_register_reproduces_the_order_it_is_given(project):
    """The negative half of N41, at the renderer, in isolation.

    `render_register` is handed findings in an order no sort would produce. If
    the output order differs from the input order the renderer sorted, and §4.3's
    "No renderer sorts" is false.
    """

    findings = [
        {"threat_id": "T-99", "id": "T-99", "scenario": "listed first"},
        {"threat_id": "T-01", "id": "T-01", "scenario": "listed second"},
        {"threat_id": "T-50", "id": "T-50", "scenario": "listed third"},
    ]
    given = [record["threat_id"] for record in findings]

    rendered = risk_mod.render_register({"risks": copy.deepcopy(findings)})

    assert _threat_ids_in_order(rendered) == given, (
        "§4.3/N41: ordering is delegated to `order_requirements` and no renderer "
        "sorts, so a renderer reproduces the disorder it is given. "
        f"`render_register` was given {given} and emitted "
        f"{_threat_ids_in_order(rendered)} — it is a second orderer, and the "
        "§4.3 guarantee that ordering has one choke point does not hold"
    )


def test_the_json_findings_and_the_rendered_register_present_one_order(project):
    """The consequence, end to end: one run must not publish two orders.

    This assertion is neutral about *which* order is right. Whatever order the
    §4.2 record chose, the human-readable register renders that record and must
    show the same sequence. Two orders for one run means a reader comparing the
    document against the JSON cannot line them up, and "the top finding" names
    two different threats depending on which artifact was opened.
    """

    document_order = _reverse_threat_order(project)
    _bind_a_real_confirmation(project)
    assert risk_mod.main(_confirm_argv(project)) == OK, "the confirmed run failed"

    report = json.loads((project / JSON_REPORT).read_text(encoding="utf-8"))
    json_order = [finding["id"] for finding in report["findings"]]
    register_order = _threat_ids_in_order(
        (project / REPORT).read_text(encoding="utf-8")
    )

    # Non-vacuity, restated. This guard originally required the report to carry
    # the store's order, which held only while nothing ordered findings at all.
    # `sdr_report.order_findings` now applies §4.3 — rating rank, score
    # descending, then id — so the report legitimately reorders the store. What
    # still has to be true is that there is something to disagree about: more
    # than one finding, and an order that is not the trivial one both artifacts
    # would reach by accident.
    assert len(json_order) > 1, (
        "one finding cannot be presented in two orders; this comparison needs "
        f"several. The report carried {json_order}"
    )
    assert json_order != document_order, (
        "the report is expected to reorder the store under §4.3. If it carries "
        "the store's order unchanged, `order_findings` is not running and this "
        f"test is comparing two copies of the same list. Store held "
        f"{document_order}, report carried {json_order}"
    )
    assert register_order == json_order, (
        "§4.3/N41: the register renders the report and adds no ordering of its "
        f"own. {JSON_REPORT} lists {json_order} and {REPORT} lists "
        f"{register_order}. One run is presenting its findings in two orders"
    )


def test_the_published_summary_orders_ratings_by_policy_and_not_by_data():
    """The one ordering a renderer may impose is a constant, not a sort.

    `render_public_summary` emits a rating row per `risk.RATINGS`, which is a
    fixed most-severe-first constant. That is not a second orderer — it does not
    depend on the data — and asserting it pins the distinction N41 draws.
    """

    summary = risk_mod.render_public_summary(
        {
            "inherent": {
                "overall": "high",
                "counts": {"critical": 0, "high": 5, "medium": 3, "low": 0},
                "coverage": "8/8",
            }
        },
        {**risk_mod.appetite_policy(APPETITE), "publish_risk_summary": True},
    )
    assert summary is not None, "the fixture opts publication in, so a summary is rendered"

    emitted = [
        rating
        for rating in re.findall(r"^\| (\w+) \| \d+ \|$", summary, flags=re.MULTILINE)
    ]
    assert emitted == list(risk_mod.RATINGS), (
        "§4.3: the public summary's rating rows follow the `RATINGS` constant, "
        "most-severe-first, whatever the counts are. A data-dependent order here "
        f"would be a second orderer. Expected {list(risk_mod.RATINGS)}, got {emitted}"
    )
