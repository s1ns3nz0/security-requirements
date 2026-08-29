"""N26 / N27 / N29 and the §4.1 publish boundary.

Plan of record: `docs/security-design-review-plan.md` §4.1 (the artifact table
and the one-transaction rule), §11.2 N26–N29, and
`docs/design-review-runner-contract.md` §4 and §6.

    **N26** With no trusted confirmation, the run writes only
    `design-review.preview.md`, marked UNCONFIRMED, and no publishable artifact.
    **N27** `design-review-confirm` with a passing gate writes the authoritative
    set; without one it refuses.
    **N29** Any binding or document-integrity error suppresses **all** rendered
    output, so untrusted material is never presented as a calculated result.

**This is the disclosure boundary.** §4.1 records that `status`, `exception`,
`expiry`, threat ids, and `retired_reason` have *each* leaked across it once and
been fixed — five separate incidents on one seam. These tests are written as if
a sixth is coming, which is why every publish-boundary assertion below is about
a **path** rather than about content. A redacted stub in `docs/security/` is
still a published file, and §4.1 says the file is not written at all.

Pinned contract under specification. `scripts/sdr_artifacts.py` does **not**
exist, so every test here is RED by construction and fails by *name*:

    artifact_entries(report, *, project_root, output_root, policy, confirmed,
                     problems=(), evidence_problems=()) -> list[tuple]
        The `(path, root, content, create_parents)` tuples for one run, in the
        shape `risk._write_text_transaction` already takes. `[]` means
        "write nothing".

        `problems` and `evidence_problems` are what N29 gates on. They are
        passed in rather than recomputed because the runner has already
        collected them, and a second collection could disagree with the first.

    write_artifacts(entries) -> None
        Exactly one `_write_text_transaction` call. Never more than one.

Reused rather than restated
---------------------------

`risk.output_allowed(problems, evidence_problems)` is N29's rule, extracted
this session so the residual preview and the design review share one copy. Two
copies agree on the day they are written and diverge on the day one is fixed,
so these tests pin that the artifacts layer *calls* it.

`risk.render_public_summary(summary, policy)` returns `None` unless
`policy["publish_risk_summary"] is True`. The runner adds an entry only when
the return is not `None`; re-deciding publishability here would be a second
opinion about the boundary that has already leaked five times.

`risk._write_text_transaction` refuses key material before writing a byte.
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

import risk as risk_mod  # noqa: E402

ARTIFACTS_MODULE_PATH = PLUGIN_SCRIPTS / "sdr_artifacts.py"

#: `publish.py:1061` `_risk_paths` — the sensitive tree.
STORE_DIRNAME = ".security-requirements"
#: §4.1 — the publishable tree.
PUBLISH_DIRNAME = Path("docs") / "security"

PREVIEW_ARTIFACT = "design-review.preview.md"
AUTHORITATIVE_ARTIFACTS = ("design-review.md", "design-review.json")
PUBLISHABLE_ARTIFACT = "design-review-summary.md"

#: A fake key, shaped to trip `risk.key_material_problems`. Never a real one.
PLANTED_KEY = "AKIAIOSFODNN7EXAMPLE"


def _sdr_artifacts():
    try:
        import sdr_artifacts
    except ImportError as exc:  # pragma: no cover - the RED path
        pytest.fail(
            f"{ARTIFACTS_MODULE_PATH} does not exist yet. §4.1 is the artifact "
            "table and the runner contract §6 puts the artifact set and the "
            "single write transaction in `sdr_artifacts.artifact_entries` and "
            f"`sdr_artifacts.write_artifacts`. import failed: {exc}"
        )
    return sdr_artifacts


def _entries_fn():
    module = _sdr_artifacts()
    builder = getattr(module, "artifact_entries", None)
    assert callable(builder), (
        "sdr_artifacts must expose `artifact_entries(report, *, project_root, "
        "output_root, policy, confirmed, problems, evidence_problems) "
        "-> list[tuple]`; found "
        f"{builder!r}"
    )
    return builder


def _write_fn():
    module = _sdr_artifacts()
    writer = getattr(module, "write_artifacts", None)
    assert callable(writer), (
        "sdr_artifacts must expose `write_artifacts(entries) -> None` making "
        f"exactly one `_write_text_transaction` call; found {writer!r}"
    )
    return writer


# ---------------------------------------------------------------------------
# Fixtures. The report is a stand-in: these tests are about *which files get
# written*, not about the record's contents, which `test_sdr_report.py` owns.
# ---------------------------------------------------------------------------

REPORT = {
    "schema_version": "1.0.0",
    "run": {
        "mode": "quick",
        "confirmed": False,
        "risk_appetite": "standard",
        "scope": {"included": ["cmp-checkout-api"], "excluded": [], "scope_filter": None},
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


def _policy(publish: bool = False) -> dict:
    return {
        "version": "0.1.0",
        "release_threshold_rating": "high",
        "publish_risk_summary": publish,
        "thresholds": {},
    }


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "inspected project"
    root.mkdir()
    return root


def _entries(project_root: Path, **overrides):
    kwargs = {
        "project_root": project_root,
        "output_root": project_root,
        "policy": _policy(),
        "confirmed": False,
        "problems": [],
        "evidence_problems": [],
    }
    kwargs.update(overrides)
    report = kwargs.pop("report", None) or _report()
    entries = _entries_fn()(report, **kwargs)
    assert isinstance(entries, list), (
        "artifact_entries returns a list of `_write_text_transaction` tuples; "
        f"got {type(entries)!r}"
    )
    for entry in entries:
        assert isinstance(entry, tuple) and len(entry) == 4, (
            "each entry is the 4-tuple `_write_text_transaction` takes: "
            f"(path, root, content, create_parents); got {entry!r}"
        )
    return entries


def _relative_paths(entries, root: Path) -> list[str]:
    """Written paths, relative to the output root, with forward slashes."""

    written = []
    for path, _root, _content, _create in entries:
        written.append(Path(path).resolve().relative_to(root.resolve()).as_posix())
    return written


def _content_of(entries, name: str) -> str:
    for path, _root, content, _create in entries:
        if Path(path).name == name:
            return content
    raise AssertionError(
        f"no entry named {name!r}; entries were {[Path(p).name for p, *_ in entries]}"
    )


# ---------------------------------------------------------------------------
# N26 — no trusted confirmation: the preview, and nothing else.
# ---------------------------------------------------------------------------


def test_an_unconfirmed_run_writes_the_preview(project):
    written = _relative_paths(_entries(project, confirmed=False), project)

    assert f"{STORE_DIRNAME}/{PREVIEW_ARTIFACT}" in written, (
        f"N26: an unconfirmed run writes {PREVIEW_ARTIFACT} into the sensitive "
        f"tree; got {written}"
    )


def test_an_unconfirmed_run_writes_no_authoritative_artifact(project):
    written = _relative_paths(_entries(project, confirmed=False), project)

    for name in AUTHORITATIVE_ARTIFACTS:
        assert f"{STORE_DIRNAME}/{name}" not in written, (
            f"N26: {name} is authoritative and requires a trusted confirmation. "
            f"An unconfirmed run must not produce it; got {written}"
        )


def test_an_unconfirmed_run_writes_nothing_into_the_publishable_tree(project):
    written = _relative_paths(_entries(project, confirmed=False), project)

    published = [path for path in written if path.startswith(PUBLISH_DIRNAME.as_posix())]
    assert published == [], (
        "N26: an unconfirmed run produces no publishable artifact at all. This "
        "is asserted by path, not by content — a redacted stub under "
        f"{PUBLISH_DIRNAME.as_posix()}/ is still a published file; got {published}"
    )


def test_the_unconfirmed_preview_says_it_is_unconfirmed(project):
    entries = _entries(project, confirmed=False)

    content = _content_of(entries, PREVIEW_ARTIFACT)
    assert "UNCONFIRMED" in content, (
        "N26 requires the preview to be *marked* UNCONFIRMED. A preview that "
        "reads like a finished review is the disclosure failure — a reader "
        "cannot tell a scored draft from a confirmed one; content began "
        f"{content[:200]!r}"
    )


# ---------------------------------------------------------------------------
# N27 — a passing gate writes the authoritative set.
# ---------------------------------------------------------------------------


def test_a_confirmed_run_writes_the_authoritative_set(project):
    written = _relative_paths(_entries(project, confirmed=True), project)

    for name in AUTHORITATIVE_ARTIFACTS:
        assert f"{STORE_DIRNAME}/{name}" in written, (
            f"N27: a confirmed run writes {name}; got {written}"
        )


def test_a_confirmed_run_writes_the_json_report_as_parseable_json(project):
    import json

    entries = _entries(project, confirmed=True)

    content = _content_of(entries, "design-review.json")
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError as exc:
        pytest.fail(f"design-review.json must be parseable JSON; {exc}")
    assert parsed.get("schema_version") == REPORT["schema_version"], (
        "the JSON artifact is the §4.2 record itself, not a rendering of it; "
        f"got {parsed.get('schema_version')!r}"
    )


def test_a_confirmed_run_does_not_also_write_the_preview(project):
    written = _relative_paths(_entries(project, confirmed=True), project)

    assert f"{STORE_DIRNAME}/{PREVIEW_ARTIFACT}" not in written, (
        "the preview is what a run produces *instead of* the authoritative set. "
        "Writing both leaves two documents describing one run, and a reader "
        f"with the stale one cannot tell; got {written}"
    )


# ---------------------------------------------------------------------------
# §4.1 — the publish boundary.
# ---------------------------------------------------------------------------


def test_a_confirmed_run_publishes_the_summary_when_the_policy_opts_in(project):
    written = _relative_paths(
        _entries(project, confirmed=True, policy=_policy(publish=True)), project
    )

    assert (PUBLISH_DIRNAME / PUBLISHABLE_ARTIFACT).as_posix() in written, (
        "§4.1: with `publish_risk_summary: true` and a confirmation, the "
        f"summary is written to {PUBLISH_DIRNAME.as_posix()}/; got {written}"
    )


def test_a_confirmed_run_publishes_nothing_when_the_policy_does_not_opt_in(project):
    written = _relative_paths(
        _entries(project, confirmed=True, policy=_policy(publish=False)), project
    )

    published = [path for path in written if path.startswith(PUBLISH_DIRNAME.as_posix())]
    assert published == [], (
        "§4.1: `publish_risk_summary: false` is the default and means the "
        "summary is **not written at all** — not written redacted, not written "
        "empty. `render_public_summary` returns None rather than a stub for "
        f"the same reason; got {published}"
    )


def test_a_policy_that_omits_the_publish_flag_publishes_nothing(project):
    policy = _policy()
    del policy["publish_risk_summary"]

    written = _relative_paths(
        _entries(project, confirmed=True, policy=policy), project
    )

    published = [path for path in written if path.startswith(PUBLISH_DIRNAME.as_posix())]
    assert published == [], (
        "publication is opt-in. An absent flag is not consent, and defaulting "
        f"it to true would publish on any policy that forgot to say no; got {published}"
    )


def test_the_publish_decision_is_render_public_summary_and_not_a_second_opinion(
    project, monkeypatch
):
    """The boundary is decided in one place, or it is decided in two."""

    calls = []
    original = risk_mod.render_public_summary

    def _spy(summary, policy):
        calls.append(policy)
        return original(summary, policy)

    monkeypatch.setattr(risk_mod, "render_public_summary", _spy)

    _entries(project, confirmed=True, policy=_policy(publish=True))

    assert calls, (
        "`render_public_summary` returns None unless the policy opts in, so it "
        "is the publishability decision. Re-deciding it here gives the "
        "boundary two opinions that can drift — and §4.1 records five leaks "
        "across this seam already."
    )


# ---------------------------------------------------------------------------
# N29 — a suppressed run writes nothing at all.
# ---------------------------------------------------------------------------


def test_a_suppressed_run_writes_nothing_including_the_preview(project):
    entries = _entries(
        project,
        confirmed=False,
        problems=["T-09 binding mismatch"],
        evidence_problems=[],
    )

    assert entries == [], (
        "N29: 'any binding or document-integrity error suppresses **all** "
        "rendered output'. All of it — a suppressed run that still writes a "
        "preview presents untrusted material as a calculated result, which is "
        f"the exact failure; got {entries!r}"
    )


def test_a_suppressed_confirmed_run_writes_nothing_either(project):
    entries = _entries(
        project,
        confirmed=True,
        problems=["threat document digest does not match the confirmation"],
        evidence_problems=[],
    )

    assert entries == [], (
        "a confirmation does not override N29. The confirmation binds the "
        "documents; a document-integrity error means the documents are not "
        f"what was bound; got {entries!r}"
    )


def test_the_suppression_decision_uses_the_shared_output_allowed_rule(
    project, monkeypatch
):
    """One rule, two callers — not two copies that drift."""

    calls = []
    original = risk_mod.output_allowed

    def _spy(problems, evidence_problems):
        calls.append((list(problems), list(evidence_problems)))
        return original(problems, evidence_problems)

    monkeypatch.setattr(risk_mod, "output_allowed", _spy)

    _entries(
        project,
        confirmed=False,
        problems=["T-09 binding mismatch"],
        evidence_problems=[],
    )

    assert calls, (
        "`risk.output_allowed` is N29's rule, extracted so the residual "
        "preview and the design review share one copy. Reimplementing the "
        "condition here means two copies that agree today and diverge the day "
        "one of them is fixed."
    )


def test_stale_evidence_alone_does_not_suppress_the_preview(project):
    """The other half of `output_allowed`: an UNDETERMINED preview still renders."""

    entries = _entries(
        project,
        confirmed=False,
        problems=["EV-1 evidence expired"],
        evidence_problems=["EV-1 evidence expired"],
    )

    written = _relative_paths(entries, project)
    assert f"{STORE_DIRNAME}/{PREVIEW_ARTIFACT}" in written, (
        "invalid or stale evidence may still render an UNDETERMINED preview — "
        "the reader learns the evidence expired, which is the answer. Only a "
        f"binding or integrity error suppresses everything; got {written}"
    )


# ---------------------------------------------------------------------------
# §4.1 — one transaction, and `--output` moving both trees.
# ---------------------------------------------------------------------------


def test_write_artifacts_makes_exactly_one_transaction(project, monkeypatch):
    calls = []

    def _spy(entries, **kwargs):
        calls.append(list(entries))

    monkeypatch.setattr(risk_mod, "_write_text_transaction", _spy)

    _write_fn()(_entries(project, confirmed=True, policy=_policy(publish=True)))

    assert len(calls) == 1, (
        "§4.1: every artifact of a run is written as **one unit**. Two "
        "transactions can leave a published summary beside a missing sensitive "
        f"report, which is a disclosure bug rather than an inconvenience; "
        f"made {len(calls)} calls"
    )


def test_write_artifacts_passes_every_entry_to_the_one_transaction(
    project, monkeypatch
):
    calls = []
    monkeypatch.setattr(
        risk_mod, "_write_text_transaction", lambda entries, **kw: calls.append(list(entries))
    )

    entries = _entries(project, confirmed=True, policy=_policy(publish=True))
    _write_fn()(entries)

    assert calls and len(calls[0]) == len(entries), (
        "splitting the set across the boundary defeats the single "
        f"transaction; passed {len(calls[0]) if calls else 0} of {len(entries)}"
    )


def test_the_output_root_moves_both_trees_together(project, tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()

    entries = _entries(
        project,
        output_root=elsewhere,
        confirmed=True,
        policy=_policy(publish=True),
    )

    written = _relative_paths(entries, elsewhere)
    assert f"{STORE_DIRNAME}/{PREVIEW_ARTIFACT}" not in written  # confirmed run
    assert any(path.startswith(STORE_DIRNAME) for path in written), (
        f"§4.1: `--output` overrides the base of the sensitive tree; got {written}"
    )
    assert any(
        path.startswith(PUBLISH_DIRNAME.as_posix()) for path in written
    ), (
        "§4.1: `--output` overrides the base of **both** trees. Moving only one "
        "splits a run across two roots, which is the partial-write failure "
        f"wearing a different hat; got {written}"
    )


def test_no_artifact_escapes_the_output_root(project, tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()

    entries = _entries(
        project,
        output_root=elsewhere,
        confirmed=True,
        policy=_policy(publish=True),
    )

    for path, root, _content, _create in entries:
        resolved = Path(path).resolve()
        assert resolved.is_relative_to(elsewhere.resolve()), (
            f"{resolved} escapes the output root {elsewhere}. `risk.safe_path` "
            "is the existing containment check and every target goes through it"
        )
        assert Path(root).resolve() == elsewhere.resolve(), (
            "each entry names the output root as its containment root, so "
            f"`_write_text_transaction` validates against it; got {root!r}"
        )


# ---------------------------------------------------------------------------
# Key material never reaches disk.
# ---------------------------------------------------------------------------


def test_a_report_carrying_key_material_is_refused_rather_than_written(
    project, tmp_path
):
    report = _report()
    report["limitations"] = [f"Found a credential: {PLANTED_KEY}"]

    entries = _entries(project, report=report, confirmed=True)

    with pytest.raises(risk_mod.RiskValidationError) as excinfo:
        _write_fn()(entries)

    message = str(excinfo.value)
    assert PLANTED_KEY not in message, (
        "the refusal names the artifact and a fingerprint, never the secret "
        f"itself — an error message is written to logs. Message was {message!r}"
    )


def test_the_key_material_refusal_happens_before_any_file_exists(project):
    report = _report()
    report["limitations"] = [f"Found a credential: {PLANTED_KEY}"]

    entries = _entries(project, report=report, confirmed=True)
    with pytest.raises(risk_mod.RiskValidationError):
        _write_fn()(entries)

    survivors = [path for path in project.rglob("*") if path.is_file()]
    assert survivors == [], (
        "`_write_text_transaction` refuses before writing a byte rather than "
        "rolling back after. A rollback still put the credential on disk, "
        "where a backup, an editor swap file, or a filesystem snapshot may "
        f"already have it; found {survivors}"
    )
