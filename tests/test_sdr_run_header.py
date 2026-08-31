"""§4.2 — the `run` header states facts instead of nulls.

Plan of record: `docs/design-review/security-design-review-plan.md` §4.2 (the
`run.repo` and `run.plugin_version` fields), §8's row for a detached HEAD or a
non-git tree, N36 (no subprocess), and `docs/design-review/design-review-runner-contract.md`
§7, which called all three of these trivial or small and then did not do them.

    "repo": { "branch": "main", "commit": "19c5c41", "dirty": false }

**Why this is worth a file of its own.** `repo.dirty` is permanently `null`,
and the argument for that is a good one: computing it needs a worktree-vs-index
diff, N36 forbids the subprocess that would answer it, and a report claiming
`"dirty": false` on a dirty tree is worse than one declining to answer —
because a reader uses that field to decide whether the commit id means
anything.

That argument only holds if there *is* a commit id. Today `branch` and `commit`
are `null` too, so the whole `repo` block tells a reader nothing at all, and
`plugin_version` is `null` in a document whose purpose is to be a record. Both
are readable without a subprocess: git writes the branch into `.git/HEAD` and
the sha into the ref that HEAD names, and the version is in the shipped
`plugin.json`.

Pinned contract under specification:

    sdr_entry.repository_head(project_root) -> dict
        {"branch": str | None, "commit": str | None}. Read from `.git`
        directly — no subprocess (N36). `None` for whatever genuinely cannot
        be determined, never a guess.

    sdr_entry.plugin_version() -> str | None
        The shipped payload's version, read from its own manifest.

Every "is populated" assertion below is paired with the value it must equal,
read independently from the same files git wrote. Asserting only that a field
is non-null would pass for a field filled with the wrong repository.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
PLUGIN_ROOT = REPO_ROOT / "plugins" / "security-requirements"
PLUGIN_SCRIPTS = PLUGIN_ROOT / "scripts"
if str(PLUGIN_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(PLUGIN_SCRIPTS))

import sdr_entry  # noqa: E402

MANIFEST = PLUGIN_ROOT / ".claude-plugin" / "plugin.json"

#: A full sha is 40 hex characters. Nothing here abbreviates one: an
#: abbreviation is ambiguous across repositories and a reader pasting it into
#: `git show` deserves the whole thing.
SHA_LENGTH = 40


def _attr(name: str):
    value = getattr(sdr_entry, name, None)
    assert callable(value), (
        f"`sdr_entry.{name}` is part of the §4.2 run-header contract; the "
        f"runner contract §7 lists it as unimplemented. found {value!r}"
    )
    return value


def _git_repository(root: Path, *, branch: str = "main", sha: str = "a" * SHA_LENGTH):
    """A `.git` directory in the shape git writes, without running git.

    Hand-built rather than shelled out: N36 bans the subprocess, and a fixture
    that used one would test a different code path from the one under test.
    """

    git = root / ".git"
    (git / "refs" / "heads").mkdir(parents=True)
    (git / "HEAD").write_text(f"ref: refs/heads/{branch}\n", encoding="utf-8")
    (git / "refs" / "heads" / branch).write_text(f"{sha}\n", encoding="utf-8")
    return git


# ---------------------------------------------------------------------------
# The branch and the commit, from the files git maintains.
# ---------------------------------------------------------------------------


def test_the_branch_and_commit_are_read_from_the_git_directory(tmp_path):
    project = tmp_path / "checkout"
    project.mkdir()
    _git_repository(project, branch="release/2026-08", sha="b" * SHA_LENGTH)

    head = _attr("repository_head")(project)

    assert head.get("branch") == "release/2026-08", (
        "the branch name is written into `.git/HEAD` and needs no subprocess to "
        f"read; got {head.get('branch')!r}"
    )
    assert head.get("commit") == "b" * SHA_LENGTH, (
        "the sha is in the ref HEAD names. Without it the `repo` block states "
        "nothing, and the argument for leaving `dirty` null — that a reader "
        "uses it to judge whether the commit id means anything — has no commit "
        f"id to be about; got {head.get('commit')!r}"
    )


def test_a_branch_name_containing_a_slash_is_read_whole(tmp_path):
    """`refs/heads/feature/x` is one branch, not a path to split on."""

    project = tmp_path / "checkout"
    project.mkdir()
    _git_repository(project, branch="feature/nested/name")

    head = _attr("repository_head")(project)

    assert head.get("branch") == "feature/nested/name", (
        f"a slash is legal in a branch name; got {head.get('branch')!r}"
    )


def test_a_detached_head_reports_the_commit_and_no_branch(tmp_path):
    """§8: metadata records what exists.

    A detached HEAD has a commit and genuinely has no branch. `None` is the
    honest answer; inventing "HEAD" or "detached" would put a branch name in
    the record that no `git checkout` would find.
    """

    project = tmp_path / "checkout"
    project.mkdir()
    git = project / ".git"
    git.mkdir()
    (git / "HEAD").write_text("c" * SHA_LENGTH + "\n", encoding="utf-8")

    head = _attr("repository_head")(project)

    assert head.get("commit") == "c" * SHA_LENGTH, (
        f"a detached HEAD holds the sha directly; got {head.get('commit')!r}"
    )
    assert head.get("branch") is None, (
        "there is no branch to name, and a placeholder would be a fact nobody "
        f"established; got {head.get('branch')!r}"
    )


def test_a_packed_ref_still_yields_the_commit(tmp_path):
    """A freshly cloned repository has no loose ref file for its branch."""

    project = tmp_path / "checkout"
    project.mkdir()
    git = project / ".git"
    git.mkdir()
    (git / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (git / "packed-refs").write_text(
        "# pack-refs with: peeled fully-peeled sorted \n"
        f"{'d' * SHA_LENGTH} refs/heads/main\n"
        f"{'e' * SHA_LENGTH} refs/remotes/origin/main\n",
        encoding="utf-8",
    )

    head = _attr("repository_head")(project)

    assert head.get("branch") == "main"
    assert head.get("commit") == "d" * SHA_LENGTH, (
        "the loose ref is absent after a clone and `packed-refs` carries the "
        f"sha; got {head.get('commit')!r}"
    )


def test_a_tree_that_is_not_a_repository_reports_neither(tmp_path):
    """§8: absent git → the fields say so rather than guessing."""

    project = tmp_path / "not-a-repo"
    project.mkdir()

    head = _attr("repository_head")(project)

    assert head == {"branch": None, "commit": None}, (
        "a directory that is not a repository has no branch and no commit. "
        f"Both stated as null, neither omitted; got {head!r}"
    )


def test_repository_head_never_raises_on_a_damaged_git_directory(tmp_path):
    for name, contents in (
        ("empty-head", ""),
        ("garbage-head", "not a ref and not a sha\n"),
        ("dangling-ref", "ref: refs/heads/gone\n"),
    ):
        project = tmp_path / name
        (project / ".git").mkdir(parents=True)
        (project / ".git" / "HEAD").write_text(contents, encoding="utf-8")
        try:
            head = _attr("repository_head")(project)
        except Exception as exc:  # noqa: BLE001 - the point of the test
            pytest.fail(f"{name} raised {exc!r}; a review reports what it could read")
        assert set(head) == {"branch", "commit"}, (
            f"{name} returned {head!r}; both keys are always present"
        )


def test_repository_head_runs_no_subprocess(tmp_path, monkeypatch):
    """N36. `git rev-parse` would be the obvious implementation and is banned."""

    import subprocess

    def _refuse(*args, **kwargs):
        raise AssertionError(
            "the run made a subprocess call. N36 forbids it, which is why the "
            "branch and sha are read from `.git` directly"
        )

    for name in ("run", "Popen", "check_output", "call"):
        monkeypatch.setattr(subprocess, name, _refuse)

    project = tmp_path / "checkout"
    project.mkdir()
    _git_repository(project)

    _attr("repository_head")(project)


# ---------------------------------------------------------------------------
# The plugin version, from the shipped manifest.
# ---------------------------------------------------------------------------


def test_the_plugin_version_matches_the_shipped_manifest():
    declared = json.loads(MANIFEST.read_text(encoding="utf-8"))["version"]

    assert _attr("plugin_version")() == declared, (
        "the report records which payload produced it, and the payload states "
        f"its own version in {MANIFEST.name}. A second copy in Python would "
        f"drift from the one that ships; manifest says {declared!r}"
    )


# ---------------------------------------------------------------------------
# End to end: the fields reach the record, and `dirty` still does not.
# ---------------------------------------------------------------------------


def test_a_real_run_records_the_branch_the_commit_and_the_version(tmp_path):
    """The paired presence. Populating the helper is not populating the report."""

    import risk as risk_mod

    project = tmp_path / "inspected project"
    project.mkdir()
    _git_repository(project, branch="main", sha="f" * SHA_LENGTH)

    head = _attr("repository_head")(project)
    assert head["commit"], "fixture check: the helper must find the sha"

    # Driven through the report builder rather than a full run: the run needs a
    # complete store, and what is under test is whether the record carries what
    # the helper found.
    import sdr_report

    record = sdr_report.build_report(
        {"policy": risk_mod.appetite_policy("standard")},
        entry={"run": {"mode": "quick", "profile": {}}},
        scope_record={"included": [], "excluded": [], "scope_filter": None},
        confirmation=None,
        risk_appetite="standard",
        invocation={
            "repo": head,
            "plugin_version": _attr("plugin_version")(),
            "timestamp": "2026-05-01T00:00:00Z",
        },
        today=None,
    )

    repo = record["run"]["repo"]
    assert repo["branch"] == "main", f"the record must carry the branch; got {repo!r}"
    assert repo["commit"] == "f" * SHA_LENGTH, (
        f"the record must carry the commit; got {repo!r}"
    )
    assert record["run"]["plugin_version"], (
        f"the record must carry the payload version; got {record['run']!r}"
    )


def test_dirty_stays_null_even_now_that_the_commit_is_known():
    """The one field that must not be populated.

    Knowing the commit makes it *more* tempting to also state cleanliness, and
    the reason not to is unchanged: computing it needs a worktree-vs-index diff
    and N36 forbids the subprocess. A false `"dirty": false` is worse than
    silence precisely because the commit id beside it now looks authoritative.
    """

    import risk as risk_mod
    import sdr_report

    record = sdr_report.build_report(
        {"policy": risk_mod.appetite_policy("standard")},
        entry={"run": {"mode": "quick", "profile": {}}},
        scope_record={"included": [], "excluded": [], "scope_filter": None},
        confirmation=None,
        risk_appetite="standard",
        invocation={"repo": {"branch": "main", "commit": "a" * SHA_LENGTH}},
        today=None,
    )

    repo = record["run"]["repo"]
    assert repo["dirty"] is None, (
        f"`dirty` is not computable under N36 and must stay null; got {repo!r}"
    )
    assert repo.get("dirty_unknown_reason"), (
        "and the record says why, so a reader does not read the null as false"
    )
