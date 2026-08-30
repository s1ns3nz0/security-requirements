#!/usr/bin/env python3
"""The design-review entry wrapper (plan F2/F4, N30/N31).

Plan §2.1 decision 5: the command is post-build internally and a wrapper
externally. With no store it *invokes* the existing `/sec-req-init` ->
`/sec-req-build` pipeline; it never reimplements intake. Reimplementing it
would mean two interviews that drift apart, and the one this module wrote
would be the one nobody reviewed.

`invoke_intake` is injected rather than imported so the invocation is
observable. "Did intake run?" is a question about a *call*, and a wrapper that
had quietly grown its own intake would still return a plausible record.

Nothing here shells out or opens a socket (plan N36). Branch-head staleness is
read from the files git already maintains, not from `git log`.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import risk as risk_mod  # noqa: E402


#: `publish.py:1061` `_risk_paths` — the canonical store directory.
STORE_DIRNAME = ".security-requirements"

#: The documents intake owns: init writes the profile, build writes the
#: threats. This module reads them and writes neither.
INTAKE_OWNED_DOCUMENTS = ("profile.yaml", "threats.yaml")

#: `commands/sec-req-init.md:72` — "Ask the seven questions. Not more."
GUIDED_QUESTION_COUNT = 7

#: The five critical unknowns quick mode asks about (plan §3 Modes). Quick is
#: not "skip the interview"; it is a shorter interview about the five answers
#: that change the threat model, and nothing else.
CRITICAL_UNKNOWNS = (
    "authentication",
    "internet_exposure",
    "sensitive_data",
    "isolation",
    "privileged_access",
)

#: What each mode asks intake for. Named after the interview rather than after
#: the mode, so a reader of the intake call sees what was actually asked.
GUIDED_INTERVIEW_DEPTH = "seven_questions"
QUICK_INTERVIEW_DEPTH = "five_critical_unknowns"

INTERVIEW_DEPTHS = {
    "guided": GUIDED_INTERVIEW_DEPTH,
    "quick": QUICK_INTERVIEW_DEPTH,
}

DEFAULT_MODE = "quick"

#: Plan §3 line 134 / §8 / N8. What quick mode was not told, it inferred, and
#: an inference may not claim more than `low`.
#:
#: Deliberately named for the axis rather than spelled `CONFIDENCE`, because
#: `blast_radius.py:36` already owns that name for a different axis with a
#: disjoint vocabulary (`confirmed` / `inferred` / `unknown`). The two
#: documents never meet — `blast_radius._check_value` runs on blast-radius
#: graph nodes, which a design review never writes — so this is a naming
#: hazard for a maintainer reaching for the wrong constant, not a runtime one.
#: Note also that `inferred` means *certainty of a graph edge* there and *how
#: a fact was established* in `risk.EVIDENCE_STATUSES`; that collision predates
#: this module and is not made worse by it.
REVIEW_CONFIDENCE_LOW = "low"

#: `risk.EVIDENCE_STATUSES` spelling for a fact nobody confirmed.
INFERRED_EVIDENCE_STATUS = "inferred"


def store_present(project_root: Path) -> bool:
    """Whether `project_root` already holds a model to score.

    An empty `.security-requirements/` is not a store. The directory is
    created by several unrelated steps, and treating its existence as a model
    would skip intake for a project that has none — the run would then score
    nothing and report it as a clean review.
    """

    store = Path(project_root) / STORE_DIRNAME
    return all((store / name).is_file() for name in INTAKE_OWNED_DOCUMENTS)


def _branch_head_marker(project_root: Path) -> Path | None:
    """The file git touches when the current branch head moves.

    Read from `.git` directly: N36 bans subprocess execution, so `git log` is
    not available to date the head commit.

    ponytail: this is the ref file's mtime, not the commit's author date. The
    two differ for a clone or a checkout, which stamp every ref at once — the
    ceiling is that a fresh clone reads as "profile older than head" until the
    profile is next written. Parsing the commit object (zlib, then the header)
    would date it exactly, and is the upgrade path if that noise matters.
    """

    git_dir = Path(project_root) / ".git"
    if not git_dir.is_dir():
        return None

    head = git_dir / "HEAD"
    if not head.is_file():
        return None
    try:
        pointer = head.read_text(encoding="utf-8").strip()
    except OSError:
        return None

    if pointer.startswith("ref:"):
        ref = git_dir / pointer.removeprefix("ref:").strip()
        if ref.is_file():
            return ref
        # A packed ref has no file of its own; `packed-refs` is what moved.
        packed = git_dir / "packed-refs"
        return packed if packed.is_file() else head
    # Detached head: HEAD itself holds the sha and is what moves.
    return head


def profile_staleness(project_root: Path) -> dict:
    """Whether `profile.yaml` predates the current branch head (plan §8).

    Reported in both modes, and reported as a stated `False` rather than an
    absent key. "The profile might be stale, we did not look" and "the profile
    is current" are different facts, and a missing key reads as the second.
    """

    profile = Path(project_root) / STORE_DIRNAME / "profile.yaml"
    marker = _branch_head_marker(project_root)
    if not profile.is_file() or marker is None:
        # No profile, or no repository to be stale against. Not stale, because
        # there is nothing it could have fallen behind.
        return {"stale_vs_head": False, "compared_against": None}
    return {
        "stale_vs_head": profile.stat().st_mtime < marker.stat().st_mtime,
        "compared_against": str(marker.name),
    }


def _answered(answers: Mapping, name: str) -> bool:
    """Whether the operator actually said something about `name`.

    `False` and `"no"` are answers. A truthiness test would read "not internet
    facing" as "never asked", which is the exact laundering N8 exists to stop:
    an unknown becoming a stated fact. Only absence, `None`, and an empty
    string or collection count as unanswered.
    """

    if name not in answers:
        return False
    value = answers[name]
    if value is None:
        return False
    if isinstance(value, (str, bytes)) and not value.strip():
        return False
    if isinstance(value, (list, tuple, set, dict)) and not value:
        return False
    return True


def unconfirmed_critical_facts(answers: object) -> list[str]:
    """The critical unknowns the operator never answered, sorted.

    Sorted rather than in `CRITICAL_UNKNOWNS` order so the value is stable
    under any answer ordering (§4.3: no set iteration reaches output).
    """

    if not isinstance(answers, Mapping):
        answers = {}
    return sorted(
        name for name in CRITICAL_UNKNOWNS if not _answered(answers, name)
    )


#: Directories a review reads past rather than into. `.git` holds object
#: files, `.security-requirements` and `docs/security` hold this tool's own
#: output — scanning either would report the review's own quoted findings as
#: fresh repository content on the next run.
SKIPPED_DIRECTORIES = frozenset(
    {
        ".git",
        ".security-requirements",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        "dist",
        "build",
    }
)

#: Bytes. A file larger than this is not prose a reviewer reads, and decoding
#: an arbitrarily large blob to grep it is how a read-only tool becomes a
#: memory problem on somebody's monorepo.
MAX_SCANNED_BYTES = 256 * 1024

#: Findings are reported to a human. Past this many, the list has stopped
#: being a disclosure and become a haystack; the count is reported instead.
MAX_UNTRUSTED_RECORDS = 50


def repository_untrusted_content(project_root: Path) -> list[dict]:
    """Instruction-shaped prose in the repository under review (plan N17).

    A design review reads a repository, so it is the thing that can see an
    instruction planted in one. Scoring the injection correctly is only half
    of N17 — a run that never noticed the README and one that recognised and
    quarantined it produce identical scores, and only the second tells the
    reader their repository carries text aimed at the reviewer.

    Read-only and in-process: no subprocess, no network (N36). Bounded by
    directory, file size and record count, because an unbounded scan of an
    unknown repository is not a thing a review should do to someone's machine.
    """

    import sdr_report

    root = Path(project_root)
    found: list[dict] = []
    for path in sorted(root.rglob("*")):
        if len(found) >= MAX_UNTRUSTED_RECORDS:
            break
        if not path.is_file() or path.is_symlink():
            continue
        if SKIPPED_DIRECTORIES.intersection(path.relative_to(root).parts[:-1]):
            continue
        try:
            if path.stat().st_size > MAX_SCANNED_BYTES:
                continue
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            # Binary, unreadable, or vanished mid-walk. A review reports what
            # it could read and does not fail over what it could not.
            continue
        location = path.relative_to(root).as_posix()
        for record in sdr_report.untrusted_content(text, location):
            if record not in found:
                found.append(record)
    return found


def design_review(
    project_root: Path,
    *,
    argument: str | None = None,
    mode: str = DEFAULT_MODE,
    invoke_intake=None,
    answers: Mapping | None = None,
) -> dict:
    """Run a design review, building the model first only if there is none.

    `argument` is the front door's `<description-or-path>`. With no store it is
    forwarded to intake unchanged; with a store present it selects or refreshes
    the evidence source and intake does not run (plan §3).
    """

    project_root = Path(project_root)
    if mode not in INTERVIEW_DEPTHS:
        raise risk_mod.RiskValidationError(
            f"unknown review mode {mode!r}; expected one of "
            f"{', '.join(sorted(INTERVIEW_DEPTHS))}"
        )

    intake_result = None
    if not store_present(project_root):
        if invoke_intake is None:
            raise risk_mod.RiskValidationError(
                f"{project_root} holds no model under {STORE_DIRNAME}/ and no "
                "intake pipeline was supplied to build one"
            )
        # Exactly one call. The depth is passed alongside the mode rather than
        # derived inside intake, so the interview that ran is recorded here.
        # Nothing gate-relaxing is passed: quick mode is a shorter interview,
        # not a waived confirmation (plan §3).
        intake_result = invoke_intake(
            project_root,
            argument=argument,
            mode=mode,
            interview_depth=INTERVIEW_DEPTHS[mode],
        )
        if not store_present(project_root):
            raise risk_mod.RiskValidationError(
                f"intake ran but wrote no model under {STORE_DIRNAME}/; this "
                "wrapper does not write profile.yaml or threats.yaml itself"
            )

    # Computed after intake, and deliberately not touched by it: intake
    # building a model is not the operator answering a question. A store
    # existing is not evidence about isolation.
    unconfirmed = unconfirmed_critical_facts(answers)

    return {
        "run": {
            "mode": mode,
            "interview_depth": INTERVIEW_DEPTHS[mode],
            # The argument names where evidence came from. Recorded rather than
            # consumed, so a reader of the report can tell a review of
            # ./services/checkout from a review of the whole repository.
            "evidence_source": argument,
            "intake_invoked": intake_result is not None,
            "profile": {
                **profile_staleness(project_root),
                # Plan §4.2 line 193 puts this beside `stale_vs_head`. Always
                # present, `[]` when nothing is unconfirmed: an absent key
                # reads as "nothing to disclose" and an empty list says it.
                "unconfirmed_critical_facts": unconfirmed,
            },
            # The list above says *which* facts are unconfirmed; these records
            # say *how they were arrived at*. A name on a list is not a
            # disclosure — a reader has to be able to see that the fact was
            # inferred and how far to trust it.
            "critical_facts": [
                {
                    "fact": name,
                    "evidence_status": INFERRED_EVIDENCE_STATUS,
                    "confidence": REVIEW_CONFIDENCE_LOW,
                }
                for name in unconfirmed
            ],
        },
    }
