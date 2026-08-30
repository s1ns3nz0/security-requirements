"""N8 — quick mode with an unanswered critical unknown.

Plan of record §3 "Modes", §4.2 (the `run` block), §4.3 "Ordering",
§8 (the "Quick mode, unknown critical fact" row, plan line 529), §11.2 N8:

>   **N8** Quick mode with an unanswered critical unknown → `inferred`,
>   confidence `low`, fact listed in `unconfirmed_critical_facts`.

and plan line 134, §3 "Modes":

>   **quick** — the five critical unknowns (authentication, internet exposure,
>   sensitive data, isolation, privileged access) and nothing more. Everything
>   else is inferred, marked `evidence_status: inferred`, confidence capped at
>   `low`.

The requirement this file defends is a *disclosure* requirement, not a
formatting one. A quick review that asked "is this isolated?", got no answer,
and then reported as though the answer were "yes" is worse than a review that
never ran: it launders an unknown into a stated fact. So every assertion here
is about what the report *says it does not know*.

Pinned contract of record, `scripts/sdr_entry.py`:

    CRITICAL_UNKNOWNS
        The five critical unknowns of plan §3. Already exists; read, never
        redefined here. Its membership is specified in `test_sdr_entry.py`
        and is deliberately not re-asserted in this file.

    design_review(project_root, *, argument=None, mode="quick",
                  invoke_intake=None, answers=None) -> dict
        `answers` maps a critical-unknown name to what the operator said. A
        name absent from `answers`, or present with a None/empty value, is
        UNANSWERED.

    record["run"]["unconfirmed_critical_facts"] -> list[str]
        Every unanswered critical unknown, sorted, and nothing else.

`answers` does not exist yet. These tests are RED by construction and fail by
*name* — there is no `importorskip` and no `skip` in this file, because a
skipped test for an inference boundary is indistinguishable from a held one.

------------------------------------------------------------------------
Three places the plan and the source disagree. Recorded here, not guessed at.
------------------------------------------------------------------------

1.  **Where the list lives.** The contract of record pinned for this slice
    says `record["run"]["unconfirmed_critical_facts"]`. Plan §4.2 (line 193)
    puts it one level deeper, inside the profile block, beside the two facts
    that block already carries:

        "profile": {
          "confirmed": false,
          "stale_vs_head": true,
          "unconfirmed_critical_facts": ["isolation", "privileged_access"]
        }

    and `sdr_entry.profile_staleness` already emits `run.profile` today. The
    pinned contract wins, as instructed, so every read here goes through
    `unconfirmed_facts()` and `test_the_unconfirmed_facts_list_lives_at_the_
    pinned_location_in_the_run_header` is the single test that nails the
    location down. If the contract is resolved in favour of plan §4.2, that
    helper and that one test are the whole edit.

2.  **Where `confidence` lives.** Plan §3, §8 and N8 all say quick mode caps
    confidence at `low`, but neither §4.2 nor §5.2 gives confidence a home in
    the `run` block: §4.2 puts `"confidence": "high"` inside a *finding*
    (line 235) and §5.2 (line 377) adds `evidence_status`, `confidence`,
    `attack_path_ids` "inside each threat record". So confidence is a
    per-record field, and this file asserts it wherever it appears rather
    than at a location the plan never pins.

3.  **The `confidence` vocabulary is already taken.** The plan's values are
    `high` / `low`. The only `confidence` vocabulary in the source is
    `blast_radius.py:36`, `CONFIDENCE = {"confirmed", "inferred", "unknown"}`
    — no `low`, no `high`, and it shares the token `inferred` with
    `risk.py:63` `EVIDENCE_STATUSES`, which is a different axis. Nothing here
    reconciles the two; these tests assert the plan's `low` because N8 and §8
    both name it, and the collision is reported rather than resolved.

Builders are local on purpose — `tests/risk_helpers.py` and
`tests/conftest.py` are under concurrent edit by other agents and this file
must not depend on their shape.
"""

from __future__ import annotations

import importlib
import inspect
from pathlib import Path
import shutil
import sys

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
PLUGIN_ROOT = REPO_ROOT / "plugins" / "security-requirements"
PLUGIN_SCRIPTS = PLUGIN_ROOT / "scripts"
sys.path.insert(0, str(PLUGIN_SCRIPTS))

SDR_ENTRY_PATH = PLUGIN_SCRIPTS / "sdr_entry.py"
RISK_PATH = PLUGIN_SCRIPTS / "risk.py"

GOLDEN_CASE = REPO_ROOT / "golden" / "movie-rating-aws"
DEFAULT_POLICY_PATH = PLUGIN_ROOT / "risk" / "default-policy.yaml"

#: `publish.py:1061` `_risk_paths` — the canonical store directory name.
STORE_DIRNAME = ".security-requirements"

#: The key under `run` that N8 is about.
FACTS_KEY = "unconfirmed_critical_facts"

#: Plan §3 last paragraph — "Quick mode never relaxes the gate for
#: `/sec-req-build` or `/sec-req-refresh`." An unanswered critical unknown is
#: exactly the situation in which relaxing it would be most tempting.
GATE_RELAXING_TOKENS = (
    "force",
    "skip",
    "bypass",
    "relax",
    "assume",
    "auto_confirm",
    "autoconfirm",
    "no_confirm",
    "noconfirm",
    "no_gate",
    "nogate",
    "unattended",
    "non_interactive",
    "noninteractive",
    "pre_confirmed",
    "preconfirmed",
)

#: Plan §3 / §8 / N8. Quick mode infers everything it was not told, so every
#: confidence a quick run emits is capped here.
QUICK_MODE_CONFIDENCE_CAP = "low"

#: Plan §3 / §8 / N8, and `risk.py:63` for the permitted spelling.
INFERRED = "inferred"


# --------------------------------------------------------------------------
# Import, by name. Never `importorskip`.
# --------------------------------------------------------------------------


def sdr_entry():
    """Import the entry wrapper, failing by name rather than by ImportError."""

    if not SDR_ENTRY_PATH.is_file():
        pytest.fail(
            "the entry wrapper is not implemented: expected the module "
            f"`sdr_entry` at {SDR_ENTRY_PATH}, providing `CRITICAL_UNKNOWNS` "
            "and `design_review` (plan §3 Modes, §8, N8)"
        )
    try:
        return importlib.import_module("sdr_entry")
    except ModuleNotFoundError as error:
        pytest.fail(
            "the entry wrapper module `sdr_entry` cannot be imported from "
            f"{PLUGIN_SCRIPTS}: {error}"
        )


def risk_module():
    """Import `risk`, the owner of the closed `evidence_status` vocabulary."""

    if not RISK_PATH.is_file():
        pytest.fail(
            f"expected the risk engine at {RISK_PATH}, which owns "
            "`EVIDENCE_STATUSES` (risk.py:63)"
        )
    try:
        return importlib.import_module("risk")
    except ModuleNotFoundError as error:
        pytest.fail(f"the `risk` module cannot be imported from {PLUGIN_SCRIPTS}: {error}")


def attribute(module, name: str):
    """Read one pinned contract attribute, failing by name if it is absent."""

    if not hasattr(module, name):
        pytest.fail(f"`{module.__name__}.{name}` is missing from the pinned contract")
    return getattr(module, name)


def critical_unknowns(module) -> tuple[str, ...]:
    """The five names, read from the module rather than restated here."""

    return tuple(str(name) for name in attribute(module, "CRITICAL_UNKNOWNS"))


def review(module, project_root: Path, **kwargs) -> dict:
    """Call `design_review`, failing by name if `answers` is not a parameter.

    The signature is inspected rather than the `TypeError` caught, so a
    genuine `TypeError` raised *inside* the runner is never mistaken for the
    parameter being absent.
    """

    design_review = attribute(module, "design_review")
    parameters = inspect.signature(design_review).parameters
    if "answers" not in parameters:
        pytest.fail(
            "`sdr_entry.design_review` does not accept an `answers` keyword. "
            "N8 needs it: the operator's answers to the five critical "
            "unknowns are what decides which facts are unconfirmed. Expected "
            "`design_review(project_root, *, argument=None, mode='quick', "
            "invoke_intake=None, answers=None)`; the signature is "
            f"({', '.join(parameters)})"
        )
    parameter = parameters["answers"]
    if parameter.kind is inspect.Parameter.POSITIONAL_ONLY:
        pytest.fail(
            "`answers` must be a keyword parameter of `design_review`, not "
            f"positional-only; got kind {parameter.kind}"
        )
    return design_review(project_root, **kwargs)


# --------------------------------------------------------------------------
# Record readers. Every read of the list goes through one function.
# --------------------------------------------------------------------------


def run_block(record) -> dict:
    assert isinstance(record, dict), f"design_review must return a dict, got {record!r}"
    run = record.get("run")
    assert isinstance(run, dict), (
        f"the returned record must carry a `run` block (plan §4.2), got {record!r}"
    )
    return run


def unconfirmed_facts(record) -> list:
    """`run.unconfirmed_critical_facts`, present or the test fails.

    Absent and empty are different claims and a report reader cannot tell
    them apart, so absence is a failure and never an implicit `[]`.
    """

    run = run_block(record)
    profile = run.get("profile")
    if not isinstance(profile, dict):
        pytest.fail(
            f"the run header must carry a `run.profile` block to hold "
            f"`{FACTS_KEY}` (plan §4.2 line 193); the run block held "
            f"{sorted(run)}"
        )
    if FACTS_KEY not in profile:
        pytest.fail(
            f"the run header must carry `run.profile.{FACTS_KEY}` (N8, plan "
            "§8, plan §4.2 line 193). An absent key and an empty list are "
            'different claims — one says "nothing is unconfirmed", the other '
            '"we did not look" — and the report reader cannot tell them '
            f"apart. The profile block held {sorted(profile)}."
        )
    return profile[FACTS_KEY]


def walk_mappings(value, key_path=(), depth: int = 0):
    """Every mapping inside a nested record, with the key path that reached it."""

    if depth > 10:
        return
    if isinstance(value, dict):
        yield key_path, value
        for key, item in value.items():
            yield from walk_mappings(item, key_path + (str(key),), depth + 1)
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            yield from walk_mappings(item, key_path + (str(index),), depth + 1)


def flattened_strings(value, depth: int = 0) -> list[str]:
    """Every string reachable inside a nested record, for containment checks."""

    if depth > 10:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        found: list[str] = []
        for key, item in value.items():
            found.extend(flattened_strings(key, depth + 1))
            found.extend(flattened_strings(item, depth + 1))
        return found
    if isinstance(value, (list, tuple, set)):
        found = []
        for item in value:
            found.extend(flattened_strings(item, depth + 1))
        return found
    return []


def mappings_naming(record, fact: str) -> list[dict]:
    """Every mapping in the record that is *about* `fact`.

    A mapping is about the fact if the fact names one of its own values, or
    if the fact is the key that reached it. The location is not asserted
    because the plan never pins one (docstring, note 2) — only that some
    record carrying the inference exists and says what it is.
    """

    found = []
    for key_path, mapping in walk_mappings(record):
        own_values = [item for item in mapping.values() if isinstance(item, str)]
        if fact in own_values or (key_path and key_path[-1] == fact):
            found.append(mapping)
    return found


def confidences(record) -> list[tuple[tuple, object]]:
    """Every `confidence` value in the record, with the path that reached it."""

    return [
        (key_path + ("confidence",), mapping["confidence"])
        for key_path, mapping in walk_mappings(record)
        if "confidence" in mapping
    ]


def evidence_statuses(record) -> list[tuple[tuple, object]]:
    """Every `evidence_status` value in the record, with its path."""

    return [
        (key_path + ("evidence_status",), mapping["evidence_status"])
        for key_path, mapping in walk_mappings(record)
        if "evidence_status" in mapping
    ]


# --------------------------------------------------------------------------
# Fixtures and store builders, local to this file.
# --------------------------------------------------------------------------


class RecordingIntake:
    """A stand-in for `/sec-req-init` -> `/sec-req-build`, recording calls."""

    def __init__(self, materialise_into: Path | None = None) -> None:
        self.calls: list[tuple[tuple, dict]] = []
        self._materialise_into = materialise_into

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if self._materialise_into is not None:
            write_store(self._materialise_into)
        return {"invoked": "init->build"}

    @property
    def call_count(self) -> int:
        return len(self.calls)

    @property
    def only_call(self) -> tuple[tuple, dict]:
        assert self.call_count == 1, (
            f"expected exactly one intake invocation, saw {self.call_count}: "
            f"{self.calls!r}"
        )
        return self.calls[0]


def write_store(project_root: Path) -> Path:
    """Materialise a real, complete store at the canonical location."""

    store = project_root / STORE_DIRNAME
    store.mkdir(parents=True, exist_ok=True)
    for name in (
        "profile.yaml",
        "threats.yaml",
        "risk-assessment.yaml",
        "risk-state.yaml",
    ):
        shutil.copyfile(GOLDEN_CASE / name, store / name)
    shutil.copyfile(DEFAULT_POLICY_PATH, store / "risk-policy.yaml")
    return store


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "inspected project"
    root.mkdir()
    (root / "README.md").write_text("# checkout\n", encoding="utf-8")
    return root


@pytest.fixture
def scored(project: Path) -> Path:
    """A project with a store already present, so no intake is involved."""

    write_store(project)
    return project


def answered(module, *names: str) -> dict:
    """Plausible operator answers for the named critical unknowns."""

    known = critical_unknowns(module)
    for name in names:
        assert name in known, (
            f"{name!r} is not one of `sdr_entry.CRITICAL_UNKNOWNS` "
            f"({list(known)}); the test, not the runner, is wrong"
        )
    return {name: f"operator answered {name}" for name in names}


def all_answered(module) -> dict:
    return answered(module, *critical_unknowns(module))


# --------------------------------------------------------------------------
# N8 — the fact is listed. Listed, not "some list is non-empty".
# --------------------------------------------------------------------------


def test_an_unanswered_critical_unknown_is_listed_and_an_answered_one_is_not(
    scored,
):
    """N8 — the plan's own example: §4.2 line 193.

    Three unknowns answered, `isolation` and `privileged_access` left
    unanswered, and the run header must name exactly those two.
    """

    module = sdr_entry()
    unanswered = ("isolation", "privileged_access")
    given = answered(module, "authentication", "internet_exposure", "sensitive_data")

    record = review(module, scored, mode="quick", answers=given)
    facts = unconfirmed_facts(record)

    for fact in unanswered:
        assert fact in facts, (
            f"the unanswered critical unknown `{fact}` must be listed in "
            f"`run.{FACTS_KEY}` (N8, plan §8). A quick review that leaves it "
            "out reports an unknown as a settled fact. The list held "
            f"{facts!r}"
        )
    for fact in given:
        assert fact not in facts, (
            f"`{fact}` was answered by the operator ({given[fact]!r}) and "
            f"must not be listed as unconfirmed in `run.{FACTS_KEY}`; the "
            f"list held {facts!r}"
        )
    assert list(facts) == sorted(unanswered), (
        f"`run.{FACTS_KEY}` must hold every unanswered critical unknown, "
        f"sorted, and nothing else (plan §4.2 line 193 shows exactly "
        f"{sorted(unanswered)}); got {facts!r}"
    )


@pytest.mark.parametrize(
    "empty_answer",
    [None, "", [], {}],
    ids=["none", "empty-string", "empty-list", "empty-mapping"],
)
def test_a_critical_unknown_present_with_an_empty_value_counts_as_unanswered(
    scored, empty_answer
):
    """A key that is present but says nothing has not answered anything."""

    module = sdr_entry()
    given = all_answered(module)
    given["isolation"] = empty_answer

    facts = unconfirmed_facts(review(module, scored, mode="quick", answers=given))

    assert "isolation" in facts, (
        "`answers` carrying `isolation` with the empty value "
        f"{empty_answer!r} has not answered it; the fact must still be listed "
        f"in `run.{FACTS_KEY}`. Treating a present-but-empty key as an answer "
        "is how an unknown becomes a stated fact. The list held "
        f"{facts!r}"
    )


@pytest.mark.parametrize(
    "negative_answer", [False, 0], ids=["false", "zero"]
)
def test_a_critical_unknown_answered_in_the_negative_counts_as_answered(
    scored, negative_answer
):
    """`internet_exposure: False` is an answer, and a load-bearing one.

    `profile.yaml` types `internet_exposure` as a bool (plan §5.1), so the
    most security-relevant answer this field can carry is falsy. A runner
    that tests `answers.get(name)` for truthiness reports "not internet
    exposed" as "we never asked" — the opposite failure from the one N8
    guards, and just as wrong. The pinned contract says None *or empty*, and
    `False` is neither.
    """

    module = sdr_entry()
    given = all_answered(module)
    given["internet_exposure"] = negative_answer

    facts = unconfirmed_facts(review(module, scored, mode="quick", answers=given))

    assert "internet_exposure" in critical_unknowns(module)
    assert "internet_exposure" not in facts, (
        f"`internet_exposure` was answered {negative_answer!r} — a negative "
        "answer is an answer, and the pinned contract makes only None and "
        "empty values unanswered. It must not be listed in "
        f"`run.{FACTS_KEY}`; the list held {facts!r}"
    )


@pytest.mark.parametrize(
    "no_answers", [None, {}], ids=["answers-none", "answers-empty"]
)
def test_with_nothing_answered_all_five_critical_unknowns_are_listed(
    scored, no_answers
):
    """Nothing asked, nothing answered — the report says so five times."""

    module = sdr_entry()
    expected = sorted(critical_unknowns(module))

    facts = unconfirmed_facts(review(module, scored, mode="quick", answers=no_answers))

    assert list(facts) == expected, (
        f"with `answers={no_answers!r}` every one of the five critical "
        f"unknowns is unanswered and all five must be listed in "
        f"`run.{FACTS_KEY}` (plan §3 Modes, N8); expected {expected}, got "
        f"{facts!r}"
    )


def test_with_everything_answered_the_list_is_present_and_empty_not_absent(scored):
    """`[]` is a claim. An absent key is a different claim."""

    module = sdr_entry()

    record = review(module, scored, mode="quick", answers=all_answered(module))

    # `unconfirmed_facts` fails by name if the key is absent, which is the
    # "we did not check" claim this test exists to rule out.
    facts = unconfirmed_facts(record)
    assert facts == [], (
        "with all five critical unknowns answered the list must be an empty "
        f"list, not None and not a placeholder; got {facts!r}"
    )
    assert facts is not None, (
        f"`run.{FACTS_KEY}` must be `[]`, never None; got {facts!r}"
    )


# --------------------------------------------------------------------------
# §4.3 — "no set iteration reaches output".
# --------------------------------------------------------------------------


def test_the_unconfirmed_facts_list_is_sorted_whatever_order_answers_arrived_in(
    scored,
):
    """§4.3 — deterministic output, not whatever a dict or set happened to hold."""

    module = sdr_entry()
    known = critical_unknowns(module)
    # Answer one, leave the other four unanswered, and hand the runner the
    # keys in an order that is not the declaration order and not sorted.
    given = {name: None for name in reversed(known)}
    given[known[0]] = "operator answered it"
    expected = sorted(known[1:])

    facts = unconfirmed_facts(review(module, scored, mode="quick", answers=given))

    assert list(facts) == expected, (
        f"`run.{FACTS_KEY}` must be sorted regardless of the order `answers` "
        "arrived in — §4.3, no set iteration reaches output. Expected "
        f"{expected}, got {facts!r}"
    )
    assert list(facts) == sorted(facts), (
        f"`run.{FACTS_KEY}` must be sorted; got {facts!r}"
    )


def test_the_unconfirmed_facts_value_is_a_list_and_not_a_set_or_tuple(scored):
    """§4.3 — a set has no order to serialize and a tuple is not JSON."""

    module = sdr_entry()

    facts = unconfirmed_facts(review(module, scored, mode="quick", answers=None))

    assert isinstance(facts, list), (
        f"`run.{FACTS_KEY}` must be a `list[str]` — a set has no order to "
        "serialize and §4.3 forbids set iteration reaching output; got "
        f"{type(facts).__name__} ({facts!r})"
    )
    assert all(isinstance(fact, str) for fact in facts), (
        f"`run.{FACTS_KEY}` must hold the unknowns' names as strings; got "
        f"{[type(fact).__name__ for fact in facts]}"
    )


def test_the_unconfirmed_facts_list_names_critical_unknowns_and_nothing_else(
    scored,
):
    """"and nothing else" — not answers the operator gave, not stray keys."""

    module = sdr_entry()
    known = set(critical_unknowns(module))
    given = all_answered(module)
    given["isolation"] = None
    # A key the runner has never heard of. It is not a critical unknown, so
    # it cannot be an unconfirmed critical fact.
    given["favourite_colour"] = None

    facts = unconfirmed_facts(review(module, scored, mode="quick", answers=given))

    assert list(facts) == ["isolation"], (
        f"`run.{FACTS_KEY}` holds unanswered *critical unknowns* and nothing "
        "else; an unrecognised key in `answers` is not one of the five. "
        f"Expected ['isolation'], got {facts!r}"
    )
    strays = [fact for fact in facts if fact not in known]
    assert not strays, (
        f"`run.{FACTS_KEY}` must draw every entry from "
        f"`sdr_entry.CRITICAL_UNKNOWNS` ({sorted(known)}); it held {strays!r}"
    )
    assert len(facts) == len(set(facts)), (
        f"`run.{FACTS_KEY}` must not repeat a fact; got {facts!r}"
    )


def test_the_unconfirmed_facts_list_lives_at_the_pinned_location_in_the_run_header(
    scored,
):
    """The one test that nails the key's location down.

    Resolved in favour of plan §4.2 line 193: the key lives at
    `run.profile.unconfirmed_critical_facts`, beside `confirmed` and
    `stale_vs_head`. The contract pinned for this slice put it one level up at
    `run`; the plan is the source of truth and `run.profile` already exists,
    so the plan won.

    The key must appear at exactly one address. A report reader looking in the
    wrong place sees an absent key, which reads as "nothing unconfirmed" — so
    emitting it in both places is not a safe compromise, it is two claims that
    can drift apart.
    """

    module = sdr_entry()

    run = run_block(review(module, scored, mode="quick", answers=None))
    profile = run.get("profile")

    assert isinstance(profile, dict) and FACTS_KEY in profile, (
        f"plan §4.2 line 193 places `{FACTS_KEY}` under `run.profile`; the "
        f"run block held {sorted(run)} and the profile block held "
        f"{sorted(profile) if isinstance(profile, dict) else profile!r}"
    )
    assert FACTS_KEY not in run, (
        f"`{FACTS_KEY}` must live at exactly one address. It appears at both "
        f"`run` and `run.profile`, which can drift into two disagreeing "
        'answers to "what do we not know". Plan §4.2 line 193 places it '
        "under `run.profile`; drop the duplicate."
    )


# --------------------------------------------------------------------------
# N8 — the inference is marked: `inferred`, confidence `low`.
# --------------------------------------------------------------------------


def test_an_unanswered_critical_unknown_is_recorded_as_inferred_evidence(scored):
    """N8 / plan line 134 — what quick mode was not told, it inferred.

    The location is not asserted: §4.2 puts `evidence_status` on architecture
    nodes and findings, and §5.2 adds it to threat records, but no section
    pins where the *inference about an unanswered critical unknown* is
    carried. So this asserts that some record naming the fact says how it was
    arrived at — anywhere in the returned record.
    """

    module = sdr_entry()
    risk = risk_module()
    permitted = attribute(risk, "EVIDENCE_STATUSES")
    assert INFERRED in permitted, (
        f"`risk.EVIDENCE_STATUSES` must contain {INFERRED!r} (risk.py:63); "
        f"it held {sorted(permitted)}"
    )

    given = all_answered(module)
    given["isolation"] = None
    record = review(module, scored, mode="quick", answers=given)

    naming = mappings_naming(record, "isolation")
    assert naming, (
        "nothing in the returned record is *about* the unanswered critical "
        "unknown `isolation`. N8 requires the inference to be recorded, not "
        "merely the name listed: some record must carry the fact together "
        f"with `evidence_status: {INFERRED!r}`. The record held "
        f"{sorted(run_block(record))} under `run`"
    )
    marked = [
        mapping for mapping in naming if mapping.get("evidence_status") == INFERRED
    ]
    assert marked, (
        f"the record for the unanswered critical unknown `isolation` must "
        f"carry `evidence_status: {INFERRED!r}` (N8, plan line 134, plan §8). "
        "Quick mode inferred this fact; a record that does not say so is "
        "indistinguishable from an observed one. The mappings naming "
        f"`isolation` were {naming!r}"
    )


def test_an_unanswered_critical_unknown_caps_its_confidence_at_low(scored):
    """N8 / §8 — confidence `low`, on whatever record carries the inference."""

    module = sdr_entry()
    given = all_answered(module)
    given["isolation"] = None

    record = review(module, scored, mode="quick", answers=given)

    naming = mappings_naming(record, "isolation")
    carrying = [mapping for mapping in naming if "confidence" in mapping]
    assert carrying, (
        "no record about the unanswered critical unknown `isolation` carries "
        "a `confidence` at all. N8 and plan §8 both require confidence "
        f"{QUICK_MODE_CONFIDENCE_CAP!r} on the inference. (Note: the plan "
        "gives `confidence` no home in the `run` block — §4.2 line 235 puts "
        "it on a finding and §5.2 line 377 on a threat record — so this "
        "asserts its presence, not its address.) The mappings naming "
        f"`isolation` were {naming!r}"
    )
    for mapping in carrying:
        assert mapping["confidence"] == QUICK_MODE_CONFIDENCE_CAP, (
            "an unanswered critical unknown caps confidence at "
            f"{QUICK_MODE_CONFIDENCE_CAP!r} (N8, plan §8, plan line 134); the "
            f"record carried {mapping['confidence']!r}"
        )


def test_quick_mode_caps_every_confidence_in_the_record_at_low(scored):
    """Plan line 134 — "Everything else is inferred, confidence capped at low".

    Not only the unanswered facts: quick mode asks five questions and infers
    the rest, so nothing a quick run emits may claim more than `low`.
    """

    module = sdr_entry()

    record = review(module, scored, mode="quick", answers=all_answered(module))

    overclaimed = [
        (path, value)
        for path, value in confidences(record)
        if value != QUICK_MODE_CONFIDENCE_CAP
    ]
    assert not overclaimed, (
        "quick mode caps confidence at "
        f"{QUICK_MODE_CONFIDENCE_CAP!r} for everything it emits (plan §3, "
        "line 134) — answering the five critical unknowns does not lift the "
        "cap, because everything *else* is still inferred. These values "
        f"exceed it: {overclaimed!r}"
    )


def test_every_evidence_status_the_record_emits_is_one_of_the_three_permitted(
    scored,
):
    """`evidence_status` is a closed set — `risk.py:63`, not a free string."""

    module = sdr_entry()
    risk = risk_module()
    permitted = set(attribute(risk, "EVIDENCE_STATUSES"))

    record = review(module, scored, mode="quick", answers=None)

    invalid = [
        (path, value)
        for path, value in evidence_statuses(record)
        if value not in permitted
    ]
    assert not invalid, (
        "`evidence_status` accepts only "
        f"{sorted(permitted)} (`risk.EVIDENCE_STATUSES`, risk.py:63, plan "
        f"§5.2 / N7); the record emitted {invalid!r}"
    )


# --------------------------------------------------------------------------
# §3 last paragraph — quick mode never relaxes the gate, least of all here.
# --------------------------------------------------------------------------


def test_an_unanswered_critical_unknown_hands_intake_no_gate_relaxing_flag(project):
    """§3 — the unanswered case is where relaxing the gate would be tempting."""

    module = sdr_entry()
    intake = RecordingIntake(materialise_into=project)

    review(
        module,
        project,
        argument="./services/checkout",
        mode="quick",
        answers=None,
        invoke_intake=intake,
    )

    args, kwargs = intake.only_call
    surface = [
        text.strip().lower().replace("-", "_")
        for text in flattened_strings([list(args), kwargs])
    ]
    for token in GATE_RELAXING_TOKENS:
        offenders = [text for text in surface if token in text]
        assert not offenders, (
            "quick mode never relaxes the gate for /sec-req-build or "
            "/sec-req-refresh (plan §3), and five unanswered critical "
            f"unknowns do not change that; the intake call carried "
            f"{offenders!r} matching `{token}`"
        )
    for key, value in kwargs.items():
        assert not (key.strip().lower() == "confirmed" and value), (
            "an unanswered critical unknown must not pre-confirm intake; the "
            f"call carried {key}={value!r}"
        )


def test_running_intake_does_not_silently_answer_an_unanswered_unknown(project):
    """Intake building a model is not the operator answering a question.

    Store absent, so init->build runs and writes a real store. The fact the
    operator never answered is still unanswered afterwards — a model existing
    is not evidence about isolation.
    """

    module = sdr_entry()
    intake = RecordingIntake(materialise_into=project)
    given = all_answered(module)
    given["isolation"] = None

    record = review(
        module,
        project,
        argument="./services/checkout",
        mode="quick",
        answers=given,
        invoke_intake=intake,
    )

    assert intake.call_count == 1, (
        "store absent must invoke the existing init->build pipeline exactly "
        f"once; saw {intake.call_count}"
    )
    facts = unconfirmed_facts(record)
    assert "isolation" in facts, (
        "intake ran and wrote a model, but nobody answered `isolation`; it "
        f"must still be listed in `run.{FACTS_KEY}` (N8). A model existing is "
        "not evidence about isolation. The list held "
        f"{facts!r}"
    )


def test_answering_all_five_unknowns_does_not_waive_the_missing_store_gate(project):
    """§3 — quick mode is a shorter interview, never a waived requirement.

    With no store and no intake pipeline the wrapper must refuse, and five
    answered critical unknowns do not substitute for a model.
    """

    module = sdr_entry()
    error_type = attribute(risk_module(), "RiskValidationError")

    with pytest.raises(error_type) as raised:
        review(
            module,
            project,
            argument="./services/checkout",
            mode="quick",
            answers=all_answered(module),
            invoke_intake=None,
        )

    message = str(raised.value)
    assert STORE_DIRNAME in message, (
        "the refusal must name the store it could not find "
        f"({STORE_DIRNAME}/), so the operator knows what is missing; got "
        f"{message!r}"
    )


def test_guided_mode_also_states_which_critical_facts_are_unconfirmed(scored):
    """Both modes report the header fact, exactly as §3 requires for staleness.

    Only presence and type are asserted. Guided runs the seven-question
    interview and its own confirmation gate, and the plan does not say
    whether `answers` reaches guided at all — so the *contents* of the list
    in guided mode are deliberately left unpinned here.
    """

    module = sdr_entry()

    # Fails by name if the key is absent, which in guided mode would read as
    # "nothing unconfirmed" — a claim guided mode has not been asked to make.
    facts = unconfirmed_facts(review(module, scored, mode="guided", answers=None))

    assert isinstance(facts, list), (
        f"`run.profile.{FACTS_KEY}` must be a list in every mode; guided mode "
        f"returned {type(facts).__name__} ({facts!r})"
    )
