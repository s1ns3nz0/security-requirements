"""N30 / N31 — the entry wrapper (`scripts/sdr_entry.py`), F2 and F4.

Plan of record §2.1 decision 5, §3 "Behaviour of the wrapper" + "Modes",
§6 F2/F4, §8 (store absent / store present), §11.2 N30 and N31.

Decision 5 is the whole point of this module: the command is **post-build
internally, a wrapper externally**. When no store exists it *invokes* the
existing `/sec-req-init` -> `/sec-req-build` pipeline; it never reimplements
intake. That is a statement about *behaviour*, not about output shape, so
every assertion here is made either

* **by call** — against the injected `invoke_intake` double, or
* **by filesystem** — against the bytes under `.security-requirements/`,

and never by inspecting the returned record for something that "looks like"
intake ran. A wrapper that quietly grew its own intake would still return a
plausible record; it cannot fake a zero call count, and it cannot write
`profile.yaml` without the filesystem noticing.

Pinned contract of record, `scripts/sdr_entry.py`:

    store_present(project_root: Path) -> bool
        Whether a `.security-requirements` store already exists.

    design_review(project_root: Path, *, argument=None, mode="quick",
                  invoke_intake=None) -> dict
        `invoke_intake` is the injected stand-in for the existing
        init -> build pipeline. Injected precisely so N30 can assert by call.

    GUIDED_INTERVIEW_DEPTH / QUICK_INTERVIEW_DEPTH
        The two interview depths of plan §3 "Modes", handed to `invoke_intake`.
    CRITICAL_UNKNOWNS
        The five critical unknowns quick mode asks about, and nothing more.
    GUIDED_QUESTION_COUNT
        Seven. Source, not plan: `commands/sec-req-init.md:72` says "Ask the
        seven questions. Not more."; `references/profile-schema.md:38` says
        "Seven mandatory questions, no more."

Where the store really lives — verified against source, which wins over the
plan: `publish.py:1061` `_risk_paths` maps every document under
`project_root / ".security-requirements"`, and `risk.py:2144`
`_project_document_path` falls back to the same directory for the documents
that have no explicit path. `commands/sec-req-init.md:92` writes
`.security-requirements/profile.yaml`; `commands/sec-req-build.md:83` writes
`.security-requirements/threats.yaml`.

Builders are local on purpose — `tests/risk_helpers.py` and
`tests/conftest.py` are under concurrent edit by other agents and this file
must not depend on their shape.
"""

from __future__ import annotations

import importlib
from pathlib import Path
import shutil
import sys

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
PLUGIN_ROOT = REPO_ROOT / "plugins" / "security-requirements"
PLUGIN_SCRIPTS = PLUGIN_ROOT / "scripts"
sys.path.insert(0, str(PLUGIN_SCRIPTS))

#: The module under specification. It does not exist yet; these tests are RED
#: by construction and must fail with a message that names it.
SDR_ENTRY_PATH = PLUGIN_SCRIPTS / "sdr_entry.py"

GOLDEN_CASE = REPO_ROOT / "golden" / "movie-rating-aws"
DEFAULT_POLICY_PATH = PLUGIN_ROOT / "risk" / "default-policy.yaml"

#: `publish.py:1061` `_risk_paths` — the canonical store directory name.
STORE_DIRNAME = ".security-requirements"

#: The two documents intake owns: init writes the profile, build writes the
#: threats. If the wrapper ever writes either of these itself, it has stopped
#: being a wrapper.
INTAKE_OWNED_DOCUMENTS = ("profile.yaml", "threats.yaml")

#: Plan §3 last paragraph — "Quick mode never relaxes the gate for
#: `/sec-req-build` or `/sec-req-refresh`." No call into intake may carry any
#: of these, under any spelling. `--force` is a real flag in this repository
#: (`apply_overlay.py:676`), so this is not a hypothetical shape.
GATE_RELAXING_TOKENS = (
    "force",
    "yes",
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


def sdr_entry():
    """Import the entry wrapper, failing by name rather than by ImportError.

    Called from test bodies, never from a fixture: a `pytest.fail` raised in
    fixture setup is reported as an ERROR, and the instruction of record is
    that these tests FAIL.
    """

    if not SDR_ENTRY_PATH.is_file():
        pytest.fail(
            "the entry wrapper is not implemented: expected the module "
            f"`sdr_entry` at {SDR_ENTRY_PATH}, providing `store_present` and "
            "`design_review` (plan §2.1 decision 5, F2, N30/N31)"
        )
    try:
        return importlib.import_module("sdr_entry")
    except ModuleNotFoundError as error:
        pytest.fail(
            "the entry wrapper module `sdr_entry` cannot be imported from "
            f"{PLUGIN_SCRIPTS}: {error}"
        )


def attribute(module, name: str):
    """Read one pinned contract attribute, failing by name if it is absent."""

    if not hasattr(module, name):
        pytest.fail(f"`sdr_entry.{name}` is missing from the entry wrapper contract")
    return getattr(module, name)


class RecordingIntake:
    """A stand-in for `/sec-req-init` -> `/sec-req-build`.

    Records every call verbatim. Optionally materialises the store, the way
    the real pipeline would, so the wrapper can go on to score a model.
    """

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
            "expected exactly one intake invocation, saw "
            f"{self.call_count}: {self.calls!r}"
        )
        return self.calls[0]

    def values_of_only_call(self) -> list:
        args, kwargs = self.only_call
        return [*args, *kwargs.values()]

    def keys_of_only_call(self) -> list[str]:
        _args, kwargs = self.only_call
        return list(kwargs)


def write_store(project_root: Path) -> Path:
    """Materialise a real, complete store at the canonical location.

    Documents are copied from the reviewed golden case rather than invented,
    so "score the existing model as-is" scores something the engine accepts.
    """

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


def store_bytes(project_root: Path) -> dict[str, bytes]:
    """Every stored document, by relative name, as raw bytes."""

    store = project_root / STORE_DIRNAME
    if not store.is_dir():
        return {}
    return {
        str(path.relative_to(store)): path.read_bytes()
        for path in sorted(store.rglob("*"))
        if path.is_file()
    }


def flattened_strings(value, depth: int = 0) -> list[str]:
    """Every string reachable inside a nested record, for containment checks."""

    if depth > 8:
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


def profile_block(record) -> dict:
    """Return `run.profile` from a returned record, failing by name if absent.

    Plan §4.2 pins the header: `run.profile.stale_vs_head`.
    """

    assert isinstance(record, dict), f"design_review must return a dict, got {record!r}"
    run = record.get("run")
    assert isinstance(run, dict), (
        f"the returned record must carry a `run` block (plan §4.2), got {record!r}"
    )
    profile = run.get("profile")
    assert isinstance(profile, dict), (
        "the returned record must carry a `run.profile` block (plan §4.2), got "
        f"{run!r}"
    )
    return profile


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "inspected project"
    root.mkdir()
    (root / "README.md").write_text("# checkout\n", encoding="utf-8")
    return root


# --------------------------------------------------------------------------
# N30 — store absent: the wrapper invokes init->build, asserted by call.
# --------------------------------------------------------------------------


def test_a_store_is_absent_until_the_canonical_directory_holds_documents(project):
    """`store_present` keys on the real location, `.security-requirements`."""

    module = sdr_entry()

    assert module.store_present(project) is False, (
        "a project with no store must report the store absent"
    )

    empty = project / STORE_DIRNAME
    empty.mkdir()
    assert module.store_present(project) is False, (
        "an empty `.security-requirements` directory holds no model; intake "
        "still has to run (plan §8, store absent)"
    )

    write_store(project)
    assert module.store_present(project) is True, (
        "a store carrying profile.yaml and threats.yaml under "
        f"{STORE_DIRNAME}/ must report present"
    )


def test_with_no_store_the_wrapper_invokes_intake_exactly_once(project):
    """N30 — asserted by call count on the injected pipeline, not by output."""

    module = sdr_entry()
    intake = RecordingIntake(materialise_into=project)

    module.design_review(
        project,
        argument="./services/checkout",
        mode="quick",
        invoke_intake=intake,
    )

    assert intake.call_count == 1, (
        "store absent must invoke the existing init->build pipeline exactly "
        f"once (F2, N30); saw {intake.call_count} invocations"
    )


def test_the_intake_invocation_carries_the_argument_and_mode_the_caller_passed(
    project,
):
    """N30 — the wrapper forwards the front door, it does not re-derive it."""

    module = sdr_entry()
    intake = RecordingIntake(materialise_into=project)

    module.design_review(
        project,
        argument="./services/checkout",
        mode="guided",
        invoke_intake=intake,
    )

    values = intake.values_of_only_call()
    assert "./services/checkout" in values, (
        "the headline `<description-or-path>` argument must reach intake "
        f"unchanged (plan §3); the call carried {intake.only_call!r}"
    )
    assert "guided" in values, (
        "the caller's `--mode` must reach intake (F2/F4); the call carried "
        f"{intake.only_call!r}"
    )


def test_the_wrapper_does_not_write_the_documents_intake_owns(project):
    """N30 — asserted on the filesystem, so a grown-in intake cannot hide.

    The injected pipeline deliberately writes nothing. If, after the run,
    `profile.yaml` or `threats.yaml` exists, the wrapper produced it itself:
    it reimplemented intake. The run may legitimately fail for want of a
    model — the filesystem verdict is what this test is about.
    """

    module = sdr_entry()
    intake = RecordingIntake(materialise_into=None)

    try:
        module.design_review(
            project,
            argument="./services/checkout",
            mode="quick",
            invoke_intake=intake,
        )
    except Exception:  # noqa: BLE001 - a modelless run may legitimately fail
        pass

    store = project / STORE_DIRNAME
    for name in INTAKE_OWNED_DOCUMENTS:
        assert not (store / name).exists(), (
            f"the wrapper wrote {STORE_DIRNAME}/{name} itself; intake owns that "
            "document (plan §2.1 decision 5 — never reimplement intake)"
        )


def test_the_two_interview_depths_mean_what_section_three_says_they_mean():
    """§3 Modes — guided is the seven-question interview, quick the five."""

    module = sdr_entry()

    guided_depth = attribute(module, "GUIDED_INTERVIEW_DEPTH")
    quick_depth = attribute(module, "QUICK_INTERVIEW_DEPTH")
    assert guided_depth != quick_depth, (
        "guided and quick must be distinguishable interview depths, not the "
        f"same value ({guided_depth!r})"
    )

    question_count = attribute(module, "GUIDED_QUESTION_COUNT")
    assert question_count == 7, (
        "guided is the full seven-question interview — sec-req-init.md:72 "
        '"Ask the seven questions. Not more."; got '
        f"{question_count!r}"
    )

    critical_unknowns = attribute(module, "CRITICAL_UNKNOWNS")
    normalized = {
        str(item).strip().lower().replace("-", "_").replace(" ", "_")
        for item in critical_unknowns
    }
    assert len(normalized) == 5, (
        "quick mode asks the five critical unknowns and nothing more "
        f"(plan §3); got {sorted(normalized)}"
    )
    for expected in (
        "authentication",
        "internet_exposure",
        "sensitive_data",
        "isolation",
        "privileged_access",
    ):
        assert expected in normalized, (
            f"the five critical unknowns must include `{expected}` "
            f"(plan §3 Modes); got {sorted(normalized)}"
        )


@pytest.mark.parametrize(
    "mode,depth_attribute",
    [
        ("guided", "GUIDED_INTERVIEW_DEPTH"),
        ("quick", "QUICK_INTERVIEW_DEPTH"),
    ],
)
def test_mode_sets_the_interview_depth_handed_to_intake(project, mode, depth_attribute):
    """F4 / N30 — `--mode` is what sets intake depth, asserted by call."""

    module = sdr_entry()
    expected_depth = attribute(module, depth_attribute)
    intake = RecordingIntake(materialise_into=project)

    module.design_review(
        project,
        argument="./services/checkout",
        mode=mode,
        invoke_intake=intake,
    )

    values = intake.values_of_only_call()
    assert expected_depth in values, (
        f"`--mode {mode}` must hand `{depth_attribute}` "
        f"({expected_depth!r}) to intake (plan §3 Modes, F4); the call "
        f"carried {intake.only_call!r}"
    )


def test_the_default_mode_is_quick_when_the_caller_names_none(project):
    """§3 — `--mode` defaults to quick, and the default reaches intake."""

    module = sdr_entry()
    quick_depth = attribute(module, "QUICK_INTERVIEW_DEPTH")
    intake = RecordingIntake(materialise_into=project)

    module.design_review(
        project, argument="./services/checkout", invoke_intake=intake
    )

    values = intake.values_of_only_call()
    assert quick_depth in values, (
        "the documented default `--mode quick` must reach intake at quick "
        f"depth; the call carried {intake.only_call!r}"
    )


def test_quick_mode_hands_intake_no_flag_that_would_relax_the_gate(project):
    """§3 last paragraph — quick never relaxes the build/refresh gate."""

    module = sdr_entry()
    intake = RecordingIntake(materialise_into=project)

    module.design_review(
        project,
        argument="./services/checkout",
        mode="quick",
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
            "quick mode must not relax the gate for /sec-req-build or "
            f"/sec-req-refresh (plan §3); the intake call carried {offenders!r} "
            f"matching `{token}`"
        )
    for key, value in kwargs.items():
        assert not (key.strip().lower() == "confirmed" and value), (
            "quick mode must not pre-confirm intake; the call carried "
            f"{key}={value!r}"
        )


# --------------------------------------------------------------------------
# N31 — store present, no argument: score as-is, no intake, no rewriting.
# --------------------------------------------------------------------------


def test_with_a_store_present_and_no_argument_intake_never_runs(project):
    """N31 — asserted as a zero call count, not as "scoring happened"."""

    module = sdr_entry()
    write_store(project)
    intake = RecordingIntake(materialise_into=None)

    module.design_review(project, invoke_intake=intake)

    assert intake.call_count == 0, (
        "with a store present and no argument the existing model is scored "
        "as-is; no intake may run (plan §3, §8, N31); saw "
        f"{intake.call_count} invocations: {intake.calls!r}"
    )


def test_scoring_an_existing_model_does_not_rewrite_a_single_stored_byte(project):
    """N31 — scoring must not mutate the model it scores."""

    module = sdr_entry()
    write_store(project)
    before = store_bytes(project)
    assert before, "the store fixture must materialise documents to compare"

    module.design_review(project, invoke_intake=RecordingIntake())

    after = store_bytes(project)
    changed = sorted(
        name
        for name in set(before) | set(after)
        if before.get(name) != after.get(name)
    )
    assert not changed, (
        "scoring rewrote the model it scores; these documents under "
        f"{STORE_DIRNAME}/ changed: {changed}"
    )


def test_an_argument_with_a_store_present_selects_evidence_without_intake(project):
    """§3 — the argument selects or refreshes the evidence source only."""

    module = sdr_entry()
    write_store(project)
    intake = RecordingIntake(materialise_into=None)

    record = module.design_review(
        project, argument="./services/checkout", invoke_intake=intake
    )

    assert intake.call_count == 0, (
        "store present with an argument still runs no intake — the argument "
        "selects or refreshes the evidence source (plan §3); saw "
        f"{intake.call_count} invocations: {intake.calls!r}"
    )
    assert "./services/checkout" in flattened_strings(record.get("run")), (
        "the argument must be recorded as the evidence source in the run "
        f"header, not swallowed; the run block was {record.get('run')!r}"
    )


# --------------------------------------------------------------------------
# §8 — profile staleness vs branch head is reported in both modes.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("mode", ["quick", "guided"])
def test_profile_staleness_against_the_branch_head_is_reported_in_both_modes(
    project, mode
):
    """§3 / §8 — "If profile.yaml is older than the current branch head, both
    modes say so in the report header." Carried, never silently omitted."""

    module = sdr_entry()
    write_store(project)

    record = module.design_review(project, mode=mode, invoke_intake=RecordingIntake())

    profile = profile_block(record)
    assert "stale_vs_head" in profile, (
        f"`--mode {mode}` must report profile staleness against the branch "
        "head in the report header (`run.profile.stale_vs_head`, plan §4.2 / "
        f"§8); the profile block was {profile!r}"
    )
    assert isinstance(profile["stale_vs_head"], bool), (
        "`run.profile.stale_vs_head` is a stated fact, not an absence; got "
        f"{profile['stale_vs_head']!r}"
    )
