"""N36 / N39 / N40 — the run guardrails and the determinism claims.

Plan of record: `docs/security-design-review-plan.md` §7 constraint 18 ("Any
network call, subprocess execution of project code, installer, build, or test
run" is an invalid state), §11.2 "Guardrails" N36, §11.2 "Determinism" N39 and
N40, and §14 ("No network access of any kind").

Three ids.

**N36** — "A full run makes no network call and no subprocess execution of
project code — asserted by patching `socket` and `subprocess` to raise."
Asserted over the engine calls and over the entry wrapper, `scripts/sdr_entry.py`
(plan §10, F2/F4), which is what makes "a full run" a single call.

**N39** — "Two runs with `today` and `confirmed_at` pinned produce an identical
`canonical_digest` over the report." GREEN, and asserted twice over: the digest
survives two builds, and it survives two builds taken under two *different*
wall clocks, which is the property that makes pinning worth anything.

**N40** — "The non-injectable clock call sites affect only timestamp metadata,
never a score, rating, or material digest. If that cannot be shown, those sites
gain a `today` parameter before shipping."

    It could not be shown. The sites gained the parameter.

Four reads of the wall clock reached something that is not timestamp metadata.
N40's remedy is the parameter, not a clock-independent answer — an acceptance
past its expiry genuinely *is* stale, and a default that ignored the date would
report it as current. So each site below is asserted twice: the pin wins over
the wall clock, and the default still expires.

1. `_risk_snapshot` was the real bug. It called `aggregate_risk(threats,
   assessment)` with no `today`; `aggregate_risk` fell back to `date.today()`,
   an expired acceptance flipped the aggregate's `status` from `confirmed` to
   `provisional`, and the whole snapshot was fed to `canonical_digest` as
   `snapshot_digest`. That digest is what `risk_state_digest` binds in the
   confirmation record, so a confirmation stopped matching on a date nobody
   chose. It now defaults `today` to the date in its own `assessed_at`: a
   snapshot is a view of one moment and must be scored as of that moment.
   There is no clock fallback — an unparseable `assessed_at` raises, because
   substituting the calendar there would restore the bug for exactly the
   inputs that are already malformed.
2. `derive_risk_links` turns `risk_exposure` from a rating into `STALE` when an
   acceptance expiry passes. `risk_exposure` is drawn from `risk.RATINGS` and
   the plan's §4.3 ordering contract sorts on it. The `today` parameter already
   existed; this file pins that it is honoured.
3. `calculate_residual` already took `today`, but `stamp_residual_assessment`
   supplied `date.today()` with no override — three separate times, so one run
   could straddle midnight and score against two days. It now takes a `today`
   of its own and reads the clock once.
4. `validate_assessment` was non-injectable end to end: it hardcoded
   `validate_treatment(record, policy, date.today())` with no parameter to
   pass. A verdict is not a score, rating, or digest, so it did not violate
   N40's enumeration — but it violated N40's headline, and a reviewer is
   entitled to reproduce a verdict. It now takes `today`.

What is genuinely GREEN under N40 is asserted too, because that is the half the
extension must not break: `calculate_inherent` takes no clock at all, and
`policy_digest`, `assessment_digest`, `threat_digest`,
`aggregate_threat_digest`, `render_register`, and `render_public_summary` are
all clock-independent.

Clock census (§11.2 N40 asks for the call sites; here they are, read from
source, not from the plan). `risk.py` is under concurrent edit for the command
surface, so line numbers are as of the read; the census *test* keys on
`(file, function, expression)` and does not depend on them:

    plugins/security-requirements/scripts/risk.py:695   calculate_residual
    plugins/security-requirements/scripts/risk.py:1064  validate_assessment
    plugins/security-requirements/scripts/risk.py:1094  aggregate_risk
    plugins/security-requirements/scripts/risk.py:1183  derive_risk_links
    plugins/security-requirements/scripts/risk.py:2279  _confirmation_metadata
    plugins/security-requirements/scripts/risk.py:2680  stamp_assessment
    plugins/security-requirements/scripts/risk.py:3023  stamp_residual_assessment
    plugins/security-requirements/scripts/risk.py:3028  stamp_residual_assessment
    plugins/security-requirements/scripts/risk.py:3076  stamp_residual_assessment
    plugins/security-requirements/scripts/risk.py:3109  stamp_residual_assessment
    plugins/security-requirements/scripts/risk.py:3247  refresh_persisted_assessment
    plugins/security-requirements/scripts/risk.py:3486  write_migration
    plugins/security-requirements/scripts/risk.py:3632  main
    plugins/security-requirements/scripts/risk.py:3649  main
    plugins/security-requirements/scripts/risk.py:3666  main
    plugins/security-requirements/scripts/lint.py:881   lint
    plugins/security-requirements/scripts/confirmation.py:43  stamp
    plugins/security-requirements/scripts/semantic_review.py:39  stamp

Line numbers drift, so the census test below freezes the
``(file, function, expression)`` triples instead and reads them with `ast`.
A new clock read anywhere in `scripts/` fails that test until somebody
classifies it.

Deliberate non-duplication:

* `tests/test_sdr_regression_baseline.py` already shows that `policy_digest`
  and `aggregate_threat_digest` ignore a pinned `confirmation` block. This file
  does not repeat that. It extends the coverage to the sites that test does not
  touch: the aggregate, the snapshot digest, the residual, the risk links, and
  the two renderers.
* `tests/risk_helpers.py` and `tests/conftest.py` are shared and untouched.
  Every builder below is local. Note that `risk_helpers.run_risk_golden`
  legitimately shells out via `subprocess` to drive the confirmation CLI — that
  is the product's own isolated-interpreter boundary, not "subprocess execution
  of project code" in the §7.18 sense. The N36 ban below is scoped to the
  in-process engine calls and never runs `run_risk_golden`.
"""

from __future__ import annotations

import ast
import contextlib
import copy
from datetime import date, datetime, timezone
from pathlib import Path
import socket
import subprocess
import sys
import warnings


REPO_ROOT = Path(__file__).resolve().parent.parent
PLUGIN_ROOT = REPO_ROOT / "plugins" / "security-requirements"
PLUGIN_SCRIPTS = PLUGIN_ROOT / "scripts"
if str(PLUGIN_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(PLUGIN_SCRIPTS))

import lint as lint_mod  # noqa: E402
import risk  # noqa: E402
import sdr_attack_paths  # noqa: E402
import sdr_mermaid  # noqa: E402


DEFAULT_POLICY_PATH = PLUGIN_ROOT / "risk" / "default-policy.yaml"

#: The entry wrapper N36's "a full run" needs (plan §10, F2/F4 row, **NEW**).
ENTRY_MODULE_PATH = PLUGIN_SCRIPTS / "sdr_entry.py"

#: Two dates straddling every expiry used below. Nothing else about the fixture
#: changes between them, so any observed difference is the calendar and only
#: the calendar.
BEFORE_EXPIRY = "2026-05-01"
AFTER_EXPIRY = "2026-07-01"

#: The same two dates as `date` objects, for the parameters that take one.
BEFORE_EXPIRY_DATE = date.fromisoformat(BEFORE_EXPIRY)
AFTER_EXPIRY_DATE = date.fromisoformat(AFTER_EXPIRY)
ACCEPTANCE_EXPIRES = "2026-06-01"
EVIDENCE_VALID_UNTIL = "2026-06-01"

#: N39's pins. Every date the report needs is supplied, so no engine call under
#: test has an excuse to read a clock.
PINNED_TODAY = date(2026, 5, 1)
PINNED_CONFIRMED_AT = "2026-01-01T00:00:00Z"

#: The clock expressions the census recognises. `time.time()` is included even
#: though nothing uses it today: the point of a census is to notice arrivals.
CLOCK_EXPRESSIONS = frozenset(
    {
        "date.today()",
        "date.fromtimestamp()",
        "datetime.now()",
        "datetime.today()",
        "datetime.utcnow()",
        "datetime.fromtimestamp()",
        "time.time()",
        "time.time_ns()",
    }
)

#: PRE-EXTENSION CENSUS — every wall-clock read in the shipped scripts, keyed by
#: `(file, enclosing function, expression)` so it survives line drift. A new
#: entry means a new clock read that nobody has classified against N40.
BASELINE_CLOCK_SITES = {
    ("confirmation.py", "stamp", "datetime.now()"): 1,
    ("lint.py", "lint", "date.today()"): 1,
    ("risk.py", "calculate_residual", "date.today()"): 1,
    ("risk.py", "validate_assessment", "date.today()"): 1,
    ("risk.py", "aggregate_risk", "date.today()"): 1,
    ("risk.py", "derive_risk_links", "date.today()"): 1,
    ("risk.py", "_confirmation_metadata", "datetime.now()"): 1,
    ("risk.py", "stamp_assessment", "datetime.now()"): 1,
    # Was 3 — three independent reads, which could straddle midnight and score
    # one run against two days. Now one read, threaded through (plan §11.2 N40).
    ("risk.py", "stamp_residual_assessment", "date.today()"): 1,
    ("risk.py", "stamp_residual_assessment", "datetime.now()"): 1,
    ("risk.py", "refresh_persisted_assessment", "datetime.now()"): 1,
    ("risk.py", "write_migration", "datetime.now()"): 1,
    ("risk.py", "main", "date.today()"): 3,
    # The design-review runner. Both are *fallbacks* for an omitted
    # `--confirmed-at`, which the subcommand now accepts precisely so a run can
    # be pinned (N39). When it is supplied neither fires, and `today` is
    # derived from the stamp rather than read separately — two reads could
    # straddle midnight and score one run against two days.
    ("risk.py", "_run_design_review", "datetime.now()"): 1,
    ("risk.py", "_run_design_review", "date.today()"): 1,
    ("semantic_review.py", "stamp", "datetime.now()"): 1,
}

#: Modules that must reach neither the network nor a child process, ever.
#: §7.18 is a property of the code, not only of one traced run, so it is
#: asserted statically as well as dynamically.
ENGINE_MODULES = (
    "risk.py",
    "lint.py",
    "render.py",
    "merge.py",
    "sdr_mermaid.py",
    "sdr_attack_paths.py",
    "safe_paths.py",
)

FORBIDDEN_IMPORTS = frozenset(
    {
        "socket",
        "subprocess",
        "urllib",
        "urllib.request",
        "http",
        "http.client",
        "requests",
        "httpx",
        "ftplib",
        "smtplib",
        "telnetlib",
        "asyncio",
        "xmlrpc",
    }
)


# --------------------------------------------------------------------------
# Local builders. Nothing here touches tests/risk_helpers.py.
# --------------------------------------------------------------------------


def _policy(*, publish: bool = False) -> dict:
    policy = risk.load_policy(DEFAULT_POLICY_PATH)
    policy["publish_risk_summary"] = publish
    return policy


def _threats() -> dict:
    return {
        "version": "0.2.0",
        "threats": [
            {
                "id": "T-01",
                "boundary": "TB-1",
                "category": "STRIDE:T",
                "novelty": "service_specific",
                "persona": "anonymous_external",
                "attack_path": "public_write_route",
                "scenario": "anonymous mutation of the catalogue",
                "affected_assets": ["movie_records"],
                "related_controls": ["AC-3"],
                "lifecycle": {"status": "active", "superseded_by": []},
            }
        ],
    }


def _proposal() -> dict:
    return {
        "likelihood": {
            "criterion": "L2-RESTRICTED",
            "evidence": {
                "exposure": "public",
                "access_required": "none",
                "exploit_complexity": "low",
                "preconditions": ["the write route is reachable"],
                "observed_controls": [],
            },
            "rationale": ["the write route is publicly reachable"],
        },
        "consequences": [
            {
                "id": "C-01",
                "asset": "movie_records",
                "axis": "integrity",
                "criterion": "I4-CROSS-SYSTEM",
                "affected_scope": "catalogue records and downstream consumers",
                "recoverability": "restore from backup and re-verify",
                "scope_expansion": {
                    "evidence": ["the route writes records other services read"]
                },
                "rationale": ["catalogue records are altered"],
            }
        ],
        "impact": {"selected_from": "C-01"},
    }


def _accepted_assessment(policy: dict) -> dict:
    """One CONFIRMED record whose acceptance expires between the two clocks."""

    proposal = _proposal()
    return {
        "assessments": [
            {
                "threat_id": "T-01",
                "status": "CONFIRMED",
                "proposed": proposal,
                "calculated": risk.calculate_inherent(policy, proposal),
                "treatment": {
                    "strategy": "accept",
                    "owner": "movie-service-team",
                    "approval": {
                        "approver": "movie-rating-risk-owner",
                        "role": "service_owner",
                        "rationale": "accepted for one release cycle",
                        "expires": ACCEPTANCE_EXPIRES,
                        "authority": "self_declared",
                    },
                },
            }
        ]
    }


def _managed_requirement() -> dict:
    return {
        "statement": "The catalogue write route rejects unauthenticated callers.",
        "verification": {"method": "test_case", "expect": "401 for anonymous POST"},
    }


def _requirements() -> dict:
    return {"requirements": [{"id": "REQ-1", "managed": _managed_requirement()}]}


def _evidence() -> dict:
    """Passing evidence that goes stale between the two clocks."""

    return {
        "evidence": [
            {
                "id": "EV-1",
                "requirement_id": "REQ-1",
                "method": "test_case",
                "result": "pass",
                "observed_at": "2026-01-02T00:00:00Z",
                "observed_by": "ci",
                "artifact": {
                    "kind": "test_log",
                    "location": "ci/runs/1/report.json",
                    "digest": "sha256:" + "ab" * 32,
                },
                "supports": ["likelihood"],
                "requirement_digest": risk.canonical_digest(_managed_requirement()),
                "valid_until": EVIDENCE_VALID_UNTIL,
            }
        ]
    }


def _residual_proposal() -> dict:
    proposal = _proposal()
    proposal["likelihood"] = {
        "criterion": "L2-RESTRICTED",
        "changed_attack_condition": "anonymous writes are rejected",
        "evidence_refs": ["EV-1"],
        "evidence": {
            "exposure": "internal",
            "access_required": "authenticated",
            "exploit_complexity": "non-trivial",
            "preconditions": ["a valid credential"],
            "observed_controls": ["route authentication"],
        },
        "rationale": ["the route now requires authentication"],
    }
    return proposal


def _architecture() -> dict:
    return {
        "actors": [{"id": "A-1", "name": "viewer", "evidence_status": "observed"}],
        "components": [
            {"id": "C-1", "name": "catalogue api", "evidence_status": "observed"},
            {"id": "C-2", "name": "rating worker", "evidence_status": "inferred"},
        ],
        "data_stores": [
            {"id": "D-1", "name": "movie table", "evidence_status": "observed"}
        ],
        "trust_boundaries": [
            {"id": "TB-1", "name": "public edge", "evidence_status": "observed"}
        ],
        "data_flows": [
            {
                "id": "F-1",
                "from": "A-1",
                "to": "C-1",
                "protocol": "https",
                "crosses": "TB-1",
                "evidence_status": "observed",
            },
            {
                "id": "F-2",
                "from": "C-1",
                "to": "D-1",
                "protocol": "tcp",
                "evidence_status": "inferred",
            },
        ],
    }


def _attack_paths() -> dict:
    return {
        "attack_paths": [
            {
                # `title`, and steps as bare threat ids — the shape
                # `validate_attack_paths` actually reads (`sdr_attack_paths.py:38`,
                # `sdr_attack_paths.py:81`), not the shape the plan's prose implies.
                "id": "AP-1",
                "title": "anonymous write to catalogue",
                "steps": ["T-01"],
            }
        ]
    }


def _report_summary(policy: dict, *, today: date, confirmed_at: str) -> dict:
    """A report summary built with every date supplied by the caller.

    This is the shape `render_register` and `render_public_summary` consume
    (`risk.py:1312`, `risk.py:1460`), assembled the way `risk_helpers`
    assembles the golden one — but with `today` threaded through every engine
    call so no clock read can reach it.
    """

    threats = _threats()
    assessment = _accepted_assessment(policy)
    records = []
    for record in assessment["assessments"]:
        threat = next(
            item for item in threats["threats"] if item["id"] == record["threat_id"]
        )
        residual = risk.calculate_residual(
            record["calculated"],
            _evidence(),
            policy,
            None,
            requirements=_requirements(),
            today=today,
        )
        records.append(
            {**copy.deepcopy(threat), **copy.deepcopy(record), "residual": residual}
        )
    return {
        "inherent": risk.aggregate_risk(threats, assessment, today=today),
        "residual": {
            "overall": "UNDETERMINED",
            "status": "provisional",
            "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "coverage": f"0/{len(records)}",
        },
        "risks": records,
        "architecture": _architecture(),
        "confirmation": {
            "status": "confirmed",
            "confirmed_by": "movie-rating-risk-owner",
            "confirmed_at": confirmed_at,
            "authority": "self_declared",
        },
    }


# --------------------------------------------------------------------------
# Clock control. `date.today` lives on an immutable C type, so the only honest
# way to move it is to swap the name the module resolved at import time for a
# subclass. It must be a *subclass*: `validate_treatment` does
# `isinstance(today, date)` (`risk.py:1493`), and a plain `date` is not an
# instance of a sibling class.
# --------------------------------------------------------------------------


def _frozen_date(iso: str) -> type:
    year, month, day = (int(part) for part in iso.split("-"))

    class _FrozenDate(date):
        @classmethod
        def today(cls) -> "_FrozenDate":
            return cls(year, month, day)

    return _FrozenDate


def _frozen_datetime(iso: str) -> type:
    year, month, day = (int(part) for part in iso.split("-"))

    class _FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz=None) -> "_FrozenDatetime":
            return cls(year, month, day, tzinfo=tz or timezone.utc)

        @classmethod
        def utcnow(cls) -> "_FrozenDatetime":
            return cls(year, month, day)

    return _FrozenDatetime


@contextlib.contextmanager
def _wall_clock(iso: str, *modules):
    """Move the wall clock the given modules read, and always put it back."""

    targets = modules or (risk,)
    saved = [(module, module.date, getattr(module, "datetime", None)) for module in targets]
    try:
        for module in targets:
            module.date = _frozen_date(iso)
            if hasattr(module, "datetime"):
                module.datetime = _frozen_datetime(iso)
        yield
    finally:
        for module, saved_date, saved_datetime in saved:
            module.date = saved_date
            if saved_datetime is not None:
                module.datetime = saved_datetime


# --------------------------------------------------------------------------
# Source census helpers.
# --------------------------------------------------------------------------


def _call_expression(node: ast.Call) -> str | None:
    func = node.func
    if not isinstance(func, ast.Attribute):
        return None
    base = func.value
    if not isinstance(base, ast.Name):
        return None
    return f"{base.id}.{func.attr}()"


def _parse(path: Path) -> ast.Module:
    # `rebuild_catalogs.py` carries a regex example in a plain docstring, which
    # raises a SyntaxWarning on compile. That is its own pre-existing business;
    # a census must not turn it into noise on every run of this file.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        return ast.parse(path.read_text(encoding="utf-8"))


def _clock_sites(path: Path) -> list[tuple[str, str, str]]:
    tree = _parse(path)
    found: list[tuple[str, str, str]] = []
    scope: list[str] = []

    class _Visitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node):  # noqa: N802 - ast API
            scope.append(node.name)
            self.generic_visit(node)
            scope.pop()

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_ClassDef(self, node):  # noqa: N802 - ast API
            scope.append(node.name)
            self.generic_visit(node)
            scope.pop()

        def visit_Call(self, node):  # noqa: N802 - ast API
            expression = _call_expression(node)
            if expression in CLOCK_EXPRESSIONS:
                found.append(
                    (path.name, scope[-1] if scope else "<module>", expression)
                )
            self.generic_visit(node)

    _Visitor().visit(tree)
    return found


def _imported_names(path: Path) -> set[str]:
    tree = _parse(path)
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


# ==========================================================================
# N36 — no network call, no subprocess execution of project code (§7.18)
# ==========================================================================


def test_the_scoring_and_rendering_engine_reaches_neither_a_socket_nor_a_child_process(
    monkeypatch,
):
    """N36 — the ban is armed, then the whole in-process engine is driven.

    Scope, stated so this test cannot be mistaken for more than it is: the
    patch below covers the engine calls made *inside this function*. It does
    not cover `risk_helpers.run_risk_golden`, which legitimately runs the
    confirmation CLI through `subprocess` under an isolated interpreter, and
    which is never called here.

    The body runs under a frozen calendar for a reason unrelated to N36: the
    fixture's acceptance expires on a fixed date and `validate_assessment`
    reads the real clock (`risk.py:1064`, and see the N40 tests below). Pinning
    it keeps this test asserting the guardrail rather than rotting into a date
    failure once the fixture ages out.
    """

    calls: list[str] = []

    def _refuse(name):
        def _blocked(*args, **kwargs):
            calls.append(name)
            raise AssertionError(f"§7.18 forbids {name} during a review run")

        return _blocked

    for attribute in ("socket", "create_connection", "getaddrinfo", "socketpair"):
        monkeypatch.setattr(
            socket, attribute, _refuse(f"socket.{attribute}"), raising=False
        )
    for attribute in ("Popen", "run", "call", "check_call", "check_output"):
        monkeypatch.setattr(
            subprocess, attribute, _refuse(f"subprocess.{attribute}"), raising=False
        )

    policy = _policy(publish=True)
    threats = _threats()
    assessment = _accepted_assessment(policy)

    with _wall_clock(BEFORE_EXPIRY, risk, lint_mod):
        inherent = risk.calculate_inherent(policy, _proposal())
        assert inherent["score"] == inherent["likelihood"] * inherent["impact"]

        residual = risk.calculate_residual(
            inherent,
            _evidence(),
            policy,
            None,
            requirements=_requirements(),
            today=PINNED_TODAY,
        )
        assert isinstance(residual, dict)

        aggregate = risk.aggregate_risk(threats, assessment, today=PINNED_TODAY)
        assert aggregate["coverage"] == "1/1"

        assert risk.validate_assessment(threats, assessment, policy) == []

        summary = _report_summary(
            policy, today=PINNED_TODAY, confirmed_at=PINNED_CONFIRMED_AT
        )
        register = risk.render_register(summary)
        assert "Internal risk register" in register

        public = risk.render_public_summary(summary, policy)
        assert public is not None and "Public risk summary" in public

        findings = lint_mod.check_public_safety("REQ-1", _managed_requirement())
        assert isinstance(findings, list)

        diagram = sdr_mermaid.render_dfd(_architecture())
        assert diagram.startswith("flowchart")

        problems = sdr_attack_paths.validate_attack_paths(_attack_paths(), threats)
        assert problems == []

    assert calls == [], f"the engine reached a forbidden call: {calls}"


def test_no_engine_module_even_imports_a_network_or_subprocess_facility():
    """N36 / §7.18 as a property of the source, not only of one traced run.

    A patched run proves the paths *this test walked* stay clean. A module that
    imports `subprocess` has a path some other input can walk.
    """

    offenders: dict[str, set[str]] = {}
    for name in ENGINE_MODULES:
        path = PLUGIN_SCRIPTS / name
        assert path.is_file(), f"{name} is missing from {PLUGIN_SCRIPTS}"
        forbidden = _imported_names(path) & FORBIDDEN_IMPORTS
        if forbidden:
            offenders[name] = forbidden
    assert offenders == {}, f"network or subprocess imports reached the engine: {offenders}"


def test_a_full_run_cannot_yet_be_placed_under_the_no_network_ban():
    """N36's *full run* half — RED, and honest about why.

    N36 says "a full run". The engine test above patches the ban around the
    scoring and rendering calls that exist today, which is every guardrail
    surface currently reachable. What it cannot cover is store detection, the
    init→build invocation, and interview depth — plan §10's F2/F4 row puts all
    three in `scripts/sdr_entry.py`, status **NEW**, and the module is not
    written. Store detection and an init→build invocation are precisely the
    steps most likely to shell out, so leaving them unasserted and calling N36
    covered would be the wrong kind of green.

    This fails rather than skips: a skipped guardrail test is invisible, and an
    invisible guardrail reads as a held one.
    """

    assert ENTRY_MODULE_PATH.is_file(), (
        f"{ENTRY_MODULE_PATH.relative_to(REPO_ROOT)} does not exist, so N36's "
        "'a full run makes no network call and no subprocess execution' cannot "
        "be asserted end to end. Plan §10 F2/F4."
    )


# ==========================================================================
# N39 — determinism under pinned dates
# ==========================================================================


def test_two_pinned_report_builds_produce_one_canonical_digest():
    """N39 — same pins, same digest."""

    policy = _policy(publish=True)
    first = _report_summary(
        policy, today=PINNED_TODAY, confirmed_at=PINNED_CONFIRMED_AT
    )
    second = _report_summary(
        policy, today=PINNED_TODAY, confirmed_at=PINNED_CONFIRMED_AT
    )

    assert risk.canonical_digest(first) == risk.canonical_digest(second)
    # The digest is only worth something if it is over a populated report.
    assert first["risks"] and first["inherent"]["coverage"] == "1/1"


def test_a_pinned_report_digest_survives_two_different_wall_clocks():
    """N39 — pinning `today` and `confirmed_at` is what makes the digest stable.

    Two builds under two calendars a month either side of every expiry in the
    fixture. If any engine call on the report path still read the clock behind
    the pin, this digest would move.
    """

    policy = _policy(publish=True)
    with _wall_clock(BEFORE_EXPIRY, risk):
        early = _report_summary(
            policy, today=PINNED_TODAY, confirmed_at=PINNED_CONFIRMED_AT
        )
    with _wall_clock(AFTER_EXPIRY, risk):
        late = _report_summary(
            policy, today=PINNED_TODAY, confirmed_at=PINNED_CONFIRMED_AT
        )

    assert risk.canonical_digest(early) == risk.canonical_digest(late)


def test_the_rendered_register_and_public_summary_are_byte_identical_across_renders():
    """N39 — rendering is a pure function of the summary, twice over."""

    policy = _policy(publish=True)
    summary = _report_summary(
        policy, today=PINNED_TODAY, confirmed_at=PINNED_CONFIRMED_AT
    )

    first_register = risk.render_register(summary)
    second_register = risk.render_register(copy.deepcopy(summary))
    assert first_register.encode("utf-8") == second_register.encode("utf-8")

    first_public = risk.render_public_summary(summary, policy)
    second_public = risk.render_public_summary(copy.deepcopy(summary), policy)
    assert first_public is not None
    assert first_public.encode("utf-8") == second_public.encode("utf-8")

    # The register carries the diagram (`risk.py:1327`), so this render is the
    # non-trivial one: a renderer iterating a set would surface here.
    assert "```mermaid" in first_register


def test_the_renderers_do_not_read_the_wall_clock():
    """N39 / N40 — the two renderers are clock-free.

    Rendering the same pinned summary under two calendars must produce the same
    bytes. This is the surface a reader compares between two review runs.
    """

    policy = _policy(publish=True)
    summary = _report_summary(
        policy, today=PINNED_TODAY, confirmed_at=PINNED_CONFIRMED_AT
    )

    with _wall_clock(BEFORE_EXPIRY, risk):
        early_register = risk.render_register(copy.deepcopy(summary))
        early_public = risk.render_public_summary(copy.deepcopy(summary), policy)
    with _wall_clock(AFTER_EXPIRY, risk):
        late_register = risk.render_register(copy.deepcopy(summary))
        late_public = risk.render_public_summary(copy.deepcopy(summary), policy)

    assert early_register.encode("utf-8") == late_register.encode("utf-8")
    assert early_public is not None
    assert early_public.encode("utf-8") == late_public.encode("utf-8")


# ==========================================================================
# N40 — the clock census, and what the clock is allowed to touch
# ==========================================================================


def test_the_clock_call_sites_in_the_shipped_scripts_are_the_ones_already_classified():
    """N40 — the census, so a new clock read cannot arrive unnoticed.

    Keyed on `(file, function, expression)` rather than line number: the
    extension will move lines, and a census that fails on every unrelated edit
    gets deleted. A census that fails when a *new* clock read appears is the
    one worth keeping, because N40 is a per-call-site claim.
    """

    observed: dict[tuple[str, str, str], int] = {}
    for path in sorted(PLUGIN_SCRIPTS.glob("*.py")):
        for site in _clock_sites(path):
            observed[site] = observed.get(site, 0) + 1

    new_sites = {site: count for site, count in observed.items() if site not in BASELINE_CLOCK_SITES}
    assert new_sites == {}, (
        "unclassified wall-clock read(s); each must be checked against N40 "
        f"(timestamp metadata only, never a score, rating, or digest): {new_sites}"
    )

    removed = {site for site in BASELINE_CLOCK_SITES if site not in observed}
    assert removed == set(), f"clock site disappeared without updating the census: {removed}"

    moved = {
        site: (BASELINE_CLOCK_SITES[site], observed[site])
        for site in BASELINE_CLOCK_SITES
        if site in observed and observed[site] != BASELINE_CLOCK_SITES[site]
    }
    assert moved == {}, f"clock read count changed inside a known function: {moved}"


def test_inherent_scores_ratings_and_material_digests_ignore_the_wall_clock():
    """N40, the half that holds — GREEN, and the half the extension must keep.

    `calculate_inherent` takes no clock argument at all, and the four material
    digests are taken over content. Moving the calendar past every expiry in
    the fixture moves none of them.

    Not a duplicate of `test_sdr_regression_baseline.py`: that file pins frozen
    digest *values* against a confirmation block. This one drives the calendar.
    """

    policy = _policy()
    threats = _threats()
    assessment = _accepted_assessment(policy)

    def _snapshot() -> dict:
        return {
            "inherent": risk.calculate_inherent(policy, _proposal()),
            "policy_digest": risk.policy_digest(policy),
            "assessment_digest": risk.assessment_digest(assessment),
            "aggregate_threat_digest": risk.aggregate_threat_digest(threats),
            "threat_digest": risk.threat_digest(threats["threats"][0]),
            "threat_material_digest": risk.threat_material_digest(threats["threats"][0]),
        }

    with _wall_clock(BEFORE_EXPIRY, risk):
        early = _snapshot()
    with _wall_clock(AFTER_EXPIRY, risk):
        late = _snapshot()

    assert early == late
    assert early["inherent"]["rating"] in risk.RATINGS


def test_the_aggregate_rating_coverage_and_counts_ignore_the_wall_clock():
    """N40, the half that holds — the numbers a reader quotes are clock-free.

    Asserted separately from `status` below, because these three fields are
    fine and the fourth is not. Collapsing them into one assertion would hide
    which is which.
    """

    policy = _policy()
    threats = _threats()
    assessment = _accepted_assessment(policy)

    with _wall_clock(BEFORE_EXPIRY, risk):
        early = risk.aggregate_risk(threats, assessment)
    with _wall_clock(AFTER_EXPIRY, risk):
        late = risk.aggregate_risk(threats, assessment)

    assert early["overall"] == late["overall"]
    assert early["counts"] == late["counts"]
    assert early["coverage"] == late["coverage"]


def test_the_snapshot_digest_does_not_move_when_only_the_wall_clock_moves():
    """N40 — RED. A non-injectable clock read reaches a material digest.

    `_risk_snapshot` (`risk.py:1610`) calls `aggregate_risk(threats,
    assessment)` and passes no `today`, so `aggregate_risk` falls back to
    `date.today()` (`risk.py:1094`). Once an acceptance expiry passes,
    `_expired_acceptance` (`risk.py:1662`) flips the aggregate's `status` from
    `confirmed` to `provisional`, that aggregate is embedded in the snapshot as
    `inherent`, and `snapshot_digest = canonical_digest(snapshot)`
    (`risk.py:1616`) is taken over the lot.

    Every input below is byte-identical between the two calls, including the
    `assessed_at` timestamp, which is pinned precisely so the calendar is the
    only variable. `snapshot_digest` is what `risk_state_digest` binds in the
    confirmation record, so a drifting value here silently invalidates a
    confirmation on a date nobody chose.

    N40's remedy is written into N40: "those sites gain a `today` parameter
    before shipping". Threading `today` through `_risk_snapshot` into
    `aggregate_risk` closes it.

    `_risk_snapshot` is private, and a guardrail test reaching for a private is
    a deliberate choice: the public callers (`stamp_assessment`,
    `refresh_persisted_assessment`, `write_migration`) all require an external
    confirmation store, and none of them would let this be shown as one clean
    variable.
    """

    policy = _policy()
    threats = _threats()
    assessment = _accepted_assessment(policy)
    requirements = _requirements()
    evidence = {"evidence": []}

    def _digest() -> str:
        return risk._risk_snapshot(
            "assessed",
            copy.deepcopy(threats),
            copy.deepcopy(assessment),
            copy.deepcopy(policy),
            copy.deepcopy(requirements),
            copy.deepcopy(evidence),
            PINNED_CONFIRMED_AT,
        )["snapshot_digest"]

    with _wall_clock(BEFORE_EXPIRY, risk):
        early = _digest()
    with _wall_clock(AFTER_EXPIRY, risk):
        late = _digest()

    assert early == late, (
        "the wall clock moved a material digest over byte-identical inputs: "
        f"{early} on {BEFORE_EXPIRY} vs {late} on {AFTER_EXPIRY}. "
        "risk.py:1610 must pass `today` into aggregate_risk (plan §11.2 N40)."
    )


def test_the_displayed_risk_exposure_rating_is_pinnable_against_the_wall_clock():
    """N40 — `derive_risk_links` is reproducible when `today` is supplied.

    `risk_exposure` is not decoration: `order_requirements` (`risk.py:1214`)
    is the plan's §4.3 single ordering choke point and sorts on the risk field,
    so an unpinnable date could reorder a published requirements document.

    What N40 asks for is the `today` parameter, not a clock-independent
    answer. The default *must* follow the calendar — `risk_exposure` becoming
    `STALE` once an acceptance expires is the feature, and a default that
    ignored the date would report an expired acceptance as current. What has
    to be true is that a caller can pin it, and that the pin wins over the
    clock. Both wall clocks below are deliberately on opposite sides of the
    expiry, so a `today` that were quietly ignored would show up here.
    """

    threats = _threats()
    assessment = _accepted_assessment(_policy())

    with _wall_clock(BEFORE_EXPIRY, risk):
        early = risk.derive_risk_links(
            ["T-01"], assessment, threats, today=AFTER_EXPIRY_DATE
        )
    with _wall_clock(AFTER_EXPIRY, risk):
        late = risk.derive_risk_links(
            ["T-01"], assessment, threats, today=AFTER_EXPIRY_DATE
        )

    assert early == late, (
        "an explicit `today` did not pin the displayed risk rating: "
        f"{early.get('risk_exposure')!r} vs {late.get('risk_exposure')!r} "
        "under two wall clocks (plan §11.2 N40)."
    )


def test_the_displayed_risk_exposure_rating_still_expires_by_default():
    """The other half of N40's remedy: the default must remain the calendar.

    Asserted so that "make it injectable" can never be satisfied by making it
    inert. An acceptance past its expiry is stale, and the default answer has
    to say so.
    """

    threats = _threats()
    assessment = _accepted_assessment(_policy())

    with _wall_clock(BEFORE_EXPIRY, risk):
        current = risk.derive_risk_links(["T-01"], assessment, threats)
    with _wall_clock(AFTER_EXPIRY, risk):
        expired = risk.derive_risk_links(["T-01"], assessment, threats)

    assert current["risk_exposure"] in risk.RATINGS, (
        "before the expiry the acceptance is current and must carry a real "
        f"rating; got {current['risk_exposure']!r}"
    )
    assert expired["risk_exposure"] == "STALE", (
        "after the expiry the default must report the acceptance stale, or the "
        f"expiry does nothing; got {expired['risk_exposure']!r}"
    )


def test_a_residual_rating_is_pinnable_against_the_wall_clock():
    """N40 — `calculate_residual` is reproducible when `today` is supplied.

    That date decides which evidence counts as current
    (`_current_passing_evidence`, `risk.py:629`), and the rating it produces is
    written into `risk-assessment.yaml`, so it reaches a material
    `assessment_digest`. `stamp_residual_assessment` used to supply it from
    `date.today()` with no override; it now takes a `today` of its own and
    reads the clock once, so a run cannot straddle midnight and score against
    two different days.
    """

    policy = _policy()
    inherent = {"likelihood": 3, "impact": 4, "score": 12, "rating": "high"}
    proposal = _residual_proposal()

    def _residual(today):
        try:
            return risk.calculate_residual(
                inherent,
                _evidence(),
                policy,
                copy.deepcopy(proposal),
                requirements=_requirements(),
                today=today,
            )
        except risk.RiskValidationError as exc:
            return f"RiskValidationError: {exc}"

    with _wall_clock(BEFORE_EXPIRY, risk):
        early = _residual(BEFORE_EXPIRY_DATE)
    with _wall_clock(AFTER_EXPIRY, risk):
        late = _residual(BEFORE_EXPIRY_DATE)

    assert early == late, (
        "an explicit `today` did not pin the residual outcome: "
        f"{early!r} vs {late!r} under two wall clocks (plan §11.2 N40)."
    )


def test_stamp_residual_assessment_accepts_a_today_it_can_be_pinned_with():
    """N40's remedy for `risk.py:3076`, asserted on the signature.

    The function needs a store, an external confirmation and refresh-bound
    state before it will do anything, so building a run here would test the
    fixture rather than the parameter. What N40 requires is that the injection
    point exists and is the single date the function threads — the two clock
    reads it used to make independently are the bug.
    """

    import inspect

    parameters = inspect.signature(risk.stamp_residual_assessment).parameters
    assert "today" in parameters, (
        "stamp_residual_assessment must take `today` so a residual rating, and "
        "the assessment_digest it lands in, can be reproduced (plan §11.2 N40)"
    )
    assert parameters["today"].default is None, (
        "`today` defaults to None and is resolved once inside, rather than "
        "defaulting to a date captured at import time; got "
        f"{parameters['today'].default!r}"
    )

    source = inspect.getsource(risk.stamp_residual_assessment)
    assert source.count("date.today()") == 1, (
        "the function must read the clock exactly once and thread that one "
        "date; reading it again could straddle midnight and score one run "
        f"against two days. Found {source.count('date.today()')} reads."
    )


def test_assessment_validation_is_pinnable_against_the_wall_clock():
    """N40 — `validate_assessment` was the one fully non-injectable site.

    It hardcoded `validate_treatment(record, policy, date.today())`, so a
    caller could not pin it at all and an expired acceptance turned a clean
    assessment into `['T-01 acceptance expired']` overnight.

    Read strictly against N40's enumeration a verdict is neither a score, a
    rating, nor a digest, so this was the mildest of the four. Read against
    N40's headline — "affect only timestamp metadata" — it failed: a validation
    verdict is not timestamp metadata, and a reviewer is entitled to reproduce
    one. It now takes `today`.
    """

    policy = _policy()
    threats = _threats()
    assessment = _accepted_assessment(policy)

    with _wall_clock(BEFORE_EXPIRY, risk):
        early = risk.validate_assessment(threats, assessment, policy, AFTER_EXPIRY_DATE)
    with _wall_clock(AFTER_EXPIRY, risk):
        late = risk.validate_assessment(threats, assessment, policy, AFTER_EXPIRY_DATE)

    assert early == late, (
        "an explicit `today` did not pin the validation verdict: "
        f"{early!r} vs {late!r} under two wall clocks (plan §11.2 N40)."
    )


def test_assessment_validation_still_reports_an_expired_acceptance_by_default():
    """The default stays the calendar, or the expiry check does nothing."""

    policy = _policy()
    threats = _threats()
    assessment = _accepted_assessment(policy)

    with _wall_clock(BEFORE_EXPIRY, risk):
        current = risk.validate_assessment(threats, assessment, policy)
    with _wall_clock(AFTER_EXPIRY, risk):
        expired = risk.validate_assessment(threats, assessment, policy)

    assert current == [], (
        f"before the expiry the assessment is valid; got {current!r}"
    )
    assert any("acceptance expired" in problem for problem in expired), (
        "after the expiry the default must report the acceptance expired, or a "
        f"stale acceptance validates clean forever; got {expired!r}"
    )


def test_the_published_summary_bytes_do_not_depend_on_the_wall_clock():
    """N40, the half that holds — the publish path is safe.

    `publish.py:184` calls `risk.aggregate_risk(threats, assessment)` with no
    `today`, which is the same omission that breaks the snapshot digest above.
    It is harmless *here* only because `render_public_summary` reads exactly
    `overall`, `counts`, and `coverage` (`risk.py:1409`) and never `status`.

    That is a property worth a test rather than a comment: the day
    `render_public_summary` grows a `status` row, the published document starts
    changing on a calendar boundary, and this test says so.
    """

    policy = _policy(publish=True)
    threats = _threats()
    assessment = _accepted_assessment(policy)

    with _wall_clock(BEFORE_EXPIRY, risk):
        early = risk.render_public_summary(
            {"inherent": risk.aggregate_risk(threats, assessment)}, policy
        )
    with _wall_clock(AFTER_EXPIRY, risk):
        late = risk.render_public_summary(
            {"inherent": risk.aggregate_risk(threats, assessment)}, policy
        )

    assert early is not None
    assert early.encode("utf-8") == late.encode("utf-8")
