"""§4.2 — the output schema, and the fact that something checks it.

Plan of record: §4.2 (the JSON report contract), §10's `schema/design-review-1.0.0.json`
row (**NEW**), and §4.3.

Pinned contract under specification. Neither exists yet, so every test here is
RED by construction and fails by *name*:

    plugins/security-requirements/schema/design-review-1.0.0.json
        The published shape of the §4.2 record.

    scripts/sdr_schema.py
        load_schema() -> dict
        validate_report(report, schema=None) -> list[str]
            House convention (§10.1): returns problems, never raises.

Why a checker ships alongside the schema
----------------------------------------

`jsonschema` is not a dependency of this payload. README and CONTRIBUTING both
put the floor at Python 3.12 and PyYAML, and the runtime executes under `-I`,
so a schema validated only by an external library is a schema the shipped tool
cannot check. It would then be documentation that drifts from the code it
documents — and a report contract nobody enforces is exactly the thing §4.2
calls a *contract of record* to avoid.

So `sdr_schema` implements the subset of JSON Schema this document actually
uses, and one test below pins that subset closed: a schema growing a keyword
the checker ignores would otherwise silently stop being enforced.

The schema is asserted against a *real* `build_report` result rather than a
hand-written sample. A schema written from the same understanding that produced
the sample validates the author's belief about the record, not the record.
"""

from __future__ import annotations

import copy
from datetime import date
import json
from pathlib import Path
import sys

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
PLUGIN_ROOT = REPO_ROOT / "plugins" / "security-requirements"
PLUGIN_SCRIPTS = PLUGIN_ROOT / "scripts"
if str(PLUGIN_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(PLUGIN_SCRIPTS))

import risk as risk_mod  # noqa: E402

SCHEMA_PATH = PLUGIN_ROOT / "schema" / "design-review-1.0.0.json"
SCHEMA_MODULE_PATH = PLUGIN_SCRIPTS / "sdr_schema.py"

#: §4.2 line 181. The schema's version is the *report's* version, and the file
#: name carries it so two report versions can ship side by side.
SCHEMA_VERSION = "1.0.0"

#: The JSON Schema keywords `sdr_schema` implements. Pinned so a schema that
#: grows a keyword the checker does not understand fails loudly rather than
#: silently going unenforced.
SUPPORTED_KEYWORDS = frozenset(
    {
        "$schema",
        "$id",
        "title",
        "description",
        "type",
        "properties",
        "required",
        "items",
        "enum",
        "additionalProperties",
        "const",
    }
)


def _sdr_schema():
    try:
        import sdr_schema
    except ImportError as exc:  # pragma: no cover - the RED path
        pytest.fail(
            f"{SCHEMA_MODULE_PATH} does not exist yet. §10 gives the report a "
            "published schema, and a schema the shipped payload cannot check is "
            "documentation rather than a contract — `jsonschema` is not a "
            "dependency and the runtime executes under `-I`. Expected "
            "`load_schema()` and `validate_report(report, schema=None) -> "
            f"list[str]`. import failed: {exc}"
        )
    return sdr_schema


def _schema_document() -> dict:
    assert SCHEMA_PATH.is_file(), (
        f"{SCHEMA_PATH} does not exist. §10 lists it as NEW: the §4.2 record is "
        "a contract of record and this is the published form of it"
    )
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# A real report, built by the real assembler.
# ---------------------------------------------------------------------------

PINNED_TODAY = date(2026, 5, 1)
PINNED_TIMESTAMP = "2026-08-29T05:57:00Z"

ARCHITECTURE = {
    "version": "0.1.0",
    "actors": [
        {"id": "act-customer", "name": "Customer", "evidence_status": "observed"}
    ],
    "components": [
        {
            "id": "cmp-checkout-api",
            "name": "checkout-api",
            "evidence_status": "observed",
            "trust_boundary": "tb-internet",
        }
    ],
    "data_stores": [],
    "data_flows": [],
    "trust_boundaries": [
        {"id": "tb-internet", "name": "Internet edge", "evidence_status": "observed"}
    ],
    "assets": [],
    "dependencies": [],
    "assumptions": ["Ingress terminates TLS at the ALB"],
}

THREATS = {
    "version": "0.2.0",
    "profile": "checkout",
    "boundaries": [{"id": "tb-internet", "from": "internet", "to": "checkout-api"}],
    "threats": [
        {
            "id": "T-09",
            "risk_family": "RF-09",
            "category": "STRIDE:T",
            "novelty": "service_specific",
            "persona": "anonymous_external",
            "attack_path": "unauthenticated_write_across_boundary",
            "scenario": "Anonymous caller alters line items.",
            "affected_assets": ["order_records"],
            "related_controls": ["AC-3"],
            "boundary": "tb-internet",
            "lifecycle": {"status": "active", "superseded_by": []},
        }
    ],
}

PROPOSED = {
    "likelihood": {
        "criterion": "L4-PUBLIC-LOW-COMPLEXITY",
        "rationale": ["Reachable from the internet."],
        "evidence": {
            "exposure": "internet",
            "access_required": "none",
            "exploit_complexity": "low",
            "preconditions": ["known order id"],
            "observed_controls": ["rate limit"],
        },
    },
    "consequences": [
        {
            "id": "c-tamper",
            "axis": "integrity",
            "criterion": "I4-CROSS-SYSTEM",
            "rationale": ["Direct financial record mutation."],
        }
    ],
    "impact": {"selected_from": "c-tamper"},
}


def _report() -> dict:
    import sdr_report
    import sdr_scope

    policy = risk_mod.appetite_policy("standard")
    assessment = {
        "version": "0.2.0",
        "assessments": [
            {
                "threat_id": "T-09",
                "status": "CONFIRMED",
                "proposed": copy.deepcopy(PROPOSED),
                "calculated": risk_mod.calculate_inherent(
                    policy, copy.deepcopy(PROPOSED)
                ),
            }
        ],
    }
    documents = {
        "policy": policy,
        "threats": copy.deepcopy(THREATS),
        "assessment": assessment,
        "requirements": {"version": "0.1.0", "requirements": []},
        "evidence": {"version": "0.1.0", "evidence": []},
        "architecture": copy.deepcopy(ARCHITECTURE),
    }
    entry = {
        "run": {
            "mode": "quick",
            "interview_depth": "five_critical_unknowns",
            "evidence_source": None,
            "intake_invoked": False,
            "profile": {
                "stale_vs_head": False,
                "compared_against": None,
                "unconfirmed_critical_facts": [],
            },
            "critical_facts": [],
        }
    }
    return sdr_report.build_report(
        documents,
        entry=entry,
        scope_record=sdr_scope.resolve_scope(copy.deepcopy(ARCHITECTURE), None),
        confirmation=None,
        risk_appetite="standard",
        invocation={
            "platform": "claude",
            "model": "claude-opus-5",
            "plugin_version": "0.2.0",
            "command": "sec-req-design-review",
            "timestamp": PINNED_TIMESTAMP,
        },
        today=PINNED_TODAY,
    )


def _problems(report, schema=None) -> list[str]:
    problems = _sdr_schema().validate_report(report, schema)
    assert isinstance(problems, list), (
        "validate_report follows the house `validate_*` convention and returns "
        f"a list of problem strings; got {type(problems)!r}"
    )
    for problem in problems:
        assert isinstance(problem, str), (
            f"every problem is a human-readable string; got {problem!r}"
        )
    return problems


# ---------------------------------------------------------------------------
# The schema document itself.
# ---------------------------------------------------------------------------


def test_the_schema_file_is_parseable_json():
    document = _schema_document()

    assert isinstance(document, dict), (
        f"the schema is a JSON object; got {type(document)!r}"
    )


def test_the_schema_declares_the_report_version_it_describes():
    document = _schema_document()

    assert SCHEMA_VERSION in str(document.get("$id", "")), (
        "the schema's `$id` carries the report version it describes, so two "
        f"report versions can ship side by side; got {document.get('$id')!r}"
    )


def test_the_schema_pins_the_report_schema_version_as_a_constant():
    document = _schema_document()

    field = document.get("properties", {}).get("schema_version", {})
    assert field.get("const") == SCHEMA_VERSION, (
        "a 1.0.0 schema describes a 1.0.0 report and nothing else. Without a "
        "`const` the schema would silently accept a record written to a "
        f"different contract; got {field!r}"
    )


def test_the_schema_uses_only_keywords_the_shipped_checker_implements():
    """A keyword the checker ignores is a rule that is not enforced."""

    document = _schema_document()

    def keywords(node, seen):
        if isinstance(node, dict):
            for key, value in node.items():
                if key in ("properties",):
                    for child in value.values():
                        keywords(child, seen)
                    continue
                seen.add(key)
                keywords(value, seen)
        elif isinstance(node, list):
            for item in node:
                keywords(item, seen)
        return seen

    used = keywords(document, set())
    unsupported = sorted(
        word
        for word in used
        if word not in SUPPORTED_KEYWORDS and not word.startswith("_")
    )
    assert not unsupported, (
        "`sdr_schema` implements a subset of JSON Schema, and a keyword outside "
        "it is a rule the shipped payload cannot check — the schema would say "
        "one thing and the tool enforce another. Either implement these or stop "
        f"using them: {unsupported}"
    )


# ---------------------------------------------------------------------------
# The checker, against a real report.
# ---------------------------------------------------------------------------


def test_a_real_report_validates_against_the_published_schema():
    """The schema describes what `build_report` emits, not what it should.

    Built by the real assembler rather than hand-written: a schema checked only
    against a sample written from the same understanding validates the author's
    belief about the record, not the record.
    """

    problems = _problems(_report())

    assert problems == [], (
        "a report the assembler actually produced must satisfy the published "
        f"schema; got {problems}"
    )


def test_validate_report_never_raises_on_malformed_input():
    for report in (None, [], "not-a-report", {}, {"run": "not-a-mapping"}):
        try:
            _problems(report)
        except Exception as exc:  # noqa: BLE001 - the point of the test
            pytest.fail(
                "validate_report returns problems rather than raising "
                f"(§10.1); {report!r} raised {exc!r}"
            )


def test_a_missing_required_block_is_reported_by_name():
    report = _report()
    del report["verdict"]

    problems = _problems(report)

    assert any("verdict" in problem for problem in problems), (
        "a required block that is absent must be named, or the operator has to "
        f"diff the schema by hand to find it; got {problems}"
    )


def test_a_block_of_the_wrong_type_is_reported():
    report = _report()
    report["findings"] = {"not": "a list"}

    problems = _problems(report)

    assert any("findings" in problem for problem in problems), (
        f"`findings` is a list and a mapping is not one; got {problems}"
    )


def test_an_unknown_top_level_key_is_reported():
    report = _report()
    report["extra_block"] = {"leaked": True}

    problems = _problems(report)

    assert any("extra_block" in problem for problem in problems), (
        "the record's top level is closed. An unrecognised block is either a "
        "field that escaped review or a consumer reading a contract this schema "
        f"does not describe; got {problems}"
    )


def test_a_wrong_schema_version_is_reported():
    report = _report()
    report["schema_version"] = "2.0.0"

    problems = _problems(report)

    assert problems, (
        "a 1.0.0 schema must reject a record claiming another version rather "
        "than validating it against rules that no longer apply"
    )


def test_every_problem_names_where_it_was_found():
    report = _report()
    report["findings"] = "not a list"
    del report["verdict"]

    problems = _problems(report)

    assert len(problems) >= 2, (
        "every offending field is reported, not the first — a record with three "
        f"faults should take one round of review, not three; got {problems}"
    )


def test_validation_is_deterministic_across_two_calls():
    report = _report()
    report["findings"] = "not a list"

    assert _problems(report) == _problems(report), (
        "§4.3: problem order must be stable, or a diff of two runs shows "
        "spurious churn"
    )


def test_validate_report_does_not_mutate_the_report():
    report = _report()
    before = copy.deepcopy(report)

    _problems(report)

    assert report == before, (
        "the validator reads the record; mutating it would leave the artifact "
        "writer serialising something the validator invented"
    )


def test_load_schema_returns_the_published_document():
    loaded = _sdr_schema().load_schema()

    assert loaded == _schema_document(), (
        "`load_schema` reads the shipped file rather than carrying a second "
        "copy in Python, which would drift from the published one"
    )
