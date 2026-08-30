"""F12 — the AI threat taxonomy applies only when there is AI to apply it to.

Plan of record: `docs/security-design-review-plan.md` F12 (line 491), §8 line
560, §9 change point 7, §10 (`scripts/sdr_ai_risk.py` — **NEW**), §10.1 (policy
as data, never a chain of `if`s), §4.3 (deterministic ordering), and §12's
constraint that "the AI threat list [is] policy data, never `if` branches".

    | F12 | Apply the AI threat taxonomy only when LLM/agent/RAG components
    |     | are detected or declared. |

    | No AI components | AI taxonomy not applied **and not mentioned**. |

**"Not mentioned" is the half that carries the weight.** A review that prints
"AI threats: none applicable" over a service with no AI has not obeyed §8. It
has added a line whose only function is to be skipped, and a reader trained to
skip one section skips the next one too. The absence has to be total: no key in
the report record, no heading in the rendered document, no sentence anywhere.
So the assertions below scan the artifacts for the *vocabulary* rather than for
one key — a key rename would slip past a key check, and the reader's experience
is of words on a page, not of JSON.

Every absence assertion here is paired with a presence assertion over the same
scan. "The word LLM does not appear" is also true of a build that never learned
the word, so on its own it cannot tell the rule from the absence of the rule.
The pair — silent for a service with no AI, explicit for one with AI — is the
property F12 and §8 actually encode.

Pinned contract under specification. `scripts/sdr_ai_risk.py` does **not**
exist, so the tests that reach it are RED by construction and fail by *name*:

    AI_COMPONENT_PATTERNS : tuple[tuple[str, re.Pattern], ...]
        `(why, pattern)` rows, in the shape of `risk.KEY_MATERIAL_PATTERNS` and
        `sdr_report.INSTRUCTION_PATTERNS`.

    AI_TAXONOMY : tuple[dict, ...]
        The threat categories, each carrying at least `{id, title, applies_to}`.

    detect_ai_components(architecture) -> list[dict]
        `{component_id, why}` per detected component. Sorted, deterministic.

    ai_coverage(architecture, threats) -> dict | None
        `None` when no AI component is present — "not mentioned" enforced at the
        source rather than by every consumer remembering to check a flag.
        Otherwise `{components, categories, uncovered}`.

Two interpretations are recorded here rather than assumed silently, because a
future reader deserves to know which line of the plan they came from:

* **`detect_ai_components` scans the whole architecture, not just the
  `components` block.** F12 names "LLM/agent/RAG components"; the pinned
  contract names "a vector store, or model endpoint" among the things to find.
  A vector store is a `data_stores` record and a hosted model endpoint is
  routinely a `dependencies` record (§4.2's seven kinds), so a scan restricted
  to `components` would miss exactly the two the contract spells out.
* **A threat "addresses" a taxonomy category when it names it unmistakably.**
  The shipped reference doc — `skills/deriving-security-requirements/
  references/ai-threats.md`, "Recording a finding" — is the closest thing to a
  join: "`category` carries the AI id alongside its STRIDE letter where one
  fits". The covering threats below are built *from the taxonomy itself* and
  carry the category id in `category`, in the normalized `attack_path`, in
  `related_controls`, and in the `scenario` prose alongside the category title.
  Any reasonable join matches such a record; none matches the retired one. A
  test that guessed a single field would report a gap in the guess rather than
  in the code.

Builders are local to this file. `tests/risk_helpers.py` and
`tests/conftest.py` are shared and are not depended on here.
"""

from __future__ import annotations

import copy
import json
import re
import shutil
from pathlib import Path
import sys

import pytest
import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
PLUGIN_ROOT = REPO_ROOT / "plugins" / "security-requirements"
PLUGIN_SCRIPTS = PLUGIN_ROOT / "scripts"
if str(PLUGIN_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(PLUGIN_SCRIPTS))

import risk as risk_mod  # noqa: E402
import sdr_entry  # noqa: E402
import sdr_report  # noqa: E402
import sdr_scope  # noqa: E402

AI_RISK_MODULE_PATH = PLUGIN_SCRIPTS / "sdr_ai_risk.py"
DISTRIBUTION_ALLOWLIST = REPO_ROOT / "scripts" / "validate_distribution.py"
#: §10 ships F12 as a module *plus* a reference doc. The doc is what a reviewer
#: reads; the table is what the tool applies. They are checked against each
#: other below so neither can drift into describing a taxonomy the other lacks.
AI_THREATS_REFERENCE = (
    PLUGIN_ROOT
    / "skills"
    / "deriving-security-requirements"
    / "references"
    / "ai-threats.md"
)

GOLDEN_CASE = REPO_ROOT / "golden" / "movie-rating-aws"
STORE_DIRNAME = ".security-requirements"
PREVIEW = f"{STORE_DIRNAME}/design-review.preview.md"

OK, PROBLEMS = 0, 1

#: Pinned so no test reads a clock (§4.3).
PINNED_STAMP = "2026-05-01T00:00:00Z"


# ---------------------------------------------------------------------------
# The module under specification, reached through accessors so a missing module
# fails each test by name rather than as one opaque collection error.
# ---------------------------------------------------------------------------


def _sdr_ai_risk():
    try:
        import sdr_ai_risk
    except ImportError as exc:  # pragma: no cover - the RED path
        pytest.fail(
            f"{AI_RISK_MODULE_PATH} does not exist yet. Plan §10 puts F12 in "
            "`scripts/sdr_ai_risk.py`, exposing AI_COMPONENT_PATTERNS, "
            "AI_TAXONOMY, detect_ai_components(architecture) and "
            f"ai_coverage(architecture, threats). import failed: {exc}"
        )
    return sdr_ai_risk


def _detect():
    module = _sdr_ai_risk()
    detector = getattr(module, "detect_ai_components", None)
    assert callable(detector), (
        "sdr_ai_risk must expose `detect_ai_components(architecture) -> "
        "list[dict]` returning a {component_id, why} record per detected "
        f"component; found {detector!r}"
    )
    return detector


def _coverage():
    module = _sdr_ai_risk()
    reporter = getattr(module, "ai_coverage", None)
    assert callable(reporter), (
        "sdr_ai_risk must expose `ai_coverage(architecture, threats) -> dict | "
        "None`, returning None when no AI component is present so that §8's "
        "'not mentioned' is enforced at the source rather than by every "
        f"consumer remembering to check a flag; found {reporter!r}"
    )
    return reporter


def _patterns():
    module = _sdr_ai_risk()
    table = getattr(module, "AI_COMPONENT_PATTERNS", None)
    assert table is not None, (
        "sdr_ai_risk must expose AI_COMPONENT_PATTERNS. §9 change point 7 and "
        "§12 both require the AI trigger to be policy data in the shape of "
        "`risk.KEY_MATERIAL_PATTERNS` — a new spelling is a row, never an `if`"
    )
    return table


def _taxonomy():
    module = _sdr_ai_risk()
    table = getattr(module, "AI_TAXONOMY", None)
    assert table is not None, (
        "sdr_ai_risk must expose AI_TAXONOMY, the threat categories. §10.1 "
        "lists 'the AI threat list' among the things that are data files"
    )
    return table


# ---------------------------------------------------------------------------
# Local builders. Ids are chosen so none is a substring of another.
# ---------------------------------------------------------------------------

TRUST_BOUNDARY = {
    "id": "tb-internet",
    "name": "Internet edge",
    "evidence_status": "observed",
}


def _component(component_id: str, name: str, **extra) -> dict:
    record = {
        "id": component_id,
        "name": name,
        "evidence_status": "observed",
        "trust_boundary": TRUST_BOUNDARY["id"],
    }
    record.update(extra)
    return record


def _architecture(**blocks) -> dict:
    """A §4.2 architecture with all seven kinds present, none of them AI."""

    document: dict = {
        "version": "0.1.0",
        "actors": [
            {"id": "act-customer", "name": "Customer", "evidence_status": "observed"}
        ],
        "components": [_component("cmp-checkout-api", "checkout-api")],
        "data_stores": [
            {
                "id": "ds-orders",
                "name": "orders-db",
                "evidence_status": "observed",
            }
        ],
        "data_flows": [],
        "trust_boundaries": [dict(TRUST_BOUNDARY)],
        "assets": [],
        "dependencies": [],
    }
    for kind, records in blocks.items():
        document[kind] = records
    return document


def _threats(*records: dict) -> dict:
    return {
        "version": "0.2.0",
        "profile": "checkout",
        "boundaries": [{"id": "tb-internet", "from": "internet", "to": "checkout-api"}],
        "threats": list(records),
    }


def _threat(threat_id: str, **extra) -> dict:
    record = {
        "id": threat_id,
        "risk_family": "RF-01",
        "category": "STRIDE:T",
        "novelty": "service_specific",
        "persona": "anonymous_external",
        "attack_path": "unauthenticated_write_across_boundary",
        "scenario": "Anonymous caller alters an order.",
        "affected_assets": ["order_records"],
        "related_controls": ["AC-3"],
        "boundary": "tb-internet",
        "evidence_status": "inferred",
        "confidence": "low",
    }
    record.update(extra)
    return record


def _category_id(category: object) -> str:
    assert isinstance(category, dict), (
        "every AI_TAXONOMY entry is a mapping carrying at least "
        f"{{id, title, applies_to}}; found {category!r}"
    )
    category_id = category.get("id")
    assert isinstance(category_id, str) and category_id.strip(), (
        f"every AI_TAXONOMY category carries a usable `id`; found {category!r}"
    )
    return category_id


def _covering_threat(category: dict, *, threat_id: str, **extra) -> dict:
    """A threat that addresses `category` under any reasonable join.

    `references/ai-threats.md` says "`category` carries the AI id alongside its
    STRIDE letter where one fits", so that is the primary link. The id is
    repeated in `attack_path`, `related_controls` and the scenario prose so a
    different join still resolves — a test that guessed one field would report
    a gap in the guess rather than in the code.
    """

    category_id = _category_id(category)
    title = category.get("title")
    return _threat(
        threat_id,
        category=f"STRIDE:T {category_id}",
        attack_path=category_id,
        ai_category=category_id,
        related_controls=["AC-3", category_id],
        scenario=(
            f"An attacker exploits {title} against the model-backed component "
            f"({category_id})."
        ),
        **extra,
    )


# ---------------------------------------------------------------------------
# The vocabulary §8 forbids on a service with no AI.
#
# Word-bounded on purpose. `storage` contains `rag` and the golden fixture uses
# the word freely; a substring scan would report the golden case as an AI
# service, which is precisely how §8's rule gets discredited. The same trap is
# waiting for `AI_COMPONENT_PATTERNS`, and `test_a_word_that_merely_contains_a
# _trigger_as_a_substring_is_not_a_match` holds the implementation to it.
# ---------------------------------------------------------------------------

AI_VOCABULARY: tuple[tuple[str, re.Pattern], ...] = (
    ("LLM", re.compile(r"\bLLMs?\b", re.I)),
    ("RAG", re.compile(r"\brag\b", re.I)),
    ("retrieval-augmented", re.compile(r"\bretrieval[- ]augmented\b", re.I)),
    ("prompt injection", re.compile(r"\bprompt\b", re.I)),
    ("jailbreak", re.compile(r"\bjail\s?break", re.I)),
    ("embedding", re.compile(r"\bembeddings?\b", re.I)),
    ("vector store", re.compile(r"\bvector\b", re.I)),
    ("agentic", re.compile(r"\bagentic\b", re.I)),
    ("model endpoint", re.compile(r"\bmodel endpoints?\b", re.I)),
    ("foundation model", re.compile(r"\bfoundation model\b", re.I)),
    ("inference", re.compile(r"\binference\b", re.I)),
    ("hallucination", re.compile(r"\bhallucinat\w*\b", re.I)),
    ("the bare acronym AI", re.compile(r"\bAI\b")),
    ("artificial intelligence", re.compile(r"\bartificial intelligence\b", re.I)),
    ("OpenAI", re.compile(r"\bopen\s?ai\b", re.I)),
    ("GPT", re.compile(r"\bgpt(?:-?\d\w*)?\b", re.I)),
    ("Claude", re.compile(r"\bclaude\b", re.I)),
    ("Bedrock", re.compile(r"\bbedrock\b", re.I)),
    ("SageMaker", re.compile(r"\bsage\s?maker\b", re.I)),
    ("Vertex AI", re.compile(r"\bvertex\b", re.I)),
)

#: Taxonomy vocabulary that appears nowhere in the store the AI fixture writes,
#: so finding it in an artifact proves the *taxonomy* was applied rather than
#: proving the component name was echoed back. `render_register` embeds the
#: Mermaid DFD, which names every component — so a scan that accepted the
#: component's own name would pass for a run that never loaded the taxonomy.
TAXONOMY_ONLY_VOCABULARY: tuple[tuple[str, re.Pattern], ...] = (
    ("prompt injection", re.compile(r"\bprompt\b", re.I)),
    ("the bare acronym AI", re.compile(r"\bAI\b")),
)


def _mentions(text: str, vocabulary=AI_VOCABULARY) -> list[str]:
    """Every AI term the text uses, with the matched span, in table order."""

    found: list[str] = []
    for term, pattern in vocabulary:
        for match in pattern.finditer(text):
            start = max(0, match.start() - 60)
            found.append(f"{term!r} at offset {match.start()}: ...{text[start:match.end() + 60]!r}...")
    return found


def _flatten(value: object, where: str = "") -> list[tuple[str, str]]:
    """Every key and string leaf in a record, with its dotted path."""

    out: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{where}.{key}" if where else str(key)
            out.append((path, str(key)))
            out.extend(_flatten(child, path))
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            out.extend(_flatten(child, f"{where}[{index}]"))
    elif isinstance(value, str):
        out.append((where, value))
    return out


def _record_mentions(record: object, vocabulary=AI_VOCABULARY) -> list[str]:
    found: list[str] = []
    for path, text in _flatten(record):
        for term, pattern in vocabulary:
            if pattern.search(text):
                found.append(f"{term!r} at {path or '<root>'}: {text!r}")
    return found


# ---------------------------------------------------------------------------
# A real store, driven end to end through `risk.main` (plan §3, §4.1).
# ---------------------------------------------------------------------------


def _architecture_for(threats: dict) -> dict:
    """The golden register's boundary ids, as a §4.2 architecture document."""

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
    """A repository whose complete store models no AI at all."""

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


def _declare_ai_component(project_root: Path) -> str:
    """Add one unmistakable LLM component to the store's architecture."""

    store = project_root / STORE_DIRNAME
    path = store / "architecture.yaml"
    architecture = yaml.safe_load(path.read_text(encoding="utf-8"))
    boundary = architecture["trust_boundaries"][0]["id"]
    architecture["components"] = [
        {
            "id": "cmp-summary-llm",
            "name": "summary-llm",
            "evidence_status": "observed",
            "trust_boundary": boundary,
        }
    ]
    path.write_text(yaml.safe_dump(architecture, sort_keys=True), encoding="utf-8")
    return "cmp-summary-llm"


def _argv(project_root: Path, *extra: str) -> list[str]:
    return [
        "design-review",
        "--project-root",
        str(project_root),
        "--output",
        str(project_root),
        "--confirmed-at",
        PINNED_STAMP,
        *extra,
    ]


def _written(project_root: Path) -> list[str]:
    return sorted(
        path.relative_to(project_root).as_posix()
        for path in project_root.rglob("*")
        if path.is_file()
    )


def _rendered_artifacts(project_root: Path) -> dict[str, str]:
    """Every artifact the run wrote, by relative path — store fixture excluded."""

    fixture = {
        "profile.yaml",
        "threats.yaml",
        "risk-assessment.yaml",
        "risk-state.yaml",
        "risk-policy.yaml",
        "architecture.yaml",
        "requirements.yaml",
        "risk-evidence.yaml",
        "attack-paths.yaml",
    }
    rendered: dict[str, str] = {}
    for name in _written(project_root):
        if Path(name).name in fixture:
            continue
        path = project_root / name
        try:
            rendered[name] = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):  # pragma: no cover - defensive
            continue
    return rendered


def _report_for(project_root: Path) -> dict:
    """The §4.2 record for this store, assembled exactly as the runner does."""

    documents = risk_mod._load_design_review_documents(project_root, "standard")
    return sdr_report.build_report(
        documents,
        entry=sdr_entry.design_review(project_root),
        scope_record=sdr_scope.resolve_scope(documents.get("architecture"), None),
        confirmation=None,
        risk_appetite="standard",
        invocation={"timestamp": PINNED_STAMP, "command": "design-review"},
        today=risk_mod._snapshot_assessed_date({"assessed_at": PINNED_STAMP}),
    )


# ---------------------------------------------------------------------------
# §9 change point 7, §10.1, §12 — the trigger and the taxonomy are data.
# ---------------------------------------------------------------------------


def test_the_ai_component_patterns_are_a_table_of_why_and_compiled_pattern_rows():
    table = _patterns()

    assert isinstance(table, tuple) and table, (
        "AI_COMPONENT_PATTERNS is a non-empty tuple of rows, like "
        f"`risk.KEY_MATERIAL_PATTERNS`; found {type(table).__name__} {table!r}"
    )
    for row in table:
        assert isinstance(row, tuple) and len(row) == 2, (
            f"every AI_COMPONENT_PATTERNS row is a (why, pattern) pair; found {row!r}"
        )
        why, pattern = row
        assert isinstance(why, str) and why.strip(), (
            "the first element states *why* a match is an AI component, in the "
            f"reader's words; found {why!r}"
        )
        assert hasattr(pattern, "search"), (
            "the second element is a compiled regular expression, so a new "
            "spelling is a row rather than an `if` branch somewhere in the "
            f"scan (§12); found {pattern!r}"
        )


def test_the_ai_taxonomy_is_a_table_of_categories_carrying_id_title_and_applies_to():
    taxonomy = _taxonomy()

    assert isinstance(taxonomy, tuple) and taxonomy, (
        "AI_TAXONOMY is a non-empty tuple of category mappings; found "
        f"{type(taxonomy).__name__} {taxonomy!r}"
    )
    for category in taxonomy:
        assert isinstance(category, dict), (
            f"every AI_TAXONOMY entry is a mapping; found {category!r}"
        )
        for key in ("id", "title", "applies_to"):
            assert key in category, (
                f"every taxonomy category carries at least {{id, title, "
                f"applies_to}}; {category!r} is missing {key!r}"
            )


def test_the_taxonomy_ids_match_the_shipped_reference_document():
    """§10 pairs `sdr_ai_risk.py` with a reference doc; they must agree.

    The doc is what a reviewer reads and the table is what the tool applies. A
    category in one and not the other means the review reports a gap nobody can
    look up, or a reviewer looks up a category the tool never checks.
    """

    assert AI_THREATS_REFERENCE.is_file(), (
        f"§10 ships F12 as `scripts/sdr_ai_risk.py` + reference doc; "
        f"{AI_THREATS_REFERENCE} is missing"
    )
    documented = re.findall(
        r"^###\s+(AI-\d+)\s+(.+?)\s*$",
        AI_THREATS_REFERENCE.read_text(encoding="utf-8"),
        re.M,
    )
    assert documented, (
        f"{AI_THREATS_REFERENCE} declares no `### AI-nn Title` categories, so "
        "there is no documented taxonomy for the table to match"
    )

    table = [(_category_id(category), category.get("title")) for category in _taxonomy()]

    assert [row[0] for row in table] == [row[0] for row in documented], (
        "AI_TAXONOMY carries exactly the categories the reference document "
        f"declares, in the same order. The doc says {[r[0] for r in documented]}; "
        f"the table says {[r[0] for r in table]}"
    )
    for (table_id, table_title), (_doc_id, doc_title) in zip(table, documented):
        assert table_title == doc_title, (
            f"{table_id} is titled {doc_title!r} in {AI_THREATS_REFERENCE.name} "
            f"and {table_title!r} in AI_TAXONOMY. A reader cannot map the "
            "review's wording back to the document that explains it"
        )


def test_every_taxonomy_category_id_is_unique():
    ids = [_category_id(category) for category in _taxonomy()]

    assert len(ids) == len(set(ids)), (
        "two categories sharing an id makes `uncovered` ambiguous — a reader "
        "cannot tell which of the two is unaddressed; ids were "
        f"{sorted(ids)}"
    )


# ---------------------------------------------------------------------------
# F12 — detection, by declared name and by kind.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "answer-llm",
        "support-agent",
        "rag-retriever",
        "vector-store",
        "embedding-index",
        "model-endpoint",
        "gpt-summarizer",
        "claude-reviewer",
        "bedrock-runtime",
        "openai-gateway",
    ],
)
def test_a_component_named_like_an_ai_system_is_detected(name):
    architecture = _architecture(
        components=[
            _component("cmp-checkout-api", "checkout-api"),
            _component("cmp-under-test", name),
        ]
    )

    detected = _detect()(architecture)
    detected_ids = [record.get("component_id") for record in detected]

    assert "cmp-under-test" in detected_ids, (
        f"F12 triggers on an LLM/agent/RAG component. A component named {name!r} "
        "is one, and the taxonomy has to be applied to it; "
        f"detect_ai_components returned {detected}"
    )


def test_detection_is_matched_on_shape_rather_than_on_one_fixtures_wording():
    """Case and separator are the author's choice, not a detection signal."""

    architecture = _architecture(
        components=[
            _component("cmp-upper", "Answer LLM"),
            _component("cmp-title", "Bedrock Runtime"),
            _component("cmp-underscore", "vector_store_reader"),
        ]
    )

    detected_ids = {
        record.get("component_id") for record in _detect()(architecture)
    }

    assert detected_ids == {"cmp-upper", "cmp-title", "cmp-underscore"}, (
        "F12 must not depend on how one architecture happens to spell a name. "
        f"'Answer LLM', 'Bedrock Runtime' and 'vector_store_reader' are all AI "
        f"components; detection found {sorted(detected_ids)}"
    )


def test_every_detection_record_names_the_component_and_why_it_matched():
    architecture = _architecture(
        components=[
            _component("cmp-checkout-api", "checkout-api"),
            _component("cmp-answer-llm", "answer-llm"),
        ]
    )

    detected = _detect()(architecture)

    assert detected, "the fixture declares an LLM component; detection found nothing"
    for record in detected:
        assert isinstance(record, dict), (
            f"detect_ai_components returns {{component_id, why}} records, in the "
            f"shape `sdr_report.untrusted_content` uses; found {record!r}"
        )
        assert set(record) >= {"component_id", "why"}, (
            "each record carries `component_id` and `why`, so a reader can see "
            "which element triggered the taxonomy and on what evidence; found "
            f"{record!r}"
        )
        assert isinstance(record["why"], str) and record["why"].strip(), (
            f"`why` is prose a reader can act on; found {record['why']!r}"
        )


def test_an_ai_element_declared_under_another_kind_is_detected():
    """A vector store is a data store and a hosted model is a dependency.

    The pinned contract names both among the things to find, and §4.2 gives
    each its own kind. A scan restricted to the `components` block would miss
    exactly the two the contract spells out.
    """

    architecture = _architecture(
        data_stores=[
            {
                "id": "ds-orders",
                "name": "orders-db",
                "evidence_status": "observed",
            },
            {
                "id": "ds-doc-vectors",
                "name": "document vector store",
                "evidence_status": "observed",
            },
        ],
        dependencies=[
            {"id": "dep-bedrock", "name": "AWS Bedrock model endpoint"},
        ],
    )

    detected_ids = {
        record.get("component_id") for record in _detect()(architecture)
    }

    assert {"ds-doc-vectors", "dep-bedrock"} <= detected_ids, (
        "F12 says 'detected or declared'. A vector store declared as a data "
        "store and a model endpoint declared as a dependency are both declared "
        f"AI components; detection found {sorted(detected_ids)}"
    )
    assert "ds-orders" not in detected_ids, (
        "an ordinary relational store is not an AI component; detection found "
        f"{sorted(detected_ids)}"
    )


# ---------------------------------------------------------------------------
# The false-positive half. This is how §8's rule gets discredited.
# ---------------------------------------------------------------------------


def test_a_component_that_merely_mentions_ai_in_prose_is_not_an_ai_component():
    architecture = _architecture(
        components=[
            _component(
                "cmp-billing-api",
                "billing-api",
                description=(
                    "Deterministic billing. No AI is used here; no LLM, no "
                    "model endpoint, and no vector store are involved."
                ),
            )
        ]
    )

    detected = _detect()(architecture)

    assert detected == [], (
        "a sentence *about* AI is not an AI component. Triggering the taxonomy "
        "on a service that says in writing it uses none is the false positive "
        "that teaches a reader to distrust the section — and the next section "
        f"they distrust is one that mattered; detection returned {detected}"
    )


@pytest.mark.parametrize(
    "name",
    [
        # `storage` contains `rag`, and the golden profile uses the word freely.
        "storage-gateway",
        "paragraph-cache",
        # `agentless`, not `agent`.
        "agentless-scanner",
        # `claim`, not `claude`; `image`, not a model.
        "claim-service",
        "image-resizer",
        "management-console",
        # The contract says "model endpoint", not "model". A bare `\bmodel\b`
        # trigger reads a data model, a threat model and a pricing model as
        # machine learning.
        "data-model-service",
    ],
)
def test_a_word_that_merely_contains_a_trigger_as_a_substring_is_not_a_match(name):
    architecture = _architecture(components=[_component("cmp-under-test", name)])

    detected = _detect()(architecture)

    assert detected == [], (
        f"{name!r} is not an AI component. An unbounded substring match reads "
        "'storage' as RAG and 'agentless' as an agent, which would apply the "
        "taxonomy to most services in existence; detection returned "
        f"{detected}"
    )


# ---------------------------------------------------------------------------
# §4.3 — deterministic, and the caller's documents survive the call.
# ---------------------------------------------------------------------------


def test_detection_is_sorted_and_independent_of_document_order():
    forward = _architecture(
        components=[
            _component("cmp-answer-llm", "answer-llm"),
            _component("cmp-checkout-api", "checkout-api"),
            _component("cmp-vector-store", "vector-store"),
        ]
    )
    reversed_document = _architecture(
        components=list(reversed(forward["components"]))
    )

    first = _detect()(forward)
    second = _detect()(reversed_document)

    assert first == second, (
        "§4.3: the output is deterministic and sorted, so two runs over the "
        f"same model produce identical bytes. Forward gave {first}, reversed "
        f"gave {second}"
    )


def test_detection_returns_the_same_result_when_called_twice():
    architecture = _architecture(
        components=[_component("cmp-answer-llm", "answer-llm")]
    )
    detector = _detect()

    assert detector(architecture) == detector(architecture), (
        "§4.3: repeated calls agree. A difference means something iterated a "
        "set or cached across calls"
    )


def test_detection_does_not_mutate_the_architecture_it_reads():
    architecture = _architecture(
        components=[_component("cmp-answer-llm", "answer-llm")]
    )
    before = copy.deepcopy(architecture)

    _detect()(architecture)

    assert architecture == before, (
        "a later stage scoring a silently mutated document is the failure this "
        f"avoids; the architecture became {architecture!r}"
    )


@pytest.mark.parametrize(
    "architecture",
    [
        None,
        "",
        [],
        42,
        {},
        {"components": "not-a-list"},
        {"components": [None, 7, "text"]},
        {"components": [{}, {"id": None, "name": "answer-llm"}]},
        {"components": [{"id": "cmp-1", "name": None}]},
    ],
)
def test_a_malformed_architecture_yields_no_components_rather_than_raising(
    architecture,
):
    """House convention (§10.1): the reporting side returns, it does not raise."""

    detected = _detect()(architecture)

    assert isinstance(detected, list), (
        "detect_ai_components returns a list for any input. §8 requires the run "
        f"to complete over a broken document; {architecture!r} gave {detected!r}"
    )


# ---------------------------------------------------------------------------
# §8 — no AI components, so no coverage block at all.
# ---------------------------------------------------------------------------


def test_ai_coverage_is_none_when_the_architecture_declares_no_ai_component():
    result = _coverage()(_architecture(), _threats(_threat("T-01")))

    assert result is None, (
        "§8: with no AI components the taxonomy is not applied *and not "
        "mentioned*. `None` is what makes that structural — an empty dict or a "
        "flag still gives a consumer something to render, and the consumer that "
        f"forgets to check is how the line reaches the page; got {result!r}"
    )


def test_ai_coverage_is_none_when_only_the_prose_mentions_ai():
    architecture = _architecture(
        components=[
            _component(
                "cmp-billing-api",
                "billing-api",
                description="No AI, LLM, or RAG component is involved.",
            )
        ]
    )

    assert _coverage()(architecture, _threats(_threat("T-01"))) is None, (
        "the trigger is a component, not a mention. A description that denies "
        "using AI must not produce a coverage block"
    )


def test_ai_coverage_is_none_when_a_threat_mentions_ai_but_no_component_exists():
    """F12's trigger is the architecture, not the register.

    A threat register that speculates about prompt injection over a service
    with no model is not evidence the service has one, and treating it as
    evidence would let one loosely-worded scenario switch the taxonomy on for
    an architecture that declares nothing.
    """

    threats = _threats(
        _threat(
            "T-01",
            scenario="Prompt injection against a future LLM feature.",
            attack_path="prompt_injection",
        )
    )

    assert _coverage()(_architecture(), threats) is None, (
        "no AI component is declared, so §8 applies and there is nothing to "
        "report"
    )


@pytest.mark.parametrize(
    "architecture, threats",
    [
        (None, None),
        ({}, {}),
        ("", ""),
        ({"components": "not-a-list"}, {"threats": "not-a-list"}),
        ({"components": [{"id": "cmp-1", "name": "answer-llm"}]}, None),
        (
            {"components": [{"id": "cmp-1", "name": "answer-llm"}]},
            {"threats": [{"id": "T-1", "lifecycle": {"status": "nonsense"}}]},
        ),
        (
            {"components": [{"id": "cmp-1", "name": "answer-llm"}]},
            {"threats": [{"lifecycle": {"status": "superseded"}}]},
        ),
    ],
)
def test_ai_coverage_never_raises_on_malformed_input(architecture, threats):
    """`risk.active_threats` raises; this reporter must not propagate it.

    `active_threats` raises `RiskValidationError` on a threat with no id, an
    unknown lifecycle status, or a `superseded` record with no replacement.
    `sdr_architecture._active_threats` already had to work around exactly this,
    and §8 requires the run to complete and record the limitation rather than
    to take the process down over one malformed record.
    """

    result = _coverage()(architecture, threats)

    assert result is None or isinstance(result, dict), (
        "ai_coverage returns `dict | None` for any input, following the house "
        f"`validate_*` convention of reporting rather than raising; got {result!r}"
    )


# ---------------------------------------------------------------------------
# The paired presence — with an AI component, the block exists and is specific.
# ---------------------------------------------------------------------------


def _ai_architecture() -> dict:
    return _architecture(
        components=[
            _component("cmp-checkout-api", "checkout-api"),
            _component("cmp-answer-llm", "answer-llm"),
        ]
    )


def test_ai_coverage_returns_a_block_when_an_ai_component_is_present():
    result = _coverage()(_ai_architecture(), _threats(_threat("T-01")))

    assert isinstance(result, dict), (
        "F12: with an LLM component detected the taxonomy is applied, so the "
        f"coverage block exists; got {result!r}"
    )
    assert set(result) >= {"components", "categories", "uncovered"}, (
        "the block carries {components, categories, uncovered}: which elements "
        "triggered it, what the taxonomy asks, and what nothing answers; found "
        f"{sorted(result)}"
    )


def test_ai_coverage_names_the_component_that_triggered_it():
    result = _coverage()(_ai_architecture(), _threats(_threat("T-01")))

    flattened = " ".join(text for _path, text in _flatten(result))
    assert "cmp-answer-llm" in flattened, (
        "a reader has to be able to see *why* the taxonomy was applied to this "
        "service. A block that lists categories without naming the component "
        f"cannot be checked against the architecture; block was {result!r}"
    )
    assert "cmp-checkout-api" not in flattened, (
        "only the AI elements belong in the block; listing the whole "
        f"architecture makes the trigger unreadable. Block was {result!r}"
    )


def test_every_taxonomy_category_is_uncovered_when_the_register_is_empty():
    result = _coverage()(_ai_architecture(), _threats())

    expected = [_category_id(category) for category in _taxonomy()]
    uncovered = list(result["uncovered"])
    assert {str(item) for item in uncovered} >= set(expected), (
        "F12: an AI component with no threats modelled against it means every "
        "taxonomy category is unaddressed. Reporting fewer would tell a reader "
        f"the model covers ground it never touched; uncovered was {uncovered} "
        f"against a taxonomy of {expected}"
    )


def test_a_category_an_active_threat_addresses_is_not_reported_as_uncovered():
    category = _taxonomy()[0]
    threats = _threats(_covering_threat(category, threat_id="T-AI-1"))

    uncovered = {str(item) for item in _coverage()(_ai_architecture(), threats)["uncovered"]}

    assert _category_id(category) not in uncovered, (
        "a threat naming this category addresses it, so it is covered. Without "
        "this pair, the uncovered assertions below would pass for an "
        "implementation that reports every category unconditionally; uncovered "
        f"was {sorted(uncovered)}"
    )


def test_a_category_no_active_threat_addresses_is_reported_as_uncovered():
    taxonomy = _taxonomy()
    if len(taxonomy) < 2:
        pytest.fail(
            "AI_TAXONOMY needs at least two categories for coverage to mean "
            f"anything; it has {len(taxonomy)}"
        )
    covered, uncovered_category = taxonomy[0], taxonomy[1]
    threats = _threats(_covering_threat(covered, threat_id="T-AI-1"))

    uncovered = {str(item) for item in _coverage()(_ai_architecture(), threats)["uncovered"]}

    assert _category_id(uncovered_category) in uncovered, (
        "`uncovered` names the taxonomy categories no active threat addresses. "
        f"{_category_id(uncovered_category)!r} has no threat against it and "
        f"must be listed; uncovered was {sorted(uncovered)}"
    )


def test_uncovered_is_empty_when_every_category_is_addressed():
    taxonomy = _taxonomy()
    threats = _threats(
        *(
            _covering_threat(category, threat_id=f"T-AI-{index}")
            for index, category in enumerate(taxonomy)
        )
    )

    uncovered = list(_coverage()(_ai_architecture(), threats)["uncovered"])

    assert uncovered == [], (
        "with a threat against every category nothing is unaddressed. A block "
        "that always reports something is a block a reader learns to skip; "
        f"uncovered was {uncovered}"
    )


def test_a_retired_threat_does_not_cover_a_taxonomy_category():
    """History is not coverage. Pairs with the active case above."""

    category = _taxonomy()[0]
    active = _covering_threat(category, threat_id="T-AI-1")
    retired = _covering_threat(
        category, threat_id="T-AI-1", lifecycle={"status": "retired"}
    )

    covered = {
        str(item)
        for item in _coverage()(_ai_architecture(), _threats(active))["uncovered"]
    }
    after_retirement = {
        str(item)
        for item in _coverage()(_ai_architecture(), _threats(retired))["uncovered"]
    }

    category_id = _category_id(category)
    assert category_id not in covered, (
        "fixture check: the active form of this threat must cover the "
        f"category, or the retirement below proves nothing; uncovered was "
        f"{sorted(covered)}"
    )
    assert category_id in after_retirement, (
        "§7.14 and `risk.active_threats`: a retired threat is history the "
        "register keeps on purpose, not a control. Counting it as coverage "
        "tells a reader the category is handled by a threat the team has "
        f"explicitly stopped tracking; uncovered was {sorted(after_retirement)}"
    )


def test_a_superseded_threat_does_not_cover_a_taxonomy_category():
    category = _taxonomy()[0]
    category_id = _category_id(category)
    replacement = _threat("T-AI-2", scenario="An unrelated replacement threat.")
    superseded = _covering_threat(
        category,
        threat_id="T-AI-1",
        lifecycle={"status": "superseded", "superseded_by": ["T-AI-2"]},
    )

    uncovered = {
        str(item)
        for item in _coverage()(
            _ai_architecture(), _threats(superseded, replacement)
        )["uncovered"]
    }

    assert category_id in uncovered, (
        "a superseded threat routinely points at architecture that was "
        "decommissioned alongside it; its replacement addresses this category "
        "or nothing does. `risk.active_threats` excludes it and so must "
        f"coverage; uncovered was {sorted(uncovered)}"
    )


def test_ai_coverage_is_deterministic_and_does_not_mutate_its_inputs():
    architecture = _ai_architecture()
    threats = _threats(_covering_threat(_taxonomy()[0], threat_id="T-AI-1"))
    before = (copy.deepcopy(architecture), copy.deepcopy(threats))
    reporter = _coverage()

    first = reporter(architecture, threats)
    second = reporter(architecture, threats)

    assert first == second, f"§4.3: repeated calls agree; got {first!r} then {second!r}"
    assert (architecture, threats) == before, (
        "§4.3 and `build_report`'s contract: a caller's documents are the same "
        "objects afterwards. Architecture became "
        f"{architecture!r}; threats became {threats!r}"
    )


# ---------------------------------------------------------------------------
# §8, end to end — the run over a service with no AI never says the word.
#
# The pair is the point. The absence test alone is also true of a build that
# never learned the vocabulary, so each assertion below has a presence twin
# over the same scan.
# ---------------------------------------------------------------------------


def test_the_no_ai_fixture_really_models_no_ai():
    """Guards the two tests below from passing on a fixture that changed."""

    architecture = _architecture()
    detected = _detect()(architecture)

    assert detected == [], (
        "the golden-shaped fixture models a movie-rating API and no AI. If "
        "detection finds something here, every 'not mentioned' assertion in "
        f"this file is measuring the wrong thing; found {detected}"
    )


def test_a_run_over_a_store_with_no_ai_component_never_mentions_ai(project):
    exit_code = risk_mod.main(_argv(project))

    assert exit_code == OK, (
        f"the store is complete and nothing is wrong with it; got {exit_code}"
    )
    offending: list[str] = []
    for name, content in _rendered_artifacts(project).items():
        offending += [f"{name}: {hit}" for hit in _mentions(content)]

    assert offending == [], (
        "§8: with no AI components the taxonomy is 'not applied **and not "
        "mentioned**'. A rendered line saying the AI section is not applicable "
        "is still a mention: it trains the reader to skim, and the next section "
        "they skim is one that mattered. Found "
        + "; ".join(offending)
    )


def test_the_report_record_for_a_service_with_no_ai_carries_no_ai_vocabulary(project):
    report = _report_for(project)

    offending = _record_mentions(report)

    assert offending == [], (
        "§8's absence is total: no key in the report record, no value, no "
        "sentence. Asserted over the vocabulary rather than over one key name, "
        "because a renamed key slips past a key check while the reader still "
        "sees the words. Found " + "; ".join(offending)
    )
    serialized = json.dumps(report, sort_keys=True, default=str)
    assert "ai_coverage" not in serialized, (
        "the coverage block must be absent, not present-and-empty. "
        "`ai_coverage` returning None is what makes that structural"
    )


def test_a_run_over_a_store_with_an_ai_component_applies_the_taxonomy(project):
    """The paired presence. Without it the absence test proves nothing."""

    component_id = _declare_ai_component(project)

    exit_code = risk_mod.main(_argv(project))

    assert exit_code == OK, (
        "an architecture that declares an LLM component is a valid model, not a "
        "document-integrity error. F12 asks the taxonomy to be applied to it, "
        f"and a suppressed run applies nothing; got {exit_code}. Component was "
        f"{component_id}"
    )
    rendered = _rendered_artifacts(project)
    assert PREVIEW in rendered, (
        f"the run must write the preview so there is something to read; it "
        f"wrote {sorted(rendered)}"
    )
    mentions: list[str] = []
    for name, content in rendered.items():
        mentions += [
            f"{name}: {hit}"
            for hit in _mentions(content, TAXONOMY_ONLY_VOCABULARY)
        ]

    assert mentions, (
        "F12: with an LLM component present the AI taxonomy is applied and the "
        "artifacts say so. Asserted on taxonomy vocabulary that appears nowhere "
        "in the store — `render_register` embeds the Mermaid DFD, which names "
        "every component, so a scan that accepted the component's own name "
        "would pass for a run that never loaded the taxonomy. The artifacts "
        f"were {sorted(rendered)}"
    )


def test_the_report_record_for_an_ai_service_carries_the_coverage_block(project):
    _declare_ai_component(project)

    report = _report_for(project)

    flattened = {path: text for path, text in _flatten(report)}
    assert any(
        "uncovered" in path.split(".")[-1] or text == "uncovered"
        for path, text in flattened.items()
    ), (
        "F12: the coverage block reaches the §4.2 record, naming the taxonomy "
        "categories no active threat addresses. Placement is the implementer's "
        "call — top level or under `architecture` — but it has to be somewhere "
        f"a consumer can read it; the record's keys were "
        f"{sorted(set(report))}"
    )
    assert "cmp-summary-llm" in json.dumps(report, sort_keys=True, default=str), (
        "the block names the component that triggered it, so a reader can "
        "check the trigger against the architecture"
    )


# ---------------------------------------------------------------------------
# §2.1 / §10 — packaging is a closed allowlist.
# ---------------------------------------------------------------------------


def test_the_ai_risk_module_is_listed_in_the_approved_payload_files():
    """A shipped file the allowlist does not name fails four other tests.

    Deliberately not fixed here: `APPROVED_PAYLOAD_FILES` and the module have
    to land together. A listed-but-untracked path fails the clean-clone check,
    which builds its archive from `git stash create` and so sees only tracked
    files — so adding the row before the module exists trades one red test for
    four.
    """

    listed = DISTRIBUTION_ALLOWLIST.read_text(encoding="utf-8")

    assert "scripts/sdr_ai_risk.py" in listed, (
        "plan §10: every file shipped inside plugins/security-requirements/ "
        "must be listed in APPROVED_PAYLOAD_FILES "
        f"({DISTRIBUTION_ALLOWLIST}), beside scripts/sdr_report.py and "
        "scripts/sdr_attack_paths.py. This row lands with the module"
    )
