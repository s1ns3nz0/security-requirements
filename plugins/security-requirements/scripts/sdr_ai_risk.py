#!/usr/bin/env python3
"""The AI threat taxonomy, applied only where there is AI (plan F12, §8).

    | F12 | Apply the AI threat taxonomy only when LLM/agent/RAG components
    |     | are detected or declared. |
    | No AI components | AI taxonomy not applied **and not mentioned**. |

"Not mentioned" is the half that carries the weight, and it is enforced here
rather than by every caller remembering a flag: `ai_coverage` returns `None`
when there is no AI, and `None` renders as nothing. A review that printed "AI
threats: none applicable" over a service with no AI would have added a line
whose only function is to be skipped — and a reader trained to skip one section
skips the next one too.

Detection is deliberately narrow, and matched on whole words. A component
*named* for a model is one; a billing service whose description mentions AI is
not. A false positive does not merely add noise: it produces categories nobody
can act on, and a reviewer who has dismissed this section once will dismiss it
on the service where it was real.

The categories themselves live in
`skills/deriving-security-requirements/references/ai-threats.md`, which is what
a human reads. This table is what the tool applies, and a test pins the two to
the same ids and titles in the same order: a category in one and not the other
means the review reports a gap nobody can look up.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import risk as risk_mod  # noqa: E402
import sdr_architecture  # noqa: E402


#: What makes an element an AI element, as data (§10.1, §12: "policy data,
#: never `if` branches"). Every pattern is anchored on word boundaries so a
#: substring cannot trigger it — `ragged`, `管理`, `agentic-billing-agenda` are
#: not RAG systems, and a taxonomy that fired on them would be ignored within a
#: week.
AI_COMPONENT_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    ("a large language model", re.compile(r"\bllms?\b", re.I)),
    ("a model-backed agent", re.compile(r"\bagents?\b", re.I)),
    ("a retrieval-augmented generation pipeline", re.compile(r"\brag\b", re.I)),
    ("a vector store", re.compile(r"\bvector(?:[\s_-]?(?:db|store|index))?\b", re.I)),
    ("an embedding pipeline", re.compile(r"\bembeddings?\b", re.I)),
    ("a model inference endpoint", re.compile(r"\b(?:inference|model)[\s_-]?endpoints?\b", re.I)),
    ("a hosted model provider", re.compile(r"\b(?:openai|anthropic|bedrock|vertex[\s_-]?ai|sagemaker)\b", re.I)),
    ("a named model family", re.compile(r"\b(?:gpt|claude|gemini|llama|mistral)\b", re.I)),
    ("a prompt-handling component", re.compile(r"\bprompts?\b", re.I)),
    ("a chat completion surface", re.compile(r"\bchat[\s_-]?completions?\b", re.I)),
)

#: The categories, paired with `references/ai-threats.md`. Ids and titles must
#: match that document exactly, in order.
#:
#: `applies_to` says what has to be true of the system for the category to be
#: worth asking about — it is guidance for the reviewer, not a second detection
#: rule. Detection decides whether the taxonomy runs at all; every category
#: then applies, because a category nobody checked is not the same as one that
#: did not apply.
AI_TAXONOMY: tuple[dict, ...] = (
    {
        "id": "AI-01",
        "title": "Prompt injection",
        "applies_to": "any content the model reads that the operator does not control",
    },
    {
        "id": "AI-02",
        "title": "Excessive agency",
        "applies_to": "any tool the model can call on a requester's behalf",
    },
    {
        "id": "AI-03",
        "title": "Training and context data disclosure",
        "applies_to": "any flow carrying sensitive data to a model that logs, retains, or trains",
    },
    {
        "id": "AI-04",
        "title": "Retrieval poisoning",
        "applies_to": "any corpus whose write path is broader than the answers it steers",
    },
    {
        "id": "AI-05",
        "title": "Output handled as trusted",
        "applies_to": "any sink that executes, renders, or forwards model output",
    },
    {
        "id": "AI-06",
        "title": "Unbounded consumption",
        "applies_to": "any turn, tool loop, or context that is not capped",
    },
    {
        "id": "AI-07",
        "title": "Supply chain of models and prompts",
        "applies_to": "any model version, system prompt, or tool definition that ships without review",
    },
)

#: Where a threat may name the category it addresses. The reference doc's
#: "Recording a finding" section says `category` carries the AI id; the rest are
#: read too, because a register that spelled it in `attack_path` and not
#: `category` has still addressed the threat, and reporting it as a gap would
#: send a reviewer to write a record that already exists.
COVERAGE_FIELDS = ("category", "attack_path", "scenario", "related_controls")


#: `_` and `-` are word characters to `\b`, so `vector_store_reader` would not
#: match a pattern anchored on `vector store`. A name is written in whichever
#: separator the author's language prefers, and F12 must not depend on that
#: choice, so they are normalised to spaces before matching.
#:
#: Applied at the detection call site and *not* inside `_text_of`, which the
#: coverage join also uses: that join searches for `AI-01`, and normalising the
#: hyphen away there would make every category permanently uncovered.
_SEPARATORS = re.compile(r"[_\-]+")


def _text_of(record: Mapping, keys: Sequence[str]) -> str:
    """Every string under `keys`, flattened, for a whole-word search."""

    parts: list[str] = []
    for key in keys:
        value = record.get(key)
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
            parts.extend(item for item in value if isinstance(item, str))
    return " ".join(parts)


def detect_ai_components(architecture: object) -> list[dict]:
    """Every modelled element that looks like an AI system.

    Scans all seven §4.2 kinds, not just `components`: a vector store is a
    `data_stores` record and a hosted model endpoint is routinely a
    `dependencies` one, so a scan restricted to components would miss exactly
    the two F12 names.

    Reads `id` and `name` only — the fields that say what a thing *is*.
    Descriptions and shared-responsibility prose are where a service explains
    that it does *not* use AI, and matching them is how the rule gets
    discredited.

    Sorted by id: §4.3 wants a stable order, and a reader comparing two runs
    should not see churn from a dict's iteration order.
    """

    found: dict[str, dict] = {}
    for kind in sdr_architecture.KINDS:
        for record in sdr_architecture._records(architecture, kind):
            if not isinstance(record, Mapping):
                continue
            record_id = record.get("id")
            if not isinstance(record_id, str) or not record_id.strip():
                continue
            haystack = _SEPARATORS.sub(" ", _text_of(record, ("id", "name")))
            for why, pattern in AI_COMPONENT_PATTERNS:
                if pattern.search(haystack) and record_id not in found:
                    found[record_id] = {"component_id": record_id, "why": why}
                    break
    return [found[key] for key in sorted(found)]


def _covered_category_ids(threats: object) -> set[str]:
    """Category ids that an *active* threat names.

    Active only. A retired threat is history the register keeps on purpose and
    a superseded one describes a system that changed; counting either as
    coverage would report a category as handled by a record nobody maintains.
    """

    covered: set[str] = set()
    try:
        active = risk_mod.active_threats(threats)
    except (risk_mod.RiskValidationError, TypeError, AttributeError):
        # A threat document that will not load is reported by its own
        # validator. Treating it as covering nothing is the safe reading:
        # the review says the category is unaddressed, which is true.
        return covered

    for record in active:
        if not isinstance(record, Mapping):
            continue
        haystack = _text_of(record, COVERAGE_FIELDS)
        for category in AI_TAXONOMY:
            category_id = category["id"]
            if re.search(rf"\b{re.escape(category_id)}\b", haystack, re.I):
                covered.add(category_id)
    return covered


def ai_coverage(architecture: object, threats: object) -> dict | None:
    """The taxonomy applied to one model, or `None` when it does not apply.

    `None` rather than an empty block, because §8 says the taxonomy is "not
    applied **and not mentioned**". Returning a block with `applies: false`
    would put the decision in every caller's hands, and one of them would
    eventually render it.
    """

    components = detect_ai_components(architecture)
    if not components:
        return None

    covered = _covered_category_ids(threats)
    return {
        "components": components,
        "categories": [dict(category) for category in AI_TAXONOMY],
        # Ordered by the taxonomy, not by a set: §4.3 forbids set iteration
        # reaching output, and a reader comparing runs wants the same sequence.
        # Ids, not objects. The full category is already in `categories`, and
        # what a reader does with an uncovered one is look it up in
        # `references/ai-threats.md` — which is keyed by id.
        "uncovered": [
            category["id"] for category in AI_TAXONOMY if category["id"] not in covered
        ],
    }
