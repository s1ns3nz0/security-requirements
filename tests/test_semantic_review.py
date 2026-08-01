from pathlib import Path
import copy
import sys

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import semantic_review  # noqa: E402


def requirement():
    return {
        "id": "REQ-TENANT-01",
        "managed": {
            "statement": "Every tenant-scoped read must enforce tenant ownership.",
            "rationale": "Prevents cross-tenant disclosure.",
            "sources": ["AC-3"],
            "threat_refs": ["T-01"],
            "verification": {
                "method": "integration_test",
                "target": "tenant-scoped read paths",
                "expect": "cross-tenant identifiers are denied",
            },
        },
        "human": {},
    }


def test_review_binds_exact_semantics_and_verification():
    req = requirement()
    semantic_review.stamp(
        req,
        reviewer="alice@example.com",
        controls=["AC-3"],
        clauses=["pipa-isms-p:2.6.1"],
        verification_reviewed=True,
        reviewed_at="2026-07-31T11:00:00Z",
    )

    assert semantic_review.validate(req) == []
    review = req["human"]["semantic_review"]
    assert review["requirement_digest"] == semantic_review.requirement_digest(req)
    assert review["control_links"] == ["AC-3"]
    assert review["overlay_clauses"] == ["pipa-isms-p:2.6.1"]


def test_model_edit_invalidates_semantic_review():
    req = requirement()
    semantic_review.stamp(
        req, "alice@example.com", ["AC-3"], ["pipa-isms-p:2.6.1"], True,
        "2026-07-31T11:00:00Z",
    )
    req["managed"]["statement"] = "A different property must hold."

    assert semantic_review.validate(req) == [
        "semantic review is stale because the managed requirement changed"
    ]


def test_ai_identity_cannot_be_the_independent_reviewer():
    req = requirement()
    semantic_review.stamp(
        req, "claude", ["AC-3"], ["pipa-isms-p:2.6.1"], True,
        "2026-07-31T11:00:00Z",
    )

    assert "reviewer must identify an independent human" in semantic_review.validate(req)


def test_review_must_cover_cited_control_and_verification():
    req = requirement()
    semantic_review.stamp(
        req, "alice@example.com", [], ["pipa-isms-p:2.6.1"], False,
        "2026-07-31T11:00:00Z",
    )

    problems = semantic_review.validate(req)
    assert "semantic review does not validate any cited control link" in problems
    assert "semantic review did not validate the verification method" in problems


def test_document_gate_blocks_unreviewed_requirements(tmp_path):
    document = {"requirements": [requirement()]}
    path = tmp_path / "requirements.yaml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")

    assert semantic_review.main(["--check", str(path)]) == 1
