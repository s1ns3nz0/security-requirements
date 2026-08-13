"""Shared test data constructors for the threat-risk feature."""

from __future__ import annotations


def consequence(id: str, criterion: str) -> dict:
    return {
        "id": id,
        "asset": "movie_records",
        "axis": "integrity",
        "criterion": criterion,
        "rationale": ["catalogue records are affected"],
    }


def proposal(likelihood: str, impact: str) -> dict:
    return {
        "likelihood": {
            "criterion": likelihood,
            "evidence": {
                "exposure": "public",
                "access_required": "none",
                "exploit_complexity": "low",
                "preconditions": ["route is reachable"],
                "observed_controls": [],
            },
            "rationale": ["the route is publicly reachable"],
        },
        "consequences": [consequence("C-01", impact)],
        "impact": {"selected_from": "C-01"},
    }


def threat_record(id: str, status: str = "active", **changes) -> dict:
    record = {
        "id": id,
        "boundary": "TB-1",
        "category": "STRIDE:T",
        "novelty": "service_specific",
        "persona": "anonymous_external",
        "attack_path": "public_write_route",
        "scenario": "anonymous mutation",
        "affected_assets": ["movie_records"],
        "related_controls": ["AC-3"],
        "lifecycle": {"status": status, "superseded_by": []},
    }
    record.update(changes)
    return record


def assessment_record(
    threat_id: str, status: str, rating: str | None = None, **changes
) -> dict:
    record = {"threat_id": threat_id, "status": status}
    if rating is not None:
        record["calculated"] = {"rating": rating}
    record.update(changes)
    return record
