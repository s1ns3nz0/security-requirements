#!/usr/bin/env python3
"""Derive deterministic blast-radius records from a threat graph.

The threat model remains the human-authored source.  This script consumes a
separate graph describing components, scopes, and threat entry points, then
writes a derived JSON document.  It does not claim that an inferred path is an
implemented control or a confirmed incident impact.

Usage:
    python3 -I "<absolute plugin root>/scripts/blast_radius.py" --threats threats.yaml --graph blast-graph.yaml \
        --out blast-radius.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml


DIMENSIONS = (
    "tenant_scope", "data_scope", "runtime_scope", "control_scope",
    "recovery_scope",
)

ORDERS = {
    "tenant_scope": ["one", "subset", "all"],
    "data_scope": ["record", "tenant_dataset", "shared_dataset", "platform_dataset"],
    "runtime_scope": ["task", "service", "namespace", "cluster", "account", "region"],
    "control_scope": ["feature", "tenant_operations", "control_plane", "platform"],
    "recovery_scope": ["local", "tenant_recovery", "platform_recovery", "regional_recovery"],
}
CONFIDENCE = {"confirmed", "inferred", "unknown"}
RESPONSIBILITIES = {"team", "shared", "csp_claimed", "org", "undetermined"}
VALIDATION_STATES = {"unreviewed", "reviewed", "confirmed", "expired"}
COARSE_SCOPES = ("contained", "tenant", "cross_tenant", "platform", "account_region")


class GraphError(ValueError):
    pass


def _load(path: Path) -> dict:
    value = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(value, dict):
        raise GraphError(f"{path}: expected a mapping")
    return value


def _list(value, field: str) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    raise GraphError(f"{field} must be a list")


def _check_value(value: str, field: str) -> None:
    if field in DIMENSIONS and value not in ORDERS[field]:
        raise GraphError(f"{field}: {value!r} is not one of {', '.join(ORDERS[field])}")
    if field == "confidence" and value not in CONFIDENCE:
        raise GraphError(f"confidence: {value!r} is not one of {sorted(CONFIDENCE)}")
    if field == "responsibility" and value not in RESPONSIBILITIES:
        raise GraphError(f"responsibility: {value!r} is not one of {sorted(RESPONSIBILITIES)}")


def _validate_nodes(raw_nodes: list) -> dict[str, dict]:
    nodes = {}
    for pos, node in enumerate(raw_nodes):
        if not isinstance(node, dict) or not node.get("id"):
            raise GraphError(f"nodes[{pos}] must be a mapping with an id")
        node_id = node["id"]
        if node_id in nodes:
            raise GraphError(f"duplicate node id: {node_id}")
        for field in DIMENSIONS + ("confidence", "responsibility"):
            if field in node:
                _check_value(node[field], field)
        nodes[node_id] = node
    return nodes


def _validate_edges(raw_edges: list, nodes: dict[str, dict]) -> dict[str, list[dict]]:
    adjacency = {node_id: [] for node_id in nodes}
    for pos, edge in enumerate(raw_edges):
        if not isinstance(edge, dict) or not edge.get("from") or not edge.get("to"):
            raise GraphError(f"edges[{pos}] must contain from and to")
        if edge["from"] not in nodes or edge["to"] not in nodes:
            raise GraphError(f"edges[{pos}] references an unknown node")
        adjacency[edge["from"]].append(edge)
    return adjacency


def _reachable(sources: list[str], adjacency: dict[str, list[dict]]) -> tuple[list[str], list[dict]]:
    seen = set()
    queue = list(sources)
    traversed = []
    while queue:
        current = queue.pop(0)
        if current in seen:
            continue
        seen.add(current)
        for edge in adjacency.get(current, []):
            traversed.append(edge)
            queue.append(edge["to"])
    return sorted(seen), traversed


def _max_dimension(nodes: list[dict], field: str) -> str:
    values = [node.get(field) for node in nodes if node.get(field)]
    if not values:
        return "unknown"
    return max(values, key=ORDERS[field].index)


def _confidence(nodes: list[dict], edges: list[dict], path: dict) -> str:
    values = [node.get("confidence", "inferred") for node in nodes]
    values += [edge.get("confidence", "inferred") for edge in edges]
    values.append(path.get("confidence", "inferred"))
    if any(value == "unknown" for value in values):
        return "unknown"
    if all(value == "confirmed" for value in values):
        return "confirmed"
    return "inferred"


def _tenant_detail(path: dict, scope: str) -> dict:
    """Keep categorical scope stable while carrying optional deployment sizing."""
    raw = path.get("affected_tenants")
    if raw is None:
        return {"value": scope, "estimate": None, "total": None, "ratio": None}
    if not isinstance(raw, dict):
        raise GraphError("affected_tenants must be a mapping")
    estimate = raw.get("estimate")
    total = raw.get("total")
    for name, value in (("estimate", estimate), ("total", total)):
        if value is not None and value != "unknown" and (not isinstance(value, int) or value < 0):
            raise GraphError(f"affected_tenants.{name} must be a non-negative integer or unknown")
    if isinstance(estimate, int) and isinstance(total, int):
        if total == 0 or estimate > total:
            raise GraphError("affected_tenants.estimate must not exceed a non-zero total")
        ratio = round(estimate / total, 6)
    else:
        ratio = raw.get("ratio")
        if ratio is not None and (not isinstance(ratio, (int, float)) or not 0 <= ratio <= 1):
            raise GraphError("affected_tenants.ratio must be between 0 and 1")
    return {
        "value": scope,
        "estimate": estimate,
        "total": total,
        "ratio": ratio,
        "basis": raw.get("basis"),
    }


def _priority(blast: dict, confidence: str, validation_status: str) -> tuple[str, list[str], bool]:
    """Apply a small, explicit escalation policy instead of one broad set test."""
    reasons = []
    if blast["tenant_scope"] == "all":
        reasons.append("all_tenants")
    if blast["data_scope"] in {"shared_dataset", "platform_dataset"}:
        reasons.append("shared_or_platform_data")
    if blast["runtime_scope"] in {"account", "region"}:
        reasons.append("account_or_region_runtime")
    if blast["control_scope"] in {"control_plane", "platform"}:
        reasons.append("platform_control")
    if blast["recovery_scope"] in {"platform_recovery", "regional_recovery"}:
        reasons.append("platform_or_regional_recovery")
    unknown = any(value == "unknown" for value in blast.values()) or confidence == "unknown"
    if unknown:
        reasons.append("uncertain_scope")
    review_required = unknown or validation_status in {"unreviewed", "expired"}
    if review_required:
        reasons.append("review_required")
    escalation_reasons = [reason for reason in reasons if reason != "review_required"]
    return ("high" if escalation_reasons else "medium"), sorted(set(reasons)), review_required


def _coarse_scope(blast: dict) -> str:
    """Map the detailed dimensions to a review-friendly maximum scope."""
    if blast["runtime_scope"] in {"account", "region"} or blast["recovery_scope"] == "regional_recovery":
        return "account_region"
    if (blast["data_scope"] == "platform_dataset"
            or blast["control_scope"] in {"control_plane", "platform"}
            or blast["recovery_scope"] == "platform_recovery"):
        return "platform"
    if (blast["tenant_scope"] in {"subset", "all"}
            or blast["data_scope"] == "shared_dataset"
            or blast["runtime_scope"] == "cluster"):
        return "cross_tenant"
    if (blast["tenant_scope"] == "one"
            or blast["data_scope"] == "tenant_dataset"
            or blast["recovery_scope"] == "tenant_recovery"):
        return "tenant"
    return "contained"


def _review(path: dict) -> dict:
    review = path.get("review") or {}
    if not isinstance(review, dict):
        raise GraphError("review must be a mapping")
    status = review.get("status", path.get("validation_status", "unreviewed"))
    if status not in VALIDATION_STATES:
        raise GraphError(f"review.status {status!r} is not one of {sorted(VALIDATION_STATES)}")
    result = {
        "status": status,
        "reviewer": review.get("reviewer"),
        "reviewed_at": review.get("reviewed_at"),
        "evidence": sorted(set(str(value) for value in (review.get("evidence") or []))),
        "expires_at": review.get("expires_at"),
    }
    if status in {"reviewed", "confirmed"} and not result["reviewer"]:
        raise GraphError("reviewer is required when review.status is reviewed or confirmed")
    if status in {"reviewed", "confirmed"} and not result["reviewed_at"]:
        raise GraphError("reviewed_at is required when review.status is reviewed or confirmed")
    if status == "confirmed" and not result["evidence"]:
        raise GraphError("review.evidence is required when review.status is confirmed")
    return result


def derive(threats_doc: dict, graph_doc: dict) -> dict:
    threats = threats_doc.get("threats") or []
    if not isinstance(threats, list):
        raise GraphError("threats must be a list")
    nodes = _validate_nodes(_list(graph_doc.get("nodes"), "nodes"))
    adjacency = _validate_edges(_list(graph_doc.get("edges"), "edges"), nodes)
    paths = graph_doc.get("threat_paths") or {}
    if not isinstance(paths, dict):
        raise GraphError("threat_paths must be a mapping")

    results = []
    seen_threats = set()
    for threat in threats:
        if not isinstance(threat, dict) or not threat.get("id"):
            raise GraphError("each threat must be a mapping with an id")
        threat_id = threat["id"]
        if threat_id in seen_threats:
            raise GraphError(f"duplicate threat id: {threat_id}")
        seen_threats.add(threat_id)
        path = paths.get(threat_id) or {}
        if not isinstance(path, dict):
            raise GraphError(f"threat_paths.{threat_id} must be a mapping")
        sources = _list(path.get("sources"), f"threat_paths.{threat_id}.sources")
        unknown_sources = sorted(set(sources) - set(nodes))
        if unknown_sources:
            raise GraphError(f"{threat_id}: unknown source nodes: {', '.join(unknown_sources)}")
        reached_ids, reached_edges = _reachable(sources, adjacency)
        reached = [nodes[node_id] for node_id in reached_ids]
        responsibilities = sorted({node.get("responsibility", "undetermined") for node in reached})
        for responsibility in responsibilities:
            _check_value(responsibility, "responsibility")
        basis = list(path.get("basis") or [])
        basis += [f"node:{node_id}" for node_id in reached_ids]
        basis += [f"edge:{edge['from']}->{edge['to']}" for edge in reached_edges]
        blast = {field: _max_dimension(reached, field) for field in DIMENSIONS}
        review = _review(path)
        validation_status = review["status"]
        confidence = _confidence(reached, reached_edges, path)
        priority_floor, priority_reasons, review_required = _priority(blast, confidence, validation_status)
        affected_assets = [
            {
                "id": node_id,
                "responsibility": nodes[node_id].get("responsibility", "undetermined"),
                "confidence": nodes[node_id].get("confidence", "inferred"),
                "scope": {field: nodes[node_id].get(field, "unknown") for field in DIMENSIONS},
            }
            for node_id in reached_ids
        ]
        results.append({
            "threat_id": threat_id,
            "blast_radius": blast,
            "coarse_scope": _coarse_scope(blast),
            "tenant_scope_detail": _tenant_detail(path, blast["tenant_scope"]),
            "affected_nodes": reached_ids,
            "affected_assets": affected_assets,
            "responsibility": responsibilities,
            "confidence": confidence,
            "basis": sorted(set(str(item) for item in basis)),
            "condition": path.get("condition"),
            "validation": {
                "status": validation_status,
                "required_checks": sorted(set(path.get("required_checks") or [])),
            },
            "review": review,
            "priority_floor": priority_floor,
            "priority_reasons": priority_reasons,
            "review_required": review_required,
        })
    return {"version": "1", "dimensions": {field: ORDERS[field] for field in DIMENSIONS},
            "coarse_scopes": list(COARSE_SCOPES), "results": results}


def render_markdown(result: dict) -> str:
    """Render a compact review table without hiding uncertainty."""
    lines = ["# Blast-radius review", "", "> Derived from the reviewed threat graph. This is not proof of implementation or certification.", "",
             "| Threat | Summary | Tenant scope | Data | Runtime | Control | Recovery | Priority floor | Why | Confidence | Validation |", "|---|---|---|---|---|---|---|---|---|---|---|"]
    for item in result.get("results", []):
        radius = item["blast_radius"]
        lines.append("| {threat_id} | {coarse_scope} | {tenant_scope} | {data_scope} | {runtime_scope} | {control_scope} | {recovery_scope} | {priority_floor} | {reasons} | {confidence} | {status} |".format(
            threat_id=item["threat_id"], coarse_scope=item.get("coarse_scope", "unknown"), **radius, priority_floor=item["priority_floor"],
            reasons=", ".join(item.get("priority_reasons") or []) or "—",
            confidence=item["confidence"], status=item["validation"]["status"]))
    lines += ["", "## Validation work", ""]
    for item in result.get("results", []):
        checks = item["validation"].get("required_checks") or []
        if checks or item["validation"]["status"] in {"unreviewed", "expired"}:
            lines.append(f"- **{item['threat_id']}**: {', '.join(checks) if checks else 'review required'}")
    return "\n".join(lines) + "\n"


def compare(current: dict, previous: dict) -> dict:
    """Report scope expansion or reduction between two derived runs."""
    current_by_id = {row["threat_id"]: row for row in current.get("results", [])}
    previous_by_id = {row["threat_id"]: row for row in previous.get("results", [])}
    changes = []
    for threat_id in sorted(set(current_by_id) | set(previous_by_id)):
        if threat_id not in previous_by_id:
            changes.append({"threat_id": threat_id, "change": "added"})
            continue
        if threat_id not in current_by_id:
            changes.append({"threat_id": threat_id, "change": "removed"})
            continue
        before = previous_by_id[threat_id].get("blast_radius", {})
        after = current_by_id[threat_id].get("blast_radius", {})
        expanded, reduced = [], []
        for field, order in ORDERS.items():
            old = before.get(field, "unknown")
            new = after.get(field, "unknown")
            if old not in order or new not in order:
                continue
            if order.index(new) > order.index(old):
                expanded.append(field)
            elif order.index(new) < order.index(old):
                reduced.append(field)
        if expanded or reduced or previous_by_id[threat_id].get("priority_floor") != current_by_id[threat_id].get("priority_floor"):
            changes.append({
                "threat_id": threat_id,
                "change": "expanded" if expanded and not reduced else "reduced" if reduced and not expanded else "changed",
                "expanded_dimensions": expanded,
                "reduced_dimensions": reduced,
                "previous_priority_floor": previous_by_id[threat_id].get("priority_floor"),
                "current_priority_floor": current_by_id[threat_id].get("priority_floor"),
            })
    return {"version": "1", "changes": changes,
            "expanded": sum(row["change"] == "expanded" for row in changes)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--threats", type=Path, required=True)
    parser.add_argument("--graph", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--markdown", type=Path,
                        help="optional Markdown review report")
    parser.add_argument("--previous", type=Path,
                        help="previous blast-radius.json for scope comparison")
    parser.add_argument("--changes", type=Path,
                        help="optional JSON path for the comparison result")
    parser.add_argument("--fail-on-expansion", action="store_true",
                        help="exit 3 when the comparison contains an expanded path")
    args = parser.parse_args(argv)
    try:
        result = derive(_load(args.threats), _load(args.graph))
    except (GraphError, OSError, yaml.YAMLError) as exc:
        parser.error(str(exc))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if args.markdown:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.write_text(render_markdown(result), encoding="utf-8")
        print(f"wrote {args.markdown}")
    exit_code = 0
    if args.fail_on_expansion and not args.previous:
        parser.error("--fail-on-expansion requires --previous")
    if args.previous:
        if not args.previous.exists():
            parser.error(f"--previous {args.previous} does not exist")
        previous = json.loads(args.previous.read_text(encoding="utf-8"))
        changes = compare(result, previous)
        if args.changes:
            args.changes.parent.mkdir(parents=True, exist_ok=True)
            args.changes.write_text(json.dumps(changes, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            print(f"wrote {args.changes}")
        else:
            print(f"scope changes: {len(changes['changes'])}; expanded: {changes['expanded']}")
        if args.fail_on_expansion and changes["expanded"]:
            print("error: blast-radius scope expanded; review is required", file=sys.stderr)
            exit_code = 3
    print(f"wrote {args.out} ({len(result['results'])} threats)")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
