#!/usr/bin/env python3
"""Derive Kubernetes attack-path candidates from the normalized graph.

This is a graph analysis, not an exploit runner. It explains how an external
entry point or workload identity can reach the Kubernetes API, another tenant,
or a shared data resource.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import yaml

from blast_radius import _validate_edges, _validate_nodes


def _walk(source: str, adjacency: dict[str, list[dict[str, Any]]]) -> list[str]:
    seen, queue = set(), [source]
    while queue:
        current = queue.pop(0)
        if current in seen:
            continue
        seen.add(current)
        queue.extend(edge["to"] for edge in adjacency.get(current, []))
    return sorted(seen)


def analyze(graph: dict[str, Any]) -> dict[str, Any]:
    nodes = _validate_nodes(graph.get("nodes") or [])
    adjacency = _validate_edges(graph.get("edges") or [], nodes)
    paths = []
    for node_id, node in nodes.items():
        if node.get("kind") not in {"Deployment", "StatefulSet", "DaemonSet", "Pod", "ServiceAccount"}:
            continue
        reached = _walk(node_id, adjacency)
        if "kubernetes-api/cluster" in reached:
            paths.append({"source": node_id, "target": "kubernetes-api/cluster",
                          "path_nodes": reached, "scope": "cluster",
                          "reason": "workload identity reaches Kubernetes API"})
    for node_id, node in nodes.items():
        if node.get("kind") == "Ingress":
            reached = _walk(node_id, adjacency)
            paths.append({"source": node_id, "target": "external-request",
                          "path_nodes": reached, "scope": node.get("tenant_scope", "unknown"),
                          "reason": "external ingress reaches workload path"})
    findings = []
    for path in paths:
        if path["target"] == "kubernetes-api/cluster":
            findings.append({"type": "design_derived", "id": "K8S-ATTACK-RBAC",
                             "severity": "high", "reason": path["reason"],
                             "source": path["source"]})
    return {"version": "1", "mode": "graph_attack_path_analysis",
            "paths": paths, "findings": findings,
            "review_required": bool(findings)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graph", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    result = analyze(yaml.safe_load(args.graph.read_text(encoding="utf-8")) or {})
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {args.out} ({len(result['paths'])} paths)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
