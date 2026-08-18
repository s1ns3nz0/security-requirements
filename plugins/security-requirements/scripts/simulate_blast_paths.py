#!/usr/bin/env python3
"""Simulate threat paths without sending traffic or changing infrastructure.

The simulator walks the reviewed graph and emits reproducible negative-test
cases.  A reachable path means the graph permits the path; it does not mean an
exploit succeeded in a running environment.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml

from blast_radius import _validate_edges, _validate_nodes


def _ordered_reachable(sources: list[str], adjacency: dict[str, list[dict]]) -> tuple[list[str], list[dict]]:
    """Keep traversal order for test steps; blast derivation intentionally sorts IDs."""
    seen = set()
    order = []
    edges = []
    queue = list(sources)
    while queue:
        current = queue.pop(0)
        if current in seen:
            continue
        seen.add(current)
        order.append(current)
        for edge in adjacency.get(current, []):
            edges.append(edge)
            queue.append(edge["to"])
    return order, edges


def simulate(threats_doc: dict, graph_doc: dict) -> dict:
    nodes = _validate_nodes(graph_doc.get("nodes") or [])
    adjacency = _validate_edges(graph_doc.get("edges") or [], nodes)
    paths = graph_doc.get("threat_paths") or {}
    results = []
    for threat in threats_doc.get("threats", []) or []:
        threat_id = threat.get("id")
        path = paths.get(threat_id) or {}
        sources = path.get("sources") or []
        known = [source for source in sources if source in nodes]
        reached, edges = _ordered_reachable(known, adjacency)
        assertions = [
            f"deny {threat.get('persona', 'unknown')} before reaching {node_id}"
            for node_id in reached[1:]
        ]
        results.append({
            "threat_id": threat_id,
            "status": "reachable" if reached else "no_path",
            "source_nodes": known,
            "path_nodes": reached,
            "path_edges": [f"{edge['from']}->{edge['to']}" for edge in edges],
            "condition": path.get("condition"),
            "negative_test_cases": sorted(set(assertions)),
            "side_effects": "none; graph traversal only",
        })
    return {"version": "1", "mode": "graph_reachability_only",
            "results": results}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--threats", type=Path, required=True)
    parser.add_argument("--graph", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--fail-on-reachable", action="store_true",
                        help="exit 3 when any threat path is reachable in the graph")
    args = parser.parse_args(argv)
    threats = yaml.safe_load(args.threats.read_text(encoding="utf-8")) or {}
    graph = yaml.safe_load(args.graph.read_text(encoding="utf-8")) or {}
    result = simulate(threats, graph)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    reachable = sum(row["status"] == "reachable" for row in result["results"])
    print(f"wrote {args.out} ({reachable} reachable threat paths; no side effects)")
    return 3 if args.fail_on_reachable and reachable else 0


if __name__ == "__main__":
    raise SystemExit(main())
