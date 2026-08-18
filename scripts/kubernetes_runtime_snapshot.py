#!/usr/bin/env python3
"""Compare a read-only Kubernetes resource snapshot with declared design.

The snapshot may be produced by ``kubectl get ... -A -o json`` or by an
offline exporter.  Secret values are never copied into the comparison output.
"""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from typing import Any

import yaml

import kubernetes_graph


def _snapshot_graph(snapshot: dict[str, Any]) -> dict[str, Any]:
    if isinstance(snapshot.get("graph"), dict):
        return snapshot["graph"]
    items = snapshot.get("items")
    if not isinstance(items, list):
        raise ValueError("runtime snapshot must contain items or graph")
    with tempfile.TemporaryDirectory(prefix="k8s-runtime-") as directory:
        path = Path(directory) / "snapshot.yaml"
        path.write_text("\n---\n".join(yaml.safe_dump(item, sort_keys=False) for item in items), encoding="utf-8")
        return kubernetes_graph.build(path)


def compare(design: dict[str, Any], runtime: dict[str, Any]) -> dict[str, Any]:
    design_nodes = {node["id"]: node for node in design.get("nodes", []) or []}
    runtime_nodes = {node["id"]: node for node in runtime.get("nodes", []) or []}
    changes: list[dict[str, Any]] = []
    for node_id in sorted(set(design_nodes) | set(runtime_nodes)):
        if node_id not in runtime_nodes:
            changes.append({"resource": node_id, "status": "missing_runtime", "review_required": True})
        elif node_id not in design_nodes:
            changes.append({"resource": node_id, "status": "unmanaged_runtime", "review_required": True})
        else:
            design_node = design_nodes[node_id]
            runtime_node = runtime_nodes[node_id]
            changed = {field: {"design": design_node.get(field), "runtime": runtime_node.get(field)}
                       for field in ("tenant_scope", "data_scope", "runtime_scope", "control_scope", "recovery_scope")
                       if design_node.get(field) != runtime_node.get(field)}
            changes.append({"resource": node_id, "status": "drift" if changed else "matched",
                            "changed_fields": changed, "review_required": bool(changed)})
    design_edges = {(e.get("from"), e.get("to"), e.get("relation")) for e in design.get("edges", []) or []}
    runtime_edges = {(e.get("from"), e.get("to"), e.get("relation")) for e in runtime.get("edges", []) or []}
    for edge in sorted(design_edges - runtime_edges):
        changes.append({"resource": f"edge:{edge[0]}->{edge[1]}", "status": "missing_runtime_edge",
                        "changed_fields": {"relation": edge[2]}, "review_required": True})
    for edge in sorted(runtime_edges - design_edges):
        changes.append({"resource": f"edge:{edge[0]}->{edge[1]}", "status": "unmanaged_runtime_edge",
                        "changed_fields": {"relation": edge[2]}, "review_required": True})
    return {"version": "1", "mode": "read_only_snapshot_compare",
            "review_required": any(item["review_required"] for item in changes),
            "changes": changes,
            "summary": {"matched": sum(c["status"] == "matched" for c in changes),
                         "drift": sum(c["status"] == "drift" for c in changes),
                         "missing_runtime": sum(c["status"] == "missing_runtime" for c in changes),
                         "unmanaged_runtime": sum(c["status"] == "unmanaged_runtime" for c in changes),
                         "edge_changes": sum(c["status"].endswith("_edge") for c in changes)}}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--design-graph", type=Path, required=True)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    design = yaml.safe_load(args.design_graph.read_text(encoding="utf-8")) or {}
    raw = yaml.safe_load(args.snapshot.read_text(encoding="utf-8")) or {}
    result = compare(design, _snapshot_graph(raw))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {args.out} ({result['summary']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
