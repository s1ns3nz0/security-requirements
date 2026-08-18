#!/usr/bin/env python3
"""Join Kubernetes Workload Identity bindings with cloud IAM policies."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import yaml


def _statements(policy: Any) -> list[dict[str, Any]]:
    if isinstance(policy, dict) and isinstance(policy.get("Statement"), list):
        return [item for item in policy["Statement"] if isinstance(item, dict)]
    if isinstance(policy, dict) and isinstance(policy.get("Statement"), dict):
        return [policy["Statement"]]
    return []


def analyze(graph: dict[str, Any], policies: dict[str, Any]) -> dict[str, Any]:
    identities = {node.get("external_reference"): node for node in graph.get("nodes", [])
                  if node.get("kind") == "ExternalIdentity" and node.get("external_reference")}
    bindings, findings = [], []
    for reference, node in identities.items():
        policy = policies.get(reference, {})
        statements = _statements(policy)
        actions = sorted({str(action) for stmt in statements
                          for action in (stmt.get("Action", []) if isinstance(stmt.get("Action", []), list)
                                         else [stmt.get("Action")]) if action})
        resources = sorted({str(resource) for stmt in statements
                            for resource in (stmt.get("Resource", []) if isinstance(stmt.get("Resource", []), list)
                                             else [stmt.get("Resource")]) if resource})
        record = {"identity": reference, "node": node["id"], "actions": actions,
                  "resources": resources, "confidence": "confirmed" if reference in policies else "unknown"}
        bindings.append(record)
        if "*" in actions or "*" in resources:
            findings.append({"type": "design_derived", "severity": "high",
                             "reason": "workload identity has wildcard cloud IAM scope",
                             "identity": reference})
        elif not statements:
            findings.append({"type": "coverage_gap", "severity": "high",
                             "reason": "cloud IAM policy for workload identity is unavailable",
                             "identity": reference})
    return {"version": "1", "mode": "kubernetes_cloud_identity_analysis",
            "bindings": bindings, "findings": findings, "review_required": bool(findings)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graph", type=Path, required=True)
    parser.add_argument("--policies", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    graph = yaml.safe_load(args.graph.read_text(encoding="utf-8")) or {}
    policies = json.loads(args.policies.read_text(encoding="utf-8"))
    result = analyze(graph, policies)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {args.out} ({len(result['bindings'])} identities)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
