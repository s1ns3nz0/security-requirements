#!/usr/bin/env python3
"""Analyze common Service Mesh policies and declared Operator scope."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import yaml

import kubernetes_graph


MESH_KINDS = {"VirtualService", "DestinationRule", "AuthorizationPolicy",
              "PeerAuthentication", "CiliumNetworkPolicy"}


def analyze(path: Path, operator_catalog: dict[str, Any] | None = None) -> dict[str, Any]:
    docs, notes = kubernetes_graph._load(path)
    policies, operators, findings = [], [], []
    for obj in docs:
        kind = obj.get("kind")
        if kind in MESH_KINDS:
            record = {"kind": kind, "name": kubernetes_graph._name(obj),
                      "namespace": kubernetes_graph._namespace(obj)}
            policies.append(record)
            if kind == "PeerAuthentication" and obj.get("spec", {}).get("mtls", {}).get("mode") in {None, "PERMISSIVE"}:
                findings.append({"type": "design_derived", "severity": "high",
                                 "reason": "service_mesh_mtls_not_strict", "resource": record})
            if kind == "AuthorizationPolicy" and not obj.get("spec", {}).get("rules"):
                findings.append({"type": "coverage_gap", "severity": "medium",
                                 "reason": "service_mesh_authorization_scope_unknown", "resource": record})
        if kind in kubernetes_graph.WORKLOADS and kubernetes_graph._operator_name(obj):
            name = kubernetes_graph._name(obj)
            catalog = (operator_catalog or {}).get(name)
            record = {"name": name, "namespace": kubernetes_graph._namespace(obj),
                      "catalog_entry": bool(catalog), "watched_kinds": (catalog or {}).get("watched_kinds", []),
                      "scope": (catalog or {}).get("scope", "unknown")}
            operators.append(record)
            if not catalog:
                findings.append({"type": "coverage_gap", "severity": "high",
                                 "reason": "advanced_operator_not_catalogued", "resource": name})
    return {"version": "1", "mode": "service_mesh_and_operator_analysis",
            "mesh_policies": policies, "operators": operators, "findings": findings,
            "parse_notes": notes, "review_required": bool(findings)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--operator-catalog", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    catalog = json.loads(args.operator_catalog.read_text(encoding="utf-8")) if args.operator_catalog else None
    result = analyze(args.input, catalog)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {args.out} ({len(result['mesh_policies'])} policies)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
