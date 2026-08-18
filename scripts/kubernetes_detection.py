#!/usr/bin/env python3
"""Create SOC detection candidates traceable to Kubernetes threats."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import yaml


def derive(requirements: dict[str, Any], attack_paths: dict[str, Any] | None = None) -> dict[str, Any]:
    detections = []
    for requirement in requirements.get("requirements", []) or []:
        statement = requirement.get("statement", "")
        if "cluster-wide" in statement or "Kubernetes API" in statement:
            detections.append({"id": f"DET-K8S-{len(detections) + 1:03d}",
                               "requirement_refs": [requirement.get("id")], "severity": "high",
                               "source": "kubernetes_audit_log",
                               "rule": "detect service accounts creating, deleting, or listing cluster-scoped resources",
                               "query": "verb in (create,delete,patch,update,list) and objectRef.namespace is null"})
        elif "NetworkPolicy" in statement:
            detections.append({"id": f"DET-K8S-{len(detections) + 1:03d}",
                               "requirement_refs": [requirement.get("id")], "severity": "high",
                               "source": "network_flow_or_cni_log",
                               "rule": "detect denied or unexpected cross-namespace connections",
                               "query": "source.namespace != destination.namespace and policy_decision != allowed"})
        elif "Operator" in statement:
            detections.append({"id": f"DET-K8S-{len(detections) + 1:03d}",
                               "requirement_refs": [requirement.get("id")], "severity": "high",
                               "source": "kubernetes_audit_log",
                               "rule": "detect Operator service account changes outside approved resource kinds",
                               "query": "user.username = operator_service_account and objectRef.resource not in allowlist"})
    return {"version": "1", "mode": "kubernetes_detection_candidates",
            "detections": detections, "review_required": bool(detections),
            "disclaimer": "Candidates require adaptation to the organization's log pipeline and approved baseline."}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--requirements", type=Path, required=True)
    parser.add_argument("--attack-paths", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    requirements = yaml.safe_load(args.requirements.read_text(encoding="utf-8")) or {}
    paths = json.loads(args.attack_paths.read_text(encoding="utf-8")) if args.attack_paths else None
    result = derive(requirements, paths)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {args.out} ({len(result['detections'])} detections)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
