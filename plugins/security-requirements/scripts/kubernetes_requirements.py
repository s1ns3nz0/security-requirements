#!/usr/bin/env python3
"""Turn a Kubernetes security graph into traceable review requirements.

The output deliberately separates benchmark references from requirements that
come from the application's topology, tenant model, or data flows.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import yaml


def _blast_by_threat(document: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    return {item.get("threat_id"): item for item in (document or {}).get("results", [])
            if item.get("threat_id")}


def derive(graph: dict[str, Any], blast_radius: dict[str, Any] | None = None,
           external_findings: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    blast = _blast_by_threat(blast_radius)
    requirements: list[dict[str, Any]] = []
    for threat in graph.get("threats", []) or []:
        threat_id = threat.get("id")
        radius = blast.get(threat_id, {})
        scope = radius.get("coarse_scope", "unknown")
        requirements.append({
            "id": f"K8S-DESIGN-{len(requirements) + 1:03d}",
            "classification": "design_derived",
            "statement": _statement(threat),
            "rationale": threat.get("scenario"),
            "priority": "high" if scope in {"cross_tenant", "platform", "account_region", "unknown"} else "medium",
            "source": {"type": "graph_derived", "threat_id": threat_id},
            "threat_refs": [threat_id],
            "blast_radius_refs": [threat_id] if threat_id in blast else [],
            "related_references": _references(threat),
            "verification": _verification(threat),
            "evidence": ["rendered Kubernetes manifest", "reviewed security graph"],
            "review_required": not bool(radius) or radius.get("review_required", True),
        })

    for issue in graph.get("issues", []) or []:
        if issue.get("type") == "benchmark_check":
            requirements.append({
                "id": f"K8S-BENCH-{len(requirements) + 1:03d}",
                "classification": "benchmark_check",
                "statement": _benchmark_statement(issue.get("reason")),
                "rationale": "A Kubernetes hardening property is missing from the rendered workload security context.",
                "priority": "medium",
                "source": {"type": "benchmark_check", "resource": issue.get("resource")},
                "related_references": [{"type": "cis-kubernetes", "id": issue.get("reference", "unknown"), "relation": "direct_check"}],
                "verification": [{"type": "rendered_manifest", "expected": "security context explicitly sets the required property"}],
                "evidence": ["rendered workload manifest"],
                "review_required": True,
            })
            continue
        if issue.get("reason") in {"unsupported_kind", "crd_behavior_unknown", "operator_behavior_unknown"}:
            requirements.append({
                "id": f"K8S-GAP-{len(requirements) + 1:03d}",
                "classification": "coverage_gap",
                "statement": f"The security behavior of {issue.get('resource')} must be reviewed because its Kubernetes kind is not supported by the analyzer.",
                "rationale": "An unrecognized resource may create or widen a security boundary.",
                "priority": "high",
                "source": {"type": "analyzer_gap", "resource": issue.get("resource")},
                "related_references": [],
                "verification": [{"type": "manual_review", "expected": "operator behavior and RBAC scope documented"}],
                "evidence": ["resource manifest", "operator documentation or source"],
                "review_required": True,
            })
    for finding in external_findings or []:
        reason = finding.get("reason", "external analyzer finding")
        classification = finding.get("type", "design_derived")
        if classification not in {"design_derived", "benchmark_check", "coverage_gap"}:
            classification = "design_derived"
        requirements.append({
            "id": f"K8S-EXT-{len(requirements) + 1:03d}",
            "classification": classification,
            "statement": f"The Kubernetes design must address the finding: {reason}.",
            "rationale": reason,
            "priority": "high" if finding.get("severity") == "high" else "medium",
            "source": {"type": "external_analyzer", "finding": finding},
            "related_references": [],
            "verification": [{"type": "manual_review", "expected": "finding is addressed and evidence is recorded"}],
            "evidence": [finding.get("evidence", "external analyzer output")],
            "review_required": True,
        })
    fail_reasons = [r["id"] for r in requirements
                    if r.get("classification") == "design_derived" and r.get("priority") == "high"
                    and any(blast.get(t, {}).get("coarse_scope") in {"platform", "account_region"}
                            for t in r.get("threat_refs", []))]
    review_reasons = [r["id"] for r in requirements if r.get("review_required")]
    decision = "fail" if fail_reasons else ("review_required" if review_reasons else "pass")
    return {"version": "1", "generated_by": "kubernetes_requirements.py",
            "platform": "kubernetes", "requirements": requirements,
            "summary": {"total": len(requirements),
                         "design_derived": sum(r["classification"] == "design_derived" for r in requirements),
                         "benchmark_check": sum(r["classification"] == "benchmark_check" for r in requirements),
                         "coverage_gap": sum(r["classification"] == "coverage_gap" for r in requirements)},
            "ci_decision": {"decision": decision, "fail_reasons": fail_reasons,
                            "review_reasons": review_reasons}}


def _statement(threat: dict[str, Any]) -> str:
    source = threat.get("source_issue")
    if source == "cluster_wide_binding":
        return "Tenant workloads must not receive cluster-wide write access; bindings must be Namespace-scoped unless a documented platform operation requires otherwise."
    if source == "workload_network_boundary_unresolved":
        return "Each tenant workload must have an explicit default-deny NetworkPolicy boundary and documented cross-tenant exceptions."
    if source == "tenant_resource_governance_unset":
        return "Each tenant Namespace must define ResourceQuota and LimitRange limits sufficient to prevent one tenant from exhausting shared cluster capacity."
    if source == "operator_behavior_unknown":
        return "The Operator's reconciliation scope, ServiceAccount permissions, and tenant-data access must be documented and tested before it is trusted as a platform component."
    return "The Kubernetes security boundary described by this threat must be explicitly enforced and verified."


def _benchmark_statement(reason: str | None) -> str:
    if reason == "workload_non_root_unset":
        return "Workloads must explicitly run as a non-root user through the Pod security context."
    if reason == "privilege_escalation_not_denied":
        return "Containers must explicitly deny privilege escalation in their security context."
    if reason == "cluster_wide_read_binding":
        return "Cluster-wide read permissions must be limited to the documented metrics or discovery resources and must not include write verbs."
    return "The workload must explicitly set the required Kubernetes hardening property."


def _references(threat: dict[str, Any]) -> list[dict[str, str]]:
    if threat.get("source_issue") == "cluster_wide_binding":
        return [{"type": "cis-kubernetes", "id": "5.1.1", "relation": "supporting_reference"},
                {"type": "owasp-kubernetes", "id": "RBAC", "relation": "threat_context"}]
    if threat.get("source_issue") == "workload_network_boundary_unresolved":
        return [{"type": "cis-kubernetes", "id": "5.3.2", "relation": "supporting_reference"},
                {"type": "owasp-kubernetes", "id": "network-segmentation", "relation": "threat_context"}]
    return []


def _verification(threat: dict[str, Any]) -> list[dict[str, str]]:
    if threat.get("source_issue") == "cluster_wide_binding":
        return [{"type": "static_graph_check", "expected": "tenant ServiceAccount reaches only Namespace Role"},
                {"type": "dynamic_cluster_test", "expected": "tenant identity cannot list or modify another Namespace"}]
    return [{"type": "static_graph_check", "expected": "NetworkPolicy applies to the workload"},
            {"type": "dynamic_cluster_test", "expected": "cross-tenant connection is denied"}]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graph", type=Path, required=True)
    parser.add_argument("--blast-radius", type=Path)
    parser.add_argument("--findings", type=Path, action="append", default=[])
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--fail-on-design-risk", action="store_true",
                        help="exit 3 when a high-priority design threat reaches platform/account scope")
    args = parser.parse_args(argv)
    graph = yaml.safe_load(args.graph.read_text(encoding="utf-8")) or {}
    blast = json.loads(args.blast_radius.read_text(encoding="utf-8")) if args.blast_radius else None
    external_findings = []
    for finding_file in args.findings:
        document = json.loads(finding_file.read_text(encoding="utf-8"))
        external_findings.extend(document.get("findings", []) or [])
    result = derive(graph, blast, external_findings)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(yaml.safe_dump(result, sort_keys=False, allow_unicode=True), encoding="utf-8")
    print(f"wrote {args.out} ({result['summary']['total']} requirements)")
    return 3 if args.fail_on_design_risk and result["ci_decision"]["decision"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
