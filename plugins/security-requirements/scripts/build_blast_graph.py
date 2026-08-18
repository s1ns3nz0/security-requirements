#!/usr/bin/env python3
"""Build a conservative blast graph from repository evidence and a threat model.

This is discovery, not proof of connectivity.  Every inferred node and edge
keeps the file evidence that caused it to be emitted.  The result is intended
for human review before ``blast_radius.py`` consumes it.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import yaml


SERVICE_PATTERNS = {
    "api-gateway": (r"api.?gateway|apigateway|RestApi", "tenant_operations"),
    "alb": (r"application.?load.?balancer|elbv2|ListenerCondition", "tenant_operations"),
    "cloudfront": (r"cloudfront|Distribution", "feature"),
    "cognito": (r"cognito|UserPool|JWT", "feature"),
    "ecs": (r"ecs|Fargate|FargateService|Cluster", "feature"),
    "dynamodb": (r"dynamodb|DynamoDB|LeadingKeys|Table", "feature"),
    "lambda": (r"lambda|Lambda|Function", "platform"),
    "s3": (r"s3|Bucket|access.?log", "platform"),
    "eventbridge": (r"eventbridge|EventBridge|Rule", "platform"),
    "codebuild": (r"codebuild|CodeBuild|Project", "platform"),
    "cloudformation": (r"cloudformation|CloudFormation|Cfn", "platform"),
    "ecr": (r"ecr|ECR|repository", "platform"),
}

SERVICE_SCOPE = {
    "api-gateway": ("all", "record", "service", "tenant_operations", "platform_recovery"),
    "alb": ("all", "record", "service", "tenant_operations", "platform_recovery"),
    "cloudfront": ("all", "record", "region", "feature", "platform_recovery"),
    "cognito": ("all", "record", "service", "feature", "platform_recovery"),
    "ecs": ("subset", "tenant_dataset", "cluster", "feature", "tenant_recovery"),
    "dynamodb": ("subset", "tenant_dataset", "service", "feature", "tenant_recovery"),
    "lambda": ("all", "platform_dataset", "service", "platform", "platform_recovery"),
    "s3": ("all", "shared_dataset", "region", "platform", "platform_recovery"),
    "eventbridge": ("all", "platform_dataset", "service", "platform", "platform_recovery"),
    "codebuild": ("all", "platform_dataset", "account", "platform", "platform_recovery"),
    "cloudformation": ("all", "platform_dataset", "account", "platform", "platform_recovery"),
    "ecr": ("all", "platform_dataset", "account", "platform", "platform_recovery"),
}

EDGE_RULES = [
    ("api-gateway", "alb"), ("alb", "ecs"), ("ecs", "dynamodb"),
    ("lambda", "dynamodb"), ("cloudfront", "s3"),
    ("eventbridge", "codebuild"), ("codebuild", "cloudformation"),
    ("cloudformation", "ecs"), ("codebuild", "ecr"), ("ecs", "s3"),
]

BOUNDARY_SOURCE = {
    "TB-1": "cloudfront", "TB-2": "api-gateway", "TB-3": "api-gateway",
    "TB-4": "ecs", "TB-5": "api-gateway", "TB-6": "eventbridge",
    "TB-7": "lambda", "TB-8": "ecs", "TB-9": "codebuild",
}


def _files(root: Path) -> list[Path]:
    ignored = {".git", "node_modules", "cdk.out", "dist", "build", ".venv"}
    return [p for p in root.rglob("*") if p.is_file() and not ignored.intersection(p.parts)]


def _evidence(root: Path, pattern: str) -> list[str]:
    found = []
    regex = re.compile(pattern, re.IGNORECASE)
    for path in _files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if len(text) > 2_000_000:
            text = text[:2_000_000]
        if regex.search(text):
            found.append(str(path.relative_to(root)))
    return sorted(found)[:20]


def build(profile: dict, threats: dict, root: Path) -> dict:
    services = profile.get("inferred", {}).get("managed_services", []) or []
    declared = {item.get("id", "").replace("aws-", "") for item in services if isinstance(item, dict)}
    nodes = {}
    evidence_by_id = {}
    for service, (pattern, control_scope) in SERVICE_PATTERNS.items():
        evidence = _evidence(root, pattern)
        if service not in declared and not evidence:
            continue
        values = SERVICE_SCOPE[service]
        nodes[service] = {
            "id": service,
            "tenant_scope": values[0], "data_scope": values[1],
            "runtime_scope": values[2], "control_scope": values[3],
            "recovery_scope": values[4],
            "responsibility": "shared" if service in {"dynamodb", "s3", "cloudfront", "alb", "api-gateway"} else "team",
            "confidence": "confirmed" if evidence else "inferred",
            "evidence": evidence,
        }
        evidence_by_id[service] = evidence

    edges = []
    for source, target in EDGE_RULES:
        if source in nodes and target in nodes:
            edges.append({"from": source, "to": target,
                          "confidence": "inferred",
                          "evidence": sorted(set(evidence_by_id[source] + evidence_by_id[target]))[:10]})

    paths = {}
    for threat in threats.get("threats", []) or []:
        threat_id = threat.get("id")
        source = BOUNDARY_SOURCE.get(threat.get("boundary"))
        if source not in nodes:
            source = next(iter(nodes), None)
        if not threat_id or not source:
            continue
        paths[threat_id] = {
            "sources": [source],
            "basis": [f"auto-discovery:{item}" for item in evidence_by_id.get(source, [])],
            "condition": f"review threat {threat_id} against discovered path from {source}",
            "validation_status": "unreviewed",
            "required_checks": ["review_auto_discovered_nodes", "confirm_edge_connectivity"],
        }
    return {
        "version": "1", "generated_by": "build_blast_graph.py",
        "review_required": True, "nodes": list(nodes.values()),
        "edges": edges, "threat_paths": paths,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--threats", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    if not args.repo.is_dir():
        parser.error(f"--repo {args.repo} is not a directory")
    profile = yaml.safe_load(args.profile.read_text(encoding="utf-8")) or {}
    threats = yaml.safe_load(args.threats.read_text(encoding="utf-8")) or {}
    result = build(profile, threats, args.repo)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(yaml.safe_dump(result, sort_keys=False, allow_unicode=True), encoding="utf-8")
    print(f"wrote {args.out} ({len(result['nodes'])} nodes, {len(result['edges'])} edges)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
