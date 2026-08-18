#!/usr/bin/env python3
"""Collect a read-only AWS resource graph for blast-radius enrichment.

No create, update, delete, deploy, or tagging API is called.  The command needs
an AWS identity with read-only permissions.  If boto3 or credentials are absent,
it fails without producing a partial graph that could be mistaken for evidence.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import yaml


def _node(resource_id: str, service: str, data_scope: str, runtime: str,
          control: str, evidence: str) -> dict:
    return {
        "id": resource_id, "service": service,
        "tenant_scope": "all", "data_scope": data_scope,
        "runtime_scope": runtime, "control_scope": control,
        "recovery_scope": "platform_recovery", "responsibility": "shared",
        "confidence": "confirmed", "evidence": [evidence],
    }


def discover(region: str, profile: str | None = None, base_graph: dict | None = None) -> dict:
    try:
        import boto3
    except ImportError as exc:
        raise RuntimeError("boto3 is required for AWS discovery") from exc
    session = boto3.Session(profile_name=profile, region_name=region)
    nodes = []
    service_ids = {}

    def add(node: dict) -> None:
        nodes.append(node)
        service_ids.setdefault(node["service"], []).append(node["id"])

    sts = session.client("sts", region_name=region)
    identity = sts.get_caller_identity()
    account = identity.get("Account", "unknown")

    ecs = session.client("ecs", region_name=region)
    for cluster_arn in ecs.list_clusters().get("clusterArns", []):
        cluster = cluster_arn.rsplit("/", 1)[-1]
        add(_node(f"ecs-cluster:{cluster}", "ecs", "tenant_dataset", "cluster", "feature", cluster_arn))
        services = ecs.list_services(cluster=cluster_arn).get("serviceArns", [])
        for service_arn in services:
            name = service_arn.rsplit("/", 1)[-1]
            add(_node(f"ecs-service:{cluster}/{name}", "ecs", "tenant_dataset", "service", "feature", service_arn))

    dynamodb = session.client("dynamodb", region_name=region)
    for table in dynamodb.list_tables().get("TableNames", []):
        detail = dynamodb.describe_table(TableName=table)["Table"]
        add(_node(f"dynamodb:{table}", "dynamodb", "tenant_dataset", "service", "feature", detail.get("TableArn", table)))

    for function in session.client("lambda", region_name=region).list_functions().get("Functions", []):
        add(_node(f"lambda:{function['FunctionName']}", "lambda", "platform_dataset", "service", "platform", function.get("FunctionArn", function["FunctionName"])))

    for api in session.client("apigateway", region_name=region).get_rest_apis().get("items", []):
        add(_node(f"api-gateway:{api['id']}", "api-gateway", "record", "service", "tenant_operations", api["id"]))

    for rule in session.client("events", region_name=region).list_rules().get("Rules", []):
        add(_node(f"eventbridge:{rule['Name']}", "eventbridge", "platform_dataset", "service", "platform", rule.get("Arn", rule["Name"])))

    cf = session.client("cloudformation", region_name=region)
    for stack in cf.list_stacks().get("StackSummaries", []):
        if stack.get("StackStatus", "").endswith("_IN_PROGRESS"):
            continue
        add(_node(f"cloudformation:{stack['StackName']}", "cloudformation", "platform_dataset", "account", "platform", stack.get("StackId", stack["StackName"])))

    ecr = session.client("ecr", region_name=region)
    for repo in ecr.describe_repositories().get("repositories", []):
        add(_node(f"ecr:{repo['repositoryName']}", "ecr", "platform_dataset", "account", "platform", repo.get("repositoryArn", repo["repositoryName"])))

    edges = []
    def connect(source_service: str, target_service: str) -> None:
        for source in service_ids.get(source_service, []):
            for target in service_ids.get(target_service, []):
                edges.append({"from": source, "to": target, "confidence": "confirmed",
                              "evidence": ["AWS read-only discovery"]})
    for source, target in (("api-gateway", "ecs"), ("ecs", "dynamodb"),
                           ("eventbridge", "lambda"), ("eventbridge", "cloudformation"),
                           ("cloudformation", "ecs"), ("lambda", "dynamodb")):
        connect(source, target)
    result = {"version": "1", "generated_by": "aws_blast_snapshot.py",
            "provider": "aws", "read_only": True, "region": region,
            "account_id": account, "review_required": True,
            "nodes": nodes, "edges": edges, "threat_paths": {}}
    if base_graph:
        result["nodes"] = (base_graph.get("nodes") or []) + result["nodes"]
        result["edges"] = (base_graph.get("edges") or []) + result["edges"]
        result["threat_paths"] = base_graph.get("threat_paths") or {}
        result["base_graph"] = "merged"
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--region", required=True)
    parser.add_argument("--profile")
    parser.add_argument("--base-graph", type=Path,
                        help="optional reviewed graph whose threats and nodes are preserved")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        base = yaml.safe_load(args.base_graph.read_text(encoding="utf-8")) if args.base_graph else None
        result = discover(args.region, args.profile, base)
    except Exception as exc:
        parser.error(str(exc))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(yaml.safe_dump(result, sort_keys=False), encoding="utf-8")
    print(f"wrote {args.out} ({len(result['nodes'])} nodes, {len(result['edges'])} edges; read-only)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
