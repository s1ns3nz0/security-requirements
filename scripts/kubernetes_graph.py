#!/usr/bin/env python3
"""Normalize Kubernetes manifests into the security graph used by the plugin.

This is intentionally a design-time reader.  It never contacts a cluster and
never executes kubectl.  The output is a conservative graph: relationships
that cannot be resolved remain visible as unknown review work instead of being
discarded.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from typing import Any

import yaml


SUPPORTED = {
    "Namespace", "Deployment", "StatefulSet", "DaemonSet", "Pod", "Service",
    "Ingress", "NetworkPolicy", "ServiceAccount", "Role", "ClusterRole",
    "RoleBinding", "ClusterRoleBinding", "Secret", "ConfigMap",
    "PersistentVolume", "PersistentVolumeClaim", "ResourceQuota", "LimitRange",
    "CustomResourceDefinition",
    "ValidatingWebhookConfiguration", "MutatingWebhookConfiguration",
    "APIService", "PodDisruptionBudget",
}
WORKLOADS = {"Deployment", "StatefulSet", "DaemonSet", "Pod"}


def _files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    return sorted(p for p in path.rglob("*") if p.is_file() and p.suffix in {".yaml", ".yml"})


def _source_digest(path: Path) -> str:
    digest = hashlib.sha256()
    for filename in _files(path):
        digest.update(str(filename).encode())
        try:
            digest.update(filename.read_bytes())
        except OSError:
            digest.update(b"<unreadable>")
    return digest.hexdigest()


def _load(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    docs: list[dict[str, Any]] = []
    evidence: list[str] = []
    skipped_templates = False
    for filename in _files(path):
        if "templates" in filename.parts:
            skipped_templates = True
            continue
        if "components" in filename.parts and filename.name.startswith("patch"):
            evidence.append(f"kustomize_patch_skipped:{filename}")
            continue
        try:
            text = filename.read_text(encoding="utf-8")
            try:
                parsed = list(yaml.safe_load_all(text))
            except yaml.YAMLError:
                # Rendered manifests can contain YAML tags such as !!binary or
                # the value tag. BaseLoader preserves the resource structure
                # without constructing application values or Secret contents.
                parsed = list(yaml.load_all(text, Loader=yaml.BaseLoader))
                evidence.append(f"{filename}: parsed_with_safe_structure_loader")
        except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
            evidence.append(f"{filename}: parse_error:{exc.__class__.__name__}")
            continue
        for item in parsed:
            if isinstance(item, dict) and item.get("kind"):
                api_version = str(item.get("apiVersion", ""))
                if api_version.startswith("kustomize.config.k8s.io"):
                    continue
                if api_version.startswith("kind.x-k8s.io"):
                    continue
                metadata = item.get("metadata") or {}
                item["metadata"] = metadata
                if not metadata.get("name"):
                    metadata["name"] = f"__unnamed__{filename.stem}"
                    item["__synthetic_name"] = True
                item["__evidence"] = str(filename)
                docs.append(item)
    if skipped_templates:
        evidence.append("helm_templates_skipped:render_with_helm_for_complete_analysis")
    return docs, evidence


def _namespace(obj: dict[str, Any]) -> str:
    if obj.get("kind") == "Namespace":
        return obj.get("metadata", {}).get("name", "default")
    return obj.get("metadata", {}).get("namespace", "default")


def _name(obj: dict[str, Any]) -> str:
    return obj.get("metadata", {}).get("name", "unnamed")


def _as_list(value: Any, *, field: str | None = None, resource: str | None = None,
             issues: list[dict[str, Any]] | None = None) -> list[Any]:
    """Return manifest fields as a list without treating malformed mappings as iterables."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if field and resource and issues is not None:
        issues.append({"type": "coverage_gap", "reason": "malformed_manifest_field",
                       "resource": resource, "field": field, "review_required": True})
    return []


def _id(kind: str, namespace: str, name: str) -> str:
    if kind == "Namespace":
        return f"namespace/{name}"
    return f"{kind.lower()}/{namespace}/{name}"


def _scope(kind: str, namespace: str, tenant: str | None = None) -> dict[str, str]:
    tenant_scope = "one" if tenant else "subset"
    data_scope = "tenant_dataset" if tenant else "shared_dataset"
    runtime = "namespace" if namespace not in {"default", "kube-system"} else "cluster"
    control = "feature" if kind in WORKLOADS | {"Service", "Ingress"} else "tenant_operations"
    if kind in {"ClusterRole", "ClusterRoleBinding", "Namespace", "CustomResourceDefinition",
                "ValidatingWebhookConfiguration", "MutatingWebhookConfiguration", "APIService"}:
        tenant_scope, data_scope, runtime, control = "all", "platform_dataset", "cluster", "control_plane"
    return {
        "tenant_scope": tenant_scope, "data_scope": data_scope,
        "runtime_scope": runtime, "control_scope": control,
        "recovery_scope": "tenant_recovery" if tenant else "platform_recovery",
    }


def _pod_template(obj: dict[str, Any]) -> dict[str, Any]:
    if obj.get("kind") == "Pod":
        return obj.get("spec") or {}
    spec = obj.get("spec") or {}
    template = spec.get("template") or {}
    return template.get("spec") or {}


def _labels(obj: dict[str, Any]) -> dict[str, str]:
    if obj.get("kind") == "Pod":
        return (obj.get("metadata") or {}).get("labels", {}) or {}
    spec = obj.get("spec") or {}
    template = spec.get("template") or {}
    return (template.get("metadata") or {}).get("labels", {}) or {}


def _matches(selector: dict[str, str], labels: dict[str, str]) -> bool:
    return bool(selector) and all(labels.get(k) == v for k, v in selector.items())


def _subjects(binding: dict[str, Any]) -> list[dict[str, Any]]:
    return binding.get("subjects", []) or []


def _operator_name(obj: dict[str, Any]) -> bool:
    name = _name(obj).lower()
    labels = obj.get("metadata", {}).get("labels", {}) or {}
    component = str(labels.get("app.kubernetes.io/component", "")).lower()
    return "operator" in name or "controller" in name or component in {"operator", "controller"}


def _identity_annotation(obj: dict[str, Any]) -> tuple[str, str] | None:
    annotations = obj.get("metadata", {}).get("annotations", {}) or {}
    bindings = (
        ("aws", "eks.amazonaws.com/role-arn"),
        ("gcp", "iam.gke.io/gcp-service-account"),
        ("azure", "azure.workload.identity/client-id"),
    )
    for provider, key in bindings:
        if annotations.get(key):
            return provider, str(annotations[key])
    return None


def _api_group(obj: dict[str, Any]) -> str:
    return str(obj.get("apiVersion", "")).split("/", 1)[0] if "/" in str(obj.get("apiVersion", "")) else ""


def _read_only_rules(rules: list[dict[str, Any]]) -> bool:
    verbs = {verb for rule in rules for verb in (rule.get("verbs", []) or [])}
    return bool(verbs) and "*" not in verbs and verbs <= {"get", "list", "watch"}


def _ref_id(ref: dict[str, Any], namespace: str) -> str | None:
    kind = ref.get("kind")
    name = ref.get("name")
    if not kind or not name:
        return None
    return _id(kind, ref.get("namespace", namespace), name)


def build(path: Path) -> dict[str, Any]:
    docs, parse_notes = _load(path)
    resources: dict[tuple[str, str, str], dict[str, Any]] = {}
    nodes: dict[str, dict[str, Any]] = {}
    issues: list[dict[str, Any]] = []
    custom_kinds = {
        ((obj.get("spec", {}) or {}).get("group"),
         ((obj.get("spec") or {}).get("names", {}) or {}).get("kind"))
        for obj in docs if obj.get("kind") == "CustomResourceDefinition"
    }

    for obj in docs:
        kind = obj.get("kind")
        if not isinstance(kind, str) or not kind:
            issues.append({"type": "coverage_gap", "reason": "malformed_manifest_kind",
                           "kind": repr(kind), "resource": obj.get("__evidence", "manifest"),
                           "review_required": True})
            continue
        namespace = _namespace(obj)
        name = _name(obj)
        rid = _id(kind, namespace, name)
        resources[(kind, namespace, name)] = obj
        custom_resource = ( _api_group(obj), kind) in custom_kinds
        if kind not in SUPPORTED and not custom_resource:
            issues.append({"type": "coverage_gap", "reason": "unsupported_kind", "kind": kind,
                           "resource": rid, "review_required": True})
            continue
        tenant = namespace if namespace not in {"default", "kube-system", "platform-system"} else None
        node = {"id": rid, "kind": "CustomResource" if custom_resource else kind,
                "platform": "kubernetes", "namespace": namespace,
                **_scope(kind, namespace, tenant), "responsibility": "team",
                "confidence": "confirmed", "evidence": [obj.get("__evidence", "manifest")]}
        if custom_resource:
            node["custom_kind"] = kind
            node["crd_ref"] = f"{_api_group(obj)}/{kind}"
        if kind == "ServiceAccount":
            node["control_scope"] = "tenant_operations" if tenant else "control_plane"
            identity = _identity_annotation(obj)
            if identity:
                provider, reference = identity
                external_id = f"external-identity/{namespace}/{name}"
                nodes[external_id] = {"id": external_id, "kind": "ExternalIdentity",
                                      "platform": provider, "namespace": namespace,
                                      **_scope("ClusterRole", namespace, tenant),
                                      "runtime_scope": "account", "control_scope": "platform",
                                      "external_reference": reference, "responsibility": "shared",
                                      "confidence": "confirmed", "evidence": node["evidence"]}
        if kind in {"Secret", "PersistentVolume", "PersistentVolumeClaim"}:
            node["data_scope"] = "tenant_dataset" if tenant else "platform_dataset"
        nodes[rid] = node
        if kind in {"Role", "ClusterRole"}:
            node["rbac_rules"] = obj.get("rules", []) or []
        if kind == "CustomResourceDefinition" or custom_resource:
            issues.append({"type": "coverage_gap", "reason": "crd_behavior_unknown",
                           "resource": rid,
                           "crd_ref": node.get("crd_ref", rid), "review_required": True})
        if kind in {"ValidatingWebhookConfiguration", "MutatingWebhookConfiguration"}:
            issues.append({"type": "design_derived", "reason": "admission_webhook_present",
                           "resource": rid, "review_required": True})

    edges: list[dict[str, Any]] = []

    if any(kind in {"Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"}
           for kind, _, _ in resources):
        nodes["kubernetes-api/cluster"] = {
            "id": "kubernetes-api/cluster", "kind": "KubernetesAPI", "platform": "kubernetes",
            "namespace": "platform-system", "tenant_scope": "all", "data_scope": "platform_dataset",
            "runtime_scope": "cluster", "control_scope": "control_plane",
            "recovery_scope": "platform_recovery", "responsibility": "shared",
            "confidence": "confirmed", "evidence": ["RBAC resources in manifest"],
        }

    def edge(source: str, target: str, relation: str, obj: dict[str, Any], confidence: str = "confirmed") -> None:
        if source in nodes and target in nodes:
            edges.append({"from": source, "to": target, "relation": relation,
                          "confidence": confidence, "evidence": [obj.get("__evidence", "manifest")]})

    # Namespace containment and workload-to-Service selection.
    for rid, node in list(nodes.items()):
        if node["kind"] != "Namespace":
            parent = _id("Namespace", node["namespace"], node["namespace"])
            if parent in nodes:
                edge(parent, rid, "contains", resources.get(("Namespace", node["namespace"], node["namespace"]), {}))
    for (kind, namespace, name), obj in resources.items():
        rid = _id(kind, namespace, name)
        if kind == "Service":
            selector = (obj.get("spec") or {}).get("selector", {}) or {}
            for wk, wn, wname in resources:
                if wk in WORKLOADS and wn == namespace and _matches(selector, _labels(resources[(wk, wn, wname)])):
                    edge(rid, _id(wk, wn, wname), "selects", obj)
        if kind == "Ingress":
            rules = (obj.get("spec") or {}).get("rules", []) or []
            for rule in rules:
                for path_item in rule.get("http", {}).get("paths", []) or []:
                    service = path_item.get("backend", {}).get("service", {}).get("name")
                    if service:
                        edge(rid, _id("Service", namespace, service), "routes_to", obj)
        if kind in {"ValidatingWebhookConfiguration", "MutatingWebhookConfiguration"}:
            for webhook in obj.get("webhooks", []) or []:
                service = webhook.get("clientConfig", {}).get("service", {})
                service_name = service.get("name")
                service_namespace = service.get("namespace", "platform-system")
                if service_name:
                    edge(rid, _id("Service", service_namespace, service_name), "calls", obj)
        if kind == "APIService":
            service = (obj.get("spec") or {}).get("service", {}) or {}
            service_name = service.get("name")
            service_namespace = service.get("namespace", "default")
            if service_name:
                edge(rid, _id("Service", service_namespace, service_name), "aggregates", obj)
            if (obj.get("spec") or {}).get("insecureSkipTLSVerify") is True:
                issues.append({"type": "benchmark_check", "reason": "aggregated_api_tls_unverified",
                               "resource": rid, "reference": "cis-kubernetes:5.4.2", "review_required": True})
        if kind in WORKLOADS:
            spec = _pod_template(obj)
            security = spec.get("securityContext", {}) or {}
            containers = _as_list(spec.get("containers"), field="spec.template.spec.containers",
                                  resource=rid, issues=issues) + _as_list(
                spec.get("initContainers"), field="spec.template.spec.initContainers",
                resource=rid, issues=issues)
            container_nonroot = bool(containers) and all(
                (container.get("securityContext", {}) or {}).get("runAsNonRoot") is True
                for container in containers
            )
            if security.get("runAsNonRoot") is not True and not container_nonroot:
                issues.append({"type": "benchmark_check", "reason": "workload_non_root_unset",
                               "resource": rid, "reference": "cis-kubernetes:5.2.6",
                               "review_required": True})
            sa = spec.get("serviceAccountName") or "default"
            edge(rid, _id("ServiceAccount", namespace, sa), "uses", obj, "inferred" if sa == "default" else "confirmed")
            if _operator_name(obj):
                issues.append({"type": "coverage_gap", "reason": "operator_behavior_unknown",
                               "resource": rid, "service_account": sa,
                               "review_required": True})
            for container in containers:
                container_security = container.get("securityContext", {}) or {}
                if container_security.get("allowPrivilegeEscalation") is not False:
                    issues.append({"type": "benchmark_check", "reason": "privilege_escalation_not_denied",
                                   "resource": rid, "container": container.get("name"),
                                   "reference": "cis-kubernetes:5.2.5", "review_required": True})
                for env in _as_list(container.get("env"), field="container.env",
                                    resource=rid, issues=issues):
                    ref = env.get("valueFrom", {}).get("secretKeyRef") or env.get("valueFrom", {}).get("configMapKeyRef")
                    if ref:
                        target_kind = "Secret" if "secretKeyRef" in env.get("valueFrom", {}) else "ConfigMap"
                        edge(rid, _id(target_kind, namespace, ref.get("name", "")), "reads", obj)
            for volume in _as_list(spec.get("volumes"), field="spec.template.spec.volumes",
                                   resource=rid, issues=issues):
                claim = volume.get("persistentVolumeClaim", {}).get("claimName")
                secret = volume.get("secret", {}).get("secretName")
                config = volume.get("configMap", {}).get("name")
                if claim:
                    edge(rid, _id("PersistentVolumeClaim", namespace, claim), "mounts", obj)
                if secret:
                    edge(rid, _id("Secret", namespace, secret), "mounts", obj)
                if config:
                    edge(rid, _id("ConfigMap", namespace, config), "mounts", obj)
        if kind in {"RoleBinding", "ClusterRoleBinding"}:
            role_ref = _ref_id(obj.get("roleRef", {}), namespace)
            if role_ref:
                edge(rid, role_ref, "binds", obj)
                if role_ref in nodes:
                    edge(role_ref, "kubernetes-api/cluster", "grants_api_access", obj)
            for subject in _subjects(obj):
                subject_kind = subject.get("kind")
                subject_name = subject.get("name")
                subject_ns = subject.get("namespace", namespace)
                if subject_kind == "ServiceAccount" and subject_name:
                    edge(_id(subject_kind, subject_ns, subject_name), rid, "granted_by", obj)
            if kind == "ClusterRoleBinding":
                role_node = nodes.get(role_ref or "", {})
                rules = role_node.get("rbac_rules", []) or []
                if _read_only_rules(rules):
                    issues.append({"type": "benchmark_check", "reason": "cluster_wide_read_binding",
                                   "resource": rid, "reference": "cis-kubernetes:5.1.1",
                                   "review_required": True})
                else:
                    issues.append({"type": "design_derived", "reason": "cluster_wide_binding",
                                   "resource": rid, "blast_radius": "cluster", "review_required": True})
        if kind == "ServiceAccount" and _identity_annotation(obj):
            provider, reference = _identity_annotation(obj)
            edge(rid, f"external-identity/{namespace}/{name}", "assumes", obj)
        if kind == "NetworkPolicy":
            selector = (obj.get("spec") or {}).get("podSelector", {}) or {}
            selected = selector.get("matchLabels", {}) if isinstance(selector, dict) else {}
            for wk, wn, wname in resources:
                if wk in WORKLOADS and wn == namespace:
                    labels = _labels(resources[(wk, wn, wname)])
                    if not selected or _matches(selected, labels):
                        edge(rid, _id(wk, wn, wname), "applies_to", obj)

    for (kind, namespace, name), obj in resources.items():
        if kind == "Namespace":
            continue
        if kind not in SUPPORTED:
            continue
        if kind in WORKLOADS and not any(e["to"] == _id(kind, namespace, name)
                                         and e["relation"] == "applies_to" for e in edges):
            issues.append({"type": "coverage_gap", "reason": "workload_network_boundary_unresolved",
                           "resource": _id(kind, namespace, name), "review_required": True})
    workload_namespaces = {ns for (kind, ns, _), obj in resources.items() if kind in WORKLOADS}
    tenant_namespaces = [n for (k, _, n), obj in resources.items() if k == "Namespace"
                         and n in workload_namespaces
                         and n not in {"default", "kube-system", "platform-system"}]
    for namespace in tenant_namespaces:
        has_quota = any(k == "ResourceQuota" and ns == namespace for k, ns, _ in resources)
        has_limits = any(k == "LimitRange" and ns == namespace for k, ns, _ in resources)
        if not (has_quota and has_limits):
            issues.append({"type": "design_derived", "reason": "tenant_resource_governance_unset",
                           "resource": f"namespace/{namespace}", "review_required": True})

    crd_issues: dict[str, dict[str, Any]] = {}
    unsupported_issues: dict[str, dict[str, Any]] = {}
    compact_issues: list[dict[str, Any]] = []
    for issue in issues:
        if issue.get("reason") == "unsupported_kind":
            key = str(issue.get("kind", "unknown"))
            grouped = unsupported_issues.setdefault(key, {
                "type": "coverage_gap", "reason": "unsupported_kind", "kind": key,
                "resources": [], "review_required": True,
            })
            grouped["resources"].append(issue.get("resource"))
            continue
        if issue.get("reason") != "crd_behavior_unknown":
            compact_issues.append(issue)
            continue
        key = issue.get("crd_ref", issue.get("resource"))
        grouped = crd_issues.setdefault(key, {"type": "coverage_gap", "reason": "crd_behavior_unknown",
                                               "crd_ref": key, "resources": [], "review_required": True})
        grouped["resources"].append(issue.get("resource"))
    issues = compact_issues + list(crd_issues.values()) + list(unsupported_issues.values())
    if parse_notes:
        issues.append({"type": "coverage_gap", "reason": "unrendered_or_invalid_yaml_sources",
                       "files": parse_notes, "review_required": True})
    threats: list[dict[str, Any]] = []
    threat_paths: dict[str, dict[str, Any]] = {}
    for index, issue in enumerate(issues, start=1):
        reason = issue.get("reason")
        resource = issue.get("resource")
        if reason == "cluster_wide_binding":
            threat_id = f"K8S-T-RBAC-{index:03d}"
            scenario = "A tenant workload identity reaches a cluster-wide binding and can affect resources outside its Namespace."
        elif reason == "workload_network_boundary_unresolved":
            threat_id = f"K8S-T-NETWORK-{index:03d}"
            scenario = "A workload has no resolved NetworkPolicy boundary, so cross-tenant traffic may be reachable."
        elif reason == "tenant_resource_governance_unset":
            threat_id = f"K8S-T-RESOURCE-{index:03d}"
            scenario = "A tenant Namespace lacks complete quota and limit governance, allowing resource exhaustion to spread to other tenants."
        elif reason == "operator_behavior_unknown":
            threat_id = f"K8S-T-OPERATOR-{index:03d}"
            scenario = "An Operator's reconciliation behavior is not established, so its effective cross-Namespace impact remains unknown."
        else:
            continue
        threats.append({"id": threat_id, "category": "KUBERNETES-DESIGN",
                        "novelty": "graph_derived", "scenario": scenario,
                        "affected_assets": [resource], "related_controls": [],
                        "source_issue": reason})
        source = resource if resource in nodes else None
        threat_paths[threat_id] = {
            "sources": [source] if source else [],
            "basis": [f"graph-issue:{reason}"],
            "condition": scenario,
            "validation_status": "unreviewed",
            "required_checks": ["review_graph_derived_threat", "confirm_boundary"],
        }
    return {"version": "1", "generated_by": "kubernetes_graph.py", "platform": "kubernetes",
            "review_required": bool(issues), "nodes": list(nodes.values()), "edges": edges,
            "issues": issues, "threats": threats, "threat_paths": threat_paths,
            "resources_seen": len(docs),
            "source_digest": _source_digest(path)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    if not args.input.exists():
        parser.error(f"--input {args.input} does not exist")
    result = build(args.input)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(yaml.safe_dump(result, sort_keys=False, allow_unicode=True), encoding="utf-8")
    print(f"wrote {args.out} ({len(result['nodes'])} nodes, {len(result['edges'])} edges, {len(result['issues'])} review items)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
