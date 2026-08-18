from pathlib import Path
import sys

import yaml

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
import kubernetes_graph
import blast_radius


ROOT = Path(__file__).parents[1]


def test_insecure_fixture_emits_cluster_binding_and_review_items():
    result = kubernetes_graph.build(ROOT / "tests" / "fixtures" / "k8s-saas-insecure")
    assert result["platform"] == "kubernetes"
    assert any(item["reason"] == "cluster_wide_binding" for item in result["issues"])
    assert any(node["id"] == "deployment/tenant-a/tenant-api" for node in result["nodes"])
    assert any(edge["relation"] == "uses" for edge in result["edges"])
    assert any(edge["relation"] == "assumes" for edge in result["edges"])
    assert any(node["kind"] == "ExternalIdentity" for node in result["nodes"])
    assert result["threats"]
    derived = blast_radius.derive({"threats": result["threats"]}, result)
    assert any(row["coarse_scope"] == "platform" for row in derived["results"])


def test_hardened_fixture_uses_namespaced_role_and_policy():
    result = kubernetes_graph.build(ROOT / "tests" / "fixtures" / "k8s-saas-hardened")
    assert not any(item["reason"] == "cluster_wide_binding" for item in result["issues"])
    assert any(edge["relation"] == "binds" and "role/tenant-a" in edge["to"]
               for edge in result["edges"])
    assert any(node["kind"] == "NetworkPolicy" for node in result["nodes"])
    assert result["threats"] == []
    assert not result["issues"]


def test_crd_is_opaque_but_visible(tmp_path):
    manifest = tmp_path / "crd.yaml"
    manifest.write_text("""apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: tenantpolicies.example.io
spec:
  group: example.io
  names:
    kind: TenantPolicy
    plural: tenantpolicies
  scope: Namespaced
  versions:
    - name: v1
      served: true
      storage: true
""", encoding="utf-8")
    result = kubernetes_graph.build(manifest)
    assert any(node["kind"] == "CustomResourceDefinition" for node in result["nodes"])
    assert any(item["reason"] == "crd_behavior_unknown" for item in result["issues"])


def test_operator_workload_is_reviewed_as_opaque_behavior(tmp_path):
    manifest = tmp_path / "operator.yaml"
    manifest.write_text("""apiVersion: v1
kind: Namespace
metadata:
  name: platform-system
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: tenant-operator
  namespace: platform-system
  labels:
    app.kubernetes.io/component: controller
spec:
  selector:
    matchLabels:
      app: tenant-operator
  template:
    metadata:
      labels:
        app: tenant-operator
    spec:
      containers:
        - name: controller
          image: example/operator:1.0.0
""", encoding="utf-8")
    result = kubernetes_graph.build(manifest)
    assert any(item["reason"] == "operator_behavior_unknown" for item in result["issues"])


def test_cli_output_is_yaml(tmp_path):
    output = tmp_path / "graph.yaml"
    assert kubernetes_graph.main([
        "--input", str(ROOT / "tests" / "fixtures" / "k8s-saas-insecure"),
        "--out", str(output),
    ]) == 0
    loaded = yaml.safe_load(output.read_text(encoding="utf-8"))
    assert loaded["resources_seen"] > 0
