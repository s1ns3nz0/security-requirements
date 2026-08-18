from pathlib import Path
import json
import sys

import yaml

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
import kubernetes_graph
import kubernetes_runtime_snapshot


ROOT = Path(__file__).parents[1]


def test_snapshot_compare_detects_unmanaged_runtime_resource(tmp_path):
    design = kubernetes_graph.build(ROOT / "tests" / "fixtures" / "k8s-saas-hardened")
    snapshot = {"items": [{"apiVersion": "v1", "kind": "Namespace",
                           "metadata": {"name": "tenant-a"}},
                          {"apiVersion": "v1", "kind": "Namespace",
                           "metadata": {"name": "runtime-only"}}]}
    result = kubernetes_runtime_snapshot.compare(
        design, kubernetes_runtime_snapshot._snapshot_graph(snapshot))
    assert any(item["status"] == "unmanaged_runtime" for item in result["changes"])
    assert result["review_required"] is True


def test_snapshot_output_does_not_include_secret_values(tmp_path):
    design = kubernetes_graph.build(ROOT / "tests" / "fixtures" / "k8s-saas-hardened")
    snapshot = {"items": [{"apiVersion": "v1", "kind": "Secret",
                           "metadata": {"name": "tenant-db", "namespace": "tenant-a"},
                           "data": {"password": "super-secret-value"}}]}
    result = kubernetes_runtime_snapshot.compare(
        design, kubernetes_runtime_snapshot._snapshot_graph(snapshot))
    assert "super-secret-value" not in json.dumps(result)
