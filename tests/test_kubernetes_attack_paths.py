from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
import kubernetes_attack_paths
import kubernetes_graph


ROOT = Path(__file__).parents[1]


def test_attack_path_reaches_kubernetes_api_from_insecure_workload():
    graph = kubernetes_graph.build(ROOT / "tests" / "fixtures" / "k8s-saas-insecure")
    result = kubernetes_attack_paths.analyze(graph)
    assert any(path["target"] == "kubernetes-api/cluster" for path in result["paths"])
    assert result["review_required"] is True
