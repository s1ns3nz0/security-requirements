from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
import blast_radius
import kubernetes_detection
import kubernetes_graph
import kubernetes_requirements


ROOT = Path(__file__).parents[1]


def test_detection_candidates_link_to_requirements():
    graph = kubernetes_graph.build(ROOT / "tests" / "fixtures" / "k8s-saas-insecure")
    radius = blast_radius.derive({"threats": graph["threats"]}, graph)
    requirements = kubernetes_requirements.derive(graph, radius)
    result = kubernetes_detection.derive(requirements)
    assert result["detections"]
    assert all(item["requirement_refs"] for item in result["detections"])
