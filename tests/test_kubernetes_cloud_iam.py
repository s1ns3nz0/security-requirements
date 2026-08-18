from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
import kubernetes_cloud_iam
import kubernetes_graph


ROOT = Path(__file__).parents[1]


def test_cloud_iam_wildcard_is_high_risk():
    graph = kubernetes_graph.build(ROOT / "tests" / "fixtures" / "k8s-saas-insecure")
    result = kubernetes_cloud_iam.analyze(graph, {
        "arn:aws:iam::111111111111:role/tenant-platform-admin": {
            "Statement": {"Action": "*", "Resource": "*"}
        }
    })
    assert result["review_required"] is True
    assert result["findings"][0]["severity"] == "high"
