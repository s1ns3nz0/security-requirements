from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
import kubernetes_graph
import kubernetes_requirements
import blast_radius


ROOT = Path(__file__).parents[1]


def test_requirements_preserve_design_and_reference_layers():
    graph = kubernetes_graph.build(ROOT / "tests" / "fixtures" / "k8s-saas-insecure")
    radius = blast_radius.derive({"threats": graph["threats"]}, graph)
    result = kubernetes_requirements.derive(graph, radius)
    assert result["summary"]["design_derived"] >= 1
    assert result["summary"]["benchmark_check"] >= 1
    assert result["ci_decision"]["decision"] == "fail"
    assert result["summary"]["benchmark_check"] >= 1
    first = result["requirements"][0]
    assert first["classification"] == "design_derived"
    assert first["related_references"]
    assert first["verification"]


def test_unsupported_resource_becomes_coverage_gap(tmp_path):
    manifest = tmp_path / "custom.yaml"
    manifest.write_text("apiVersion: example.io/v1\nkind: TenantPolicy\nmetadata:\n  name: policy\n", encoding="utf-8")
    graph = kubernetes_graph.build(manifest)
    result = kubernetes_requirements.derive(graph)
    assert result["summary"]["coverage_gap"] == 1


def test_external_analyzer_finding_becomes_traceable_requirement():
    result = kubernetes_requirements.derive({}, external_findings=[{
        "type": "design_derived", "severity": "high", "reason": "wildcard cloud IAM scope"
    }])
    assert result["requirements"][0]["source"]["type"] == "external_analyzer"
