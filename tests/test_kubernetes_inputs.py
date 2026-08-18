from pathlib import Path
import argparse
import sys

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
import kubernetes_inputs


ROOT = Path(__file__).parents[1]


def test_manifest_input_records_provenance():
    args = argparse.Namespace(
        input=ROOT / "tests" / "fixtures" / "k8s-saas-hardened",
        helm_chart=None, kustomize_dir=None, terraform_plan=None,
        release_name="review", values=[],
    )
    result = kubernetes_inputs.build(args)
    assert result["input_provenance"]["mode"] == "manifest"


def test_terraform_plan_resources_are_normalized(tmp_path):
    plan = tmp_path / "plan.json"
    plan.write_text("""{"planned_values":{"root_module":{"resources":[{"type":"kubernetes_manifest","values":{"manifest":{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"tenant-a"}}}}]}}}""", encoding="utf-8")
    args = argparse.Namespace(
        input=None, helm_chart=None, kustomize_dir=None, terraform_plan=plan,
        release_name="review", values=[],
    )
    result = kubernetes_inputs.build(args)
    assert result["input_provenance"]["mode"] == "terraform_plan"
    assert any(node["kind"] == "Namespace" for node in result["nodes"])
