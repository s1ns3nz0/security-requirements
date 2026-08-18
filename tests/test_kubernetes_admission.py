from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
import kubernetes_graph


def test_admission_webhook_is_control_plane_review_item(tmp_path):
    manifest = tmp_path / "admission.yaml"
    manifest.write_text("""apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: tenant-policy
webhooks:
  - name: policy.example.io
    clientConfig:
      service:
        name: policy-webhook
        namespace: platform-system
""", encoding="utf-8")
    result = kubernetes_graph.build(manifest)
    node = next(n for n in result["nodes"] if n["kind"] == "ValidatingWebhookConfiguration")
    assert node["control_scope"] == "control_plane"
    assert any(i["reason"] == "admission_webhook_present" for i in result["issues"])
