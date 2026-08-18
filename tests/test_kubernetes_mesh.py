from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
import kubernetes_mesh


def test_mesh_and_operator_extension_flags_weak_mtls(tmp_path):
    manifest = tmp_path / "mesh.yaml"
    manifest.write_text("""apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: tenant-a
spec:
  mtls:
    mode: PERMISSIVE
""", encoding="utf-8")
    result = kubernetes_mesh.analyze(manifest)
    assert any(item["reason"] == "service_mesh_mtls_not_strict" for item in result["findings"])
