from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
import kubernetes_graph


def test_container_level_run_as_non_root_is_accepted(tmp_path):
    manifest = tmp_path / "deployment.yaml"
    manifest.write_text("""apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  selector:
    matchLabels: {app: app}
  template:
    metadata:
      labels: {app: app}
    spec:
      containers:
        - name: app
          image: example/app:1.0
          securityContext:
            runAsNonRoot: true
            allowPrivilegeEscalation: false
""", encoding="utf-8")
    result = kubernetes_graph.build(manifest)
    assert not any(i.get("reason") == "workload_non_root_unset" for i in result["issues"])


def test_aggregated_api_service_tls_setting_is_visible(tmp_path):
    manifest = tmp_path / "apiservice.yaml"
    manifest.write_text("""apiVersion: apiregistration.k8s.io/v1
kind: APIService
metadata:
  name: v1beta1.metrics.example.io
spec:
  service:
    name: metrics
    namespace: kube-system
  insecureSkipTLSVerify: true
""", encoding="utf-8")
    result = kubernetes_graph.build(manifest)
    assert any(i.get("reason") == "aggregated_api_tls_unverified" for i in result["issues"])


def test_kustomize_patch_does_not_replace_base_workload(tmp_path):
    base = tmp_path / "base.yaml"
    patch = tmp_path / "components" / "patch.yaml"
    patch.parent.mkdir()
    base.write_text("""apiVersion: apps/v1
kind: Deployment
metadata: {name: app, namespace: default}
spec:
  selector: {matchLabels: {app: app}}
  template:
    metadata: {labels: {app: app}}
    spec:
      containers:
        - name: app
          image: example/app:1.0
          securityContext: {runAsNonRoot: true, allowPrivilegeEscalation: false}
""", encoding="utf-8")
    patch.write_text("""apiVersion: apps/v1
kind: Deployment
metadata: {name: app, namespace: default}
spec:
  template:
    spec:
      containers:
        - name: app
          args: [--debug]
""", encoding="utf-8")
    result = kubernetes_graph.build(tmp_path)
    assert not any(i.get("reason") == "workload_non_root_unset" for i in result["issues"])


def test_yaml_value_tags_fall_back_to_structure_loader(tmp_path):
    manifest = tmp_path / "secret.yaml"
    manifest.write_text("""apiVersion: v1
kind: Secret
metadata:
  name: example
type: Opaque
data:
  token: !!value =
""", encoding="utf-8")
    result = kubernetes_graph.build(manifest)
    assert any(node["kind"] == "Secret" for node in result["nodes"])
    assert any("parsed_with_safe_structure_loader" in str(note)
               for issue in result["issues"] for note in issue.get("files", []))


def test_crd_instances_are_grouped_as_opaque_custom_resources(tmp_path):
    manifest = tmp_path / "custom-resources.yaml"
    manifest.write_text("""apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: widgets.example.io
spec:
  group: example.io
  names:
    kind: Widget
    plural: widgets
  scope: Namespaced
  versions:
    - name: v1
      served: true
      storage: true
---
apiVersion: example.io/v1
kind: Widget
metadata:
  name: one
  namespace: tenant-a
spec: {}
""", encoding="utf-8")
    result = kubernetes_graph.build(manifest)
    assert any(node.get("kind") == "CustomResource" and node.get("custom_kind") == "Widget"
               for node in result["nodes"])


def test_binary_named_yaml_files_are_skipped_without_aborting_scan(tmp_path):
    valid = tmp_path / "deployment.yaml"
    valid.write_text("""apiVersion: apps/v1
kind: Deployment
metadata: {name: app}
spec: {template: {spec: {containers: [{name: app, image: example/app:1.0}]}}}
""", encoding="utf-8")
    (tmp_path / "generated.yaml").write_bytes(b"\xff\xfe\x00\x01")
    result = kubernetes_graph.build(tmp_path)
    assert any(node.get("kind") == "Deployment" for node in result["nodes"])
    assert any("UnicodeDecodeError" in str(note)
               for issue in result["issues"] for note in issue.get("files", []))


def test_malformed_container_mapping_does_not_abort_repository_scan(tmp_path):
    manifest = tmp_path / "deployment.yaml"
    manifest.write_text("""apiVersion: apps/v1
kind: Deployment
metadata: {name: malformed}
spec: {template: {spec: {containers: {app: example/app:1.0}}}}
""", encoding="utf-8")
    result = kubernetes_graph.build(tmp_path)
    assert any(node.get("kind") == "Deployment" for node in result["nodes"])
    assert any(i.get("reason") == "malformed_manifest_field"
               and i.get("field") == "spec.template.spec.containers"
               for i in result["issues"])


def test_unsupported_kinds_are_grouped_for_large_repositories(tmp_path):
    manifest = tmp_path / "resources.yaml"
    manifest.write_text("""apiVersion: example.io/v1
kind: Widget
metadata: {name: one}
---
apiVersion: example.io/v1
kind: Widget
metadata: {name: two}
""", encoding="utf-8")
    result = kubernetes_graph.build(tmp_path)
    unsupported = [i for i in result["issues"] if i.get("reason") == "unsupported_kind"]
    assert len(unsupported) == 1
    assert unsupported[0]["resources"] == ["widget/default/one", "widget/default/two"]


def test_null_spec_does_not_abort_network_policy_scan(tmp_path):
    manifest = tmp_path / "network-policy.yaml"
    manifest.write_text("""apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: empty}
spec: null
""", encoding="utf-8")
    result = kubernetes_graph.build(tmp_path)
    assert any(node.get("kind") == "NetworkPolicy" for node in result["nodes"])


def test_non_string_kind_does_not_abort_repository_scan(tmp_path):
    manifest = tmp_path / "malformed.yaml"
    manifest.write_text("""apiVersion: v1
kind: [Deployment]
metadata: {name: malformed}
""", encoding="utf-8")
    result = kubernetes_graph.build(tmp_path)
    assert any(i.get("reason") == "malformed_manifest_kind" for i in result["issues"])


def test_null_metadata_does_not_abort_repository_scan(tmp_path):
    manifest = tmp_path / "null-metadata.yaml"
    manifest.write_text("""apiVersion: v1
kind: ConfigMap
metadata: null
data: {mode: test}
""", encoding="utf-8")
    result = kubernetes_graph.build(tmp_path)
    assert any(node.get("kind") == "ConfigMap" for node in result["nodes"])
