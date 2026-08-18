from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
import kubernetes_supply_chain


ROOT = Path(__file__).parents[1]


def test_supply_chain_flags_mutable_image():
    result = kubernetes_supply_chain.analyze(ROOT / "tests" / "fixtures" / "k8s-saas-insecure")
    assert any(item["reason"] == "mutable_or_unpinned_image" for item in result["findings"])
