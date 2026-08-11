import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
PLUGIN_NAME = "security-requirements"
QUALIFIED_PLUGIN_NAME = f"{PLUGIN_NAME}@{PLUGIN_NAME}"
VALIDATOR = REPO_ROOT / "scripts" / "validate_distribution.py"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _load_validator():
    spec = importlib.util.spec_from_file_location("validate_distribution", VALIDATOR)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_clean_clone_documentation_covers_claude_and_codex_installation():
    readme = _read(REPO_ROOT / "README.md")

    for heading in ("### Claude Code", "### Codex"):
        assert heading in readme

    for command in (
        "/plugin marketplace add s1ns3nz0/security-requirements",
        f"/plugin install {QUALIFIED_PLUGIN_NAME}",
        "codex plugin marketplace add .",
        f"codex plugin add {QUALIFIED_PLUGIN_NAME}",
        "codex plugin list --marketplace security-requirements",
    ):
        assert command in readme

    assert "/sec-req-init" in readme
    assert "/sec-req-build" in readme
    assert "/sec-req-refresh" in readme
    for prompt in (
        "Initialize the security requirements profile",
        "Build security requirements from the confirmed profile",
        "Refresh security requirements after service changes",
    ):
        assert prompt in readme


def test_clean_clone_documentation_covers_updates_dependencies_and_state():
    text = "\n".join(
        _read(path) for path in (REPO_ROOT / "README.md", REPO_ROOT / "CONTRIBUTING.md")
    )

    for command in (
        "/plugin update security-requirements",
        "/plugin uninstall security-requirements",
        f"codex plugin remove {QUALIFIED_PLUGIN_NAME}",
        "codex plugin marketplace remove security-requirements",
        "git pull --ff-only",
    ):
        assert command in text

    for requirement in ("Python 3", "PyYAML", "`gh`", "fallback", "external"):
        assert requirement in text

    assert "python3 scripts/validate_distribution.py ." in text
    assert "python3 -m pytest tests/test_distribution_docs.py -q" in text


def test_distribution_validator_accepts_the_repository_and_is_read_only(tmp_path):
    assert VALIDATOR.is_file(), "distribution validator must exist"
    module = _load_validator()

    before = {
        path.relative_to(REPO_ROOT): path.stat().st_mtime_ns
        for path in (
            REPO_ROOT / ".claude-plugin" / "marketplace.json",
            REPO_ROOT / ".agents" / "plugins" / "marketplace.json",
            REPO_ROOT / "plugins" / PLUGIN_NAME / ".claude-plugin" / "plugin.json",
            REPO_ROOT / "plugins" / PLUGIN_NAME / ".codex-plugin" / "plugin.json",
        )
    }
    assert module.validate(REPO_ROOT) == []
    after = {path: (REPO_ROOT / path).stat().st_mtime_ns for path in before}
    assert after == before

    result = subprocess.run(
        [sys.executable, str(VALIDATOR), str(REPO_ROOT)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""


def test_distribution_validator_reports_all_fixture_errors(tmp_path):
    assert VALIDATOR.is_file(), "distribution validator must exist"
    clone = tmp_path / "clone"
    shutil.copytree(REPO_ROOT, clone, ignore=shutil.ignore_patterns(".git", ".pytest_cache", "__pycache__"))

    claude_marketplace = clone / ".claude-plugin" / "marketplace.json"
    data = json.loads(claude_marketplace.read_text(encoding="utf-8"))
    data["plugins"][0]["source"] = "./wrong-payload"
    claude_marketplace.write_text(json.dumps(data), encoding="utf-8")

    codex_manifest = clone / "plugins" / PLUGIN_NAME / ".codex-plugin" / "plugin.json"
    data = json.loads(codex_manifest.read_text(encoding="utf-8"))
    data["name"] = "wrong-name"
    data["skills"] = "./missing-skills/"
    codex_manifest.write_text(json.dumps(data), encoding="utf-8")

    duplicate = clone / "duplicate" / "scripts"
    duplicate.mkdir(parents=True)
    (duplicate / "runtime_paths.py").write_text("", encoding="utf-8")
    (clone / "plugins" / PLUGIN_NAME / "catalogs-link").symlink_to(
        clone / "plugins" / PLUGIN_NAME / "catalogs"
    )

    result = subprocess.run(
        [sys.executable, str(VALIDATOR), str(clone)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    for expected in (
        "Claude marketplace",
        "Codex manifest name",
        "missing-skills",
        "duplicate runtime directory: scripts",
        "symlink",
    ):
        assert expected in result.stderr
