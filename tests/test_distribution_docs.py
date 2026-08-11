import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


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

    for workflow in ("init", "build", "refresh"):
        assert f"/security-requirements:sec-req-{workflow}" in readme
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
        "/plugin marketplace update security-requirements",
        "claude plugin uninstall security-requirements@security-requirements --keep-data",
        f"codex plugin remove {QUALIFIED_PLUGIN_NAME}",
        "codex plugin marketplace remove security-requirements",
        "git pull --ff-only",
    ):
        assert command in text

    for requirement in ("Python 3", "PyYAML", "`gh`", "fallback", "external"):
        assert requirement in text

    assert "python3 scripts/validate_distribution.py ." in text
    assert "python3 -m pytest tests/test_distribution_docs.py -q" in text
    claude_update = text[
        text.index("Claude Code uses the manifest version"):text.index("### Runtime requirements")
    ]
    ordered = (
        "/plugin marketplace update security-requirements",
        "claude plugin uninstall security-requirements@security-requirements --keep-data",
        "/plugin install security-requirements@security-requirements",
    )
    assert [claude_update.index(command) for command in ordered] == sorted(
        claude_update.index(command) for command in ordered
    )
    assert "/plugin marketplace add ." not in claude_update


def test_distribution_validator_accepts_the_repository_and_is_read_only(tmp_path):
    assert VALIDATOR.is_file(), "distribution validator must exist"
    module = _load_validator()
    marketplace = json.loads(
        (REPO_ROOT / ".agents" / "plugins" / "marketplace.json").read_text(encoding="utf-8")
    )
    assert marketplace["name"] == PLUGIN_NAME

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


@pytest.mark.parametrize(
    "invocation",
    (
        "python scripts/lint.py requirements.yaml",
        "python3 scripts/lint.py requirements.yaml",
        "python -I scripts/lint.py requirements.yaml",
        "python3 -u -B scripts/lint.py requirements.yaml",
        "python3 -X utf8 scripts/lint.py requirements.yaml",
    ),
)
def test_distribution_validator_rejects_cwd_relative_payload_script_invocations(
    tmp_path, invocation
):
    module = _load_validator()
    clone = tmp_path / "clone"
    shutil.copytree(REPO_ROOT, clone, ignore=shutil.ignore_patterns(".git", ".pytest_cache", "__pycache__"))
    stale_example = clone / "plugins" / PLUGIN_NAME / "skills" / "stale-example.md"
    stale_example.write_text(f"{invocation}\n", encoding="utf-8")

    errors = module.validate(clone)
    assert any(
        "cwd-relative payload script invocation" in error
        and "skills/stale-example.md:1" in error
        for error in errors
    )


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

    codex_marketplace = clone / ".agents" / "plugins" / "marketplace.json"
    data = json.loads(codex_marketplace.read_text(encoding="utf-8"))
    data["name"] = "wrong-marketplace"
    codex_marketplace.write_text(json.dumps(data), encoding="utf-8")

    duplicate = clone / "plugins" / "duplicate" / "scripts"
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
        "Codex marketplace name",
        "missing-skills",
        "duplicate runtime directory: scripts",
        "symlink",
    ):
        assert expected in result.stderr


@pytest.mark.parametrize("value", ("../outside", "./../outside", "skills/", "/absolute"))
def test_distribution_validator_rejects_noncanonical_manifest_paths(tmp_path, value):
    module = _load_validator()
    clone = tmp_path / "clone"
    shutil.copytree(REPO_ROOT, clone, ignore=shutil.ignore_patterns(".git", ".pytest_cache", "__pycache__"))
    manifest_path = clone / "plugins" / PLUGIN_NAME / ".codex-plugin" / "plugin.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["skills"] = value
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    errors = module.validate(clone)
    assert any("Codex manifest.skills" in error for error in errors)


def test_distribution_validator_checks_nested_path_valued_manifest_fields(tmp_path):
    module = _load_validator()
    clone = tmp_path / "clone"
    shutil.copytree(REPO_ROOT, clone, ignore=shutil.ignore_patterns(".git", ".pytest_cache", "__pycache__"))
    manifest_path = clone / "plugins" / PLUGIN_NAME / ".codex-plugin" / "plugin.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["interface"]["assetPath"] = "./missing-asset"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    assert any("Codex manifest.interface.assetPath" in error for error in module.validate(clone))


@pytest.mark.parametrize(
    "field,value",
    (
        ("agents", "../outside"),
        ("outputStyles", ["./../outside"]),
        ("screenshots", ["/absolute.png"]),
        ("mcpServers", "servers.json"),
    ),
)
def test_distribution_validator_checks_supported_path_fields(tmp_path, field, value):
    module = _load_validator()
    clone = tmp_path / "clone"
    shutil.copytree(REPO_ROOT, clone, ignore=shutil.ignore_patterns(".git", ".pytest_cache", "__pycache__"))
    manifest_path = clone / "plugins" / PLUGIN_NAME / ".claude-plugin" / "plugin.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest[field] = value
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    assert any(f"Claude manifest.{field}" in error for error in module.validate(clone))


def test_distribution_validator_preserves_path_field_context_in_nested_lists(tmp_path):
    module = _load_validator()
    clone = tmp_path / "clone"
    shutil.copytree(REPO_ROOT, clone, ignore=shutil.ignore_patterns(".git", ".pytest_cache", "__pycache__"))
    manifest_path = clone / "plugins" / PLUGIN_NAME / ".claude-plugin" / "plugin.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["outputStyles"] = {"dark": ["../outside"]}
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    assert any(
        "Claude manifest.outputStyles.dark[0]" in error for error in module.validate(clone)
    )


def test_distribution_validator_rejects_malformed_path_field_values(tmp_path):
    module = _load_validator()
    clone = tmp_path / "clone"
    shutil.copytree(REPO_ROOT, clone, ignore=shutil.ignore_patterns(".git", ".pytest_cache", "__pycache__"))
    manifest_path = clone / "plugins" / PLUGIN_NAME / ".claude-plugin" / "plugin.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["agents"] = 42
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    assert any("Claude manifest.agents must contain path strings" in error for error in module.validate(clone))


@pytest.mark.parametrize(
    "field,value",
    (
        ("mcpServers", {"example": {"command": "npx", "args": ["-y", "server"]}}),
        ("hooks", {"PreToolUse": [{"matcher": "Bash", "hooks": [{"command": "npx"}]}]}),
        ("lspServers", {"example": {"command": "npx", "env": {"MODE": "test"}}}),
    ),
)
def test_distribution_validator_accepts_inline_component_objects(tmp_path, field, value):
    module = _load_validator()
    clone = tmp_path / "clone"
    shutil.copytree(REPO_ROOT, clone, ignore=shutil.ignore_patterns(".git", ".pytest_cache", "__pycache__"))
    manifest_path = clone / "plugins" / PLUGIN_NAME / ".claude-plugin" / "plugin.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest[field] = value
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    assert module.validate(clone) == []


@pytest.mark.parametrize("value", ("./../outside", "./missing-mcp-config.json"))
def test_distribution_validator_validates_string_component_paths(tmp_path, value):
    module = _load_validator()
    clone = tmp_path / "clone"
    shutil.copytree(REPO_ROOT, clone, ignore=shutil.ignore_patterns(".git", ".pytest_cache", "__pycache__"))
    manifest_path = clone / "plugins" / PLUGIN_NAME / ".claude-plugin" / "plugin.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["mcpServers"] = value
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    assert any("Claude manifest.mcpServers" in error for error in module.validate(clone))


@pytest.mark.parametrize("component", ("mcpServers", "apps", "hooks"))
def test_distribution_validator_rejects_unsupported_codex_components(tmp_path, component):
    module = _load_validator()
    clone = tmp_path / "clone"
    shutil.copytree(REPO_ROOT, clone, ignore=shutil.ignore_patterns(".git", ".pytest_cache", "__pycache__"))
    manifest_path = clone / "plugins" / PLUGIN_NAME / ".codex-plugin" / "plugin.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest[component] = {}
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    assert f"Codex manifest must not declare {component}" in module.validate(clone)


@pytest.mark.parametrize("component", ("hooks", "apps", ".mcp.json", ".app.json"))
def test_distribution_validator_rejects_unsupported_codex_payload_components(tmp_path, component):
    module = _load_validator()
    clone = tmp_path / "clone"
    shutil.copytree(REPO_ROOT, clone, ignore=shutil.ignore_patterns(".git", ".pytest_cache", "__pycache__"))
    component_path = clone / "plugins" / PLUGIN_NAME / component
    if component.startswith("."):
        component_path.write_text("{}", encoding="utf-8")
    else:
        component_path.mkdir()

    assert any(component in error for error in module.validate(clone))


def test_distribution_validator_rejects_metadata_symlinks_and_aggregates_parser_errors(tmp_path):
    module = _load_validator()
    clone = tmp_path / "clone"
    shutil.copytree(REPO_ROOT, clone, ignore=shutil.ignore_patterns(".git", ".pytest_cache", "__pycache__"))

    claude_marketplace = clone / ".claude-plugin" / "marketplace.json"
    claude_marketplace.unlink()
    claude_marketplace.symlink_to(clone / ".agents" / "plugins" / "marketplace.json")

    claude_manifest = clone / "plugins" / PLUGIN_NAME / ".claude-plugin" / "plugin.json"
    claude_manifest.unlink()
    claude_manifest.mkdir()

    codex_manifest = clone / "plugins" / PLUGIN_NAME / ".codex-plugin" / "plugin.json"
    codex_manifest.write_bytes(b"\x80")

    codex_marketplace = clone / ".agents" / "plugins" / "marketplace.json"
    codex_marketplace.write_text("[]", encoding="utf-8")

    errors = module.validate(clone)
    for expected in (
        "symlink is not allowed in distribution metadata",
        "cannot read JSON file",
        "cannot decode JSON file",
        "JSON object required",
    ):
        assert any(expected in error for error in errors), errors


@pytest.mark.parametrize("directory", ("scripts", "catalogs", "overlays", "responsibility", "skills"))
def test_distribution_validator_rejects_runtime_copies_outside_the_payload(tmp_path, directory):
    module = _load_validator()
    clone = tmp_path / "clone"
    shutil.copytree(REPO_ROOT, clone, ignore=shutil.ignore_patterns(".git", ".pytest_cache", "__pycache__"))
    if directory == "scripts":
        (clone / directory / "runtime_paths.py").write_text("", encoding="utf-8")
    else:
        (clone / directory).mkdir()
    extra = clone / "plugins" / "other-payload" / directory
    extra.mkdir(parents=True)

    errors = module.validate(clone)
    assert any(f"top-level runtime directory: {directory}" in error for error in errors)
    assert any(f"duplicate runtime directory: {directory}" in error for error in errors)
