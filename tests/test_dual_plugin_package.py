import json
import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
PLUGIN_ROOT = REPO_ROOT / "plugins" / "security-requirements"
RUNTIME_DIRECTORIES = ("scripts", "catalogs", "overlays", "responsibility")
SHARED_DERIVATION_SKILL = Path("skills") / "deriving-security-requirements"
CODEX_ENTRY_SKILLS = {
    workflow: PLUGIN_ROOT
    / "skills"
    / f"security-requirements-{workflow}"
    / "SKILL.md"
    for workflow in ("init", "build", "refresh")
}

CODEX_ROOT_INITIALIZATION = '''SECURITY_REQUIREMENTS_SKILL_PATH="<absolute path of this selected SKILL.md>"
SECURITY_REQUIREMENTS_ROOT="$(
  python3 -c 'from pathlib import Path; import sys; path=Path(sys.argv[1]).expanduser(); path.is_absolute() or sys.exit("selected SKILL.md path must be absolute"); print(path.resolve().parent.parent.parent)' \\
    "${SECURITY_REQUIREMENTS_SKILL_PATH}"
)" || exit
export SECURITY_REQUIREMENTS_ROOT'''

STATE_INITIALIZATION = """if [ -z "${SECURITY_REQUIREMENTS_DATA:-}" ]; then
  SECURITY_REQUIREMENTS_DATA="$(
    python3 "${SECURITY_REQUIREMENTS_ROOT}/scripts/runtime_paths.py"
  )" || exit
  export SECURITY_REQUIREMENTS_DATA
fi"""

PAYLOAD_VALIDATION = '''test -f "${SECURITY_REQUIREMENTS_ROOT}/scripts/runtime_paths.py" || exit
test -f "${SECURITY_REQUIREMENTS_ROOT}/scripts/select_baseline.py" || exit
test -d "${SECURITY_REQUIREMENTS_ROOT}/catalogs" || exit'''


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_both_marketplaces_resolve_to_the_single_payload():
    claude = read_json(REPO_ROOT / ".claude-plugin" / "marketplace.json")
    codex = read_json(REPO_ROOT / ".agents" / "plugins" / "marketplace.json")
    assert claude["plugins"][0]["source"] == "./plugins/security-requirements"
    assert codex["plugins"][0]["source"] == {
        "source": "local",
        "path": "./plugins/security-requirements",
    }
    assert PLUGIN_ROOT.is_dir()


def test_payload_has_both_host_manifests_and_one_shared_implementation():
    claude = read_json(PLUGIN_ROOT / ".claude-plugin" / "plugin.json")
    codex = read_json(PLUGIN_ROOT / ".codex-plugin" / "plugin.json")
    assert claude["name"] == codex["name"] == PLUGIN_ROOT.name
    assert codex["skills"] == "./skills/"
    for relative in RUNTIME_DIRECTORIES:
        assert (PLUGIN_ROOT / relative).is_dir()
        if relative != "scripts":
            assert not (REPO_ROOT / relative).exists()
    assert (REPO_ROOT / "scripts" / "validate_distribution.py").is_file()


def test_runtime_payload_uses_no_symlinks_or_duplicate_directories():
    symlinks = [
        path.relative_to(PLUGIN_ROOT)
        for path in PLUGIN_ROOT.rglob("*")
        if path.is_symlink()
    ]
    assert symlinks == []

    for directory in RUNTIME_DIRECTORIES:
        locations = [
            path.relative_to(REPO_ROOT)
            for path in REPO_ROOT.rglob(directory)
            if path.is_dir()
        ]
        if directory == "scripts":
            locations.remove(Path("scripts"))
        assert locations == [Path("plugins") / PLUGIN_ROOT.name / directory]


def test_shared_derivation_skill_has_exactly_one_payload_copy():
    locations = [
        path.relative_to(REPO_ROOT)
        for path in REPO_ROOT.rglob(SHARED_DERIVATION_SKILL.name)
        if path.is_dir()
    ]
    assert locations == [
        Path("plugins") / PLUGIN_ROOT.name / SHARED_DERIVATION_SKILL
    ]


def test_codex_entry_skills_delegate_to_the_shared_workflows():
    names = []
    for workflow, path in CODEX_ENTRY_SKILLS.items():
        assert path.is_file()
        text = path.read_text(encoding="utf-8")
        expected_name = f"security-requirements-{workflow}"
        names.append(re.search(r"(?m)^name: ([a-z0-9-]+)$", text).group(1))

        assert f"name: {expected_name}" in text
        assert re.search(r"(?m)^description: Use when .+", text)
        assert (
            "${SECURITY_REQUIREMENTS_ROOT}/skills/"
            "deriving-security-requirements/SKILL.md"
        ) in text
        assert (
            f"${{SECURITY_REQUIREMENTS_ROOT}}/commands/sec-req-{workflow}.md"
        ) in text

    assert names == [
        f"security-requirements-{workflow}" for workflow in CODEX_ENTRY_SKILLS
    ]
    assert len(names) == len(set(names))


def test_codex_entry_skills_execute_payload_and_state_resolution():
    for path in CODEX_ENTRY_SKILLS.values():
        text = path.read_text(encoding="utf-8")
        assert CODEX_ROOT_INITIALIZATION in text
        assert PAYLOAD_VALIDATION in text
        assert STATE_INITIALIZATION in text
        assert "Do not derive either path from the current working directory" in text


def test_codex_entry_skills_preserve_confirmation_and_do_not_copy_pipeline():
    for path in CODEX_ENTRY_SKILLS.values():
        text = path.read_text(encoding="utf-8")
        assert "stop and wait" in text
        assert "explicit user confirmation" in text
        assert "--stamp" in text
        assert "--check" in text
        assert "Do not execute its Claude-only initialization block" in text
        script_references = re.findall(
            r"\$\{SECURITY_REQUIREMENTS_ROOT\}/scripts/([a-z_]+\.py)", text
        )
        assert script_references == [
            "runtime_paths.py",
            "select_baseline.py",
            "runtime_paths.py",
        ]


def test_payload_excludes_mcp_app_and_hook_components():
    codex = read_json(PLUGIN_ROOT / ".codex-plugin" / "plugin.json")
    for field in ("mcpServers", "apps", "hooks"):
        assert field not in codex
    for relative in (".mcp.json", ".app.json", "hooks", "apps"):
        assert not (PLUGIN_ROOT / relative).exists()


def test_codex_marketplace_declares_installation_policy():
    marketplace = read_json(REPO_ROOT / ".agents" / "plugins" / "marketplace.json")
    plugin = marketplace["plugins"][0]
    assert plugin["name"] == PLUGIN_ROOT.name
    assert plugin["policy"] == {
        "installation": "AVAILABLE",
        "authentication": "ON_INSTALL",
    }
    assert plugin["category"] == "Developer Tools"


def test_codex_manifest_declares_the_required_plugin_interface():
    claude = read_json(PLUGIN_ROOT / ".claude-plugin" / "plugin.json")
    codex = read_json(PLUGIN_ROOT / ".codex-plugin" / "plugin.json")
    for field in ("version", "author", "license", "homepage", "repository", "keywords"):
        assert codex[field] == claude[field]
    assert re.fullmatch(r"\d+\.\d+\.\d+", codex["version"])
    assert codex["interface"] == {
        "displayName": "Security Requirements",
        "shortDescription": "Derive verifiable security requirements for a service",
        "longDescription": (
            "Build and maintain a tailored security requirements contract from "
            "architecture or repository evidence, NIST, OWASP ASVS, cloud "
            "responsibility guidance, threat modeling, and applicable regulatory "
            "overlays."
        ),
        "developerName": "s1ns3nz0",
        "category": "Developer Tools",
        "capabilities": ["Interactive", "Read", "Write"],
        "defaultPrompt": [
            "Initialize the security requirements profile for this repository.",
            "Build security requirements from the confirmed profile.",
            "Refresh security requirements after service changes.",
        ],
    }
