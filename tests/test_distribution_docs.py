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
SAFE_PATHS = REPO_ROOT / "plugins" / PLUGIN_NAME / "scripts" / "safe_paths.py"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _load_validator():
    spec = importlib.util.spec_from_file_location("validate_distribution", VALIDATOR)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def _load_safe_paths():
    spec = importlib.util.spec_from_file_location(
        "safe_paths_for_distribution_test", SAFE_PATHS
    )
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def _distribution_clone(tmp_path: Path) -> Path:
    clone = tmp_path / "clone"
    shutil.copytree(
        REPO_ROOT,
        clone,
        ignore=shutil.ignore_patterns(".git", ".pytest_cache", "__pycache__"),
    )
    return clone


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


def test_documentation_uses_packaged_payload_paths_for_runtime_assets():
    readme = _read(REPO_ROOT / "README.md")
    contributing = _read(REPO_ROOT / "CONTRIBUTING.md")
    design = _read(REPO_ROOT / "DESIGN.md")

    for path in (
        "scripts/lint.py",
        "scripts/rebuild_catalogs.py",
        "scripts/eval_golden.py",
        "scripts/axis_coverage.py",
    ):
        assert f"plugins/{PLUGIN_NAME}/{path}" in readme
    for stale in (
        "`scripts/lint.py`",
        "python3 scripts/rebuild_catalogs.py",
        "python3 scripts/eval_golden.py",
        "`scripts/axis_coverage.py`",
    ):
        assert stale not in readme

    for path in (
        "responsibility/services/<provider>-<service>.yaml",
        "responsibility/layers.yaml",
        "overlays/SCHEMA.md",
        "catalogs/data-types/classification.yaml",
        "scripts/rebuild_catalogs.py",
        "scripts/lint.py",
    ):
        assert f"plugins/{PLUGIN_NAME}/{path}" in contributing
    for stale in (
        "`responsibility/services/<provider>-<service>.yaml`",
        "`responsibility/layers.yaml`",
        "`overlays/SCHEMA.md`",
        "`catalogs/data-types/classification.yaml`",
        "python3 scripts/rebuild_catalogs.py",
        "python3 scripts/lint.py",
    ):
        assert stale not in contributing

    for path in (
        "catalogs/nist-*",
        "catalogs/asvs-5/",
        "overlays/",
        "catalogs/data-types/classification.yaml",
        "catalogs/data-types/availability.yaml",
        "skills/deriving-security-requirements/references/profile-schema.md",
        "overlays/SCHEMA.md",
        "scripts/profile_schema.py",
    ):
        assert f"plugins/{PLUGIN_NAME}/{path}" in design
    for stale in (
        "`catalogs/nist-*`",
        "`catalogs/asvs-5/`",
        "`overlays/`",
        "`catalogs/data-types/classification.yaml`",
        "`catalogs/data-types/availability.yaml`",
        "`skills/deriving-security-requirements/references/profile-schema.md`",
        "`overlays/SCHEMA.md`",
        "`scripts/profile_schema.py`",
    ):
        assert stale not in design


def test_design_directory_tree_matches_the_dual_host_payload_layout():
    design = _read(REPO_ROOT / "DESIGN.md")
    section = design[design.index("## 4. 디렉토리 구조") :]
    tree = section[section.index("```") + 3 :]
    tree = tree[: tree.index("```")]

    for fragment in (
        ".claude-plugin/\n  marketplace.json",
        ".agents/\n  plugins/\n    marketplace.json",
        "plugins/\n  security-requirements/\n    .claude-plugin/\n      plugin.json",
        "    .codex-plugin/\n      plugin.json",
        "    commands/",
        "    skills/",
        "    scripts/",
        "    catalogs/",
        "    responsibility/",
    ):
        assert fragment in tree

    for stale_root in (
        "\ncommands/",
        "\nskills/",
        "\ncatalogs/",
        "\nresponsibility/",
    ):
        assert stale_root not in tree


def test_gitignore_exposes_only_the_codex_marketplace_under_agent_tooling():
    expected = ".agents/plugins/marketplace.json"
    tracked = subprocess.run(
        ["git", "ls-files", "--", ".agents/plugins"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    assert tracked.stdout.splitlines() == [expected]

    result = subprocess.run(
        ["git", "check-ignore", "--no-index", "-q", expected],
        cwd=REPO_ROOT,
        check=False,
    )
    assert result.returncode == 1, f"{expected} must be unignored"

    for ignored in (
        ".agents/local-settings.json",
        ".agents/plugins/other.json",
        ".agents/plugins/nested/plugin.json",
    ):
        result = subprocess.run(
            ["git", "check-ignore", "--no-index", "-q", ignored],
            cwd=REPO_ROOT,
            check=False,
        )
        assert result.returncode == 0, f"{ignored} must remain ignored"


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
        "python3 ./scripts/lint.py requirements.yaml",
        "python3.12 scripts/lint.py requirements.yaml",
        "python3.12 -I ./scripts/lint.py requirements.yaml",
        "/usr/bin/python3.12 -I ./scripts/lint.py requirements.yaml",
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


def test_distribution_validator_rejects_multiline_cwd_relative_python_invocation(tmp_path):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    stale_example = clone / "plugins" / PLUGIN_NAME / "skills" / "stale-example.md"
    stale_example.write_text(
        "python3 \\\n"
        "  -X utf8 \\\n"
        "  ./scripts/lint.py requirements.yaml\n",
        encoding="utf-8",
    )

    errors = module.validate(clone)

    assert any(
        "cwd-relative payload script invocation" in error
        and "skills/stale-example.md:1" in error
        for error in errors
    )


def test_distribution_validator_inspects_packaged_script_docstrings(tmp_path):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    stale_script = clone / "plugins" / PLUGIN_NAME / "scripts" / "stale_example.py"
    stale_script.write_text(
        '"""Example:\npython3 ./scripts/lint.py requirements.yaml\n"""\n',
        encoding="utf-8",
    )

    errors = module.validate(clone)

    assert any(
        "cwd-relative payload script invocation" in error
        and "scripts/stale_example.py:2" in error
        for error in errors
    )


@pytest.mark.parametrize(
    "invocation",
    (
        "python3 -I -c 'import yaml; print(yaml.__version__)'",
        "python3 -Ic 'import yaml; print(yaml.__version__)'",
        "python3 -I -c 'from pathlib import Path; print(Path.cwd())'",
        "/usr/bin/python3 -I -c 'import yaml'",
        "python3 -I - < payload.py",
    ),
)
def test_distribution_validator_rejects_inline_python_in_workflows(tmp_path, invocation):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    workflow = clone / "plugins" / PLUGIN_NAME / "skills" / "stale-example.md"
    workflow.write_text(f"{invocation}\n", encoding="utf-8")

    errors = module.validate(clone)

    assert any(
        "inline Python is not allowed in workflow" in error
        and "skills/stale-example.md:1" in error
        for error in errors
    )


def test_distribution_validator_requires_isolated_python_for_workflow_scripts(tmp_path):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    workflow = clone / "plugins" / PLUGIN_NAME / "skills" / "stale-example.md"
    workflow.write_text(
        'python3 "<absolute plugin root>/scripts/lint.py" requirements.yaml\n',
        encoding="utf-8",
    )

    errors = module.validate(clone)

    assert any(
        "workflow Python invocation must use -I" in error
        and "skills/stale-example.md:1" in error
        for error in errors
    )


@pytest.mark.parametrize(
    "invocation",
    (
        "python3 evil.py",
        "python3 -I /tmp/evil.py",
        'python3 -I "$PWD/scripts/lint.py" requirements.yaml',
        'python3 -I "/tmp/plugin/scripts/lint.py" requirements.yaml',
        'python3 -I "<absolute project root>/scripts/lint.py" requirements.yaml',
    ),
)
def test_distribution_validator_rejects_untrusted_workflow_script_paths(
    tmp_path, invocation
):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    workflow = clone / "plugins" / PLUGIN_NAME / "skills" / "stale-example.md"
    workflow.write_text(f"{invocation}\n", encoding="utf-8")

    errors = module.validate(clone)

    assert any(
        "workflow Python script is not rooted in the plugin payload" in error
        and "skills/stale-example.md:1" in error
        for error in errors
    )


@pytest.mark.parametrize(
    "invocation",
    (
        'python3 -I "<absolute plugin root>/scripts/lint.py" requirements.yaml',
        'python3 -I "<exact absolute plugin root>/scripts/lint.py" requirements.yaml',
        'python3 -I "<absolute plugin root>/scripts/axis_coverage.py" --strict',
        'python3 -I "<exact absolute plugin root>/scripts/'
        '<trusted packaged script name.py>" <arguments>',
        'python3 -I "${CLAUDE_PLUGIN_ROOT}/scripts/runtime_paths.py" --project-root "$PWD"',
        'python3 -I "<derived absolute candidate>/scripts/runtime_paths.py" '
        '--skill "<selected absolute SKILL.md>"',
    ),
)
def test_distribution_validator_accepts_trusted_isolated_workflow_scripts(
    tmp_path, invocation
):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    workflow = clone / "plugins" / PLUGIN_NAME / "skills" / "trusted-example.md"
    workflow.write_text(f"{invocation}\n", encoding="utf-8")

    errors = module.validate(clone)

    assert not any("skills/trusted-example.md" in error for error in errors), errors


def test_distribution_validator_parses_trusted_command_substitution(tmp_path):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    workflow = clone / "plugins" / PLUGIN_NAME / "skills" / "trusted-example.md"
    workflow.write_text(
        'SECURITY_REQUIREMENTS_ROOT="$(python3 -I '
        '"<derived absolute candidate>/scripts/runtime_paths.py" '
        '--skill "<selected absolute SKILL.md>")" || exit\n',
        encoding="utf-8",
    )

    errors = module.validate(clone)

    assert not any("skills/trusted-example.md" in error for error in errors), errors


def test_distribution_validator_parses_yaml_quoted_python_commands(tmp_path):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    workflow = clone / "plugins" / PLUGIN_NAME / "skills" / "stale-example.yaml"
    workflow.write_text(
        "rebuild: 'python3 \"${SECURITY_REQUIREMENTS_ROOT}/scripts/rebuild_overlay_hipaa.py\"'\n",
        encoding="utf-8",
    )

    errors = module.validate(clone)

    assert any(
        "workflow Python invocation must use -I" in error
        and "skills/stale-example.yaml:1" in error
        for error in errors
    ), errors


@pytest.mark.parametrize(
    ("workflow", "outputs"),
    (
        ("init", '.security-requirements'),
        ("build", '.security-requirements docs/security'),
        ("refresh", '.security-requirements docs/security'),
    ),
)
def test_distribution_validator_requires_safe_output_preflight(
    tmp_path, workflow, outputs
):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    command = (
        clone
        / "plugins"
        / PLUGIN_NAME
        / "commands"
        / f"sec-req-{workflow}.md"
    )
    command.write_text(
        'python3 -I "<absolute plugin root>/scripts/lint.py" requirements.yaml\n',
        encoding="utf-8",
    )

    errors = module.validate(clone)

    assert (
        f"missing safe output preflight in commands/sec-req-{workflow}.md: "
        f"--project-root $PWD --check-output {outputs}"
    ) in errors


def test_distribution_validator_accepts_output_preflight_bound_to_target_cwd(tmp_path):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    command = clone / "plugins" / PLUGIN_NAME / "commands" / "sec-req-build.md"
    command.write_text(
        'python3 -I "<absolute plugin root>/scripts/safe_paths.py" '
        '--project-root "$PWD" --check-output .security-requirements docs/security\n',
        encoding="utf-8",
    )

    errors = module.validate(clone)

    assert not any(
        "safe output preflight" in error and "commands/sec-req-build.md" in error
        for error in errors
    ), errors


@pytest.mark.parametrize(
    "root_arguments",
    (
        '--project-root "$PWD" --project-root=/private/tmp',
        '--project-root=/private/tmp --project-root "$PWD"',
        '--project-r=/private/tmp --project-root "$PWD"',
        '--p=/private/tmp --project-root "$PWD"',
    ),
)
def test_distribution_validator_rejects_hidden_project_root_overrides(
    tmp_path, root_arguments
):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    command = clone / "plugins" / PLUGIN_NAME / "commands" / "sec-req-build.md"
    command.write_text(
        'python3 -I "<absolute plugin root>/scripts/safe_paths.py" '
        f'{root_arguments} --check-output .security-requirements docs/security\n',
        encoding="utf-8",
    )

    errors = module.validate(clone)

    assert any(
        "invalid safe output preflight" in error
        and "commands/sec-req-build.md" in error
        for error in errors
    ), errors


@pytest.mark.parametrize(
    "root_arguments",
    (
        ("--project-root", "$PROJECT", "--project-root=/private/tmp"),
        ("--project-root=/private/tmp", "--project-root", "$PROJECT"),
        ("--project-r=/private/tmp", "--project-root", "$PROJECT"),
        ("--p=/private/tmp", "--project-root", "$PROJECT"),
    ),
)
def test_safe_paths_parser_rejects_repeated_and_abbreviated_project_roots(
    tmp_path, root_arguments
):
    module = _load_safe_paths()
    project = tmp_path / "project"
    project.mkdir()
    arguments = [
        str(project) if value == "$PROJECT" else value for value in root_arguments
    ]

    assert module.main([*arguments, "--check-output", ".security-requirements"]) == 2


def test_safe_paths_parser_accepts_one_equals_form_project_root(tmp_path):
    module = _load_safe_paths()
    project = tmp_path / "project"
    project.mkdir()

    assert module.main(
        [
            f"--project-root={project}",
            "--check-output=.security-requirements",
        ]
    ) == 0


def test_distribution_validator_ignores_scoped_safe_path_checks_beside_broad_preflight(
    tmp_path,
):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    command = clone / "plugins" / PLUGIN_NAME / "commands" / "sec-req-build.md"
    command.write_text(
        'python3 -I "<absolute plugin root>/scripts/safe_paths.py" '
        '--project-root "$PWD" --check-output .security-requirements docs/security\n'
        'python3 -I "<absolute plugin root>/scripts/safe_paths.py" '
        '--project-root "$PWD" '
        '--check-output .security-requirements/requirements.yaml\n'
        'python3 -I "<absolute plugin root>/scripts/safe_paths.py" '
        '--project-root "<exact absolute data root>" '
        '--check-output "<exact absolute data root>/confirmation.json"\n',
        encoding="utf-8",
    )

    errors = module.validate(clone)

    assert not any(
        "safe output preflight" in error and "commands/sec-req-build.md" in error
        for error in errors
    ), errors


@pytest.mark.parametrize(
    "preflight",
    (
        'python3 -I "<absolute plugin root>/scripts/safe_paths.py" '
        '--check-output .security-requirements docs/security',
        'python3 -I "<absolute plugin root>/scripts/safe_paths.py" '
        '--project-root /tmp --check-output .security-requirements docs/security',
        'python3 -I "<absolute plugin root>/scripts/safe_paths.py" '
        '--project-root "$PWD" --project-root /tmp '
        '--check-output .security-requirements docs/security',
        'python3 -I "<absolute plugin root>/scripts/safe_paths.py" '
        '--project-root "$PWD" '
        '--check-output .security-requirements docs/security '
        '--check-output .security-requirements',
        'python3 -I "$PWD/scripts/safe_paths.py" '
        '--project-root "$PWD" --check-output .security-requirements docs/security',
    ),
)
def test_distribution_validator_rejects_preflight_not_bound_to_trusted_payload_and_cwd(
    tmp_path, preflight
):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    command = clone / "plugins" / PLUGIN_NAME / "commands" / "sec-req-build.md"
    command.write_text(f"{preflight}\n", encoding="utf-8")

    errors = module.validate(clone)

    assert any(
        "safe output preflight" in error and "commands/sec-req-build.md" in error
        for error in errors
    ), errors


def test_distribution_validator_rejects_an_invalid_preflight_beside_a_valid_one(
    tmp_path,
):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    command = clone / "plugins" / PLUGIN_NAME / "commands" / "sec-req-build.md"
    command.write_text(
        'python3 -I "<absolute plugin root>/scripts/safe_paths.py" '
        '--project-root "$PWD" --check-output .security-requirements docs/security\n'
        'python3 -I "<absolute plugin root>/scripts/safe_paths.py" '
        '--project-root /tmp --check-output .security-requirements docs/security\n',
        encoding="utf-8",
    )

    errors = module.validate(clone)

    assert any(
        "invalid safe output preflight" in error
        and "commands/sec-req-build.md" in error
        for error in errors
    ), errors


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
