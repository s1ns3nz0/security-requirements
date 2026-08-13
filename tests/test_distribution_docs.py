import ast
import importlib.util
import json
import shutil
from types import SimpleNamespace
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PureWindowsPath

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
PLUGIN_NAME = "security-requirements"
QUALIFIED_PLUGIN_NAME = f"{PLUGIN_NAME}@{PLUGIN_NAME}"
VALIDATOR = REPO_ROOT / "scripts" / "validate_distribution.py"
SAFE_PATHS = REPO_ROOT / "plugins" / PLUGIN_NAME / "scripts" / "safe_paths.py"
CANONICAL_BUILD_PREFLIGHT = (
    'python3 -I "${CLAUDE_PLUGIN_ROOT}/scripts/safe_paths.py" '
    '--project-root "$PWD" --check-output .security-requirements docs/security'
)
RISK_ASSETS = (
    "risk/default-policy.yaml",
    "scripts/risk.py",
    "commands/sec-req-risk.md",
    "skills/security-requirements-risk/SKILL.md",
    "skills/deriving-security-requirements/references/risk-assessment.md",
)
RISK_PROMPT = "Assess and review threat risk for this repository."
WORKFLOW_PROMPTS = (
    "Initialize the security requirements profile for this repository.",
    "Build security requirements from the confirmed profile.",
    "Refresh security requirements after service changes.",
    RISK_PROMPT,
)
LEGACY_BUILD_PREFLIGHT = (
    'python3 -I "<absolute plugin root>/scripts/safe_paths.py" '
    '--project-root "$PWD" --check-output .security-requirements docs/security'
)


def _bash_block(command: str) -> str:
    return f"```bash\n{command}\n```\n"


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


def test_documentation_exposes_risk_rating_governance_on_both_hosts():
    readme = _read(REPO_ROOT / "README.md")
    design = _read(REPO_ROOT / "DESIGN.md")
    combined = f"{readme}\n{design}"

    assert "/security-requirements:sec-req-risk" in readme
    assert "security-requirements-risk" in readme
    assert RISK_PROMPT in readme
    assert "1–4" in combined and "5–9" in combined
    assert "10–16" in combined and "17–25" in combined
    assert "model proposes" in combined.lower()
    assert "does not approve" in combined.lower()
    assert "publish_risk_summary: true" in combined
    assert "Residual" in combined and "implementation evidence" in combined
    assert "legacy" in combined.lower() and "0.1.0" in combined
    assert "accepted risk" in combined.lower()
    assert "Requirement priority is not a risk rating" in combined


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

    for requirement in (
        "Python 3.12 or newer",
        "PyYAML",
        "`gh`",
        "fallback",
        "external",
    ):
        assert requirement in text

    for path in (REPO_ROOT / "README.md", REPO_ROOT / "CONTRIBUTING.md"):
        assert "Python 3.12 or newer" in _read(path)

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
    clone = _distribution_clone(tmp_path)
    marketplace = json.loads(
        (clone / ".agents" / "plugins" / "marketplace.json").read_text(encoding="utf-8")
    )
    assert marketplace["name"] == PLUGIN_NAME

    before = {
        path.relative_to(clone): path.stat().st_mtime_ns
        for path in (
            clone / ".claude-plugin" / "marketplace.json",
            clone / ".agents" / "plugins" / "marketplace.json",
            clone / "plugins" / PLUGIN_NAME / ".claude-plugin" / "plugin.json",
            clone / "plugins" / PLUGIN_NAME / ".codex-plugin" / "plugin.json",
        )
    }
    assert module.validate(clone) == []
    after = {path: (clone / path).stat().st_mtime_ns for path in before}
    assert after == before

    result = subprocess.run(
        [sys.executable, str(VALIDATOR), str(clone)],
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
    workflow = (
        clone
        / "plugins"
        / PLUGIN_NAME
        / "skills"
        / "deriving-security-requirements"
        / "references"
        / "requirement-style.md"
    )
    workflow.write_text(f"{invocation}\n", encoding="utf-8")

    errors = module.validate(clone)

    assert not any("requirement-style.md" in error for error in errors), errors


def test_distribution_validator_parses_trusted_command_substitution(tmp_path):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    workflow = (
        clone
        / "plugins"
        / PLUGIN_NAME
        / "skills"
        / "deriving-security-requirements"
        / "references"
        / "requirement-style.md"
    )
    workflow.write_text(
        'SECURITY_REQUIREMENTS_ROOT="$(python3 -I '
        '"<derived absolute candidate>/scripts/runtime_paths.py" '
        '--skill "<selected absolute SKILL.md>")" || exit\n',
        encoding="utf-8",
    )

    errors = module.validate(clone)

    assert not any("requirement-style.md" in error for error in errors), errors


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


@pytest.mark.parametrize(
    ("workflow", "outputs"),
    (
        ("init", ".security-requirements"),
        ("build", ".security-requirements docs/security"),
        ("refresh", ".security-requirements docs/security"),
    ),
)
def test_distribution_validator_accepts_exact_canonical_output_preflight(
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
        _bash_block(
            'python3 -I "${CLAUDE_PLUGIN_ROOT}/scripts/safe_paths.py" '
            f'--project-root "$PWD" --check-output {outputs}'
        ),
        encoding="utf-8",
    )

    errors = module.validate(clone)

    assert not any(
        f"commands/sec-req-{workflow}.md" in error for error in errors
    ), errors


@pytest.mark.parametrize(
    "document",
    (
        pytest.param(
            f"<!--\n```bash\n{CANONICAL_BUILD_PREFLIGHT}\n```\n-->\n",
            id="html-comment",
        ),
        pytest.param(
            f"```text\n{CANONICAL_BUILD_PREFLIGHT}\n```\n",
            id="text-fence",
        ),
        pytest.param(
            "```bash\n"
            "cat <<'EOF'\n"
            f"{CANONICAL_BUILD_PREFLIGHT}\n"
            "EOF\n"
            "```\n",
            id="heredoc",
        ),
        pytest.param(
            "```bash\n: '\n"
            + f"{CANONICAL_BUILD_PREFLIGHT}\n"
            + "'\n```\n",
            id="shell-noop-string",
        ),
    ),
)
def test_distribution_validator_rejects_an_inert_exact_canonical_preflight(
    tmp_path, document
):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    command = clone / "plugins" / PLUGIN_NAME / "commands" / "sec-req-build.md"
    command.write_text(document, encoding="utf-8")

    errors = module.validate(clone)

    assert any(
        "invalid safe output preflight" in error
        and "commands/sec-req-build.md" in error
        for error in errors
    ), errors


@pytest.mark.parametrize(
    "preflight",
    (
        pytest.param(
            CANONICAL_BUILD_PREFLIGHT.replace('"$PWD"', "$PWD"),
            id="unquoted-pwd",
        ),
        pytest.param(
            CANONICAL_BUILD_PREFLIGHT.replace('"$PWD"', "'$PWD'"),
            id="single-quoted-pwd",
        ),
        pytest.param(
            CANONICAL_BUILD_PREFLIGHT.replace('"$PWD"', r"\$PWD"),
            id="escaped-pwd",
        ),
        pytest.param(
            CANONICAL_BUILD_PREFLIGHT.replace("python3 -I", "python3 -I -h"),
            id="interpreter-short-help",
        ),
        pytest.param(
            CANONICAL_BUILD_PREFLIGHT.replace("python3 -I", "python3 -I --help"),
            id="interpreter-long-help",
        ),
        pytest.param(
            CANONICAL_BUILD_PREFLIGHT.replace("python3 -I", "python3 -I -V"),
            id="interpreter-short-version",
        ),
        pytest.param(
            CANONICAL_BUILD_PREFLIGHT.replace("python3 -I", "python3 -I --version"),
            id="interpreter-long-version",
        ),
        pytest.param(
            CANONICAL_BUILD_PREFLIGHT.replace("safe_paths.py\"", 'safe_paths.py" -h'),
            id="script-short-help",
        ),
        pytest.param(
            CANONICAL_BUILD_PREFLIGHT.replace(
                "safe_paths.py\"", 'safe_paths.py" --help'
            ),
            id="script-long-help",
        ),
        pytest.param(f"cd /private/tmp && {CANONICAL_BUILD_PREFLIGHT}", id="cd-prefix"),
        pytest.param(
            f"env SECURITY_REQUIREMENTS_ROOT=/private/tmp {CANONICAL_BUILD_PREFLIGHT}",
            id="env-prefix",
        ),
        pytest.param(f"true && {CANONICAL_BUILD_PREFLIGHT}", id="true-prefix"),
        pytest.param(f"true || {CANONICAL_BUILD_PREFLIGHT}", id="dead-true-or-prefix"),
        pytest.param(f"{CANONICAL_BUILD_PREFLIGHT} || true", id="status-masking"),
        pytest.param(f"{CANONICAL_BUILD_PREFLIGHT} | cat", id="pipe-suffix"),
        pytest.param(f"{CANONICAL_BUILD_PREFLIGHT}; true", id="semicolon-suffix"),
        pytest.param(f"# {CANONICAL_BUILD_PREFLIGHT}", id="commented-out"),
        pytest.param(
            f"{CANONICAL_BUILD_PREFLIGHT}\n{CANONICAL_BUILD_PREFLIGHT}",
            id="duplicate",
        ),
        pytest.param(
            CANONICAL_BUILD_PREFLIGHT.replace(
                'safe_paths.py" --project-root',
                'safe_paths.py" \\' + "\n" + "--project-root",
            ),
            id="line-continuation",
        ),
        pytest.param(
            CANONICAL_BUILD_PREFLIGHT.replace(
                ".security-requirements docs/security",
                "docs/security .security-requirements",
            ),
            id="reversed-outputs",
        ),
        pytest.param(
            CANONICAL_BUILD_PREFLIGHT.replace("python3 -I", "python3 -I -B"),
            id="extra-interpreter-option",
        ),
        pytest.param(LEGACY_BUILD_PREFLIGHT, id="legacy-script-root"),
    ),
)
def test_distribution_validator_rejects_noncanonical_broad_preflight_source(
    tmp_path, preflight
):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    command = clone / "plugins" / PLUGIN_NAME / "commands" / "sec-req-build.md"
    command.write_text(_bash_block(preflight), encoding="utf-8")

    errors = module.validate(clone)

    assert any(
        "invalid safe output preflight" in error
        and "commands/sec-req-build.md" in error
        for error in errors
    ), errors


@pytest.mark.parametrize(
    "extra_preflight",
    (
        pytest.param(
            CANONICAL_BUILD_PREFLIGHT.replace('"$PWD"', "/private/tmp").replace(
                ".security-requirements", '.security-"requirements"'
            ),
            id="quote-spliced-output",
        ),
        pytest.param(
            CANONICAL_BUILD_PREFLIGHT.replace('"$PWD"', "/private/tmp").replace(
                "safe_paths.py", 'safe_""paths.py'
            ),
            id="quote-spliced-script",
        ),
        pytest.param(
            CANONICAL_BUILD_PREFLIGHT.replace('"$PWD"', "/private/tmp").replace(
                ".security-requirements", r".security\-requirements"
            ),
            id="escaped-output",
        ),
        pytest.param(
            'py"thon3" -I '
            '"${CLAUDE_PLUGIN_ROOT}/scripts/safe_""paths.py" '
            '--project-root /private/tmp '
            '--check-output .security-requirements docs/security',
            id="combined-quote-splicing",
        ),
        pytest.param(
            'py"thon3" -I safe_""paths.py '
            '--project-root /private/tmp '
            '--check-output .security-requirements docs/security',
            id="relative-quote-spliced-script",
        ),
        pytest.param(
            'python3 -I "${CLAUDE_PLUGIN_ROOT}/scripts/safe_"paths.py '
            '--project-root /private/tmp '
            '--check-output .security-requirements docs/security"',
            id="malformed-quote-spliced-script",
        ),
        pytest.param(
            CANONICAL_BUILD_PREFLIGHT.replace('"$PWD"', "/private/tmp").replace(
                ".security-requirements docs/security",
                ".security-requirements/. docs//security",
            ),
            id="path-equivalent-outputs",
        ),
        pytest.param(
            "```bash\n"
            'OUTPUTS=".security-requirements docs/security"\n'
            'python3 -I "<absolute plugin root>/scripts/safe_paths.py" '
            '--project-root /private/tmp --check-output $OUTPUTS\n'
            "```",
            id="dynamic-output-set",
        ),
        pytest.param(
            LEGACY_BUILD_PREFLIGHT.replace('"$PWD"', "/private/tmp").replace(
                ".security-requirements", ".security-\\\nrequirements"
            ),
            id="line-continuation-split-security-requirements",
        ),
        pytest.param(
            LEGACY_BUILD_PREFLIGHT.replace('"$PWD"', "/private/tmp").replace(
                "docs/security", "docs/sec\\\nurity"
            ),
            id="line-continuation-split-docs-security",
        ),
    ),
)
def test_distribution_validator_rejects_a_shell_equivalent_broad_candidate_beside_canonical(
    tmp_path, extra_preflight
):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    command = clone / "plugins" / PLUGIN_NAME / "commands" / "sec-req-build.md"
    command.write_text(
        _bash_block(CANONICAL_BUILD_PREFLIGHT) + f"{extra_preflight}\n",
        encoding="utf-8",
    )

    errors = module.validate(clone)

    assert any(
        "invalid safe output preflight" in error
        and "commands/sec-req-build.md" in error
        for error in errors
    ), errors


def test_distribution_validator_rejects_claude_root_for_a_scoped_preflight(
    tmp_path,
):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    command = clone / "plugins" / PLUGIN_NAME / "commands" / "sec-req-build.md"
    command.write_text(
        _bash_block(CANONICAL_BUILD_PREFLIGHT)
        + 'python3 -I "${CLAUDE_PLUGIN_ROOT}/scripts/safe_paths.py" '
        '--project-root "$PWD" '
        '--check-output .security-requirements/requirements.yaml\n',
        encoding="utf-8",
    )

    errors = module.validate(clone)

    assert any(
        "workflow Python script is not rooted in the plugin payload" in error
        and "commands/sec-req-build.md:4" in error
        for error in errors
    ), errors


def test_distribution_validator_rejects_quote_spliced_claude_root_scoped_preflight(
    tmp_path,
):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    command = clone / "plugins" / PLUGIN_NAME / "commands" / "sec-req-build.md"
    command.write_text(
        _bash_block(CANONICAL_BUILD_PREFLIGHT)
        + 'py"thon3" -I '
        '"${CLAUDE_PLUGIN_ROOT}/scripts/safe_""paths.py" '
        '--project-root "$PWD" '
        '--check-output .security-requirements/profile.yaml\n',
        encoding="utf-8",
    )

    errors = module.validate(clone)

    assert any(
        "workflow Python script is not rooted in the plugin payload" in error
        and "commands/sec-req-build.md:4" in error
        for error in errors
    ), errors


def test_distribution_validator_rejects_canonical_claude_preflight_outside_its_command(
    tmp_path,
):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    workflow = clone / "plugins" / PLUGIN_NAME / "skills" / "stale-example.md"
    workflow.write_text(f"{CANONICAL_BUILD_PREFLIGHT}\n", encoding="utf-8")

    errors = module.validate(clone)

    assert any(
        "workflow Python script is not rooted in the plugin payload" in error
        and "skills/stale-example.md:1" in error
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
        _bash_block(
            'python3 -I "<absolute plugin root>/scripts/safe_paths.py" '
            f"{root_arguments} --check-output .security-requirements docs/security"
        ),
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


@pytest.mark.parametrize(
    "redirect_location",
    ("project-root", "output-ancestor", "output-target"),
)
def test_safe_path_rejects_a_simulated_junction_at_every_boundary(
    tmp_path, monkeypatch, redirect_location
):
    module = _load_safe_paths()
    project = tmp_path / "project"
    target = project / "docs" / "security" / "requirements.md"
    project.mkdir()
    redirects = {
        "project-root": project,
        "output-ancestor": project / "docs",
        "output-target": target,
    }
    redirect = redirects[redirect_location]

    monkeypatch.setattr(
        Path,
        "is_junction",
        lambda path: path == redirect,
    )

    with pytest.raises(module.UnsafePathError, match="junction"):
        module.safe_path(target, project_root=project)


def test_safe_path_allows_a_redirect_above_the_project_root(tmp_path, monkeypatch):
    module = _load_safe_paths()
    project = tmp_path / "project"
    target = project / "docs" / "security" / "requirements.md"
    project.mkdir()

    monkeypatch.setattr(
        Path,
        "is_junction",
        lambda path: path == project.parent,
    )

    assert module.safe_path(target, project_root=project) == target


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS /tmp is a system symlink")
def test_safe_paths_cli_accepts_an_ordinary_project_under_macos_tmp():
    module = _load_safe_paths()
    with tempfile.TemporaryDirectory(prefix="safe-paths-", dir="/tmp") as directory:
        project = Path(directory)
        assert Path("/tmp").is_symlink()
        assert module.main(
            [
                "--project-root",
                str(project),
                "--check-output",
                ".security-requirements",
            ]
        ) == 0


def test_safe_paths_cli_rejects_python_older_than_3_12(
    tmp_path, monkeypatch, capsys
):
    module = _load_safe_paths()
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.setattr(module.sys, "version_info", (3, 11, 9))

    assert module.main(
        [
            "--project-root",
            str(project),
            "--check-output",
            ".security-requirements",
        ]
    ) == 2

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "requires Python 3.12 or newer" in captured.err


def test_junction_detection_is_mandatory_on_the_supported_runtime():
    module = _load_safe_paths()

    class LegacyPath:
        def is_symlink(self):
            return False

    with pytest.raises(AttributeError):
        module._is_redirect(LegacyPath())


@pytest.mark.skipif(
    not sys.platform.startswith("win"),
    reason="requires Windows",
)
def test_safe_path_rejects_a_real_windows_junction(tmp_path):
    module = _load_safe_paths()
    project = tmp_path / "project"
    outside = tmp_path / "outside"
    project.mkdir()
    outside.mkdir()
    junction = project / "docs"
    subprocess.run(
        ["cmd.exe", "/d", "/c", "mklink", "/J", str(junction), str(outside)],
        check=True,
        capture_output=True,
        text=True,
    )
    assert junction.is_junction()

    with pytest.raises(module.UnsafePathError, match="junction"):
        module.safe_path(
            junction / "security" / "requirements.md",
            project_root=project,
        )


def test_safe_paths_cli_rejects_parent_segments_before_symlink_resolution(tmp_path):
    project = tmp_path / "project"
    outside = tmp_path / "outside"
    redirected_child = outside / "child"
    project.mkdir()
    redirected_child.mkdir(parents=True)
    link = project / "link"
    link.symlink_to(redirected_child, target_is_directory=True)
    raw_target = link / ".." / "escaped.txt"

    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(SAFE_PATHS),
            "--project-root",
            str(project),
            "--check-output",
            str(raw_target),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 2
    assert "parent path segment" in result.stderr
    assert not (outside / "escaped.txt").exists()


def test_exact_containment_rejects_windows_case_variant_sibling():
    module = _load_safe_paths()
    project = PureWindowsPath(r"C:\work\repo")
    case_variant_sibling = PureWindowsPath(r"C:\work\REPO\escaped.txt")

    # pathlib's Windows containment comparison is case-insensitive, including
    # when the backing NTFS directory is configured for case sensitivity.
    assert case_variant_sibling.is_relative_to(project)
    with pytest.raises(ValueError, match="exact component prefix"):
        module._relative_parts_exact(case_variant_sibling, project)


def test_distribution_validator_ignores_scoped_safe_path_checks_beside_broad_preflight(
    tmp_path,
):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    command = clone / "plugins" / PLUGIN_NAME / "commands" / "sec-req-build.md"
    command.write_text(
        _bash_block(CANONICAL_BUILD_PREFLIGHT)
        + 'python3 -I "<absolute plugin root>/scripts/safe_paths.py" '
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
    command.write_text(_bash_block(preflight), encoding="utf-8")

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
        _bash_block(CANONICAL_BUILD_PREFLIGHT)
        + 'python3 -I "<absolute plugin root>/scripts/safe_paths.py" '
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
def test_distribution_validator_rejects_top_level_runtime_copies_only(tmp_path, directory):
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
    assert not any("other-payload" in error for error in errors)


@pytest.mark.parametrize("relative", RISK_ASSETS)
def test_distribution_validator_requires_each_canonical_risk_asset(tmp_path, relative):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    asset = clone / "plugins" / PLUGIN_NAME / relative
    asset.unlink()
    if asset.parent.name == "security-requirements-risk":
        asset.parent.rmdir()

    errors = module.validate(clone)

    assert f"missing required risk asset: {relative}" in errors


@pytest.mark.parametrize(
    ("relative", "duplicate"),
    (
        ("risk/default-policy.yaml", "risk/duplicate/default-policy.yaml"),
        ("scripts/risk.py", "scripts/duplicate/risk.py"),
        ("commands/sec-req-risk.md", "commands/duplicate/sec-req-risk.md"),
    ),
)
def test_distribution_validator_rejects_duplicate_risk_assets(
    tmp_path, relative, duplicate
):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    payload = clone / "plugins" / PLUGIN_NAME
    source = payload / relative
    target = payload / duplicate
    target.parent.mkdir(parents=True)
    shutil.copyfile(source, target)

    errors = module.validate(clone)

    assert any(
        "duplicate risk asset" in error and duplicate in error for error in errors
    ), errors


@pytest.mark.parametrize(
    "mutation",
    (
        lambda text: text.replace("max: 4", "max: 5", 1),
        lambda text: text.replace(
            "L5-DIRECT-AUTOMATABLE: {score: 5",
            "L5-DIRECT-AUTOMATABLE: {score: 4",
        ),
        lambda text: text.replace("publish_risk_summary: false\n", ""),
        lambda text: text + "unexpected: true\n",
        lambda text: text.replace('version: "1.0.0"', "version: !unsafe 1.0.0"),
    ),
)
def test_distribution_validator_rejects_invalid_bundled_default_policy(
    tmp_path, mutation
):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    policy = clone / "plugins" / PLUGIN_NAME / "risk" / "default-policy.yaml"
    policy.write_text(mutation(_read(policy)), encoding="utf-8")

    errors = module.validate(clone)

    assert any("invalid bundled default risk policy" in error for error in errors), errors


def test_distribution_validator_requires_release_and_schema_version_agreement(tmp_path):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    claude_path = clone / "plugins" / PLUGIN_NAME / ".claude-plugin" / "plugin.json"
    codex_path = clone / "plugins" / PLUGIN_NAME / ".codex-plugin" / "plugin.json"
    threat_reference = (
        clone
        / "plugins"
        / PLUGIN_NAME
        / "skills"
        / "deriving-security-requirements"
        / "references"
        / "threat-modeling.md"
    )
    claude = json.loads(_read(claude_path))
    codex = json.loads(_read(codex_path))
    claude["version"] = "0.2.0"
    codex["version"] = "0.3.0"
    claude_path.write_text(json.dumps(claude), encoding="utf-8")
    codex_path.write_text(json.dumps(codex), encoding="utf-8")
    threat_reference.write_text(
        _read(threat_reference).replace("schema version `0.2.0`", "schema version `0.3.0`"),
        encoding="utf-8",
    )

    errors = module.validate(clone)

    assert any("payload manifest versions must both equal 0.2.0" in error for error in errors)
    assert any("threat schema version must agree with release 0.2.0" in error for error in errors)


def test_distribution_validator_requires_engine_schema_version_agreement(tmp_path):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    engine = clone / "plugins" / PLUGIN_NAME / "scripts" / "risk.py"
    engine.write_text(_read(engine).replace('"0.2.0"', '"0.3.0"'), encoding="utf-8")

    errors = module.validate(clone)

    assert any(
        "risk engine schema contract mismatch" in error
        and "CURRENT_THREAT_SCHEMA_VERSION" in error
        for error in errors
    )


def test_payload_manifests_publish_020_while_marketplace_metadata_is_unchanged():
    payload = REPO_ROOT / "plugins" / PLUGIN_NAME
    claude = json.loads(_read(payload / ".claude-plugin" / "plugin.json"))
    codex = json.loads(_read(payload / ".codex-plugin" / "plugin.json"))
    marketplace = json.loads(_read(REPO_ROOT / ".claude-plugin" / "marketplace.json"))

    assert claude["version"] == codex["version"] == "0.2.0"
    assert marketplace["metadata"]["version"] == "0.1.0"


@pytest.mark.parametrize("host", ("claude", "codex"))
def test_distribution_validator_requires_exactly_four_host_entrypoints(tmp_path, host):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    payload = clone / "plugins" / PLUGIN_NAME
    if host == "claude":
        extra = payload / "commands" / "sec-req-extra.md"
        extra.write_text("---\ndescription: extra\n---\n", encoding="utf-8")
    else:
        extra = payload / "skills" / "security-requirements-extra" / "SKILL.md"
        extra.parent.mkdir()
        extra.write_text("---\nname: security-requirements-extra\n---\n", encoding="utf-8")

    errors = module.validate(clone)

    assert any(f"unexpected {host.title()} entry point" in error for error in errors), errors


def test_distribution_validator_requires_exactly_four_ordered_codex_prompts(tmp_path):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    manifest_path = clone / "plugins" / PLUGIN_NAME / ".codex-plugin" / "plugin.json"
    manifest = json.loads(_read(manifest_path))
    manifest["version"] = "0.2.0"
    manifest["interface"]["defaultPrompt"] = [*WORKFLOW_PROMPTS, RISK_PROMPT]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    errors = module.validate(clone)

    assert "Codex manifest must declare exactly the four canonical workflow prompts" in errors


def test_distribution_validator_rejects_unapproved_payload_components_without_execution(
    tmp_path
):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    marker = tmp_path / "repository-code-ran"
    probe = clone / "plugins" / PLUGIN_NAME / "scripts" / "unapproved_probe.py"
    probe.write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n",
        encoding="utf-8",
    )

    errors = module.validate(clone)

    assert any("unapproved payload path" in error for error in errors), errors
    assert not marker.exists()


def test_distribution_validator_rejects_junctions_without_traversing_them(
    tmp_path, monkeypatch
):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    redirect = clone / "plugins" / PLUGIN_NAME / "risk" / "redirect"
    redirect.mkdir()
    (redirect / "default-policy.yaml").write_text("unsafe", encoding="utf-8")
    real_is_junction = Path.is_junction

    def simulated_junction(path):
        return path == redirect or real_is_junction(path)

    monkeypatch.setattr(Path, "is_junction", simulated_junction)

    errors = module.validate(clone)

    assert any("junction is not allowed in payload" in error for error in errors), errors
    assert not any(
        "duplicate risk asset" in error and "redirect/default-policy.yaml" in error
        for error in errors
    )


def test_distribution_validator_ignores_a_junction_beside_the_payload(
    tmp_path, monkeypatch
):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    redirect = clone / "plugins" / "duplicate-payload"
    redirect.mkdir()
    real_is_junction = Path.is_junction

    def simulated_junction(path):
        return path == redirect or real_is_junction(path)

    monkeypatch.setattr(Path, "is_junction", simulated_junction)

    errors = module.validate(clone)

    assert not any("duplicate-payload" in error for error in errors)


@pytest.mark.parametrize("relative", RISK_ASSETS)
def test_distribution_validator_never_reads_a_redirected_canonical_risk_asset(
    tmp_path, monkeypatch, relative
):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    asset = clone / "plugins" / PLUGIN_NAME / relative
    real_is_junction = Path.is_junction
    real_read_text = Path.read_text
    reads = []

    def simulated_junction(path):
        return path == asset or real_is_junction(path)

    def observed_read(path, *args, **kwargs):
        if path == asset:
            reads.append(path)
        return real_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "is_junction", simulated_junction)
    monkeypatch.setattr(Path, "read_text", observed_read)

    errors = module.validate(clone)

    assert any("junction is not allowed in payload" in error for error in errors)
    assert reads == []


@pytest.mark.parametrize("redirect_kind", ("symlink", "junction"))
def test_distribution_validator_performs_no_descendant_operation_on_redirected_payload(
    tmp_path, monkeypatch, redirect_kind
):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    payload = clone / "plugins" / PLUGIN_NAME
    real_scandir = module.os.scandir
    real_methods = {
        name: getattr(Path, name)
        for name in ("lstat", "stat", "read_text", "exists", "is_file", "is_dir")
    }
    operations = []

    if redirect_kind == "symlink":
        outside = tmp_path / "outside-payload"
        shutil.copytree(payload, outside)
        shutil.rmtree(payload)
        payload.symlink_to(outside, target_is_directory=True)
    real_is_junction = Path.is_junction

    def observed_method(name):
        def observe(path, *args, **kwargs):
            if path != payload and payload in path.parents:
                operations.append((name, path))
            return real_methods[name](path, *args, **kwargs)

        return observe

    def observed_junction(path):
        if path != payload and payload in path.parents:
            operations.append(("is_junction", path))
        if redirect_kind == "junction" and path == payload:
            return True
        return real_is_junction(path)

    def observed_scandir(path):
        candidate = Path(path)
        if candidate != payload and payload in candidate.parents:
            operations.append(("scandir", candidate))
        return real_scandir(path)

    for name in real_methods:
        monkeypatch.setattr(Path, name, observed_method(name))
    monkeypatch.setattr(Path, "is_junction", observed_junction)
    monkeypatch.setattr(module.os, "scandir", observed_scandir)

    errors = module.validate(clone)

    assert any(f"{redirect_kind} is not allowed in payload" in error for error in errors)
    assert operations == []


def test_distribution_validator_rejects_python_cache_artifacts_in_payload(tmp_path):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    payload = clone / "plugins" / PLUGIN_NAME
    cache = payload / "scripts" / "__pycache__"
    cache.mkdir()
    bytecode = cache / "risk.cpython-312.pyc"
    bytecode.write_bytes(b"not distributed bytecode")

    errors = module.validate(clone)

    assert any(
        "unapproved payload path" in error and "scripts/__pycache__" in error
        for error in errors
    ), errors
    assert any(
        "unapproved payload path" in error
        and "scripts/__pycache__/risk.cpython-312.pyc" in error
        for error in errors
    ), errors


def test_distribution_validator_accepts_the_exact_git_archive_payload(tmp_path):
    module = _load_validator()
    archive = tmp_path / "repository.tar"
    candidate = subprocess.run(
        ["git", "stash", "create", "distribution-test-candidate"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    revision = candidate or "HEAD"
    with archive.open("wb") as output:
        result = subprocess.run(
            ["git", "archive", "--format=tar", revision],
            cwd=REPO_ROOT,
            stdout=output,
            check=False,
        )
    assert result.returncode == 0
    extracted = tmp_path / "archive"
    extracted.mkdir()
    with tarfile.open(archive) as bundle:
        bundle.extractall(extracted, filter="data")

    assert module.validate(extracted) == []


def test_distribution_validator_aggregates_risk_distribution_errors(tmp_path):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    payload = clone / "plugins" / PLUGIN_NAME
    (payload / "scripts" / "risk.py").unlink()
    (payload / "risk" / "default-policy.yaml").write_text(
        "publish_risk_summary: true\n", encoding="utf-8"
    )
    manifest_path = payload / ".codex-plugin" / "plugin.json"
    manifest = json.loads(_read(manifest_path))
    manifest["interface"]["defaultPrompt"] = []
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    (payload / "unknown-component").mkdir()

    errors = module.validate(clone)

    for expected in (
        "missing required risk asset: scripts/risk.py",
        "invalid bundled default risk policy",
        "exactly the four canonical workflow prompts",
        "unapproved payload path",
    ):
        assert any(expected in error for error in errors), errors


def test_distribution_validator_rejects_a_symlinked_repository_root_without_traversal(
    tmp_path, monkeypatch
):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    linked_root = tmp_path / "linked-root"
    linked_root.symlink_to(clone, target_is_directory=True)
    real_scandir = module.os.scandir
    traversed = []

    def observed_scandir(path):
        if Path(path) == linked_root:
            traversed.append(Path(path))
        return real_scandir(path)

    monkeypatch.setattr(module.os, "scandir", observed_scandir)

    errors = module.validate(linked_root)

    assert any("symlink is not allowed in distribution root" in error for error in errors)
    assert traversed == []


def test_distribution_validator_does_not_follow_top_level_scripts_redirect(
    tmp_path, monkeypatch
):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    scripts = clone / "scripts"
    shutil.rmtree(scripts)
    outside = tmp_path / "outside-scripts"
    outside.mkdir()
    (outside / "repository_probe.py").write_text("raise SystemExit(99)\n", encoding="utf-8")
    scripts.symlink_to(outside, target_is_directory=True)
    real_scandir = module.os.scandir
    real_iterdir = Path.iterdir
    traversed = []

    def observed_scandir(path):
        if Path(path) == scripts:
            traversed.append(Path(path))
        return real_scandir(path)

    def observed_iterdir(path):
        if path == scripts:
            traversed.append(path)
        return real_iterdir(path)

    monkeypatch.setattr(module.os, "scandir", observed_scandir)
    monkeypatch.setattr(Path, "iterdir", observed_iterdir)

    errors = module.validate(clone)

    assert any("symlink is not allowed in top-level scripts" in error for error in errors)
    assert traversed == []


def test_distribution_validator_classifies_generic_windows_reparse_points(
    tmp_path, monkeypatch
):
    module = _load_validator()
    path = tmp_path / "reparse"
    path.mkdir()
    mode = path.lstat().st_mode
    reparse_flag = 0x400
    monkeypatch.setattr(
        Path,
        "lstat",
        lambda self: SimpleNamespace(
            st_mode=mode,
            st_file_attributes=reparse_flag if self == path else 0,
        ),
    )
    monkeypatch.setattr(Path, "is_symlink", lambda self: False)
    monkeypatch.setattr(Path, "is_junction", lambda self: False)

    assert module._redirect_kind(path) == "reparse point"


@pytest.mark.parametrize(
    "relative",
    (
        "commands/nested/extra.md",
        "skills/unrelated/SKILL.md",
        "risk/extra.yaml",
        "catalogs/extra.txt",
        "overlays/extra.txt",
        "responsibility/extra.txt",
        ".claude-plugin/extra.json",
        ".codex-plugin/extra.json",
        "scripts/rogue.txt",
    ),
)
def test_distribution_validator_rejects_every_non_allowlisted_payload_path(
    tmp_path, relative
):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    rogue = clone / "plugins" / PLUGIN_NAME / relative
    rogue.parent.mkdir(parents=True, exist_ok=True)
    rogue.write_text("not part of the release\n", encoding="utf-8")

    errors = module.validate(clone)

    assert any(
        "unapproved payload path" in error and relative in error for error in errors
    ), errors


def test_distribution_validator_requires_every_allowlisted_payload_file(tmp_path):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    missing = "catalogs/asvs-5/V1.jsonl"
    (clone / "plugins" / PLUGIN_NAME / missing).unlink()

    errors = module.validate(clone)

    assert f"missing required payload file: {missing}" in errors


def test_distribution_validator_does_not_scan_unrelated_files_outside_payload(tmp_path):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    unrelated = clone / "unrelated" / "risk" / "default-policy.yaml"
    unrelated.parent.mkdir(parents=True)
    shutil.copyfile(
        clone / "plugins" / PLUGIN_NAME / "risk" / "default-policy.yaml",
        unrelated,
    )

    errors = module.validate(clone)

    assert not any("unrelated" in error for error in errors), errors


@pytest.mark.parametrize("interface", (None, [], "invalid", 42, True))
def test_distribution_validator_aggregates_non_mapping_codex_interfaces(
    tmp_path, interface
):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    manifest_path = clone / "plugins" / PLUGIN_NAME / ".codex-plugin" / "plugin.json"
    manifest = json.loads(_read(manifest_path))
    manifest["interface"] = interface
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    errors = module.validate(clone)

    assert "Codex manifest.interface must be a mapping" in errors
    assert "Codex manifest must declare exactly the four canonical workflow prompts" in errors


def test_distribution_validator_aggregates_malformed_prompt_and_version_types(tmp_path):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    payload = clone / "plugins" / PLUGIN_NAME
    claude_path = payload / ".claude-plugin" / "plugin.json"
    codex_path = payload / ".codex-plugin" / "plugin.json"
    claude = json.loads(_read(claude_path))
    codex = json.loads(_read(codex_path))
    claude["version"] = {"not": "semver"}
    codex["interface"]["defaultPrompt"] = {"not": "a list"}
    claude_path.write_text(json.dumps(claude), encoding="utf-8")
    codex_path.write_text(json.dumps(codex), encoding="utf-8")

    errors = module.validate(clone)

    assert any("payload manifest versions must both equal 0.2.0" in error for error in errors)
    assert "Codex manifest.interface.defaultPrompt must be a list of strings" in errors
    assert "Codex manifest must declare exactly the four canonical workflow prompts" in errors


@pytest.mark.parametrize(
    "mutation",
    (
        lambda text: text.replace("L1-EXCEPTIONAL: {score: 1", "L1-EXCEPTIONAL: {score: true"),
        lambda text: text.replace("L1-EXCEPTIONAL: {score: 1", "L1-EXCEPTIONAL: {score: 1.0"),
        lambda text: text.replace("- {min: 1, max: 4", "- {min: true, max: 4"),
    ),
)
def test_distribution_validator_requires_exact_integer_policy_numbers(
    tmp_path, mutation
):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    policy = clone / "plugins" / PLUGIN_NAME / "risk" / "default-policy.yaml"
    policy.write_text(mutation(_read(policy)), encoding="utf-8")

    errors = module.validate(clone)

    assert any("invalid bundled default risk policy" in error for error in errors), errors


def test_distribution_validator_rejects_duplicate_policy_criterion_ids(tmp_path):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    policy = clone / "plugins" / PLUGIN_NAME / "risk" / "default-policy.yaml"
    line = (
        '  L1-EXCEPTIONAL: {score: 1, definition: "Requires multiple independent, '
        'exceptional preconditions."}'
    )
    policy.write_text(_read(policy).replace(line, f"{line}\n{line}", 1), encoding="utf-8")

    errors = module.validate(clone)

    assert any(
        "invalid bundled default risk policy" in error
        and "duplicate mapping key: L1-EXCEPTIONAL" in error
        for error in errors
    ), errors


@pytest.mark.parametrize(
    ("function_name", "literal_old", "literal_new", "constant_old", "constant_new"),
    (
        (
            "_validate_threats",
            'threats_doc.get("version") != "0.2.0"',
            'threats_doc.get("version") != "0.1.0"',
            'threats_doc.get("version") != CURRENT_THREAT_SCHEMA_VERSION',
            'threats_doc.get("version") != LEGACY_THREAT_SCHEMA_VERSION',
        ),
        (
            "migrate",
            'threats.get("version") != "0.1.0"',
            'threats.get("version") != "0.2.0"',
            'threats.get("version") != LEGACY_THREAT_SCHEMA_VERSION',
            'threats.get("version") != CURRENT_THREAT_SCHEMA_VERSION',
        ),
        (
            "_load_risk_state",
            'state.get("version") != "0.2.0"',
            'state.get("version") != "0.1.0"',
            'state.get("version") != RISK_SCHEMA_VERSION',
            'state.get("version") != LEGACY_THREAT_SCHEMA_VERSION',
        ),
    ),
)
def test_distribution_validator_rejects_semantically_wrong_engine_schema_gates(
    tmp_path,
    function_name,
    literal_old,
    literal_new,
    constant_old,
    constant_new,
):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    engine = clone / "plugins" / PLUGIN_NAME / "scripts" / "risk.py"
    text = _read(engine)
    if constant_old in text:
        mutated = text.replace(constant_old, constant_new, 1)
    else:
        assert literal_old in text
        mutated = text.replace(literal_old, literal_new, 1)
    engine.write_text(mutated, encoding="utf-8")

    errors = module.validate(clone)

    assert any(
        "risk engine schema contract mismatch" in error and function_name in error
        for error in errors
    ), errors


def test_distribution_validator_rejects_an_unreachable_current_schema_gate(tmp_path):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    engine = clone / "plugins" / PLUGIN_NAME / "scripts" / "risk.py"
    source = _read(engine)
    live_gate = (
        '    if threats_doc.get("version") != CURRENT_THREAT_SCHEMA_VERSION:\n'
        '        problems.append("threat schema version must be 0.2.0")\n'
    )
    decoy = (
        "    if False:\n"
        '        if threats_doc.get("version") != CURRENT_THREAT_SCHEMA_VERSION:\n'
        '            problems.append("threat schema version must be 0.2.0")\n'
    )
    mutated = source.replace(live_gate, decoy, 1)
    assert mutated != source
    engine.write_text(mutated, encoding="utf-8")

    errors = module.validate(clone)

    assert any(
        "risk engine schema contract mismatch" in error
        and "_validate_threats" in error
        for error in errors
    ), errors


@pytest.mark.parametrize(
    ("function_name", "live_gate", "decoy"),
    (
        (
            "migrate",
            'or threats.get("version") != LEGACY_THREAT_SCHEMA_VERSION',
            'or False and threats.get("version") != LEGACY_THREAT_SCHEMA_VERSION',
        ),
        (
            "_load_risk_state",
            "if not isinstance(state, Mapping) or "
            'state.get("version") != RISK_SCHEMA_VERSION:',
            "if not isinstance(state, Mapping) or False and "
            'state.get("version") != RISK_SCHEMA_VERSION:',
        ),
    ),
)
def test_distribution_validator_rejects_short_circuited_engine_schema_gates(
    tmp_path, function_name, live_gate, decoy
):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    engine = clone / "plugins" / PLUGIN_NAME / "scripts" / "risk.py"
    source = _read(engine)
    mutated = source.replace(live_gate, decoy, 1)
    assert mutated != source
    engine.write_text(mutated, encoding="utf-8")

    errors = module.validate(clone)

    assert any(
        "risk engine schema contract mismatch" in error and function_name in error
        for error in errors
    ), errors


def test_distribution_validator_requires_mapping_in_the_migration_guard(tmp_path):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    engine = clone / "plugins" / PLUGIN_NAME / "scripts" / "risk.py"
    source = _read(engine)
    mutated = source.replace(
        "        not isinstance(threats, Mapping)",
        "        not isinstance(threats, str)",
        1,
    )
    assert mutated != source
    engine.write_text(mutated, encoding="utf-8")

    errors = module.validate(clone)

    assert any(
        "risk engine schema contract mismatch" in error and "migrate" in error
        for error in errors
    ), errors


@pytest.mark.parametrize(
    ("function_name", "termination"),
    (
        ("_validate_threats", "return [], []"),
        ("migrate", "raise RuntimeError('unreachable schema guard')"),
        ("_load_risk_state", "raise RuntimeError('unreachable schema guard')"),
    ),
)
def test_distribution_validator_requires_the_canonical_schema_gate_prefix(
    tmp_path, function_name, termination
):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    engine = clone / "plugins" / PLUGIN_NAME / "scripts" / "risk.py"
    source = _read(engine)
    syntax = ast.parse(source)
    function = next(
        node
        for node in syntax.body
        if isinstance(node, ast.FunctionDef) and node.name == function_name
    )
    first = function.body[0]
    if (
        isinstance(first, ast.Expr)
        and isinstance(first.value, ast.Constant)
        and isinstance(first.value.value, str)
    ):
        insertion = first.end_lineno
    else:
        insertion = first.lineno - 1
    lines = source.splitlines(keepends=True)
    lines.insert(insertion, f"    if True:\n        {termination}\n")
    engine.write_text("".join(lines), encoding="utf-8")

    errors = module.validate(clone)

    assert any(
        "risk engine schema contract mismatch" in error and function_name in error
        for error in errors
    ), errors


@pytest.mark.parametrize(
    ("function_name", "live_body", "mutated_body"),
    (
        (
            "_validate_threats",
            '        problems.append("threat schema version must be 0.2.0")',
            "        return [], []\n"
            '        problems.append("threat schema version must be 0.2.0")',
        ),
        (
            "migrate",
            '        raise RiskValidationError("legacy threat schema must be 0.1.0")',
            "        return {}\n"
            '        raise RiskValidationError("legacy threat schema must be 0.1.0")',
        ),
        (
            "_load_risk_state",
            '        raise RiskValidationError("risk state version must be 0.2.0")',
            "        return\n"
            '        raise RiskValidationError("risk state version must be 0.2.0")',
        ),
    ),
)
def test_distribution_validator_rejects_a_gate_body_prefix_before_rejection(
    tmp_path, function_name, live_body, mutated_body
):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    engine = clone / "plugins" / PLUGIN_NAME / "scripts" / "risk.py"
    source = _read(engine)
    mutated = source.replace(live_body, mutated_body, 1)
    assert mutated != source
    engine.write_text(mutated, encoding="utf-8")

    errors = module.validate(clone)

    assert any(
        "risk engine schema contract mismatch" in error and function_name in error
        for error in errors
    ), errors


@pytest.mark.parametrize(
    ("function_name", "live_expression", "mutated_expression"),
    (
        (
            "_validate_threats",
            "problems: list[str] = []",
            "problems: list[str] = 1 / 0",
        ),
        (
            "_load_risk_state",
            '_project_document_path(paths, "state")',
            '_project_document_path(1 / 0, paths, "state")',
        ),
    ),
)
def test_distribution_validator_rejects_noncanonical_schema_setup_expressions(
    tmp_path, function_name, live_expression, mutated_expression
):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    engine = clone / "plugins" / PLUGIN_NAME / "scripts" / "risk.py"
    source = _read(engine)
    mutated = source.replace(live_expression, mutated_expression, 1)
    assert mutated != source
    engine.write_text(mutated, encoding="utf-8")

    errors = module.validate(clone)

    assert any(
        "risk engine schema contract mismatch" in error and function_name in error
        for error in errors
    ), errors


def test_distribution_validator_rejects_extra_isinstance_keywords_in_schema_guard(
    tmp_path,
):
    module = _load_validator()
    clone = _distribution_clone(tmp_path)
    engine = clone / "plugins" / PLUGIN_NAME / "scripts" / "risk.py"
    source = _read(engine)
    mutated = source.replace(
        "not isinstance(threats, Mapping)",
        "not isinstance(threats, Mapping, extra=True)",
        1,
    )
    assert mutated != source
    engine.write_text(mutated, encoding="utf-8")

    errors = module.validate(clone)

    assert any(
        "risk engine schema contract mismatch" in error and "migrate" in error
        for error in errors
    ), errors
