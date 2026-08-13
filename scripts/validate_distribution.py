#!/usr/bin/env python3
"""Validate the source tree that both plugin marketplaces distribute."""

from __future__ import annotations

import json
from pathlib import Path
import re
import shlex
import sys


PLUGIN_NAME = "security-requirements"
PAYLOAD = Path("plugins") / PLUGIN_NAME
RUNTIME_DIRECTORIES = ("scripts", "catalogs", "overlays", "responsibility", "skills")
WORKFLOWS = ("init", "build", "refresh", "risk")
FORBIDDEN_CODEX_COMPONENTS = ("mcpServers", "apps", "hooks")
METADATA_FILES = (
    Path(".claude-plugin") / "marketplace.json",
    Path(".agents") / "plugins" / "marketplace.json",
    PAYLOAD / ".claude-plugin" / "plugin.json",
    PAYLOAD / ".codex-plugin" / "plugin.json",
)
PATH_FIELD_NAMES = {
    "agents", "commands", "outputstyles",
    "path", "paths", "screenshots", "skills", "scripts", "files", "directories", "source",
}
INLINE_OR_PATH_FIELDS = {"hooks", "mcpservers", "lspservers"}
TEXT_PAYLOAD_SUFFIXES = {".json", ".md", ".py", ".toml", ".yaml", ".yml"}
PYTHON_INTERPRETER = re.compile(
    r'''(?<![\w./-])(?P<quote>["']?)(?:/(?:[^\s/"']+/)*)?'''
    r"python(?:\d+(?:\.\d+)*)?(?P=quote)(?=[ \t]|$)"
)
PYTHON_OPTIONS_WITH_VALUE = {"-W", "-X", "--check-hash-based-pycs"}
TRUSTED_WORKFLOW_SCRIPTS = {
    "<trusted packaged script name.py>",
    "apply_overlay.py",
    "axis_coverage.py",
    "classify_resp.py",
    "confirmation.py",
    "eval_golden.py",
    "lint.py",
    "merge.py",
    "mutate.py",
    "profile_locale.py",
    "publish.py",
    "rebuild_catalogs.py",
    "rebuild_overlay_hipaa.py",
    "render.py",
    "runtime_paths.py",
    "risk.py",
    "safe_paths.py",
    "select_baseline.py",
    "semantic_review.py",
    "validate_overlays.py",
}
TRUSTED_SCRIPT_PREFIXES = (
    "<absolute plugin root>/scripts/",
    "<exact absolute plugin root>/scripts/",
    "<derived absolute candidate>/scripts/",
    "${CLAUDE_PLUGIN_ROOT}/scripts/",
)
SAFE_OUTPUTS = {
    "init": (".security-requirements",),
    "build": (".security-requirements", "docs/security"),
    "refresh": (".security-requirements", "docs/security"),
    "risk": (".security-requirements",),
}
CANONICAL_SAFE_OUTPUT_PREFLIGHTS = {
    workflow: (
        'python3 -I "${CLAUDE_PLUGIN_ROOT}/scripts/safe_paths.py" '
        f'--project-root "$PWD" --check-output {" ".join(outputs)}'
    )
    for workflow, outputs in SAFE_OUTPUTS.items()
}
CANONICAL_SAFE_OUTPUT_PREFLIGHTS_BY_PATH = {
    Path("commands") / f"sec-req-{workflow}.md": command
    for workflow, command in CANONICAL_SAFE_OUTPUT_PREFLIGHTS.items()
}


def _read_json(path: Path, errors: list[str]) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except UnicodeDecodeError as error:
        errors.append(f"cannot decode JSON file: {path}: {error.reason}")
        return {}
    except OSError as error:
        errors.append(f"cannot read JSON file: {path}: {error.strerror or error}")
        return {}
    except json.JSONDecodeError as error:
        errors.append(f"invalid JSON in {path}: {error.msg}")
        return {}
    except TypeError as error:
        errors.append(f"invalid JSON input for {path}: {error}")
        return {}
    if not isinstance(data, dict):
        errors.append(f"JSON object required: {path}")
        return {}
    return data


def _plugin_entry(marketplace: dict, host: str, errors: list[str]) -> dict:
    entries = marketplace.get("plugins")
    if not isinstance(entries, list):
        errors.append(f"{host} marketplace must contain a plugins list")
        return {}
    matches = [entry for entry in entries if isinstance(entry, dict) and entry.get("name") == PLUGIN_NAME]
    if len(matches) != 1:
        errors.append(f"{host} marketplace must declare exactly one {PLUGIN_NAME} entry")
        return {}
    return matches[0]


def _relative_path(value: object, base: Path, label: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not value.startswith("./"):
        errors.append(f"{label} must be a relative path beginning with ./: {value!r}")
        return
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        errors.append(f"{label} must not use an absolute or traversal path: {value}")
        return
    path = base / value
    try:
        path.resolve().relative_to(base.resolve())
    except ValueError:
        errors.append(f"{label} escapes its payload: {value}")
        return
    if not path.exists():
        errors.append(f"missing manifest-declared path for {label}: {path}")


def _is_path_field(name: str) -> bool:
    lowered = name.replace("-", "_").lower()
    return lowered in PATH_FIELD_NAMES or lowered.endswith(
        ("path", "paths", "file", "files", "directory", "directories")
    )


def _path_values(value: object, payload: Path, label: str, errors: list[str]) -> None:
    if isinstance(value, str):
        _relative_path(value, payload, label, errors)
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _path_values(nested, payload, f"{label}[{index}]", errors)
    elif isinstance(value, dict):
        for key, nested in value.items():
            _path_values(nested, payload, f"{label}.{key}", errors)
    else:
        errors.append(f"{label} must contain path strings, lists, or mappings: {value!r}")


def _manifest_paths(
    value: object,
    payload: Path,
    label: str,
    errors: list[str],
    field: str = "",
    inline_context: bool = False,
) -> None:
    normalized_field = field.replace("-", "_").lower()
    if normalized_field in INLINE_OR_PATH_FIELDS and not inline_context:
        if isinstance(value, str):
            _relative_path(value, payload, label, errors)
            return
        if not isinstance(value, (dict, list)):
            errors.append(f"{label} must be a path string or inline configuration: {value!r}")
            return
        _manifest_paths(value, payload, label, errors, inline_context=True)
        return
    if _is_path_field(field):
        _path_values(value, payload, label, errors)
        return
    if isinstance(value, dict):
        for key, nested in value.items():
            _manifest_paths(nested, payload, f"{label}.{key}", errors, key, inline_context)
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _manifest_paths(nested, payload, f"{label}[{index}]", errors, field, inline_context)
    elif isinstance(value, str) and value.startswith("./"):
        _relative_path(value, payload, label, errors)


def _metadata_symlinks(root: Path, errors: list[str]) -> None:
    found: set[Path] = set()
    for relative in METADATA_FILES:
        path = root / relative
        while path != root:
            if path.is_symlink() and path not in found:
                errors.append(
                    f"symlink is not allowed in distribution metadata: {path.relative_to(root)}"
                )
                found.add(path)
            path = path.parent


def _duplicate_runtime_directories(root: Path, payload: Path, errors: list[str]) -> None:
    root_scripts = root / "scripts"
    if root_scripts.is_dir():
        allowed = {"validate_distribution.py", "__pycache__"}
        if any(path.name not in allowed for path in root_scripts.iterdir()):
            errors.append("top-level runtime directory: scripts")
    for directory in RUNTIME_DIRECTORIES[1:]:
        if (root / directory).exists():
            errors.append(f"top-level runtime directory: {directory}")

    for directory in RUNTIME_DIRECTORIES:
        expected = payload / directory
        if not expected.is_dir():
            errors.append(f"missing runtime directory: {expected}")
            continue
        for path in payload.parent.rglob(directory):
            if path.is_dir() and path != expected:
                errors.append(f"duplicate runtime directory: {directory} at {path}")


def _logical_lines(text: str):
    """Yield shell-style logical lines while retaining their first line number."""
    buffered = ""
    start = 1
    for number, line in enumerate(text.splitlines(), start=1):
        if not buffered:
            start = number
        if line.endswith("\\"):
            buffered += line[:-1]
            continue
        yield start, buffered + line
        buffered = ""
    if buffered:
        yield start, buffered


def _python_arguments(command: str, start: int) -> list[str]:
    """Tokenise one Python invocation from its interpreter to the shell boundary."""
    fragment = command[start:]
    prefix = command[:start]
    if "$(" in prefix:
        closing = max(fragment.rfind(')"'), fragment.rfind(")'"))
        if closing >= 0:
            fragment = fragment[:closing]
    try:
        tokens = shlex.split(fragment, posix=True)
    except ValueError:
        prefix = prefix.rstrip()
        stripped = fragment.rstrip()
        if (
            prefix.endswith(("'", '"'))
            and stripped.endswith(prefix[-1])
        ):
            try:
                tokens = shlex.split(stripped[:-1], posix=True)
            except ValueError:
                return []
        else:
            return []
    bounded = []
    for token in tokens:
        if token in {";", "&&", "||", "|"}:
            break
        bounded.append(token.rstrip("`"))
    return bounded


def _python_script(tokens: list[str]) -> tuple[str | None, bool, bool]:
    """Return (script, isolated, inline) for an already-tokenised invocation."""
    isolated = False
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            index += 1
            break
        if token == "-":
            break
        if token == "-c" or token.startswith("-c"):
            return None, isolated, True
        if token == "-m" or token.startswith("-m"):
            return token, isolated, True
        if token in PYTHON_OPTIONS_WITH_VALUE:
            index += 2
            continue
        if token.startswith("-X") or token.startswith("-W"):
            index += 1
            continue
        if token.startswith("-"):
            short_options = token[1:] if not token.startswith("--") else ""
            if token == "-I" or "I" in short_options:
                isolated = True
            if "c" in short_options or "m" in short_options:
                return None, isolated, True
            index += 1
            continue
        break
    script = tokens[index] if index < len(tokens) else None
    if script in (None, "-"):
        return None, isolated, True
    return script, isolated, False


def _trusted_workflow_script(script: str, tokens: list[str]) -> bool:
    matching_prefix = next(
        (prefix for prefix in TRUSTED_SCRIPT_PREFIXES if script.startswith(prefix)), None
    )
    if matching_prefix is None:
        return False
    name = script.removeprefix(matching_prefix)
    if "/" in name or name not in TRUSTED_WORKFLOW_SCRIPTS:
        return False
    if matching_prefix == "${CLAUDE_PLUGIN_ROOT}/scripts/":
        return name == "runtime_paths.py"
    if matching_prefix == "<derived absolute candidate>/scripts/":
        return name == "runtime_paths.py" and "--skill" in tokens
    return True


def _workflow_python_invocations(payload: Path, errors: list[str]) -> None:
    for path in payload.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in TEXT_PAYLOAD_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as error:
            errors.append(f"cannot inspect payload file: {path}: {error}")
            continue
        relative = path.relative_to(payload)
        canonical_preflight = CANONICAL_SAFE_OUTPUT_PREFLIGHTS_BY_PATH.get(relative)
        for line_number, command in _logical_lines(text):
            if command.lstrip().startswith("#!"):
                continue
            for match in PYTHON_INTERPRETER.finditer(command):
                tokens = _python_arguments(command, match.start())
                if not tokens:
                    errors.append(
                        "cannot parse Python invocation in workflow: "
                        f"{relative}:{line_number}"
                    )
                    continue
                script, isolated, inline = _python_script(tokens)
                location = f"{relative}:{line_number}"
                if inline:
                    errors.append(f"inline Python is not allowed in workflow: {location}")
                    continue
                if script.startswith(("scripts/", "./scripts/")):
                    errors.append(f"cwd-relative payload script invocation: {location}")
                    continue
                if not isolated:
                    errors.append(f"workflow Python invocation must use -I: {location}")
                if (
                    not _trusted_workflow_script(script, tokens)
                    and command != canonical_preflight
                ):
                    error = (
                        "workflow Python script is not rooted in the plugin payload: "
                        f"{location}"
                    )
                    if error not in errors:
                        errors.append(error)

            try:
                semantic_tokens = shlex.split(command, posix=True)
            except ValueError:
                continue
            claude_safe_paths_mention = any(
                "CLAUDE_PLUGIN_ROOT" in token.rstrip("`")
                and Path(token.rstrip("`")).name == "safe_paths.py"
                for token in semantic_tokens
            )
            if claude_safe_paths_mention and command != canonical_preflight:
                error = (
                    "workflow Python script is not rooted in the plugin payload: "
                    f"{relative}:{line_number}"
                )
                if error not in errors:
                    errors.append(error)


def _contains_broad_safe_output_preflight(
    command: str, required_outputs: tuple[str, ...]
) -> bool:
    raw_outputs = all(
        re.search(
            rf"(?<![A-Za-z0-9_.-]){re.escape(output)}/?"
            r"(?![A-Za-z0-9_./-])",
            command,
        )
        for output in required_outputs
    )
    if raw_outputs and (
        "safe_paths.py" in command or "--check-output" in command
    ):
        return True

    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return False
    cleaned = [token.rstrip("`") for token in tokens]
    safe_paths_mention = any(Path(token).name == "safe_paths.py" for token in cleaned)
    output_values: list[str] = []
    for index, token in enumerate(cleaned):
        if token == "--check-output":
            output_values = cleaned[index + 1 :]
            break
        if token.startswith("--check-output="):
            output_values = [token.partition("=")[2], *cleaned[index + 1 :]]
            break
    dynamic_output = any(
        re.search(r"[$`*?{}\[\]()]|^~", value) for value in output_values
    )
    if safe_paths_mention and (not output_values or dynamic_output):
        return True
    normalized = {Path(token).as_posix() for token in cleaned}
    normalized.update(
        Path(token.partition("=")[2]).as_posix()
        for token in cleaned
        if token.startswith("--check-output=")
    )
    if not set(required_outputs) <= normalized:
        return False
    output_claim = any(
        token == "--check-output" or token.startswith("--check-output=")
        for token in cleaned
    )
    return safe_paths_mention or output_claim


def _bash_blocks(text: str) -> list[list[str]]:
    """Return executable Markdown bash blocks, excluding comments/nested fences."""
    blocks: list[list[str]] = []
    fence: tuple[str, int, str] | None = None
    content: list[str] = []
    in_html_comment = False

    for line in text.splitlines():
        if fence is not None:
            character, minimum, language = fence
            if re.fullmatch(rf"{re.escape(character)}{{{minimum},}}[ \t]*", line):
                if language == "bash":
                    blocks.append(content)
                fence = None
                content = []
            else:
                content.append(line)
            continue

        if in_html_comment:
            if "-->" in line:
                in_html_comment = False
            continue
        if "<!--" in line:
            if "-->" not in line.split("<!--", 1)[1]:
                in_html_comment = True
            continue

        opening = re.fullmatch(r"(?P<marker>`{3,}|~{3,})(?P<info>.*)", line)
        if opening:
            marker = opening.group("marker")
            fence = (marker[0], len(marker), opening.group("info").strip())
            content = []

    return blocks


def _safe_output_preflights(payload: Path, errors: list[str]) -> None:
    for workflow, required_outputs in SAFE_OUTPUTS.items():
        path = payload / "commands" / f"sec-req-{workflow}.md"
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        canonical = CANONICAL_SAFE_OUTPUT_PREFLIGHTS[workflow]
        candidates = [
            command
            for _, command in _logical_lines(text)
            if _contains_broad_safe_output_preflight(command, required_outputs)
        ]
        valid = (
            candidates == [canonical]
            and _bash_blocks(text).count([canonical]) == 1
        )
        relative = path.relative_to(payload)
        expected = " ".join(required_outputs)
        if valid:
            continue
        if candidates:
            errors.append(
                f"invalid safe output preflight in {relative}: "
                f"--project-root $PWD --check-output {expected}"
            )
        else:
            errors.append(
                f"missing safe output preflight in {relative}: "
                f"--project-root $PWD --check-output {expected}"
            )


def validate(root: Path) -> list[str]:
    """Return every detected packaging error without changing *root*."""
    root = root.resolve()
    errors: list[str] = []
    payload = root / PAYLOAD
    claude_marketplace_path = root / ".claude-plugin" / "marketplace.json"
    codex_marketplace_path = root / ".agents" / "plugins" / "marketplace.json"
    claude_marketplace = _read_json(claude_marketplace_path, errors)
    codex_marketplace = _read_json(codex_marketplace_path, errors)
    _metadata_symlinks(root, errors)
    claude_entry = _plugin_entry(claude_marketplace, "Claude", errors)
    codex_entry = _plugin_entry(codex_marketplace, "Codex", errors)

    expected_source = "./plugins/security-requirements"
    if claude_entry.get("source") != expected_source:
        errors.append(f"Claude marketplace source must be {expected_source}")
    codex_source = codex_entry.get("source")
    if not isinstance(codex_source, dict) or codex_source.get("source") != "local":
        errors.append("Codex marketplace source must be a local source")
    elif codex_source.get("path") != expected_source:
        errors.append(f"Codex marketplace source path must be {expected_source}")

    if codex_marketplace.get("name") != PLUGIN_NAME:
        errors.append(f"Codex marketplace name must equal qualified install marketplace: {PLUGIN_NAME}")
    if f"{codex_entry.get('name')}@{codex_marketplace.get('name')}" != f"{PLUGIN_NAME}@{PLUGIN_NAME}":
        errors.append(f"Codex marketplace must resolve {PLUGIN_NAME}@{PLUGIN_NAME}")

    for host, entry in (("Claude", claude_entry), ("Codex", codex_entry)):
        if entry.get("name") not in (None, payload.name):
            errors.append(f"{host} marketplace name must equal payload folder: {payload.name}")

    manifests = {
        "Claude": _read_json(payload / ".claude-plugin" / "plugin.json", errors),
        "Codex": _read_json(payload / ".codex-plugin" / "plugin.json", errors),
    }
    for host, manifest in manifests.items():
        if manifest.get("name") != payload.name:
            errors.append(f"{host} manifest name must equal payload folder: {payload.name}")
        _manifest_paths(manifest, payload, f"{host} manifest", errors)

    for component in FORBIDDEN_CODEX_COMPONENTS:
        if component in manifests["Codex"]:
            errors.append(f"Codex manifest must not declare {component}")
        if (payload / component).exists():
            errors.append(f"Codex payload must not include {component}")
    for component in (".mcp.json", ".app.json"):
        if (payload / component).exists():
            errors.append(f"Codex payload must not include {component}")

    if payload.is_symlink():
        errors.append(f"symlink is not allowed in payload: {PAYLOAD}")
    elif payload.exists():
        for path in payload.rglob("*"):
            if path.is_symlink():
                errors.append(f"symlink is not allowed in payload: {path.relative_to(root)}")

    _duplicate_runtime_directories(root, payload, errors)
    _workflow_python_invocations(payload, errors)
    _safe_output_preflights(payload, errors)

    for workflow in WORKFLOWS:
        command = payload / "commands" / f"sec-req-{workflow}.md"
        skill = payload / "skills" / f"security-requirements-{workflow}" / "SKILL.md"
        if not command.is_file():
            errors.append(f"missing Claude entry point: {command.relative_to(root)}")
        if not skill.is_file():
            errors.append(f"missing Codex entry point: {skill.relative_to(root)}")
    return errors


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 1:
        print("usage: validate_distribution.py REPOSITORY_ROOT", file=sys.stderr)
        return 2
    errors = validate(Path(arguments[0]))
    for error in errors:
        print(f"error: {error}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
