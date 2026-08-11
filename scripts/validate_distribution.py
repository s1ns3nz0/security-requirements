#!/usr/bin/env python3
"""Validate the source tree that both plugin marketplaces distribute."""

from __future__ import annotations

import json
from pathlib import Path
import re
import sys


PLUGIN_NAME = "security-requirements"
PAYLOAD = Path("plugins") / PLUGIN_NAME
RUNTIME_DIRECTORIES = ("scripts", "catalogs", "overlays", "responsibility", "skills")
WORKFLOWS = ("init", "build", "refresh")
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
CWD_RELATIVE_SCRIPT_INVOCATION = re.compile(
    r"(?<![\w./-])python3?"
    r"(?:(?:[ \t]+-[^ \t]+)(?:[ \t]+(?!(?:scripts/))[^- \t][^ \t]*)?)*"
    r"[ \t]+[\"']?scripts/"
)


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


def _cwd_relative_script_invocations(payload: Path, errors: list[str]) -> None:
    for path in payload.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in TEXT_PAYLOAD_SUFFIXES:
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as error:
            errors.append(f"cannot inspect payload file: {path}: {error}")
            continue
        for line_number, line in enumerate(lines, start=1):
            if CWD_RELATIVE_SCRIPT_INVOCATION.search(line):
                errors.append(
                    "cwd-relative payload script invocation: "
                    f"{path.relative_to(payload)}:{line_number}"
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
    _cwd_relative_script_invocations(payload, errors)

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
