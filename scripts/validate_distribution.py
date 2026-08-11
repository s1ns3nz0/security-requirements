#!/usr/bin/env python3
"""Validate the source tree that both plugin marketplaces distribute."""

from __future__ import annotations

import json
from pathlib import Path
import sys


PLUGIN_NAME = "security-requirements"
PAYLOAD = Path("plugins") / PLUGIN_NAME
RUNTIME_DIRECTORIES = ("scripts", "catalogs", "overlays", "responsibility")
WORKFLOWS = ("init", "build", "refresh")


def _read_json(path: Path, errors: list[str]) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        errors.append(f"missing JSON file: {path}")
        return {}
    except json.JSONDecodeError as error:
        errors.append(f"invalid JSON in {path}: {error.msg}")
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
    path = base / value
    try:
        path.resolve().relative_to(base.resolve())
    except ValueError:
        errors.append(f"{label} escapes its payload: {value}")
        return
    if not path.exists():
        errors.append(f"missing manifest-declared path: {path}")


def _manifest_paths(value: object, payload: Path, label: str, errors: list[str]) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            _manifest_paths(nested, payload, f"{label}.{key}", errors)
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _manifest_paths(nested, payload, f"{label}[{index}]", errors)
    elif isinstance(value, str) and value.startswith("./"):
        _relative_path(value, payload, label, errors)


def validate(root: Path) -> list[str]:
    """Return every detected packaging error without changing *root*."""
    root = root.resolve()
    errors: list[str] = []
    payload = root / PAYLOAD
    claude_marketplace_path = root / ".claude-plugin" / "marketplace.json"
    codex_marketplace_path = root / ".agents" / "plugins" / "marketplace.json"
    claude_marketplace = _read_json(claude_marketplace_path, errors)
    codex_marketplace = _read_json(codex_marketplace_path, errors)
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

    for path in payload.rglob("*") if payload.exists() else ():
        if path.is_symlink():
            errors.append(f"symlink is not allowed in payload: {path.relative_to(root)}")

    for directory in RUNTIME_DIRECTORIES:
        locations = [path for path in root.rglob(directory) if path.is_dir()]
        expected = payload / directory
        unexpected = [path for path in locations if path != expected and path != root / "scripts"]
        if not expected.is_dir():
            errors.append(f"missing runtime directory: {expected.relative_to(root)}")
        for path in unexpected:
            errors.append(f"duplicate runtime directory: {directory} at {path.relative_to(root)}")

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
