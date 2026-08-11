"""Resolve persistent state locations for the security-requirements plugin."""

from __future__ import annotations

import argparse
import os
from collections.abc import Mapping
from pathlib import Path
import sys


PAYLOAD_ROOT = Path(__file__).resolve().parent.parent


def absolute_path(value: str | None) -> Path | None:
    """Expand an absolute path, returning ``None`` for a relative value."""
    if not value:
        return None
    path = Path(value).expanduser()
    return path if path.is_absolute() else None


def inspected_project_root(profile_path: Path) -> Path:
    """Return the target project bound to a profile path."""
    path = profile_path.expanduser()
    parent = path.parent
    project = parent.parent if parent.name == ".security-requirements" else parent
    return project.resolve()


def plugin_root_from_skill(
    skill_path: Path, ambient_root: Path | None = None
) -> Path:
    """Derive this payload from one loader-selected skill, never ambient state."""
    selected = skill_path.expanduser()
    if not selected.is_absolute():
        raise ValueError("selected SKILL.md path must be absolute")
    try:
        selected = selected.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"cannot resolve selected SKILL.md: {exc}") from exc
    expected_parent = PAYLOAD_ROOT / "skills" / selected.parent.name / "SKILL.md"
    if selected != expected_parent:
        raise ValueError("selected SKILL.md does not belong to this plugin payload")
    if ambient_root is not None:
        ambient = ambient_root.expanduser()
        ambient_lexical = (
            Path(os.path.abspath(ambient)) if ambient.is_absolute() else ambient
        )
        if (
            not ambient.is_absolute()
            or ambient_lexical != PAYLOAD_ROOT
            or ambient.resolve() != PAYLOAD_ROOT
        ):
            raise ValueError("ambient plugin root does not match selected SKILL.md")
    return PAYLOAD_ROOT


def plugin_data_root(
    env: Mapping[str, str] | None = None,
    platform: str | None = None,
    project_root: Path | None = None,
) -> Path:
    """Return the plugin state root without creating it.

    The neutral environment variable is preferred so the plugin can run under
    any host. ``CLAUDE_PLUGIN_DATA`` remains a compatibility fallback.
    """
    variables = os.environ if env is None else env
    source = "default plugin state root"
    for name in ("SECURITY_REQUIREMENTS_DATA", "CLAUDE_PLUGIN_DATA"):
        if value := variables.get(name):
            path = absolute_path(value)
            if path is None:
                raise ValueError(f"{name} must be an absolute path")
            source = name
            break
    else:
        current_platform = sys.platform if platform is None else platform
        if current_platform.startswith("win"):
            base = absolute_path(variables.get("LOCALAPPDATA"))
            if base is None:
                base = Path.home() / "AppData" / "Local"
        elif current_platform == "darwin":
            base = Path.home() / "Library" / "Application Support"
        else:
            base = absolute_path(variables.get("XDG_STATE_HOME"))
            if base is None:
                base = Path.home() / ".local" / "state"
        path = base.expanduser() / "security-requirements" / "v1"

    lexical = Path(os.path.abspath(path.expanduser()))
    resolved = lexical.resolve()
    if project_root is not None:
        project_lexical = Path(os.path.abspath(project_root.expanduser()))
        project = project_lexical.resolve()
        if (
            lexical == project_lexical
            or lexical.is_relative_to(project_lexical)
            or resolved == project
            or resolved.is_relative_to(project)
        ):
            raise ValueError(f"{source} must be outside the inspected project")
    return resolved


def main(argv: list[str] | None = None) -> int:
    """Print one canonical runtime root for host adapters."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--skill", type=Path)
    parser.add_argument("--ambient-root", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.skill:
            ambient_root = args.ambient_root
            if ambient_root is None and os.environ.get("SECURITY_REQUIREMENTS_ROOT"):
                ambient_root = Path(os.environ["SECURITY_REQUIREMENTS_ROOT"])
            root = plugin_root_from_skill(args.skill, ambient_root)
        else:
            if args.ambient_root:
                parser.error("--ambient-root requires --skill")
            root = plugin_data_root(project_root=args.project_root)
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1
    print(root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
