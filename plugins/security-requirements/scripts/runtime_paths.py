"""Resolve persistent state locations for the security-requirements plugin."""

from __future__ import annotations

import argparse
import hashlib
import os
from collections.abc import Mapping
from pathlib import Path
import shlex
import sys


PAYLOAD_ROOT = Path(__file__).resolve().parent.parent
MINIMUM_PYTHON = (3, 12)


def _absolute_lexical(path: Path) -> Path:
    return Path(os.path.abspath(path.expanduser()))


def _lexically_contained(candidate: Path, project: Path) -> bool:
    return candidate == project or candidate.is_relative_to(project)


def path_is_within_project(candidate: Path, project_root: Path) -> bool:
    """Return whether a path is lexically, resolved, or physically project-owned."""
    candidate_lexical = _absolute_lexical(candidate)
    project_lexical = _absolute_lexical(project_root)
    if _lexically_contained(candidate_lexical, project_lexical):
        return True

    candidates = [candidate_lexical]
    try:
        candidate_resolved = candidate_lexical.resolve()
        project_resolved = project_lexical.resolve()
    except (OSError, RuntimeError):
        pass
    else:
        if _lexically_contained(candidate_resolved, project_resolved):
            return True
        candidates.append(candidate_resolved)

    inspected: set[Path] = set()
    for path in candidates:
        for ancestor in (path, *path.parents):
            if ancestor in inspected or not ancestor.exists():
                continue
            inspected.add(ancestor)
            try:
                if os.path.samefile(ancestor, project_lexical):
                    return True
            except OSError:
                continue
    return False


def isolated_script_command(script_name: str, *arguments: str) -> str:
    """Return a shell-safe command for one trusted packaged script."""
    if Path(script_name).name != script_name:
        raise ValueError("packaged script name must not contain a path")
    scripts = (PAYLOAD_ROOT / "scripts").resolve()
    script = (scripts / script_name).resolve(strict=True)
    if not script.is_file() or not script.is_relative_to(scripts):
        raise ValueError("packaged script must remain under the trusted scripts root")
    return shlex.join(
        [str(Path(sys.executable).resolve()), "-I", str(script), *arguments]
    )


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

    lexical = _absolute_lexical(path)
    resolved = lexical.resolve()
    if project_root is not None:
        if path_is_within_project(lexical, project_root):
            raise ValueError(f"{source} must be outside the inspected project")
    return resolved


def confirmation_state_path(project_root: Path, kind: str) -> Path:
    """Return one project-bound external risk-confirmation state path."""
    kind_path = Path(kind)
    if kind_path.name != kind or kind in {"", ".", ".."}:
        raise ValueError("confirmation kind must be one path component")
    project = project_root.resolve()
    key = hashlib.sha256(str(project).encode()).hexdigest()
    root = plugin_data_root(project_root=project_root)
    target = root / "risk" / kind / f"{key}.yaml"
    if path_is_within_project(target, project_root):
        raise ValueError(f"{kind} confirmation state must remain outside the project")
    return target


def main(argv: list[str] | None = None) -> int:
    """Print one canonical runtime root for host adapters."""
    if sys.version_info < MINIMUM_PYTHON:
        print(
            "error: security-requirements requires Python 3.12 or newer",
            file=sys.stderr,
        )
        return 2
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
