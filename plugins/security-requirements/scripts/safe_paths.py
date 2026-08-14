#!/usr/bin/env python3
"""Validate and atomically write output paths without filesystem redirects."""

from __future__ import annotations

import argparse
import os
from pathlib import Path, PurePath
import tempfile
import sys


MINIMUM_PYTHON = (3, 12)


class UnsafePathError(ValueError):
    """A target path could follow a repository-controlled redirect."""


class SafePathsArgumentError(ValueError):
    """The safe-path command line does not match its strict grammar."""


class _StrictArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise SafePathsArgumentError(message)


class _StoreOnce(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None) -> None:
        if getattr(namespace, self.dest, None) is not None:
            raise argparse.ArgumentError(
                self, f"{option_string or self.dest} may be specified only once"
            )
        setattr(namespace, self.dest, values)


def argument_parser() -> argparse.ArgumentParser:
    """Return the shared strict parser for runtime and distribution checks."""
    parser = _StrictArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--project-root", type=Path, action=_StoreOnce)
    parser.add_argument(
        "--check-output", type=Path, nargs="+", required=True, action=_StoreOnce
    )
    return parser


def _absolute_lexical(path: Path, base: Path | None = None) -> Path:
    value = path.expanduser()
    if not value.is_absolute():
        value = (Path.cwd() if base is None else base) / value
    return Path(os.path.abspath(value))


def _reject_parent_segments(path: Path, label: str) -> None:
    if ".." in path.expanduser().parts:
        raise UnsafePathError(f"{label} contains a parent path segment: {path}")


def _relative_parts_exact(path: PurePath, anchor: PurePath) -> tuple[str, ...]:
    """Return relative parts only when every anchor component matches exactly."""
    anchor_parts = anchor.parts
    path_parts = path.parts
    if path_parts[: len(anchor_parts)] != anchor_parts:
        raise ValueError(f"{path} lacks exact component prefix {anchor}")
    return path_parts[len(anchor_parts) :]


def _inferred_project_root(target: Path) -> Path:
    parts = target.parts
    for index, part in enumerate(parts):
        if part == ".security-requirements":
            return Path(*parts[:index])
        if part == "docs" and index + 1 < len(parts) and parts[index + 1] == "security":
            return Path(*parts[:index])
    return target.parent


def _is_redirect(path: Path) -> bool:
    """Return whether *path* is a symlink or a supported junction."""
    return path.is_symlink() or path.is_junction()


def safe_path(path: Path, project_root: Path | None = None) -> Path:
    """Return a contained absolute path after rejecting filesystem redirects."""
    _reject_parent_segments(path, "output path")
    if project_root is not None:
        _reject_parent_segments(project_root, "project root")
    root = _absolute_lexical(project_root) if project_root is not None else None
    target = _absolute_lexical(path, root)
    anchor = root or _inferred_project_root(target)
    try:
        relative_parts = _relative_parts_exact(target, anchor)
    except ValueError as exc:
        raise UnsafePathError(f"output path escapes project root: {target}") from exc

    if _is_redirect(anchor):
        raise UnsafePathError(
            f"project root is a symlink or junction: {anchor}"
        )

    current = anchor
    for part in relative_parts:
        current = current / part
        if _is_redirect(current):
            raise UnsafePathError(
                f"output path contains a symlink or junction: {current}"
            )

    try:
        resolved_target = target.resolve()
        resolved_anchor = anchor.resolve()
        _relative_parts_exact(resolved_target, resolved_anchor)
    except (OSError, RuntimeError, ValueError) as exc:
        raise UnsafePathError(
            f"resolved output path escapes project root: {target}"
        ) from exc
    return target


def preflight_output_paths(
    paths: list[Path] | tuple[Path, ...], project_root: Path | None = None
) -> list[Path]:
    """Validate a complete output set before any member is written."""
    return [safe_path(path, project_root=project_root) for path in paths]


def safe_mkdir(path: Path, project_root: Path | None = None) -> Path:
    target = safe_path(path, project_root=project_root)
    target.mkdir(parents=True, exist_ok=True)
    return safe_path(target, project_root=project_root)


def safe_write_text(
    path: Path,
    text: str,
    *,
    encoding: str = "utf-8",
    project_root: Path | None = None,
    create_parents: bool = False,
) -> Path:
    """Atomically replace a validated regular output without following symlinks."""
    target = safe_path(path, project_root=project_root)
    if create_parents:
        safe_mkdir(target.parent, project_root=project_root)
    else:
        safe_path(target.parent, project_root=project_root)

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding=encoding) as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        safe_path(target, project_root=project_root)
        os.replace(temporary, target)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return target


def main(argv: list[str] | None = None) -> int:
    if sys.version_info < MINIMUM_PYTHON:
        print(
            "error: security-requirements requires Python 3.12 or newer",
            file=sys.stderr,
        )
        return 2
    try:
        args = argument_parser().parse_args(argv)
        project_root = args.project_root or Path.cwd()
        preflight_output_paths(args.check_output, project_root=project_root)
    except (SafePathsArgumentError, UnsafePathError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
