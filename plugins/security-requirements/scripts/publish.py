#!/usr/bin/env python3
"""Publish validated security documents as one recoverable transaction."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys
import tempfile
from collections.abc import Mapping, Sequence

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import risk  # noqa: E402
from runtime_paths import plugin_data_root  # noqa: E402
from safe_paths import (  # noqa: E402
    UnsafePathError,
    safe_mkdir,
    safe_path,
    safe_write_text,
)


MINIMUM_PYTHON = (3, 12)
PUBLIC_ROOT = Path("docs/security")
CONTROLLED_STAGING_ROOTS = (Path(".security-requirements"), PUBLIC_ROOT)
BASE_MANAGED_FILES = (
    "requirements.md",
    "traceability.md",
    "responsibility.md",
)
RISK_SUMMARY_FILE = "risk-summary.md"
PLUGIN_MANAGED_FILES = {
    *BASE_MANAGED_FILES,
    RISK_SUMMARY_FILE,
}
STATE_VERSION = "1.0.0"
COPY_PLATFORM = os.name


class PublicationError(ValueError):
    """Raised when a publication transaction cannot be made safely."""


class PublicationArgumentError(ValueError):
    """Raised when the publication CLI does not match its strict grammar."""


class _StrictArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise PublicationArgumentError(message)


class _StoreOnce(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None) -> None:
        if getattr(namespace, self.dest, None) is not None:
            raise argparse.ArgumentError(
                self, f"{option_string or self.dest} may be specified only once"
            )
        setattr(namespace, self.dest, values)


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(path.expanduser()))


def _relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _managed_names(values: Sequence[str]) -> tuple[PurePosixPath, ...]:
    if isinstance(values, (str, bytes)):
        raise PublicationError("publication requires the exact managed file set")
    result: list[PurePosixPath] = []
    seen: set[str] = set()
    for value in values:
        if not isinstance(value, str) or not value.strip():
            raise PublicationError("managed file names must be non-empty strings")
        if "\\" in value:
            raise PublicationError(f"managed file must use a relative POSIX path: {value}")
        name = PurePosixPath(value)
        if name.is_absolute() or name == PurePosixPath(".") or ".." in name.parts:
            raise PublicationError(f"managed file must be a contained relative path: {value}")
        canonical = name.as_posix()
        if canonical not in PLUGIN_MANAGED_FILES:
            raise PublicationError(f"public file is not plugin-managed: {canonical}")
        if canonical in seen:
            raise PublicationError("publication requires the exact managed file set")
        seen.add(canonical)
        result.append(name)
    expected = set(BASE_MANAGED_FILES)
    if seen not in (expected, expected | {RISK_SUMMARY_FILE}):
        raise PublicationError("publication requires the exact managed file set")
    ordered = BASE_MANAGED_FILES + (
        (RISK_SUMMARY_FILE,) if RISK_SUMMARY_FILE in seen else ()
    )
    return tuple(PurePosixPath(name) for name in ordered)


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _walk_is_safe(root: Path, project_root: Path) -> None:
    safe_path(root, project_root=project_root)
    if not root.exists():
        return
    if not root.is_dir():
        raise PublicationError(f"public output root is not a directory: {root}")
    for member in root.rglob("*"):
        safe_path(member, project_root=project_root)
        if not member.is_dir() and not member.is_file():
            raise PublicationError(f"public output contains a special file: {member}")


def _publication_state_target(project_root: Path) -> tuple[Path, Path]:
    state_root = plugin_data_root(project_root=project_root)
    project_key = hashlib.sha256(str(project_root.resolve()).encode()).hexdigest()
    state_path = state_root / "publication" / f"{project_key}.yaml"
    safe_path(state_path, project_root=state_root)
    return state_root, state_path


def _load_state(state_path: Path, state_root: Path) -> dict[str, str]:
    safe_path(state_path, project_root=state_root)
    if not state_path.exists():
        return {}
    document = yaml.safe_load(state_path.read_text(encoding="utf-8"))
    if not isinstance(document, Mapping):
        raise PublicationError("publication state must be a mapping")
    if document.get("version") != STATE_VERSION:
        raise PublicationError("publication state version is unsupported")
    managed = document.get("managed_files")
    if not isinstance(managed, Mapping):
        raise PublicationError("publication state managed_files must be a mapping")
    names = _managed_names(tuple(managed))
    result: dict[str, str] = {}
    for name in names:
        digest = managed[name.as_posix()]
        if (
            not isinstance(digest, str)
            or not digest.startswith("sha256:")
            or len(digest) != 71
        ):
            raise PublicationError(
                f"publication state digest is invalid: {name.as_posix()}"
            )
        result[name.as_posix()] = digest
    return result


def _load_risk_documents(project_root: Path) -> tuple[dict, dict, dict]:
    paths = _risk_paths(project_root)
    problems = risk.check_policy(paths)
    for problem in risk.check_assessment(paths):
        if problem not in problems:
            problems.append(problem)
    if problems:
        raise PublicationError("risk publication gate: " + "; ".join(problems))
    policy = risk.load_policy(paths["policy"])
    threats = yaml.safe_load(paths["threats"].read_text(encoding="utf-8"))
    assessment = yaml.safe_load(paths["assessment"].read_text(encoding="utf-8"))
    if not isinstance(threats, dict) or not isinstance(assessment, dict):
        raise PublicationError("risk publication documents must be mappings")
    return policy, threats, assessment


def _authoritative_summary_bytes(project_root: Path) -> bytes:
    policy, threats, assessment = _load_risk_documents(project_root)
    if policy.get("publish_risk_summary") is not True:
        raise PublicationError(
            "confirmed policy does not enable publish_risk_summary"
        )
    rendered = risk.render_public_summary(
        {"inherent": risk.aggregate_risk(threats, assessment)}, policy
    )
    if rendered is None:
        raise PublicationError("confirmed policy does not enable publish_risk_summary")
    return rendered.encode("utf-8")


def _state_text(managed: Mapping[str, str]) -> str:
    return yaml.safe_dump(
        {"version": STATE_VERSION, "managed_files": dict(sorted(managed.items()))},
        allow_unicode=True,
        sort_keys=False,
    )


def _temporary_directory(project_root: Path, prefix: str) -> Path:
    path = Path(tempfile.mkdtemp(prefix=prefix, dir=project_root))
    return safe_path(path, project_root=project_root)


def _unused_directory_path(parent: Path, project_root: Path, prefix: str) -> Path:
    path = Path(tempfile.mkdtemp(prefix=prefix, dir=parent))
    path.rmdir()
    return safe_path(path, project_root=project_root)


def _is_redirect_stat(metadata: os.stat_result) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & reparse_flag
    )


def _remove_tree(path: Path, project_root: Path) -> None:
    """Remove a contained tree or redirect object without following its target."""

    lexical = _absolute(Path(path))
    root = _absolute(Path(project_root))
    try:
        lexical.relative_to(root)
    except ValueError as exc:
        raise UnsafePathError(f"cleanup path escapes project root: {lexical}") from exc
    safe_path(lexical.parent, project_root=root)
    try:
        metadata = os.lstat(lexical)
    except FileNotFoundError:
        return
    if _is_redirect_stat(metadata):
        try:
            os.unlink(lexical)
        except (IsADirectoryError, PermissionError):
            # Windows directory junctions/reparse points are removed as the
            # link object itself with rmdir. This never walks their target.
            os.rmdir(lexical)
        return
    safe_path(lexical, project_root=root)
    if stat.S_ISDIR(metadata.st_mode):
        shutil.rmtree(lexical)
    else:
        os.unlink(lexical)


def _best_effort_remove_tree(path: Path, project_root: Path) -> None:
    try:
        _remove_tree(path, project_root)
    except BaseException:
        # The publication is already committed (or the previous tree already
        # restored). A leftover recovery directory is safer than reporting a
        # failure whose visible output has in fact changed.
        pass


def _require_no_follow_copy_support() -> tuple[int, int]:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory_only = getattr(os, "O_DIRECTORY", 0)
    if COPY_PLATFORM != "posix" or not nofollow or not directory_only:
        # Python does not expose an equivalent atomic no-follow directory-open
        # contract for Windows junctions/reparse points. Fail before reading
        # staged bytes or creating a candidate tree.
        raise PublicationError(
            f"no-follow tree copying is unsupported on platform {COPY_PLATFORM}"
        )
    return nofollow, directory_only


def _tree_manifest_no_follow(root: Path) -> tuple[tuple[str, str, str], ...]:
    """Return an exact, no-follow manifest of regular files and directories."""

    nofollow, directory_only = _require_no_follow_copy_support()
    directory_flags = os.O_RDONLY | directory_only | nofollow
    root_fd = os.open(root, directory_flags)
    entries: list[tuple[str, str, str]] = []

    def inspect_directory(read_fd: int, prefix: PurePosixPath) -> None:
        for name in sorted(os.listdir(read_fd)):
            member = prefix / name
            member_name = member.as_posix()
            source_stat = os.stat(name, dir_fd=read_fd, follow_symlinks=False)
            if stat.S_ISLNK(source_stat.st_mode):
                raise UnsafePathError(
                    f"source tree contains a symlink: {member_name}"
                )
            if stat.S_ISDIR(source_stat.st_mode):
                entries.append(("directory", member_name, ""))
                child = os.open(name, directory_flags, dir_fd=read_fd)
                try:
                    inspect_directory(child, member)
                finally:
                    os.close(child)
                continue
            if not stat.S_ISREG(source_stat.st_mode):
                raise PublicationError(
                    f"source tree contains a special file: {member_name}"
                )
            source = os.open(name, os.O_RDONLY | nofollow, dir_fd=read_fd)
            try:
                opened_stat = os.fstat(source)
                if (
                    not stat.S_ISREG(opened_stat.st_mode)
                    or (opened_stat.st_dev, opened_stat.st_ino)
                    != (source_stat.st_dev, source_stat.st_ino)
                ):
                    raise UnsafePathError(
                        f"source file changed while inspecting: {member_name}"
                    )
                digest = hashlib.sha256()
                while chunk := os.read(source, 1024 * 1024):
                    digest.update(chunk)
                entries.append(("file", member_name, digest.hexdigest()))
            finally:
                os.close(source)

    try:
        inspect_directory(root_fd, PurePosixPath())
    finally:
        os.close(root_fd)
    return tuple(entries)


def _tree_matches(
    root: Path,
    expected: tuple[tuple[str, str, str], ...],
    project_root: Path,
) -> bool:
    try:
        safe_path(root, project_root=project_root)
        return root.is_dir() and _tree_manifest_no_follow(root) == expected
    except (OSError, PublicationError, UnsafePathError):
        return False


def _copy_tree_no_follow(source: Path, destination: Path, **kwargs) -> Path:
    """Copy a tree without following redirects at the file-open boundary."""

    dirs_exist_ok = kwargs.pop("dirs_exist_ok", False)
    if kwargs:
        raise TypeError(f"unsupported copy options: {', '.join(sorted(kwargs))}")
    nofollow, directory_only = _require_no_follow_copy_support()
    directory_flags = os.O_RDONLY | directory_only | nofollow

    if destination.exists():
        if not dirs_exist_ok:
            raise FileExistsError(destination)
    else:
        destination.mkdir(mode=0o700)

    source_fd = os.open(source, directory_flags)
    destination_fd = os.open(destination, directory_flags)

    def copy_directory(read_fd: int, write_fd: int) -> None:
        for name in os.listdir(read_fd):
            source_stat = os.stat(name, dir_fd=read_fd, follow_symlinks=False)
            if stat.S_ISLNK(source_stat.st_mode):
                raise UnsafePathError(f"source tree contains a symlink: {name}")
            if stat.S_ISDIR(source_stat.st_mode):
                os.mkdir(name, mode=0o700, dir_fd=write_fd)
                child_read = os.open(name, directory_flags, dir_fd=read_fd)
                child_write = os.open(name, directory_flags, dir_fd=write_fd)
                try:
                    copy_directory(child_read, child_write)
                finally:
                    os.close(child_write)
                    os.close(child_read)
                continue
            if not stat.S_ISREG(source_stat.st_mode):
                raise PublicationError(f"source tree contains a special file: {name}")

            read_file = os.open(name, os.O_RDONLY | nofollow, dir_fd=read_fd)
            try:
                opened_stat = os.fstat(read_file)
                if (
                    not stat.S_ISREG(opened_stat.st_mode)
                    or (opened_stat.st_dev, opened_stat.st_ino)
                    != (source_stat.st_dev, source_stat.st_ino)
                ):
                    raise UnsafePathError(
                        f"source file changed while copying: {name}"
                    )
                write_file = os.open(
                    name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow,
                    source_stat.st_mode & 0o777,
                    dir_fd=write_fd,
                )
                try:
                    while chunk := os.read(read_file, 1024 * 1024):
                        view = memoryview(chunk)
                        while view:
                            written = os.write(write_file, view)
                            view = view[written:]
                    os.fsync(write_file)
                finally:
                    os.close(write_file)
            finally:
                os.close(read_file)

    try:
        copy_directory(source_fd, destination_fd)
    finally:
        os.close(destination_fd)
        os.close(source_fd)
    return destination


def _public_tree_state(
    public_root: Path,
    project_root: Path,
    old_manifest: tuple[tuple[str, str, str], ...] | None,
    new_manifest: tuple[tuple[str, str, str], ...],
) -> str:
    if old_manifest is not None and _tree_matches(
        public_root, old_manifest, project_root
    ):
        return "old"
    if _tree_matches(public_root, new_manifest, project_root):
        return "new"
    try:
        safe_path(public_root, project_root=project_root)
    except (OSError, UnsafePathError):
        return "unknown"
    return "absent" if not public_root.exists() else "unknown"


def _move_previous_tree_to_backup(
    public_root: Path,
    backup: Path,
    old_recovery: Path,
    project_root: Path,
    old_manifest: tuple[tuple[str, str, str], ...],
) -> None:
    """Move the old tree aside, resolving replace-then-raise ambiguity."""

    try:
        os.replace(public_root, backup)
    except BaseException as move_error:
        if _tree_matches(backup, old_manifest, project_root):
            try:
                safe_path(public_root, project_root=project_root)
            except (OSError, UnsafePathError):
                pass
            else:
                if not public_root.exists():
                    return
        if _tree_matches(public_root, old_manifest, project_root):
            raise move_error
        # Never propagate the ambiguous rename error while the canonical path
        # is absent. A verified old backup means the move did commit and it is
        # safe to continue to candidate activation.
        if _tree_matches(backup, old_manifest, project_root):
            return
        # The rename committed but the destination no longer matches the old
        # bytes. Restore the canonical path from the separately verified old
        # recovery snapshot before reporting failure.
        if _tree_matches(old_recovery, old_manifest, project_root):
            try:
                if _public_tree_state(
                    public_root, project_root, old_manifest, ()
                ) != "absent":
                    _remove_tree(public_root, project_root)
                _copy_tree_no_follow(old_recovery, public_root)
            except BaseException:
                state = _public_tree_state(
                    public_root, project_root, old_manifest, ()
                )
                if state == "old":
                    raise move_error
                if state != "absent":
                    try:
                        _remove_tree(public_root, project_root)
                    except BaseException:
                        state = _public_tree_state(
                            public_root, project_root, old_manifest, ()
                        )
                if state == "absent" or _public_tree_state(
                    public_root, project_root, old_manifest, ()
                ) == "absent":
                    try:
                        os.replace(old_recovery, public_root)
                    except BaseException:
                        pass
            if _tree_matches(public_root, old_manifest, project_root):
                raise move_error
        raise PublicationError(
            "cannot determine the state of the previous public-tree move"
        ) from move_error


def _restore_public_root(
    public_root: Path,
    backup: Path,
    old_recovery: Path | None,
    displaced_slot: Path,
    recovery_slots: tuple[Path, Path],
    project_root: Path,
    old_manifest: tuple[tuple[str, str, str], ...] | None,
    new_manifest: tuple[tuple[str, str, str], ...],
) -> str:
    """Return ``old`` after rollback or ``new`` after verified commit-forward.

    Only an exact manifest match can select either result. Hidden backups and
    recovery artifacts are retained whenever the new tree remains committed.
    """

    state = _public_tree_state(
        public_root, project_root, old_manifest, new_manifest
    )
    if state == "old":
        return "old"

    displaced: Path | None = None
    outcome: str | None = None
    if state != "absent":
        try:
            displaced = safe_path(displaced_slot, project_root=project_root)
            if os.path.lexists(displaced):
                raise PublicationError("reserved displaced-tree slot is occupied")
        except BaseException:
            if state == "new":
                return "new"
            # An incomplete/unknown tree is not a valid commit-forward result.
            # It has no publication value, so remove it and recover the old
            # canonical state without first allocating an artifact path.
            try:
                _remove_tree(public_root, project_root)
            except BaseException as remove_error:
                if _public_tree_state(
                    public_root, project_root, old_manifest, new_manifest
                ) == "new":
                    return "new"
                raise PublicationError(
                    "cannot remove an incomplete committed public tree"
                ) from remove_error
        else:
            safe_path(public_root, project_root=project_root)
            safe_path(displaced, project_root=project_root)
            try:
                os.replace(public_root, displaced)
            except BaseException:
                after_move = _public_tree_state(
                    public_root, project_root, old_manifest, new_manifest
                )
                if after_move == "old":
                    return "old"
                if after_move == "absent":
                    # The rename committed before reporting failure. Inspect
                    # the displaced tree at its actual location. Inspection
                    # failure cannot strand the canonical path absent; the
                    # verified old backup below remains authoritative.
                    try:
                        _tree_manifest_no_follow(displaced)
                    except BaseException:
                        pass
                elif after_move == "new":
                    # The rename did not commit. Preserve the live new tree in
                    # a recovery copy before removing it for rollback.
                    try:
                        _copy_tree_no_follow(public_root, displaced)
                        if not _tree_matches(displaced, new_manifest, project_root):
                            raise PublicationError(
                                "recovery copy does not match the committed tree"
                            )
                    except BaseException:
                        # Copying did not mutate the canonical tree. Only an
                        # exact reinspection may select commit-forward success.
                        if _public_tree_state(
                            public_root,
                            project_root,
                            old_manifest,
                            new_manifest,
                        ) == "new":
                            return "new"
                        raise
                    try:
                        _remove_tree(public_root, project_root)
                    except BaseException:
                        after_remove = _public_tree_state(
                            public_root,
                            project_root,
                            old_manifest,
                            new_manifest,
                        )
                        if after_remove == "new":
                            return "new"
                        if after_remove == "old":
                            return "old"
                        # A failed recursive removal may have partially changed
                        # the tree. Retry only after proving it is neither
                        # complete expected tree; then restore the old backup.
                        try:
                            _remove_tree(public_root, project_root)
                        except BaseException as retry_error:
                            after_retry = _public_tree_state(
                                public_root,
                                project_root,
                                old_manifest,
                                new_manifest,
                            )
                            if after_retry == "new":
                                return "new"
                            if after_retry == "old":
                                return "old"
                            if after_retry != "absent":
                                raise PublicationError(
                                    "cannot clear a partially removed public tree"
                                ) from retry_error
                else:
                    try:
                        _remove_tree(public_root, project_root)
                    except BaseException as remove_error:
                        raise PublicationError(
                            "cannot remove an incomplete committed public tree"
                        ) from remove_error
    try:
        if old_manifest is None:
            state = _public_tree_state(
                public_root, project_root, old_manifest, new_manifest
            )
            if state == "absent":
                outcome = "old"
                return outcome
            if state == "new":
                outcome = "new"
                return outcome
            raise PublicationError("cannot restore the previously absent public tree")

        def verified_restore_source() -> Path | None:
            if _tree_matches(backup, old_manifest, project_root):
                return backup
            if old_recovery is not None and _tree_matches(
                old_recovery, old_manifest, project_root
            ):
                return old_recovery
            return None

        def install_from_verified_copy(
            recovery: Path,
        ) -> tuple[str, BaseException | None]:
            """Attempt restoration without consuming the authoritative source."""

            restore_source = verified_restore_source()
            if restore_source is None:
                return (
                    _public_tree_state(
                        public_root, project_root, old_manifest, new_manifest
                    ),
                    PublicationError(
                        "verified previous public-tree recovery is missing"
                    ),
                )

            safe_path(restore_source, project_root=project_root)
            attempt_error: BaseException | None = None
            try:
                if os.path.lexists(recovery):
                    _remove_tree(recovery, project_root)
                safe_path(recovery, project_root=project_root)
                _copy_tree_no_follow(restore_source, recovery)
                if not _tree_matches(recovery, old_manifest, project_root):
                    raise PublicationError(
                        "recovery copy does not match the previous public tree"
                    )
                safe_path(public_root, project_root=project_root)
                try:
                    # Move only the disposable verified copy. The backup and
                    # independent snapshot remain available across a
                    # check-to-rename mutation race.
                    os.replace(recovery, public_root)
                except BaseException as recovery_error:
                    attempt_error = recovery_error
            except BaseException as recovery_error:
                attempt_error = recovery_error
            finally:
                _best_effort_remove_tree(recovery, project_root)

            return (
                _public_tree_state(
                    public_root, project_root, old_manifest, new_manifest
                ),
                attempt_error,
            )

        def clear_invalid_canonical() -> str:
            current = _public_tree_state(
                public_root, project_root, old_manifest, new_manifest
            )
            if current in {"old", "new", "absent"}:
                return current
            try:
                _remove_tree(public_root, project_root)
            except BaseException as remove_error:
                current = _public_tree_state(
                    public_root, project_root, old_manifest, new_manifest
                )
                if current in {"old", "new", "absent"}:
                    return current
                raise PublicationError(
                    "cannot clear a mutated rollback tree"
                ) from remove_error
            return _public_tree_state(
                public_root, project_root, old_manifest, new_manifest
            )

        state, first_restore_error = install_from_verified_copy(recovery_slots[0])
        if state in {"old", "new"}:
            outcome = state
            return outcome

        # A successful rename is not a commit boundary: its source may have
        # changed after validation. Remove only the invalid canonical copy,
        # then reselect a currently exact source and retry once. Both original
        # sources were preserved because only disposable copies are renamed.
        state = clear_invalid_canonical()
        if state in {"old", "new"}:
            outcome = state
            return outcome
        if state != "absent":
            raise PublicationError("rollback did not clear the invalid public tree")

        state, second_restore_error = install_from_verified_copy(recovery_slots[1])
        if state in {"old", "new"}:
            outcome = state
            return outcome

        state = clear_invalid_canonical()
        if state in {"old", "new"}:
            outcome = state
            return outcome
        restore_error = second_restore_error or first_restore_error
        raise PublicationError(
            "rollback did not produce a verified public tree"
        ) from restore_error
    finally:
        if displaced is not None and outcome == "old":
            _best_effort_remove_tree(displaced, project_root)


def stage_and_publish(
    project_root: Path, generated: Path, managed_files: tuple[str, ...]
) -> None:
    """Replace the complete managed public set or leave prior public bytes intact.

    ``generated`` must be a staging directory outside the two repository-owned
    output trees. Files not named by ``managed_files`` are carried forward. A
    previously managed file is removed only while its bytes still match the
    digest-bound ownership record; a human-modified file is preserved.
    """

    project = _absolute(Path(project_root))
    safe_path(project, project_root=project)
    if not project.is_dir():
        raise PublicationError(f"project root is not a directory: {project}")
    _require_no_follow_copy_support()

    staging = _absolute(Path(generated))
    safe_path(staging, project_root=staging)
    if not staging.is_dir():
        raise PublicationError(f"generated staging directory does not exist: {staging}")
    for controlled in CONTROLLED_STAGING_ROOTS:
        controlled_root = _absolute(project / controlled)
        if _relative_to(staging, controlled_root):
            raise PublicationError(
                "generated staging must remain outside repository-controlled output trees"
            )

    desired_names = _managed_names(managed_files)
    desired: dict[str, bytes] = {}
    for name in desired_names:
        if name.as_posix() == RISK_SUMMARY_FILE:
            desired[RISK_SUMMARY_FILE] = _authoritative_summary_bytes(project)
            continue
        source = safe_path(staging / Path(*name.parts), project_root=staging)
        if not source.is_file():
            raise FileNotFoundError(f"managed staged file is missing: {name.as_posix()}")
        desired[name.as_posix()] = source.read_bytes()

    public_root = safe_path(project / PUBLIC_ROOT, project_root=project)
    state_root, state_path = _publication_state_target(project)
    _walk_is_safe(public_root, project)
    previous_managed = _load_state(state_path, state_root)
    previous_state_bytes = (
        state_path.read_bytes() if state_path.exists() else None
    )
    had_public_root = public_root.exists()
    old_manifest = (
        _tree_manifest_no_follow(public_root) if had_public_root else None
    )

    final_targets = tuple(
        public_root / Path(*PurePosixPath(name).parts)
        for name in sorted(set(previous_managed) | set(desired))
    )
    for target in final_targets:
        safe_path(target, project_root=project)

    candidate = _temporary_directory(project, ".security-publish-candidate-")
    backup: Path | None = None
    old_recovery: Path | None = None
    displaced_slot: Path | None = None
    recovery_slots: tuple[Path, Path] | None = None
    activated = False
    committed = False
    try:
        if had_public_root:
            _copy_tree_no_follow(public_root, candidate, dirs_exist_ok=True)

        # The copy preserves redirects rather than following them. Reject any
        # redirect copied from a racing public tree before reading ownership
        # bytes or composing the prospective output.
        _walk_is_safe(candidate, project)

        summary = candidate / RISK_SUMMARY_FILE
        if (
            RISK_SUMMARY_FILE in desired
            and summary.exists()
            and RISK_SUMMARY_FILE not in previous_managed
        ):
            raise PublicationError(
                "refusing to overwrite human-owned risk-summary.md without managed state"
            )
        if (
            RISK_SUMMARY_FILE in desired
            and summary.is_file()
            and RISK_SUMMARY_FILE in previous_managed
            and _digest(summary.read_bytes()) != previous_managed[RISK_SUMMARY_FILE]
        ):
            raise PublicationError(
                "refusing to overwrite human-modified risk-summary.md"
            )

        for name, data in desired.items():
            target = safe_path(
                candidate / Path(*PurePosixPath(name).parts), project_root=project
            )
            safe_write_text(
                target,
                data.decode("utf-8"),
                encoding="utf-8",
                project_root=project,
                create_parents=True,
            )

        for name, old_digest in previous_managed.items():
            if name in desired:
                continue
            candidate_target = candidate / Path(*PurePosixPath(name).parts)
            if (
                candidate_target.is_file()
                and _digest(candidate_target.read_bytes()) == old_digest
            ):
                safe_path(candidate_target, project_root=project)
                candidate_target.unlink(missing_ok=True)

        next_managed = {name: _digest(data) for name, data in desired.items()}
        safe_mkdir(public_root.parent, project_root=project)
        safe_mkdir(state_path.parent, project_root=state_root)
        backup = _unused_directory_path(
            public_root.parent, project, ".security-publish-backup-"
        )
        displaced_slot = _unused_directory_path(
            public_root.parent, project, ".security-publish-failed-"
        )
        recovery_slots = (
            _unused_directory_path(
                public_root.parent, project, ".security-publish-recovery-a-"
            ),
            _unused_directory_path(
                public_root.parent, project, ".security-publish-recovery-b-"
            ),
        )
        if had_public_root:
            assert old_manifest is not None
            old_recovery = _unused_directory_path(
                public_root.parent, project, ".security-publish-previous-"
            )
            _copy_tree_no_follow(public_root, old_recovery)
            if not _tree_matches(old_recovery, old_manifest, project):
                raise PublicationError(
                    "previous public-tree recovery copy is incomplete"
                )

        # Revalidate both complete trees after all staging work and immediately
        # before the directory transaction. This closes the deterministic seam
        # where a redirect can appear after the initial public-tree check.
        _walk_is_safe(public_root, project)
        _walk_is_safe(candidate, project)
        new_manifest = _tree_manifest_no_follow(candidate)
        for target in final_targets:
            safe_path(target, project_root=project)
        safe_path(candidate, project_root=project)
        safe_path(public_root, project_root=project)
        if had_public_root:
            assert old_manifest is not None
            assert old_recovery is not None
            _move_previous_tree_to_backup(
                public_root, backup, old_recovery, project, old_manifest
            )
        if not _tree_matches(candidate, new_manifest, project):
            assert displaced_slot is not None
            assert recovery_slots is not None
            state = _restore_public_root(
                public_root,
                backup,
                old_recovery,
                displaced_slot,
                recovery_slots,
                project,
                old_manifest,
                new_manifest,
            )
            if state == "old":
                raise PublicationError("candidate tree changed before activation")
            raise PublicationError(
                "candidate changed and recovery did not restore the old tree"
            )
        try:
            safe_path(candidate, project_root=project)
            safe_path(public_root, project_root=project)
            os.replace(candidate, public_root)
            activated = True
        except BaseException as activation_error:
            state = _public_tree_state(
                public_root, project, old_manifest, new_manifest
            )
            if state == "new":
                # The replace committed before reporting failure. Continue to
                # the state write only after verifying the exact new tree.
                activated = True
            else:
                activated = False
                assert displaced_slot is not None
                assert recovery_slots is not None
                state = _restore_public_root(
                    public_root,
                    backup,
                    old_recovery,
                    displaced_slot,
                    recovery_slots,
                    project,
                    old_manifest,
                    new_manifest,
                )
            if state == "old":
                raise activation_error
            if state != "new":
                raise PublicationError(
                    "activation recovery did not produce a verified public tree"
                ) from activation_error

        if not _tree_matches(public_root, new_manifest, project):
            activated = False
            assert displaced_slot is not None
            assert recovery_slots is not None
            state = _restore_public_root(
                public_root,
                backup,
                old_recovery,
                displaced_slot,
                recovery_slots,
                project,
                old_manifest,
                new_manifest,
            )
            if state == "old":
                raise PublicationError(
                    "activated public tree does not match the candidate"
                )
            raise PublicationError(
                "activated tree changed and recovery did not restore the old tree"
            )

        try:
            safe_path(state_path, project_root=state_root)
            safe_write_text(
                state_path,
                _state_text(next_managed),
                encoding="utf-8",
                project_root=state_root,
                create_parents=True,
            )
        except BaseException as state_error:
            activated = False
            assert displaced_slot is not None
            assert recovery_slots is not None
            state = _restore_public_root(
                public_root,
                backup,
                old_recovery,
                displaced_slot,
                recovery_slots,
                project,
                old_manifest,
                new_manifest,
            )
            if state == "old":
                raise state_error
            if state == "new":
                # Rollback could not begin, but only an exact manifest match
                # can cross the commit-forward success boundary. Preserve the
                # sole previous-tree backup as the recovery artifact.
                committed = True
                return
            raise PublicationError(
                "state-write recovery did not produce a verified public tree"
            ) from state_error

        # State persistence is not the cleanup boundary. Recheck the complete
        # canonical tree immediately before the sole old backup can be removed.
        if not _tree_matches(public_root, new_manifest, project):
            activated = False
            assert displaced_slot is not None
            assert recovery_slots is not None
            state = _restore_public_root(
                public_root,
                backup,
                old_recovery,
                displaced_slot,
                recovery_slots,
                project,
                old_manifest,
                new_manifest,
            )
            if state != "old":
                raise PublicationError(
                    "public tree changed before backup cleanup and old bytes "
                    "could not be restored"
                )
            safe_path(state_path, project_root=state_root)
            if previous_state_bytes is None:
                state_path.unlink(missing_ok=True)
            else:
                safe_write_text(
                    state_path,
                    previous_state_bytes.decode("utf-8"),
                    encoding="utf-8",
                    project_root=state_root,
                    create_parents=True,
                )
            raise PublicationError(
                "public tree changed before backup cleanup"
            )
        # This is the commit point. Do not run cleanup, path inspection, or any
        # other caller-observable seam after this exact manifest check. The two
        # verified old copies are deliberately retained as recovery artifacts.
        committed = True
    finally:
        if not committed:
            _best_effort_remove_tree(candidate, project)


def argument_parser() -> argparse.ArgumentParser:
    parser = _StrictArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--project-root", type=Path, required=True, action=_StoreOnce)
    parser.add_argument("--generated", type=Path, required=True, action=_StoreOnce)
    parser.add_argument("--risk-summary", action="store_true")
    return parser


def _risk_paths(project_root: Path) -> dict[str, Path]:
    internal = project_root / ".security-requirements"
    return {
        "project_root": project_root,
        "policy": internal / "risk-policy.yaml",
        "threats": internal / "threats.yaml",
        "assessment": internal / "risk-assessment.yaml",
    }


def main(argv: list[str] | None = None) -> int:
    if sys.version_info < MINIMUM_PYTHON:
        print(
            "error: security-requirements requires Python 3.12 or newer",
            file=sys.stderr,
        )
        return 2
    try:
        args = argument_parser().parse_args(argv)
        project_root = _absolute(args.project_root)
        paths = _risk_paths(project_root)
        problems = risk.check_policy(paths)
        for problem in risk.check_assessment(paths):
            if problem not in problems:
                problems.append(problem)
        if problems:
            for problem in problems:
                print(f"ERROR: risk publication gate: {problem}", file=sys.stderr)
            return 1
        stage_and_publish(
            project_root,
            args.generated,
            BASE_MANAGED_FILES
            + ((RISK_SUMMARY_FILE,) if args.risk_summary else ()),
        )
        for name in BASE_MANAGED_FILES + (
            (RISK_SUMMARY_FILE,) if args.risk_summary else ()
        ):
            print(f"published {project_root / PUBLIC_ROOT / name}")
        return 0
    except PublicationArgumentError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (OSError, RuntimeError, UnsafePathError, ValueError, yaml.YAMLError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
