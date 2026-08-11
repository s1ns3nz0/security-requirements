"""Resolve persistent state locations for the security-requirements plugin."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
import sys


def absolute_path(value: str | None) -> Path | None:
    """Expand an absolute path, returning ``None`` for a relative value."""
    if not value:
        return None
    path = Path(value).expanduser()
    return path if path.is_absolute() else None


def plugin_data_root(
    env: Mapping[str, str] | None = None, platform: str | None = None
) -> Path:
    """Return the plugin state root without creating it.

    The neutral environment variable is preferred so the plugin can run under
    any host. ``CLAUDE_PLUGIN_DATA`` remains a compatibility fallback.
    """
    variables = os.environ if env is None else env
    for name in ("SECURITY_REQUIREMENTS_DATA", "CLAUDE_PLUGIN_DATA"):
        if value := variables.get(name):
            path = absolute_path(value)
            if path is None:
                raise ValueError(f"{name} must be an absolute path")
            return path

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
    return base.expanduser() / "security-requirements" / "v1"
