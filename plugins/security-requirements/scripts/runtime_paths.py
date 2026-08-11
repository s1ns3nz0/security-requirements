"""Resolve persistent state locations for the security-requirements plugin."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
import sys


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
            return Path(value).expanduser()

    current_platform = sys.platform if platform is None else platform
    if current_platform.startswith("win"):
        base = Path(variables.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    elif current_platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(variables.get("XDG_STATE_HOME") or Path.home() / ".local" / "state")
    return base.expanduser() / "security-requirements" / "v1"
