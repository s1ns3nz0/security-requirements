"""Make plugin-owned helper scripts importable by the test suite."""

from pathlib import Path
import sys


PLUGIN_SCRIPTS = Path(__file__).parents[1] / "plugins" / "security-requirements" / "scripts"
sys.path.insert(0, str(PLUGIN_SCRIPTS))
