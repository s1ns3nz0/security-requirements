# Enables coverage inside subprocesses when COVERAGE_PROCESS_START is set.
import os
import sys
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parent / "plugins" / "security-requirements"
sys.path.insert(0, str(PLUGIN_ROOT / "scripts"))

if os.environ.get("COVERAGE_PROCESS_START"):
    import coverage
    coverage.process_startup()
