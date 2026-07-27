# Enables coverage inside subprocesses when COVERAGE_PROCESS_START is set.
import os
if os.environ.get("COVERAGE_PROCESS_START"):
    import coverage
    coverage.process_startup()
