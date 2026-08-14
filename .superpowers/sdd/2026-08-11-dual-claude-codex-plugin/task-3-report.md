# Task 3 report: neutral persistent-state resolution

## RED

After adding resolver, confirmation, and generated-service tests, before any
runtime implementation:

```text
$ pytest tests/test_confirmation.py tests/test_pipeline.py -q
ERROR tests/test_confirmation.py
ModuleNotFoundError: No module named 'runtime_paths'
1 error in 0.56s
```

The requested `python3 -m pytest` command could not be used because the
available Python 3.14 installation has no `pytest` module. The available
`pytest` executable runs under Python 3.12 and was used for all test evidence.

## GREEN

```text
$ pytest tests/test_confirmation.py tests/test_pipeline.py -q \
    -k 'not test_the_test_count_on_the_front_page_is_the_test_count'
758 passed, 1 deselected in 19.27s
```

`git diff --check` also passed.

The unfiltered command ran successfully apart from the existing
README-count sentinel:

```text
758 passed, 1 failed
FAILED tests/test_pipeline.py::test_the_test_count_on_the_front_page_is_the_test_count
README says 766, the suite collects 780
```

Before this task's six new tests, the suite would already have collected 774,
so the README was already eight tests stale. It is outside this task's owned
file list and was left unchanged.

## Self-review

- `plugin_data_root` prefers `SECURITY_REQUIREMENTS_DATA`, retains
  `CLAUDE_PLUGIN_DATA` only as a compatibility fallback, and otherwise returns
  OS-specific, versioned user-state paths without creating directories.
- Confirmation preserves the existing project-root digest and all validation
  branches; only its state-root source changed. Its writer still creates only
  `confirmations/`.
- Generated service lookup uses the same resolver. Existing identifier
  validation and resolved-path containment checks remain in `service_path`;
  the containment test now exercises the neutral root.
- No concern in the implementation. The only remaining suite concern is the
  unrelated stale README test count noted above.

## Round 1: relative state-root hardening

### RED

```text
$ pytest tests/test_confirmation.py tests/test_pipeline.py -q \
    -k 'relative or generated_service_curation_rejects'
6 failed, 759 deselected in 0.27s
```

The failures established that relative `SECURITY_REQUIREMENTS_DATA`,
`CLAUDE_PLUGIN_DATA`, `XDG_STATE_HOME`, and `LOCALAPPDATA` paths were accepted
under the current working directory, including confirmation state writes.

### GREEN

```text
$ pytest tests/test_confirmation.py tests/test_pipeline.py -q \
    -k 'relative or generated_service_curation_rejects'
6 passed, 759 deselected in 0.16s

$ pytest tests/test_confirmation.py tests/test_pipeline.py -q \
    -k 'not test_the_test_count_on_the_front_page_is_the_test_count'
764 passed, 1 deselected in 18.56s
```

`git diff --check` passed.

### Fix and self-review

- Explicit neutral and legacy plugin roots are now expanded and required to be
  absolute; a relative value raises a clear `ValueError` naming the variable.
  Confirmation handles that error as a normal command failure before it stamps
  or writes state.
- Relative `XDG_STATE_HOME` and `LOCALAPPDATA` values are ignored. The resolver
  uses its absolute, home-derived platform default instead.
- New tests change into a project directory and prove explicit roots cannot
  create confirmation or generated-service state there. They also prove
  Linux/Windows OS-state fallbacks are absolute and outside the project.
- Precedence, confirmation digest/validation, and generated-service path
  containment are unchanged.
