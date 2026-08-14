# Two residual bypasses: fix report

Date: 2026-08-12

Status: complete

Implementation commit: `727f0ec fix: close confirmation and preflight bypasses`

## Scope and resolution

### Final confirmation-state containment

`confirmation_state_path()` previously validated only the selected plugin data
root. An ancestor data root could still make the derived
`confirmations/<project-hash>.yaml` artifact land inside the inspected project.

The function now resolves that final artifact and rejects equality with, or
containment beneath, the inspected project using the explicit error:

```text
confirmation state must remain outside the project
```

Regression coverage proves that stamping leaves the profile unchanged and does
not create authority, and that a matching project-owned forged profile/state
pair is rejected.

### Shared strict safe-output parser

`safe_paths.py` now exposes `argument_parser()`, which is also used by
`validate_distribution.py`. The shared grammar disables argparse abbreviation
and rejects repeated `--project-root` and `--check-output` occurrences. The
distribution validator requires exactly one semantic `$PWD` project root,
exactly the workflow's expected output set, and no unknown or extra arguments.
A valid single equals-form project root remains accepted.

This closes the scanner/parser disagreement for equals-form duplicates,
last-wins reverse order, `--project-r`, and `--p`.

## Strict TDD evidence

The focused RED selection, before production changes:

```text
10 failed, 1 passed, 108 deselected in 0.58s
```

The ten failures were the two confirmation bypasses, four validator evasions,
and four runtime parser evasions. The passing case was the compatibility test
for a single equals-form project root.

The same focused selection after the minimal implementation:

```text
11 passed, 108 deselected in 0.35s
```

Both affected test modules then passed together:

```text
119 passed in 5.49s
```

## Exact repro reruns

Ancestor-root stamp and matching-forgery checks:

```text
2 passed in 0.12s
```

Both argument orders were executed directly against `safe_paths.py`:

```text
--project-root "$PWD" --project-root=/private/tmp
--project-root=/private/tmp --project-root "$PWD"

error: argument --project-root: --project-root may be specified only once
exit 2
```

The validator/runtime regression group for duplicate and abbreviated roots:

```text
8 passed, 78 deselected in 1.08s
```

## Final verification

Python 3.12.11 full suite:

```text
918 passed in 25.66s
```

Post-commit validators:

- `python scripts/validate_distribution.py .`: exit 0, no output.
- Codex plugin schema validator: `Plugin validation passed`, exit 0.
- `claude plugin validate --strict plugins/security-requirements`: passed.
- `claude plugin validate --strict .`: passed.

The README deterministic test count and the durable dual-plugin verification
report were updated to 918.

## Residual concerns

No known residual remains for these two bypasses. The shared parser is imported
from the trusted sibling plugin payload by the repository validator; this is
appropriate for validating this distribution but is not a general mechanism
for executing an arbitrary target repository's parser. This follow-up did not
perform a new independent review of unrelated security surfaces.
