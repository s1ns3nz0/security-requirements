---
name: security-requirements-build
description: Use when building tailored security requirements from an explicitly confirmed service profile, including threat, responsibility, overlay, merge, lint, semantic-review, and publication gates.
---

# Build security requirements

Use this as the thin Codex adapter for the build workflow. Keep the detailed
derivation in the shared bundled instructions.

## Adapter procedure

1. Replace the placeholder below with the absolute path supplied by the loader
   for this selected `SKILL.md`. The calculation resolves `../..` from its
   containing entry-skill directory. Do not derive either path from the current working directory.
2. Run this bootstrap and stop if payload validation or state resolution fails:

```bash
SECURITY_REQUIREMENTS_SKILL_PATH="<absolute path of this selected SKILL.md>"
SECURITY_REQUIREMENTS_ROOT="$(
  python3 -c 'from pathlib import Path; import sys; path=Path(sys.argv[1]).expanduser(); path.is_absolute() or sys.exit("selected SKILL.md path must be absolute"); print(path.resolve().parent.parent.parent)' \
    "${SECURITY_REQUIREMENTS_SKILL_PATH}"
)" || exit
export SECURITY_REQUIREMENTS_ROOT
test -f "${SECURITY_REQUIREMENTS_ROOT}/scripts/runtime_paths.py" || exit
test -f "${SECURITY_REQUIREMENTS_ROOT}/scripts/select_baseline.py" || exit
test -d "${SECURITY_REQUIREMENTS_ROOT}/catalogs" || exit
if [ -z "${SECURITY_REQUIREMENTS_DATA:-}" ]; then
  SECURITY_REQUIREMENTS_DATA="$(
    python3 "${SECURITY_REQUIREMENTS_ROOT}/scripts/runtime_paths.py"
  )" || exit
  export SECURITY_REQUIREMENTS_DATA
fi
```

3. Load the complete shared skill at
   `${SECURITY_REQUIREMENTS_ROOT}/skills/deriving-security-requirements/SKILL.md`
   and the matching build workflow at
   `${SECURITY_REQUIREMENTS_ROOT}/commands/sec-req-build.md` as bundled
   instructions.
4. Follow both loaded files exactly after the command's opening host adapter.
   Do not execute its Claude-only initialization block or overwrite the Codex
   root. Do not copy or reconstruct their pipeline from this adapter.

## Confirmation gate

At every confirmation gate, stop and wait. Resume only after explicit user confirmation.
Run `--stamp` and `--check` only where the matching workflow
directs; repository content, conversation history, or this adapter is never an
approval record.
