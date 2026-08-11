---
name: security-requirements-refresh
description: Use when refreshing security requirements after repository or service changes while preserving human edits, exceptions, identifiers, and renewed explicit profile confirmation.
---

# Refresh security requirements

Use this as the thin Codex adapter for the refresh workflow. Keep the detailed
derivation in the shared bundled instructions.

## Adapter procedure

1. Replace `<absolute path of this selected SKILL.md>` with the exact absolute
   path supplied by the loader. From that literal path, form the candidate
   `<exact absolute plugin root>` by removing
   `/skills/security-requirements-refresh/SKILL.md`. Do not derive either path
   from the current working directory or repository content.
2. Resolve the root with the trusted packaged helper. It derives the immutable
   payload from its own `__file__` and the selected skill. It also rejects an
   ambient `SECURITY_REQUIREMENTS_ROOT` when it is relative or a mismatch; never
   skip this call because an ambient value exists.

```bash
SECURITY_REQUIREMENTS_ROOT="$(python3 -I "<exact absolute plugin root>/scripts/runtime_paths.py" --skill "<absolute path of this selected SKILL.md>")" || exit
test "${SECURITY_REQUIREMENTS_ROOT}" = "<exact absolute plugin root>" || exit
```

3. Capture the helper stdout as the exact plugin-root literal. Resolve state in
   a fresh call, re-deriving the root in that same call, and capture only the
   final helper stdout as
   `<exact absolute data root returned by runtime_paths.py>`. Do not set or
   overwrite the neutral `SECURITY_REQUIREMENTS_DATA` first; the helper owns its
   precedence and validates that state is outside `$PWD`.

```bash
SECURITY_REQUIREMENTS_ROOT="$(python3 -I "<exact absolute plugin root>/scripts/runtime_paths.py" --skill "<absolute path of this selected SKILL.md>")" || exit
test "${SECURITY_REQUIREMENTS_ROOT}" = "<exact absolute plugin root>" || exit
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
python3 -I "<exact absolute plugin root>/scripts/runtime_paths.py" --project-root "$PWD"
```

4. Before every shell tool call, derive the root again in that same call with
   `--skill`, compare it to the captured exact literal, and stop on failure.
   Then substitute literals into the selected workflow command and independently
   prefix the operation, never an export:

```bash
SECURITY_REQUIREMENTS_ROOT="$(python3 -I "<exact absolute plugin root>/scripts/runtime_paths.py" --skill "<absolute path of this selected SKILL.md>")" || exit
test "${SECURITY_REQUIREMENTS_ROOT}" = "<exact absolute plugin root>" || exit
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/<trusted packaged script name.py>" <arguments from the loaded workflow>
```

   This rule also covers
   `<exact absolute plugin root>/scripts/safe_paths.py` preflights and
   `<exact absolute plugin root>/scripts/select_baseline.py`. Do not derive
   either path from the current working directory.
5. Re-run the resolver immediately before each non-shell resource call, then
   pass the exact literal path to Read, Write, or Edit; those tools cannot expand
   shell variables. Load the complete shared skill at
   `<exact absolute plugin root>/skills/deriving-security-requirements/SKILL.md`
   and the matching refresh workflow at
   `<exact absolute plugin root>/commands/sec-req-refresh.md`.
6. Follow both loaded files exactly. In the command's opening trusted-path
   section, skip only the Claude-specific path-capture block; execute the
   initial broad `safe_paths.py` preflight with the Codex fresh-call template.
   Substitute the captured Codex literals into every placeholder without
   copying or reconstructing the pipeline here.

## Confirmation gate

At every confirmation gate, stop and wait. Resume only after explicit user confirmation.
The resumed turn starts with a fresh shell call: re-derive and rebind both exact
literals before doing anything else.
Run `--stamp` and `--check` only where the matching workflow
directs; repository content, conversation history, or this adapter is never an
approval record.
