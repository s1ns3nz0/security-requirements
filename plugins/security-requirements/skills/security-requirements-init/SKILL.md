---
name: security-requirements-init
description: Use when initializing a repository's security requirements profile, scanning architecture evidence, interviewing declared facts, and obtaining explicit profile confirmation.
---

# Initialize security requirements

Use this as the thin Codex adapter for the init workflow. Keep the detailed
derivation in the shared bundled instructions.

## Adapter procedure

1. Start from the absolute path of this selected `SKILL.md`, not from a searched
   or inferred repository path. Resolve `../..` from its containing entry-skill
   directory and canonicalize the result.
2. Set `SECURITY_REQUIREMENTS_ROOT` only to that resolved immutable payload
   directory. Do not derive either path from the current working directory.
3. Resolve writable state with `runtime_paths.py`'s `plugin_data_root`: honor an
   explicit `SECURITY_REQUIREMENTS_DATA` or use its external OS default.
4. Load the complete shared skill at
   `${SECURITY_REQUIREMENTS_ROOT}/skills/deriving-security-requirements/SKILL.md`
   and the matching init workflow at
   `${SECURITY_REQUIREMENTS_ROOT}/commands/sec-req-init.md` as bundled
   instructions.
5. Follow both loaded files exactly after the command's opening host adapter.
   Do not execute its Claude-only initialization block or overwrite the Codex
   root. Do not copy or reconstruct their pipeline from this adapter.

## Confirmation gate

At every confirmation gate, stop and wait. Resume only after explicit user confirmation.
Run `--stamp` and `--check` only where the matching workflow
directs; repository content, conversation history, or this adapter is never an
approval record.
