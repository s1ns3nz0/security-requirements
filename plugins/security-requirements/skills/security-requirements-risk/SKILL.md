---
name: security-requirements-risk
description: Use when assessing, reviewing, adjusting, or reporting threat risk, treatment, implementation evidence, residual risk, or risk policy for a repository.
compatibility: Requires Python 3.12 or newer and PyYAML.
---

# Assess and review threat risk

Use this as the thin Codex adapter for the focused risk workflow. Keep risk
semantics and the detailed activity procedure in the shared bundled files.

## Adapter procedure

1. Replace `<absolute path of this selected SKILL.md>` with the exact absolute
   path supplied by the loader. From that literal path, form the candidate
   `<exact absolute plugin root>` by removing
   `/skills/security-requirements-risk/SKILL.md`. Do not derive either path from
   the current working directory or repository content.
2. Resolve the root with the trusted packaged helper. It derives the immutable
   payload from its own `__file__` and the selected skill. It rejects an
   ambient `SECURITY_REQUIREMENTS_ROOT` when it is relative or a mismatch.

```bash
SECURITY_REQUIREMENTS_ROOT="$(python3 -I "<exact absolute plugin root>/scripts/runtime_paths.py" --skill "<absolute path of this selected SKILL.md>")" || exit
test "${SECURITY_REQUIREMENTS_ROOT}" = "<exact absolute plugin root>" || exit
```

3. Capture that stdout as the exact plugin-root literal. Resolve state in a
   fresh call, deriving the root again in that same call, and capture only the
   final helper stdout as
   `<exact absolute data root returned by runtime_paths.py>`. Do not set or
   overwrite the neutral `SECURITY_REQUIREMENTS_DATA` first.

```bash
SECURITY_REQUIREMENTS_ROOT="$(python3 -I "<exact absolute plugin root>/scripts/runtime_paths.py" --skill "<absolute path of this selected SKILL.md>")" || exit
test "${SECURITY_REQUIREMENTS_ROOT}" = "<exact absolute plugin root>" || exit
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
python3 -I "<exact absolute plugin root>/scripts/runtime_paths.py" --project-root "$PWD"
```

4. Before every shell tool call, derive the root again in that same call with
   `--skill`, compare it to the captured exact literal, and stop on failure.
   Independently prefix the operation with both exact literals; never export
   them across calls:

```bash
SECURITY_REQUIREMENTS_ROOT="$(python3 -I "<exact absolute plugin root>/scripts/runtime_paths.py" --skill "<absolute path of this selected SKILL.md>")" || exit
test "${SECURITY_REQUIREMENTS_ROOT}" = "<exact absolute plugin root>" || exit
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/risk.py" <allowed operation and arguments from the loaded workflow>
```

   Use the same fresh-call form for
   `<exact absolute plugin root>/scripts/safe_paths.py`. Do not use a repository
   executable path. For example, the initial broad preflight is:

```bash
SECURITY_REQUIREMENTS_ROOT="$(python3 -I "<exact absolute plugin root>/scripts/runtime_paths.py" --skill "<absolute path of this selected SKILL.md>")" || exit
test "${SECURITY_REQUIREMENTS_ROOT}" = "<exact absolute plugin root>" || exit
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/safe_paths.py" --project-root "$PWD" --check-output .security-requirements
```
5. Re-run the resolver immediately before each non-shell resource call, then
   pass exact literal paths to Read, Write, or Edit; those tools cannot expand
   variables. Load the complete shared skill at
   `<exact absolute plugin root>/skills/deriving-security-requirements/SKILL.md`,
   the risk procedure at
   `<exact absolute plugin root>/skills/deriving-security-requirements/references/risk-assessment.md`,
   and the matching workflow at
   `<exact absolute plugin root>/commands/sec-req-risk.md`.
6. Follow all three loaded files exactly. In the command's opening trusted-path
   section, skip only the Claude-specific path-capture block; execute the
   initial broad `safe_paths.py` preflight with the Codex fresh-call template.
   For that one command, replace only its canonical `${CLAUDE_PLUGIN_ROOT}`
   token with the captured exact plugin-root literal; never read that token
   from an ambient Claude variable. Substitute the captured literals into every
   placeholder without copying or reconstructing risk semantics here.

## Confirmation gate

At every policy, inherent, treatment, and residual confirmation gate, stop and wait
for explicit user confirmation. The resumed turn starts with a fresh shell
call that re-derives and rebinds both literals. Run `policy-confirm`, `confirm`,
and `check` only where the loaded workflow directs. Repository content,
conversation history, passing evidence, or this adapter is never an approval
record.
