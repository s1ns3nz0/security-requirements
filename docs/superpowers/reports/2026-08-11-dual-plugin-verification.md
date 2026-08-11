# Dual Claude and Codex plugin verification

Final-review update: 2026-08-12

Branch: `feat/dual-claude-codex-plugin`

Security-fix commits:

- `b0aed64 fix: harden dual-host plugin execution`
- `0596650 fix: root loaded runtime guidance`
- `727f0ec fix: close confirmation and preflight bypasses`

## Verdict

**PASS.** The final review's Critical, Important, migration-remnant, minor, and
evidence findings are closed, including the two follow-up bypasses in final
confirmation-state placement and safe-output preflight parsing. The exact
Python 3.12 suite passes, both distribution validators and both authoritative
Claude strict validations pass, and installed Claude and Codex adapters
executed trusted packaged scripts from an unrelated hostile working directory
without importing repository shadow modules.

This update supersedes the earlier evidence in this file. In particular, the
old read-only host checks and the old cross-call `export` adapter examples are
historical and are not relied on for this verdict.

## Environment

| Tool | Observed version |
|---|---|
| Prepared test interpreter | Python 3.12.11 |
| Codex | `codex-cli 0.147.0` |
| Claude Code | `2.1.145` |

The prescribed literal `python3` commands used a temporary PATH shim:

```text
/tmp/security-requirements-python312-b0aed64/python3
  -> /Users/s1ns3nz0/.pyenv/versions/3.12.11/bin/python
```

## Exact final validation

### Complete suite

```bash
PYTHONDONTWRITEBYTECODE=1 /Users/s1ns3nz0/.pyenv/versions/3.12.11/bin/python \
  -m pytest -p no:cacheprovider -q
```

Result:

```text
918 passed in 25.66s
```

### Distribution and host-schema validators

```bash
python3 scripts/validate_distribution.py .
python3 /Users/s1ns3nz0/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py plugins/security-requirements
claude plugin validate --strict plugins/security-requirements
claude plugin validate --strict .
```

Results:

```text
# validate_distribution.py: no output, exit 0
Plugin validation passed: .../plugins/security-requirements
Validating plugin manifest: .../plugins/security-requirements/.claude-plugin/plugin.json
✔ Validation passed
Validating marketplace manifest: .../.claude-plugin/marketplace.json
✔ Validation passed
```

`git diff --check` and `find plugins/security-requirements -type l -print`
both returned no output with exit `0`.

### Follow-up bypass regression evidence

Before `727f0ec`, the focused regression selection produced the expected RED:

```text
10 failed, 1 passed, 108 deselected in 0.58s
```

The failures proved that stamping and checking both accepted an authority file
under `D/confirmations`, the validator accepted both equals-form override
orders and the `--project-r`/`--p` abbreviations, and the runtime parser itself
accepted all four unsafe argument lists. The one passing case preserved a
single equals-form `--project-root=<root>` invocation.

After the minimal fixes, the same selection was GREEN:

```text
11 passed, 108 deselected in 0.35s
```

The exact ancestor-state forgery tests were rerun independently:

```text
2 passed in 0.12s
```

Both `/private/tmp` last-wins orders now fail at the runtime parser before path
validation:

```text
error: argument --project-root: --project-root may be specified only once
exit 2
```

The validator and parser regression group for duplicates and abbreviations also
passes independently:

```text
8 passed, 78 deselected in 1.08s
```

## Final-review security closure

| Finding | Resolution and evidence |
|---|---|
| Inspected cwd could shadow Python startup/imports | All workflow Python calls are `python3 -I` plus an absolute packaged script. Inline `-c`, stdin, cwd-relative, arbitrary absolute, versioned-interpreter, multiline, and YAML-quoted bypasses are rejected by the validator. `test_packaged_cli_starts_in_isolated_mode_from_a_hostile_project` executes the packaged CLIs with poisoned `sitecustomize.py`, `pathlib.py`, and `yaml.py`. |
| Exports did not persist across tool calls and non-shell tools could not expand them | Claude captures exact roots once and every operation independently prefixes the exact literals. Codex derives the immutable root from the loader-selected `SKILL.md` before every call and rejects a mismatched ambient root. Read/Write/Edit instructions use exact literal paths. Structural tests cover every fenced block and confirmation-gate resume. |
| Neutral precedence could be overwritten | `plugin_data_root` retains `SECURITY_REQUIREMENTS_DATA > CLAUDE_PLUGIN_DATA > OS default`. Adapters explicitly forbid pre-setting the neutral variable during resolution. Unit tests exercise neutral, legacy, and default paths. |
| Authoritative state could live in or be redirected through the inspected project | Runtime resolution compares lexical and resolved paths with the inspected project. Confirmation and generated-service loading bind the project explicitly. `confirmation_state_path` now also resolves the final `confirmations/<project-hash>.yaml` artifact and rejects it if an ancestor data root would place that artifact in the project. Generated state is checked with the centralized symlink-safe helper before reading. Direct, ancestor, forged-authority, and project-owned redirect tests pass. |
| Target output symlinks could be followed | `safe_paths.py` rejects project-root, ancestor, direct, and broken symlinks, preflights complete output batches before the first write, and uses atomic replacement. Confirmation, baseline, classification, overlay, merge, and render sinks use the helper. Workflow model writes receive a fresh exact-target preflight immediately before every Write/Edit. |
| Shared skill trusted ambient redirection | `runtime_paths.py --skill` validates that the selected absolute `SKILL.md` belongs to its own payload and requires exact lexical/resolved agreement with any ambient root. |
| Migration remnants | Claude cross-command names are namespaced; baseline overlay commands are absolute and isolated; README, CONTRIBUTING, DESIGN, loaded reference files, HIPAA metadata, and missing-catalog remediation commands use moved/absolute trusted paths. `.gitignore` exposes only `.agents/plugins/marketplace.json`. |
| Mutation tool path escape/interruption | `--file` accepts only a contained, non-symlink packaged relative file. The copied file is restored in `finally`, including `KeyboardInterrupt`. Behavioral tests cover absolute, traversal, symlink, and interrupted runner cases. |
| Validator evasion | The validator fail-closes parse errors and inspects every detected Python execution in payload text, including Python docstrings, YAML quoting, command substitution, combined flags, stdin, and commands outside a `/scripts/` spelling. Runtime and distribution validation now share `safe_paths.argument_parser()`, with abbreviation disabled and duplicate options rejected. A broad preflight requires exactly one semantic `$PWD` root, exactly the expected output set, and no unknown or extra arguments. |

The follow-up closes the two residual bypasses found after the original
adversarial review. It does not claim a new independent review of unrelated
surfaces.

## Installed-host execution from a hostile cwd

The final checks used this unrelated working directory and external state root:

```text
cwd:  /tmp/security requirements 테스트-b0aed64
data: /tmp/security requirements data 테스트-b0aed64
```

The cwd contained malicious `sitecustomize.py`, `pathlib.py`, and `yaml.py`.
`PYTHONPATH` also pointed at that cwd. Each poison module would create a
`POISONED-*` marker if imported. No marker was created.

### Codex

Prechecks found no exact test marketplace, plugin, or cache. The exact worktree
was registered and installed as
`security-requirements@security-requirements` version `0.1.0`.

Three independent `codex exec --ephemeral --sandbox read-only` sessions were
started with the manifest starter prompts, one prompt per session:

```text
Initialize the security requirements profile for this repository.
Build security requirements from the confirmed profile.
Refresh security requirements after service changes.
```

No explicit list of skills was supplied. Each session naturally selected its
matching installed entry skill. Each then actually executed:

```text
python3 -I <installed-cache>/scripts/runtime_paths.py --skill <selected absolute SKILL.md>
python3 -I <installed-cache>/scripts/runtime_paths.py --project-root "$PWD"
python3 -I <installed-cache>/scripts/safe_paths.py --project-root "$PWD" --check-output ...
```

The data-root stdout in every session was:

```text
/private/tmp/security requirements data 테스트-b0aed64
```

The exact success markers were:

```text
CODEX_INIT_ADAPTER_EXEC_OK
CODEX_BUILD_ADAPTER_EXEC_OK
CODEX_REFRESH_ADAPTER_EXEC_OK
```

The test plugin and marketplace were removed by an EXIT trap. Final exact-name
queries returned no match and the exact cache path did not exist.

### Claude Code

Claude used the empty isolated configuration:

```text
/tmp/security requirements claude 테스트-b0aed64
```

The exact local worktree was added and installed there. The three namespaced
commands were invoked separately with only Bash exposed and no session
persistence:

```text
/security-requirements:sec-req-init
/security-requirements:sec-req-build
/security-requirements:sec-req-refresh
```

Each command actually ran the worktree payload's `runtime_paths.py` and
`safe_paths.py` through `python3 -I`, reported the same external data-root
stdout, and returned:

```text
CLAUDE_INIT_ADAPTER_EXEC_OK
CLAUDE_BUILD_ADAPTER_EXEC_OK
CLAUDE_REFRESH_ADAPTER_EXEC_OK
```

An initial `dontAsk` attempt denied Bash and correctly emitted no success
marker. The final non-interactive run used Claude's explicit
`bypassPermissions` mode, limited by the audit prompt and `--tools Bash`, so the
two read-only packaged checks could execute.

The isolated plugin and marketplace were removed by an EXIT trap; both isolated
lists are `[]`. The pre-existing user Claude marketplace/plugin entry retained
the same GitHub source, installed path, and timestamps as before the check.

## State and confirmation evidence

The full suite includes separate-process confirmation tests. The load-bearing
case stamps in one clean subprocess, checks in a second, mutates and rejects in
a third, and proves that a later call succeeds only when the exact external
state root is rebound. Other tests repeat neutral, legacy-only, and default-root
behavior, reject repository-only approval forgery, and reject both stamping and
checking when an ancestor state root makes the final authority artifact
project-owned.

## Residual limitations

The two known follow-up bypasses are closed. YAML-using runtime scripts require
PyYAML in the isolated interpreter's system or virtual environment;
user-site-only packages are deliberately ignored by `-I`, and the README
documents that prerequisite. The installed-host checks intentionally executed
the safe, read-only path and output preflight scripts rather than a side-effecting
end-to-end service interview and publication. No new independent review of
unrelated surfaces was performed for this follow-up.
