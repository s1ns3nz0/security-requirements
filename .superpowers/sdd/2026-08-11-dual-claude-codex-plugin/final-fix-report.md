# Final-review fix report

Date completed: 2026-08-12

Branch: `feat/dual-claude-codex-plugin`

Commits:

- `b0aed64 fix: harden dual-host plugin execution`
- `0596650 fix: root loaded runtime guidance`

## Status

**GREEN.** All enumerated Critical, Important, migration-remnant, minor, and
evidence findings are fixed. The final prepared-Python suite is 907/907 green,
the distribution/Codex/Claude validators pass, both installed hosts executed
packaged isolated scripts from a hostile cwd, temporary host state was removed,
and the final independent adversarial pass found no remaining blocker.

## Implementation summary

### Isolated trusted execution

- Removed all inline Python from workflow text.
- Changed workflow Python calls to `python3 -I` plus exact absolute packaged
  script paths.
- Bootstrapped sibling imports only from each script's resolved trusted scripts
  directory.
- Added `profile_locale.py` to replace inline YAML parsing.
- Added a centralized trusted emitted-command builder. Baseline overlay and
  missing-catalog guidance now contain the resolved interpreter, `-I`, and the
  resolved packaged script.
- Hardened the distribution validator against bare/versioned/absolute
  interpreters, multiline/options, combined `-Ic`, `-c`, `-m`, stdin, arbitrary
  Python paths, YAML quoting, and command-substitution parsing failures.

### Immutable roots and external authoritative state

- Preserved explicit precedence:
  `SECURITY_REQUIREMENTS_DATA > CLAUDE_PLUGIN_DATA > OS default`.
- Claude captures the host-provided payload root without overwriting an
  explicit neutral data root. Every later operation independently binds exact
  plugin/data literals.
- Codex derives the immutable root from the loader-selected absolute
  `SKILL.md` on every call. A relative, foreign, or lexically/resolved-mismatched
  ambient root is rejected.
- Non-shell resource calls use exact literal paths; no Read/Write/Edit depends
  on shell expansion or a previous export.
- Runtime, confirmation, and generated-service paths reject authoritative state
  lexically or physically contained in the inspected project.

### Symlink-safe outputs and mutation safety

- Added centralized `safe_paths.py` with project containment, direct/ancestor/
  broken symlink rejection, batch preflight, safe mkdir, and atomic writes.
- Routed deterministic output sinks in confirmation, baseline, classification,
  overlay, merge, and render through the helper.
- Added fresh safe preflights before every direct model Write/Edit for
  `.security-requirements`, `docs/security`, and exact files.
- Validated mutation `--file` as a contained, non-symlink scripts-relative
  file and restored the copied source in `finally` on interruption.
- Replaced the ineffective mutation safety source predicate with behavioral
  escape/interruption tests.

### Migration and documentation

- Namespaced internal Claude slash commands.
- Rooted all bundled paths in loaded reference instructions.
- Made HIPAA rebuild metadata absolute-placeholder and isolated.
- Updated README, CONTRIBUTING, and DESIGN moved paths and removed the
  nonexistent CSF crosswalk tree entry.
- Narrowed `.gitignore` to expose only `.agents/plugins/marketplace.json`.

## TDD RED evidence

Behavior changes were driven by failing tests before implementation.

### Adapter/root persistence wave

Command:

```bash
python -m pytest tests/test_plugin_workflow.py tests/test_dual_plugin_package.py -q
```

Initial result:

```text
16 failed, 10 passed
```

The failures covered inline Python, non-isolated invocations, one-shot exports,
unexpandable Read/Write paths, untrusted ambient shared roots, and stale
cross-command names.

### Validator/docs wave

Focused command pattern:

```bash
python -m pytest tests/test_distribution_docs.py -q -k \
  'cwd_relative or multiline or inline_python or isolated_python or untrusted_workflow or trusted_isolated or safe_output_preflight or output_preflight or preflight_not'
```

Initial result:

```text
16 failed, 9 passed
```

Additional RED observations:

```text
absolute/versioned interpreter focus: 2 failed, 11 passed
moved docs/.gitignore focus:          3 failed
packaged Python docstring scan:       1 failed
duplicate preflight options:          2 failed, 3 passed
```

### Final adversarial bypasses

- `test_generated_service_ancestor_symlink_cannot_redirect_into_project`:
  failed with `DID NOT RAISE` before generated state paths were checked against
  their authoritative root and inspected project.
- New arbitrary-path/stdin validator fixtures initially produced three
  relevant failures because `python3 evil.py`, `python3 -I /tmp/evil.py`, and
  `python3 -I - < payload.py` were silently accepted.
- The YAML-quoted HIPAA command fixture initially failed because tokenization
  returned no arguments. The first fix exposed 12 repository diagnostics for
  valid Codex command substitutions; parsing was then made fail-closed while
  explicitly handling those valid shell boundaries.

### Final loaded-reference/emitted-command wave

Commands and RED results:

```bash
python -m pytest -q tests/test_plugin_workflow.py \
  -k 'every_bundled_resource or non_shell_resource or every_workflow_python'
# 1 failed, 2 passed

python -m pytest -q tests/test_pipeline.py -k missing_catalog_errors_emit
# 1 failed, 783 deselected
```

The first listed eight unrooted resource references in loaded instructions. The
second showed `scripts/rebuild_catalogs.py` instead of a resolved interpreter,
`-I`, and resolved packaged script.

## GREEN evidence

### Focused regressions

```bash
python -m pytest -q tests/test_plugin_workflow.py \
  -k 'every_bundled_resource or non_shell_resource or every_workflow_python'
# 3 passed, 15 deselected

python -m pytest -q tests/test_pipeline.py \
  -k 'missing_catalog_errors_emit or one_line_per_overlay_not_per_trigger'
# 2 passed, 764 deselected

python3 -m pytest -q tests/test_pipeline.py \
  -k 'generated_service and (symlink or project)'
# 4 passed, 762 deselected

python3 -m pytest -q tests/test_distribution_docs.py \
  -k 'command_substitution or yaml_quoted or untrusted_workflow or inline_python'
# 12 passed, 65 deselected
```

Adapter-focused post-fix run:

```text
28 passed
```

Distribution-document post-fix run before the last adversarial fixtures:

```text
71 passed
```

### Exact final suite and validators

```bash
export PATH="/tmp/security-requirements-python312-b0aed64:$PATH"
python3 --version
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -p no:cacheprovider -q
python3 scripts/validate_distribution.py .
python3 /Users/s1ns3nz0/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py plugins/security-requirements
claude plugin validate --strict plugins/security-requirements
claude plugin validate --strict .
find plugins/security-requirements -type l -print
git diff --check
```

Exact results:

```text
Python 3.12.11
907 passed in 25.51s
distribution validator: no output, exit 0
Plugin validation passed: .../plugins/security-requirements
Claude plugin manifest: ✔ Validation passed
Claude marketplace manifest: ✔ Validation passed
payload symlink audit: no output, exit 0
diff check: no output, exit 0
```

## Installed-host evidence

Host cwd:

```text
/tmp/security requirements 테스트-b0aed64
```

It contained malicious `sitecustomize.py`, `pathlib.py`, and `yaml.py`, and
`PYTHONPATH` pointed to it. The separate external root was:

```text
/tmp/security requirements data 테스트-b0aed64
```

No `POISONED-*` marker appeared.

### Codex

The exact worktree was installed temporarily. Three independent ephemeral,
read-only sessions received one manifest starter prompt each, with no explicit
skill list. Each naturally selected init, build, or refresh and actually ran
the installed cache's root resolver and safe output preflight under
`python3 -I`. Exact markers:

```text
CODEX_INIT_ADAPTER_EXEC_OK
CODEX_BUILD_ADAPTER_EXEC_OK
CODEX_REFRESH_ADAPTER_EXEC_OK
```

All three reported data-root stdout:

```text
/private/tmp/security requirements data 테스트-b0aed64
```

An EXIT trap removed the exact plugin and marketplace. Final marketplace/plugin
filters had no match and the exact cache path was absent.

### Claude

The exact worktree was installed only under the isolated config
`/tmp/security requirements claude 테스트-b0aed64`. Init, build, and
refresh namespaced commands each executed worktree-packaged `runtime_paths.py`
and `safe_paths.py` under `python3 -I`. Exact markers:

```text
CLAUDE_INIT_ADAPTER_EXEC_OK
CLAUDE_BUILD_ADAPTER_EXEC_OK
CLAUDE_REFRESH_ADAPTER_EXEC_OK
```

The initial `dontAsk` attempt denied Bash and correctly did not emit a marker.
The final narrow run used Claude's explicit non-interactive permission mode and
only Bash. Cleanup returned both isolated lists to `[]`; the existing user
GitHub marketplace/plugin source, installed path, and timestamps were unchanged.

## Independent final review

After fixes, the adversarial reviewer reran the validator, diff check, 12
focused bypass regressions, and test collection. Final assessment:

```text
Critical: none remaining
Important: none remaining
Minor: none remaining
Residual concern: none within the enumerated threat model
```

## Cleanup and residual concerns

- No Codex test marketplace, plugin, or cache remains.
- The isolated Claude marketplace and plugin lists are both empty.
- Temporary host evidence and Python-shim directories are removed after the
  reports are committed.
- No repository output or authoritative security state was created by host
  checks.
- PyYAML must be installed in the isolated interpreter's system or virtual
  environment. `-I` intentionally ignores user-site/PYTHONPATH packages; this
  is documented and is an environment prerequisite, not an unresolved code
  finding.
- Full conversational service scanning/interview/publication was not run; the
  required host evidence deliberately exercised safe packaged scripts through
  the real installed adapters.
