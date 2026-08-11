# Dual Claude and Codex plugin verification

Final-review update: 2026-08-12

Branch: `feat/dual-claude-codex-plugin`

Security-fix commits:

- `b0aed64 fix: harden dual-host plugin execution`
- `0596650 fix: root loaded runtime guidance`
- `727f0ec fix: close confirmation and preflight bypasses`
- `7e2fc56 fix: require canonical output preflights`

## Verdict

**PASS with platform evidence qualified below.** The final review's Critical,
Important, migration-remnant, minor, and evidence findings are closed,
including the later canonical-preflight and filesystem-redirect findings. The
exact Python 3.12 suite passes, as do the source distribution validator, the
Codex plugin validator, and both authoritative Claude strict validations.

This update supersedes the earlier evidence in this file. In particular, the
old read-only host checks and the old cross-call `export` adapter examples are
historical and are not relied on for this verdict. The installed-host section
records the earlier `b0aed64` execution; installed hosts were not rerun after
`7e2fc56`. Current adapter behavior is covered by source-contract tests and the
host schema validators, not claimed as fresh installed-host execution.

## Environment

| Tool | Observed version |
|---|---|
| Prepared test interpreter | Python 3.12.11 |
| Codex | `codex-cli 0.147.0` |
| Claude Code | `2.1.145` |

The current suite and Python validators invoked the prepared interpreter by its
absolute path. The temporary `python3` PATH shim below belongs to the historical
installed-host run:

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
964 passed, 1 skipped in 46.13s
```

### Distribution and host-schema validators

```bash
/Users/s1ns3nz0/.pyenv/versions/3.12.11/bin/python scripts/validate_distribution.py .
/Users/s1ns3nz0/.pyenv/versions/3.12.11/bin/python /Users/s1ns3nz0/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py plugins/security-requirements
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

### Canonical-preflight and redirect follow-up

The follow-up at `7e2fc56` used separate RED checks before implementation. The
initial source mutations were all accepted by the old semantic parser, and the
portable junction seam showed every simulated junction boundary was accepted:

```text
24 failed, 85 deselected in 3.02s
4 failed, 111 deselected in 1.08s
```

Review then added executable-context, combined quote-splicing,
path-equivalence, raw parent-segment, dynamic-output, path-scoped trust, and
Windows exact-case regressions. Each new group failed before its corresponding
implementation. Representative RED results were:

```text
8 failed, 3 passed, 117 deselected in 1.12s
1 failed in 0.11s
2 failed, 5 deselected in 0.27s
2 failed in 1.45s
```

After implementation, the focused distribution/workflow contract was GREEN:

```text
150 passed, 1 skipped in 24.67s
```

The skip is the real Windows `/J` integration test on this macOS host. The
same redirect predicate was exercised platform-independently at project-parent,
project-root, output-ancestor, and output-target boundaries by monkeypatching
the `Path.is_junction` seam. `PureWindowsPath` separately verifies that the
exact-case component-prefix check rejects a `repo`/`REPO` sibling even though
the standard Windows pathlib containment comparison considers it relative.
Neither seam is represented as a real Windows filesystem execution.

The earlier confirmation-state fix was also rerun without selection:

```text
33 passed in 0.88s
```

## Final-review security closure

| Finding | Resolution and evidence |
|---|---|
| Inspected cwd could shadow Python startup/imports | All workflow Python calls are `python3 -I` plus an absolute packaged script. Inline `-c`, stdin, cwd-relative, arbitrary absolute, versioned-interpreter, multiline, and YAML-quoted bypasses are rejected by the validator. `test_packaged_cli_starts_in_isolated_mode_from_a_hostile_project` executes the packaged CLIs with poisoned `sitecustomize.py`, `pathlib.py`, and `yaml.py`. |
| Exports did not persist across tool calls and non-shell tools could not expand them | Claude captures exact roots once and every later operation independently prefixes the exact literals. The one initial canonical broad preflight intentionally retains `${CLAUDE_PLUGIN_ROOT}` for Claude; the Codex adapter replaces only that token with its loader-verified exact root. Read/Write/Edit and scoped-preflight instructions use exact literal paths. Structural tests cover every fenced block and confirmation-gate resume. |
| Neutral precedence could be overwritten | `plugin_data_root` retains `SECURITY_REQUIREMENTS_DATA > CLAUDE_PLUGIN_DATA > OS default`. Adapters explicitly forbid pre-setting the neutral variable during resolution. Unit tests exercise neutral, legacy, and default paths. |
| Authoritative state could live in or be redirected through the inspected project | Runtime resolution compares lexical and resolved paths with the inspected project. Confirmation and generated-service loading bind the project explicitly. `confirmation_state_path` now also resolves the final `confirmations/<project-hash>.yaml` artifact and rejects it if an ancestor data root would place that artifact in the project. Generated state is checked with the centralized symlink-safe helper before reading. Direct, ancestor, forged-authority, and project-owned redirect tests pass. |
| Target output redirects could be followed | `safe_paths.py` centralizes symlink/junction detection across every project-root ancestor, root, output ancestor, and target; rejects raw `..` before lexical normalization; preserves exact-case lexical and resolved containment; preflights complete output batches; and uses atomic replacement. Confirmation, baseline, classification, overlay, merge, and render sinks use the helper. Workflow model writes receive a fresh exact-target preflight immediately before every Write/Edit. Junction behavior is proven through a portable seam here; the real Windows `/J` test was skipped. |
| Shared skill trusted ambient redirection | `runtime_paths.py --skill` validates that the selected absolute `SKILL.md` belongs to its own payload and requires exact lexical/resolved agreement with any ambient root. |
| Migration remnants | Claude cross-command names are namespaced; baseline overlay commands are absolute and isolated; README, CONTRIBUTING, DESIGN, loaded reference files, HIPAA metadata, and missing-catalog remediation commands use moved/absolute trusted paths. `.gitignore` exposes only `.agents/plugins/marketplace.json`. |
| Mutation tool path escape/interruption | `--file` accepts only a contained, non-symlink packaged relative file. The copied file is restored in `finally`, including `KeyboardInterrupt`. Behavioral tests cover absolute, traversal, symlink, and interrupted runner cases. |
| Validator evasion | Broad-preflight validity no longer relies on reconstructing shell quote/control-flow semantics. Ordered `SAFE_OUTPUTS` centrally generates one exact source command per workflow; it must be the sole line of one executable `bash` fence, and the exact command must be the only broad candidate. Semantic tokenization is used only to reject additional equivalent, malformed, path-normalized, or dynamic-output candidates and noncanonical Claude-root scoped calls. The runtime `safe_paths` parser remains independently strict about abbreviations and duplicate options. |

This follow-up closes the canonical-preflight and filesystem-redirect findings
from the subsequent adversarial review. It does not claim a new independent
review of unrelated surfaces.

## Historical installed-host execution from a hostile cwd

This section records the earlier `b0aed64` run and was not rerun for
`7e2fc56`.

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

The reviewed follow-up findings are closed. A real Windows junction and a
case-sensitive NTFS directory were not available: those properties are covered
by portable unit seams, while the real `/J` integration remains skipped on
non-Windows hosts. A preflight followed by an independent model Write/Edit is
still a check-then-use protocol rather than an OS-level directory capability;
the workflow narrows that interval by requiring an immediate exact-target
check, but does not claim to eliminate a concurrent filesystem race.

YAML-using runtime scripts require PyYAML in the isolated interpreter's system
or virtual environment; user-site-only packages are deliberately ignored by
`-I`, and the README documents that prerequisite. Installed-host execution was
not repeated after `7e2fc56`; the historical run exercised only safe read-only
path/output checks rather than a side-effecting end-to-end service interview
and publication. No new independent review of unrelated surfaces was performed
for this follow-up.
