# Dual Claude and Codex plugin verification

Final-review update: 2026-08-12

Branch: `feat/dual-claude-codex-plugin`

Security-fix commits:

- `b0aed64 fix: harden dual-host plugin execution`
- `0596650 fix: root loaded runtime guidance`
- `727f0ec fix: close confirmation and preflight bypasses`
- `7e2fc56 fix: require canonical output preflights`
- `574ccef fix: close final portability gaps`

## Verdict

**PASS with the residual platform boundary documented below.** The final review's Critical,
Important, migration-remnant, minor, and evidence findings are closed,
including the later canonical-preflight and filesystem-redirect findings. The
exact Python 3.12 suite passes, as do the source distribution validator, the
Codex plugin validator, and both authoritative Claude strict validations.

This update supersedes the earlier evidence in this file. In particular, the
old read-only host checks and the old cross-call `export` adapter examples are
historical and are not relied on for this verdict. Commit
`574ccef8e7d65f3943f694d6ef1c0ef2eae18df7` received fresh installed-host
verification through isolated Claude and Codex configurations. The current
section below records the accepted commands, outputs, postconditions, and
cleanup.

## Environment

| Tool | Observed version |
|---|---|
| Prepared test interpreter | Python 3.12.11 |
| Codex | `codex-cli 0.147.0` |
| Claude Code | `2.1.145` |

The current suite and Python validators invoked the prepared interpreter by its
absolute path. Installed-host verification used a task-local `python3` shim
pointing to the same Python 3.12.11 interpreter:

```text
/tmp/security requirements final 테스트-574ccef.rjMWWJ/python shim Ω/python3
  -> /Users/s1ns3nz0/.pyenv/versions/3.12.11/bin/python
```

The exact containing temporary root was deleted after isolated host cleanup.

## Exact final validation

### Complete suite

```bash
PYTHONDONTWRITEBYTECODE=1 /Users/s1ns3nz0/.pyenv/versions/3.12.11/bin/python \
  -m pytest -p no:cacheprovider -q
```

Result:

```text
976 passed, 2 skipped in 46.75s
```

The skips were the real Windows `/J` integration on macOS and the
case-sensitive case-variant sibling integration on this case-insensitive
volume. The real macOS physical alias and `/tmp` regressions executed and
passed; portable predicate/error seams cover the unavailable cases.

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
The later `574ccef` portability fix supersedes only the project-parent part of
this historical result: redirects above the project are now accepted, while
root and project-contained output redirects remain rejected.

The earlier confirmation-state fix was also rerun without selection:

```text
33 passed in 0.88s
```

### Final portability follow-up

Thirteen regressions were written before the `574ccef` implementation. The
physical-containment, final-consumer, version-floor, junction, `/tmp`, and
metadata selection was RED with `11 failed`. Two exact additional broad
preflights that split `.security-requirements` or `docs/security` with a shell
line continuation were separately accepted by the old validator (`errors:
[]`), giving the remaining `2 failed`.

After implementation, the affected files were GREEN:

```text
952 passed, 2 skipped
```

The complete fresh run and validators are recorded above. An independent
implementation review also ran `176 passed, 2 skipped`, the distribution
validator, and `git diff --check`, and reported no Critical, Important, or
Minor issue within the five-finding scope.

## Final-review security closure

| Finding | Resolution and evidence |
|---|---|
| Inspected cwd could shadow Python startup/imports | All workflow Python calls are `python3 -I` plus an absolute packaged script. Inline `-c`, stdin, cwd-relative, arbitrary absolute, versioned-interpreter, multiline, and YAML-quoted bypasses are rejected by the validator. `test_packaged_cli_starts_in_isolated_mode_from_a_hostile_project` executes the packaged CLIs with poisoned `sitecustomize.py`, `pathlib.py`, and `yaml.py`. |
| Exports did not persist across tool calls and non-shell tools could not expand them | Claude captures exact roots once and every later operation independently prefixes the exact literals. The one initial canonical broad preflight intentionally retains `${CLAUDE_PLUGIN_ROOT}` for Claude; the Codex adapter replaces only that token with its loader-verified exact root. Read/Write/Edit and scoped-preflight instructions use exact literal paths. Structural tests cover every fenced block and confirmation-gate resume. |
| Neutral precedence could be overwritten | `plugin_data_root` retains `SECURITY_REQUIREMENTS_DATA > CLAUDE_PLUGIN_DATA > OS default`. Adapters explicitly forbid pre-setting the neutral variable during resolution. Unit tests exercise neutral, legacy, and default paths. |
| Authoritative state could live in or be redirected through the inspected project | `path_is_within_project` combines lexical and resolved containment with physical `os.path.samefile` comparison of each existing candidate ancestor. Runtime data-root resolution, the final `confirmations/<project-hash>.yaml` authority, and generated-service loading all use it. A real macOS `Repo`/`rEPO` alias and portable samefile/`OSError`/final-consumer seams pass. |
| Target output redirects could be followed | `safe_paths.py` centralizes symlink/junction detection at the canonical project root, each project-contained output ancestor, and the target; rejects raw `..` before lexical normalization; preflights complete output batches; and uses atomic replacement. Redirect ancestors above the project, including macOS `/tmp`, are not treated as project-owned, while a redirected root or internal output path remains rejected. Confirmation, baseline, classification, overlay, merge, and render sinks use the helper. The real Windows `/J` test was skipped; mandatory direct `Path.is_junction()` and portable boundary seams pass. |
| Shared skill trusted ambient redirection | `runtime_paths.py --skill` validates that the selected absolute `SKILL.md` belongs to its own payload and requires exact lexical/resolved agreement with any ambient root. |
| Migration remnants | Claude cross-command names are namespaced; baseline overlay commands are absolute and isolated; README, CONTRIBUTING, DESIGN, loaded reference files, HIPAA metadata, and missing-catalog remediation commands use moved/absolute trusted paths. `.gitignore` exposes only `.agents/plugins/marketplace.json`. |
| Mutation tool path escape/interruption | `--file` accepts only a contained, non-symlink packaged relative file. The copied file is restored in `finally`, including `KeyboardInterrupt`. Behavioral tests cover absolute, traversal, symlink, and interrupted runner cases. |
| Validator evasion | Broad-preflight validity no longer relies on reconstructing shell quote/control-flow semantics. Ordered `SAFE_OUTPUTS` centrally generates one exact source command per workflow; it must be the sole line of one executable `bash` fence, and the exact command must be the only broad candidate. Shell `\\`-newline continuation is reconstructed without inserting whitespace, so split `.security-requirements` and `docs/security` candidates are detected and rejected. Semantic tokenization rejects additional equivalent, malformed, path-normalized, or dynamic-output candidates and noncanonical Claude-root scoped calls. |
| Runtime version ambiguity | Runtime and plugin support is Python 3.12 or newer plus PyYAML. The bootstrap rejects older interpreters before normal output, all host metadata/skill frontmatters state the floor, and `Path.is_junction()` is mandatory on the supported runtime. |

This follow-up closes the canonical-preflight and filesystem-redirect findings
from the subsequent adversarial review. It does not claim a new independent
review of unrelated surfaces.

## Current-HEAD installed-host execution from an isolated hostile cwd

Commit `574ccef8e7d65f3943f694d6ef1c0ef2eae18df7` was installed separately in
task-local Codex and Claude configurations. The unrelated cwd, config, data,
and shim paths all contained spaces and Unicode. `PYTHONPATH` pointed at the
cwd, which contained poisoned `sitecustomize.py`, `pathlib.py`, and `yaml.py`.

```text
root: /tmp/security requirements final 테스트-574ccef.rjMWWJ
cwd:  /tmp/security requirements final 테스트-574ccef.rjMWWJ/hostile cwd Ω
data: /tmp/security requirements final 테스트-574ccef.rjMWWJ/external data Ω
```

Codex received a mode-0600 auth-file copy in its isolated config. Both hosts
registered the exact worktree and installed version `0.1.0`. The installed
`runtime_paths.py` and `safe_paths.py` copies on both hosts compared
byte-for-byte with current HEAD before and after execution.

### Codex

Three independent JSON-streamed sessions used
`codex exec --ephemeral --sandbox read-only --skip-git-repo-check`, one exact
manifest starter per session:

```text
Initialize the security requirements profile for this repository.
Build security requirements from the confirmed profile.
Refresh security requirements after service changes.
```

Each naturally selected the corresponding installed entry skill. Structured
command events prove execution under `python3 -I`:

```text
<installed>/scripts/runtime_paths.py --skill <selected absolute SKILL.md>
<installed>/scripts/runtime_paths.py --project-root "$PWD"
<installed>/scripts/safe_paths.py --project-root "$PWD" --check-output ...
```

All commands exited 0. Init checked `.security-requirements`; build and refresh
checked `.security-requirements docs/security`. Resolver stdout was:

```text
/private/tmp/security requirements final 테스트-574ccef.rjMWWJ/external data Ω
```

Accepted markers:

```text
CODEX_INIT_ADAPTER_EXEC_OK
CODEX_BUILD_ADAPTER_EXEC_OK
CODEX_REFRESH_ADAPTER_EXEC_OK
```

### Claude Code

Three accepted sessions used `--print --no-session-persistence
--permission-mode bypassPermissions --tools Bash --output-format stream-json`.
The namespaced commands were invoked separately:

```text
/security-requirements:sec-req-init
/security-requirements:sec-req-build
/security-requirements:sec-req-refresh
```

Every host-init event listed the installed plugin and requested command. Each
stream contained Bash tool-use/result pairs for the isolated installed
`runtime_paths.py` and `safe_paths.py` under `python3 -I`; all returned status
0 and the same canonical data-root stdout. Accepted markers:

```text
CLAUDE_INIT_ADAPTER_EXEC_OK
CLAUDE_BUILD_ADAPTER_EXEC_OK
CLAUDE_REFRESH_ADAPTER_EXEC_OK
```

One earlier init attempt successfully ran both scripts but exhausted its turn
cap while rediscovering the isolated cache and returned no marker; it was
discarded. The accepted rerun used the install root reported by the isolated
host and completed with the marker.

### Postconditions and cleanup

No `POISONED-*` marker, `.security-requirements`, `docs/security`, or external
data entry existed after the sessions. Exact plugin removal was followed by
exact marketplace removal on each isolated host. Final state was:

```text
Codex plugin list:       {"installed": [], "available": []}
Codex marketplace list:  {"marketplaces": []}
Claude plugin list:      []
Claude marketplace list: []
TEMP_ROOT_ABSENT
```

The exact temporary root, including the auth copy and retained isolated Claude
cache, was permanently deleted after validation. The real Codex config retained
SHA-256
`fa732d1031da27d71cf8425bdbc35e67ced0ce4aa9af129c7bcd811852579823`.
The pre-existing Claude GitHub marketplace source, plugin path/version and
timestamps, clean marketplace HEAD
`b987ae4a95563f0da619518e3c22913b30c85c19`, and five-file persistent-data
digest `6e8be6dbe1d31f028904c474ce843defda5682fe683d54dbb671f9802bf28de1`
were unchanged.

The full command transcript, installed script hashes, exact cleanup commands,
and before/after table are retained in
`.superpowers/sdd/2026-08-11-dual-claude-codex-plugin/final-portability-fix-report.md`.

## State and confirmation evidence

The full suite includes separate-process confirmation tests. The load-bearing
case stamps in one clean subprocess, checks in a second, mutates and rejects in
a third, and proves that a later call succeeds only when the exact external
state root is rebound. Other tests repeat neutral, legacy-only, and default-root
behavior, reject repository-only approval forgery, and reject both stamping and
checking when an ancestor state root makes the final authority artifact
project-owned.

## Residual limitations

The reviewed follow-up findings are closed. The real Windows `/J` integration
was unavailable on macOS, and the distinct-case-sibling integration was skipped
because this temporary filesystem is case-insensitive. Mandatory junction and
physical-containment behavior is covered by portable unit seams; the real
macOS case-insensitive project alias executed successfully. A preflight
followed by an independent model Write/Edit is still a check-then-use protocol
rather than an OS-level directory capability; the workflow narrows that
interval by requiring an immediate exact-target check, but does not claim to
eliminate a concurrent filesystem race.

YAML-using runtime scripts require PyYAML in the isolated interpreter's system
or virtual environment; user-site-only packages are deliberately ignored by
`-I`, and the README documents that prerequisite. Fresh current-HEAD
installed-host verification exercised adapter discovery and the packaged
runtime/output checks, not the side-effecting service scan, interview,
confirmation, derivation, or publication workflow; the deterministic suite
covers that business pipeline. No unrelated surface was reviewed or changed in
this follow-up.
