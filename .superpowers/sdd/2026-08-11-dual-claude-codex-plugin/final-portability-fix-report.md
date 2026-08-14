# Final portability fix report

Date: 2026-08-12

Implementation commit: `574ccef8e7d65f3943f694d6ef1c0ef2eae18df7`

## Result

PASS for the five requested findings. The implementation used a strict
RED/GREEN cycle, the complete deterministic suite and all distribution/host
validators pass, and current HEAD was installed and executed through both
host CLIs from an unrelated hostile working directory. No shared Codex or
Claude configuration, marketplace, plugin, cache, or persistent data was
changed by the installed-host check.

| Finding | Final behavior |
|---|---|
| Case-insensitive physical aliases | `path_is_within_project` combines lexical and resolved containment with `os.path.samefile` checks over every existing ancestor of both candidate forms. `OSError` is handled non-fatally while lexical and resolved checks remain in force. Runtime data-root selection, the final confirmation authority, and generated responsibility state all reject state physically owned by the inspected project. The real macOS `Repo`/`rEPO` alias case and portable samefile/error seams are covered. |
| Backslash-newline broad preflight | Shell logical lines remove, rather than whitespace-normalize, an exact line continuation. An additional broad candidate that splits either `.security-requirements` or `docs/security` is therefore reconstructed and rejected. The sole canonical one-line preflight remains accepted. |
| Junction runtime contract | Runtime and plugin support is explicitly Python 3.12 or newer plus PyYAML. Both bootstraps fail on an older interpreter before normal output. `Path.is_junction()` is mandatory rather than optional. README, CONTRIBUTING, both host manifests, the Claude marketplace entry, and all four Codex skill frontmatters state the floor. |
| macOS `/tmp` | `safe_paths.py` canonicalizes the physical project root but does not reject redirect ancestors above it. It still rejects a redirected project root and redirects at output ancestors/targets. A real macOS `/tmp` project passes; portable internal redirect seams fail. |
| Current-HEAD evidence | Codex init/build/refresh and Claude namespaced init/build/refresh each executed installed `runtime_paths.py` and `safe_paths.py` under `python3 -I`, returned status 0, and emitted their unique success marker. Exact isolated state was removed and real user state matched its pre-run snapshot. |

## Strict TDD evidence

Thirteen focused regressions were added before implementation.

The initial physical-containment, final-consumer, Python-floor, junction, `/tmp`,
and metadata selection was RED:

```text
11 failed
```

The two exact broad-preflight mutants were also run against the old validator
independently. Each appended a trusted legacy broad call beside the canonical
call while splitting one protected output with `\\` plus newline:

```text
.security-require\\
ments

docs/sec\\
urity
```

The old validator returned no error for either fixture, so both regressions
failed as intended:

```text
2 failed
validator errors for each mutated sec-req-build.md: []
```

After the minimal implementation, the affected test files were GREEN:

```text
952 passed, 2 skipped
```

The regressions cover:

- a real macOS case-insensitive `Repo`/`rEPO` samefile alias, gated when the
  temporary filesystem is case-sensitive;
- a samefile ancestor seam for a nonexistent final suffix, an `OSError` seam,
  and the distinct-case sibling converse;
- both final consumers: `confirmations/<project-hash>.yaml` and generated
  responsibility service state;
- the two exact line-continuation mutants and preservation of the canonical
  one-line rule;
- a redirect above the project, a real project below macOS `/tmp`, and
  simulated junctions at the root, output ancestor, and target;
- older-interpreter stderr-only bootstrap failures, mandatory direct
  `is_junction`, and documented/packaged Python 3.12 metadata.

## Complete deterministic verification

The exact interpreter and command were:

```bash
PYTHONDONTWRITEBYTECODE=1 \
  /Users/s1ns3nz0/.pyenv/versions/3.12.11/bin/python \
  -m pytest -p no:cacheprovider -q
```

Result:

```text
976 passed, 2 skipped in 46.75s
```

The two platform skips are the real Windows `/J` integration on macOS and the
case-sensitive case-variant sibling integration on this case-insensitive
volume. Their portable predicate/seam coverage passed. The real macOS alias
and `/tmp` regressions passed.

Validators and hygiene checks:

```bash
/Users/s1ns3nz0/.pyenv/versions/3.12.11/bin/python scripts/validate_distribution.py .
/Users/s1ns3nz0/.pyenv/versions/3.12.11/bin/python \
  /Users/s1ns3nz0/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py \
  plugins/security-requirements
claude plugin validate --strict plugins/security-requirements
claude plugin validate --strict .
find plugins/security-requirements -type l -print
git diff --check
```

Results:

```text
distribution validator: no output, exit 0
Codex plugin validator: Plugin validation passed
Claude payload manifest: Validation passed
Claude marketplace manifest: Validation passed
payload symlink audit: no output, exit 0
diff check: no output, exit 0
```

An independent implementation review found no Critical, Important, or Minor
issue in the requested scope. Its own verification returned `176 passed,
2 skipped`, a clean validator, and a clean diff check.

## Current-HEAD installed-host execution

### Isolation and hostile environment

Observed host versions:

```text
Python 3.12.11
codex-cli 0.147.0
Claude Code 2.1.145
```

The test used the exact implementation commit and these temporary paths:

```text
root:   /tmp/security requirements final 테스트-574ccef.rjMWWJ
cwd:    /tmp/security requirements final 테스트-574ccef.rjMWWJ/hostile cwd Ω
data:   /tmp/security requirements final 테스트-574ccef.rjMWWJ/external data Ω
Codex:  /tmp/security requirements final 테스트-574ccef.rjMWWJ/Codex config Ω
Claude: /tmp/security requirements final 테스트-574ccef.rjMWWJ/Claude config Ω
shim:   /tmp/security requirements final 테스트-574ccef.rjMWWJ/python shim Ω/python3
```

The shim targeted
`/Users/s1ns3nz0/.pyenv/versions/3.12.11/bin/python`. `PYTHONPATH` pointed at
the hostile cwd. That directory contained `sitecustomize.py`, `pathlib.py`, and
`yaml.py`; each would create its own `POISONED-*` marker and raise if imported.
The Codex config received only a mode-0600 copy of the existing authentication
file. No credential contents were printed or recorded.

Both isolated hosts registered the exact worktree and installed
`security-requirements@security-requirements` version `0.1.0`:

```bash
env CODEX_HOME="$E2E_CODEX_CONFIG" \
  codex plugin marketplace add "$WORKTREE" --json
env CODEX_HOME="$E2E_CODEX_CONFIG" \
  codex plugin add security-requirements@security-requirements --json

env CLAUDE_CONFIG_DIR="$E2E_CLAUDE_CONFIG" \
  claude plugin marketplace add "$WORKTREE"
env CLAUDE_CONFIG_DIR="$E2E_CLAUDE_CONFIG" \
  claude plugin install security-requirements@security-requirements
```

Install metadata bound Claude to commit
`574ccef8e7d65f3943f694d6ef1c0ef2eae18df7`. Before execution, both installed
copies of each runtime script compared byte-for-byte with current HEAD:

```text
runtime_paths.py  1460d1004f930d4658172bfcac9274aab2bec126831f4861ee9d8c731d3e87ee
safe_paths.py      9f09f687ad4a35e819476f0ef0faf8ccd906622666b5f114d9d3418de30319ee
Codex runtime_paths.py byte-identical
Codex safe_paths.py byte-identical
Claude runtime_paths.py byte-identical
Claude safe_paths.py byte-identical
```

### Codex

Three independent sessions used:

```bash
env CODEX_HOME="$E2E_CODEX_CONFIG" \
  PATH="$E2E_PYTHON_SHIM:$PATH" \
  PYTHONPATH="$E2E_CWD" \
  SECURITY_REQUIREMENTS_DATA="$E2E_DATA" \
  codex exec --json --ephemeral --sandbox read-only \
    --skip-git-repo-check --color never -C "$E2E_CWD" '<prompt>'
```

The exact manifest starters were supplied one per session:

```text
Initialize the security requirements profile for this repository.
Build security requirements from the confirmed profile.
Refresh security requirements after service changes.
```

Structured events show natural selection of the installed
`security-requirements-{init,build,refresh}/SKILL.md`, then real
`command_execution` events for the installed scripts. Init checked only
`.security-requirements`; build and refresh checked both
`.security-requirements` and `docs/security`.

Representative exact commands, with the selected skill suffix varying by
session, were:

```bash
python3 -I '<installed Codex root>/scripts/runtime_paths.py' \
  --skill '<installed Codex root>/skills/security-requirements-init/SKILL.md'
python3 -I '<installed Codex root>/scripts/runtime_paths.py' \
  --project-root "$PWD"
python3 -I '<installed Codex root>/scripts/safe_paths.py' \
  --project-root "$PWD" \
  --check-output .security-requirements docs/security
```

Every command exited 0. The resolver stdout was:

```text
/private/tmp/security requirements final 테스트-574ccef.rjMWWJ/external data Ω
```

The safe-path checks had empty stdout. Accepted markers:

```text
CODEX_INIT_ADAPTER_EXEC_OK
CODEX_BUILD_ADAPTER_EXEC_OK
CODEX_REFRESH_ADAPTER_EXEC_OK
```

### Claude Code

Three independent accepted sessions used:

```bash
cd "$E2E_CWD"
env CLAUDE_CONFIG_DIR="$E2E_CLAUDE_CONFIG" \
  PATH="$E2E_PYTHON_SHIM:$PATH" \
  PYTHONPATH="$E2E_CWD" \
  SECURITY_REQUIREMENTS_DATA="$E2E_DATA" \
  claude --print --no-session-persistence \
    --permission-mode bypassPermissions --tools Bash \
    --output-format stream-json --verbose --max-turns 8 '<command and audit prompt>'
```

The namespaced commands were invoked one per session:

```text
/security-requirements:sec-req-init
/security-requirements:sec-req-build
/security-requirements:sec-req-refresh
```

Each host-init event listed the installed plugin and the requested namespaced
command. The isolated host's `plugin list --json` install root was supplied as
an exact literal to avoid deriving it from hostile content. Each stream then
contained two Bash tool-use/result pairs:

```bash
python3 -I '<installed Claude root>/scripts/runtime_paths.py' \
  --project-root "$PWD"
python3 -I '<installed Claude root>/scripts/safe_paths.py' \
  --project-root "$PWD" \
  --check-output .security-requirements docs/security
```

Init again used only `.security-requirements` for the second call. Every
accepted tool result reported exit status 0, the resolver printed the same
canonical `/private/tmp/.../external data Ω` root, and safe paths printed
nothing. Accepted markers:

```text
CLAUDE_INIT_ADAPTER_EXEC_OK
CLAUDE_BUILD_ADAPTER_EXEC_OK
CLAUDE_REFRESH_ADAPTER_EXEC_OK
```

One earlier Claude init attempt is deliberately excluded: it executed both
scripts successfully but spent its remaining turns rediscovering the isolated
cache and hit `error_max_turns` before returning a marker. The deterministic
rerun above used the host-reported install root directly and completed in three
turns with the marker.

### Postconditions and cleanup

Before uninstall:

```text
POISONED-* markers: none
.security-requirements: absent
docs/security: absent
external data entries: 0
both installed script pairs still byte-identical to current HEAD
```

Exact isolated removal commands:

```bash
env CODEX_HOME="$E2E_CODEX_CONFIG" \
  codex plugin remove security-requirements@security-requirements --json
env CODEX_HOME="$E2E_CODEX_CONFIG" \
  codex plugin marketplace remove security-requirements --json

env CLAUDE_CONFIG_DIR="$E2E_CLAUDE_CONFIG" \
  claude plugin uninstall security-requirements@security-requirements --keep-data
env CLAUDE_CONFIG_DIR="$E2E_CLAUDE_CONFIG" \
  claude plugin marketplace remove security-requirements
```

Final isolated queries returned:

```text
Codex plugin list:       {"installed": [], "available": []}
Codex marketplace list:  {"marketplaces": []}
Claude plugin list:      []
Claude marketplace list: []
```

The exact temporary root was validated as a directory rather than a symlink,
then permanently removed with `find <exact-root> -depth -delete`. This also
removed Claude's isolated post-uninstall cache and the copied Codex auth file.
Final proof:

```text
TEMP_ROOT_ABSENT
```

The temporary evidence state is intentionally not recoverable.

### Shared user-state before/after proof

| Shared state | Before | After |
|---|---|---|
| `~/.codex/config.toml` SHA-256 | `fa732d1031da27d71cf8425bdbc35e67ced0ce4aa9af129c7bcd811852579823` | same |
| Exact real Codex plugin/marketplace filters | `[]` / `[]` | `[]` / `[]` |
| Real Claude plugin | version `0.1.0`, path under `~/.claude/plugins/cache`, installed/updated `2026-07-27T05:45:23.652Z` | identical |
| Real Claude marketplace | GitHub `s1ns3nz0/security-requirements` at the same install location | identical |
| Real marketplace checkout | HEAD `b987ae4a95563f0da619518e3c22913b30c85c19`, expected origin, clean | identical |
| Real persistent data | 5 files, digest `6e8be6dbe1d31f028904c474ce843defda5682fe683d54dbb671f9802bf28de1` | identical |

## Residual boundary

- A real Windows junction host was unavailable. The Windows `/J` integration
  remains skipped on macOS; mandatory junction behavior is covered by direct
  supported-runtime and portable boundary tests.
- The accepted installed-host runs intentionally exercised adapter discovery,
  installed packaged execution, isolation, state-root resolution, and output
  preflight only. They did not perform the side-effecting service interview,
  confirmation, derivation, or publication workflow. The deterministic
  978-test suite covers that business pipeline.
- A preflight followed by a separate model write remains a check-then-use
  protocol rather than an OS directory capability; this change does not claim
  to remove an adversarial concurrent filesystem race.
- No unrelated hardening surface was reviewed or changed in this follow-up.
