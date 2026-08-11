# Dual Claude and Codex plugin verification

Date: 2026-08-11

Branch: `feat/dual-claude-codex-plugin`

Validated commit before this report: `2564c09` (`fix: reject cwd-relative payload invocations`)

## Verdict

**INCOMPLETE.** Every repository-controlled test and validator passed. Both
hosts installed the exact local clone in isolated/reversible state, and both
completed non-mutating live discovery and payload-resolution checks. The one
remaining gap is literal end-to-end execution of init, build, and refresh
through both hosts: those workflows intentionally scan, interview, gate on user
confirmation, and write artifacts, so an audit-only invocation cannot exercise
them without expanding the authorized side effects. Structural and
deterministic evidence for those workflow stages is recorded separately below.

## Environment

| Tool | Observed version |
|---|---|
| Test interpreter | `Python 3.12.11`, exposed as `python3` by a temporary PATH shim |
| System `python3` | `Python 3.14.3` |
| Codex | `codex-cli 0.147.0` |
| Claude Code | `2.1.145` |

The brief's exact `python3` commands were run unchanged. A temporary directory
outside the repository placed a symlink to the working Python 3.12 executable
first on PATH:

```bash
python -c 'import sys; print(sys.executable)'
mktemp -d /tmp/security-requirements-python312.XXXXXX
ln -s /Users/s1ns3nz0/.pyenv/versions/3.12.11/bin/python /tmp/security-requirements-python312-final.dQ9aZP/python3
export PATH="/tmp/security-requirements-python312-final.dQ9aZP:$PATH"
command -v python3
python3 --version
```

Setup output:

```text
/Users/s1ns3nz0/.pyenv/versions/3.12.11/bin/python
/tmp/security-requirements-python312-final.dQ9aZP
/tmp/security-requirements-python312-final.dQ9aZP/python3
Python 3.12.11
```

## Regression and validator evidence

### Full suite

Command:

```bash
python3 -m pytest -q
```

Final output:

```text
........................................................................ [  8%]
........................................................................ [ 17%]
........................................................................ [ 26%]
........................................................................ [ 34%]
........................................................................ [ 43%]
........................................................................ [ 52%]
........................................................................ [ 60%]
........................................................................ [ 69%]
........................................................................ [ 78%]
........................................................................ [ 86%]
........................................................................ [ 95%]
......................................                                   [100%]
830 passed in 21.37s
```

Exit code: `0`.

### Distribution validator

Command:

```bash
python3 scripts/validate_distribution.py .
```

Output: empty. Exit code: `0`.

### Codex plugin validator

Command:

```bash
python3 /Users/s1ns3nz0/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py plugins/security-requirements
```

Output:

```text
Plugin validation passed: /Users/s1ns3nz0/orca/projects/security-design/.worktrees/dual-claude-codex-plugin/plugins/security-requirements
```

Exit code: `0`.

## Reference and payload audit

Prescribed command:

```bash
rg -n 'python3[[:space:]]+scripts/|CLAUDE_PLUGIN_ROOT|CLAUDE_PLUGIN_DATA' plugins/security-requirements
```

Output (all matches):

```text
plugins/security-requirements/commands/sec-req-refresh.md:6:export SECURITY_REQUIREMENTS_ROOT="${CLAUDE_PLUGIN_ROOT}"
plugins/security-requirements/commands/sec-req-refresh.md:7:if [ -n "${CLAUDE_PLUGIN_DATA:-}" ]; then
plugins/security-requirements/commands/sec-req-refresh.md:8:  export SECURITY_REQUIREMENTS_DATA="${CLAUDE_PLUGIN_DATA}"
plugins/security-requirements/commands/sec-req-build.md:6:export SECURITY_REQUIREMENTS_ROOT="${CLAUDE_PLUGIN_ROOT}"
plugins/security-requirements/commands/sec-req-build.md:7:if [ -n "${CLAUDE_PLUGIN_DATA:-}" ]; then
plugins/security-requirements/commands/sec-req-build.md:8:  export SECURITY_REQUIREMENTS_DATA="${CLAUDE_PLUGIN_DATA}"
plugins/security-requirements/commands/sec-req-init.md:6:export SECURITY_REQUIREMENTS_ROOT="${CLAUDE_PLUGIN_ROOT}"
plugins/security-requirements/commands/sec-req-init.md:7:if [ -n "${CLAUDE_PLUGIN_DATA:-}" ]; then
plugins/security-requirements/commands/sec-req-init.md:8:  export SECURITY_REQUIREMENTS_DATA="${CLAUDE_PLUGIN_DATA}"
plugins/security-requirements/scripts/runtime_paths.py:25:    any host. ``CLAUDE_PLUGIN_DATA`` remains a compatibility fallback.
plugins/security-requirements/scripts/runtime_paths.py:28:    for name in ("SECURITY_REQUIREMENTS_DATA", "CLAUDE_PLUGIN_DATA"):
```

The matches are limited to the three Claude compatibility adapters and the
persistent-state compatibility resolver. There were no
`python3 scripts/...` matches. Exit code: `0`, because the allowed compatibility
matches exist.

Command:

```bash
find plugins/security-requirements -type l -print
```

Output: empty. Exit code: `0`.

`git diff --check` also returned no output with exit code `0` before the fix
commit.

### Audit defect found and corrected

The first prescribed reference audit found 19 stale `python3 scripts/...`
examples in packaged script docstrings and HIPAA overlay metadata. Root cause:
the payload migration moved those files without updating their root-level usage
examples, and the distribution validator did not scan payload text for this
invariant.

The regression test
`tests/test_distribution_docs.py::test_distribution_validator_rejects_cwd_relative_payload_script_invocations`
was added and observed failing before implementation:

```text
FAILED tests/test_distribution_docs.py::test_distribution_validator_rejects_cwd_relative_payload_script_invocations
1 failed in 0.42s
```

After the fix, the focused check produced:

```text
..                                                                       [100%]
2 passed in 0.41s
```

Fix-round review found that the first guard recognized only literal
`python3 scripts/...`; `python`, interpreter flags, and flags with separate
values could bypass it. The existing test was parameterized over these literal
cases:

```text
python scripts/lint.py requirements.yaml
python3 scripts/lint.py requirements.yaml
python -I scripts/lint.py requirements.yaml
python3 -u -B scripts/lint.py requirements.yaml
python3 -X utf8 scripts/lint.py requirements.yaml
```

Before broadening the matcher, the focused run produced:

```text
F.FFF                                                                    [100%]
4 failed, 1 passed in 0.70s
```

After implementation:

```text
.....                                                                    [100%]
5 passed in 0.60s
```

The validator now reports cwd-relative packaged invocations made with either
`python` or `python3`, including interpreter options before `scripts/...`, with
a payload-relative file and line number. All shipped examples use
`${SECURITY_REQUIREMENTS_ROOT}`.

Adding the regression test intentionally tripped
`tests/test_pipeline.py::test_the_test_count_on_the_front_page_is_the_test_count`
because README still claimed 825 tests. The original report updated it to 826;
the four additional parameter cases in this fix round raised collection to 830,
and the final README count and suite output now agree at 830.

## Separate-process confirmation-state smoke tests

A temporary project was created under
`/tmp/security-requirements-task6.EWMNo9`. Every stamp and check below was a
separate Python process. The temporary directory was moved to Trash after the
checks.

### Neutral state (`SECURITY_REQUIREMENTS_DATA`)

The sequence stamped a copied golden profile, checked it, changed
`locale: en` to `locale: ko`, checked the changed profile, restored the stamped
repository copy, and checked it against a new empty external state root.

Exact output:

```text
confirmed /tmp/security-requirements-task6.EWMNo9/neutral-project/.security-requirements/profile.yaml (sha256:b2b4e435faa9f69e0d94526f04ec345ba2846ad8a38797759b2e44f9bb134d66)
neutral_stamp_exit=0
neutral_check_exit=0
ERROR: profile changed after confirmation; run the confirmation gate again
neutral_mutated_check_exit=1
ERROR: plugin-owned confirmation state is missing
neutral_repository_only_check_exit=1
/tmp/security-requirements-task6.EWMNo9/neutral-state/confirmations/960b543eab241ecc6f45600986b1f76c7e98f82fcced497d9425a5e5039018e0.yaml
```

### Legacy Claude state (`CLAUDE_PLUGIN_DATA`)

The same sequence was run with `SECURITY_REQUIREMENTS_DATA` unset and only the
legacy Claude variable set.

Exact output:

```text
confirmed /tmp/security-requirements-task6.EWMNo9/legacy-project/.security-requirements/profile.yaml (sha256:b2b4e435faa9f69e0d94526f04ec345ba2846ad8a38797759b2e44f9bb134d66)
legacy_stamp_exit=0
legacy_check_exit=0
ERROR: profile changed after confirmation; run the confirmation gate again
legacy_mutated_check_exit=1
ERROR: plugin-owned confirmation state is missing
legacy_repository_only_check_exit=1
/tmp/security-requirements-task6.EWMNo9/legacy-state/confirmations/2b8ffdaf76e11f14b7dd7381c8f43618033dc6763d9a19ec7927a3b332960225.yaml
```

This directly proves persistence across invocations, digest invalidation, the
repository-only forgery rejection, neutral state behavior, and legacy Claude
compatibility.

## Clean-clone host installation smoke tests

### Codex: installation, live discovery, and restoration passed

These were the exact precheck, registration, installation, listing, and cache
commands. The `rg` filters intentionally omit unrelated user plugins:

```bash
codex plugin marketplace list | rg '^security-requirements([[:space:]]|$)'
codex plugin list | rg '^security-requirements@'
test -e /Users/s1ns3nz0/.codex/plugins/cache/security-requirements/security-requirements/0.1.0
find '/Users/s1ns3nz0/Library/Application Support/security-requirements/v1' -type f 2>/dev/null | wc -l | tr -d ' '
codex plugin marketplace add /Users/s1ns3nz0/orca/projects/security-design/.worktrees/dual-claude-codex-plugin --json
codex plugin list --marketplace security-requirements --available --json
codex plugin add security-requirements@security-requirements --json
codex plugin list --marketplace security-requirements --json
find /Users/s1ns3nz0/.codex/plugins/cache/security-requirements/security-requirements/0.1.0/skills -mindepth 2 -maxdepth 2 -name SKILL.md -print | sort
test -f /Users/s1ns3nz0/.codex/plugins/cache/security-requirements/security-requirements/0.1.0/.codex-plugin/plugin.json
```

Both precheck filters and the exact-cache precheck returned the expected
no-match/nonexistence exit `1`. Marketplace add returned:

```json
{
  "marketplaceName": "security-requirements",
  "installedRoot": "/Users/s1ns3nz0/orca/projects/security-design/.worktrees/dual-claude-codex-plugin",
  "alreadyAdded": false
}
```

Plugin add returned:

```json
{
  "pluginId": "security-requirements@security-requirements",
  "name": "security-requirements",
  "marketplaceName": "security-requirements",
  "version": "0.1.0",
  "installedPath": "/Users/s1ns3nz0/.codex/plugins/cache/security-requirements/security-requirements/0.1.0",
  "authPolicy": "ON_INSTALL"
}
```

The installed JSON listing reported `installed: true`, `enabled: true`, the
exact local worktree source, `AVAILABLE`, and `ON_INSTALL`. The cache check found
the shared derivation skill plus init/build/refresh entry skills and the Codex
manifest; its exit code was `0`.

The load-bearing read-only invocation was:

```bash
codex exec --ephemeral --sandbox read-only --color never \
  -C /Users/s1ns3nz0/orca/projects/security-design/.worktrees/dual-claude-codex-plugin \
  -o /tmp/security-requirements-codex-e2e-final.txt \
  'Use the installed security-requirements-init, security-requirements-build, and security-requirements-refresh skills for an audit-only read. Do not run workflows or scripts, do not enumerate the payload, and do not write project files. Read only the three selected SKILL.md files, their matching sec-req-init.md, sec-req-build.md, and sec-req-refresh.md files, the shared deriving-security-requirements/SKILL.md, and .codex-plugin/plugin.json. Return a concise list with each selected skill absolute path, resolved common payload root, each matching command absolute path, shared skill frontmatter name, all three defaultPrompt strings verbatim, then E2E_READ_ONLY_OK. Emit the marker only if all eight installed-plugin files were actually read.'
```

Exit code was `0`. The final message named all three cache skill paths, the
common installed payload root, all three command paths, shared skill name
`deriving-security-requirements`, and the three manifest prompts verbatim:

```text
- Skill: /Users/s1ns3nz0/.codex/plugins/cache/security-requirements/security-requirements/0.1.0/skills/security-requirements-init/SKILL.md
  Command: /Users/s1ns3nz0/.codex/plugins/cache/security-requirements/security-requirements/0.1.0/commands/sec-req-init.md
- Skill: /Users/s1ns3nz0/.codex/plugins/cache/security-requirements/security-requirements/0.1.0/skills/security-requirements-build/SKILL.md
  Command: /Users/s1ns3nz0/.codex/plugins/cache/security-requirements/security-requirements/0.1.0/commands/sec-req-build.md
- Skill: /Users/s1ns3nz0/.codex/plugins/cache/security-requirements/security-requirements/0.1.0/skills/security-requirements-refresh/SKILL.md
  Command: /Users/s1ns3nz0/.codex/plugins/cache/security-requirements/security-requirements/0.1.0/commands/sec-req-refresh.md
- Common payload root: /Users/s1ns3nz0/.codex/plugins/cache/security-requirements/security-requirements/0.1.0
- Shared skill frontmatter name: deriving-security-requirements
- defaultPrompt:
  - Initialize the security requirements profile for this repository.
  - Build security requirements from the confirmed profile.
  - Refresh security requirements after service changes.

E2E_READ_ONLY_OK
```

Two unrelated pre-existing Notion connector authentication errors appeared at
startup and are omitted here; they did not prevent plugin discovery or file
reads. The process was `--ephemeral`, approval was `never`, and sandbox mode was
`read-only`.

Exact removal and restoration checks:

```bash
plugin_state_root=$(env -u SECURITY_REQUIREMENTS_DATA -u CLAUDE_PLUGIN_DATA python plugins/security-requirements/scripts/runtime_paths.py)
codex plugin remove security-requirements@security-requirements --json
codex plugin marketplace remove security-requirements --json
codex plugin marketplace list | rg '^security-requirements([[:space:]]|$)'
codex plugin list | rg '^security-requirements@'
test -e /Users/s1ns3nz0/.codex/plugins/cache/security-requirements/security-requirements/0.1.0
```

The external state root remained
`/Users/s1ns3nz0/Library/Application Support/security-requirements/v1` with zero
files before and after. Both post-removal filters and the cache-existence check
returned `1`, proving the exact test entries/cache were absent again. Removal
returned the exact plugin and marketplace names; the marketplace
`installedRoot` was `null` after removal.

### Claude Code: isolated installation and live command invocation passed

The original user state was captured without printing unrelated entries:

```bash
claude plugin marketplace list --json | jq '.[] | select(.name == "security-requirements")'
claude plugin list --json | jq '.[] | select(.id == "security-requirements@security-requirements" or .name == "security-requirements")'
git -C /Users/s1ns3nz0/.claude/plugins/marketplaces/security-requirements rev-parse HEAD
git -C /Users/s1ns3nz0/.claude/plugins/marketplaces/security-requirements remote get-url origin
git -C /Users/s1ns3nz0/.claude/plugins/marketplaces/security-requirements status --short
find /Users/s1ns3nz0/.claude/plugins/data/security-requirements-security-requirements -type f | wc -l | tr -d ' '
find /Users/s1ns3nz0/.claude/plugins/data/security-requirements-security-requirements -type f -print0 | sort -z | xargs -0 shasum -a 256 | shasum -a 256
```

The exact filtered JSON and state output was:

```text
{
  "name": "security-requirements",
  "source": "github",
  "repo": "s1ns3nz0/security-requirements",
  "installLocation": "/Users/s1ns3nz0/.claude/plugins/marketplaces/security-requirements"
}
{
  "id": "security-requirements@security-requirements",
  "version": "0.1.0",
  "scope": "user",
  "enabled": true,
  "installPath": "/Users/s1ns3nz0/.claude/plugins/cache/security-requirements/security-requirements/0.1.0",
  "installedAt": "2026-07-27T05:45:23.652Z",
  "lastUpdated": "2026-07-27T05:45:23.652Z"
}
b987ae4a95563f0da619518e3c22913b30c85c19
https://github.com/s1ns3nz0/security-requirements.git
5
6e8be6dbe1d31f028904c474ce843defda5682fe683d54dbb671f9802bf28de1  -
```

Marketplace `git status --short` was empty. The same commands produced the
same output after isolated cleanup.

Rather than replace that state, Claude's supported `CLAUDE_CONFIG_DIR` was used
to make an empty isolated configuration and perform the exact local install:

```bash
mktemp -d /tmp/security-requirements-claude-e2e.XXXXXX
CLAUDE_CONFIG_DIR=/tmp/security-requirements-claude-e2e.Ueo9xn claude plugin marketplace list --json
CLAUDE_CONFIG_DIR=/tmp/security-requirements-claude-e2e.Ueo9xn claude plugin list --json
CLAUDE_CONFIG_DIR=/tmp/security-requirements-claude-e2e.Ueo9xn claude plugin marketplace add /Users/s1ns3nz0/orca/projects/security-design/.worktrees/dual-claude-codex-plugin --scope user
CLAUDE_CONFIG_DIR=/tmp/security-requirements-claude-e2e.Ueo9xn claude plugin marketplace list --json | jq '.[] | select(.name == "security-requirements")'
CLAUDE_CONFIG_DIR=/tmp/security-requirements-claude-e2e.Ueo9xn claude plugin install security-requirements@security-requirements --scope user
CLAUDE_CONFIG_DIR=/tmp/security-requirements-claude-e2e.Ueo9xn claude plugin list --json | jq '.[] | select(.id == "security-requirements@security-requirements" or .name == "security-requirements")'
```

The initial isolated lists were both `[]`. Add reported directory source equal
to the exact worktree. The filtered installed-plugin JSON reported these
material fields:

```json
{
  "id": "security-requirements@security-requirements",
  "version": "0.1.0",
  "scope": "user",
  "enabled": true,
  "installPath": "/tmp/security-requirements-claude-e2e.Ueo9xn/plugins/cache/security-requirements/security-requirements/0.1.0"
}
```

The installed namespaced-command invocation was:

```bash
CLAUDE_CONFIG_DIR=/tmp/security-requirements-claude-e2e.Ueo9xn \
claude --print --no-session-persistence --permission-mode dontAsk --tools Read \
  --output-format json \
  '/security-requirements:sec-req-init Audit-only invocation of the installed local-clone command. Do not scan the target repository, interview, run shell commands or scripts, or write anything. Use Read only to open the installed shared deriving-security-requirements/SKILL.md and references/profile-schema.md. Return only: this command description and exact SECURITY_REQUIREMENTS_ROOT initialization; the two absolute installed-cache paths read; shared skill frontmatter name; profile schema heading; the other two namespaced command names; and CLAUDE_INSTALLED_E2E_OK. Emit the marker only after both installed-cache files were actually read.'
```

Exit code was `0`. Only the Read tool was exposed. Claude invoked the namespaced
init command, reported the exact neutral-root adapter and isolated plugin-data
root, read the shared skill and profile schema through the worktree-backed local
payload, discovered the namespaced build and refresh commands, and ended with:

```text
CLAUDE_INSTALLED_E2E_OK
```

Eight initial Read attempts against guessed isolated-cache layouts were denied;
the command then used its resolved local marketplace payload successfully. No
repository scan, shell/script execution, interview, or file write occurred.

Exact isolated removal, state-preserving cleanup, and postchecks:

```bash
CLAUDE_CONFIG_DIR=/tmp/security-requirements-claude-e2e.Ueo9xn claude plugin uninstall security-requirements@security-requirements --scope user --keep-data
CLAUDE_CONFIG_DIR=/tmp/security-requirements-claude-e2e.Ueo9xn claude plugin marketplace remove security-requirements
CLAUDE_CONFIG_DIR=/tmp/security-requirements-claude-e2e.Ueo9xn claude plugin marketplace list --json
CLAUDE_CONFIG_DIR=/tmp/security-requirements-claude-e2e.Ueo9xn claude plugin list --json
trash /tmp/security-requirements-python312.Gg6MlS /tmp/security-requirements-claude-e2e.Ueo9xn /tmp/security-requirements-codex-e2e-final.txt
trash /tmp/security-requirements-python312-final.dQ9aZP
```

Uninstall and marketplace removal succeeded; both isolated lists returned `[]`.
Isolated plugin data contained zero files before and after `--keep-data`.
The original user marketplace/plugin JSON, install timestamps, five-file count,
and persistent-data digest were identical after the isolated run. All three
temporary evidence paths were moved to Trash and verified absent from `/tmp`.

## Success-criterion matrix

| Approved design criterion | Status | Evidence |
|---|---|---|
| Clone only this repository and install in Claude Code | **PASS** | Empty isolated `CLAUDE_CONFIG_DIR` local marketplace add/install/list/remove transcript above; exact worktree directory source; `test_clean_clone_documentation_covers_claude_and_codex_installation`; `test_both_marketplaces_resolve_to_the_single_payload`. |
| Register and install the same clone in Codex | **PASS** | Direct add/list/install/cache-validate/remove smoke test above; `test_codex_marketplace_declares_installation_policy`; `test_codex_manifest_declares_the_required_plugin_interface`. |
| Claude retains init/build/refresh slash commands | **PASS** | Isolated installed `/security-requirements:sec-req-init` invocation loaded the shared payload and explicitly discovered the build and refresh namespaced commands; all three artifacts also pass `test_claude_commands_initialize_the_neutral_payload_root`. |
| Codex exposes equivalent discoverable skills and starter prompts | **PASS** | Installed read-only `codex exec` selected all three skills, read their shared payload and matching commands, and returned all three manifest prompts verbatim with `E2E_READ_ONLY_OK`; entry-skill and manifest tests pass. |
| Both hosts execute the same deterministic scripts and bundled data | **INCOMPLETE** | Both installed hosts resolved and read the one shared payload; `test_payload_has_both_host_manifests_and_one_shared_implementation`, `test_shared_derivation_skill_has_exactly_one_payload_copy`, `test_runtime_payload_uses_no_symlinks_or_duplicate_directories`, and 830 deterministic tests pass. Literal init/build/refresh workflow execution through both hosts was deliberately not performed because it would scan/interview/write and require user confirmation. |
| Confirmation gate resists repository-only forgery and persists externally | **PASS** | Both separate-process smoke sequences above; `test_profile_change_invalidates_confirmation`, `test_repository_cannot_forge_plugin_owned_approval`, `test_cli_stamp_writes_authoritative_state_outside_repository`, `test_cli_stamp_and_check_use_neutral_data_root`, and `test_cli_stamp_and_check_use_default_data_root`. |
| Existing edits, exceptions, identifiers, threat behavior, overlays, semantic review, lint, and rendering retain semantics | **PASS** | Full suite; representative exact tests include `test_identifiers_are_stable_across_reruns`, `test_human_edits_are_never_overwritten`, `test_requirements_are_retired_not_deleted`, `test_threat_only_bucket_is_populated`, `test_overlays_pass_the_validator`, `test_review_binds_exact_semantics_and_verification`, `test_golden_fixture_passes_lint`, and `test_the_reader_gets_the_reasoning_and_a_way_to_check_by_hand`. |
| Existing and new tests pass | **PASS** | Final exact `python3 -m pytest -q`: `830 passed in 21.37s`; both exact `python3` validator commands exited `0`. |

## Security-invariant matrix

| Invariant | Evidence |
|---|---|
| Repository content is evidence, never workflow instruction | `test_repository_scan_loads_the_untrusted_input_policy` verifies the packaged policy and both init/shared entry references. |
| Approval is an exact digest-bound repository/external-state match | Separate-process mutation checks; `test_stamp_binds_confirmation_to_exact_profile`; `test_profile_change_invalidates_confirmation`. |
| Repository files alone cannot forge approval | Separate-process empty-state checks; `test_repository_cannot_forge_plugin_owned_approval`. |
| Explicit confirmation is a hard gate before build or refresh | `test_profile_confirmation_is_persisted_and_enforced`; `test_cli_check_rejects_unconfirmed_profile`; ordered refresh gate in `test_refresh_rebuilds_and_republishes_the_complete_pipeline`. |
| Bundled data resolves from the plugin, never cwd | `test_bundled_scripts_are_rooted_at_plugin_installation`; `test_bundled_references_are_rooted_at_plugin_installation`; `test_every_bundled_resource_named_by_the_workflow_is_plugin_rooted`; new validator regression test; no-match payload audit. |
| Generated service mappings stay unverified until review | `test_uncurated_services_are_reported`; `test_generated_service_curation_is_loaded_from_persistent_plugin_data`; build acceptance text at `commands/sec-req-build.md:59-63`. |
| Public/unknown visibility keeps warning and `.gitignore` behavior | Structural acceptance evidence at `commands/sec-req-init.md:33-41` and `:84-94`. Live host compliance was not exercised and is included in the overall host-behavior incompleteness. |
| Human blocks are immutable and generated changes become pending review | `test_human_edits_are_never_overwritten`; refresh acceptance text at `commands/sec-req-refresh.md:21-39`. |
| Requirements are retired/superseded, never deleted | `test_requirements_are_retired_not_deleted`; `test_retired_requirements_stay_out_of_the_document`; refresh acceptance text at `commands/sec-req-refresh.md:33-37`. |

## Init/build/refresh completion map

### Init

| Invariant | Evidence |
|---|---|
| Bind immutable payload and external state before resource use | `test_claude_commands_initialize_the_neutral_payload_root`; `test_claude_commands_bind_external_state_with_the_runtime_helper`; `test_shared_skill_bootstraps_payload_and_state_before_resource_use`; `test_codex_entry_skills_execute_payload_and_state_resolution`. |
| Treat repository as untrusted evidence and retain source evidence | `test_repository_scan_loads_the_untrusted_input_policy`; structural acceptance at `sec-req-init.md:22-31`. |
| Fail safe when repository visibility is unknown | Structural acceptance at `sec-req-init.md:33-41` and `:84-94`. |
| Ask seven owner questions, preserve locale, and retain `UNDETERMINED` cost | Structural acceptance at `sec-req-init.md:43-50`; `test_unknown_region_is_undetermined_not_guessed`; `test_the_build_carries_the_locale_to_the_step_that_needs_it`. |
| Write profile before deterministic baseline derivation | `test_profile_confirmation_is_persisted_and_enforced`. |
| Stop for explicit confirmation and record user overrides/reason | `test_profile_confirmation_is_persisted_and_enforced`; structural acceptance at `sec-req-init.md:63-82`. |
| Persist the exact approval outside the project | Neutral/legacy smoke tests; `test_cli_stamp_writes_authoritative_state_outside_repository`. |

### Build

| Invariant | Evidence |
|---|---|
| Reject missing/stale/repository-only confirmation before work | Neutral/legacy smoke tests; `test_cli_check_rejects_unconfirmed_profile`; `test_repository_cannot_forge_plugin_owned_approval`; `test_profile_confirmation_is_persisted_and_enforced`. |
| Derive DFD-based service-specific threats and run LINDDUN when applicable | Structural acceptance at `sec-req-build.md:33-48`; `test_threat_only_bucket_is_populated`; `test_service_specific_threats_raise_priority`. Live host adherence to the DFD/LINDDUN instructions was not exercised and remains part of the overall host-behavior incompleteness. |
| Split responsibility and retain unverified generated mappings externally | `test_uncurated_services_are_reported`; `test_generated_service_curation_is_loaded_from_persistent_plugin_data`; `test_generated_service_curation_rejects_relative_plugin_data_root`; `test_managed_service_identifier_cannot_escape_curation_directory`; `test_generated_service_symlink_cannot_escape_plugin_data`. |
| Apply scoped regulatory overlays and surface clauses no control expresses | `test_overlay_does_not_apply_outside_its_jurisdiction`; `test_clauses_no_control_expresses_are_named`; `test_overlays_pass_the_validator`. |
| Cross controls/responsibility/threats and preserve threat-only work | `test_threat_only_bucket_is_populated`; `test_service_specific_threats_raise_priority`; `test_merge_runs_from_the_command_line`. |
| Generate atomic, verifiable, forced requirements and stable IDs | `test_one_requirement_per_requirement`; `test_missing_verification_is_blocked`; `test_identifiers_are_stable_across_reruns`; `test_forced_requirements_are_produced`; `test_forced_requirements_reach_the_work_list`. |
| Merge before lint, lint threat references and locale, then render | `test_build_lints_requirement_threat_references`; `test_the_build_carries_the_locale_to_the_step_that_needs_it`; `test_golden_fixture_passes_lint`; `test_the_reader_gets_the_reasoning_and_a_way_to_check_by_hand`. |
| Re-run overlays against authored requirements and keep assurance stages distinct | `test_workflow_documents_the_independent_semantic_gate`; `test_review_binds_exact_semantics_and_verification`; `test_model_edit_invalidates_semantic_review`; `test_the_funnel_rows_are_each_a_subset_of_the_row_above`; `test_overlay_user_output_uses_staged_assurance_language`. |
| Report team control counts, unverified services, overlays, gaps/deferrals, uncovered regimes, and unknowns | Structural acceptance at `sec-req-build.md:216-227`; `test_the_overlay_command_line_prints_the_funnel`; `test_deferred_is_not_a_gap`; `test_a_prioritised_control_with_nothing_written_is_a_gap`; `test_every_count_the_documentation_claims_is_the_count_that_is_there`. |

### Refresh

| Invariant | Evidence |
|---|---|
| Preserve human edits/exceptions, route generated changes to review, and retire rather than delete | `test_human_edits_are_never_overwritten`; `test_retirement_preserves_an_accepted_risk`; `test_a_returning_requirement_is_reopened`; `test_requirements_are_retired_not_deleted`. |
| Preserve locale and stable identifiers across reruns | `test_identifiers_are_stable_across_reruns`; `test_the_build_carries_the_locale_to_the_step_that_needs_it`; structural acceptance at `sec-req-refresh.md:31-39`. |
| Re-scan only changed evidence and re-gate impact changes | Structural acceptance at `sec-req-refresh.md:41-50`; digest invalidation directly exercised in both smoke scenarios. |
| Re-derive baseline, stamp/check, classify, update threats, overlays, and forced work in order | `test_refresh_rebuilds_and_republishes_the_complete_pipeline`; structural acceptance at `sec-req-refresh.md:52-85`. |
| Cross and apply a newly authored draft while reusing ID state | `test_refresh_rebuilds_and_republishes_the_complete_pipeline`; `test_identifiers_are_stable_across_reruns`; structural acceptance at `sec-req-refresh.md:87-110`. |
| Block publication until lint and every overlay succeeds, then render | `test_refresh_rebuilds_and_republishes_the_complete_pipeline`; `test_build_lints_requirement_threat_references`; `test_the_linter_passes_a_clean_document_and_counts_nothing`; `test_the_overlay_command_line_runs_end_to_end`; `test_the_documented_order_lints_before_it_publishes`. |
| Report added/proposed/superseded/unchanged work and expiring exceptions | Structural acceptance at `sec-req-refresh.md:142-155`; `test_retirement_preserves_an_accepted_risk`; `test_the_merge_report_names_a_reopened_requirement_carrying_an_exception`. |

## Remaining incompleteness

The only remaining evidence required before changing the overall verdict to
complete is literal init, build, and refresh workflow execution through each
live host. That would scan a target repository, conduct or depend on an owner
interview and explicit confirmation, persist confirmation state, and write
security artifacts. Those side effects were outside this audit-only validation
scope. The installed-host checks therefore stopped after proving real host
discovery, adapter dispatch, and shared-payload reads; they do not claim that
the complete workflows ran.

No repository test or validator failure remains.
