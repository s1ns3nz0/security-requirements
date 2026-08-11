# Dual Claude and Codex plugin verification

Date: 2026-08-11

Branch: `feat/dual-claude-codex-plugin`

Validated commit before this report: `2564c09` (`fix: reject cwd-relative payload invocations`)

## Verdict

**INCOMPLETE.** Every repository-controlled test, validator, state smoke test,
and Codex clean-clone installation check passed. The overall migration goal is
not marked complete because the current Claude user profile already contained a
same-name marketplace and installed plugin. The safety constraint prohibited
replacing them, so a Claude install from this exact local clone and live Claude
slash-command execution were not exercised. Codex installation was exercised,
but interactive skill selection and starter-prompt dispatch were not.

Structural evidence for those host behaviors is recorded below; it is not
promoted to live-host evidence.

## Environment

| Tool | Observed version |
|---|---|
| Test interpreter | `Python 3.12.11` (`python`) |
| System `python3` | `Python 3.14.3` |
| Codex | `codex-cli 0.147.0` |
| Claude Code | `2.1.145` |

The full suite used the working Python 3.12 interpreter as required by the task
brief supplied to the validation worker.

## Regression and validator evidence

### Full suite

Command:

```bash
python -m pytest -q
```

Final output:

```text
........................................................................ [  8%]
........................................................................ [ 17%]
........................................................................ [ 26%]
........................................................................ [ 34%]
........................................................................ [ 43%]
........................................................................ [ 52%]
........................................................................ [ 61%]
........................................................................ [ 69%]
........................................................................ [ 78%]
........................................................................ [ 87%]
........................................................................ [ 95%]
..................................                                       [100%]
826 passed in 20.22s
```

Exit code: `0`.

### Distribution validator

Command:

```bash
python scripts/validate_distribution.py .
```

Output: empty. Exit code: `0`.

### Codex plugin validator

Command:

```bash
python /Users/s1ns3nz0/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py plugins/security-requirements
```

Output:

```text
Plugin validation passed: /Users/s1ns3nz0/orca/projects/security-design/.worktrees/dual-claude-codex-plugin/plugins/security-requirements
```

Exit code: `0`.

## Reference and payload audit

Command:

```bash
rg -n 'python3[[:space:]]+scripts/' plugins/security-requirements
```

Output: empty. Exit code: `1`, the expected ripgrep no-match result.

Command:

```bash
rg -n 'CLAUDE_PLUGIN_ROOT|CLAUDE_PLUGIN_DATA' plugins/security-requirements
```

Output:

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
persistent-state compatibility resolver.

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

The validator now reports every cwd-relative packaged Python invocation with a
payload-relative file and line number. All shipped examples use
`${SECURITY_REQUIREMENTS_ROOT}`. Commit: `2564c09`.

Adding the regression test intentionally tripped
`tests/test_pipeline.py::test_the_test_count_on_the_front_page_is_the_test_count`
because README still claimed 825 tests. The README count was updated to 826 and
the final full suite passed.

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

### Codex: passed and restored

Precondition checks returned no exact same-name entries:

```text
codex_pre_marketplace_match_exit=1
codex_pre_plugin_match_exit=1
```

The exact worktree was registered:

```json
{
  "marketplaceName": "security-requirements",
  "installedRoot": "/Users/s1ns3nz0/orca/projects/security-design/.worktrees/dual-claude-codex-plugin",
  "alreadyAdded": false
}
```

`codex plugin list --marketplace security-requirements --available --json`
then reported version `0.1.0`, local source
`.../plugins/security-requirements`, install policy `AVAILABLE`, authentication
policy `ON_INSTALL`, and `installed: false`.

Installation output:

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

The installed listing was:

```text
PLUGIN                                       STATUS              VERSION  PATH
security-requirements@security-requirements  installed, enabled  0.1.0    /Users/s1ns3nz0/orca/projects/security-design/.worktrees/dual-claude-codex-plugin/plugins/security-requirements
```

The installed cache contained:

```text
/Users/s1ns3nz0/.codex/plugins/cache/security-requirements/security-requirements/0.1.0/skills/deriving-security-requirements/SKILL.md
/Users/s1ns3nz0/.codex/plugins/cache/security-requirements/security-requirements/0.1.0/skills/security-requirements-build/SKILL.md
/Users/s1ns3nz0/.codex/plugins/cache/security-requirements/security-requirements/0.1.0/skills/security-requirements-init/SKILL.md
/Users/s1ns3nz0/.codex/plugins/cache/security-requirements/security-requirements/0.1.0/skills/security-requirements-refresh/SKILL.md
```

No symlinks were found in the installed cache. The Codex plugin validator run
against that cache returned:

```text
Plugin validation passed: /Users/s1ns3nz0/.codex/plugins/cache/security-requirements/security-requirements/0.1.0
```

Only the installed plugin and marketplace created by this smoke test were then
removed. The default persistent state root remained outside the installation
cache and unchanged:

```text
persistent_state_root=/Users/s1ns3nz0/Library/Application Support/security-requirements/v1
persistent_state_files_before=0
{
  "pluginId": "security-requirements@security-requirements",
  "name": "security-requirements",
  "marketplaceName": "security-requirements"
}
{
  "marketplaceName": "security-requirements",
  "installedRoot": null
}
persistent_state_files_after=0
```

Postcondition checks:

```text
codex_post_marketplace_match_exit=1
codex_post_plugin_match_exit=1
codex_post_cache_exists_exit=1
```

### Claude Code: incomplete and untouched

The Claude precheck found same-name user state before any mutation:

```text
  ❯ security-requirements
    Source: GitHub (s1ns3nz0/security-requirements)
  ❯ security-requirements@security-requirements
    Version: 0.1.0
    Scope: user
    Status: ✔ enabled
```

Because this was pre-existing and not the exact local worktree marketplace, the
safe noninteractive add/install/uninstall/remove sequence was not run. The same
filtered output was observed after the Codex smoke test, proving the Claude
entries were not changed. This keeps the clean-clone Claude host criterion
incomplete.

## Success-criterion matrix

| Approved design criterion | Status | Evidence |
|---|---|---|
| Clone only this repository and install in Claude Code | **INCOMPLETE** | README flow is covered by `test_clean_clone_documentation_covers_claude_and_codex_installation`; marketplace and manifest resolve in `test_both_marketplaces_resolve_to_the_single_payload`; live local-clone install was not safe because same-name Claude state already existed. |
| Register and install the same clone in Codex | **PASS** | Direct add/list/install/cache-validate/remove smoke test above; `test_codex_marketplace_declares_installation_policy`; `test_codex_manifest_declares_the_required_plugin_interface`. |
| Claude retains init/build/refresh slash commands | **INCOMPLETE** | All three command artifacts pass `test_claude_commands_initialize_the_neutral_payload_root` and the distribution validator, but the current worktree was not installed into Claude and slash-command discovery/execution was not exercised. |
| Codex exposes equivalent discoverable skills and starter prompts | **INCOMPLETE** | Installed cache contained init/build/refresh skills; `test_codex_entry_skills_delegate_to_the_shared_workflows`, `test_codex_entry_skills_execute_payload_and_state_resolution`, and manifest validation pass. Interactive discovery/prompt dispatch was not exercised. |
| Both hosts execute the same deterministic scripts and bundled data | **INCOMPLETE** | `test_payload_has_both_host_manifests_and_one_shared_implementation`, `test_shared_derivation_skill_has_exactly_one_payload_copy`, `test_runtime_payload_uses_no_symlinks_or_duplicate_directories`, and 826 deterministic tests pass. End-to-end workflow execution through both live hosts was not exercised. |
| Confirmation gate resists repository-only forgery and persists externally | **PASS** | Both separate-process smoke sequences above; `test_profile_change_invalidates_confirmation`, `test_repository_cannot_forge_plugin_owned_approval`, `test_cli_stamp_writes_authoritative_state_outside_repository`, `test_cli_stamp_and_check_use_neutral_data_root`, and `test_cli_stamp_and_check_use_default_data_root`. |
| Existing edits, exceptions, identifiers, threat behavior, overlays, semantic review, lint, and rendering retain semantics | **PASS** | Full suite; representative exact tests include `test_identifiers_are_stable_across_reruns`, `test_human_edits_are_never_overwritten`, `test_requirements_are_retired_not_deleted`, `test_threat_only_bucket_is_populated`, `test_overlays_pass_the_validator`, `test_review_binds_exact_semantics_and_verification`, `test_golden_fixture_passes_lint`, and `test_the_reader_gets_the_reasoning_and_a_way_to_check_by_hand`. |
| Existing and new tests pass | **PASS** | `826 passed in 20.22s`; both validators exited `0`. |

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

The following evidence would be required before changing the overall verdict to
complete:

1. In an isolated Claude configuration with no same-name state, register this
   exact local clone, install `security-requirements@security-requirements`,
   confirm all three namespaced slash commands are discoverable, invoke them far
   enough to prove adapter loading, then uninstall with `--keep-data` and remove
   only the test marketplace.
2. In an isolated Codex session using the installed plugin, confirm the three
   entry skills and manifest starter prompts are discoverable and dispatch to
   their matching workflows.
3. Exercise one init/build/refresh adapter path through each live host if the
   phrase “both hosts execute” is to be treated as runtime acceptance rather
   than structural parity.

No repository test or validator failure remains.
