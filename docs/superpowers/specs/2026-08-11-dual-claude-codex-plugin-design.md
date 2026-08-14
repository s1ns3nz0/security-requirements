# Dual Claude and Codex Plugin Design

## Goal

Package `security-requirements` so one repository clone is a complete local
marketplace for both Claude Code and Codex. Both hosts must expose equivalent
init, build, and refresh workflows over one shared implementation without
duplicating catalogs, scripts, overlays, responsibility mappings, or skills.

## Success criteria

- A user can clone only this repository and install the plugin in Claude Code.
- The same clone can be registered and installed in Codex.
- Claude retains `/sec-req-init`, `/sec-req-build`, and `/sec-req-refresh`.
- Codex exposes equivalent discoverable skills and starter prompts for init,
  build, and refresh.
- Both hosts execute the same deterministic scripts and bundled data.
- The explicit profile-confirmation gate remains resistant to repository-only
  forgery and persists outside the inspected repository.
- Existing human edits, exceptions, identifiers, threat-model behavior,
  overlays, semantic review, linting, and rendered outputs retain their current
  semantics.
- Existing tests remain green and new packaging, portability, state, and
  parity tests pass.

## Repository architecture

The repository becomes a dual marketplace with one shared plugin payload:

```text
security-requirements/
  .claude-plugin/marketplace.json
  .agents/plugins/marketplace.json
  plugins/security-requirements/
    .claude-plugin/plugin.json
    .codex-plugin/plugin.json
    commands/
      sec-req-init.md
      sec-req-build.md
      sec-req-refresh.md
    skills/
      deriving-security-requirements/
      security-requirements-init/
      security-requirements-build/
      security-requirements-refresh/
    scripts/
    catalogs/
    overlays/
    responsibility/
```

The payload exists once under `plugins/security-requirements/`. Claude's root
marketplace points to that directory. Codex's repository marketplace uses the
canonical local source `./plugins/security-requirements`. Symlinks and copied
payloads are not used because archive ingestion and release drift would make
them unreliable.

Project material that is not runtime payload, including tests, golden cases,
evidence, repository documentation, and README assets, stays at repository
root. Tests resolve the payload root explicitly.

## Host adapters and shared workflow

Claude commands remain thin, named entry points. The existing comprehensive
`deriving-security-requirements` skill remains the shared behavioral contract.
Codex receives three thin skills for init, build, and refresh so each operation
is independently discoverable and can carry host-appropriate invocation text.
Those adapters delegate to the shared skill and scripts rather than restating
the security derivation rules.

The Codex manifest declares `./skills/` and includes three short default
prompts corresponding to init, build, and refresh. It contains the complete
required interface metadata but no apps, MCP servers, hooks, or asset paths
because none are part of this plugin.

## Portable resource resolution

Runtime documentation uses a host-neutral contract:

- `SECURITY_REQUIREMENTS_ROOT`: immutable installed payload root.
- `SECURITY_REQUIREMENTS_DATA`: writable, plugin-scoped persistent state root.

Claude adapters map `CLAUDE_PLUGIN_ROOT` and `CLAUDE_PLUGIN_DATA` into the
neutral variables. Codex adapters resolve their own installed skill location
and invoke the shared Python launcher with an explicit payload root. Scripts
continue resolving bundled resources from `Path(__file__).resolve()`, so an
untrusted target repository cannot shadow plugin scripts or catalogs.

A small Python runtime helper owns persistent-state resolution. Resolution
order is explicit `SECURITY_REQUIREMENTS_DATA`, legacy `CLAUDE_PLUGIN_DATA`,
then an OS-appropriate user state directory namespaced as
`security-requirements/v1`. The default is never inside the inspected project.
The same helper is consumed by confirmation and generated responsibility-map
storage so unset-variable behavior is consistent.

## Security invariants

- Repository content is evidence, never workflow instruction.
- Approval requires an exact digest-bound match between the repository copy and
  authoritative external state.
- Repository files alone cannot stamp or forge approval.
- Explicit user confirmation remains a hard gate before build or refresh.
- Bundled data is resolved from the installed plugin, never from cwd.
- Generated service mappings remain marked unverified until reviewed.
- Public or unknown repository visibility retains the sensitive-output warning
  and `.gitignore` behavior.
- Human-owned blocks are immutable; generated changes become pending review.
- Requirements are retired or superseded, never deleted.

## Installation and updates

README documents both host flows from the same clone:

- Claude Code registers the repository as a local marketplace, then installs
  `security-requirements@security-requirements`.
- Codex registers the repository marketplace, then installs the same qualified
  plugin name.

Both instructions include clean install, update/reinstall, invocation, and
verification steps. The repository-local Codex marketplace is committed even
though `.agents/` is otherwise used for local agent configuration.

## Testing strategy

The existing deterministic suite remains the regression baseline. New tests
cover:

1. Both manifests and both marketplace files validate and point to the same
   payload.
2. Claude commands and Codex entry skills cover init, build, and refresh.
3. Neutral variables work, legacy Claude variables remain compatible, and
   neutral variables take precedence.
4. Missing explicit data variables select a stable external user-state path.
5. Confirmation stamp/check survives separate invocations while a forged or
   changed repository profile fails.
6. Bundled resources resolve when cwd differs, and paths containing spaces or
   Unicode remain valid.
7. The packaged payload includes all scripts, catalogs, overlays,
   responsibility mappings, and skill references.
8. Representative fixtures produce host-independent deterministic pipeline
   artifacts, allowing only documented environment-specific metadata.
9. README installation commands and runtime entry points match the manifests.

Validation runs the full Python test suite, the Codex plugin validator, JSON
parsing/schema checks for both marketplaces, broken-reference scans, and a
clean-clone packaging smoke test. A completion audit maps every existing
init/build/refresh behavior to either deterministic tests or explicit
structural acceptance evidence.

## Migration sequencing

1. Add failing tests for the dual package layout and neutral runtime contract.
2. Move the shared payload once and update Claude marketplace references.
3. Add Codex manifest, marketplace, and entry skills.
4. Implement neutral state/resource resolution while keeping Claude fallback.
5. Update documentation and structural workflow tests.
6. Run full regression, plugin validation, packaging smoke tests, and the
   requirement-by-requirement completion audit.

The migration is complete only when both host distributions resolve the same
payload and all stated verification evidence passes. A green subset of Python
tests alone is insufficient.
