# Dual Claude and Codex Plugin Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make one clone of `security-requirements` an installable, functionally equivalent local plugin marketplace for Claude Code and Codex.

**Architecture:** The repository root is a dual-host marketplace and `plugins/security-requirements/` is the single runtime payload. Host-specific commands or entry skills initialize a neutral runtime contract, while every deterministic script and bundled catalog remains shared.

**Tech Stack:** Markdown skills and commands, JSON manifests, Python 3, PyYAML, pytest, Codex plugin validator, Claude Code local marketplace.

## Global Constraints

- Preserve every init, build, and refresh invariant documented in the approved design.
- Keep exactly one runtime copy of scripts, catalogs, overlays, responsibility mappings, and the shared derivation skill.
- Never use the inspected repository as authoritative confirmation storage.
- Never resolve executable plugin resources from the current working directory.
- Preserve Claude command names and legacy `CLAUDE_PLUGIN_ROOT` / `CLAUDE_PLUGIN_DATA` compatibility.
- Codex must expose independent init, build, and refresh entry skills.
- No MCP server, app, hook, symlink, or duplicated payload is introduced.

---

### Task 1: Define the dual-package contract with failing tests

**Files:**
- Create: `tests/test_dual_plugin_package.py`
- Modify: `tests/test_plugin_workflow.py`

**Interfaces:**
- Produces: `REPO_ROOT` and `PLUGIN_ROOT = REPO_ROOT / "plugins" / "security-requirements"` test constants.
- Produces: structural requirements consumed by Tasks 2 and 4.

- [ ] **Step 1: Write the failing package-layout tests**

Add tests that parse both marketplace files and both manifests:

```python
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PLUGIN_ROOT = REPO_ROOT / "plugins" / "security-requirements"


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_both_marketplaces_resolve_to_the_single_payload():
    claude = read_json(REPO_ROOT / ".claude-plugin" / "marketplace.json")
    codex = read_json(REPO_ROOT / ".agents" / "plugins" / "marketplace.json")
    assert claude["plugins"][0]["source"] == "./plugins/security-requirements"
    assert codex["plugins"][0]["source"] == {
        "source": "local",
        "path": "./plugins/security-requirements",
    }
    assert PLUGIN_ROOT.is_dir()


def test_payload_has_both_host_manifests_and_one_shared_implementation():
    claude = read_json(PLUGIN_ROOT / ".claude-plugin" / "plugin.json")
    codex = read_json(PLUGIN_ROOT / ".codex-plugin" / "plugin.json")
    assert claude["name"] == codex["name"] == PLUGIN_ROOT.name
    assert codex["skills"] == "./skills/"
    for relative in ("scripts", "catalogs", "overlays", "responsibility"):
        assert (PLUGIN_ROOT / relative).is_dir()
        assert not (REPO_ROOT / relative).exists()
```

Add a no-symlink/no-duplicate scan and assertions for Codex marketplace policy fields and required manifest interface fields.

- [ ] **Step 2: Change workflow tests to point at the wished-for payload**

Replace the old root constants in `tests/test_plugin_workflow.py`:

```python
REPO_ROOT = Path(__file__).resolve().parent.parent
ROOT = REPO_ROOT / "plugins" / "security-requirements"
COMMANDS = sorted((ROOT / "commands").glob("*.md"))
SKILL = ROOT / "skills" / "deriving-security-requirements" / "SKILL.md"
```

Change the rooting assertions from Claude-only strings to the neutral
`${SECURITY_REQUIREMENTS_ROOT}` contract, while retaining a separate assertion
that each Claude command initializes it from `${CLAUDE_PLUGIN_ROOT}`.

- [ ] **Step 3: Run the focused tests and verify RED**

Run:

```bash
python3 -m pytest tests/test_dual_plugin_package.py tests/test_plugin_workflow.py -q
```

Expected: failures because `plugins/security-requirements`, the Codex manifest,
the Codex marketplace, and neutral workflow references do not exist.

- [ ] **Step 4: Commit the executable contract**

```bash
git add tests/test_dual_plugin_package.py tests/test_plugin_workflow.py
git commit -m "test: define dual plugin package contract"
```

### Task 2: Move the single payload and add both distribution manifests

**Files:**
- Move: `.claude-plugin/plugin.json` → `plugins/security-requirements/.claude-plugin/plugin.json`
- Move: `commands/` → `plugins/security-requirements/commands/`
- Move: `skills/deriving-security-requirements/` → `plugins/security-requirements/skills/deriving-security-requirements/`
- Move: `scripts/` → `plugins/security-requirements/scripts/`
- Move: `catalogs/` → `plugins/security-requirements/catalogs/`
- Move: `overlays/` → `plugins/security-requirements/overlays/`
- Move: `responsibility/` → `plugins/security-requirements/responsibility/`
- Create: `plugins/security-requirements/.codex-plugin/plugin.json`
- Modify: `.claude-plugin/marketplace.json`
- Create: `.agents/plugins/marketplace.json`
- Modify: `.gitignore`
- Modify: `sitecustomize.py`
- Modify: `tests/test_pipeline.py`
- Modify: `tests/test_confirmation.py`
- Modify: `tests/test_semantic_review.py`

**Interfaces:**
- Produces: canonical payload root `plugins/security-requirements/`.
- Produces: Claude source string and Codex local source object resolving to that root.
- Consumes: Task 1 structural tests.

- [ ] **Step 1: Move runtime-owned files without copying them**

Use `git mv` for the listed runtime directories and Claude manifest. Do not move
`tests/`, `golden/`, `evidence/`, README assets, or repository documentation.

- [ ] **Step 2: Add the Codex manifest**

Create `.codex-plugin/plugin.json` with strict semver `0.1.0`, existing author,
license, homepage, repository, and keywords; `skills: "./skills/"`; and:

```json
"interface": {
  "displayName": "Security Requirements",
  "shortDescription": "Derive verifiable security requirements for a service",
  "longDescription": "Build and maintain a tailored security requirements contract from architecture or repository evidence, NIST, OWASP ASVS, cloud responsibility guidance, threat modeling, and applicable regulatory overlays.",
  "developerName": "s1ns3nz0",
  "category": "Developer Tools",
  "capabilities": ["Interactive", "Read", "Write"],
  "defaultPrompt": [
    "Initialize the security requirements profile for this repository.",
    "Build security requirements from the confirmed profile.",
    "Refresh security requirements after service changes."
  ]
}
```

- [ ] **Step 3: Add the Codex marketplace and update Claude source**

The Codex entry must include:

```json
{
  "name": "security-requirements",
  "source": {"source": "local", "path": "./plugins/security-requirements"},
  "policy": {"installation": "AVAILABLE", "authentication": "ON_INSTALL"},
  "category": "Developer Tools"
}
```

Update Claude's entry to `source: "./plugins/security-requirements"` and remove
the obsolete `metadata.pluginRoot: "."`. Add narrow `.gitignore` exceptions:

```gitignore
.agents/
!.agents/
.agents/*
!.agents/plugins/
!.agents/plugins/marketplace.json
```

- [ ] **Step 4: Update repository test imports for the new payload**

Every test that imports scripts uses:

```python
REPO_ROOT = Path(__file__).resolve().parent.parent
PLUGIN_ROOT = REPO_ROOT / "plugins" / "security-requirements"
sys.path.insert(0, str(PLUGIN_ROOT / "scripts"))
```

Update direct catalog/overlay/responsibility paths similarly. Update
`sitecustomize.py` to insert the payload script directory.

- [ ] **Step 5: Run package and deterministic tests**

Run:

```bash
python3 -m pytest tests/test_dual_plugin_package.py tests/test_pipeline.py tests/test_semantic_review.py -q
```

Expected: package/layout and deterministic script tests pass; workflow tests
may still fail on neutral adapters, which Task 4 owns.

- [ ] **Step 6: Commit the shared package layout**

```bash
git add .claude-plugin .agents .gitignore plugins sitecustomize.py tests
git commit -m "feat: package one payload for Claude and Codex"
```

### Task 3: Add neutral persistent-state resolution with TDD

**Files:**
- Create: `plugins/security-requirements/scripts/runtime_paths.py`
- Modify: `plugins/security-requirements/scripts/confirmation.py`
- Modify: `plugins/security-requirements/scripts/classify_resp.py`
- Modify: `tests/test_confirmation.py`
- Modify: `tests/test_pipeline.py`

**Interfaces:**
- Produces: `plugin_data_root(env: Mapping[str, str] | None = None, platform: str | None = None) -> Path`.
- Priority: `SECURITY_REQUIREMENTS_DATA`, then `CLAUDE_PLUGIN_DATA`, then OS user-state default.
- Consumes: confirmation state and generated responsibility service lookup.

- [ ] **Step 1: Write failing precedence and fallback tests**

Add real-environment tests with monkeypatch:

```python
def test_neutral_data_root_precedes_legacy_claude_root(tmp_path, monkeypatch):
    neutral = tmp_path / "neutral"
    legacy = tmp_path / "legacy"
    monkeypatch.setenv("SECURITY_REQUIREMENTS_DATA", str(neutral))
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(legacy))
    assert runtime_paths.plugin_data_root() == neutral


def test_default_data_root_is_external_and_stable(tmp_path, monkeypatch):
    monkeypatch.delenv("SECURITY_REQUIREMENTS_DATA", raising=False)
    monkeypatch.delenv("CLAUDE_PLUGIN_DATA", raising=False)
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    expected = tmp_path / "state" / "security-requirements" / "v1"
    assert runtime_paths.plugin_data_root(platform="linux") == expected
    assert runtime_paths.plugin_data_root(platform="linux") == expected
```

Add macOS (`~/Library/Application Support/...`) and Windows
(`LOCALAPPDATA`) cases, plus confirmation stamp/check under neutral and default
roots. Add a pipeline test proving generated service mappings load from the
neutral root and cannot escape `responsibility/services`.

- [ ] **Step 2: Run tests and verify RED**

Run:

```bash
python3 -m pytest tests/test_confirmation.py tests/test_pipeline.py -q
```

Expected: import failure for `runtime_paths` or assertions showing only the
legacy Claude variable is honored.

- [ ] **Step 3: Implement the minimal resolver**

Implement `plugin_data_root` with `Path.expanduser()` and explicit platform
branches. Do not create directories inside the resolver. Import it from
`confirmation.py` and `classify_resp.py`; both callers create only the narrow
subdirectory they write. Keep confirmation's project-root digest and validation
logic unchanged.

- [ ] **Step 4: Run focused and full state tests**

Run:

```bash
python3 -m pytest tests/test_confirmation.py tests/test_pipeline.py -q
```

Expected: all pass, including forged-repository rejection and service path
containment.

- [ ] **Step 5: Commit the runtime contract**

```bash
git add plugins/security-requirements/scripts tests/test_confirmation.py tests/test_pipeline.py
git commit -m "feat: make plugin state portable across hosts"
```

### Task 4: Add host adapters and preserve all workflow invariants

**Files:**
- Modify: `plugins/security-requirements/commands/sec-req-init.md`
- Modify: `plugins/security-requirements/commands/sec-req-build.md`
- Modify: `plugins/security-requirements/commands/sec-req-refresh.md`
- Modify: `plugins/security-requirements/skills/deriving-security-requirements/SKILL.md`
- Modify: `plugins/security-requirements/skills/deriving-security-requirements/references/profile-schema.md`
- Create: `plugins/security-requirements/skills/security-requirements-init/SKILL.md`
- Create: `plugins/security-requirements/skills/security-requirements-build/SKILL.md`
- Create: `plugins/security-requirements/skills/security-requirements-refresh/SKILL.md`
- Modify: `tests/test_plugin_workflow.py`
- Modify: `tests/test_dual_plugin_package.py`

**Interfaces:**
- Claude adapter initializes `SECURITY_REQUIREMENTS_ROOT` from `CLAUDE_PLUGIN_ROOT`.
- Codex adapter derives payload root from its installed `SKILL.md` location.
- All shared commands reference `${SECURITY_REQUIREMENTS_ROOT}` only.

- [ ] **Step 1: Add failing adapter coverage tests**

Assert all three Claude commands contain the exact initialization:

```bash
export SECURITY_REQUIREMENTS_ROOT="${CLAUDE_PLUGIN_ROOT}"
if [ -n "${CLAUDE_PLUGIN_DATA:-}" ]; then
  export SECURITY_REQUIREMENTS_DATA="${CLAUDE_PLUGIN_DATA}"
fi
```

Assert three Codex entry skill names exist, reference the shared skill, explain
how to resolve the payload from their own skill location, and name the matching
workflow. Assert the combined adapter/shared text still contains every ordered
pipeline marker currently checked for init, build, and refresh.

- [ ] **Step 2: Run workflow tests and verify RED**

Run:

```bash
python3 -m pytest tests/test_plugin_workflow.py tests/test_dual_plugin_package.py -q
```

Expected: failures for missing Codex skills and absent neutral initialization.

- [ ] **Step 3: Implement thin host adapters**

Insert the Claude initialization block before the first resource access in each
command. Replace every `${CLAUDE_PLUGIN_ROOT}` resource reference in shared
workflow text with `${SECURITY_REQUIREMENTS_ROOT}` and every plugin-data prose
reference with `${SECURITY_REQUIREMENTS_DATA}`.

Each Codex entry skill must:

- have a unique kebab-case name and explicit trigger description;
- load the shared derivation skill and the matching Claude workflow file as
  bundled instructions;
- derive the payload root from the absolute path of its own selected `SKILL.md`
  (`../..` from the entry skill directory);
- set `SECURITY_REQUIREMENTS_ROOT` only to that resolved immutable directory;
- use the neutral/default state resolver rather than cwd;
- preserve the exact explicit-confirmation stop/resume behavior.

- [ ] **Step 4: Verify workflow invariants**

Run:

```bash
python3 -m pytest tests/test_plugin_workflow.py tests/test_dual_plugin_package.py -q
rg -n 'CLAUDE_PLUGIN_ROOT|CLAUDE_PLUGIN_DATA' plugins/security-requirements
```

Expected: tests pass; remaining Claude variables appear only in the three
Claude adapter initialization blocks and compatibility code/tests, never in
shared resource references.

- [ ] **Step 5: Commit adapters**

```bash
git add plugins/security-requirements/commands plugins/security-requirements/skills tests
git commit -m "feat: expose equivalent Claude and Codex workflows"
```

### Task 5: Document and validate clean-clone installation

**Files:**
- Modify: `README.md`
- Modify: `DESIGN.md`
- Modify: `CONTRIBUTING.md`
- Create: `scripts/validate_distribution.py`
- Create: `tests/test_distribution_docs.py`

**Interfaces:**
- Produces: `validate_distribution.py` returning zero only when both host
  marketplaces, manifests, payload references, and required assets are valid.
- Produces: exact local-clone install/update/invocation instructions.

- [ ] **Step 1: Write failing documentation/distribution tests**

Tests must assert README contains separate Claude Code and Codex sections,
qualified plugin name `security-requirements@security-requirements`, local clone
marketplace registration, init/build/refresh invocations, update/reinstall, and
the Python/PyYAML/`gh` dependency behavior. Import and run the distribution
validator against the repository.

- [ ] **Step 2: Run the tests and verify RED**

Run:

```bash
python3 -m pytest tests/test_distribution_docs.py -q
```

Expected: failures because Codex instructions and the validator do not exist.

- [ ] **Step 3: Implement the distribution validator**

The validator parses JSON, resolves both marketplace entries, checks outer
folder/manifest name equality, checks every manifest-declared relative path,
rejects symlinks and duplicate runtime directories, verifies the three entry
points per host, and reports each failure to stderr before returning nonzero.
It must not mutate marketplace files or install plugins.

- [ ] **Step 4: Update documentation**

Document both clean-clone flows using commands confirmed by current CLI help.
Explain that Codex uses natural-language skill invocation/starter prompts while
Claude retains slash commands. Document external confirmation-state storage,
update behavior, missing `gh` safety fallback, Python 3 and PyYAML requirements,
and the validation commands maintainers run before release.

- [ ] **Step 5: Validate documentation and distribution**

Run:

```bash
python3 -m pytest tests/test_distribution_docs.py -q
python3 scripts/validate_distribution.py .
```

Expected: both pass with no warnings.

- [ ] **Step 6: Commit distribution documentation**

```bash
git add README.md DESIGN.md CONTRIBUTING.md scripts/validate_distribution.py tests/test_distribution_docs.py
git commit -m "docs: add dual-host installation and validation"
```

### Task 6: Run full validation and completion audit

**Files:**
- Modify only files implicated by failures.
- Create: `docs/superpowers/reports/2026-08-11-dual-plugin-verification.md`

**Interfaces:**
- Consumes: all prior deliverables.
- Produces: requirement-by-requirement evidence report.

- [ ] **Step 1: Run the complete regression suite**

Run:

```bash
python3 -m pytest -q
```

Expected: all existing and new tests pass.

- [ ] **Step 2: Run both package validators**

Run:

```bash
python3 scripts/validate_distribution.py .
python3 /Users/s1ns3nz0/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py plugins/security-requirements
```

Expected: both validators return zero.

- [ ] **Step 3: Run reference and payload audits**

Run:

```bash
rg -n 'python3[[:space:]]+scripts/|CLAUDE_PLUGIN_ROOT|CLAUDE_PLUGIN_DATA' plugins/security-requirements
find plugins/security-requirements -type l -print
git status --short
```

Expected: no cwd-relative script calls; Claude variables only in compatibility
adapters/runtime resolver; no symlinks; no unintended files.

- [ ] **Step 4: Exercise state across separate invocations**

In a temporary project, create a valid profile, stamp it in one Python process,
check it in another, mutate the profile and verify check fails, then restore it
and verify a repository-only forged confirmation fails when external state is
absent. Run once with neutral state and once with legacy Claude state.

- [ ] **Step 5: Write the completion evidence report**

Map every success criterion and each init/build/refresh invariant from the
approved design to exact passing test names, validator output, or smoke-test
commands. Explicitly record any host behavior that could not be exercised; such
an item keeps the goal incomplete rather than being treated as passed.

- [ ] **Step 6: Commit verified evidence**

```bash
git add docs/superpowers/reports/2026-08-11-dual-plugin-verification.md
git commit -m "test: verify dual plugin distribution"
```

- [ ] **Step 7: Final repository audit**

Run:

```bash
git status --short
git log --oneline -8
```

Expected: clean worktree and a reviewable sequence of focused commits.
