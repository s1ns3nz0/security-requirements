import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
PLUGIN_ROOT = REPO_ROOT / "plugins" / "security-requirements"
RUNTIME_DIRECTORIES = ("scripts", "catalogs", "overlays", "responsibility")
SHARED_DERIVATION_SKILL = Path("skills") / "deriving-security-requirements"
CODEX_ENTRY_SKILLS = {
    workflow: PLUGIN_ROOT
    / "skills"
    / f"security-requirements-{workflow}"
    / "SKILL.md"
    for workflow in ("init", "build", "refresh", "risk")
}
PIPELINE_CODEX_ENTRY_SKILLS = {
    workflow: path
    for workflow, path in CODEX_ENTRY_SKILLS.items()
    if workflow != "risk"
}
PLUGIN_ROOT_LITERAL = "<exact absolute plugin root>"
DATA_ROOT_LITERAL = "<exact absolute data root returned by runtime_paths.py>"
SELECTED_SKILL_LITERAL = "<absolute path of this selected SKILL.md>"

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
    for relative in RUNTIME_DIRECTORIES:
        assert (PLUGIN_ROOT / relative).is_dir()
        if relative != "scripts":
            assert not (REPO_ROOT / relative).exists()
    assert (REPO_ROOT / "scripts" / "validate_distribution.py").is_file()


def test_plugin_metadata_declares_the_python_3_12_runtime_floor():
    requirement = "Requires Python 3.12 or newer and PyYAML."
    for manifest_path in (
        PLUGIN_ROOT / ".claude-plugin" / "plugin.json",
        PLUGIN_ROOT / ".codex-plugin" / "plugin.json",
    ):
        assert requirement in read_json(manifest_path)["description"]

    for skill_path in (
        PLUGIN_ROOT / SHARED_DERIVATION_SKILL / "SKILL.md",
        *CODEX_ENTRY_SKILLS.values(),
    ):
        assert f"compatibility: {requirement}" in skill_path.read_text(encoding="utf-8")


def test_runtime_payload_uses_no_symlinks_or_duplicate_directories():
    symlinks = [
        path.relative_to(PLUGIN_ROOT)
        for path in PLUGIN_ROOT.rglob("*")
        if path.is_symlink()
    ]
    assert symlinks == []

    for directory in RUNTIME_DIRECTORIES:
        locations = [
            path.relative_to(REPO_ROOT)
            for path in REPO_ROOT.rglob(directory)
            if path.is_dir()
        ]
        if directory == "scripts":
            locations.remove(Path("scripts"))
        assert locations == [Path("plugins") / PLUGIN_ROOT.name / directory]


def test_shared_derivation_skill_has_exactly_one_payload_copy():
    locations = [
        path.relative_to(REPO_ROOT)
        for path in REPO_ROOT.rglob(SHARED_DERIVATION_SKILL.name)
        if path.is_dir()
    ]
    assert locations == [
        Path("plugins") / PLUGIN_ROOT.name / SHARED_DERIVATION_SKILL
    ]


def test_codex_entry_skills_delegate_to_the_shared_workflows():
    names = []
    for workflow, path in CODEX_ENTRY_SKILLS.items():
        assert path.is_file()
        text = path.read_text(encoding="utf-8")
        expected_name = f"security-requirements-{workflow}"
        names.append(re.search(r"(?m)^name: ([a-z0-9-]+)$", text).group(1))

        assert f"name: {expected_name}" in text
        assert re.search(r"(?m)^description: Use when .+", text)
        assert (
            f"{PLUGIN_ROOT_LITERAL}/skills/"
            "deriving-security-requirements/SKILL.md"
        ) in text
        assert (
            f"{PLUGIN_ROOT_LITERAL}/commands/sec-req-{workflow}.md"
        ) in text

    assert names == [
        f"security-requirements-{workflow}" for workflow in CODEX_ENTRY_SKILLS
    ]
    assert len(names) == len(set(names))


def test_codex_entry_skills_resolve_from_the_selected_skill_for_every_call():
    for path in CODEX_ENTRY_SKILLS.values():
        text = path.read_text(encoding="utf-8")
        assert f'--skill "{SELECTED_SKILL_LITERAL}"' in text
        assert "python3 -c" not in text
        assert "export SECURITY_REQUIREMENTS_" not in text
        assert "Before every shell tool call" in text
        assert "derive the root again in that same call" in text
        assert "ambient `SECURITY_REQUIREMENTS_ROOT`" in text
        assert "mismatch" in text
        assert PLUGIN_ROOT_LITERAL in text
        assert DATA_ROOT_LITERAL in text
        normalized = " ".join(text.split())
        assert "Do not derive either path from the current working directory" in normalized


def test_codex_entry_skills_preserve_confirmation_and_do_not_copy_pipeline():
    for path in PIPELINE_CODEX_ENTRY_SKILLS.values():
        text = path.read_text(encoding="utf-8")
        assert "stop and wait" in text
        assert "explicit user confirmation" in text
        assert "--stamp" in text
        assert "--check" in text
        assert "skip only the Claude-specific path-capture block" in text
        assert "fresh shell call" in text
        assert "pass the exact literal path" in text
        assert text.count("/scripts/runtime_paths.py") >= 2
        assert "/scripts/select_baseline.py" in text
        assert "/scripts/safe_paths.py" in text
        assert "/scripts/classify_resp.py" not in text


def test_codex_risk_entry_skill_delegates_without_copying_risk_semantics():
    text = CODEX_ENTRY_SKILLS["risk"].read_text(encoding="utf-8")
    assert f"{PLUGIN_ROOT_LITERAL}/commands/sec-req-risk.md" in text
    assert (
        f"{PLUGIN_ROOT_LITERAL}/skills/deriving-security-requirements/SKILL.md"
        in text
    )
    assert "/scripts/risk.py" in text
    assert "/scripts/safe_paths.py" in text
    assert (
        f'python3 -I "{PLUGIN_ROOT_LITERAL}/scripts/safe_paths.py"'
        in text
    )
    assert "/scripts/select_baseline.py" not in text
    assert "/scripts/classify_resp.py" not in text
    assert "stop and wait" in text
    assert "explicit user confirmation" in text


def test_payload_excludes_mcp_app_and_hook_components():
    codex = read_json(PLUGIN_ROOT / ".codex-plugin" / "plugin.json")
    for field in ("mcpServers", "apps", "hooks"):
        assert field not in codex
    for relative in (".mcp.json", ".app.json", "hooks", "apps"):
        assert not (PLUGIN_ROOT / relative).exists()


def test_codex_marketplace_declares_installation_policy():
    marketplace = read_json(REPO_ROOT / ".agents" / "plugins" / "marketplace.json")
    plugin = marketplace["plugins"][0]
    assert plugin["name"] == PLUGIN_ROOT.name
    assert plugin["policy"] == {
        "installation": "AVAILABLE",
        "authentication": "ON_INSTALL",
    }
    assert plugin["category"] == "Developer Tools"


def test_codex_manifest_declares_the_required_plugin_interface():
    claude = read_json(PLUGIN_ROOT / ".claude-plugin" / "plugin.json")
    codex = read_json(PLUGIN_ROOT / ".codex-plugin" / "plugin.json")
    for field in ("version", "author", "license", "homepage", "repository", "keywords"):
        assert codex[field] == claude[field]
    assert re.fullmatch(r"\d+\.\d+\.\d+", codex["version"])
    assert codex["interface"] == {
        "displayName": "Security Requirements",
        "shortDescription": "Derive verifiable security requirements for a service",
        "longDescription": (
            "Build and maintain a tailored security requirements contract from "
            "architecture or repository evidence, NIST, OWASP ASVS, cloud "
            "responsibility guidance, threat modeling, and applicable regulatory "
            "overlays."
        ),
        "developerName": "s1ns3nz0",
        "category": "Developer Tools",
        "capabilities": ["Interactive", "Read", "Write"],
        "defaultPrompt": [
            "Initialize the security requirements profile for this repository.",
            "Build security requirements from the confirmed profile.",
            "Refresh security requirements after service changes.",
            "Assess and review threat risk for this repository.",
            "Review a service design against its threat model for this repository.",
        ],
    }


# ==========================================================================
# N43 — one payload, two entrypoints.
#
# Everything above this line reads the package. Nothing above it runs the
# package, and "both manifests point at one directory" is a much weaker claim
# than "both entrypoints produce the same numbers". These tests run a real
# fixture through the Claude entrypoint and through the Codex entrypoint and
# compare what came out.
#
# What is compared, and what is deliberately not:
#
# * Compared — the parsed documents the run writes, the calculated scores and
#   ratings inside them, the digests, the exit code of every operation, and the
#   validation problems each operation reported.
# * Not compared — rendered markdown, ordering of narrative, or any human
#   sentence. Plan §11.2 N43 says prose may differ. Comparing rendered text
#   measures paraphrase, not parity, and would fail for a reworded heading
#   while missing a changed score.
#
# How the two entrypoints actually differ, which is the whole point of running
# both: they disagree about *where the payload is*, and about nothing else.
#
# * Claude (`commands/sec-req-risk.md`): the host supplies
#   `${CLAUDE_PLUGIN_ROOT}`; the workflow captures it and resolves the data
#   root once with `runtime_paths.py --project-root`.
# * Codex (`skills/security-requirements-risk/SKILL.md`): there is no ambient
#   root. Step 1 forms the candidate root by stripping
#   `/skills/security-requirements-risk/SKILL.md` from the loader-supplied
#   path; step 2 has `runtime_paths.py --skill` derive it from the payload's
#   own `__file__`; step 4 re-derives it before *every* call and compares.
#
# The operations themselves are read out of `commands/sec-req-risk.md` rather
# than retyped here. Both hosts load that same workflow — the Codex adapter
# delegates to it by path — so a flag invented in this file would be a flag
# neither entrypoint runs.
# ==========================================================================


CLAUDE_RISK_WORKFLOW = PLUGIN_ROOT / "commands" / "sec-req-risk.md"
CODEX_RISK_ENTRY_SKILL = CODEX_ENTRY_SKILLS["risk"]
RUNTIME_PATHS_SCRIPT = "scripts/runtime_paths.py"
RISK_SCRIPT = "scripts/risk.py"

STORE_DIRNAME = ".security-requirements"
ADVERSARIAL_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "adversarial-checkout"
GOLDEN_MODEL = REPO_ROOT / "golden" / "movie-rating-aws"
GOLDEN_MODEL_DOCUMENTS = (
    "profile.yaml",
    "threats.yaml",
    "risk-assessment.yaml",
    "risk-state.yaml",
)
DEFAULT_POLICY = PLUGIN_ROOT / "risk" / "default-policy.yaml"
#: `tests/fixtures/adversarial-checkout` ships the dotenv under a neutral name.
MATERIALISED_NAMES = {"env.fixture": ".env"}

#: Plan §11.5 says "Two" and then describes one — the adversarial repository
#: fixture — so "both fixtures" in N43 is read here as the two things a review
#: actually reads: the repository it inspects and the model it scores.
#:
#: Both run the same model, because `golden/movie-rating-aws` is the only
#: complete one in the tree. What differs is the project the payload runs
#: inside: one hostile by construction (planted key, injected README, real
#: `.env`), one clean. Equality between the two fixtures is therefore expected
#: and is not what these tests assert — each fixture is compared across the
#: two entrypoints, and `test_a_changed_model_changes_the_digests...` is what
#: shows the comparison is sensitive to content at all.
PARITY_FIXTURES = ("adversarial-checkout", "golden-model")

#: Enough of the workflow to produce every digest the payload writes:
#: `policy-confirm` stamps the policy, `confirm` stamps the assessment and the
#: state snapshot, `check` re-reads all of it through the gate.
PARITY_OPERATIONS = ("policy-confirm", "confirm", "check")

WELL_FORMED_DIGEST = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
ANY_DIGEST = re.compile(r"sha256:[0-9a-f]+")

#: Every digest a confirming run writes. The first five are taken over
#: material content; the last two are taken over records that also carry the
#: confirmation clock, which is why the clock is pinned below.
DIGEST_KEYS_A_CONFIRMING_RUN_WRITES = (
    "policy_digest",
    "threat_digest",
    "assessment_digest",
    "requirements_digest",
    "evidence_digest",
    "risk_state_digest",
    "snapshot_digest",
)

#: §11.4 — "Pin `today` and `confirmed_at` in every date-touching test."
#:
#: Unpinned, `risk._confirmation_metadata` stamps `datetime.now` into the
#: confirmation and into the state snapshot, and `risk_state_digest` and
#: `snapshot_digest` are taken over those records. Two runs then disagree on
#: two digests — not because the hosts differ but because the clock moved, and
#: the same entrypoint run twice disagrees with itself the same way. The pin is
#: what makes N43's "identical digests" mean the payload rather than the
#: second hand; `test_the_grammar_accepts_the_clock_pin_the_parity_run_needs`
#: fails loudly if it is ever withdrawn.
PINNED_CONFIRMED_AT = "2026-01-01T00:00:00Z"
CLOCK_PINNED_OPERATIONS = ("policy-confirm", "confirm", "residual-confirm")


def workflow_invocations(path: Path) -> dict[str, list[str]]:
    """Every `risk.py` operation one workflow document declares, by name.

    Read out of the document instead of retyped, so this file cannot drift
    into testing a command surface neither host runs. Placeholders are left in
    place; `entrypoint_arguments` substitutes them per host.
    """

    invocations: dict[str, list[str]] = {}
    for block in re.findall(r"(?ms)^```bash\n(.*?)^```", path.read_text(encoding="utf-8")):
        for line in block.replace("\\\n", " ").splitlines():
            if RISK_SCRIPT not in line:
                continue
            tokens = shlex.split(line)
            index = next(
                (position for position, token in enumerate(tokens) if token.endswith("risk.py")),
                None,
            )
            if index is None or index + 1 >= len(tokens):
                continue
            invocations.setdefault(tokens[index + 1], tokens[index + 2 :])
    return invocations


def entrypoint_arguments(
    operation: str, plugin_root: str, project_root: Path
) -> list[str]:
    """One workflow invocation with this host's literals substituted in.

    The confirmation clock is pinned on the operations whose grammar accepts
    it (§11.4). That is the one argument here the workflow document does not
    spell out, and it is a test affordance rather than a behaviour change: the
    flag is optional, omitting it means "stamp now", and pinning it is what
    lets two runs be compared on the digests that cover the stamp.
    """

    declared = workflow_invocations(CLAUDE_RISK_WORKFLOW)[operation]
    substitutions = {
        "<exact absolute plugin root>": plugin_root,
        "${CLAUDE_PLUGIN_ROOT}": plugin_root,
        "$PWD": str(project_root),
    }
    arguments = []
    for token in declared:
        for placeholder, literal in substitutions.items():
            token = token.replace(placeholder, literal)
        arguments.append(token)
    if operation in CLOCK_PINNED_OPERATIONS:
        arguments.extend(["--confirmed-at", PINNED_CONFIRMED_AT])
    return arguments


def fresh_environment(home: Path, **extra: str) -> dict[str, str]:
    """A host environment built from nothing rather than inherited.

    The shell that runs this suite may already export `CLAUDE_PLUGIN_DATA`
    (a Claude host sets it) or `SECURITY_REQUIREMENTS_DATA`. Inheriting either
    sends both runs at the developer's real state directory: the run would
    write outside the temporary tree, and the "Codex has no ambient root"
    premise would be false before the first call.
    """

    home.mkdir(parents=True, exist_ok=True)
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(home),
        # `plugin_data_root` reads this on Linux and `HOME` on macOS. Setting
        # both keeps the resolved data root inside `home` on either.
        "XDG_STATE_HOME": str(home / "state"),
        "LANG": "C.UTF-8",
    }
    environment.update(extra)
    return environment


def capture(command: list[str], *, cwd: Path, env: dict[str, str]) -> dict:
    """Run one command, returning its result rather than asserting on it.

    Returned rather than asserted because these runs happen inside a
    module-scoped fixture: an assertion here is reported as a setup ERROR
    attached to no requirement, and a parity claim that fails must fail by
    name.
    """

    completed = subprocess.run(
        command, cwd=str(cwd), env=env, capture_output=True, text=True
    )
    return {
        "command": command,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def normalised(value, replacements: list[tuple[str, str]]):
    """A structure with run-local absolute paths replaced by stable tokens.

    Each entrypoint runs in its own project directory and its own state root,
    so `confirmation.project` and every path inside a validation message names
    a different directory. That difference is the harness, not the payload.
    """

    if isinstance(value, dict):
        return {key: normalised(item, replacements) for key, item in value.items()}
    if isinstance(value, list):
        return [normalised(item, replacements) for item in value]
    if isinstance(value, str):
        for text, token in replacements:
            value = value.replace(text, token)
        return value
    return value


def path_replacements(project_root: Path, data_root: str, home: Path) -> list[tuple[str, str]]:
    """Longest first, so `/tmp/x/project` is not half-replaced by `/tmp/x`."""

    pairs = [
        (str(Path(project_root).resolve()), "<project root>"),
        (str(project_root), "<project root>"),
        (str(Path(data_root).resolve()) if data_root else "", "<data root>"),
        (data_root, "<data root>"),
        (str(Path(home).resolve()), "<home>"),
        (str(home), "<home>"),
    ]
    return sorted(
        ((text, token) for text, token in pairs if text),
        key=lambda pair: len(pair[0]),
        reverse=True,
    )


def operation_record(result: dict, replacements: list[tuple[str, str]]) -> dict:
    """One operation reduced to its structured result.

    `stdout` is mined for digests and then discarded: the sentence around the
    digest is prose and N43 allows it to differ. `stderr` problems are the
    engine's own validation list, emitted by shared code, and are compared —
    with run-local paths normalised out.
    """

    return {
        "returncode": result["returncode"],
        "digests": ANY_DIGEST.findall(result["stdout"]),
        "problems": sorted(
            normalised(line.strip(), replacements)
            for line in result["stderr"].splitlines()
            if line.startswith("ERROR:")
        ),
    }


def store_documents(project_root: Path, replacements) -> dict:
    store = Path(project_root) / STORE_DIRNAME
    return {
        path.name: normalised(
            yaml.safe_load(path.read_text(encoding="utf-8")), replacements
        )
        for path in sorted(store.glob("*.yaml"))
    }


def external_confirmations(data_root: str, replacements) -> dict:
    """The plugin-owned confirmation records, keyed by kind.

    Keyed by kind rather than by filename: the filename is a digest of the
    project path (`runtime_paths.confirmation_state_path`), so the two runs
    name the same record differently for a reason that is not parity.
    """

    root = Path(data_root) / "risk"
    if not root.is_dir():
        return {}
    records = {}
    for kind in sorted(path for path in root.iterdir() if path.is_dir()):
        for document in sorted(kind.glob("*.yaml")):
            records[kind.name] = normalised(
                yaml.safe_load(document.read_text(encoding="utf-8")), replacements
            )
    return records


def entrypoint_payload(project_root: Path, data_root: str, home: Path, operations: dict) -> dict:
    replacements = path_replacements(project_root, data_root, home)
    return {
        "operations": {
            name: operation_record(result, replacements)
            for name, result in operations.items()
        },
        "documents": store_documents(project_root, replacements),
        "confirmations": external_confirmations(data_root, replacements),
    }


def run_through_claude_entrypoint(project_root: Path, home: Path) -> dict:
    """`commands/sec-req-risk.md`, "Trusted runtime paths", step by step.

    The Claude host hands the workflow `${CLAUDE_PLUGIN_ROOT}`; the workflow
    resolves persistent state once and prefixes both literals onto every later
    call rather than exporting them.
    """

    plugin_root = str(PLUGIN_ROOT)
    environment = fresh_environment(home, CLAUDE_PLUGIN_ROOT=plugin_root)

    resolution = capture(
        [
            sys.executable,
            "-I",
            f"{plugin_root}/{RUNTIME_PATHS_SCRIPT}",
            "--project-root",
            str(project_root),
        ],
        cwd=project_root,
        env={**environment, "SECURITY_REQUIREMENTS_ROOT": plugin_root},
    )
    data_root = resolution["stdout"].strip()

    operations = {}
    for name in PARITY_OPERATIONS:
        operations[name] = capture(
            [
                sys.executable,
                "-I",
                f"{plugin_root}/{RISK_SCRIPT}",
                name,
                *entrypoint_arguments(name, plugin_root, project_root),
            ],
            cwd=project_root,
            env={
                **environment,
                "SECURITY_REQUIREMENTS_ROOT": plugin_root,
                "SECURITY_REQUIREMENTS_DATA": data_root,
            },
        )

    payload = entrypoint_payload(project_root, data_root, home, operations)
    payload["resolution"] = {
        "entrypoint": "claude",
        "plugin_root": plugin_root,
        "data_root": data_root,
        "resolver_returncode": resolution["returncode"],
        "rederived_roots": [],
    }
    return payload


def run_through_codex_entrypoint(project_root: Path, home: Path) -> dict:
    """`skills/security-requirements-risk/SKILL.md`, its adapter procedure.

    No `CLAUDE_PLUGIN_ROOT` is placed in the environment: the Codex host has
    none, and a run that quietly read one would prove nothing about the
    adapter. The root comes from the loader-selected SKILL.md, is checked
    against the candidate literal the way the skill's `test ... || exit` line
    does, and is re-derived before every call (adapter step 4).
    """

    skill = CODEX_RISK_ENTRY_SKILL
    # Adapter step 1: strip `/skills/<name>/SKILL.md` from the selected path.
    candidate_root = str(skill.parent.parent.parent)
    environment = fresh_environment(home)
    resolver = [
        sys.executable,
        "-I",
        f"{candidate_root}/{RUNTIME_PATHS_SCRIPT}",
        "--skill",
        str(skill),
    ]

    derivation = capture(resolver, cwd=project_root, env=environment)
    plugin_root = derivation["stdout"].strip()

    resolution = capture(
        [
            sys.executable,
            "-I",
            f"{plugin_root}/{RUNTIME_PATHS_SCRIPT}",
            "--project-root",
            str(project_root),
        ],
        cwd=project_root,
        env={**environment, "SECURITY_REQUIREMENTS_ROOT": plugin_root},
    )
    data_root = resolution["stdout"].strip()

    operations = {}
    rederived = []
    for name in PARITY_OPERATIONS:
        # Step 4: derive the root again in a fresh call before the operation.
        rederived.append(capture(resolver, cwd=project_root, env=environment)["stdout"].strip())
        operations[name] = capture(
            [
                sys.executable,
                "-I",
                f"{plugin_root}/{RISK_SCRIPT}",
                name,
                *entrypoint_arguments(name, plugin_root, project_root),
            ],
            cwd=project_root,
            env={
                **environment,
                "SECURITY_REQUIREMENTS_ROOT": plugin_root,
                "SECURITY_REQUIREMENTS_DATA": data_root,
            },
        )

    payload = entrypoint_payload(project_root, data_root, home, operations)
    payload["resolution"] = {
        "entrypoint": "codex",
        "plugin_root": plugin_root,
        "candidate_root": candidate_root,
        "data_root": data_root,
        "resolver_returncode": derivation["returncode"],
        "rederived_roots": rederived,
    }
    return payload


def materialise_adversarial_tree(destination: Path) -> Path:
    """The plan §11.5 repository fixture, assembled inside a temporary tree.

    Local rather than imported: `tests/risk_helpers.py` is under concurrent
    edit, and a parity test that breaks when a helper is renamed reports the
    wrong failure.
    """

    for source in sorted(ADVERSARIAL_FIXTURE.rglob("*")):
        if not source.is_file():
            continue
        relative = source.relative_to(ADVERSARIAL_FIXTURE)
        target = destination / relative.parent / MATERIALISED_NAMES.get(
            relative.name, relative.name
        )
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
    return destination


def write_model(project_root: Path, *, mutate_threat_scenario: bool = False) -> Path:
    """Materialise the golden model as a project store.

    Copied from `golden/movie-rating-aws` rather than invented: a model this
    file made up could be scored identically by both entrypoints and still be
    a model the engine would reject in the field.
    """

    store = project_root / STORE_DIRNAME
    store.mkdir(parents=True, exist_ok=True)
    for name in GOLDEN_MODEL_DOCUMENTS:
        shutil.copyfile(GOLDEN_MODEL / name, store / name)
    shutil.copyfile(DEFAULT_POLICY, store / "risk-policy.yaml")

    # Round-tripped in both arms so the control differs by its one edit and
    # not by YAML formatting.
    threats_path = store / "threats.yaml"
    threats = yaml.safe_load(threats_path.read_text(encoding="utf-8"))
    if mutate_threat_scenario:
        threats["threats"][0]["scenario"] = (
            str(threats["threats"][0]["scenario"])
            + " The scenario now describes a materially different attack."
        )
    threats_path.write_text(
        yaml.safe_dump(threats, allow_unicode=True, sort_keys=False), encoding="utf-8"
    )
    return store


def build_parity_project(fixture: str, destination: Path) -> Path:
    """One parity fixture: a project tree plus the model to score in it."""

    destination.mkdir(parents=True, exist_ok=True)
    if fixture == "adversarial-checkout":
        materialise_adversarial_tree(destination)
    else:
        (destination / "README.md").write_text(
            "# movie-rating-aws\n\nA repository carrying no planted material.\n",
            encoding="utf-8",
        )
    write_model(destination)
    return destination


@pytest.fixture(scope="module")
def parity_runs(tmp_path_factory) -> dict:
    """Every parity fixture, run once through each entrypoint.

    Module scoped because each run is a handful of real subprocesses and every
    test below asks a different question of the same two answers.
    """

    runs = {}
    for fixture in PARITY_FIXTURES:
        base = tmp_path_factory.mktemp(f"parity-{fixture}")
        runs[fixture] = {
            "claude": run_through_claude_entrypoint(
                build_parity_project(fixture, base / "claude" / fixture),
                base / "claude-home",
            ),
            "codex": run_through_codex_entrypoint(
                build_parity_project(fixture, base / "codex" / fixture),
                base / "codex-home",
            ),
        }
    return runs


def digests_by_location(payload) -> dict[str, str]:
    """Every `sha256:` value in a payload, keyed by where it was found."""

    found: dict[str, str] = {}

    def walk(value, location: str) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                walk(item, f"{location}.{key}")
        elif isinstance(value, list):
            for index, item in enumerate(value):
                walk(item, f"{location}[{index}]")
        elif isinstance(value, str) and value.startswith("sha256:"):
            found[location] = value

    walk(payload, "")
    return found


def calculated_scores(payload) -> dict[str, dict]:
    """`threat_id -> calculated` for every assessed record the run wrote."""

    assessment = payload["documents"].get("risk-assessment.yaml") or {}
    return {
        str(record.get("threat_id")): record.get("calculated")
        for record in assessment.get("assessments", [])
        if isinstance(record, dict) and record.get("calculated") is not None
    }


def differing_locations(left, right, location: str = "") -> list[str]:
    """Every dotted location at which two payloads disagree."""

    if isinstance(left, dict) and isinstance(right, dict):
        differences = []
        for key in sorted(set(left) | set(right)):
            if key not in left or key not in right:
                differences.append(f"{location}.{key}")
                continue
            differences.extend(differing_locations(left[key], right[key], f"{location}.{key}"))
        return differences
    if isinstance(left, list) and isinstance(right, list):
        if len(left) != len(right):
            return [f"{location}[length]"]
        differences = []
        for index, (one, other) in enumerate(zip(left, right)):
            differences.extend(differing_locations(one, other, f"{location}[{index}]"))
        return differences
    return [] if left == right else [location]


def payload_differences(left: dict, right: dict) -> list[str]:
    """Where two entrypoint payloads disagree, ignoring where they ran.

    `resolution` records the data root and the host's own literals, which are
    per-run by construction and normalised out of everything else.
    """

    return [
        location
        for location in differing_locations(left, right)
        if not location.startswith(".resolution")
    ]


def test_the_two_entrypoints_resolve_to_the_same_plugin_payload_root(parity_runs):
    """The premise every other parity test rests on, asserted by execution.

    The Claude workflow is handed `${CLAUDE_PLUGIN_ROOT}`; the Codex adapter
    derives its root from the selected SKILL.md with no ambient variable
    present. If those two ever name different directories, "one payload" is a
    statement about the repository layout and not about what runs.
    """

    for fixture, runs in parity_runs.items():
        claude = runs["claude"]["resolution"]
        codex = runs["codex"]["resolution"]

        assert codex["resolver_returncode"] == 0, (
            "the Codex adapter must derive the payload root from the selected "
            f"SKILL.md ({CODEX_RISK_ENTRY_SKILL}); the resolver exited "
            f"{codex['resolver_returncode']} for fixture {fixture}"
        )
        assert codex["plugin_root"] == codex["candidate_root"], (
            "adapter step 2 requires the derived root to equal the candidate "
            "formed by stripping /skills/<name>/SKILL.md; derived "
            f"{codex['plugin_root']!r}, candidate {codex['candidate_root']!r}"
        )
        assert claude["plugin_root"] == codex["plugin_root"], (
            "both entrypoints must resolve to the one payload root; Claude "
            f"resolved {claude['plugin_root']!r} and Codex resolved "
            f"{codex['plugin_root']!r} for fixture {fixture}"
        )
        assert codex["rederived_roots"] == [codex["plugin_root"]] * len(PARITY_OPERATIONS), (
            "adapter step 4 re-derives the root before every call and stops on "
            f"a mismatch; the {len(PARITY_OPERATIONS)} calls of fixture "
            f"{fixture} derived {codex['rederived_roots']!r}"
        )


def grammar_operations(home: Path) -> set[str]:
    """Every subcommand `risk.py` actually accepts, read from the grammar.

    Asked of the engine rather than listed here, so "the adapter names a real
    operation" is decided by the payload and not by this file's memory of it.
    """

    usage = capture(
        [sys.executable, "-I", f"{PLUGIN_ROOT}/{RISK_SCRIPT}", "--help"],
        cwd=REPO_ROOT,
        env=fresh_environment(home),
    )["stdout"]
    choices = re.search(r"\{([a-z0-9,-]+)\}", usage)
    return set(choices.group(1).split(",")) if choices else set()


def test_the_codex_adapter_names_no_risk_operation_the_claude_workflow_omits(tmp_path):
    """One payload means one command surface, not two that resemble each other.

    The adapter is meant to delegate to `commands/sec-req-risk.md`. An
    operation named in the adapter but absent from the workflow would be a
    second, unreviewed surface — and the run comparison below would never see
    it, because it runs what the workflow declares. Candidates are recognised
    against the engine's own grammar, so the test can fail: `migrate` or
    `design-review` named in the adapter is exactly what it looks for.
    """

    grammar = grammar_operations(tmp_path / "grammar-home")
    assert grammar, (
        f"`{RISK_SCRIPT} --help` listed no subcommand; the operation names in "
        "the adapter cannot be recognised"
    )

    declared = set(workflow_invocations(CLAUDE_RISK_WORKFLOW))
    assert declared, (
        "no `risk.py` invocation was found in "
        f"{CLAUDE_RISK_WORKFLOW}; the parity run has nothing to execute"
    )
    invented = sorted(declared - grammar)
    assert not invented, (
        f"{CLAUDE_RISK_WORKFLOW.name} invokes operations the engine does not "
        f"accept: {invented}; the grammar accepts {sorted(grammar)}"
    )

    adapter = CODEX_RISK_ENTRY_SKILL.read_text(encoding="utf-8")
    named = {
        candidate
        for candidate in re.findall(r"`([a-z][a-z0-9-]*)`", adapter)
        if candidate in grammar
    }
    assert named, (
        f"the Codex adapter {CODEX_RISK_ENTRY_SKILL} names no risk operation "
        "at all; either it stopped delegating or this test stopped reading it"
    )
    unknown = sorted(named - declared)
    assert not unknown, (
        "the Codex adapter names risk operations the shared workflow does not "
        f"declare: {unknown}; the workflow declares {sorted(declared)}"
    )


@pytest.mark.parametrize("fixture", PARITY_FIXTURES)
def test_both_fixtures_yield_the_same_structured_record_through_both_entrypoints(
    parity_runs, fixture
):
    """N43 — the structured payload, compared field by field.

    Documents, exit codes and validation problems, not rendered text.
    """

    claude = parity_runs[fixture]["claude"]
    codex = parity_runs[fixture]["codex"]

    for entrypoint, payload in (("claude", claude), ("codex", codex)):
        assert payload["documents"], (
            f"the {entrypoint} entrypoint wrote no document under "
            f"{STORE_DIRNAME}/ for fixture {fixture}; an empty payload would "
            "make every comparison below pass for the wrong reason"
        )
        assert calculated_scores(payload), (
            f"the {entrypoint} entrypoint produced no calculated assessment "
            f"record for fixture {fixture}; there is nothing to compare"
        )

    differences = payload_differences(claude, codex)
    assert not differences, (
        f"fixture {fixture} produced different structured values through the "
        "two entrypoints; they must agree on every field except prose "
        f"(plan §11.2 N43). Disagreeing at: {differences}"
    )


@pytest.mark.parametrize("fixture", PARITY_FIXTURES)
def test_both_fixtures_yield_the_same_scores_through_both_entrypoints(
    parity_runs, fixture
):
    """N43 — the numbers, checked for substance before being compared.

    A score comparison that passes because neither side computed anything is
    the failure mode this test exists to refuse, so every score is asserted to
    be a real 1-25 product of its own likelihood and impact first.
    """

    claude = calculated_scores(parity_runs[fixture]["claude"])
    codex = calculated_scores(parity_runs[fixture]["codex"])

    assert claude, (
        f"fixture {fixture} scored nothing through the Claude entrypoint; an "
        "empty score set cannot demonstrate parity"
    )
    for entrypoint in ("claude", "codex"):
        confirmation = parity_runs[fixture][entrypoint]["operations"]["confirm"]
        assert confirmation["returncode"] == 0, (
            f"the {entrypoint} entrypoint's `confirm` exited "
            f"{confirmation['returncode']} for fixture {fixture}: "
            f"{confirmation['problems']}. The golden model ships `calculated` "
            "blocks of its own, so a failed run leaves them in place and the "
            "comparison below would be over fixture data rather than over what "
            "this run computed"
        )
    for entrypoint, scores in (("claude", claude), ("codex", codex)):
        for threat_id, calculated in sorted(scores.items()):
            likelihood = calculated.get("likelihood")
            impact = calculated.get("impact")
            score = calculated.get("score")
            assert isinstance(score, int) and 1 <= score <= 25, (
                f"{threat_id} scored {score!r} through the {entrypoint} "
                "entrypoint; the 5x5 model gives an integer 1-25 "
                "(plan §2.2)"
            )
            assert score == likelihood * impact, (
                f"{threat_id} through the {entrypoint} entrypoint reports "
                f"score {score!r} for likelihood {likelihood!r} x impact "
                f"{impact!r}; score is the product, not a stored opinion"
            )
            assert calculated.get("rating"), (
                f"{threat_id} through the {entrypoint} entrypoint carries no "
                f"rating: {calculated!r}"
            )

    assert claude == codex, (
        f"fixture {fixture} scored differently through the two entrypoints. "
        f"Claude: {claude!r}. Codex: {codex!r}"
    )


@pytest.mark.parametrize("fixture", PARITY_FIXTURES)
def test_both_fixtures_yield_the_same_digests_through_both_entrypoints(
    parity_runs, fixture
):
    """N43 — every digest, asserted to exist and to be well formed first.

    Two empty digest sets are equal, and two `None`s are equal. Neither says
    anything about the payload, so the shape of every value is pinned before
    any comparison is made.
    """

    claude = digests_by_location(parity_runs[fixture]["claude"])
    codex = digests_by_location(parity_runs[fixture]["codex"])

    for entrypoint, digests in (("claude", claude), ("codex", codex)):
        assert digests, (
            f"the {entrypoint} entrypoint wrote no digest at all for fixture "
            f"{fixture}; equal-because-absent is not parity"
        )
        malformed = sorted(
            f"{location}={value}"
            for location, value in digests.items()
            if not WELL_FORMED_DIGEST.fullmatch(value)
        )
        assert not malformed, (
            f"the {entrypoint} entrypoint wrote digests that are not this "
            "repository's `sha256:` + 64 lowercase hex characters "
            f"(`risk.canonical_digest`): {malformed}"
        )
        written = {location.rsplit(".", 1)[-1] for location in digests}
        missing = [
            key for key in DIGEST_KEYS_A_CONFIRMING_RUN_WRITES if key not in written
        ]
        assert not missing, (
            f"the {entrypoint} entrypoint wrote no {missing} for fixture "
            f"{fixture}; the run did not reach the state snapshot and the "
            "comparison below would be over a fraction of the payload"
        )

    assert claude == codex, (
        f"fixture {fixture} produced different digests through the two "
        "entrypoints; identical inputs must digest identically on either "
        f"host. Claude: {claude!r}. Codex: {codex!r}"
    )


@pytest.mark.parametrize("fixture", PARITY_FIXTURES)
def test_nothing_at_all_differs_between_the_two_entrypoints(parity_runs, fixture):
    """The whole payload at once, with no field exempted.

    The tests above each ask about one slice, and a slice-by-slice suite can
    let an unexamined field drift. This compares the entire structured record
    — documents, plugin-owned confirmations, exit codes, problems, digests and
    timestamps — and names every location that disagrees. The only thing
    dropped is `resolution`, which records where each host found the payload
    and is per-run by construction.
    """

    differences = payload_differences(
        parity_runs[fixture]["claude"], parity_runs[fixture]["codex"]
    )
    assert not differences, (
        f"fixture {fixture} disagrees between the two entrypoints at: "
        f"{differences}. With the confirmation clock pinned to "
        f"{PINNED_CONFIRMED_AT}, one payload run twice has nothing left to "
        "differ about"
    )


def test_a_changed_model_changes_the_digests_so_parity_is_not_a_constant(tmp_path):
    """The negative control for every equality asserted above.

    If the digests were fixed strings, or were computed over nothing, both
    entrypoints would agree perfectly and prove nothing. One edited sentence
    inside one threat must move the digest that binds it.
    """

    baseline = tmp_path / "baseline"
    control = tmp_path / "control"
    baseline.mkdir()
    control.mkdir()
    write_model(baseline)
    write_model(control, mutate_threat_scenario=True)

    first = run_through_claude_entrypoint(baseline, tmp_path / "baseline-home")
    second = run_through_claude_entrypoint(control, tmp_path / "control-home")

    def threat_digests(payload) -> set[str]:
        return {
            value
            for location, value in digests_by_location(payload).items()
            if location.endswith("threat_digest")
        }

    changed = threat_digests(first)
    control_digests = threat_digests(second)
    assert changed and control_digests, (
        "neither run wrote a `threat_digest`; the control cannot show that "
        f"digests track content. Baseline: {changed!r}. Control: "
        f"{control_digests!r}"
    )
    assert changed.isdisjoint(control_digests), (
        "editing a threat's scenario left the threat digest unchanged "
        f"({changed!r}); the digests the parity tests compare do not track "
        "the model, so their equality means nothing"
    )


def test_the_run_recalculates_the_scores_it_reports_rather_than_echoing_them(tmp_path):
    """The negative control for the score comparison.

    `golden/movie-rating-aws` ships `calculated` blocks, so two entrypoints
    could agree on every score by copying the same input through. This plants
    a model-declared 5x5 = 25 critical on the first record and asserts the run
    replaces it with the policy's own result, which is what makes "identical
    scores through both entrypoints" a statement about calculation.
    """

    project = tmp_path / "declared"
    project.mkdir()
    write_model(project)
    assessment_path = project / STORE_DIRNAME / "risk-assessment.yaml"
    assessment = yaml.safe_load(assessment_path.read_text(encoding="utf-8"))
    declared = {"likelihood": 5, "impact": 5, "score": 25, "rating": "critical"}
    threat_id = assessment["assessments"][0]["threat_id"]
    assessment["assessments"][0]["calculated"] = dict(declared)
    assessment_path.write_text(
        yaml.safe_dump(assessment, allow_unicode=True, sort_keys=False), encoding="utf-8"
    )

    payload = run_through_claude_entrypoint(project, tmp_path / "declared-home")
    scored = calculated_scores(payload).get(threat_id)

    assert scored, (
        f"the run wrote no calculated block for {threat_id}; the control "
        f"cannot show the score was recomputed. Payload scores: "
        f"{calculated_scores(payload)!r}"
    )
    assert scored != declared, (
        f"the run reported {threat_id} as the model's own declared "
        f"{declared!r}; a score copied out of the document would compare "
        "equal through both entrypoints while proving nothing about scoring"
    )
    assert scored["score"] == scored["likelihood"] * scored["impact"], (
        f"{threat_id} was recomputed to {scored!r}, which is not a product of "
        "its own criteria"
    )


def test_the_grammar_accepts_the_clock_pin_the_parity_run_needs(tmp_path):
    """Without `--confirmed-at`, "identical digests" is unreachable from a CLI.

    `risk._confirmation_metadata` stamps `datetime.now` unless a caller pins
    it, and `snapshot_digest` and `confirmation.risk_state_digest` are taken
    over records carrying that stamp. Both entrypoints reach the engine only
    through the command line, so without the flag those two digests differ
    between any two runs — the same entrypoint run twice disagrees with
    itself, and N43's "identical ... digests" would hold for five of the seven
    digests at best.

    Asserted on every confirming operation rather than on the one the parity
    run happens to use, because withdrawing the flag from any of them silently
    narrows what a parity run can claim.
    """

    for operation in CLOCK_PINNED_OPERATIONS:
        project = tmp_path / operation
        project.mkdir()
        write_model(project)
        arguments = entrypoint_arguments(operation, str(PLUGIN_ROOT), project)

        assert "--confirmed-at" in arguments, (
            f"the parity run's `{operation}` call carries no `--confirmed-at`; "
            "the two runs would then be compared across a moving clock "
            f"(§11.4). The call was {arguments!r}"
        )
        pinned = capture(
            [
                sys.executable,
                "-I",
                f"{PLUGIN_ROOT}/{RISK_SCRIPT}",
                operation,
                *arguments,
            ],
            cwd=project,
            env=fresh_environment(
                tmp_path / f"{operation}-home",
                SECURITY_REQUIREMENTS_ROOT=str(PLUGIN_ROOT),
            ),
        )

        assert pinned["returncode"] != 2, (
            f"`risk.py {operation}` rejected the pinned confirmation clock: "
            f"{pinned['stderr'].strip()!r}. Without `--confirmed-at` "
            "(`risk._add_confirmed_at_argument`) `snapshot_digest` and "
            "`confirmation.risk_state_digest` cannot be compared between two "
            "runs, and the parity tests above would be comparing the second "
            "hand rather than the payload"
        )
