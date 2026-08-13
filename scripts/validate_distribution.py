#!/usr/bin/env python3
"""Validate the source tree that both plugin marketplaces distribute."""

from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import re
import shlex
import sys

import yaml


PLUGIN_NAME = "security-requirements"
PAYLOAD = Path("plugins") / PLUGIN_NAME
RELEASE_VERSION = "0.2.0"
THREAT_SCHEMA_VERSION = "0.2.0"
RUNTIME_DIRECTORIES = ("scripts", "catalogs", "overlays", "responsibility", "skills")
WORKFLOWS = ("init", "build", "refresh", "risk")
WORKFLOW_PROMPTS = (
    "Initialize the security requirements profile for this repository.",
    "Build security requirements from the confirmed profile.",
    "Refresh security requirements after service changes.",
    "Assess and review threat risk for this repository.",
)
RISK_ASSETS = (
    Path("risk") / "default-policy.yaml",
    Path("scripts") / "risk.py",
    Path("commands") / "sec-req-risk.md",
    Path("skills") / "security-requirements-risk" / "SKILL.md",
    Path("skills") / "deriving-security-requirements" / "references" / "risk-assessment.md",
)
APPROVED_PAYLOAD_ROOTS = {
    ".claude-plugin",
    ".codex-plugin",
    "catalogs",
    "commands",
    "overlays",
    "responsibility",
    "risk",
    "scripts",
    "skills",
}
FORBIDDEN_CODEX_COMPONENTS = ("mcpServers", "apps", "hooks")
METADATA_FILES = (
    Path(".claude-plugin") / "marketplace.json",
    Path(".agents") / "plugins" / "marketplace.json",
    PAYLOAD / ".claude-plugin" / "plugin.json",
    PAYLOAD / ".codex-plugin" / "plugin.json",
)
PATH_FIELD_NAMES = {
    "agents", "commands", "outputstyles",
    "path", "paths", "screenshots", "skills", "scripts", "files", "directories", "source",
}
INLINE_OR_PATH_FIELDS = {"hooks", "mcpservers", "lspservers"}
TEXT_PAYLOAD_SUFFIXES = {".json", ".md", ".py", ".toml", ".yaml", ".yml"}
PYTHON_INTERPRETER = re.compile(
    r'''(?<![\w./-])(?P<quote>["']?)(?:/(?:[^\s/"']+/)*)?'''
    r"python(?:\d+(?:\.\d+)*)?(?P=quote)(?=[ \t]|$)"
)
PYTHON_OPTIONS_WITH_VALUE = {"-W", "-X", "--check-hash-based-pycs"}
TRUSTED_WORKFLOW_SCRIPTS = {
    "<trusted packaged script name.py>",
    "apply_overlay.py",
    "axis_coverage.py",
    "classify_resp.py",
    "confirmation.py",
    "eval_golden.py",
    "lint.py",
    "merge.py",
    "mutate.py",
    "profile_locale.py",
    "profile_schema.py",
    "publish.py",
    "rebuild_catalogs.py",
    "rebuild_overlay_hipaa.py",
    "render.py",
    "runtime_paths.py",
    "risk.py",
    "safe_paths.py",
    "select_baseline.py",
    "semantic_review.py",
    "validate_overlays.py",
}
APPROVED_SCRIPT_FILES = TRUSTED_WORKFLOW_SCRIPTS - {"<trusted packaged script name.py>"}
TRUSTED_SCRIPT_PREFIXES = (
    "<absolute plugin root>/scripts/",
    "<exact absolute plugin root>/scripts/",
    "<derived absolute candidate>/scripts/",
    "${CLAUDE_PLUGIN_ROOT}/scripts/",
)
SAFE_OUTPUTS = {
    "init": (".security-requirements",),
    "build": (".security-requirements", "docs/security"),
    "refresh": (".security-requirements", "docs/security"),
    "risk": (".security-requirements",),
}
CANONICAL_SAFE_OUTPUT_PREFLIGHTS = {
    workflow: (
        'python3 -I "${CLAUDE_PLUGIN_ROOT}/scripts/safe_paths.py" '
        f'--project-root "$PWD" --check-output {" ".join(outputs)}'
    )
    for workflow, outputs in SAFE_OUTPUTS.items()
}
CANONICAL_SAFE_OUTPUT_PREFLIGHTS_BY_PATH = {
    Path("commands") / f"sec-req-{workflow}.md": command
    for workflow, command in CANONICAL_SAFE_OUTPUT_PREFLIGHTS.items()
}


def _redirect_kind(path: Path) -> str | None:
    """Return the redirect kind without following repository-controlled paths."""

    try:
        if path.is_symlink():
            return "symlink"
        if path.is_junction():
            return "junction"
    except OSError:
        return "redirect"
    return None


def _redirect_in_path(path: Path, boundary: Path) -> tuple[Path, str] | None:
    """Find a redirect from *boundary* through *path*, including both endpoints."""

    try:
        relative = path.relative_to(boundary)
    except ValueError:
        return path, "outside-boundary"
    current = boundary
    for part in relative.parts:
        current = current / part
        kind = _redirect_kind(current)
        if kind is not None:
            return current, kind
    return None


def _walk_no_redirect(
    base: Path,
    errors: list[str],
    *,
    label: str,
    report_redirects: bool = True,
) -> list[Path]:
    """List descendants without following symlinks or junctions."""

    entries: list[Path] = []
    kind = _redirect_kind(base)
    if kind is not None:
        if report_redirects:
            errors.append(f"{kind} is not allowed in {label}: {base}")
        return entries
    if not base.is_dir():
        return entries

    pending = [base]
    while pending:
        directory = pending.pop()
        try:
            children = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as error:
            errors.append(f"cannot inspect {label}: {directory}: {error}")
            continue
        for child in children:
            path = Path(child.path)
            entries.append(path)
            redirect = _redirect_kind(path)
            if redirect is not None:
                if report_redirects:
                    errors.append(f"{redirect} is not allowed in {label}: {path}")
                continue
            try:
                if child.is_dir(follow_symlinks=False):
                    pending.append(path)
            except OSError as error:
                errors.append(f"cannot inspect {label}: {path}: {error}")
    return entries


def _read_json(path: Path, errors: list[str], boundary: Path | None = None) -> dict:
    if boundary is not None:
        redirected = _redirect_in_path(path, boundary)
        if redirected is not None:
            redirect, kind = redirected
            errors.append(f"{kind} is not allowed in distribution metadata: {redirect}")
            return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except UnicodeDecodeError as error:
        errors.append(f"cannot decode JSON file: {path}: {error.reason}")
        return {}
    except OSError as error:
        errors.append(f"cannot read JSON file: {path}: {error.strerror or error}")
        return {}
    except json.JSONDecodeError as error:
        errors.append(f"invalid JSON in {path}: {error.msg}")
        return {}
    except TypeError as error:
        errors.append(f"invalid JSON input for {path}: {error}")
        return {}
    if not isinstance(data, dict):
        errors.append(f"JSON object required: {path}")
        return {}
    return data


def _plugin_entry(marketplace: dict, host: str, errors: list[str]) -> dict:
    entries = marketplace.get("plugins")
    if not isinstance(entries, list):
        errors.append(f"{host} marketplace must contain a plugins list")
        return {}
    matches = [entry for entry in entries if isinstance(entry, dict) and entry.get("name") == PLUGIN_NAME]
    if len(matches) != 1:
        errors.append(f"{host} marketplace must declare exactly one {PLUGIN_NAME} entry")
        return {}
    return matches[0]


def _relative_path(value: object, base: Path, label: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not value.startswith("./"):
        errors.append(f"{label} must be a relative path beginning with ./: {value!r}")
        return
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        errors.append(f"{label} must not use an absolute or traversal path: {value}")
        return
    path = base / value
    redirected = _redirect_in_path(path, base)
    if redirected is not None:
        redirect, kind = redirected
        errors.append(f"{label} must not traverse a {kind}: {redirect}")
        return
    try:
        path.resolve().relative_to(base.resolve())
    except ValueError:
        errors.append(f"{label} escapes its payload: {value}")
        return
    if not path.exists():
        errors.append(f"missing manifest-declared path for {label}: {path}")


def _is_path_field(name: str) -> bool:
    lowered = name.replace("-", "_").lower()
    return lowered in PATH_FIELD_NAMES or lowered.endswith(
        ("path", "paths", "file", "files", "directory", "directories")
    )


def _path_values(value: object, payload: Path, label: str, errors: list[str]) -> None:
    if isinstance(value, str):
        _relative_path(value, payload, label, errors)
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _path_values(nested, payload, f"{label}[{index}]", errors)
    elif isinstance(value, dict):
        for key, nested in value.items():
            _path_values(nested, payload, f"{label}.{key}", errors)
    else:
        errors.append(f"{label} must contain path strings, lists, or mappings: {value!r}")


def _manifest_paths(
    value: object,
    payload: Path,
    label: str,
    errors: list[str],
    field: str = "",
    inline_context: bool = False,
) -> None:
    normalized_field = field.replace("-", "_").lower()
    if normalized_field in INLINE_OR_PATH_FIELDS and not inline_context:
        if isinstance(value, str):
            _relative_path(value, payload, label, errors)
            return
        if not isinstance(value, (dict, list)):
            errors.append(f"{label} must be a path string or inline configuration: {value!r}")
            return
        _manifest_paths(value, payload, label, errors, inline_context=True)
        return
    if _is_path_field(field):
        _path_values(value, payload, label, errors)
        return
    if isinstance(value, dict):
        for key, nested in value.items():
            _manifest_paths(nested, payload, f"{label}.{key}", errors, key, inline_context)
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _manifest_paths(nested, payload, f"{label}[{index}]", errors, field, inline_context)
    elif isinstance(value, str) and value.startswith("./"):
        _relative_path(value, payload, label, errors)


def _metadata_symlinks(root: Path, errors: list[str]) -> None:
    found: set[Path] = set()
    for relative in METADATA_FILES:
        path = root / relative
        while path != root:
            redirect = _redirect_kind(path)
            if redirect is not None and path not in found:
                errors.append(
                    f"{redirect} is not allowed in distribution metadata: {path.relative_to(root)}"
                )
                found.add(path)
            path = path.parent


def _duplicate_runtime_directories(
    root: Path,
    payload: Path,
    errors: list[str],
    plugin_entries: list[Path],
) -> None:
    root_scripts = root / "scripts"
    if root_scripts.is_dir():
        allowed = {"validate_distribution.py", "__pycache__"}
        if any(path.name not in allowed for path in root_scripts.iterdir()):
            errors.append("top-level runtime directory: scripts")
    for directory in RUNTIME_DIRECTORIES[1:]:
        if (root / directory).exists():
            errors.append(f"top-level runtime directory: {directory}")

    for directory in RUNTIME_DIRECTORIES:
        expected = payload / directory
        if _redirect_in_path(expected, payload) is not None or not expected.is_dir():
            errors.append(f"missing runtime directory: {expected}")
            continue
        for path in plugin_entries:
            if path.name == directory and path.is_dir() and path != expected:
                errors.append(f"duplicate runtime directory: {directory} at {path}")


def _logical_lines(text: str):
    """Yield shell-style logical lines while retaining their first line number."""
    buffered = ""
    start = 1
    for number, line in enumerate(text.splitlines(), start=1):
        if not buffered:
            start = number
        if line.endswith("\\"):
            buffered += line[:-1]
            continue
        yield start, buffered + line
        buffered = ""
    if buffered:
        yield start, buffered


def _python_arguments(command: str, start: int) -> list[str]:
    """Tokenise one Python invocation from its interpreter to the shell boundary."""
    fragment = command[start:]
    prefix = command[:start]
    if "$(" in prefix:
        closing = max(fragment.rfind(')"'), fragment.rfind(")'"))
        if closing >= 0:
            fragment = fragment[:closing]
    try:
        tokens = shlex.split(fragment, posix=True)
    except ValueError:
        prefix = prefix.rstrip()
        stripped = fragment.rstrip()
        if (
            prefix.endswith(("'", '"'))
            and stripped.endswith(prefix[-1])
        ):
            try:
                tokens = shlex.split(stripped[:-1], posix=True)
            except ValueError:
                return []
        else:
            return []
    bounded = []
    for token in tokens:
        if token in {";", "&&", "||", "|"}:
            break
        bounded.append(token.rstrip("`"))
    return bounded


def _python_script(tokens: list[str]) -> tuple[str | None, bool, bool]:
    """Return (script, isolated, inline) for an already-tokenised invocation."""
    isolated = False
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            index += 1
            break
        if token == "-":
            break
        if token == "-c" or token.startswith("-c"):
            return None, isolated, True
        if token == "-m" or token.startswith("-m"):
            return token, isolated, True
        if token in PYTHON_OPTIONS_WITH_VALUE:
            index += 2
            continue
        if token.startswith("-X") or token.startswith("-W"):
            index += 1
            continue
        if token.startswith("-"):
            short_options = token[1:] if not token.startswith("--") else ""
            if token == "-I" or "I" in short_options:
                isolated = True
            if "c" in short_options or "m" in short_options:
                return None, isolated, True
            index += 1
            continue
        break
    script = tokens[index] if index < len(tokens) else None
    if script in (None, "-"):
        return None, isolated, True
    return script, isolated, False


def _trusted_workflow_script(script: str, tokens: list[str]) -> bool:
    matching_prefix = next(
        (prefix for prefix in TRUSTED_SCRIPT_PREFIXES if script.startswith(prefix)), None
    )
    if matching_prefix is None:
        return False
    name = script.removeprefix(matching_prefix)
    if "/" in name or name not in TRUSTED_WORKFLOW_SCRIPTS:
        return False
    if matching_prefix == "${CLAUDE_PLUGIN_ROOT}/scripts/":
        return name == "runtime_paths.py"
    if matching_prefix == "<derived absolute candidate>/scripts/":
        return name == "runtime_paths.py" and "--skill" in tokens
    return True


def _workflow_python_invocations(
    payload: Path, errors: list[str], payload_entries: list[Path]
) -> None:
    for path in payload_entries:
        if not path.is_file() or path.suffix.lower() not in TEXT_PAYLOAD_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as error:
            errors.append(f"cannot inspect payload file: {path}: {error}")
            continue
        relative = path.relative_to(payload)
        canonical_preflight = CANONICAL_SAFE_OUTPUT_PREFLIGHTS_BY_PATH.get(relative)
        for line_number, command in _logical_lines(text):
            if command.lstrip().startswith("#!"):
                continue
            for match in PYTHON_INTERPRETER.finditer(command):
                tokens = _python_arguments(command, match.start())
                if not tokens:
                    errors.append(
                        "cannot parse Python invocation in workflow: "
                        f"{relative}:{line_number}"
                    )
                    continue
                script, isolated, inline = _python_script(tokens)
                location = f"{relative}:{line_number}"
                if inline:
                    errors.append(f"inline Python is not allowed in workflow: {location}")
                    continue
                if script.startswith(("scripts/", "./scripts/")):
                    errors.append(f"cwd-relative payload script invocation: {location}")
                    continue
                if not isolated:
                    errors.append(f"workflow Python invocation must use -I: {location}")
                if (
                    not _trusted_workflow_script(script, tokens)
                    and command != canonical_preflight
                ):
                    error = (
                        "workflow Python script is not rooted in the plugin payload: "
                        f"{location}"
                    )
                    if error not in errors:
                        errors.append(error)

            try:
                semantic_tokens = shlex.split(command, posix=True)
            except ValueError:
                continue
            claude_safe_paths_mention = any(
                "CLAUDE_PLUGIN_ROOT" in token.rstrip("`")
                and Path(token.rstrip("`")).name == "safe_paths.py"
                for token in semantic_tokens
            )
            if claude_safe_paths_mention and command != canonical_preflight:
                error = (
                    "workflow Python script is not rooted in the plugin payload: "
                    f"{relative}:{line_number}"
                )
                if error not in errors:
                    errors.append(error)


def _contains_broad_safe_output_preflight(
    command: str, required_outputs: tuple[str, ...]
) -> bool:
    raw_outputs = all(
        re.search(
            rf"(?<![A-Za-z0-9_.-]){re.escape(output)}/?"
            r"(?![A-Za-z0-9_./-])",
            command,
        )
        for output in required_outputs
    )
    if raw_outputs and (
        "safe_paths.py" in command or "--check-output" in command
    ):
        return True

    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return False
    cleaned = [token.rstrip("`") for token in tokens]
    safe_paths_mention = any(Path(token).name == "safe_paths.py" for token in cleaned)
    output_values: list[str] = []
    for index, token in enumerate(cleaned):
        if token == "--check-output":
            output_values = cleaned[index + 1 :]
            break
        if token.startswith("--check-output="):
            output_values = [token.partition("=")[2], *cleaned[index + 1 :]]
            break
    dynamic_output = any(
        re.search(r"[$`*?{}\[\]()]|^~", value) for value in output_values
    )
    if safe_paths_mention and (not output_values or dynamic_output):
        return True
    normalized = {Path(token).as_posix() for token in cleaned}
    normalized.update(
        Path(token.partition("=")[2]).as_posix()
        for token in cleaned
        if token.startswith("--check-output=")
    )
    if not set(required_outputs) <= normalized:
        return False
    output_claim = any(
        token == "--check-output" or token.startswith("--check-output=")
        for token in cleaned
    )
    return safe_paths_mention or output_claim


def _bash_blocks(text: str) -> list[list[str]]:
    """Return executable Markdown bash blocks, excluding comments/nested fences."""
    blocks: list[list[str]] = []
    fence: tuple[str, int, str] | None = None
    content: list[str] = []
    in_html_comment = False

    for line in text.splitlines():
        if fence is not None:
            character, minimum, language = fence
            if re.fullmatch(rf"{re.escape(character)}{{{minimum},}}[ \t]*", line):
                if language == "bash":
                    blocks.append(content)
                fence = None
                content = []
            else:
                content.append(line)
            continue

        if in_html_comment:
            if "-->" in line:
                in_html_comment = False
            continue
        if "<!--" in line:
            if "-->" not in line.split("<!--", 1)[1]:
                in_html_comment = True
            continue

        opening = re.fullmatch(r"(?P<marker>`{3,}|~{3,})(?P<info>.*)", line)
        if opening:
            marker = opening.group("marker")
            fence = (marker[0], len(marker), opening.group("info").strip())
            content = []

    return blocks


def _safe_output_preflights(payload: Path, errors: list[str]) -> None:
    for workflow, required_outputs in SAFE_OUTPUTS.items():
        path = payload / "commands" / f"sec-req-{workflow}.md"
        if _redirect_in_path(path, payload) is not None or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        canonical = CANONICAL_SAFE_OUTPUT_PREFLIGHTS[workflow]
        candidates = [
            command
            for _, command in _logical_lines(text)
            if _contains_broad_safe_output_preflight(command, required_outputs)
        ]
        valid = (
            candidates == [canonical]
            and _bash_blocks(text).count([canonical]) == 1
        )
        relative = path.relative_to(payload)
        expected = " ".join(required_outputs)
        if valid:
            continue
        if candidates:
            errors.append(
                f"invalid safe output preflight in {relative}: "
                f"--project-root $PWD --check-output {expected}"
            )
        else:
            errors.append(
                f"missing safe output preflight in {relative}: "
                f"--project-root $PWD --check-output {expected}"
            )


def _risk_asset_contract(
    root: Path,
    payload: Path,
    errors: list[str],
    repository_entries: list[Path],
) -> None:
    for relative in RISK_ASSETS:
        expected = payload / relative
        if _redirect_in_path(expected, payload) is not None or not expected.is_file():
            errors.append(f"missing required risk asset: {relative.as_posix()}")

        matches = [
            path
            for path in repository_entries
            if path != expected
            and path.is_file()
            and (
                path.relative_to(root).as_posix().endswith(relative.as_posix())
                or (relative == Path("scripts/risk.py") and path.name == "risk.py")
            )
        ]
        for duplicate in matches:
            errors.append(
                "duplicate risk asset: "
                f"{duplicate.relative_to(root).as_posix()} duplicates {relative.as_posix()}"
            )


def _policy_contract(payload: Path, errors: list[str]) -> None:
    path = payload / "risk" / "default-policy.yaml"
    if _redirect_in_path(path, payload) is not None or not path.is_file():
        return
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as error:
        errors.append(f"invalid bundled default risk policy: cannot parse YAML: {error}")
        return

    expected_ids = {
        "likelihood": [
            "L1-EXCEPTIONAL",
            "L2-RESTRICTED",
            "L3-AUTHENTICATED",
            "L4-PUBLIC-LOW-COMPLEXITY",
            "L5-DIRECT-AUTOMATABLE",
        ],
        "impact": [
            "I1-LOCAL-RECOVERABLE",
            "I2-LIMITED-SCOPE",
            "I3-CORE-SERVICE",
            "I4-CROSS-SYSTEM",
            "I5-ORGANISATION-IRREVERSIBLE",
        ],
    }
    expected_thresholds = [
        {"min": 1, "max": 4, "rating": "low"},
        {"min": 5, "max": 9, "rating": "medium"},
        {"min": 10, "max": 16, "rating": "high"},
        {"min": 17, "max": 25, "rating": "critical"},
    ]
    problems: list[str] = []
    if not isinstance(document, dict):
        problems.append("document must be a mapping")
    else:
        allowed = {"version", "thresholds", "likelihood", "impact", "publish_risk_summary"}
        if set(document) != allowed:
            problems.append("top-level fields must match the bundled policy schema exactly")
        if document.get("version") != "1.0.0":
            problems.append("version must be 1.0.0")
        if document.get("thresholds") != expected_thresholds:
            problems.append("thresholds must define the complete canonical 5x5 bands")
        if document.get("publish_risk_summary") is not False:
            problems.append("public summary must default to false")
        for axis, ids in expected_ids.items():
            criteria = document.get(axis)
            if not isinstance(criteria, dict) or list(criteria) != ids:
                problems.append(f"{axis} must declare the five canonical criteria in order")
                continue
            for score, criterion_id in enumerate(ids, start=1):
                criterion = criteria.get(criterion_id)
                if (
                    not isinstance(criterion, dict)
                    or set(criterion) != {"score", "definition"}
                    or criterion.get("score") != score
                    or not isinstance(criterion.get("definition"), str)
                    or not criterion["definition"].strip()
                ):
                    problems.append(f"{axis} criterion {criterion_id} is invalid")
    for problem in problems:
        errors.append(f"invalid bundled default risk policy: {problem}")


def _release_contract(payload: Path, manifests: dict[str, dict], errors: list[str]) -> None:
    versions = {host: manifest.get("version") for host, manifest in manifests.items()}
    if any(version != RELEASE_VERSION for version in versions.values()):
        errors.append(
            f"payload manifest versions must both equal {RELEASE_VERSION}: "
            f"Claude={versions['Claude']!r}, Codex={versions['Codex']!r}"
        )

    reference = (
        payload
        / "skills"
        / "deriving-security-requirements"
        / "references"
        / "threat-modeling.md"
    )
    if _redirect_in_path(reference, payload) is None:
        try:
            threat_text = reference.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            threat_text = ""
        declared = re.findall(r"schema version `([^`]+)`", threat_text)
        if declared != [THREAT_SCHEMA_VERSION]:
            errors.append(
                f"threat schema version must agree with release {THREAT_SCHEMA_VERSION}: "
                f"found {declared!r}"
            )

    engine = payload / "scripts" / "risk.py"
    if _redirect_in_path(engine, payload) is None:
        try:
            syntax = ast.parse(engine.read_text(encoding="utf-8"), filename=str(engine))
        except (OSError, UnicodeDecodeError, SyntaxError) as error:
            errors.append(f"cannot inspect risk engine schema versions: {error}")
        else:
            engine_versions = {
                node.value
                for node in ast.walk(syntax)
                if isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and re.fullmatch(r"\d+\.\d+\.\d+", node.value)
            }
            expected_versions = {"0.1.0", THREAT_SCHEMA_VERSION}
            if engine_versions != expected_versions:
                errors.append(
                    f"risk engine schema versions must agree with release {THREAT_SCHEMA_VERSION}: "
                    f"found {sorted(engine_versions)!r}"
                )

    prompts = manifests["Codex"].get("interface", {}).get("defaultPrompt")
    if prompts != list(WORKFLOW_PROMPTS):
        errors.append("Codex manifest must declare exactly the four canonical workflow prompts")


def _entrypoint_contract(payload: Path, errors: list[str], payload_entries: list[Path]) -> None:
    expected_commands = {f"sec-req-{workflow}.md" for workflow in WORKFLOWS}
    commands = payload / "commands"
    for path in payload_entries:
        if path.parent == commands and path.is_file() and path.suffix == ".md":
            if path.name not in expected_commands:
                errors.append(f"unexpected Claude entry point: {path.relative_to(payload)}")

    expected_skills = {f"security-requirements-{workflow}" for workflow in WORKFLOWS}
    skills = payload / "skills"
    for path in payload_entries:
        if path.parent == skills and path.is_dir() and path.name.startswith("security-requirements-"):
            if path.name not in expected_skills:
                errors.append(f"unexpected Codex entry point: {path.relative_to(payload)}")


def _approved_payload_contract(payload: Path, errors: list[str], payload_entries: list[Path]) -> None:
    for path in payload_entries:
        relative = path.relative_to(payload)
        if len(relative.parts) == 1 and relative.name not in APPROVED_PAYLOAD_ROOTS:
            errors.append(f"unapproved payload component: {relative.as_posix()}")
        if (
            relative.parent == Path("scripts")
            and path.is_file()
            and relative.name not in APPROVED_SCRIPT_FILES
            and relative.name != "__pycache__"
        ):
            errors.append(f"unapproved payload component: {relative.as_posix()}")


def validate(root: Path) -> list[str]:
    """Return every detected packaging error without changing *root*."""
    root = root.resolve()
    errors: list[str] = []
    payload = root / PAYLOAD
    repository_entries = _walk_no_redirect(
        root, errors, label="distribution", report_redirects=False
    )
    plugins_root = root / "plugins"
    plugin_entries = _walk_no_redirect(
        plugins_root, errors, label="plugin distribution"
    )
    payload_entries = [
        path
        for path in plugin_entries
        if path != payload
        and payload in path.parents
        and _redirect_in_path(path, payload) is None
    ]
    claude_marketplace_path = root / ".claude-plugin" / "marketplace.json"
    codex_marketplace_path = root / ".agents" / "plugins" / "marketplace.json"
    claude_marketplace = _read_json(claude_marketplace_path, errors, root)
    codex_marketplace = _read_json(codex_marketplace_path, errors, root)
    _metadata_symlinks(root, errors)
    claude_entry = _plugin_entry(claude_marketplace, "Claude", errors)
    codex_entry = _plugin_entry(codex_marketplace, "Codex", errors)

    expected_source = "./plugins/security-requirements"
    if claude_entry.get("source") != expected_source:
        errors.append(f"Claude marketplace source must be {expected_source}")
    codex_source = codex_entry.get("source")
    if not isinstance(codex_source, dict) or codex_source.get("source") != "local":
        errors.append("Codex marketplace source must be a local source")
    elif codex_source.get("path") != expected_source:
        errors.append(f"Codex marketplace source path must be {expected_source}")

    if codex_marketplace.get("name") != PLUGIN_NAME:
        errors.append(f"Codex marketplace name must equal qualified install marketplace: {PLUGIN_NAME}")
    if f"{codex_entry.get('name')}@{codex_marketplace.get('name')}" != f"{PLUGIN_NAME}@{PLUGIN_NAME}":
        errors.append(f"Codex marketplace must resolve {PLUGIN_NAME}@{PLUGIN_NAME}")

    for host, entry in (("Claude", claude_entry), ("Codex", codex_entry)):
        if entry.get("name") not in (None, payload.name):
            errors.append(f"{host} marketplace name must equal payload folder: {payload.name}")

    manifests = {
        "Claude": _read_json(payload / ".claude-plugin" / "plugin.json", errors, root),
        "Codex": _read_json(payload / ".codex-plugin" / "plugin.json", errors, root),
    }
    for host, manifest in manifests.items():
        if manifest.get("name") != payload.name:
            errors.append(f"{host} manifest name must equal payload folder: {payload.name}")
        _manifest_paths(manifest, payload, f"{host} manifest", errors)

    for component in FORBIDDEN_CODEX_COMPONENTS:
        if component in manifests["Codex"]:
            errors.append(f"Codex manifest must not declare {component}")
        if (payload / component).exists():
            errors.append(f"Codex payload must not include {component}")
    for component in (".mcp.json", ".app.json"):
        if (payload / component).exists():
            errors.append(f"Codex payload must not include {component}")

    _duplicate_runtime_directories(root, payload, errors, plugin_entries)
    _workflow_python_invocations(payload, errors, payload_entries)
    _safe_output_preflights(payload, errors)
    _risk_asset_contract(root, payload, errors, repository_entries)
    _policy_contract(payload, errors)
    _release_contract(payload, manifests, errors)
    _entrypoint_contract(payload, errors, payload_entries)
    _approved_payload_contract(payload, errors, payload_entries)

    for workflow in WORKFLOWS:
        command = payload / "commands" / f"sec-req-{workflow}.md"
        skill = payload / "skills" / f"security-requirements-{workflow}" / "SKILL.md"
        if _redirect_in_path(command, payload) is not None or not command.is_file():
            errors.append(f"missing Claude entry point: {command.relative_to(root)}")
        if _redirect_in_path(skill, payload) is not None or not skill.is_file():
            errors.append(f"missing Codex entry point: {skill.relative_to(root)}")
    return errors


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 1:
        print("usage: validate_distribution.py REPOSITORY_ROOT", file=sys.stderr)
        return 2
    errors = validate(Path(arguments[0]))
    for error in errors:
        print(f"error: {error}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
