#!/usr/bin/env python3
"""Validate the source tree that both plugin marketplaces distribute."""

from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import re
import shlex
import stat
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
APPROVED_PAYLOAD_FILES = frozenset(
    Path(value)
    for value in """
.claude-plugin/plugin.json
.codex-plugin/plugin.json
catalogs/asvs-5/LICENSE
catalogs/asvs-5/NOTICE
catalogs/asvs-5/V1.jsonl
catalogs/asvs-5/V10.jsonl
catalogs/asvs-5/V11.jsonl
catalogs/asvs-5/V12.jsonl
catalogs/asvs-5/V13.jsonl
catalogs/asvs-5/V14.jsonl
catalogs/asvs-5/V15.jsonl
catalogs/asvs-5/V16.jsonl
catalogs/asvs-5/V17.jsonl
catalogs/asvs-5/V2.jsonl
catalogs/asvs-5/V3.jsonl
catalogs/asvs-5/V4.jsonl
catalogs/asvs-5/V5.jsonl
catalogs/asvs-5/V6.jsonl
catalogs/asvs-5/V7.jsonl
catalogs/asvs-5/V8.jsonl
catalogs/asvs-5/V9.jsonl
catalogs/asvs-5/meta.json
catalogs/csf-2.0/categories.json
catalogs/csf-2.0/meta.json
catalogs/csf-2.0/subcategories.jsonl
catalogs/csp-rules/aws.md
catalogs/data-types/availability.yaml
catalogs/data-types/classification.yaml
catalogs/nist-800-53r5/AC.jsonl
catalogs/nist-800-53r5/AT.jsonl
catalogs/nist-800-53r5/AU.jsonl
catalogs/nist-800-53r5/CA.jsonl
catalogs/nist-800-53r5/CM.jsonl
catalogs/nist-800-53r5/CP.jsonl
catalogs/nist-800-53r5/IA.jsonl
catalogs/nist-800-53r5/IR.jsonl
catalogs/nist-800-53r5/LICENSE
catalogs/nist-800-53r5/MA.jsonl
catalogs/nist-800-53r5/MP.jsonl
catalogs/nist-800-53r5/PE.jsonl
catalogs/nist-800-53r5/PL.jsonl
catalogs/nist-800-53r5/PM.jsonl
catalogs/nist-800-53r5/PS.jsonl
catalogs/nist-800-53r5/PT.jsonl
catalogs/nist-800-53r5/RA.jsonl
catalogs/nist-800-53r5/SA.jsonl
catalogs/nist-800-53r5/SC.jsonl
catalogs/nist-800-53r5/SI.jsonl
catalogs/nist-800-53r5/SR.jsonl
catalogs/nist-800-53r5/baselines.json
catalogs/nist-800-53r5/meta.json
commands/sec-req-build.md
commands/sec-req-init.md
commands/sec-req-refresh.md
commands/sec-req-risk.md
overlays/SCHEMA.md
overlays/gdpr/criteria.jsonl
overlays/gdpr/mappings.jsonl
overlays/gdpr/meta.yaml
overlays/hipaa-security-rule/criteria.jsonl
overlays/hipaa-security-rule/mappings.jsonl
overlays/hipaa-security-rule/meta.yaml
overlays/hipaa-security-rule/source.json
overlays/iso-27001/criteria.jsonl
overlays/iso-27001/mappings.jsonl
overlays/iso-27001/meta.yaml
overlays/pci-dss/criteria.jsonl
overlays/pci-dss/mappings.jsonl
overlays/pci-dss/meta.yaml
overlays/pipa-isms-p/criteria.jsonl
overlays/pipa-isms-p/mappings.jsonl
overlays/pipa-isms-p/meta.yaml
overlays/soc2/criteria.jsonl
overlays/soc2/mappings.jsonl
overlays/soc2/meta.yaml
responsibility/layers.yaml
responsibility/services/aws-alb.yaml
responsibility/services/aws-api-gateway.yaml
responsibility/services/aws-cloudfront.yaml
responsibility/services/aws-cognito.yaml
responsibility/services/aws-dynamodb.yaml
responsibility/services/aws-ecs.yaml
responsibility/services/aws-lambda.yaml
responsibility/services/aws-rds.yaml
responsibility/services/aws-s3.yaml
responsibility/services/aws-sqs.yaml
responsibility/services/azure-blob.yaml
responsibility/services/gcp-gke.yaml
risk/default-policy.yaml
scripts/apply_overlay.py
scripts/axis_coverage.py
scripts/classify_resp.py
scripts/confirmation.py
scripts/eval_golden.py
scripts/lint.py
scripts/merge.py
scripts/mutate.py
scripts/profile_locale.py
scripts/profile_schema.py
scripts/publish.py
scripts/rebuild_catalogs.py
scripts/rebuild_overlay_hipaa.py
scripts/render.py
scripts/risk.py
scripts/runtime_paths.py
scripts/safe_paths.py
scripts/select_baseline.py
scripts/semantic_review.py
scripts/validate_overlays.py
skills/deriving-security-requirements/SKILL.md
skills/deriving-security-requirements/references/profile-schema.md
skills/deriving-security-requirements/references/repository-trust.md
skills/deriving-security-requirements/references/requirement-style.md
skills/deriving-security-requirements/references/risk-assessment.md
skills/deriving-security-requirements/references/threat-modeling.md
skills/security-requirements-build/SKILL.md
skills/security-requirements-init/SKILL.md
skills/security-requirements-refresh/SKILL.md
skills/security-requirements-risk/SKILL.md
""".splitlines()
    if value
)
APPROVED_PAYLOAD_DIRECTORIES = frozenset(
    parent
    for file_path in APPROVED_PAYLOAD_FILES
    for parent in file_path.parents
    if parent != Path(".")
)
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


class _UniqueKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def _construct_unique_mapping(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as error:
            raise yaml.YAMLError(f"unhashable mapping key: {key!r}") from error
        if duplicate:
            raise yaml.YAMLError(f"duplicate mapping key: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _redirect_kind(path: Path) -> str | None:
    """Return the redirect kind without following repository-controlled paths."""

    try:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            return "symlink"
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        if getattr(metadata, "st_file_attributes", 0) & reparse_flag:
            return "junction" if path.is_junction() else "reparse point"
        if path.is_junction():
            return "junction"
    except FileNotFoundError:
        return None
    except OSError:
        return "redirect"
    return None


def _lexical_type(path: Path) -> str:
    """Classify one lexical path with lstat, never following redirects."""

    redirect = _redirect_kind(path)
    if redirect is not None:
        return redirect
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return "missing"
    except OSError:
        return "unreadable"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISREG(mode):
        return "file"
    return "unsupported file type"


def _redirect_in_path(path: Path, boundary: Path) -> tuple[Path, str] | None:
    """Find a redirect from *boundary* through *path*, including both endpoints."""

    try:
        relative = path.relative_to(boundary)
    except ValueError:
        return path, "outside-boundary"
    current = boundary
    boundary_kind = _redirect_kind(current)
    if boundary_kind is not None:
        return current, boundary_kind
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
    if _lexical_type(base) != "directory":
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
    if _lexical_type(path) == "missing":
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


def _metadata_symlinks(
    root: Path, errors: list[str], metadata_files: tuple[Path, ...]
) -> None:
    found: set[Path] = set()
    for relative in metadata_files:
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
) -> None:
    root_scripts = root / "scripts"
    root_scripts_type = _lexical_type(root_scripts)
    if root_scripts_type in {"symlink", "junction", "reparse point", "redirect"}:
        errors.append(
            f"{root_scripts_type} is not allowed in top-level scripts: scripts"
        )
    elif root_scripts_type == "directory":
        allowed = {"validate_distribution.py", "__pycache__"}
        try:
            names = {entry.name for entry in os.scandir(root_scripts)}
        except OSError as error:
            errors.append(f"cannot inspect top-level scripts: {error}")
        else:
            if names - allowed:
                errors.append("top-level runtime directory: scripts")
    for directory in RUNTIME_DIRECTORIES[1:]:
        candidate = root / directory
        candidate_type = _lexical_type(candidate)
        if candidate_type in {"symlink", "junction", "reparse point", "redirect"}:
            errors.append(
                f"{candidate_type} is not allowed in top-level runtime path: {directory}"
            )
        elif candidate_type != "missing":
            errors.append(f"top-level runtime directory: {directory}")


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
        if _lexical_type(path) != "file" or path.suffix.lower() not in TEXT_PAYLOAD_SUFFIXES:
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
        if _redirect_in_path(path, payload) is not None or _lexical_type(path) != "file":
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
    payload: Path,
    errors: list[str],
    payload_entries: list[Path],
) -> None:
    for relative in RISK_ASSETS:
        expected = payload / relative
        if _lexical_type(expected) != "file":
            errors.append(f"missing required risk asset: {relative.as_posix()}")

        duplicates = [
            path
            for path in payload_entries
            if path != expected
            and _lexical_type(path) == "file"
            and path.name == expected.name
            and path.relative_to(payload) not in APPROVED_PAYLOAD_FILES
        ]
        for duplicate in duplicates:
            errors.append(
                "duplicate risk asset: "
                f"{duplicate.relative_to(payload).as_posix()} duplicates {relative.as_posix()}"
            )


def _policy_contract(payload: Path, errors: list[str]) -> None:
    path = payload / "risk" / "default-policy.yaml"
    if _redirect_in_path(path, payload) is not None or _lexical_type(path) != "file":
        return
    try:
        document = yaml.load(
            path.read_text(encoding="utf-8"), Loader=_UniqueKeySafeLoader
        )
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
        thresholds = document.get("thresholds")
        exact_threshold_numbers = (
            isinstance(thresholds, list)
            and all(
                isinstance(row, dict)
                and type(row.get("min")) is int
                and type(row.get("max")) is int
                for row in thresholds
            )
        )
        if thresholds != expected_thresholds or not exact_threshold_numbers:
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
                    or type(criterion.get("score")) is not int
                    or not 1 <= criterion["score"] <= 5
                    or criterion["score"] != score
                    or not isinstance(criterion.get("definition"), str)
                    or not criterion["definition"].strip()
                ):
                    problems.append(f"{axis} criterion {criterion_id} is invalid")
    for problem in problems:
        errors.append(f"invalid bundled default risk policy: {problem}")


def _assigned_string_constants(syntax: ast.AST) -> dict[str, str]:
    values: dict[str, str] = {}
    for node in getattr(syntax, "body", []):
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            values[node.targets[0].id] = node.value.value
    return values


def _matches_version_comparison(
    comparison: ast.Compare,
    receiver: str,
    operator: type[ast.cmpop],
    version_constant: str,
) -> bool:
    call = comparison.left
    return (
        len(comparison.ops) == 1
        and isinstance(comparison.ops[0], operator)
        and isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr == "get"
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id == receiver
        and len(call.args) == 1
        and isinstance(call.args[0], ast.Constant)
        and call.args[0].value == "version"
        and len(comparison.comparators) == 1
        and isinstance(comparison.comparators[0], ast.Name)
        and comparison.comparators[0].id == version_constant
    )


def _gate_rejects(body: list[ast.stmt]) -> bool:
    for node in body:
        if isinstance(node, ast.Raise):
            return True
        if (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Attribute)
            and node.value.func.attr == "append"
            and isinstance(node.value.func.value, ast.Name)
            and node.value.func.value.id == "problems"
        ):
            return True
    return False


def _direct_gate_comparisons(
    function_name: str, test: ast.expr
) -> list[ast.Compare]:
    if function_name != "migrate":
        return [test] if isinstance(test, ast.Compare) else []
    if not (
        isinstance(test, ast.BoolOp)
        and isinstance(test.op, ast.Or)
        and len(test.values) == 2
    ):
        return []
    type_guard, version_guard = test.values
    if not (
        isinstance(type_guard, ast.UnaryOp)
        and isinstance(type_guard.op, ast.Not)
        and isinstance(type_guard.operand, ast.Call)
        and isinstance(type_guard.operand.func, ast.Name)
        and type_guard.operand.func.id == "isinstance"
        and type_guard.operand.args
        and isinstance(type_guard.operand.args[0], ast.Name)
        and type_guard.operand.args[0].id == "threats"
        and len(type_guard.operand.args) == 2
        and isinstance(type_guard.operand.args[1], ast.Name)
        and type_guard.operand.args[1].id == "Mapping"
        and isinstance(version_guard, ast.Compare)
    ):
        return []
    return [version_guard]


def _executable_body(function: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.stmt]:
    body = function.body
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        return body[1:]
    return body


def _exact_setup_call(
    statement: ast.stmt, targets: tuple[str, ...], function: str
) -> bool:
    if not (
        isinstance(statement, ast.Assign)
        and len(statement.targets) == 1
        and isinstance(statement.value, ast.Call)
        and isinstance(statement.value.func, ast.Name)
        and statement.value.func.id == function
    ):
        return False
    assigned = statement.targets[0]
    if len(targets) == 1:
        return isinstance(assigned, ast.Name) and assigned.id == targets[0]
    return (
        isinstance(assigned, ast.Tuple)
        and len(assigned.elts) == len(targets)
        and all(isinstance(item, ast.Name) for item in assigned.elts)
        and tuple(item.id for item in assigned.elts) == targets
    )


def _canonical_gate_statement(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> ast.If | None:
    body = _executable_body(function)
    if function.name == "migrate":
        return body[0] if body and isinstance(body[0], ast.If) else None
    if function.name == "_validate_threats":
        if not (
            len(body) >= 3
            and isinstance(body[0], ast.AnnAssign)
            and isinstance(body[0].target, ast.Name)
            and body[0].target.id == "problems"
            and isinstance(body[1], ast.If)
            and isinstance(body[1].test, ast.UnaryOp)
            and isinstance(body[1].test.op, ast.Not)
            and isinstance(body[1].test.operand, ast.Call)
            and isinstance(body[1].test.operand.func, ast.Name)
            and body[1].test.operand.func.id == "isinstance"
            and len(body[1].test.operand.args) == 2
            and isinstance(body[1].test.operand.args[0], ast.Name)
            and body[1].test.operand.args[0].id == "threats_doc"
            and isinstance(body[1].test.operand.args[1], ast.Name)
            and body[1].test.operand.args[1].id == "Mapping"
            and len(body[1].body) == 1
            and isinstance(body[1].body[0], ast.Return)
            and isinstance(body[2], ast.If)
        ):
            return None
        return body[2]
    if function.name == "_load_risk_state":
        if not (
            len(body) >= 3
            and _exact_setup_call(
                body[0], ("project_root", "state_path"), "_project_document_path"
            )
            and _exact_setup_call(body[1], ("state",), "_load_optional_mapping")
            and isinstance(body[2], ast.If)
        ):
            return None
        return body[2]
    return None


def _function_uses_version_gate(
    syntax: ast.AST,
    function_name: str,
    receiver: str,
    operator: type[ast.cmpop],
    version_constant: str,
) -> bool:
    function = next(
        (
            node
            for node in getattr(syntax, "body", [])
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == function_name
        ),
        None,
    )
    if function is None:
        return False
    statement = _canonical_gate_statement(function)
    if statement is None or not _gate_rejects(statement.body):
        return False
    comparisons = _direct_gate_comparisons(function_name, statement.test)
    return any(
        _matches_version_comparison(
            comparison, receiver, operator, version_constant
        )
        for comparison in comparisons
    )


def _risk_engine_schema_contract(syntax: ast.AST, errors: list[str]) -> None:
    expected_constants = {
        "LEGACY_THREAT_SCHEMA_VERSION": "0.1.0",
        "CURRENT_THREAT_SCHEMA_VERSION": THREAT_SCHEMA_VERSION,
        "RISK_SCHEMA_VERSION": RELEASE_VERSION,
    }
    declarations = _assigned_string_constants(syntax)
    for name, expected in expected_constants.items():
        if declarations.get(name) != expected:
            errors.append(
                f"risk engine schema contract mismatch: {name} must equal {expected}"
            )

    gates = (
        (
            "_validate_threats",
            "threats_doc",
            ast.NotEq,
            "CURRENT_THREAT_SCHEMA_VERSION",
        ),
        ("migrate", "threats", ast.NotEq, "LEGACY_THREAT_SCHEMA_VERSION"),
        ("_load_risk_state", "state", ast.NotEq, "RISK_SCHEMA_VERSION"),
    )
    for function_name, receiver, operator, constant in gates:
        if not _function_uses_version_gate(
            syntax, function_name, receiver, operator, constant
        ):
            errors.append(
                "risk engine schema contract mismatch: "
                f"{function_name} must compare {receiver}.version with {constant}"
            )


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
            _risk_engine_schema_contract(syntax, errors)

    interface = manifests["Codex"].get("interface")
    if not isinstance(interface, dict):
        errors.append("Codex manifest.interface must be a mapping")
        prompts = None
    else:
        prompts = interface.get("defaultPrompt")
        if not isinstance(prompts, list) or any(
            not isinstance(prompt, str) for prompt in prompts
        ):
            errors.append(
                "Codex manifest.interface.defaultPrompt must be a list of strings"
            )
    if prompts != list(WORKFLOW_PROMPTS):
        errors.append("Codex manifest must declare exactly the four canonical workflow prompts")


def _entrypoint_contract(payload: Path, errors: list[str], payload_entries: list[Path]) -> None:
    expected_commands = {f"sec-req-{workflow}.md" for workflow in WORKFLOWS}
    commands = payload / "commands"
    for path in payload_entries:
        if path.parent == commands and _lexical_type(path) == "file" and path.suffix == ".md":
            if path.name not in expected_commands:
                errors.append(f"unexpected Claude entry point: {path.relative_to(payload)}")

    expected_skills = {f"security-requirements-{workflow}" for workflow in WORKFLOWS}
    skills = payload / "skills"
    for path in payload_entries:
        if (
            path.parent == skills
            and _lexical_type(path) == "directory"
            and path.name.startswith("security-requirements-")
        ):
            if path.name not in expected_skills:
                errors.append(f"unexpected Codex entry point: {path.relative_to(payload)}")


def _approved_payload_contract(
    payload: Path, errors: list[str], payload_entries: list[Path]
) -> None:
    for path in payload_entries:
        relative = path.relative_to(payload)
        path_type = _lexical_type(path)
        approved = (
            path_type == "file" and relative in APPROVED_PAYLOAD_FILES
        ) or (
            path_type == "directory" and relative in APPROVED_PAYLOAD_DIRECTORIES
        )
        if not approved and path_type not in {
            "symlink",
            "junction",
            "reparse point",
            "redirect",
        }:
            errors.append(f"unapproved payload path: {relative.as_posix()}")

    for relative in sorted(APPROVED_PAYLOAD_DIRECTORIES):
        if _lexical_type(payload / relative) != "directory":
            errors.append(f"missing required payload directory: {relative.as_posix()}")
    for relative in sorted(APPROVED_PAYLOAD_FILES):
        if _lexical_type(payload / relative) != "file":
            errors.append(f"missing required payload file: {relative.as_posix()}")


def validate(root: Path) -> list[str]:
    """Return every detected packaging error without changing *root*."""
    root = Path(os.path.abspath(root))
    errors: list[str] = []
    root_redirect = _redirect_kind(root)
    if root_redirect is not None:
        return [f"{root_redirect} is not allowed in distribution root: {root}"]
    payload = root / PAYLOAD
    payload_redirect = _redirect_kind(payload)
    payload_entries = _walk_no_redirect(payload, errors, label="payload")
    claude_marketplace_path = root / ".claude-plugin" / "marketplace.json"
    codex_marketplace_path = root / ".agents" / "plugins" / "marketplace.json"
    claude_marketplace = _read_json(claude_marketplace_path, errors, root)
    codex_marketplace = _read_json(codex_marketplace_path, errors, root)
    _metadata_symlinks(root, errors, METADATA_FILES[:2])
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

    if payload_redirect is not None:
        return errors

    _metadata_symlinks(root, errors, METADATA_FILES[2:])

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
        if _lexical_type(payload / component) != "missing":
            errors.append(f"Codex payload must not include {component}")
    for component in (".mcp.json", ".app.json"):
        if _lexical_type(payload / component) != "missing":
            errors.append(f"Codex payload must not include {component}")

    _duplicate_runtime_directories(root, payload, errors)
    _workflow_python_invocations(payload, errors, payload_entries)
    _safe_output_preflights(payload, errors)
    _risk_asset_contract(payload, errors, payload_entries)
    _policy_contract(payload, errors)
    _release_contract(payload, manifests, errors)
    _entrypoint_contract(payload, errors, payload_entries)
    _approved_payload_contract(payload, errors, payload_entries)

    for workflow in WORKFLOWS:
        command = payload / "commands" / f"sec-req-{workflow}.md"
        skill = payload / "skills" / f"security-requirements-{workflow}" / "SKILL.md"
        if _redirect_in_path(command, payload) is not None or _lexical_type(command) != "file":
            errors.append(f"missing Claude entry point: {command.relative_to(root)}")
        if _redirect_in_path(skill, payload) is not None or _lexical_type(skill) != "file":
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
