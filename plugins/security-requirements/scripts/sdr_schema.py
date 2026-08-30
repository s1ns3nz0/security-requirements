#!/usr/bin/env python3
"""Check a design-review report against its published schema (plan §4.2, §10).

`schema/design-review-1.0.0.json` is the contract of record for the report.
This module is what makes it a contract rather than documentation.

**Why not `jsonschema`.** It is not a dependency of this payload. README and
CONTRIBUTING both put the floor at Python 3.12 and PyYAML, and the runtime
executes under `-I`, so a schema validated only by an external library is one
the shipped tool cannot check — and an unenforced schema drifts from the code
it describes, which is the failure §4.2 calls itself a *contract of record* to
avoid. So this implements the subset of JSON Schema the document actually uses.

The subset is deliberately small and deliberately closed. `test_sdr_schema`
pins the keyword list, so a schema growing a keyword this file ignores fails
loudly rather than silently ceasing to be enforced. That test is the reason
this narrowness is safe: the alternative to a subset is not full JSON Schema,
it is a schema nobody checks.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import json
from pathlib import Path


SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schema" / "design-review-1.0.0.json"

#: JSON Schema type names mapped to what they mean in Python. `integer` excludes
#: `bool`, which is an `int` in Python and is never what a schema means by one.
_TYPES: dict[str, object] = {
    "object": Mapping,
    "array": (list, tuple),
    "string": str,
    "boolean": bool,
    "number": (int, float),
    "integer": int,
    "null": type(None),
}


def load_schema(path: Path | None = None) -> dict:
    """Read the published schema.

    From the shipped file rather than a second copy in Python, which would be
    free to drift from the document consumers actually read.
    """

    target = Path(path) if path is not None else SCHEMA_PATH
    return json.loads(target.read_text(encoding="utf-8"))


def _matches_type(value: object, expected: object) -> bool:
    names = expected if isinstance(expected, list) else [expected]
    for name in names:
        python_type = _TYPES.get(name)
        if python_type is None:
            continue
        if name == "integer" and isinstance(value, bool):
            continue
        if name == "number" and isinstance(value, bool):
            continue
        if name == "boolean" and not isinstance(value, bool):
            continue
        if isinstance(value, python_type):
            return True
    return False


def _check(value: object, schema: object, where: str, problems: list[str]) -> None:
    """Append every problem `value` has against `schema`, depth first.

    Every problem carries `where` — a dotted path into the record. "findings is
    invalid" tells a reader nothing they can act on; `findings[3].calculated.score`
    names the field to open.
    """

    if not isinstance(schema, Mapping):
        return

    expected = schema.get("type")
    if expected is not None and not _matches_type(value, expected):
        names = expected if isinstance(expected, list) else [expected]
        problems.append(
            f"{where}: expected {' or '.join(str(n) for n in names)}, "
            f"got {type(value).__name__}"
        )
        # Nothing below can be checked against a value of the wrong shape, and
        # reporting the children too would bury the one problem that matters.
        return

    if "const" in schema and value != schema["const"]:
        problems.append(f"{where}: must be {schema['const']!r}, got {value!r}")

    if "enum" in schema and value not in schema["enum"]:
        allowed = ", ".join(repr(item) for item in schema["enum"])
        problems.append(f"{where}: {value!r} is not one of {allowed}")

    if isinstance(value, Mapping):
        _check_object(value, schema, where, problems)
    elif isinstance(value, (list, tuple)) and "items" in schema:
        for index, item in enumerate(value):
            _check(item, schema["items"], f"{where}[{index}]", problems)


def _check_object(
    value: Mapping, schema: Mapping, where: str, problems: list[str]
) -> None:
    properties = schema.get("properties")
    properties = properties if isinstance(properties, Mapping) else {}

    for name in schema.get("required", []):
        if name not in value:
            problems.append(f"{where or 'report'}: missing required key {name!r}")

    if schema.get("additionalProperties") is False:
        for name in value:
            if name not in properties:
                problems.append(
                    f"{where or 'report'}: unexpected key {name!r}; the schema "
                    "closes this object"
                )

    # Sorted, not document order: §4.3 wants a stable problem list, and a dict
    # built from JSON preserves insertion order that a caller could vary.
    for name in sorted(properties):
        if name in value:
            child = f"{where}.{name}" if where else name
            _check(value[name], properties[name], child, problems)


def validate_report(report: object, schema: object = None) -> list[str]:
    """Return problems with a report, in the house `validate_*` shape.

    Returns and never raises (§10.1), so a caller collects these alongside
    every other problem and decides once whether to write anything.
    """

    if schema is None:
        try:
            schema = load_schema()
        except (OSError, ValueError) as exc:
            return [f"design-review schema could not be read: {exc}"]

    if not isinstance(report, Mapping):
        return [f"report must be an object, got {type(report).__name__}"]

    problems: list[str] = []
    _check(report, schema, "", problems)
    return problems
