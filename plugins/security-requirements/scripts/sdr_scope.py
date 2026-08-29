#!/usr/bin/env python3
"""Review scope: which modelled elements a run covers (plan F5, N32).

`--scope` narrows a review to a subset of *modelled components*. It is not an
evidence selector (plan §3): the operator names a component id, not a path or a
glob, and the run records both what that included and what it left out.

Recording both sides is the point. A narrowed review whose report lists only
what it covered reads exactly like a complete one, and the reader has no way to
tell three components reviewed from three components modelled. `excluded` is
what makes the limitation visible.

The matching rule is exact and deliberately dumb. A glob or a prefix would make
`--scope cmp-*` silently select everything, which is §8's "never silently review
everything" wearing different clothes — the operator believes they narrowed and
got the whole model.

Plan note: the §4.2 *example* spells the scope record with path globs
(`"included": ["services/checkout/**"]`), which contradicts §3 and §8 — both
make `--scope` a filter over component ids and make the failure message a list
of component ids. The normative prose wins; the example is illustrative filler.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import risk as risk_mod  # noqa: E402


#: Every kind of record an architecture holds, in the order they are reported.
#: Fixed order rather than `dict` iteration so the record is byte-stable (§4.3).
ARCHITECTURE_KINDS = (
    "actors",
    "components",
    "data_stores",
    "data_flows",
    "trust_boundaries",
)


def _records(architecture: object, kind: str) -> list[dict]:
    """Records of one kind, tolerating a missing or malformed architecture."""

    if not isinstance(architecture, Mapping):
        return []
    entries = architecture.get(kind)
    if not isinstance(entries, Sequence) or isinstance(entries, (str, bytes)):
        return []
    return [entry for entry in entries if isinstance(entry, Mapping)]


def _ids(architecture: object, kind: str) -> list[str]:
    """Ids of one kind, in document order, without repeats."""

    seen: set[str] = set()
    ordered: list[str] = []
    for record in _records(architecture, kind):
        record_id = record.get("id")
        if isinstance(record_id, str) and record_id and record_id not in seen:
            seen.add(record_id)
            ordered.append(record_id)
    return ordered


def _all_ids(architecture: object) -> list[str]:
    """Every modelled id, kind by kind, in document order."""

    seen: set[str] = set()
    ordered: list[str] = []
    for kind in ARCHITECTURE_KINDS:
        for record_id in _ids(architecture, kind):
            if record_id not in seen:
                seen.add(record_id)
                ordered.append(record_id)
    return ordered


def _selected_ids(architecture: object, scope: str | None) -> set[str]:
    """The ids a scope filter reaches, or every id when there is no filter.

    A component alone is not reviewable: a component without its flows has no
    threats to find. So a matched component pulls in the flows that touch it,
    the elements at the far end of those flows, and the boundaries they cross.

    Reachability is deliberately one hop. Two hops would walk the whole
    connected graph and hand back the full model under a scope flag — silent
    widening again.
    """

    if scope is None:
        return set(_all_ids(architecture))

    if not risk_mod._nonempty_text(scope):
        return set()

    seeds = {
        record["id"]
        for record in _records(architecture, "components")
        if record.get("id") == scope
    }
    if not seeds:
        # No match. Empty rather than everything: `scope_problems` reports it,
        # and a run that reviews nothing is at least honestly empty.
        return set()

    selected = set(seeds)
    for record in _records(architecture, "components"):
        if record.get("id") not in seeds:
            continue
        boundary = record.get("trust_boundary")
        if isinstance(boundary, str) and boundary:
            selected.add(boundary)

    # Reads `seeds`, not `selected`, so a boundary pulled in above cannot itself
    # pull in every flow that crosses it.
    for record in _records(architecture, "data_flows"):
        if record.get("from") not in seeds and record.get("to") not in seeds:
            continue
        for key in ("id", "from", "to", "crosses"):
            value = record.get(key)
            if isinstance(value, str) and value:
                selected.add(value)

    return selected


def resolve_scope(architecture: object, scope: str | None) -> dict:
    """The plan §4.2 `run.scope` record: what was reviewed, what was not.

    Both sides are ordered lists filtered from the modelled ids, so they
    partition the model exactly — no id on both sides, none on neither, and no
    set iteration reaching output (§4.3).
    """

    selected = _selected_ids(architecture, scope)
    included: list[str] = []
    excluded: list[str] = []
    for record_id in _all_ids(architecture):
        (included if record_id in selected else excluded).append(record_id)
    return {
        "included": included,
        "excluded": excluded,
        # Verbatim, so the report can quote what the operator actually asked for
        # — including on the failing path, where the suppressed run has to stay
        # explainable after the fact.
        "scope_filter": scope,
    }


def scope_problems(architecture: object, scope: str | None) -> list[str]:
    """Return problems with the scope filter, in the house `validate_*` shape.

    Returns rather than raises (plan §10.1) so the caller collects this
    alongside every other problem and exits once.
    """

    if scope is None:
        return []
    if not isinstance(scope, str) or not risk_mod._nonempty_text(scope):
        return [
            f"--scope {scope!r} is empty; omit --scope to review the whole model"
        ]

    known = _ids(architecture, "components")
    if scope in known:
        return []

    # §8 requires the ids themselves, not a count. "3 known components" gives
    # the operator nothing to act on; the list lets them fix a typo from the
    # message alone.
    if known:
        return [
            f"--scope {scope!r} matches no modelled component. "
            f"Known component ids: {', '.join(known)}"
        ]
    return [
        f"--scope {scope!r} matches no modelled component; "
        "the architecture models no components"
    ]
