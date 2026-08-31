#!/usr/bin/env python3
"""Threat ids: reuse the author's, mint only where none exists (plan F10).

    | F10 | **Reuse** stable threat IDs; mint only in description mode;
    |     | dedupe by `threat_digest`. |

Three jobs, and the first is the one that matters: **an author's id is never
touched.** `T-09` appears in the assessment, in every requirement's
`threat_refs`, and in whatever ticket the team opened against it. Renumbering
it does not rename a threat — it silently repoints every reference to a
different one, or to nothing.

Minting exists for description mode, where a system is described in prose and
no register assigned ids yet. A minted id is **content-addressed**: derived from
the record's material fields, so the same threat gets the same id on every run
and a changed threat gets a different one. A counter would be deterministic and
still wrong — insert one record and every id after it shifts, which is exactly
the renumbering the reuse clause forbids.

F10 says "dedupe by `threat_digest`", and that is loose wording this module does
not follow. `THREAT_DIGEST_FIELDS` opens with `id` (`risk.py:28`), so two
records differing only by id have different digests *by construction*: the
binding digest can never detect the thing F10 asks it to. Deduplication uses
`risk.threat_material_digest`, the same fields with `id` excluded. Plan §11.2
N42 records the correction.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import risk as risk_mod  # noqa: E402


#: Minted ids wear a different prefix from authored ones on purpose. An
#: author's `T-09` was chosen by a person and will not move; a minted id
#: follows its record's content and changes when the content does. Rendering
#: both in one vocabulary tells a reader they can rely on them equally.
MINTED_PREFIX = "TX-"

#: Digest characters in a minted id. Twelve hex characters is 48 bits — far
#: past collision for a register a human reads, and short enough to quote in a
#: sentence without wrapping.
MINTED_DIGEST_LENGTH = 12


def _records(threats: object) -> list:
    """Threat records, tolerating a malformed document."""

    if not isinstance(threats, Mapping):
        return []
    declared = threats.get("threats")
    if not isinstance(declared, Sequence) or isinstance(declared, (str, bytes)):
        return []
    return list(declared)


def _usable_id(record: object) -> str | None:
    """The record's own id, or `None` when it has none worth keeping.

    A non-string id cannot be referenced by anything downstream — `threat_refs`
    is a list of strings and every digest is taken over text — so a record
    carrying one has no usable id rather than a broken one.
    """

    if not isinstance(record, Mapping):
        return None
    record_id = record.get("id")
    if not isinstance(record_id, str) or not record_id.strip():
        return None
    return record_id


def mint_id(threat: object, *, taken: Sequence[str] = ()) -> str:
    """A content-addressed id for a record that has none.

    Derived from the material fields, so it is stable across runs and machines
    and independent of the record's position in the document.

    `taken` is consulted rather than assumed empty: two records that say
    exactly the same thing hash to the same value, and two records are two
    records even when they say the same thing — sharing an id would make one of
    them unreachable. The tie breaks by appending a discriminator rather than
    by falling back to a counter, so the *first* occurrence keeps the id its
    content earns and only the collision moves.
    """

    material = risk_mod.threat_material_digest(
        dict(threat) if isinstance(threat, Mapping) else {}
    )
    # `threat_material_digest` returns `sha256:<hex>`; the prefix carries no
    # information here and would double the length of every id in the register.
    digest = material.split(":", 1)[-1]
    candidate = f"{MINTED_PREFIX}{digest[:MINTED_DIGEST_LENGTH]}"

    unavailable = set(taken)
    if candidate not in unavailable:
        return candidate
    for suffix in range(2, len(digest)):
        # Lengthen rather than counting: the id stays a function of content,
        # and a document with three identical records still produces three ids
        # that any run of that same document reproduces exactly.
        longer = f"{MINTED_PREFIX}{digest[:MINTED_DIGEST_LENGTH]}-{suffix}"
        if longer not in unavailable:
            return longer
    return f"{MINTED_PREFIX}{digest}"


def assign_ids(threats: object) -> dict:
    """The document with every record identified.

    Existing ids are carried through untouched — not renumbered, not
    normalised, not reordered. Only records with no usable id are minted.
    """

    if not isinstance(threats, Mapping):
        return {}

    document = dict(threats)
    records = _records(threats)
    if not records:
        return document

    taken = {
        record_id
        for record_id in (_usable_id(record) for record in records)
        if record_id is not None
    }

    assigned: list = []
    for record in records:
        if not isinstance(record, Mapping):
            # Not a record. Reported by `_validate_threats`, which owns that
            # message; passing it through unchanged keeps one reporter.
            assigned.append(record)
            continue
        if _usable_id(record) is not None:
            assigned.append(dict(record))
            continue
        minted = mint_id(record, taken=tuple(sorted(taken)))
        taken.add(minted)
        assigned.append({**record, "id": minted})

    document["threats"] = assigned
    return document


def duplicate_pairs(threats: object) -> list[tuple[str, str]]:
    """Records that say the same thing under two ids.

    A public name for `risk._duplicate_threat_pairs`, which already implements
    this and is already called by `aggregate_risk`. The first version of this
    module reimplemented it — same material digest, same active-only rule,
    same ordering — and a mutation test caught the redundancy: removing the
    second copy's call changed nothing, because the first copy was doing the
    work. Two implementations of one rule agree on the day they are written and
    diverge on the day one of them is fixed.

    Kept as a name rather than dropped because F10 names deduplication as part
    of this module's job, and a reader looking for it here should find it
    rather than conclude it does not exist.

    By material digest, never by `threat_digest`: the binding digest opens with
    `id`, so two records differing only by id have different digests by
    construction (plan §11.2 N42).
    """

    return risk_mod._duplicate_threat_pairs(_records(threats))
