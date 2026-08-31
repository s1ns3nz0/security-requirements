"""F10 — reuse author ids, mint only where none exists, dedupe by material.

Plan of record: `docs/design-review/security-design-review-plan.md` F10, §4.2
("Finding IDs are the existing stable threat IDs … Minting applies only to
description mode, where no ID exists yet"), §11.2 N42, and §4.3.

Pinned contract under specification. `scripts/sdr_ids.py` does **not** exist, so
every test that reaches it is RED by construction and fails by *name*:

    mint_id(threat, *, taken=()) -> str
    assign_ids(threats) -> dict
    duplicate_pairs(threats) -> list[tuple[str, str]]

Three properties carry this file, and each is worth more than the shapes.

**An author's id is never touched.** `T-09` appears in the assessment, in every
requirement's `threat_refs`, and in whatever ticket the team opened. Renumbering
it does not rename a threat; it silently repoints every reference to a different
one — or to nothing. So the strongest test here is a negative: run the assigner
over a fully-identified document and assert it changed nothing at all.

**Minting is content-addressed, not sequential.** A counter satisfies "the same
document yields the same ids" and fails the moment two runs see the records in
a different order, or one record is inserted ahead of another. The property
that matters is that an id follows its *content*: the same threat gets the same
id wherever it appears, and a changed threat gets a different one. Both halves
are asserted; determinism alone would pass for a counter.

**Deduplication cannot use `threat_digest`.** Its first member is `id`
(`risk.py:28`), so two records differing only by id have different digests *by
construction* — it can never detect the thing F10 asks it to detect. §11.2 N42
records that correction. One test below asserts `threat_digest` fails on the
duplicate pair, so a future implementation that reached for the obvious helper
is caught rather than silently detecting nothing.
"""

from __future__ import annotations

import copy
from pathlib import Path
import sys

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
PLUGIN_ROOT = REPO_ROOT / "plugins" / "security-requirements"
PLUGIN_SCRIPTS = PLUGIN_ROOT / "scripts"
if str(PLUGIN_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(PLUGIN_SCRIPTS))

import risk as risk_mod  # noqa: E402

IDS_MODULE_PATH = PLUGIN_SCRIPTS / "sdr_ids.py"


def _sdr_ids():
    try:
        import sdr_ids
    except ImportError as exc:  # pragma: no cover - the RED path
        pytest.fail(
            f"{IDS_MODULE_PATH} does not exist yet. §10 lists it as NEW and F10 "
            "gives it three jobs: carry an author's id unchanged, mint a "
            "content-addressed id where none exists, and report records that "
            f"say the same thing under two ids. import failed: {exc}"
        )
    return sdr_ids


def _attr(name: str):
    module = _sdr_ids()
    value = getattr(module, name, None)
    assert callable(value), (
        f"`sdr_ids.{name}` is part of the pinned F10 contract; found {value!r}"
    )
    return value


# ---------------------------------------------------------------------------
# Records. Every material field is populated, because a digest over mostly
# empty records would collide for reasons that have nothing to do with the
# rule under test.
# ---------------------------------------------------------------------------


def _threat(threat_id: str | None = None, **overrides) -> dict:
    record = {
        "risk_family": "RF-checkout",
        "category": "STRIDE:T",
        "novelty": "service_specific",
        "persona": "anonymous_external",
        "attack_path": "unauthenticated_write_across_boundary",
        "scenario": "Anonymous caller POSTs /orders/{id} and alters line items.",
        "affected_assets": ["order_records"],
        "related_controls": ["AC-3"],
        "boundary": "tb-internet",
        "lifecycle": {"status": "active", "superseded_by": []},
    }
    if threat_id is not None:
        record["id"] = threat_id
    record.update(overrides)
    return record


def _document(*threats: dict) -> dict:
    return {"version": "0.2.0", "profile": "checkout", "threats": list(threats)}


def _ids_of(document: dict) -> list[str]:
    return [record.get("id") for record in document.get("threats", [])]


# ---------------------------------------------------------------------------
# F10's first clause: reuse. The negative that matters most.
# ---------------------------------------------------------------------------


def test_a_document_whose_records_all_carry_ids_is_returned_unchanged():
    """The strongest statement of "reuse": nothing moved.

    `T-09` appears in the assessment, in every requirement's `threat_refs`, and
    in whatever ticket the team opened against it. Renumbering does not rename a
    threat — it repoints every reference to a different one, or to nothing.
    """

    document = _document(_threat("T-01"), _threat("T-02", scenario="Second."))
    before = copy.deepcopy(document)

    assigned = _attr("assign_ids")(document)

    assert assigned == before, (
        "a fully identified document has nothing to mint, so the assigner is a "
        f"no-op over it.\nbefore: {before}\nafter:  {assigned}"
    )


def test_an_author_id_is_carried_unchanged_even_beside_a_minted_one():
    document = _document(_threat("T-09"), _threat(None, scenario="No id here."))

    assigned = _attr("assign_ids")(document)

    assert _ids_of(assigned)[0] == "T-09", (
        "minting a neighbour must not disturb an author's id; got "
        f"{_ids_of(assigned)}"
    )


def test_an_unusual_author_id_is_not_normalised():
    """Not renumbered, not reformatted, not lower-cased."""

    document = _document(_threat("threat/2024-11 · checkout"))

    assigned = _attr("assign_ids")(document)

    assert _ids_of(assigned) == ["threat/2024-11 · checkout"], (
        "an id is an opaque key the author chose, and rewriting it to match a "
        f"house style breaks every reference to it; got {_ids_of(assigned)}"
    )


def test_assign_ids_does_not_mutate_the_document_it_is_given():
    document = _document(_threat("T-01"), _threat(None))
    before = copy.deepcopy(document)

    _attr("assign_ids")(document)

    assert document == before, (
        "the caller's document is an input. Mutating it leaves a later stage "
        "digesting a record the caller never wrote"
    )


def test_record_order_is_preserved():
    document = _document(
        _threat("T-03", scenario="Third."),
        _threat("T-01", scenario="First."),
        _threat("T-02", scenario="Second."),
    )

    assigned = _attr("assign_ids")(document)

    assert _ids_of(assigned) == ["T-03", "T-01", "T-02"], (
        "§4.3 puts ordering in one place and this is not it. Sorting here would "
        f"give the register a second opinion about sequence; got {_ids_of(assigned)}"
    )


# ---------------------------------------------------------------------------
# F10's second clause: minting, in description mode only.
# ---------------------------------------------------------------------------


def test_a_record_with_no_id_is_given_one():
    document = _document(_threat(None))

    assigned = _attr("assign_ids")(document)

    minted = _ids_of(assigned)[0]
    assert isinstance(minted, str) and minted.strip(), (
        f"a record with no id is unusable downstream; got {minted!r}"
    )


def test_a_minted_id_is_visibly_distinct_from_an_author_id():
    """A reader must be able to tell which ids are stable.

    An author's id was chosen by a person and will not move. A minted one
    follows its record's content and changes when the content does. Rendering
    them in the same vocabulary tells a reader they can rely on both equally,
    and they cannot.
    """

    document = _document(_threat("T-09"), _threat(None, scenario="Unidentified."))

    assigned = _attr("assign_ids")(document)
    author_id, minted = _ids_of(assigned)

    assert minted != author_id
    assert not minted.startswith("T-0"), (
        "a minted id must not imitate the author's sequential form, or nobody "
        f"can tell a stable id from a derived one; minted {minted!r}"
    )


def test_the_same_content_mints_the_same_id_across_two_documents():
    """Content-addressed, not sequential. A counter fails this."""

    first = _attr("assign_ids")(_document(_threat(None)))
    second = _attr("assign_ids")(_document(_threat(None)))

    assert _ids_of(first) == _ids_of(second), (
        "the same described system reviewed twice must produce the same ids, or "
        "a reader cannot compare two runs and every finding looks new.\n"
        f"first: {_ids_of(first)}\nsecond: {_ids_of(second)}"
    )


def test_a_changed_record_mints_a_different_id():
    """The other half. Determinism alone is satisfied by a constant."""

    first = _attr("assign_ids")(_document(_threat(None)))
    second = _attr("assign_ids")(
        _document(_threat(None, scenario="A materially different threat."))
    )

    assert _ids_of(first) != _ids_of(second), (
        "two different threats sharing an id would merge them in every "
        f"downstream reference; both minted {_ids_of(first)}"
    )


def test_position_in_the_document_does_not_change_a_minted_id():
    """A counter passes the determinism test above and fails this one."""

    alone = _attr("assign_ids")(_document(_threat(None)))
    trailing = _attr("assign_ids")(
        _document(_threat("T-01"), _threat("T-02", scenario="Other."), _threat(None))
    )

    assert _ids_of(alone)[0] == _ids_of(trailing)[-1], (
        "an id follows its record's content, not its index. Otherwise inserting "
        "a threat renumbers every one after it, which is the failure F10's "
        f"'reuse' clause exists to prevent; got {_ids_of(alone)} and "
        f"{_ids_of(trailing)}"
    )


def test_a_mint_never_collides_with_an_id_already_in_the_document():
    unidentified = _threat(None)
    predicted = _attr("mint_id")(unidentified)

    document = _document(_threat(predicted), copy.deepcopy(unidentified))
    assigned = _attr("assign_ids")(document)

    ids = _ids_of(assigned)
    assert len(ids) == len(set(ids)), (
        "a mint that lands on an id already in use merges two threats into one "
        f"reference; got {ids}"
    )


def test_two_identical_unidentified_records_do_not_receive_the_same_id():
    """Content-addressing collides here by construction; the tie must break."""

    document = _document(_threat(None), _threat(None))

    ids = _ids_of(_attr("assign_ids")(document))

    assert len(ids) == len(set(ids)), (
        "two records are two records even when they say the same thing. Sharing "
        f"an id makes one of them unreachable; got {ids}"
    )


def test_mint_id_avoids_everything_in_taken():
    threat = _threat(None)
    natural = _attr("mint_id")(threat)

    avoided = _attr("mint_id")(threat, taken=(natural,))

    assert avoided != natural, (
        f"`taken` names ids already in use and a mint must avoid them; got "
        f"{avoided!r} against taken={(natural,)!r}"
    )


# ---------------------------------------------------------------------------
# F10's third clause: dedupe — and the digest it cannot use.
# ---------------------------------------------------------------------------


def test_two_records_differing_only_by_id_are_reported_as_duplicates():
    document = _document(_threat("T-01"), _threat("T-02"))

    pairs = _attr("duplicate_pairs")(document)

    assert pairs, (
        "these two records say the same thing under two ids. Scoring both "
        "inflates the register, and an inflated register reads as assessed, so "
        "nobody goes looking"
    )
    flattened = {item for pair in pairs for item in pair}
    assert {"T-01", "T-02"} <= flattened, (
        f"the report must name both ids so the author knows what to merge; got {pairs}"
    )


def test_the_binding_digest_cannot_detect_that_duplicate():
    """§11.2 N42, asserted rather than restated.

    `THREAT_DIGEST_FIELDS` opens with `id`, so two records differing only by id
    have different digests by construction. A dedupe built on the obvious
    helper would run, report nothing, and look correct.
    """

    first, second = _threat("T-01"), _threat("T-02")

    assert risk_mod.THREAT_DIGEST_FIELDS[0] == "id", (
        "this test rests on `id` being part of the binding digest; the fields "
        f"are {risk_mod.THREAT_DIGEST_FIELDS}"
    )
    assert risk_mod.threat_digest(first) != risk_mod.threat_digest(second), (
        "if the binding digest ever stopped covering `id`, deduplication could "
        "use it and this file's premise would be wrong"
    )
    assert risk_mod.threat_material_digest(first) == risk_mod.threat_material_digest(
        second
    ), (
        "the material digest excludes `id` and is what deduplication needs; if "
        "these differ, `MATERIAL_THREAT_FIELDS` no longer describes the same "
        "threat"
    )


def test_records_that_differ_materially_are_not_duplicates():
    document = _document(_threat("T-01"), _threat("T-02", scenario="Different."))

    pairs = _attr("duplicate_pairs")(document)

    assert pairs == [], (
        "two genuinely different threats must not be merged; a false duplicate "
        f"deletes a finding. got {pairs}"
    )


def test_a_superseded_record_is_not_a_duplicate_of_the_one_that_replaced_it():
    """Supersede legitimately produces two near-identical records.

    `risk._duplicate_threat_pairs` already skips non-active records for exactly
    this reason. Reporting the pair would make every supersede generate a
    permanent complaint the author can only silence by deleting history.
    """

    retired = _threat("T-01", lifecycle={"status": "superseded", "superseded_by": ["T-02"]})
    document = _document(retired, _threat("T-02"))

    pairs = _attr("duplicate_pairs")(document)

    assert pairs == [], (
        f"a superseded record and its replacement are one threat over time; got {pairs}"
    )


def test_duplicate_pairs_is_stable_across_two_calls():
    document = _document(_threat("T-01"), _threat("T-02"))

    assert _attr("duplicate_pairs")(document) == _attr("duplicate_pairs")(document), (
        "§4.3: no set iteration reaches output"
    )


# ---------------------------------------------------------------------------
# Malformed input is reported or ignored, never raised.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "document",
    [None, {}, {"threats": None}, {"threats": "not-a-list"}, {"threats": ["not-a-record"]}],
)
def test_neither_entry_point_raises_on_a_malformed_document(document):
    for name in ("assign_ids", "duplicate_pairs"):
        try:
            _attr(name)(document)
        except Exception as exc:  # noqa: BLE001 - the point of the test
            pytest.fail(
                f"`{name}` follows the house convention of tolerating a "
                f"malformed document rather than raising; {document!r} raised {exc!r}"
            )


def test_a_record_whose_id_is_not_a_string_is_treated_as_unidentified():
    document = _document(_threat(None, id=42))

    assigned = _attr("assign_ids")(document)

    minted = _ids_of(assigned)[0]
    assert isinstance(minted, str), (
        "an id that is not a string cannot be referenced by anything "
        f"downstream, so the record has no usable id and gets one; got {minted!r}"
    )
