#!/usr/bin/env python3
"""The §4.2 JSON report record, assembled.

Pure: this module reads documents and returns a mapping. It opens no file,
writes nothing, and reads no clock — `today` and the invocation timestamp are
injected, because §4.3 and N39 both turn on two identical runs producing an
identical digest.

It also derives almost nothing. `calculate_inherent`, `cia_scores`,
`aggregate_risk`, `derive_risk_links` and `order_requirements` already own the
arithmetic and the ordering; this module carries their output rather than
recomputing it. A second derivation is a second opinion, and the two drift.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import copy
import re
from datetime import date
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import risk as risk_mod  # noqa: E402
import sdr_architecture  # noqa: E402
import sdr_attack_paths  # noqa: E402
import sdr_scope  # noqa: E402


#: §4.2 line 181. The *report's* version, distinct from a document's `version`
#: — the two are different artifacts and conflating them would make a document
#: schema change look like a report schema change.
SCHEMA_VERSION = "1.0.0"

#: The keys `calculate_inherent` returns, and the only keys `calculated` may
#: carry. `risk_helpers._golden_report` compares a stored block against the
#: engine result by exact equality, so an extra key breaks R2.
CALCULATED_KEYS = ("likelihood", "impact", "score", "rating")

#: F14 — the verdict states a threshold comparison and never an approval.
#: Re-exported from `risk` so the published summary and this report cannot
#: drift apart on the sentence that matters most.
NEVER_ASSERT_SECURE = risk_mod.NEVER_ASSERT_SECURE


#: Prose shaped like an instruction aimed at the reviewer rather than a
#: description of the system. Repository content is data, and a sentence in it
#: telling the reviewer what to conclude is an attempt to be obeyed.
#:
#: Policy-as-data, like `risk.KEY_MATERIAL_PATTERNS`, and matched on the
#: *shape* of an instruction rather than on any fixture's wording — a list of
#: known-bad sentences only catches the attacker who copied one.
#:
#: Deliberately narrow. This decides what gets quoted rather than paraphrased,
#: so a false positive costs a reader one labelled block; the alternative
#: failure is the review reproducing attacker prose in its own voice.
INSTRUCTION_PATTERNS: tuple[tuple[str, object], ...] = (
    (
        "an instruction to disregard prior direction",
        re.compile(r"\bignore\s+(?:all\s+|any\s+)?previous\s+instructions?\b", re.I),
    ),
    (
        "an instruction to lower or waive findings",
        re.compile(
            r"\b(?:score|rate|report|mark)\b[^.]{0,60}?"
            r"\b(?:all|every)\b[^.]{0,40}?\b(?:low|accepted|safe|no\s+risk)\b",
            re.I,
        ),
    ),
    (
        "an instruction addressed to the reviewing agent",
        re.compile(r"\byou\s+(?:must|should|will)\s+(?:not\s+)?report\b", re.I),
    ),
)

#: What a redacted instruction is replaced with in the review's own prose. The
#: text still reaches the reader — verbatim, once, inside the labelled block —
#: but never in a position where it reads as the analyst's own sentence.
REDACTION_NOTICE = "[untrusted content removed — see Untrusted content]"


def untrusted_content(value: object, location: str = "") -> list[dict]:
    """Instruction-shaped prose found in repository-sourced text.

    Returns `{location, quoted, why}` records. Reported rather than obeyed, and
    reported *verbatim*: a reviewer deciding whether this matters needs to read
    what was actually written, not a summary of it.
    """

    found: list[dict] = []
    if not isinstance(value, str):
        return found
    for why, pattern in INSTRUCTION_PATTERNS:
        for match in pattern.finditer(value):
            sentence = _enclosing_sentence(value, match.start(), match.end())
            record = {"location": location, "quoted": sentence, "why": why}
            if record not in found:
                found.append(record)
    return found


def _enclosing_sentence(text: str, start: int, end: int) -> str:
    """The whole sentence a match sits in, so the quote is not a fragment."""

    left = max(text.rfind(".", 0, start), text.rfind("\n", 0, start))
    right = text.find(".", end)
    right = len(text) if right == -1 else right + 1
    return text[left + 1 : right].strip()


def redact_instructions(value: object) -> object:
    """Replace instruction-shaped sentences with a pointer to the quoted block.

    The review must not reproduce attacker prose in its own voice. A reader
    scanning a scenario cannot tell a sentence the analyst wrote from one the
    repository supplied, and the whole point of the injection is to be read as
    the former.
    """

    if not isinstance(value, str):
        return value
    redacted = value
    for _why, pattern in INSTRUCTION_PATTERNS:
        for match in reversed(list(pattern.finditer(redacted))):
            sentence = _enclosing_sentence(redacted, match.start(), match.end())
            if sentence:
                redacted = redacted.replace(sentence, REDACTION_NOTICE)
    return redacted


def _mapping(value: object) -> dict:
    return dict(value) if isinstance(value, Mapping) else {}


def _sequence(value: object) -> list:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return []
    return list(value)


def _document(documents: object, name: str) -> object:
    if not isinstance(documents, Mapping):
        return None
    return documents.get(name)


def report_problems(
    documents: object,
    *,
    scope: str | None = None,
    policy: object = None,
    today: date | None = None,
) -> list[str]:
    """Every problem with the inputs, in the house `validate_*` shape.

    Returns and never raises (§10.1), so the runner collects these alongside
    the evidence problems and decides once whether anything may be rendered.
    Each underlying validator already reports its own domain; this only
    gathers them, in a fixed order so the list is stable (§4.3).
    """

    problems: list[str] = []
    threats = _document(documents, "threats")
    assessment = _document(documents, "assessment")
    architecture = _document(documents, "architecture")

    if architecture is not None:
        problems.extend(sdr_architecture.validate_architecture(architecture))
    problems.extend(
        sdr_architecture.unknown_architecture_refs(threats, architecture)
    )
    if scope is not None:
        problems.extend(sdr_scope.scope_problems(architecture, scope))

    if isinstance(policy, Mapping):
        try:
            problems.extend(
                risk_mod.validate_assessment(threats, assessment, dict(policy), today)
            )
        except (risk_mod.RiskValidationError, TypeError, AttributeError):
            # A document too malformed to validate is already reported by the
            # validators above. Reporting it twice, in two vocabularies, makes
            # one fault look like two.
            pass

    # Deduplicated, order preserved: two validators can legitimately notice the
    # same missing id, and a reader should see it once.
    return list(dict.fromkeys(problems))


def _finding(
    threat: Mapping,
    record: Mapping,
    *,
    policy: dict,
    requirements: object,
    assessment: object,
    threats: object,
    evidence: object,
    attack_paths: object,
    today: date | None,
) -> dict:
    """One §4.2 finding: the threat, its calculation, and what it demands."""

    threat_id = threat.get("id")
    finding: dict = {
        # The existing author-assigned id, carried unchanged. Minting belongs to
        # description mode, where no id exists yet.
        "id": threat_id,
        "threat": {
            "stride": threat.get("category"),
            "normalized": threat.get("attack_path"),
            "title": redact_instructions(threat.get("scenario")),
        },
        "target": {
            "kind": "trust_boundary" if threat.get("boundary") else None,
            "ref": threat.get("boundary"),
        },
        "scenario": redact_instructions(threat.get("scenario")),
        "threat_digest": risk_mod.threat_digest(dict(threat)),
        "status": record.get("status"),
        "evidence_status": threat.get("evidence_status"),
        "confidence": threat.get("confidence"),
    }

    proposed = record.get("proposed")
    if isinstance(proposed, Mapping):
        finding["proposed"] = dict(proposed)

    # Carried from the assessment record, not re-derived. Without these the
    # register's Owner, Treatment, Acceptance and Expiry rows print
    # "not recorded" for every finding even when the assessment holds a valid
    # accepted risk — so a reader of the sensitive report cannot see that a
    # risk was accepted, by whom, or when the acceptance lapses. Each of the
    # four is also named in §4.1 as having crossed the publish boundary once,
    # which is only testable once they reach an artifact at all.
    for carried in ("treatment", "residual", "owner"):
        value = record.get(carried)
        if value is not None:
            finding[carried] = copy.deepcopy(value)

    calculated = record.get("calculated")
    if isinstance(calculated, Mapping):
        # Verbatim, and narrowed to the four engine keys. Anything else the
        # record happens to carry is not part of the calculation R2 compares.
        finding["calculated"] = {
            key: calculated[key] for key in CALCULATED_KEYS if key in calculated
        }
    if isinstance(proposed, Mapping):
        # A sibling of `calculated`, never a member — §4.2 is explicit, and
        # nesting it breaks every fixture that records a calculation.
        finding["cia"] = risk_mod.cia_scores(policy, dict(proposed))

    path_ids = sdr_attack_paths.attack_path_ids(attack_paths, threat_id)
    if path_ids:
        finding["attack_path_ids"] = path_ids

    requirement = _requirement_for(requirements, threat_id)
    if requirement is not None:
        finding["requirement"] = requirement
        supporting = _evidence_for(evidence, requirement.get("id"))
        if supporting:
            finding["evidence"] = supporting
        links = risk_mod.derive_risk_links(
            [threat_id], _mapping(assessment), _mapping(threats), today=today
        )
        finding["risk_exposure"] = links.get("risk_exposure")
    return finding


def _evidence_for(evidence: object, requirement_id: object) -> list[dict]:
    """§4.2 `findings[].evidence` — what shows this finding is real.

    Projected to `{kind, location, excerpt}` and nothing else. The stored
    record carries a digest, an observer, an expiry and a requirement digest
    besides; a report that copied the whole record would put four more fields
    on the sensitive/publishable seam, and §4.1 already lists five that crossed
    it. A projection is a smaller thing to keep on the right side of a boundary
    than a filter.

    Linked through the requirement, which is how the evidence document
    addresses its subject: an evidence record names `requirement_id`, never a
    threat. A finding without a requirement has nothing to link through and
    carries no evidence, rather than carrying all of it.
    """

    if not _nonempty(requirement_id):
        return []
    supporting: list[dict] = []
    for record in _sequence(_mapping(evidence).get("evidence")):
        if not isinstance(record, Mapping):
            continue
        if record.get("requirement_id") != requirement_id:
            continue
        artifact = _mapping(record.get("artifact"))
        projected = {
            "kind": artifact.get("kind"),
            "location": artifact.get("location"),
        }
        excerpt = artifact.get("excerpt")
        if excerpt is not None:
            projected["excerpt"] = excerpt
        supporting.append(projected)
    return supporting


def _nonempty(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def order_findings(findings: Sequence) -> list[dict]:
    """§4.3 — rating rank, then score descending, then id.

    The one place findings are ordered. `render_register` used to sort by id,
    which made a run publish two orders: document order in the JSON and id
    order in the markdown. It no longer sorts, so this is the order both
    artifacts carry, and "the top finding" means the same thing in either.

    A finding with no rating sorts last rather than first. An unscored record
    is not the most severe thing in the report, and putting it at the top is
    the reading a hurried reviewer would act on.
    """

    def key(finding: object) -> tuple:
        record = _mapping(finding)
        calculated = _mapping(record.get("calculated"))
        rating = calculated.get("rating")
        rank = (
            risk_mod.RATINGS.index(rating)
            if rating in risk_mod.RATINGS
            else len(risk_mod.RATINGS)
        )
        score = calculated.get("score")
        score = score if isinstance(score, int) and not isinstance(score, bool) else -1
        # Negated so a higher score sorts earlier under an ascending sort.
        return (rank, -score, str(record.get("id") or ""))

    return sorted((_mapping(finding) for finding in findings), key=key)


def _requirement_for(requirements: object, threat_id: object) -> dict | None:
    """The first requirement tracing to this threat, in ordered order.

    Ordering goes through `order_requirements`, the §4.3 single choke point.
    This module sorts nothing itself.
    """

    declared = _sequence(_mapping(requirements).get("requirements"))
    if not declared:
        return None
    try:
        ordered = risk_mod.order_requirements(declared)
    except risk_mod.RiskValidationError:
        return None
    for requirement in ordered:
        if not isinstance(requirement, Mapping):
            continue
        if threat_id in _sequence(requirement.get("threat_refs")):
            return dict(requirement)
    return None


def _verdict(threats: object, assessment: object, policy: dict, today) -> dict:
    """The threshold comparison, and the sentence that must never overclaim."""

    inherent = risk_mod.aggregate_risk(
        _mapping(threats), _mapping(assessment), today=today
    )
    threshold = policy.get("release_threshold_rating")

    overall = inherent.get("overall")
    exceeds = False
    if overall in risk_mod.RATINGS and threshold in risk_mod.RATINGS:
        # RATINGS is ordered most-severe-first, so a lower index is worse.
        exceeds = risk_mod.RATINGS.index(overall) <= risk_mod.RATINGS.index(threshold)

    counts = _mapping(inherent.get("counts"))
    at_or_above = 0
    if threshold in risk_mod.RATINGS:
        limit = risk_mod.RATINGS.index(threshold)
        at_or_above = sum(
            int(counts.get(rating, 0) or 0)
            for rating in risk_mod.RATINGS[: limit + 1]
        )

    # "Nothing was modelled" and "nothing was found" are different facts and a
    # count of zero renders them alike. `0 finding(s) at or above the release
    # threshold` is the sentence a thoroughly-reviewed clean service gets, and
    # a reader has no way to tell it from a review that had nothing to look at.
    # The distinction lives in `overall`/`coverage`, which reach only the JSON,
    # and an unconfirmed run never writes the JSON — so it has to be said here.
    if overall == "UNDETERMINED" or inherent.get("coverage") == "0/0":
        statement = (
            "No threats are modelled, so nothing was assessed and the overall "
            f"rating is UNDETERMINED (coverage {inherent.get('coverage')}). "
            "This is not a finding of low risk. "
            f"{NEVER_ASSERT_SECURE}"
        )
    else:
        statement = (
            f"{at_or_above} finding(s) at or above the release threshold "
            f"({threshold}). {NEVER_ASSERT_SECURE}"
        )

    return {
        "release_threshold_rating": threshold,
        "exceeds_threshold": exceeds,
        "inherent": inherent,
        "statement": statement,
    }


def _limitations(
    entry: Mapping, scope_record: Mapping, inherent: Mapping | None = None
) -> list[str]:
    """What the run could not see, stated rather than left to inference."""

    limitations = [
        "Static, local, read-only analysis. "
        "No execution, probing, or network access.",
    ]
    # First, because it governs how everything below it should be read. The
    # generic disclaimer above appears on every run and cannot carry this
    # meaning: a reader who skims sees a limitations list either way.
    if isinstance(inherent, Mapping) and inherent.get("coverage") == "0/0":
        limitations.insert(
            0,
            "No threats are modelled, so this review assessed nothing. "
            "Run /sec-req-build to produce a threat model before reading "
            "anything below as coverage.",
        )
    excluded = _sequence(scope_record.get("excluded"))
    if excluded:
        limitations.append(
            f"{len(excluded)} modelled element(s) were outside "
            f"`--scope {scope_record.get('scope_filter')}` and were not reviewed: "
            + ", ".join(str(item) for item in excluded)
        )
    profile = _mapping(_mapping(entry.get("run")).get("profile"))
    unconfirmed = _sequence(profile.get("unconfirmed_critical_facts"))
    if unconfirmed:
        limitations.append(
            "Profile was not confirmed; these critical facts were inferred: "
            + ", ".join(str(fact) for fact in unconfirmed)
        )
    if profile.get("stale_vs_head") is True:
        limitations.append(
            "profile.yaml is older than the current branch head, so the model "
            "may not describe the code that was reviewed."
        )
    return limitations


def build_report(
    documents: object,
    *,
    entry: object,
    scope_record: object,
    confirmation: object = None,
    risk_appetite: str | None = None,
    invocation: object = None,
    today: date | None = None,
) -> dict:
    """Assemble the §4.2 record.

    Reads its inputs and copies what it takes, so a caller's documents are the
    same objects afterwards — a later stage scoring a silently mutated
    document is the failure this avoids.
    """

    policy = _mapping(_document(documents, "policy"))
    threats = _document(documents, "threats")
    assessment = _document(documents, "assessment")
    requirements = _document(documents, "requirements")
    architecture = _mapping(_document(documents, "architecture"))
    attack_paths = _document(documents, "attack_paths")

    entry_run = _mapping(_mapping(entry).get("run"))
    scope_block = dict(_mapping(scope_record))
    invocation_block = _mapping(invocation)

    records = {
        record.get("threat_id"): record
        for record in _sequence(_mapping(assessment).get("assessments"))
        if isinstance(record, Mapping)
    }

    findings = []
    for threat in risk_mod.active_threats(threats):
        record = records.get(threat.get("id"))
        if record is None:
            continue
        findings.append(
            _finding(
                threat,
                record,
                policy=policy,
                requirements=requirements,
                assessment=assessment,
                threats=threats,
                evidence=_document(documents, "evidence"),
                attack_paths=attack_paths,
                today=today,
            )
        )

    # §4.3's single ordering choke point for findings. Applied here so both
    # the JSON and the rendered register carry the same order.
    findings = order_findings(findings)

    # Collected from the *unredacted* model, because the findings above now
    # carry the pointer rather than the prose. Reported, never obeyed.
    quoted: list[dict] = [
        record
        for record in _sequence(
            invocation_block.get("repository_untrusted_content")
        )
        if isinstance(record, Mapping)
    ]
    for threat in risk_mod.active_threats(threats):
        for field in ("scenario", "attack_path"):
            for record in untrusted_content(
                threat.get(field), f"threats.yaml:{threat.get('id')}.{field}"
            ):
                if record not in quoted:
                    quoted.append(record)
    for index, assumption in enumerate(_sequence(architecture.get("assumptions"))):
        for record in untrusted_content(
            assumption, f"architecture.yaml:assumptions[{index}]"
        ):
            if record not in quoted:
                quoted.append(record)

    paths = [
        {
            "id": record.get("id"),
            "title": record.get("title"),
            "steps": list(record.get("steps", [])),
            "combined_rating": sdr_attack_paths.combined_rating(
                record.get("id"), attack_paths, assessment, policy
            ),
        }
        for record in _sequence(_mapping(attack_paths).get("attack_paths"))
        if isinstance(record, Mapping)
    ]

    verdict = _verdict(threats, assessment, policy, today)

    return {
        "schema_version": SCHEMA_VERSION,
        "run": {
            # Caller knowledge. Nothing here knows which host or model is
            # running, and `None` is the honest answer rather than a default
            # that puts an unestablished fact in the report.
            "platform": invocation_block.get("platform"),
            "model": invocation_block.get("model"),
            "plugin_version": invocation_block.get("plugin_version"),
            "command": invocation_block.get("command"),
            "mode": entry_run.get("mode"),
            "confirmed": confirmation is not None,
            "risk_appetite": risk_appetite,
            "policy_digest": risk_mod.policy_digest(policy),
            "timestamp": invocation_block.get("timestamp"),
            "repo": _repo_block(invocation_block),
            "scope": scope_block,
            "profile": dict(_mapping(entry_run.get("profile"))),
            "critical_facts": list(_sequence(entry_run.get("critical_facts"))),
        },
        "architecture": architecture,
        "findings": findings,
        "attack_paths": paths,
        "verdict": verdict,
        "limitations": _limitations(
            _mapping(entry), scope_block, verdict.get("inherent")
        ),
        "disclosures_blocked": list(
            _sequence(invocation_block.get("disclosures_blocked"))
        ),
        # N17/N18. What the repository said to the reviewer, quoted so a human
        # can judge it, and never acted on.
        "untrusted_content": quoted,
    }


def _repo_block(invocation: Mapping) -> dict:
    """Branch, commit, and the flag that cannot be computed.

    `dirty` means "the worktree differs from the index", which needs a
    stat-and-hash of every tracked file; N36 bans the subprocess that would
    answer it. It is `None` with the reason stated rather than an
    approximation: a report claiming `"dirty": false` on a dirty tree is worse
    than one declining to answer, because that field is how a reader decides
    whether the commit id means anything at all.
    """

    repo = _mapping(invocation.get("repo"))
    return {
        "branch": repo.get("branch"),
        "commit": repo.get("commit"),
        "dirty": None,
        "dirty_unknown_reason": (
            "not computed: determining a dirty worktree requires a subprocess, "
            "which plan N36 forbids"
        ),
    }
