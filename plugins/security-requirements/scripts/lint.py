#!/usr/bin/env python3
"""Quality gate for generated requirements.

Two kinds of check, and the first is the important one.

**Source integrity (blocking).** Every control identifier a requirement cites
must exist in the bundled catalog. This is the second reason the catalog is
bundled: it does not merely reduce the chance of an invented identifier, it
detects one after the fact. Without this check, a fabricated ``SC-28(4)`` reads
exactly like the three enhancements that are real, and nobody finds out until an
auditor does.

**Style (blocking or advisory).** A requirement nobody can check is not a
requirement. The rules come from references/requirement-style.md: verifiable,
atomic, states a property rather than an implementation.

Usage
-----
    python3 -I "<absolute plugin root>/scripts/lint.py" .security-requirements/requirements.yaml
    python3 -I "<absolute plugin root>/scripts/lint.py" requirements.yaml --threats threats.yaml
    python3 -I "<absolute plugin root>/scripts/lint.py" requirements.yaml --strict   # warnings fail too
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import profile_schema  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
CATALOG_DIR = REPO_ROOT / "catalogs" / "nist-800-53r5"
CSF_DIR = REPO_ROOT / "catalogs" / "csf-2.0"
ASVS_DIR = REPO_ROOT / "catalogs" / "asvs-5"

ID_RE = re.compile(r"^REQ-[A-Z0-9]+(?:-[A-Z0-9]+)*-\d{2}$")

# The fields `managed` may carry, from references/requirement-style.md. Anything
# else is a field nothing reads, and a field nothing reads is a field nothing
# checks.
MANAGED_KEYS = {
    # The record shape, from references/requirement-style.md.
    "statement", "rationale", "csf", "sources", "threat_refs", "responsibility",
    "csp_part", "team_part", "evidence", "verification", "priority",
    # Carried through the pipeline rather than written by hand. `unverified`
    # comes from the responsibility split -- a service whose curation nobody has
    # reviewed -- and render.py prints it. It was left out of the first version
    # of this list, which would have rejected any document that preserved it:
    # an allowlist has to cover what the rest of the tool reads, not what one
    # fixture happens to carry.
    # `unverified` only. `services` and `org_control_declared` are fields of a
    # crossed item, not of a requirement, and nothing reads them from `managed`
    # -- they were added here on the same guess as the two removed below.
    "unverified",
}
# `asvs` and `overlay_refs` were here on the strength of a guess. Neither is in
# the record shape, neither appears in any golden draft, and nothing reads
# either -- and the whole point of this list is that a key nothing reads is an
# error. Widening it on a hunch is the failure it exists to prevent, made by the
# person maintaining it. If a requirement needs to cite an overlay clause, the
# field arrives with the consumer that reads it.
NIST_RE = re.compile(r"^[A-Z]{2}-\d+(?:\(\d+\))?$")
CSF_RE = re.compile(r"^[A-Z]{2}\.[A-Z]{2}-\d{2}$")
ASVS_RE = re.compile(r"^ASVS-V\d+(?:\.\d+)*$")

# How a requirement may be checked. A closed set, because "verify it somehow"
# is not a verification method and the downstream automation planned for v2
# dispatches on this value.
VERIFICATION_METHODS = {
    "iac_inspect",    # read infrastructure-as-code or the resolved plan
    "config_api",     # query the running configuration through a provider API
    "code_grep",      # locate a construct in the source
    "test_case",      # an automated test asserts the property
    "artifact_review", # read a document, report, or agreement
    "manual",         # a person checks and records the result
}

# Terms that make a requirement undecidable when they carry the obligation.
VAGUE = {
    "en": [
        "appropriate", "adequate", "adequately", "sufficient", "sufficiently",
        "as needed", "where necessary", "as necessary", "properly", "robust",
        "best practice", "best practices", "regularly", "periodically",
        "reasonable", "reasonably", "strong", "secure enough",
    ],
    "ko": [
        "적절한", "적절히", "충분한", "충분히", "필요시", "필요에 따라",
        "적합한", "안전하게", "주기적으로", "적정", "합리적",
    ],
}

# Two obligations fused into one. Keyed on repeated modal verbs rather than on
# conjunctions: "naming the caller, the document, and the time" is one
# obligation with three parts, while "X must ... and Y must ..." is two. Testing
# for `and` alone flags every enumeration and trains the reader to skip the
# warning.
# Double quotes only. `'[^']*'` was here for one commit and the apostrophe took
# it out: "the organisation's data must be encrypted and the team's key must be
# rotated" has two possessives, so the span between them was stripped as a quote
# and a genuine second obligation disappeared. The curly apostrophe is the same
# character English typesets a possessive with, so it is out for the same reason.
QUOTED_SPAN = re.compile("\"[^\"]*\"|\u201c[^\u201d]*\u201d|\u300c[^\u300d]*\u300d")

MODAL = {
    "en": r"\b(?:must|shall|is required to|are required to)\b",
    # Korean obligation is `~야 하-`, whatever the verb, plus the periphrastic
    # forms that carry the same force. The first version listed four 하다/되다
    # spellings, which meant `거쳐야 한다` -- an ordinary way to write a
    # requirement -- counted as zero obligations, and the conjunctive endings
    # that join two obligations in one sentence (`...해야 하고 ...되어야 한다`)
    # counted as one. Both directions were wrong at once.
    "ko": (r"(?:야만?\s*(?:한다|하며|하고|합니다)"
           r"|야\s*할\s*필요가\s*있"
           r"|도록\s*(?:한다|하고|하며)"
           r"|필수(?:이다|로\s*함|임))"),
}

# Implementation detail that belongs in guidance rather than the statement.
IMPLEMENTATION_HINTS = [
    "nginx", "apache", "terraform resource", "kubectl", "systemd",
    "redis", "postgres.conf", "my.cnf", "iptables", ".env",
]


# A rationale that is the only thing holding a requirement up has to be readable
# as a reason. "TODO" satisfies a strip() and satisfies nobody else.
PLACEHOLDER_RATIONALE = frozenset({
    "todo", "tbd", "tba", "n/a", "na", "none", "nil", "later", "fixme", "xxx",
    "wip", "pending", "unknown", "?", "미정", "추후", "없음", "해당없음",
})


def is_substantive(text) -> bool:
    """Whether a rationale says anything a reader could evaluate.

    Named placeholders and strings with no letters in them, and nothing else.
    The first version added a ten-character floor, on the theory that a real
    reason is longer than "TODO" -- and it rejected "Contract", "PCI DSS", and
    "\ubc95\uc801 \uc758\ubb34", each of which is a complete answer to why a requirement
    exists. That made a rule written to stop a placeholder into a rule that
    blocked correct documents, which is the failure this file spent the day
    finding elsewhere.

    This cannot tell a thoughtful reason from a lazy one and does not try. A
    requirement resting on its rationale alone still draws a warning saying so;
    the error is reserved for having written nothing at all.
    """
    stripped = str(text or "").strip().strip(".-\u2014\u00b7? ")
    if not stripped or not any(c.isalpha() for c in stripped):
        return False
    # Word by word, not the whole string. Matching the exact text let "TODO
    # later" through, which is the same non-answer with a word after it.
    # Not on the slash: "n/a" is one token and splitting it produced "n" and
    # "a", neither of which is a placeholder, so the fix for "TODO later" let
    # "n/a" back through.
    words = [w for w in re.split(r"[\s,;:.!?()\[\]-]+", stripped.lower()) if w]
    return not all(w in PLACEHOLDER_RATIONALE for w in words)


class Finding:
    def __init__(self, level: str, req_id: str, rule: str, message: str):
        self.level, self.req_id, self.rule, self.message = level, req_id, rule, message

    def __str__(self) -> str:
        return f"  {self.level:<5} {self.req_id:<28} {self.rule:<18} {self.message}"


def load_catalog_ids() -> set[str]:
    if not CATALOG_DIR.exists():
        raise SystemExit("catalog not built; run scripts/rebuild_catalogs.py")
    ids = set()
    for path in CATALOG_DIR.glob("*.jsonl"):
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                ids.add(json.loads(line)["id"])
    return ids


def bundled_families() -> set[str]:
    return {p.stem for p in CATALOG_DIR.glob("*.jsonl")}


def known_families() -> set[str]:
    """Every family the publication defines, from the rebuild provenance."""
    path = CATALOG_DIR / "meta.json"
    if not path.exists():
        return set()
    return set(json.loads(path.read_text(encoding="utf-8")).get("all_families", []))


def load_ids(directory: Path, pattern: str = "*.jsonl") -> set[str]:
    if not directory.exists():
        return set()
    ids = set()
    for path in directory.glob(pattern):
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                ids.add(json.loads(line)["id"])
    return ids


def as_list(req_id: str, field: str, value) -> tuple[list, list[Finding]]:
    """Coerce a field that must be a list, saying so once.

    A string is iterable, so a scalar `sources: "SC-28"` was checked character
    by character and produced one identical format error per letter. Five
    errors about 'S', 'C', and '-' do not tell the reader that the real problem
    is a missing pair of brackets.
    """
    if value is None:
        return [], []
    if isinstance(value, list):
        return value, []
    return [value], [Finding("ERROR", req_id, f"{field}-format",
                             f"{field} must be a list; a single value was given")]


def canonical_source(value: str) -> str:
    """Delegates. This used to be a second implementation of one decision, and
    it refused `ac-3.1` -- the OSCAL spelling merge.py accepted and its own
    comment said a reader copies out of the bundled records."""
    return profile_schema.canonical_control_id(value)


def check_sources(
    req_id: str,
    sources,
    catalog: set[str],
    bundled: set[str],
    known: set[str],
) -> list[Finding]:
    sources, findings = as_list(req_id, "sources", sources)
    asvs_ids = load_ids(ASVS_DIR)
    for source in sources:
        if not isinstance(source, str):
            findings.append(Finding("ERROR", req_id, "source-format",
                                    f"{source!r} is not a control identifier"))
            continue
        source = canonical_source(source)
        if source.startswith("ASVS-"):
            if not ASVS_RE.match(source):
                findings.append(Finding("ERROR", req_id, "source-format",
                                        f"{source!r} is not an ASVS requirement identifier"))
            elif asvs_ids and source not in asvs_ids:
                findings.append(Finding("ERROR", req_id, "source-unknown",
                                        f"{source} does not exist in the ASVS catalog -- invented identifier"))
            continue
        if not NIST_RE.match(source):
            findings.append(Finding("ERROR", req_id, "source-format",
                                    f"{source!r} is not a control identifier"))
            continue
        if source in catalog:
            continue
        family = source.split("-")[0]
        if known and family not in known:
            findings.append(Finding("ERROR", req_id, "source-unknown",
                                    f"{source} names family {family}, which does not exist -- invented identifier"))
        elif family not in bundled:
            findings.append(Finding("WARN", req_id, "source-unbundled",
                                    f"{source} is in family {family}, which is not bundled yet"))
        else:
            findings.append(Finding("ERROR", req_id, "source-unknown",
                                    f"{source} does not exist in the catalog -- invented identifier"))
    return findings


# Scripts a statement may be written in, and the locale whose rules cover them.
# Checked because getting the locale wrong is silent in the direction that
# matters: a Korean document linted as English passes clean while containing
# '적절히', and the vague-term check is the one that decides whether a
# requirement can be verified at all.
SCRIPT_RANGES = {
    "ko": (("\uac00", "\ud7a3"), ("\u1100", "\u11ff")),
    "ja": (("\u3040", "\u309f"), ("\u30a0", "\u30ff")),
    "zh": (("\u4e00", "\u9fff"),),
}


def script_of(text: str) -> str | None:
    """Which script the statement is largely written in, or None.

    Counted, not sniffed. The first version returned the first non-Latin script
    it saw anywhere, so an English requirement naming a Korean product was
    reported as written in Korean and blocked -- a claim about the whole
    statement made from one character. A quotation or a product name is not the
    language of the sentence.

    Below the threshold nothing is claimed at all. Script alone cannot settle
    Japanese written without kana, and a rule that guesses in the direction of
    blocking is worse than one that stays quiet.
    """
    letters = [ch for ch in text if not ch.isspace() and not ch.isdigit()
               and not (ch.isascii() and not ch.isalpha())]
    if not letters:
        return None
    counts = {locale: sum(1 for ch in letters
                          for low, high in ranges if low <= ch <= high)
              for locale, ranges in SCRIPT_RANGES.items()}
    # Japanese carries Han as well as kana, so any kana at all settles it.
    if counts["ja"]:
        counts["zh"] = 0
    dominant = max(counts, key=lambda k: counts[k])
    if not counts[dominant]:
        return None
    share = counts[dominant] / len(letters)
    return dominant if share >= 0.5 else None


# Things that name one instance rather than one kind of thing. Not a judgement
# about meaning -- this repository has been wrong every time it inferred meaning
# from shape -- but these five forms cannot be a resource type, a control, or a
# property. A verification target is meant to name what to look at ("the bucket
# encryption configuration"), and docs/security/ is publishable, so a target
# naming the production bucket answers "where the data lives", which the README
# puts on the other side of the line.
INSTANCE_FORMS = (
    # Case-insensitive: ARN:AWS: and arn:aws: are the same disclosure.
    (re.compile(r"\barn:[a-z0-9-]*:", re.IGNORECASE), "an ARN"),
    (re.compile(r"\b[a-z0-9-]+\.(?:internal|local|corp|intranet)\b", re.IGNORECASE),
     "an internal hostname"),
    # Hosts that cannot exist without an account, bucket, or tenant name in
    # them. Unlike a bare URL, there is no reading of these that is a citation.
    (re.compile(
        r"\b[a-z0-9][a-z0-9.-]*\.(?:"
        r"s3[.a-z0-9-]*\.amazonaws\.com"
        r"|execute-api\.[a-z0-9-]+\.amazonaws\.com"
        r"|rds\.amazonaws\.com"
        r"|elb\.amazonaws\.com"
        r"|blob\.core\.windows\.net"
        r"|vault\.azure\.net"
        r"|database\.windows\.net"
        r"|storage\.googleapis\.com"
        r"|run\.app"
        r"|appspot\.com"
        r")\b", re.IGNORECASE),
     "a cloud resource endpoint"),
)
# Three patterns were here and are gone. A dotted quad matches an IP address and
# also matches an agent version (1.24.3.1) and a certificate policy OID
# (2.16.840.1); an absolute path matches /etc/app/config.yaml, which names a
# kind of file rather than one particular one.
#
# The third was `https?://`, and removing it was an overcorrection that lasted
# one review. The observation was right -- a URL is also how a requirement cites
# the regulation it comes from, and this repository's own GDPR overlay records
# EUR-Lex article addresses -- but the conclusion was wrong. Deleting the rule
# made a presigned URL, complete with its signature, publishable; that is the
# most damaging single value this boundary could ever carry.
#
# The burden runs the other way. Publication is irreversible, so an address this
# tool does not recognise is a disclosure until someone says otherwise, and
# saying otherwise means adding a host to the list below on purpose. Citation
# intent cannot be read off a URL's shape; it can be read off its origin.

CITATION_HOSTS = frozenset({
    # Standards and law. An address here is a reference a reader can follow.
    "eur-lex.europa.eu", "gdpr-info.eu",
    "csrc.nist.gov", "nvlpubs.nist.gov", "nist.gov", "www.nist.gov",
    "owasp.org", "cheatsheetseries.owasp.org",
    "iso.org", "www.iso.org",
    "pcisecuritystandards.org", "www.pcisecuritystandards.org",
    "hhs.gov", "www.hhs.gov", "ecfr.gov", "www.ecfr.gov",
    "law.go.kr", "www.law.go.kr", "privacy.go.kr", "www.privacy.go.kr",
    "kisa.or.kr", "www.kisa.or.kr",
    "datatracker.ietf.org", "rfc-editor.org", "www.rfc-editor.org",
    "cwe.mitre.org", "attack.mitre.org", "cve.mitre.org",
    "cisa.gov", "www.cisa.gov",
    "aicpa-cima.com", "www.aicpa-cima.com",
    # Provider documentation, which the responsibility files cite by design.
    # Documentation paths carry no tenant; the resource endpoints do, and those
    # live under different hosts caught by the pattern above.
    "docs.aws.amazon.com", "learn.microsoft.com", "cloud.google.com",
})

# Parameter names that turn a link into a credential. Compared against decoded
# names, because `x-amz-%73ignature` is the same parameter.
SIGNED_PARAM_NAMES = frozenset({
    "x-amz-signature", "x-amz-credential", "x-amz-security-token", "x-amz-algorithm",
    "sig", "signature", "token", "access_token", "id_token", "refresh_token",
    "api_key", "apikey", "key", "password", "passwd", "secret", "sas", "code",
})

# To the next whitespace, and no further. The first version stopped at the
# characters that cannot appear in an authority -- an apostrophe, a comma, a
# closing bracket -- reasoning that they are sentence punctuation. They are also
# legal in userinfo, so `https://csrc.nist.gov\'@evil.com/secret` was truncated
# to a recognised citation host and published, while every real client resolves
# it to evil.com. A permission-granting parser cannot trim before it validates.
URL_IN_TEXT = re.compile(r"https?://\S+", re.IGNORECASE)

# Punctuation that ends a sentence rather than a URL. Stripped only from the
# very end of a candidate, where there is nothing after it to be confused by.
TRAILING_PUNCTUATION = ".,;:!?)]}>\"'\u201d\u2019`"


def url_problem(url: str) -> str | None:
    """Why this URL must not be published, or None if it is a citation.

    Everything that is not a recognised citation origin is a problem, including
    hosts this tool has never heard of. The alternative -- enumerating the ways
    a URL can be dangerous -- is the list that let a custom tenant domain, a git
    remote, an issue-tracker link naming an internal project, and a bare IP
    literal all through in the same afternoon.

    This grants publication, so it parses with urlsplit rather than by hand and
    refuses anything it cannot read the same way a client would. The hand-written
    version disagreed with real clients about backslashes, percent-encoded
    separators, and where a query begins -- it read the host of
    `https://csrc.nist.gov?topic=encryption` as the whole string and blocked a
    legitimate citation, and it read the host of the userinfo attack above as the
    part before the apostrophe.
    """
    from urllib.parse import urlsplit, parse_qsl, unquote

    candidate = url.rstrip(TRAILING_PUNCTUATION)

    # A backslash is a path separator to every browser and not to urlsplit, so a
    # string containing one does not mean here what it means there.
    if "\\" in candidate:
        return "a URL containing a backslash, which clients read as a path separator"
    if any(ord(c) < 0x20 or ord(c) == 0x7f for c in candidate):
        return "a URL containing a control character"

    try:
        parts = urlsplit(candidate)
        host = parts.hostname
        parts.port  # raises on a malformed port
    except ValueError:
        return "a URL this tool cannot parse, and so cannot vouch for"

    if parts.scheme.lower() not in ("http", "https") or not host:
        return "a URL this tool cannot parse, and so cannot vouch for"
    if parts.username or parts.password:
        return "a URL carrying credentials"
    if "%" in parts.netloc:
        return "a URL with a percent-encoded authority"

    host = host.rstrip(".")
    if not host.isascii():
        # A homograph is indistinguishable from the host it imitates at this
        # distance, and encoding it to IDNA to compare would grant permission on
        # the strength of a comparison the reader cannot make.
        return "a URL whose host is not ASCII"
    if host not in CITATION_HOSTS:
        return "a URL to a host that is not a recognised citation source"

    for blob in (parts.query, parts.fragment):
        if not blob:
            continue
        for name, _ in parse_qsl(blob, keep_blank_values=True):
            if unquote(name).strip().lower() in SIGNED_PARAM_NAMES:
                return "a URL carrying a signature or token"
    return None


def check_public_safety(req_id: str, managed: dict) -> list[Finding]:
    """Fields that reach docs/security/ and could name one particular thing."""
    findings = []
    verification = managed.get("verification")
    # Every field that reaches a published document as free text. The first
    # version listed four and the style guide repeated the number; `statement`,
    # `rationale`, and `verification.expect` are published too, so
    # "expect: the endpoint equals https://prod.internal/..." walked straight
    # past a rule written to catch exactly that.
    fields = {
        "statement": managed.get("statement"),
        "rationale": managed.get("rationale"),
        "evidence": managed.get("evidence"),
        "csp_part": managed.get("csp_part"),
        "team_part": managed.get("team_part"),
    }
    if isinstance(verification, dict):
        fields["verification.target"] = verification.get("target")
        fields["verification.expect"] = verification.get("expect")
        fields["verification.fallback_manual"] = verification.get("fallback_manual")

    def report(name: str, what: str) -> None:
        # ERROR, not WARN. The other warnings are about how well a requirement
        # is written, and a document with a clumsy statement is still safe to
        # publish. This one is about what leaves the building, and it is the
        # only rule here whose failure cannot be undone once the file is public.
        findings.append(Finding(
            "ERROR", req_id, "names-an-instance",
            f"managed.{name} contains {what}. This field is published, and naming "
            f"one particular resource answers \"where the data lives\" -- name the "
            f"kind of thing instead, or cite a recognised source."))

    for name, value in fields.items():
        text = "; ".join(map(str, value)) if isinstance(value, (list, tuple)) else str(value or "")
        # Every distinct problem in the field, not the first. Reporting one at a
        # time turns a draft with three disclosures into three rounds of lint,
        # fix, lint -- and the author has no way to know how many are left.
        problems = []
        for pattern, what in INSTANCE_FORMS:
            if pattern.search(text) and what not in problems:
                problems.append(what)
        for url in URL_IN_TEXT.findall(text):
            problem = url_problem(url)
            if problem and problem not in problems:
                problems.append(problem)
        for problem in problems:
            report(name, problem)
    return findings


def check_statement(req_id: str, statement: str, locale: str) -> list[Finding]:
    findings = []
    lowered = statement.lower()

    written_in = script_of(statement)
    if written_in and written_in != locale:
        supported = ", ".join(sorted(VAGUE))
        findings.append(Finding(
            "ERROR", req_id, "locale-mismatch",
            f"the statement is largely {written_in} and the linter was run with "
            f"--locale {locale}, so only the {locale} rules were applied"
            + (f". Re-run with --locale {written_in}." if written_in in VAGUE
               else f". {written_in} is not supported; the rules cover {supported}.")))

    for term in VAGUE.get(locale, []) + VAGUE["en"]:
        if term in lowered:
            findings.append(Finding("ERROR", req_id, "vague",
                                    f"{term!r} makes the requirement undecidable"))
            break

    # One locale's modal, not two added together. The English pattern used to be
    # added to every other locale's count, on the theory that it would catch an
    # English statement in a Korean document -- but locale-mismatch above already
    # catches that, with an ERROR, and the addition instead counted the "must" in
    # a quoted control title as a second Korean obligation.
    modal = MODAL.get(locale, MODAL["en"])
    # Quoted spans first. A statement may quote the control it derives from, and
    # `정책은 "암호화되어야 한다"라고 정의해야 한다` carries one obligation and
    # two obligation-shaped spans.
    #
    # This is a heuristic and stays a warning because of it. Reported speech
    # without quotation marks -- `...기록되어야 한다고 명시한다` -- still counts
    # twice, and telling that from an obligation needs a parser rather than a
    # pattern. A warning that is sometimes wrong is useful; an error that is
    # sometimes wrong blocks a correct document.
    unquoted = QUOTED_SPAN.sub(" ", statement)
    if len(re.findall(modal, unquoted, re.IGNORECASE)) > 1:
        findings.append(Finding("WARN", req_id, "not-atomic",
                                "more than one obligation in a single statement; split it"))

    for hint in IMPLEMENTATION_HINTS:
        if hint in lowered:
            findings.append(Finding("WARN", req_id, "implementation",
                                    f"{hint!r} names an implementation; state the property instead"))
            break

    if len(statement.split()) < 5:
        findings.append(Finding("WARN", req_id, "too-short", "statement is too short to be checkable"))

    return findings


def lint(doc: dict, locale: str, threats: dict | None) -> list[Finding]:
    catalog = load_catalog_ids()
    bundled = bundled_families()
    known = known_families()
    csf_ids = load_ids(CSF_DIR)
    findings = []

    for req in doc.get("requirements", []) or []:
        req_id = req.get("id", "<no id>")

        if not ID_RE.match(req_id):
            findings.append(Finding("ERROR", req_id, "id-format",
                                    f"expected REQ-<DOMAIN>-<TOPIC>-NN matching {ID_RE.pattern}, "
                                    f"derived from content -- never a running number. "
                                    f"DOMAIN and TOPIC are the author's words, not a fixed list."))

        managed = req.get("managed")
        if managed is None:
            # An absent block and an empty statement are different mistakes, and
            # the reader fixes them differently. Reported as "managed.statement
            # is empty", a document written in the flat shape -- statement at
            # the top level -- got five identical errors and no hint that the
            # whole managed/human split had been missed.
            stray = sorted(k for k in ("statement", "controls", "verification", "rationale")
                           if k in req)
            findings.append(Finding(
                "ERROR", req_id, "no-managed-block",
                "no `managed:` block" + (
                    f"; {', '.join(stray)} " + ("is" if len(stray) == 1 else "are")
                    + " at the top level. Requirements are split into `managed:`, which the"
                      " tool owns and rewrites, and `human:`, which it never touches."
                    if stray else ". See references/requirement-style.md.")))
            continue
        # Every guarantee this linter makes is keyed on the schema. A
        # requirement carrying `controls:` where `sources:` belongs cited
        # SC-28(4) -- the invented identifier this repository names in its own
        # comments -- and passed with zero errors, because the source-integrity
        # check reads `sources` and nothing was reading anything else. A key the
        # schema does not define is not a stylistic matter; it is the difference
        # between a document that was checked and one that was not.
        unknown_keys = sorted(set(managed) - MANAGED_KEYS)
        if unknown_keys:
            findings.append(Finding(
                "ERROR", req_id, "unknown-field",
                f"managed.{', managed.'.join(unknown_keys)} is not part of the record shape. "
                f"Nothing reads it, so anything it carries goes unchecked -- identifiers "
                f"under the wrong key are never verified against the catalog. "
                f"Expected: {', '.join(sorted(MANAGED_KEYS))}."))

        # `sources` is deliberately not required. A requirement with no control
        # identifiers is the threat-only case -- a risk no baseline control
        # addresses -- which is this tool's central claim, and three of the
        # eight golden requirements are exactly that. Requiring it would have
        # forbidden the most important kind of requirement the tool produces.
        for required, why in (("csf", "the requirements document is organised by CSF function, "
                                      "and a requirement without one is filed as UNCLASSIFIED"),
                              ("responsibility", "the document prints UNDETERMINED and nobody "
                                                 "owns the requirement")):
            if not managed.get(required):
                findings.append(Finding("ERROR", req_id, f"no-{required}",
                                        f"managed.{required} is missing -- {why}"))

        statement = (managed or {}).get("statement", "")
        if not statement:
            findings.append(Finding("ERROR", req_id, "no-statement",
                                    "managed.statement is present but empty"))
            continue

        findings += check_statement(req_id, statement, locale)
        findings += check_public_safety(req_id, managed)
        findings += check_sources(req_id, managed.get("sources", []) or [], catalog, bundled, known)

        csf_ids_declared, csf_findings = as_list(req_id, "csf", managed.get("csf"))
        findings += csf_findings
        for csf_id in csf_ids_declared:
            csf_id = csf_id.strip().upper() if isinstance(csf_id, str) else csf_id
            if not isinstance(csf_id, str) or not CSF_RE.match(csf_id):
                findings.append(Finding("ERROR", req_id, "csf-format",
                                        f"{csf_id!r} is not a CSF 2.0 subcategory identifier"))
            elif csf_ids and csf_id not in csf_ids:
                findings.append(Finding("ERROR", req_id, "csf-unknown",
                                        f"{csf_id} does not exist in CSF 2.0 -- invented identifier"))

        verification = managed.get("verification")
        if not verification:
            findings.append(Finding("ERROR", req_id, "no-verification",
                                    "verification block is required; an unverifiable requirement is a sentiment"))
        else:
            for field in ("method", "expect"):
                if not verification.get(field):
                    findings.append(Finding("ERROR", req_id, "verification-incomplete",
                                            f"verification.{field} is missing"))
            method = verification.get("method")
            if isinstance(method, str):
                method = method.strip().lower()
            if method and method not in VERIFICATION_METHODS:
                findings.append(Finding("ERROR", req_id, "verification-method",
                                        f"{method!r} is not one of {sorted(VERIFICATION_METHODS)}"))

        # `shared` too. The published responsibility document opens with
        # "Inheritance is a claim, not a fact. Every provider-claimed control
        # lists the evidence an auditor will ask for" -- and a shared control is
        # a provider claim for its csp_part. A shared requirement with no
        # evidence rendered into that document with an empty cell under a
        # sentence promising the opposite.
        # Stripped. `evidence: [""]`, `csp_part: " "` are truthy and render as
        # empty cells, which defeats the guarantee these rules exist to make.
        evidence_given = managed.get("evidence")
        if isinstance(evidence_given, str):
            evidence_given = [evidence_given]
        has_evidence = any(str(e).strip() for e in evidence_given or [])
        if managed.get("responsibility") in ("csp_claimed", "shared") and not has_evidence:
            findings.append(Finding("ERROR", req_id, "no-evidence",
                                    "inheritance is a claim; state the evidence needed to "
                                    "substantiate it"))

        # And a shared control has to say which half is whose, or the document
        # asserts a division it cannot describe.
        if managed.get("responsibility") == "shared":
            for half, whose in (("csp_part", "the provider's"), ("team_part", "the team's")):
                if not (managed.get(half) or "").strip():
                    findings.append(Finding(
                        "ERROR", req_id, f"no-{half.replace('_', '-')}",
                        f"responsibility is shared but {half} does not say what {whose} half is"))

        # A requirement derived purely from the threat model legitimately cites
        # no control -- that is what the threat-only bucket means, and those are
        # the findings the baseline could not produce. Only flag a requirement
        # with no basis of any kind.
        #
        # A written rationale counts. This tool's whole claim is that every
        # requirement can be traced to why it exists, so a requirement with no
        # control, no threat, and no stated reason should not reach a published
        # document -- but demanding an identifier from an author whose
        # requirement came from a contract or a business rule is the pressure
        # that produces invented identifiers, which is the failure this
        # repository was built to prevent. A reason a reader can evaluate is a
        # basis; a fabricated control number is not.
        if not managed.get("sources") and not managed.get("threat_refs"):
            if is_substantive(managed.get("rationale")):
                findings.append(Finding(
                    "WARN", req_id, "no-basis",
                    "cites neither a control nor a threat, and traces only to its "
                    "own rationale"))
            else:
                findings.append(Finding(
                    "ERROR", req_id, "no-basis",
                    "cites neither a control nor a threat and gives no rationale; "
                    "nothing traces to this, and traceability is what this document "
                    "claims. Cite a control, reference a threat, or write down why "
                    "it exists -- but do not invent an identifier"))

    if threats:
        known_threats = {t.get("id") for t in threats.get("threats", []) or [] if t.get("id")}
        for req in doc.get("requirements", []) or []:
            managed = req.get("managed") or {}
            refs = managed.get("threat_refs")
            if isinstance(refs, str):
                findings.append(Finding("ERROR", req.get("id", "<no id>"), "threat-ref-format",
                                        f"threat_refs is the single string {refs!r}; a string is "
                                        f"iterable, so it would be read one character at a time"))
                continue
            for ref in refs or []:
                if ref not in known_threats:
                    # The threat side of the same check has been here all along
                    # -- a threat's control identifiers are verified against the
                    # catalogue. A requirement's threat references were not
                    # verified against anything, so a mistyped id produced a
                    # requirement that traces to nothing and says it traces to a
                    # threat.
                    findings.append(Finding(
                        "ERROR", req.get("id", "<no id>"), "threat-ref-unknown",
                        f"{ref!r} is not a threat in the model. The requirement claims a "
                        f"provenance it does not have, and the traceability document will "
                        f"repeat the claim."))

        for threat in threats.get("threats", []) or []:
            findings += check_sources(threat.get("id", "<threat>"),
                                      threat.get("related_controls", []) or [], catalog, bundled, known)

    return findings


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("requirements", type=Path)
    ap.add_argument("--threats", type=Path)
    ap.add_argument("--locale", default="en")
    ap.add_argument("--strict", action="store_true", help="treat warnings as failures")
    args = ap.parse_args()

    # Before the file is opened. An unsupported locale is a usage error, and
    # checking it after the read reported a missing file when the argument was
    # what was wrong.
    if args.locale not in VAGUE:
        print(f"--locale {args.locale} is not supported; the rules cover "
              f"{', '.join(sorted(VAGUE))}. Falling back to English would check a "
              f"document nobody wrote in English, so nothing is checked instead.",
              file=sys.stderr)
        return 2

    doc = yaml.safe_load(args.requirements.read_text(encoding="utf-8")) or {}
    threats = None
    if args.threats and args.threats.exists():
        threats = yaml.safe_load(args.threats.read_text(encoding="utf-8"))

    findings = lint(doc, args.locale, threats)
    errors = [f for f in findings if f.level == "ERROR"]
    warnings = [f for f in findings if f.level == "WARN"]

    if findings:
        print("Lint findings\n")
        for finding in findings:
            print(finding)
        print()
    print(f"{len(errors)} error(s), {len(warnings)} warning(s)")

    if errors:
        # Flushed first. stdout carries the findings and stderr the verdict, and
        # unflushed the terminal showed "Blocked." above the list of what
        # blocked it.
        sys.stdout.flush()
        print("\nBlocked. A cited identifier that does not exist, or a requirement with no way\n"
              "to check it, discredits the whole document.", file=sys.stderr)
        return 1
    if warnings and args.strict:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
