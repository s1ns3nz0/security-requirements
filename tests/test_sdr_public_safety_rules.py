"""N15/N16 -- the public-safety scan keeps working while F15 extends it.

The security-design-review plan (docs/security-design-review-plan.md F15) extends
`lint.check_public_safety` with key-material patterns. Two obligations come with
that extension, and this file is both of them:

* **N15** -- the existing `INSTANCE_FORMS`, `CITATION_HOSTS`, and
  `SIGNED_PARAM_NAMES` rules still *fire*. An allowlist that quietly stops
  matching is indistinguishable from no allowlist at all.
* **N16** -- a recognised citation URL survives. A scanner that flags every URL
  is a scanner people turn off, so the false-positive side is tested with the
  same weight as the true-positive side, together with near-miss hosts that
  prove the allowlist is doing work rather than the check being absent.

What is asserted, and what deliberately is not:

* The **structured surface** `Finding(level, req_id, rule, message)`
  (`lint.py:162`) -- specifically `(level, req_id, rule)`. Message prose may be
  reworded legitimately (plan §11.2 N25), so no assertion reads it. Every one of
  the four rule families reports under the single rule name `names-an-instance`
  (`lint.py:488`), so structure alone cannot tell them apart; each true-positive
  test therefore pairs the finding with a **differential** -- the same sentence
  with the offending value replaced by a benign phrase must produce nothing --
  which pins the finding to the value rather than to the surrounding prose.
* The closed sets are guarded as a **floor, never an equality**. N23/N24 are
  meant to grow them; an equality assert would be engineered to fail on the
  intended change. `tests/test_sdr_lint_baseline.py` already pins membership
  (`BASELINE <= lint.SET`); what is added here is the *behavioural* floor it does
  not cover -- every recorded member still has its effect, and so does every
  member added since. A dropped member fails these too, from the other side.

Every value used here is synthetic: reserved domains (`example.com`,
`.example`), documentation ARNs, and placeholder bucket names. Nothing in this
file resembles a real resource.
"""

from __future__ import annotations

import pytest

# tests/conftest.py already puts the plugin scripts directory on sys.path.
import lint as lint_mod


# ---------------------------------------------------------------------------
# Synthetic disclosures, one per rule family. Each is a (label, text) pair where
# the label is the INSTANCE_FORMS label at lint.py:321 that the text provokes.
# ---------------------------------------------------------------------------
ARN_TEXT = "Confirm the object store arn:aws:s3:::example-bucket-name is encrypted."
INTERNAL_HOSTNAME_TEXT = "Payroll traffic reaches payments-example.internal over TLS."
CLOUD_ENDPOINT_TEXT = (
    "The audit log is written to example-bucket.s3.us-east-1.amazonaws.com."
)
SIGNED_URL_TEXT = "Download the evidence from https://csrc.nist.gov/export?sig=SYNTHETIC"

# The same sentences with the one-particular-thing replaced by a kind of thing.
# These carry the surrounding prose and none of the disclosure, so a finding on
# the pair above is attributable to the value and not to the wording.
ARN_BENIGN = "Confirm the object store bucket is encrypted."
INTERNAL_HOSTNAME_BENIGN = "Payroll traffic reaches the payments service over TLS."
CLOUD_ENDPOINT_BENIGN = "The audit log is written to the managed object store."
SIGNED_URL_BENIGN = "Download the evidence from https://csrc.nist.gov/export"

INSTANCE_FORM_CASES = [
    ("an ARN", ARN_TEXT, ARN_BENIGN),
    ("an internal hostname", INTERNAL_HOSTNAME_TEXT, INTERNAL_HOSTNAME_BENIGN),
    ("a cloud resource endpoint", CLOUD_ENDPOINT_TEXT, CLOUD_ENDPOINT_BENIGN),
]

# Every free-text field `check_public_safety` reads (lint.py:470-480). The scan
# is only as wide as this list, so the list is exercised rather than trusted.
PUBLISHED_FIELDS = [
    "statement", "rationale", "evidence", "csp_part", "team_part",
    "verification.target", "verification.expect", "verification.fallback_manual",
]

# PRE-EXTENSION BASELINE: the members of the two closed sets whose *effect* is
# guarded below. Recorded here so a member dropped from lint.py still gets
# exercised -- iterating the live set alone could not notice a deletion.
CITATION_HOSTS_BASELINE = frozenset({
    "aicpa-cima.com", "attack.mitre.org", "cheatsheetseries.owasp.org", "cisa.gov",
    "cloud.google.com", "csrc.nist.gov", "cve.mitre.org", "cwe.mitre.org",
    "datatracker.ietf.org", "docs.aws.amazon.com", "ecfr.gov", "eur-lex.europa.eu",
    "gdpr-info.eu", "hhs.gov", "iso.org", "kisa.or.kr", "law.go.kr",
    "learn.microsoft.com", "nist.gov", "nvlpubs.nist.gov", "owasp.org",
    "pcisecuritystandards.org", "privacy.go.kr", "rfc-editor.org",
    "www.aicpa-cima.com", "www.cisa.gov", "www.ecfr.gov", "www.hhs.gov",
    "www.iso.org", "www.kisa.or.kr", "www.law.go.kr", "www.nist.gov",
    "www.pcisecuritystandards.org", "www.privacy.go.kr", "www.rfc-editor.org",
})
SIGNED_PARAM_NAMES_BASELINE = frozenset({
    "access_token", "api_key", "apikey", "code", "id_token", "key", "passwd",
    "password", "refresh_token", "sas", "secret", "sig", "signature", "token",
    "x-amz-algorithm", "x-amz-credential", "x-amz-security-token", "x-amz-signature",
})

# Recorded members plus anything the extension adds: both must behave.
ALL_CITATION_HOSTS = sorted(CITATION_HOSTS_BASELINE | set(lint_mod.CITATION_HOSTS))
ALL_SIGNED_PARAM_NAMES = sorted(
    SIGNED_PARAM_NAMES_BASELINE | set(lint_mod.SIGNED_PARAM_NAMES)
)

# N16 asks for four hosts by name; these are the four the plan cites plus two
# more drawn from different corners of the allowlist (an RFC source and provider
# documentation), each with a plausible citation path.
CITATION_URLS = [
    "https://csrc.nist.gov/pubs/sp/800/53/r5/final",
    "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
    "https://eur-lex.europa.eu/eli/reg/2016/679/oj",
    "https://datatracker.ietf.org/doc/html/rfc8446",
    "https://docs.aws.amazon.com/kms/latest/developerguide/overview.html",
]

# Hosts that read like a citation source and are not one. Each is a reserved or
# non-existent domain; none may be granted publication.
NEAR_MISS_HOST_URLS = [
    # The allowlisted host as a *label* of somebody else's domain.
    "https://csrc.nist.gov.example.com/sp800-53",
    "https://owasp.org.example.net/Top10/",
    # A hyphen where the dot was.
    "https://owasp-org.example.org/Top10/",
]

# The userinfo trick lint.py:391 records: every real client resolves this to the
# host after the @, not the recognised one before it. Kept apart from the list
# above because the host it reads as is not the question -- the URL is refused
# before that, for carrying a separator this tool and a browser disagree about.
USERINFO_LOOKALIKE_URL = "https://csrc.nist.gov\\@evil.example/secret"

NEAR_MISS_URLS = NEAR_MISS_HOST_URLS + [USERINFO_LOOKALIKE_URL]


# ---------------------------------------------------------------------------
# Helpers. Defined locally on purpose: tests/conftest.py, tests/risk_helpers.py
# and tests/fixtures/ are owned by other work in flight and are not touched.
# ---------------------------------------------------------------------------

REQ_ID = "REQ-SDR-PUB-01"


def _managed(field: str, text) -> dict:
    """A managed block carrying `text` in one published field."""
    if field.startswith("verification."):
        return {"verification": {field.split(".", 1)[1]: text}}
    return {field: text}


def _scan(field: str, text) -> list[tuple[str, str, str]]:
    """The structured surface of the scan: (level, req_id, rule) per finding."""
    return [
        (f.level, f.req_id, f.rule)
        for f in lint_mod.check_public_safety(REQ_ID, _managed(field, text))
    ]


def _messages(field: str, text) -> list[str]:
    """Message text, for failure output only -- never asserted on."""
    return [f.message for f in lint_mod.check_public_safety(REQ_ID, _managed(field, text))]


BLOCKED = ("ERROR", REQ_ID, "names-an-instance")


# ---------------------------------------------------------------------------
# N15 -- each rule family still fires.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("label,text,benign", INSTANCE_FORM_CASES,
                         ids=[c[0] for c in INSTANCE_FORM_CASES])
def test_an_instance_naming_form_is_still_blocked_at_error_level(label, text, benign):
    """N15: ARN, internal hostname, and cloud resource endpoint each still fire."""
    assert _scan("statement", text) == [BLOCKED], _messages("statement", text)


@pytest.mark.parametrize("label,text,benign", INSTANCE_FORM_CASES,
                         ids=[c[0] for c in INSTANCE_FORM_CASES])
def test_the_same_sentence_naming_a_kind_of_thing_is_not_blocked(label, text, benign):
    """The differential: the finding above belongs to the value, not the prose."""
    assert _scan("statement", benign) == [], _messages("statement", benign)


def test_a_url_carrying_a_signed_parameter_is_still_blocked_at_error_level():
    """N15: a presigned URL is blocked even on an allowlisted citation host --
    the signed-parameter check at lint.py:452 runs after the host is accepted."""
    assert _scan("verification.target", SIGNED_URL_TEXT) == [BLOCKED], _messages(
        "verification.target", SIGNED_URL_TEXT
    )


def test_the_same_url_without_the_signed_parameter_is_not_blocked():
    """The differential for the signed-parameter rule."""
    assert _scan("verification.target", SIGNED_URL_BENIGN) == [], _messages(
        "verification.target", SIGNED_URL_BENIGN
    )


def test_an_arn_is_blocked_whatever_case_it_is_written_in():
    """lint.py:322 says ARN:AWS: and arn:aws: are the same disclosure."""
    shouted = ARN_TEXT.replace("arn:aws:", "ARN:AWS:")
    assert shouted != ARN_TEXT
    assert _scan("statement", shouted) == [BLOCKED], _messages("statement", shouted)


@pytest.mark.parametrize("field", PUBLISHED_FIELDS)
def test_every_published_field_is_scanned_for_instance_names(field):
    """N15: the scan is only as wide as the field list at lint.py:470."""
    assert _scan(field, ARN_TEXT) == [BLOCKED], _messages(field, ARN_TEXT)


def test_a_disclosure_inside_a_list_valued_field_is_still_found():
    """`evidence` may be a list; lint.py:494 joins it before scanning."""
    value = ["A screenshot of the console.", CLOUD_ENDPOINT_TEXT]
    assert _scan("evidence", value) == [BLOCKED], _messages("evidence", value)


def test_two_different_disclosures_in_one_field_are_reported_separately():
    """lint.py:498 collects every distinct problem, not the first one."""
    text = f"{ARN_TEXT} {INTERNAL_HOSTNAME_TEXT}"
    assert _scan("statement", text) == [BLOCKED, BLOCKED], _messages("statement", text)


def test_a_requirement_with_no_published_fields_produces_no_findings():
    assert lint_mod.check_public_safety(REQ_ID, {}) == []


# ---------------------------------------------------------------------------
# N15 -- the behavioural floor on the closed sets. Membership is pinned in
# tests/test_sdr_lint_baseline.py; what is asserted here is that each member
# still has an effect. Members may be added, never dropped.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("host", ALL_CITATION_HOSTS)
def test_every_allowlisted_citation_host_still_grants_publication(host):
    """Floor over the recorded baseline *and* anything the extension adds: a
    host is on the allowlist so that a URL to it may be published."""
    assert lint_mod.url_problem(f"https://{host}/reference/document") is None


@pytest.mark.parametrize("name", ALL_SIGNED_PARAM_NAMES)
def test_every_signed_parameter_name_still_blocks_the_url_carrying_it(name):
    """Floor over the recorded baseline *and* anything the extension adds."""
    url = f"https://csrc.nist.gov/export?{name}=SYNTHETIC-VALUE"
    assert lint_mod.url_problem(url) is not None


@pytest.mark.parametrize("name", ALL_SIGNED_PARAM_NAMES)
def test_a_signed_parameter_name_is_matched_after_percent_decoding(name):
    """lint.py:381 says names are compared decoded -- `%73ig` is `sig`."""
    encoded = f"%{ord(name[0]):02x}{name[1:]}"
    url = f"https://csrc.nist.gov/export?{encoded}=SYNTHETIC-VALUE"
    assert lint_mod.url_problem(url) is not None


@pytest.mark.parametrize("label,text,benign", INSTANCE_FORM_CASES,
                         ids=[c[0] for c in INSTANCE_FORM_CASES])
def test_every_recorded_instance_form_still_has_a_pattern_that_matches(label, text, benign):
    """Floor on INSTANCE_FORMS: the label is still carried by a pattern, and that
    pattern still matches the shape it was written for."""
    patterns = [p for p, lab in lint_mod.INSTANCE_FORMS if lab == label]
    assert patterns, f"{label!r} is no longer an instance form"
    assert any(p.search(text) for p in patterns)


# ---------------------------------------------------------------------------
# N16 -- the false-positive guard, and the proof that the allowlist is what
# separates the two halves.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("url", CITATION_URLS)
def test_a_recognised_citation_url_is_not_a_problem(url):
    """N16 at the `url_problem` level (lint.py:401)."""
    assert lint_mod.url_problem(url) is None


@pytest.mark.parametrize("url", CITATION_URLS)
def test_a_recognised_citation_url_produces_no_finding(url):
    """N16 through the scan a requirement actually goes through."""
    text = f"Derived from {url} and reviewed by the security team."
    assert _scan("rationale", text) == [], _messages("rationale", text)


def test_several_citation_urls_in_one_field_produce_no_findings():
    text = "See " + ", ".join(CITATION_URLS) + " for the control text."
    assert _scan("rationale", text) == [], _messages("rationale", text)


def test_a_citation_url_ending_a_sentence_is_still_recognised():
    """lint.py:398 strips sentence punctuation from the end of a candidate."""
    text = "The control text is at https://owasp.org/Top10/."
    assert _scan("rationale", text) == [], _messages("rationale", text)


def test_a_citation_url_carrying_an_ordinary_query_is_still_recognised():
    """Only the names in SIGNED_PARAM_NAMES turn a link into a credential."""
    url = "https://csrc.nist.gov/publications?topic=encryption&page=2"
    assert lint_mod.url_problem(url) is None


@pytest.mark.parametrize("url", NEAR_MISS_URLS)
def test_a_host_that_only_looks_like_a_citation_source_is_still_blocked(url):
    """N16's other half: the allowlist is doing the work. Without it, each of
    these would be published on the strength of resembling a recognised host."""
    assert lint_mod.url_problem(url) is not None
    text = f"Derived from {url} and reviewed by the security team."
    assert _scan("rationale", text) == [BLOCKED], _messages("rationale", text)


@pytest.mark.parametrize("url", NEAR_MISS_HOST_URLS)
def test_a_near_miss_host_is_not_on_the_citation_allowlist(url):
    """The near misses are near misses because of what the set does not contain;
    if one were ever added on purpose, the test above should be revisited rather
    than the allowlist quietly widened."""
    from urllib.parse import urlsplit

    host = (urlsplit(url).hostname or "").rstrip(".")
    assert host not in lint_mod.CITATION_HOSTS


def test_a_url_whose_recognised_host_is_only_userinfo_is_still_blocked():
    """A client resolves `https://csrc.nist.gov\\@evil.example/secret` to
    evil.example. The allowlist must not be reached by a string that only looks
    like it names a citation host."""
    assert lint_mod.url_problem(USERINFO_LOOKALIKE_URL) is not None
