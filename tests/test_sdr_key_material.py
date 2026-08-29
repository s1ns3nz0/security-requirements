"""F15 -- key-material patterns at the publish boundary (plan §11.2 N13, N14).

These tests are written **red on purpose**. `lint.check_public_safety`
(lint.py:461) is a shape-and-host scanner: `INSTANCE_FORMS` (lint.py:321),
`CITATION_HOSTS` (lint.py:360), and `SIGNED_PARAM_NAMES` (lint.py:382) are the
whole of its vocabulary. None of them knows what a credential is. Plan §6 F15
and §9 mark key-material patterns **EXTEND**, and this file is the
specification that extension has to satisfy.

The threat is not that a secret sits in the repository under review -- the
adversarial fixture puts it there deliberately. The threat is that a model
*reads* the fixture and quotes what it found into a requirement's `evidence` or
`rationale`, and that requirement is then rendered into `docs/security/`, which
is publishable. `check_public_safety` scans exactly those requirement fields
(statement, rationale, evidence, csp_part, team_part, and the three published
`verification` fields), so it is the right choke point; it simply cannot see a
credential today.

Three properties are asserted, and they are not the same property:

1. **Detected.** The value is reported at all.
2. **Not echoed.** A report that quotes the secret has copied it into a second
   place. A scanner that leaks what it scans for is worse than no scanner.
3. **Fingerprinted.** The report distinguishes *which* secret it found without
   carrying the secret. Asserted behaviourally rather than by pinning a hash
   algorithm: the same value must report the same way, two different values
   must report differently, and neither report may contain either value. A
   message that satisfies all three carries a fingerprint whatever the
   implementation chose to compute it with.

**Scope note for N14.** The plan's "pre-write choke point" wording assumes
`scripts/sdr_entry.py`, which plan §9 marks **NEW** and which does not exist.
The only real write path this repository ships today is
`risk._write_text_transaction` (risk.py:2188, plan §9 "EXISTS -- mandatory"), so
that is what `test_the_write_path_refuses_a_document_carrying_a_planted_secret`
drives, and it asserts on the bytes on disk rather than on the scanner's own
report. No write API is invented here.
"""

from __future__ import annotations

from pathlib import Path

import pytest

# tests/conftest.py already puts the plugin scripts directory on sys.path.
import lint as lint_mod
import risk as risk_mod

from risk_helpers import materialise_adversarial_fixture


# The field a quoted secret would most plausibly land in, and one alternative,
# so a rule cannot be written against the name `evidence` alone.
PUBLISHED_FIELD = "evidence"
ALTERNATE_FIELD = "rationale"


# ---------------------------------------------------------------------------
# Fixture reading. The planted values are read out of the materialised tree
# rather than hardcoded, so that these tests track the fixture: if
# tests/fixtures/adversarial-checkout stops carrying a secret, the helpers
# below fail loudly instead of silently asserting about a string nobody plants
# any more (which is how a disclosure test passes for the wrong reason).
# ---------------------------------------------------------------------------


def _dotenv(root: Path) -> dict[str, str]:
    values = {}
    for line in (root / ".env").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, _, value = line.partition("=")
        values[name.strip()] = value.strip()
    return values


@pytest.fixture()
def planted(tmp_path) -> dict[str, str]:
    """The three secrets N13 names, read from the materialised fixture."""

    root = materialise_adversarial_fixture(tmp_path)
    env = _dotenv(root)

    secrets = {
        "aws_access_key_id": env.get("AWS_ACCESS_KEY_ID", ""),
        "aws_secret_access_key": env.get("AWS_SECRET_ACCESS_KEY", ""),
        "dotenv_token": env.get("SESSION_SIGNING_TOKEN", ""),
        "connection_string": env.get("DATABASE_URL", ""),
    }
    for name, value in secrets.items():
        assert value, f"the fixture no longer plants {name}; N13 cannot be tested"

    # The access key is planted twice on purpose -- in .env and in reviewable
    # source -- because a scanner keyed on the .env filename would miss the
    # second copy entirely.
    source = (root / "src" / "config" / "aws.py").read_text(encoding="utf-8")
    assert secrets["aws_access_key_id"] in source, (
        "the fixture no longer plants the access key in reviewable source")
    return secrets


def scan(value: str, field: str = PUBLISHED_FIELD) -> list[lint_mod.Finding]:
    """Run the publish-boundary scan over a requirement that quotes `value`.

    This is the model-quotes-what-it-read shape: the secret arrives inside
    ordinary evidence prose, next to the path it was read from.
    """

    managed = {
        "statement": "The receipt export job shall authenticate to the object store.",
        field: [f"reviewed src/config/aws.py; the client is configured with {value}"],
    }
    return lint_mod.check_public_safety("SR-KEY-01", managed)


def as_tuples(findings) -> list[tuple[str, str, str]]:
    """`Finding` has no `__eq__` (lint.py:162), so compare structurally."""

    return [(f.level, f.req_id, f.rule) for f in findings]


def messages(findings) -> str:
    return "\n".join(f.message for f in findings)


def leak_candidates(secret: str) -> list[str]:
    """Substrings whose presence in a report would be a second disclosure.

    The whole value; the password out of a DSN's userinfo, which is the part of
    a connection string that is actually a credential; and every eight-character
    run of the value, eight being the shortest head start worth giving anyone
    reading the report.

    Runs that are ordinary lowercase words are excluded. The existing
    `INSTANCE_FORMS` message legitimately contains the English word "internal",
    which is also eight consecutive characters of the fixture's hostname; that
    is prose about the *kind* of thing found, not a leak of the value.
    """

    candidates = [secret]
    if "://" in secret and "@" in secret:
        userinfo = secret.split("://", 1)[1].split("@", 1)[0]
        if ":" in userinfo:
            candidates.append(userinfo.split(":", 1)[1])
    for index in range(len(secret) - 7):
        run = secret[index:index + 8]
        if run.isalpha() and run.islower():
            continue
        candidates.append(run)
    return [c for c in candidates if c]


def echoes(text: str, secret: str) -> bool:
    return any(candidate in text for candidate in leak_candidates(secret))


# ---------------------------------------------------------------------------
# N13 -- planted key, token, and connection string appear in no artifact; only
# {location, kind, fingerprint}.
# ---------------------------------------------------------------------------


def test_a_quoted_aws_access_key_id_is_reported_at_the_publish_boundary(planted):
    """N13 -- `AKIA` plus sixteen characters, quoted into published evidence."""

    findings = scan(planted["aws_access_key_id"])

    assert findings, (
        "check_public_safety reported nothing for a quoted AWS access key id. "
        "F15's key-material patterns are not implemented: INSTANCE_FORMS, "
        "CITATION_HOSTS, and SIGNED_PARAM_NAMES match shapes and hosts, and "
        "none of them recognises a credential.")


def test_a_quoted_aws_secret_access_key_is_reported_at_the_publish_boundary(planted):
    """N13 -- the matching secret, which has no prefix to key on at all."""

    findings = scan(planted["aws_secret_access_key"])

    assert findings, (
        "check_public_safety reported nothing for a quoted AWS secret access "
        "key. F15's key-material patterns are not implemented; a value with no "
        "recognisable prefix needs an entropy or assignment-context rule.")


def test_a_quoted_dotenv_token_is_reported_at_the_publish_boundary(planted):
    """N13 -- the `.env` session token, quoted into published rationale."""

    findings = scan(planted["dotenv_token"], field=ALTERNATE_FIELD)

    assert findings, (
        "check_public_safety reported nothing for a quoted .env token. F15's "
        "key-material patterns are not implemented, and the scan must cover "
        "every published field, not only evidence.")


def test_a_quoted_connection_string_is_reported_at_the_publish_boundary(planted):
    """N13 -- the `postgresql://` DSN, password and all.

    This one the shape scanner already catches, but only incidentally: the
    fixture's host ends in `.internal`, so `INSTANCE_FORMS` (lint.py:332) fires
    on the *hostname*. The credential in the userinfo is invisible to it, and
    `URL_IN_TEXT` (lint.py:395) only matches `https?://`, so the DSN scheme is
    never parsed.
    """

    findings = scan(planted["connection_string"])

    assert findings, (
        "check_public_safety reported nothing for a quoted database connection "
        "string carrying a password.")


def test_a_connection_string_is_caught_for_its_credential_not_only_its_host(planted):
    """N13 -- the same DSN with a public host is still a published password.

    Substituting the host removes the only reason the scanner fires today. If
    this is red while the test above is green, the connection string is caught
    by accident and would sail through the moment the host changes.
    """

    dsn = planted["connection_string"].replace(
        "orders-db.internal.example.invalid", "db.example.com")
    assert "internal" not in dsn, "the substitution must remove the hostname trigger"

    findings = scan(dsn)

    assert findings, (
        "a postgresql:// DSN carrying a password was reported only because its "
        "host matched INSTANCE_FORMS; with an ordinary host the same password "
        "reaches docs/security/ unreported. F15 must key on the credential.")


def test_no_report_of_a_planted_secret_echoes_the_secret(planted):
    """N13 -- a scanner report that quotes the secret has leaked it twice."""

    leaked = []
    for name, secret in planted.items():
        text = messages(scan(secret))
        if not text:
            leaked.append(f"{name}: not reported at all, so nothing to echo")
        elif echoes(text, secret):
            leaked.append(f"{name}: the finding message contains the value")

    unreported = [entry for entry in leaked if "not reported" in entry]
    echoed = [entry for entry in leaked if "contains the value" in entry]

    assert not echoed, (
        "a finding message carries the secret it reports; report "
        "{location, kind, fingerprint} only:\n" + "\n".join(echoed))
    assert not unreported, (
        "these planted secrets produce no finding at all, so N13's no-echo "
        "property is vacuous for them -- F15 is not implemented:\n"
        + "\n".join(unreported))


def test_a_report_names_the_location_the_secret_reached(planted):
    """N13 -- `location`: which published field carried it."""

    for name, secret in planted.items():
        findings = scan(secret, field=ALTERNATE_FIELD)
        assert findings, (
            f"{name} produces no finding, so it reports no location; F15's "
            f"key-material patterns are not implemented")
        assert f"managed.{ALTERNATE_FIELD}" in messages(findings), (
            f"the finding for {name} does not name the field the secret "
            f"reached, so a reader cannot find and redact it")


def test_a_report_fingerprints_the_secret_rather_than_naming_a_kind(planted):
    """N13 -- `fingerprint`: same value reports the same, different values differ.

    Asserted behaviourally so the implementation is free to choose its own
    digest. Combined with the no-echo test above, a message that is stable per
    value and distinct between values is carrying a fingerprint, whatever
    computed it. Today every message for a given rule is identical prose, so
    two different leaked keys are indistinguishable in the report.
    """

    for name, secret in planted.items():
        first = messages(scan(secret))
        assert first, (
            f"{name} produces no finding, so it carries no fingerprint; F15's "
            f"key-material patterns are not implemented")
        assert messages(scan(secret)) == first, (
            f"the report for {name} is not stable between runs, so it cannot "
            f"be a fingerprint")

        # A second value of the same shape. Reversing preserves the character
        # set and length, so any rule that fires on the original fires here.
        other = secret[:4] + secret[4:][::-1]
        assert other != secret
        second = messages(scan(other))
        assert second, (
            f"a second {name}-shaped value produces no finding, so the pair "
            f"cannot be distinguished")
        assert second != first, (
            f"two different {name} values report identically, so the report "
            f"carries a kind but no fingerprint -- a reader cannot tell which "
            f"credential leaked or whether two findings are the same one")


# ---------------------------------------------------------------------------
# N14 -- the scan is a pre-write choke point, and it blocks.
# ---------------------------------------------------------------------------


def test_a_key_material_finding_blocks_at_error_level(planted):
    """N14 -- ERROR, not WARN. A warning does not block a write.

    `check_public_safety` already reports its own rule at ERROR (lint.py:485,
    and the comment there says why). The extension must not downgrade key
    material to advice on the grounds that it might be a false positive:
    publication is irreversible and lint's WARN level is for prose quality.
    """

    for name, secret in planted.items():
        findings = scan(secret)
        assert findings, (
            f"{name} produces no finding, so it blocks nothing; F15's "
            f"key-material patterns are not implemented")
        levels = {level for level, _req, _rule in as_tuples(findings)}
        assert levels == {"ERROR"}, (
            f"the finding for {name} is at {sorted(levels)}; only ERROR blocks "
            f"a write, and a WARN-level disclosure finding is a document that "
            f"gets published anyway")


def test_the_write_path_refuses_a_document_carrying_a_planted_secret(planted, tmp_path):
    """N14 -- the choke point, asserted on the bytes on disk.

    Driven through `risk._write_text_transaction` (risk.py:2188) because that is
    the only real write path this repository ships; `scripts/sdr_entry.py` is
    plan §9 **NEW** and does not exist, and inventing an API here would make the
    test pass against nothing.

    The assertion deliberately does not consult the scanner's report. A scan
    that flags a secret and then writes the file anyway satisfies every
    assertion above and still publishes the credential, which is the exact
    failure N14 exists to catch.
    """

    project_root = tmp_path / "project"
    document = project_root / "docs" / "security" / "requirements.md"
    body = (
        "# Security requirements\n\n"
        "## SR-KEY-01\n\n"
        "Evidence: reviewed src/config/aws.py; the client is configured with "
        f"{planted['aws_access_key_id']} and {planted['aws_secret_access_key']}.\n"
    )

    try:
        risk_mod._write_text_transaction(
            [(document, project_root, body, True)])
    except Exception:
        # Blocked, which is the required behaviour. The bytes check below then
        # confirms the transaction left nothing behind.
        pass

    written = [path for path in project_root.rglob("*") if path.is_file()]
    for path in written:
        raw = path.read_bytes()
        for name, secret in planted.items():
            assert secret.encode("utf-8") not in raw, (
                f"{path.relative_to(project_root)} on disk contains the planted "
                f"{name}. The publish-boundary scan is not wired into the write "
                f"path at all: risk._write_text_transaction does not call "
                f"lint.check_public_safety, so nothing stands between a model "
                f"quoting a credential and a file under docs/security/.")
