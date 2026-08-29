"""R7 -- frozen pre-extension baseline for `lint.py` on the golden requirements.

The security-design-review plan (docs/security-design-review-plan.md §11.1 R7)
mutates `threats.yaml`, `risk.py`, `lint.py`, and `render.py`. R7 is the tripwire
that says the linter's verdict on the requirements this repository already ships
does not move: same error count, same warning count, same rule names.

Everything marked PRE-EXTENSION BASELINE in this file was captured by running the
real `lint.lint()` against the real golden drafts before any part of the plan was
implemented. It is a record of behaviour, not a wish. A red test here means the
extension changed the linter's verdict on documents it was not supposed to touch.

What is deliberately *not* frozen:

* Finding **messages**. Prose may be reworded legitimately; the structured
  surface `Finding(level, req_id, rule, message)` is the contract (plan §11.2
  N25), so only `(level, rule)` and the per-level totals are pinned.
* The **contents** of `MANAGED_KEYS` and `EVIDENCE_METHODS`. The plan adds
  requirement fields (N23) and may add verification methods (N24); pinning those
  sets to today's members would be a test engineered to fail on the intended
  change. What is asserted instead is the *relationship* the plan depends on --
  `VERIFICATION_METHODS is EVIDENCE_METHODS` -- and that no member of the
  public-safety closed sets is silently dropped (N15).
"""

from __future__ import annotations

import collections
import json
import subprocess
import sys
from datetime import date
from pathlib import Path

import pytest
import yaml

# tests/conftest.py already puts the plugin scripts directory on sys.path.
import lint as lint_mod
import merge as merge_mod
import risk as risk_mod

REPO_ROOT = Path(__file__).resolve().parents[1]
GOLDEN_ROOT = REPO_ROOT / "golden"
LINT_SCRIPT = REPO_ROOT / "plugins" / "security-requirements" / "scripts" / "lint.py"


# ---------------------------------------------------------------------------
# PRE-EXTENSION BASELINE -- captured from a real `lint.lint()` run, not authored.
#
# The golden *requirements* set is the three golden cases that ship a draft.json;
# the other five golden directories carry a profile and a coverage expectation
# but no requirements, so the linter has nothing to read there. Each case is
# linted in the locale its own profile.yaml declares -- payroll-integration is
# `ko`, and linting it as `en` produces 8 spurious locale-mismatch errors, which
# is why the locale is part of the frozen record rather than a hardcoded "en".
# ---------------------------------------------------------------------------
GOLDEN_LINT_BASELINE = {
    "access-terminal": {
        "locale": "en",
        "requirement_count": 7,
        "has_threats": False,
        "level_counts": {"ERROR": 0, "WARN": 1},
        # One statement fuses two obligations. Advisory, not blocking.
        "findings": [("WARN", "not-atomic")],
    },
    "b2b-saas-aws": {
        "locale": "en",
        "requirement_count": 8,
        "has_threats": True,
        "level_counts": {"ERROR": 0, "WARN": 0},
        "findings": [],
    },
    "payroll-integration": {
        "locale": "ko",
        "requirement_count": 8,
        "has_threats": False,
        "level_counts": {"ERROR": 0, "WARN": 0},
        "findings": [],
    },
}

# The whole rule vocabulary the golden requirements provoke today. Aggregated
# across all three cases, exactly one rule fires.
GOLDEN_LINT_BASELINE_RULES = {"not-atomic"}

# PRE-EXTENSION BASELINE: the members of the three closed sets `check_public_safety`
# dispatches on (plan §11.2 N15). Asserted as a floor, never as an equality --
# the extension may add hosts or parameter names, it may not drop them.
INSTANCE_FORM_LABELS_BASELINE = frozenset({
    "an ARN", "an internal hostname", "a cloud resource endpoint",
})
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

GOLDEN_CASES = sorted(GOLDEN_LINT_BASELINE)


# ---------------------------------------------------------------------------
# Local helpers. Defined here on purpose: tests/conftest.py and
# tests/risk_helpers.py are owned by other work in flight and are not touched.
# ---------------------------------------------------------------------------

def _golden_dir(case: str) -> Path:
    return GOLDEN_ROOT / case


def _golden_locale(case: str) -> str:
    profile = yaml.safe_load(
        (_golden_dir(case) / "profile.yaml").read_text(encoding="utf-8")
    ) or {}
    return profile.get("locale", "en")


def _golden_requirements_doc(case: str) -> dict:
    """Assemble the requirements document the way the existing suite does.

    tests/test_pipeline.py::test_golden_fixture_passes_lint builds it from
    draft.json through `merge.issue_id`; this follows that convention rather
    than inventing a second one.
    """
    draft = json.loads((_golden_dir(case) / "draft.json").read_text(encoding="utf-8"))
    return {
        "requirements": [
            {
                "id": merge_mod.issue_id(item["slug"], {"issued": {}}),
                "managed": item["managed"],
                "human": {},
            }
            for item in draft["requirements"]
        ]
    }


def _golden_threats(case: str):
    path = _golden_dir(case) / "threats.yaml"
    if not path.exists():
        return None
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _lint_golden(case: str) -> list:
    return lint_mod.lint(
        _golden_requirements_doc(case),
        _golden_locale(case),
        _golden_threats(case),
    )


def _pairs(findings) -> list[tuple[str, str]]:
    return sorted((f.level, f.rule) for f in findings)


def _level_counts(findings) -> dict[str, int]:
    counts = collections.Counter(f.level for f in findings)
    return {"ERROR": counts.get("ERROR", 0), "WARN": counts.get("WARN", 0)}


# ---------------------------------------------------------------------------
# The structured surface the baseline is expressed in (plan §11.2 N25).
# ---------------------------------------------------------------------------

def test_a_finding_carries_a_level_a_requirement_id_a_rule_and_a_message():
    finding = lint_mod.Finding("WARN", "REQ-X-Y-01", "some-rule", "some message")
    assert (finding.level, finding.req_id, finding.rule, finding.message) == (
        "WARN", "REQ-X-Y-01", "some-rule", "some message"
    )


def test_the_golden_set_is_the_three_cases_that_ship_a_requirements_draft():
    with_drafts = sorted(
        d.name for d in GOLDEN_ROOT.iterdir() if (d / "draft.json").exists()
    )
    assert with_drafts == GOLDEN_CASES


# ---------------------------------------------------------------------------
# R7 -- the frozen baseline itself.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("case", GOLDEN_CASES)
def test_the_golden_case_is_linted_in_the_locale_its_profile_declares(case):
    assert _golden_locale(case) == GOLDEN_LINT_BASELINE[case]["locale"]


@pytest.mark.parametrize("case", GOLDEN_CASES)
def test_the_golden_case_still_carries_the_baseline_requirement_count(case):
    doc = _golden_requirements_doc(case)
    assert len(doc["requirements"]) == GOLDEN_LINT_BASELINE[case]["requirement_count"]


@pytest.mark.parametrize("case", GOLDEN_CASES)
def test_lint_error_and_warning_counts_on_the_golden_case_are_unchanged(case):
    """R7: same error count, same warning count."""
    findings = _lint_golden(case)
    assert _level_counts(findings) == GOLDEN_LINT_BASELINE[case]["level_counts"], (
        f"{case}: " + str([str(f) for f in findings])
    )


@pytest.mark.parametrize("case", GOLDEN_CASES)
def test_the_level_and_rule_pairs_on_the_golden_case_are_unchanged(case):
    """R7: same rule names, at the same severity, with the same multiplicity.

    Message text is excluded on purpose -- prose may be reworded.
    """
    findings = _lint_golden(case)
    assert _pairs(findings) == sorted(GOLDEN_LINT_BASELINE[case]["findings"]), (
        f"{case}: " + str([str(f) for f in findings])
    )


@pytest.mark.parametrize("case", GOLDEN_CASES)
def test_no_golden_requirement_is_blocked_by_the_linter(case):
    errors = [f for f in _lint_golden(case) if f.level == "ERROR"]
    assert errors == [], [str(f) for f in errors]


@pytest.mark.parametrize("case", GOLDEN_CASES)
def test_every_finding_on_the_golden_case_names_a_real_requirement(case):
    ids = {r["id"] for r in _golden_requirements_doc(case)["requirements"]}
    stray = [str(f) for f in _lint_golden(case) if f.req_id not in ids]
    assert stray == []


def test_the_whole_golden_set_provokes_only_the_baseline_rule_vocabulary():
    """R7 aggregated: no new rule fires on documents the plan does not touch."""
    rules = {f.rule for case in GOLDEN_CASES for f in _lint_golden(case)}
    assert rules == GOLDEN_LINT_BASELINE_RULES


def test_the_whole_golden_set_totals_zero_errors_and_one_warning():
    findings = [f for case in GOLDEN_CASES for f in _lint_golden(case)]
    assert _level_counts(findings) == {"ERROR": 0, "WARN": 1}


def test_lint_on_the_golden_case_is_deterministic_across_runs():
    for case in GOLDEN_CASES:
        assert _pairs(_lint_golden(case)) == _pairs(_lint_golden(case))


def test_supplying_the_golden_threats_document_adds_no_findings():
    """b2b-saas-aws is the only golden case with threats; its related_controls
    all resolve against the bundled catalog, so the threats pass contributes
    nothing to the baseline."""
    case = "b2b-saas-aws"
    doc = _golden_requirements_doc(case)
    without = lint_mod.lint(doc, "en", None)
    with_threats = lint_mod.lint(doc, "en", _golden_threats(case))
    assert _pairs(with_threats) == _pairs(without) == []


def test_the_movie_rating_risk_assessment_adds_no_lint_findings():
    """golden/movie-rating-aws ships no requirements draft, so it enters lint
    only through the risk/evidence reference pass. It declares T-01..T-08 and no
    residual evidence_refs, and contributes nothing today."""
    case_dir = GOLDEN_ROOT / "movie-rating-aws"
    assessment = yaml.safe_load(
        (case_dir / "risk-assessment.yaml").read_text(encoding="utf-8")
    )
    threats = yaml.safe_load((case_dir / "threats.yaml").read_text(encoding="utf-8"))
    findings = lint_mod.lint(
        {"requirements": []}, "en", threats,
        assessment=assessment, evidence=None, today=date(2026, 1, 1),
    )
    assert [str(f) for f in findings] == []


# ---------------------------------------------------------------------------
# R7 through the command line, where the counts are what a human reads.
# ---------------------------------------------------------------------------

def test_the_lint_command_reports_zero_errors_for_the_clean_golden_case(tmp_path):
    doc = _golden_requirements_doc("b2b-saas-aws")
    requirements = tmp_path / "requirements.yaml"
    requirements.write_text(yaml.safe_dump(doc, sort_keys=False, allow_unicode=True),
                            encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-I", str(LINT_SCRIPT), str(requirements),
         "--threats", str(GOLDEN_ROOT / "b2b-saas-aws" / "threats.yaml"),
         "--locale", "en", "--strict"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "0 error(s), 0 warning(s)" in result.stdout


# ---------------------------------------------------------------------------
# Closed sets the plan depends on. Relationships and floors, never equalities --
# see the module docstring for why.
# ---------------------------------------------------------------------------

def test_the_verification_methods_the_linter_accepts_are_the_risk_evidence_methods():
    """Plan §11.2 N24 assumes these are one set. lint.py:78 binds the name
    directly to risk.EVIDENCE_METHODS (risk.py:59), so they cannot drift."""
    assert lint_mod.VERIFICATION_METHODS is risk_mod.EVIDENCE_METHODS


def test_every_golden_verification_method_is_an_accepted_method():
    for case in GOLDEN_CASES:
        for requirement in _golden_requirements_doc(case)["requirements"]:
            verification = requirement["managed"].get("verification") or {}
            method = verification.get("method")
            if method is None:
                continue
            assert method.strip().lower() in lint_mod.VERIFICATION_METHODS, (
                f"{case}/{requirement['id']}: {method!r}"
            )


def test_every_field_the_golden_drafts_carry_is_an_allowed_managed_field():
    """MANAGED_KEYS is a closed allowlist and the extension widens it (N23);
    what must never regress is that today's golden drafts stay inside it."""
    carried = {
        key
        for case in GOLDEN_CASES
        for requirement in _golden_requirements_doc(case)["requirements"]
        for key in requirement["managed"]
    }
    assert carried <= lint_mod.MANAGED_KEYS, sorted(carried - lint_mod.MANAGED_KEYS)


def test_no_instance_form_is_dropped_from_the_public_safety_scan():
    labels = {label for _pattern, label in lint_mod.INSTANCE_FORMS}
    assert INSTANCE_FORM_LABELS_BASELINE <= labels, sorted(
        INSTANCE_FORM_LABELS_BASELINE - labels
    )


def test_no_citation_host_is_dropped_from_the_public_safety_allowlist():
    assert CITATION_HOSTS_BASELINE <= lint_mod.CITATION_HOSTS, sorted(
        CITATION_HOSTS_BASELINE - lint_mod.CITATION_HOSTS
    )


def test_no_signed_parameter_name_is_dropped_from_the_public_safety_denylist():
    assert SIGNED_PARAM_NAMES_BASELINE <= lint_mod.SIGNED_PARAM_NAMES, sorted(
        SIGNED_PARAM_NAMES_BASELINE - lint_mod.SIGNED_PARAM_NAMES
    )
