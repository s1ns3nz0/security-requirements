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
    python3 scripts/lint.py .security-requirements/requirements.yaml
    python3 scripts/lint.py requirements.yaml --threats threats.yaml
    python3 scripts/lint.py requirements.yaml --strict   # warnings fail too
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
CATALOG_DIR = REPO_ROOT / "catalogs" / "nist-800-53r5"

ID_RE = re.compile(r"^REQ-[A-Z0-9]+(?:-[A-Z0-9]+)*-\d{2}$")
NIST_RE = re.compile(r"^[A-Z]{2}-\d+(?:\(\d+\))?$")

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

# Conjunctions that usually mean two obligations were fused into one.
CONJUNCTION = {
    "en": [r"\band\b", r"\bas well as\b", r"\balong with\b"],
    "ko": [r"하고\s", r"하며", r"및\s", r"와\s+함께"],
}

# Implementation detail that belongs in guidance rather than the statement.
IMPLEMENTATION_HINTS = [
    "nginx", "apache", "terraform resource", "kubectl", "systemd",
    "redis", "postgres.conf", "my.cnf", "iptables", ".env",
]


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


def check_sources(
    req_id: str,
    sources: list[str],
    catalog: set[str],
    bundled: set[str],
    known: set[str],
) -> list[Finding]:
    findings = []
    for source in sources:
        if source.startswith("ASVS-") or source.startswith("PR.") or source.startswith("ID."):
            continue  # checked against their own catalogs once bundled
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


def check_statement(req_id: str, statement: str, locale: str) -> list[Finding]:
    findings = []
    lowered = statement.lower()

    for term in VAGUE.get(locale, []) + VAGUE["en"]:
        if term in lowered:
            findings.append(Finding("ERROR", req_id, "vague",
                                    f"{term!r} makes the requirement undecidable"))
            break

    for pattern in CONJUNCTION.get(locale, []) + CONJUNCTION["en"]:
        if re.search(pattern, statement, re.IGNORECASE):
            findings.append(Finding("WARN", req_id, "not-atomic",
                                    "looks like two obligations; consider splitting"))
            break

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
    findings = []

    for req in doc.get("requirements", []) or []:
        req_id = req.get("id", "<no id>")

        if not ID_RE.match(req_id):
            findings.append(Finding("ERROR", req_id, "id-format",
                                    "expected REQ-<DOMAIN>-<TOPIC>-NN, derived from content"))

        managed = req.get("managed") or {}
        statement = managed.get("statement", "")
        if not statement:
            findings.append(Finding("ERROR", req_id, "no-statement", "managed.statement is empty"))
            continue

        findings += check_statement(req_id, statement, locale)
        findings += check_sources(req_id, managed.get("sources", []) or [], catalog, bundled, known)

        verification = managed.get("verification")
        if not verification:
            findings.append(Finding("ERROR", req_id, "no-verification",
                                    "verification block is required; an unverifiable requirement is a sentiment"))
        else:
            for field in ("method", "expect"):
                if not verification.get(field):
                    findings.append(Finding("ERROR", req_id, "verification-incomplete",
                                            f"verification.{field} is missing"))

        if managed.get("responsibility") == "csp_claimed" and not managed.get("evidence"):
            findings.append(Finding("ERROR", req_id, "no-evidence",
                                    "inheritance is a claim; state the evidence needed to substantiate it"))

        # A requirement derived purely from the threat model legitimately cites
        # no control -- that is what the threat-only bucket means, and those are
        # the findings the baseline could not produce. Only flag a requirement
        # with no basis of any kind.
        if not managed.get("sources") and not managed.get("threat_refs"):
            findings.append(Finding("WARN", req_id, "no-basis",
                                    "cites neither a control nor a threat; nothing traces to this"))

    if threats:
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
        print("\nBlocked. A cited identifier that does not exist, or a requirement with no way\n"
              "to check it, discredits the whole document.", file=sys.stderr)
        return 1
    if warnings and args.strict:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
