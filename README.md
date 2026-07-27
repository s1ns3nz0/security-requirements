# security-requirements

Derives security requirements for a service. Not a scanner.

Most security tooling is **discovery** — read the code, find the flaw. There is
plenty of it. This is **prescription**: state what the service must satisfy,
before or independently of any code existing. That is the artefact a compliance
or design stage actually needs, and it is the one nothing produces.

> **Status: pre-release.** The pipeline runs end to end with the full SP 800-53
> Rev 5 catalog, CSF 2.0, ASVS 5.0, twelve curated services across three providers, and six regulatory
> overlays (ISMS-P, HIPAA, GDPR, PCI DSS, SOC 2, ISO 27001). Exercised against a dozen local repositories and three public ones
> (CloudGoat, OWASP WrongSecrets, Online Boutique); see [DESIGN.md](DESIGN.md).

## What it produces

```
docs/security/
  requirements.md      organised by CSF 2.0 function, so it reads as work
  traceability.md      control -> requirement, so an auditor can check coverage
  responsibility.md    who owns what, and what evidence backs each claim
```

Each requirement is verifiable, atomic, states a property rather than an
implementation, and carries the control identifiers it derives from.

## How it works

Two paths, crossed.

```
profile
  |-- FIPS 199 impact -> 800-53B baseline        completeness
  |-- DFD -> STRIDE / LINDDUN -> threats         relevance
        |
        v
  threat AND baseline  ->  raised priority
  threat only          ->  additional requirement    <- why this exists
  baseline only        ->  retained, lower priority
        |
        v  responsibility split
  provider claimed / shared / organisational / team
```

The baseline guarantees nothing is missed. The threat model finds what a
baseline cannot express — tenant isolation, business logic replay, personal data
leaving inside a stack trace. The responsibility split is what makes the result
usable: a Moderate baseline is about 290 controls, and most of them are not the
delivery team's work.

## Design commitments

**Control identifiers are never recalled from memory.** The catalog is derived
mechanically from NIST's OSCAL release, and `scripts/lint.py` fails the build if
a requirement cites an identifier the catalog does not contain. A fabricated
`SC-28(4)` reads exactly like the three enhancements that are real; one of them
in a compliance document discredits all of it.

**Inheritance is a claim, not a fact.** Nothing is asserted to be handled by the
cloud provider. Provider-claimed controls carry the evidence a reader must
obtain to substantiate them.

**Coverage gaps are stated, never implied away.** Detected regulations outside
the supported set are declared as not covered. Services without a curated
responsibility file are shown as unverified. Controls in families that are not
yet bundled are reported as unavailable rather than dropped.

**Human edits survive re-runs.** Exception approvals, rewritten statements, and
status are never overwritten; competing changes land in `pending_review`.
Requirements are retired with a reason, never deleted — last quarter's audit
report has to remain answerable.

**Identifiers are stable.** Derived from content, not sequence. A requirement
inserted in the middle does not silently repoint every existing ticket and
evidence link.

## Usage

```
/sec-req-init      scan the repository, interview the gaps, confirm impact
/sec-req-build     threat model, responsibility split, write requirements
/sec-req-refresh   re-derive after a change, preserving human edits
```

Where a profile triggers a regulation an overlay covers, `/sec-req-build` runs
it and reports the clauses no control reaches — the ones an audit asks about
and a SP 800-53 derivation cannot produce. The clause mapping is this
repository's reading, not a published crosswalk, and says so.

## Output placement

`.security-requirements/` holds the profile, threat model, and implementation
status. Together those describe where the data lives, which trust boundaries
exist, which controls are not implemented, and which risks were accepted until
when. That is a reconnaissance document. On a public repository it is gitignored
with an explanation; git history survives deletion.

`docs/security/` holds the requirement definitions, which are safe to publish
and better for being read.

## What is bundled

| Catalog | Contents | Licence |
|---|---|---|
| NIST SP 800-53 Rev 5 | 1,196 controls across 20 families; Low, Moderate, High and Privacy baselines, plus the PM family as a programme layer that no baseline selects | US Government work, public domain |
| NIST CSF 2.0 | 106 subcategories under 22 categories | US Government work, public domain |
| OWASP ASVS 5.0 | 345 requirements across 17 chapters, with levels | CC BY-SA 4.0, isolated in its own directory |
| Data type classification | Impact contribution per data type, with jurisdiction-gated regulatory triggers | Apache-2.0 |
| Responsibility layers | Family defaults and control overrides for seven deployment models | Apache-2.0 |
| Service curation | Ten AWS services, Azure Blob, GKE | Apache-2.0 |
| ISMS-P overlay | 101 certification criteria with an authored control mapping | Korean notice, outside copyright (Article 7) |
| HIPAA overlay | 22 standards and 46 implementation specifications, rebuildable from the eCFR API | US Government work, public domain |
| GDPR overlay | 46 articles across Chapters II–V, titles only with links to the Official Journal | EUR-Lex reuse policy |
| PCI DSS overlay | 12 principal requirements, identifiers and our own descriptions only | Standard **not** bundled — PCI SSC terms |
| SOC 2 overlay | 13 criteria series with elective category selection | Criteria **not** bundled — AICPA |
| ISO 27001 overlay | Clauses 4–10 and the four Annex A themes | Standard **not** bundled — ISO |

CIS Benchmarks, PCI DSS, ISO/IEC 27001 Annex A, and SOC 2 criteria are **not**
bundled — their terms do not permit redistribution. Provider guidance is
summarised in our own words with links, never reproduced.

## Development

```
python3 scripts/rebuild_catalogs.py     # rebuild every catalog from upstream
python3 -m pytest tests/                # deterministic layer, 536 tests
python3 scripts/eval_golden.py golden/b2b-saas-aws requirements.yaml
```

Four golden cases keep the whole scale reachable — they derive to Low,
Moderate, Moderate, and High. If they all collapse to one level, the tailoring
has stopped discriminating, so a test asserts the spread rather than leaving it
to whoever notices.

Only `b2b-saas-aws` carries a written requirements document, so it is the only
case `eval_golden.py` can score. The other three exercise the derivation and
their `expected-coverage.yaml` waits for a draft.

See [CONTRIBUTING.md](CONTRIBUTING.md). Curated service files are the most
useful contribution: one managed service, one file, one pull request.

## Licence

Apache-2.0 for the code. Bundled reference data keeps its own terms — see
[NOTICE](NOTICE). NIST does not endorse this project.

This tool produces drafts. It is not legal advice and does not substitute for
compliance certification.

## Measuring coverage

A large part of the suite exercises the command line through subprocess, and
without `COVERAGE_PROCESS_START` the report counts none of it — several scripts
read as barely tested while their CLIs are covered end to end. Measured wrongly,
the number sends the next round of work at the wrong file.

```
COVERAGE_PROCESS_START=$PWD/.coveragerc PYTHONPATH=$PWD \
  python3 -m coverage run -m pytest tests/ -q
python3 -m coverage combine && python3 -m coverage report
```

Delete the data files between runs with `rm -f .coverage .coverage.*`, not
`rm .coverage*` — the second glob matches `.coveragerc`, and the only symptom of
losing it is a total about ten points too low.
