<p align="center">
  <img src="./assets/readme/hero.svg" width="100%"
       alt="security-requirements states what a service must satisfy, before or without any code to scan. Beside the title, a rendered requirement: personal data must be removed from exception payloads before they reach the error reporter, with no control recorded against it.">
</p>

Most security tooling is **discovery** — read the code, find the flaw. There is
plenty of it.

This is **prescription**. It states what a service must satisfy, before or
independently of any code existing. That is the artefact a design or compliance
stage actually needs, and it is the one nothing produces.

## What comes out

```
docs/security/
  requirements.md      organised by CSF 2.0 function, so it reads as work
  traceability.md      control -> requirement, so an auditor can check coverage
  responsibility.md    who owns what, and what evidence backs each claim
```

Each requirement is verifiable, atomic, states a property rather than an
implementation, and carries the control identifiers it derives from. One of
them, verbatim from a run of the `b2b-saas-aws` golden case:

---

#### REQ-AUDITLOG-WRITE-SEPARATION-01

The audit log destination must not be writable by any identity whose actions it records.

*An audit log an actor can alter is not audit evidence. The separation has to hold at the destination, because application-level restraint fails once code execution is obtained.*

| | |
|---|---|
| Responsibility | shared |
| Provider | Durability of the log store. |
| Team | Deliver audit records to a destination in a separate trust domain from the application execution role. |
| Evidence | AWS SOC 2 Type II report, plus the IAM policy attached to the runtime role |
| Basis | AU-9, AU-9(4) |
| Priority | high |
| Verify | iac_inspect: `IAM policy for the application execution role` — expect no write or delete permission on the audit log destination |
| Verify (manual) | Attempt a delete against the log destination using the runtime role. |

---

## How it derives them

<p align="center">
  <img src="./assets/readme/crossing.svg" width="100%"
       alt="A FIPS 199 impact rating selects an SP 800-53B baseline of 350 controls, supplying completeness. STRIDE and LINDDUN on the data flow diagram produce 8 threats across 7 trust boundaries, supplying relevance. Crossing the two gives 8 requirements raised in priority, 3 additional requirements the baseline does not express, and 342 controls retained at lower priority.">
</p>

The baseline guarantees nothing is missed. The threat model finds what a
baseline cannot express — tenant isolation, business logic replay, personal data
leaving inside a stack trace.

The middle row is the reason this exists. If it is empty, the threat model was
generic, and what you are holding is a filtered baseline.

## Who has to do it

<p align="center">
  <img src="./assets/readme/responsibility.svg" width="100%"
       alt="Of 350 controls at Moderate impact, 93 are implemented by the delivery team, 59 are shared with the cloud provider, 44 are provider-claimed and require evidence, and 154 are organisational. 152 reach the delivery team.">
</p>

A Moderate baseline is about 350 controls once the privacy set and the programme
layer are added, and most of them are not the delivery team's work. The split is
what makes the result usable rather than filed and forgotten.

Nothing is asserted to be handled by the cloud provider. **Inheritance is a
claim, not a fact** — every provider-claimed control carries the evidence a
reader must obtain to substantiate it.

## Run it

```
/plugin marketplace add s1ns3nz0/security-requirements
/plugin install security-requirements@security-requirements
```

Then, in the repository you want requirements for:

```
/sec-req-init      scan the repository, interview the gaps, confirm impact
/sec-req-build     threat model, responsibility split, write requirements
/sec-req-refresh   re-derive after a change, preserving human edits
```

Where a profile triggers a regulation an overlay covers, `/sec-req-build` runs
it and reports the clauses no control reaches — the ones an audit asks about
and an SP 800-53 derivation cannot produce. The clause mapping is this
repository's reading, not a published crosswalk, and says so.

### Where the files go

`.security-requirements/` holds the profile, threat model, and implementation
status. Together those describe where the data lives, which trust boundaries
exist, which controls are not implemented, and which risks were accepted until
when. That is a reconnaissance document. On a public repository it is gitignored
with an explanation; git history survives deletion.

`docs/security/` holds the requirement definitions, which are safe to publish
and better for being read.

## What it refuses to do

**Recall a control identifier from memory.** The catalog is derived mechanically
from NIST's OSCAL release, and `scripts/lint.py` fails the build if a
requirement cites an identifier the catalog does not contain. A fabricated
`SC-28(4)` reads exactly like the three enhancements that are real; one of them
in a compliance document discredits all of it.

**Imply a coverage gap away.** Detected regulations outside the supported set are
declared as not covered. Services without a curated responsibility file are shown
as unverified. Controls in families that are not yet bundled are reported as
unavailable rather than dropped.

**Overwrite a human edit.** Exception approvals, rewritten statements, and status
survive re-runs; competing changes land in `pending_review`. Requirements are
retired with a reason, never deleted — last quarter's audit report has to remain
answerable.

**Renumber.** Identifiers are derived from content, not sequence. A requirement
inserted in the middle does not silently repoint every existing ticket and
evidence link.

## Status

Pre-release. The pipeline runs end to end with the full SP 800-53 Rev 5 catalog,
CSF 2.0, ASVS 5.0, twelve curated services across three providers, and six
regulatory overlays (ISMS-P, HIPAA, GDPR, PCI DSS, SOC 2, ISO 27001).

Exercised against twelve local repositories and four rounds of public ones —
CloudGoat, OWASP WrongSecrets, Online Boutique, Airflow, Jaeger, and twenty
infrastructure projects run with authored threat models. Every round is recorded
in [DESIGN.md](DESIGN.md) §17–18 with the defects it found.

**Nobody outside this repository has used it.** The requirement text itself is
written by a model, not derived mechanically, and its quality has only ever been
scored against an answer key written by the same author.

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

```bash
python3 scripts/rebuild_catalogs.py     # rebuild every catalog from upstream
python3 -m pytest tests/                # deterministic layer, 738 tests
```

Seven golden cases keep the whole scale reachable — they derive to Low, three
Moderates, and three Highs. If they all collapse to one level, the tailoring has
stopped discriminating, so a test asserts the spread rather than leaving it to
whoever notices.

All seven are synthetic. A profile describes where the data is and what it is
worth, and this repository is public, so a real one plus its open requirements
would be a reconnaissance document.

Three of them — `b2b-saas-aws`, `payroll-integration`, and `access-terminal` —
carry written requirements documents, so they are the three cases
`eval_golden.py` can score against a derived `requirements.yaml`:

```bash
python3 scripts/eval_golden.py golden/b2b-saas-aws .security-requirements/requirements.yaml
```

The other four exercise the derivation and their `expected-coverage.yaml`
waits for a draft — an expectation file with no draft beside it is scored by
nothing, which is a fixture that looks like a check and is not.

Two cases are there because of what they alone reach. `metering-ledger` is the
only shape where every declared type is Low on both axes, so it is the only one
where the RPO integrity hint has anything to do — both other `rpo_zero` cases
were already at Moderate integrity from their data types, which is how the hint
stayed broken. `payroll-integration` is written in Korean, and the tool maps 101
ISMS-P criteria without ever having put a Korean document through its own
pipeline; it also carries the two elective overlays, ISO 27001 and SOC 2, which
are declared rather than detected, so until a profile named them a third of the
bundled overlays had never evaluated against anything.

`scripts/axis_coverage.py` reports which values of which input axes any run has
ever carried. Adding a repository adds coverage only when it carries one nothing
has carried before.

See [CONTRIBUTING.md](CONTRIBUTING.md). Curated service files are the most
useful contribution: one managed service, one file, one pull request.

### Measuring coverage

A large part of the suite exercises the command line through subprocess, and
without `COVERAGE_PROCESS_START` the report counts none of it — several scripts
read as barely tested while their CLIs are covered end to end. Measured wrongly,
the number sends the next round of work at the wrong file.

```bash
COVERAGE_PROCESS_START=$PWD/.coveragerc PYTHONPATH=$PWD \
  python3 -m coverage run -m pytest tests/ -q
python3 -m coverage combine && python3 -m coverage report
```

Delete the data files between runs with `rm -f .coverage .coverage.*`, not
`rm .coverage*` — the second glob matches `.coveragerc`, and the only symptom of
losing it is a total about ten points too low.

## Licence

Apache-2.0 for the code. Bundled reference data keeps its own terms — see
[NOTICE](NOTICE). NIST does not endorse this project.

This tool produces drafts. It is not legal advice and does not substitute for
compliance certification.
