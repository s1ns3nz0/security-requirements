# security-requirements

Derives security requirements from a repository and a confirmed service
profile. It is a design-stage prescription tool, not a vulnerability scanner.

The repository supplies architecture evidence. Seven owner questions supply
intent code cannot reveal: data sensitivity, recovery objectives, users,
external boundaries, obligations, existing controls, and jurisdiction.

The result is a reviewable contract for architecture and development: what the
service must satisfy, why it applies, who acts, and how it can be verified.

> **Status: pre-release.** The pipeline runs end to end with the full SP 800-53
> Rev 5 catalog, CSF 2.0, ASVS 5.0, twelve curated services across three providers,
> and six regulatory overlays (ISMS-P, HIPAA, GDPR, PCI DSS, SOC 2, ISO 27001).
>
> Exercised against twelve local repositories and four rounds of public ones —
> CloudGoat, OWASP WrongSecrets, Online Boutique, Airflow, Jaeger, and twenty
> infrastructure projects run with authored threat models. Every round is
> recorded in [DESIGN.md](DESIGN.md) §17–18 with the defects it found.
>
> **Nobody outside this repository has used it.** Models interpret repositories,
> write threats, and draft prose: the requirement text is written by a model.
> Scripts do catalog lookup, baseline selection, responsibility classification,
> crossing, linting, and state transitions.
>
> Requirement quality has only been scored against an answer key written by the same author.
> The evaluation is useful for regression, not independent validation.
>
> Output is a draft. It is not evidence that a requirement is implemented, proof
> that a provider control is inherited, or a compliance determination.

## Where it fits

This project overlaps several established categories. It does not replace them.
The distinction is the stage it serves and the trace it keeps.

| Tool or category | What it does well | Difference here |
|---|---|---|
| [OWASP SecurityRAT](https://owasp.org/www-project-securityrat/) | Selects and tracks requirements from application properties, with issue-tracker workflow | This project also derives repository architecture, crosses a full baseline with service-specific threats, and assigns cloud responsibility and evidence |
| [SD Elements](https://docs.sdelements.com/release/latest/guide/) | Commercial requirements automation from technology, business, and compliance drivers; it can scan repositories to pre-answer surveys | This project is open and repository-local, exposes its catalogs and derivation, and separates model judgement from deterministic stages |
| [OWASP Threat Dragon](https://owasp.org/www-project-threat-dragon/) and [Threagile](https://threagile.io/) | Create threat models, diagrams, risks, and mitigations | Threats are one input here; they are crossed with impact, control baselines, regulatory overlays, and responsibility data |
| [NIST OSCAL](https://pages.nist.gov/OSCAL/) and [Compliance Trestle](https://github.com/oscal-compass/compliance-trestle) | Represent, author, validate, and govern machine-readable compliance artifacts | They provide interchange and artifact workflows; this project derives what a particular service must satisfy before those artifacts are populated |
| [Checkov](https://www.checkov.io/1.Welcome/What%20is%20Checkov.html), CodeQL, SAST, and secret scanners | Detect defects or policy violations in code and infrastructure that already exist | This project states properties a design and future implementation must satisfy, including requirements a scanner cannot observe yet |

The closest comparison is SD Elements, not a scanner. The narrower goal here is
transparent derivation that lives with the repository and survives architecture
changes, review edits, exceptions, and later evidence.

## What it produces

```
docs/security/
  requirements.md      organised by CSF 2.0 function, so it reads as work
  traceability.md      control -> requirement, so an auditor can check coverage
  responsibility.md    who owns what, and what evidence backs each claim

.security-requirements/
  profile.yaml         confirmed inputs and impact derivation
  threats.yaml         DFD boundaries and service-specific threats
  requirements.yaml    stable records, review state, exceptions, evidence links
  status.yaml          assurance state; never inferred from prose alone
```

Each requirement is verifiable, atomic, states a property rather than an
implementation, and carries its control and threat references.

The internal files are sensitive. They expose architecture, storage locations,
unimplemented controls, and accepted risks. Only `docs/security/` is intended
for publication.

## How derivation works

The inputs branch. A payment service with a zero-loss objective must not receive
the same result as a public documentation site merely because both use AWS.

```
repository evidence + seven owner answers
  -> confirmed profile                              hard gate
     |-- data + RTO/RPO -> FIPS 199 impact
     |                    -> SP 800-53B + ASVS       completeness
     |-- DFD boundaries -> STRIDE / LINDDUN         relevance
     |-- region + data + declared regimes
     |                    -> regulatory overlays     applicability
     `-- provider + deployment + managed services
                          -> responsibility           ownership

baseline AND threat  -> raised priority
threat only          -> additional requirement
baseline only        -> retained, lower priority
```

The baseline provides completeness. The threat model adds what a baseline
cannot express: tenant isolation, business-logic replay, or personal data
leaving inside a stack trace.

The responsibility split makes the result usable. A Moderate baseline is about
290 controls, and most are not the delivery team's work.

Profile confirmation is mandatory. A wrong region or recovery objective can
change hundreds of downstream decisions while still producing convincing prose.

Unknown input remains `UNDETERMINED`. It surfaces a consequence and a refresh
instruction; it is not silently replaced with a model guess.

## Security design review

The generated requirements are review criteria. An architecture review can mark
each one `pass`, `conditional`, `fail`, `not_applicable`, or `undetermined`,
with evidence and an owner.

This is requirements-driven review, not automatic certification. A repository
can show that a control is planned or configured; assessment evidence is needed
to show that it operates effectively.

The assurance funnel is one-way:

```
authored -> trace-linked -> semantically reviewed -> implemented -> evidenced
```

No stage implies the next. A valid control identifier does not make requirement
prose correct. A correct requirement is not implemented. A provider claim
without current evidence is not inherited.

## Cloud-specific requirements

Requirements state durable properties. Service files add provider-specific
responsibility, configuration checks, and evidence without baking one cloud
implementation into the requirement text.

```yaml
statement: "Payment records must be recoverable to a point before deletion."
responsibility: shared
csp_part: "AWS provides the DynamoDB point-in-time recovery mechanism."
team_part: "Enable it before accepting production payment records."
verification:
  method: iac_inspect
  target: "the DynamoDB table's point-in-time recovery setting"
  expect: "enabled"
evidence:
  - "deployed configuration"
  - "successful restoration exercise"
  - "applicable provider assurance report"
```

A curated service file is reviewed project knowledge. If a managed service has
no file, the fallback is explicitly `unverified`; the tool does not invent a
provider split and present it as fact.

## Design commitments

**Control identifiers are never recalled from memory.** The catalog is derived
from NIST's OSCAL release. `scripts/lint.py` fails if a requirement cites an
identifier the catalog does not contain.

A fabricated `SC-28(4)` looks like a real enhancement. One invented identifier
in a compliance document discredits the rest.

**Inheritance is a claim, not a fact.** Nothing is asserted to be handled by the
cloud provider. Provider-claimed controls carry the evidence a reader must
obtain to substantiate them.

**Coverage gaps are stated, never implied away.** Unsupported regulations are
declared as not covered. Services without a curated responsibility file are
shown as unverified.

Controls in families that are not bundled are reported as unavailable rather
than dropped.

**Human edits survive re-runs.** Exception approvals, rewritten statements, and
status are never overwritten. Competing changes land in `pending_review`.

Requirements are retired with a reason, never deleted. Last quarter's audit
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

The normal sequence is:

1. Scan the repository as untrusted evidence; do not execute its code.
2. Present inferred architecture and ask the seven owner questions.
3. Confirm the complete profile and impact derivation.
4. Select the baseline, model threats, classify responsibility, and run overlays.
5. Draft atomic requirements, lint identifiers and links, then render reports.
6. Re-run overlays against written requirements to expose the assurance gap.

Where a profile triggers a supported regulation, `/sec-req-build` reports the
clauses no control reaches. These are obligations an SP 800-53 derivation cannot
produce.

The clause mapping is this repository's interpretation, not a published
crosswalk, and says so.

## What it does not do

- It does not find implementation vulnerabilities; use SAST, DAST, SCA, secret
  scanning, IaC scanning, and penetration testing after requirements exist.
- It does not execute an inspected repository. Repository text is untrusted
  evidence and may contain instructions intended to influence the model.
- It does not assert cloud inheritance. Provider claims require current evidence.
- It does not decide whether a law applies or establish certification.
- It does not mark a requirement implemented or evidenced from plausible prose.

## Output placement

`.security-requirements/` holds the profile, threat model, and implementation
status. Together they expose data locations, trust boundaries, unimplemented
controls, and accepted risks.

That is a reconnaissance document. On a public repository it is gitignored with
an explanation; git history survives deletion.

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
python3 -m pytest tests/                # deterministic layer, 766 tests
python3 scripts/eval_golden.py golden/b2b-saas-aws requirements.yaml
```

Seven golden cases keep the whole scale reachable: one Low, three Moderate, and
three High. A test asserts this spread so a loss of tailoring is visible.

All seven are synthetic. A profile describes where the data is and what it is
worth, and this repository is public, so a real one plus its open requirements
would be a reconnaissance document.

`metering-ledger` is the only case where every declared type is Low on both axes.
It makes the RPO integrity hint observable.

The other `rpo_zero` cases already had Moderate integrity from their data. That
is how a broken hint previously remained hidden.

`b2b-saas-aws`, `payroll-integration`, and `access-terminal` carry written
requirements, so `eval_golden.py` can score them.

The other four exercise derivation. Each expectation waits for a draft. An
expectation file without a draft is scored by nothing and must not be presented
as a check.

`payroll-integration` is written in Korean because the tool maps 101 ISMS-P
criteria and needed a Korean document through the complete pipeline.

It also carries ISO 27001 and SOC 2. Those overlays are declared rather than
detected, so a profile must name them before they are evaluated.

`scripts/axis_coverage.py` reports which values of which input axes any run has
ever carried. Adding a repository adds coverage only when it carries one
nothing has carried before.

See [CONTRIBUTING.md](CONTRIBUTING.md). Curated service files are the most
useful contribution: one managed service, one file, one pull request.

## Licence

Apache-2.0 for the code. Bundled reference data keeps its own terms — see
[NOTICE](NOTICE). NIST does not endorse this project.

This tool produces drafts. It is not legal advice and does not substitute for
compliance certification.

## Measuring coverage

Much of the suite exercises CLIs through subprocesses. Without
`COVERAGE_PROCESS_START`, the report misses that execution and makes covered
scripts appear untested.

```
COVERAGE_PROCESS_START=$PWD/.coveragerc PYTHONPATH=$PWD \
  python3 -m coverage run -m pytest tests/ -q
python3 -m coverage combine && python3 -m coverage report
```

Delete the data files between runs with `rm -f .coverage .coverage.*`, not
`rm .coverage*` — the second glob matches `.coveragerc`, and the only symptom of
losing it is a total about ten points too low.
