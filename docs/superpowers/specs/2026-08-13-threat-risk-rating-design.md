# Threat Risk Rating Design

## Goal

Extend `security-requirements` from threat identification and requirement
prioritisation into a complete, reviewable risk-assessment workflow. Each
active threat receives an evidence-backed 5×5 inherent-risk proposal, a human
confirmation gate, a treatment decision, and—only after implementation
evidence exists—a separately confirmed residual-risk assessment.

Risk rating must remain distinct from the existing requirement priority:

- risk rating describes the magnitude of a threat;
- requirement priority describes how directly a requirement is supported by a
  service-specific threat and the selected control baseline.

The first release uses risk ratings for ordering and reporting. It does not
block publication merely because a confirmed rating exceeds an organisation's
risk appetite. Inherent-risk confirmation itself is a publication gate.

## Success criteria

- Every active threat can be assessed with a reproducible 5×5 policy.
- The model proposes criteria and rationale but cannot confirm its own scores.
- Repository content alone cannot forge policy or assessment approval.
- Every score refers to a policy criterion and carries structured evidence.
- Inherent risk is assessed without credit for mitigating controls.
- Residual risk remains `UNDETERMINED` until valid implementation evidence
  exists; a written requirement is not evidence of implementation.
- Risk acceptance does not reduce or conceal the risk rating.
- Overall rating uses the highest active threat, accompanied by distribution
  and assessment coverage rather than an additive total or average.
- Detailed risk information remains internal. Public risk summary generation
  is opt-in.
- Existing threat schema `0.1.0` projects migrate without changing prior
  published documents or fabricating confirmed scores.
- Claude and Codex expose equivalent risk workflows over one deterministic
  shared engine.

## End-to-end workflow

```text
repository evidence
    -> service profile
    -> profile confirmation
    -> FIPS 199 impact and 800-53B baseline
    -> data-flow diagram
    -> STRIDE and conditional LINDDUN threats
    -> inherent-risk proposals
    -> human risk confirmation gate
    -> responsibility classification
    -> threat × baseline cross
    -> requirement authoring, lint, and render
    -> implementation evidence registration
    -> residual-risk proposals
    -> human residual-risk confirmation
```

The threat-model procedure continues to derive threats per boundary crossing,
then expands them by persona and attack path. Risk evaluation is inserted after
threat recording and before official requirement publication.

## Risk policy

The bundled default is a semi-quantitative 5×5 model:

```text
risk score = likelihood × impact
```

| Score | Rating |
|---:|---|
| 1–4 | low |
| 5–9 | medium |
| 10–16 | high |
| 17–25 | critical |

The default criteria are technology-neutral and have stable IDs.

### Likelihood criteria

| ID | Score | Definition |
|---|---:|---|
| `L1-EXCEPTIONAL` | 1 | Requires multiple independent, exceptional preconditions. |
| `L2-RESTRICTED` | 2 | Requires restricted access and non-trivial preconditions. |
| `L3-AUTHENTICATED` | 3 | Requires ordinary authenticated or internal access. |
| `L4-PUBLIC-LOW-COMPLEXITY` | 4 | Reachable from a public surface with low complexity. |
| `L5-DIRECT-AUTOMATABLE` | 5 | Directly reproducible without an effective control and readily automated. |

### Impact criteria

| ID | Score | Definition |
|---|---:|---|
| `I1-LOCAL-RECOVERABLE` | 1 | Localised and immediately recoverable effect. |
| `I2-LIMITED-SCOPE` | 2 | Limited users or records with routine recovery. |
| `I3-CORE-SERVICE` | 3 | Core service function or a broad record set is materially affected. |
| `I4-CROSS-SYSTEM` | 4 | Account-wide, cross-system, prolonged, contractual, or regulated effect. |
| `I5-ORGANISATION-IRREVERSIBLE` | 5 | Organisation-wide compromise, irreversible harm, or safety impact. |

The policy may include non-binding anchors such as “an anonymous unprotected
write path merits consideration of L5.” Anchors produce warnings, never an
automatic score. The calculator performs no hidden weighting.

An optional project proposal at `.security-requirements/risk-policy.yaml` may
override criteria, descriptions, thresholds, permitted approval roles, and
reporting preferences. A policy proposal becomes authoritative only after
human confirmation writes a matching digest-bound record outside the inspected
repository. Without an approved override, the bundled default policy applies
and reports that organisation-specific appetite is not configured.

Any policy change recalculates all scores and invalidates assessment approval.

## Assessment unit and threat schema

Risk is assessed per `threat × persona × attack path`. The same weakness is
split when personas have materially different access conditions or
consequences. Related records may share a `risk_family`, but their scores are
not averaged or summed.

Threat schema version advances to `0.2.0`. Existing required fields remain:

```yaml
boundary: TB-1
category: STRIDE:T
novelty: service_specific
persona: anonymous_external
scenario: "..."
affected_assets: [movie_records]
related_controls: [AC-3]
```

The schema adds lifecycle and attack-path identity without embedding
human-owned risk approval in the model-owned threat record:

```yaml
id: T-03
risk_family: RF-UNAUTHORISED-MUTATION
attack_path: public_write_route
lifecycle:
  status: active                 # active | retired | superseded
  superseded_by: []
```

`mitigate` and a Low residual rating leave a threat active. A threat is retired
only when the feature, flow, or trust boundary that creates the attack path has
been removed and that removal is evidenced and confirmed. Supersession names
the replacement threat IDs. Records and history are never deleted.

## Inherent-risk assessment

Inherent risk ignores the effectiveness of mitigating controls, including
controls already visible in source. It does reflect structural facts such as
public exposure, required starting authority, data scale, and blast radius.

The model proposes a criterion and structured evidence for likelihood. Impact
is based on one or more explicit consequences:

```yaml
assessments:
  - threat_id: T-03
    proposed:
      likelihood:
        criterion: L5-DIRECT-AUTOMATABLE
        evidence:
          exposure: public
          access_required: none
          exploit_complexity: low
          preconditions:
            - "A write route reaches the handler without an observed authorisation decision."
          observed_controls: []
        rationale:
          - "Anonymous callers can reach the write interface."
      consequences:
        - id: C-01
          asset: movie_records
          axis: integrity
          criterion: I3-CORE-SERVICE
          affected_scope: all_records
          recoverability: recoverable_from_backup
          rationale:
            - "An attacker can alter the primary catalogue."
      impact:
        selected_from: C-01
      treatment:
        strategy: mitigate
        owner: service-team
        status: planned
```

Impact is the high-water mark of confirmed consequences, never an average. A
consequence that expands beyond the profiled service may exceed the service's
FIPS 199 impact, but it must record `scope_expansion` and concrete evidence.
An unresolved highest consequence makes impact `UNDETERMINED`.

The deterministic engine resolves criterion IDs to numeric values, multiplies
them, and supplies `score` and `rating`. The model does not write authoritative
numeric results. A human adjustment requires an `override_reason`.

At this gate the human confirms the treatment strategy and owner, but not
requirement IDs that have not yet been issued. After requirement authoring,
the deterministic cross step populates `requirement_refs`; linkage validation
must pass before publication. A generated linkage cannot change the confirmed
inherent score, strategy, or owner. A human change to strategy or owner makes
the treatment decision stale.

All active threats must have confirmed inherent risk before official
publication. `UNDETERMINED`, `PROPOSED`, or `STALE` blocks publication and
names the affected threat IDs.

## Confirmation and trust boundary

Risk approval follows the existing anti-forgery confirmation pattern.

The repository copy contains reviewable assessment content, confirmation
metadata, and an assessment digest. Plugin-owned state outside the inspected
project contains the authoritative matching record, including:

- project identity;
- threat digest;
- policy digest;
- assessment digest;
- confirmer identifier and time;
- external-attestation metadata when supplied.

Approval succeeds only when all digests and both copies match. Repository
content cannot select an authoritative state path inside the project, invoke
approval, or declare itself confirmed. Writes use the existing safe-path and
atomic-write contracts.

The local plugin records identity but does not claim to authenticate it.
Approval authority is represented as `self_declared` or
`externally_attested`. Organisation policies may restrict declared roles, but
actual identity validation belongs to an external review, IAM, or signed CI
system.

Risk acceptance requires approver, role, owner, rationale, and expiry. All
treatment strategies are confirmed at the risk gate. `accept` additionally
requires the acceptance metadata and can never be proposed or approved by the
model alone.

## Treatment model

Supported strategies are:

- `mitigate`: implement controls that reduce likelihood or impact;
- `avoid`: remove the feature or attack path;
- `transfer`: assign some responsibility through contract, insurance, or a
  provider without implying that risk disappears;
- `accept`: explicitly retain residual risk under time-bound human approval.

Treatment status is incomplete without an owner. Neither `accept` nor
`transfer` changes the score. Accepted risk remains present in individual and
overall ratings, with acceptance shown as a separate state. Expired acceptance
becomes unresolved.

The threat-level risk assessment becomes the authoritative acceptance record.
Requirements refer to it with `risk_refs`; they do not maintain a second
approval ledger. Existing requirement exceptions are preserved and proposed
for migration through `pending_review`, never silently moved.

## Evidence and residual risk

Requirements describe how to verify a property; they do not prove that the
property is implemented. Residual risk requires a separate evidence record:

```yaml
evidence:
  - id: EVID-AUTHZ-INTEGRATION-01
    requirement_id: REQ-WRITE-AUTHORIZATION-01
    method: test_case
    result: pass
    observed_at: "2026-09-10T09:00:00Z"
    observed_by: security-reviewer
    artifact:
      kind: test_report
      location: internal-ci-artifact
      digest: "sha256:..."
    valid_until: "2026-12-10"
```

Only substantiated `pass` evidence supports a residual-risk reduction. Missing
artifact identity or digest marks evidence unsubstantiated. Evidence becomes
stale when it expires or its requirement changes. Manual evidence is allowed
but must name its reviewer and observation; reports retain the method.

Residual risk is a fresh criterion-based assessment, not a fixed subtraction
from inherent risk. Every reduction names evidence and explains which attack
condition or consequence changed. Likelihood-only controls do not lower
impact. Impact falls only when evidence demonstrates reduced consequence or
blast radius. A reduction of two or more levels triggers an independent-review
warning. A score of 1 requires evidence that the attack path was removed.

Residual risk may exceed inherent risk if implementation introduces a new
attack surface or reveals a larger consequence. Until sufficient evidence
exists, residual status is `UNDETERMINED`; this does not block initial
publication.

The first release supports file-based evidence registration and validation.
Direct CI or identity-provider integration is a future extension.

## Aggregation, ordering, and reporting

No total risk score and no average are produced. Overall inherent and residual
ratings use the highest confirmed active threat. Reports always include the
rating distribution and assessment coverage:

```yaml
risk_summary:
  inherent:
    overall: high
    status: confirmed
    coverage: 8/8
    counts: {critical: 0, high: 5, medium: 3, low: 0}
  residual:
    overall: UNDETERMINED
    confirmed: 0
    undetermined: 8
```

Incomplete active-threat coverage makes overall status provisional. Retired
and superseded threats remain in history but are excluded from the current
rating.

Requirements retain the existing `priority` field and add `risk_refs` plus a
derived display-only `risk_exposure`. They are ordered:

```text
critical
unresolved: UNDETERMINED, STALE, PROPOSED
high
medium
low
then requirement priority and stable requirement ID
```

Risk assessment history is immutable. Delta reporting shows new, increased,
decreased, stale, retired, and acceptance-expired risks plus changes in rating
distribution. It does not sum independent scores.

## Storage and publication

```text
.security-requirements/
  threats.yaml
  risk-policy.yaml
  risk-assessment.yaml
  risk-evidence.yaml
  risk-state.yaml
  reports/
    risk-register.md

docs/security/
  risk-summary.md             # opt-in only
```

The internal register includes scenarios, criteria, rationale, inherent and
residual scores, evidence, owner, treatment, acceptance, expiry, and stale
state. It is sensitive and never published by default.

The optional public summary contains only overall rating, distribution, and
coverage. It excludes attack paths, unimplemented-control detail, owners,
acceptance rationale, expiry, and internal artifact locations. Publication
requires explicit `publish_risk_summary: true` in the approved policy.

Machine fields, enums, IDs, criteria, scores, ratings, and digests remain in
English. Assessment records retain one canonical rationale used by approval;
rendered translations are derived presentation fields and are excluded from
the digest. Human-readable reports, treatment explanations, and manual
verification guidance follow the profile locale. Changing locale alone does
not change calculations or approval digests, while changing canonical
rationale does.

## Engine and host workflow

A single deterministic `scripts/risk.py` owns risk semantics:

```text
propose     validate and normalise proposal structure
calculate   map criteria to scores and ratings
confirm     write digest-bound external approval
check       enforce the build gate
register    render the internal risk register
summary     render the opt-in public summary
evidence    validate and register implementation evidence
residual    validate residual proposals against evidence
migrate     create unconfirmed risk structures for legacy projects
```

The model authors threats, proposes criterion selections and rationale, and
suggests non-acceptance treatment. The engine validates schemas, performs
arithmetic, calculates digests, manages state, and renders deterministic
outputs. The human confirms assessments and all treatment decisions.

A fourth host workflow is added:

- Claude: `/security-requirements:sec-req-risk`;
- Codex: `security-requirements-risk` skill.

It supports assess, show, adjust, evidence, residual, and policy activities.
Both thin adapters execute the same shared skill and `risk.py`. Existing build
and refresh workflows call `risk.py check` and stop with actionable guidance
when inherent assessment is incomplete.

## Review UX

The workflow first displays a batch table with every threat, proposed
likelihood, impact, score, rating, and unresolved field. A user may inspect or
adjust individual threats, with reasons required for changes, then confirms one
canonical assessment digest.

`UNDETERMINED` fields prevent batch confirmation. Changing one threat makes the
overall assessment stale, but unchanged individual records are reused to limit
the next review to affected threats. The same pattern applies to residual risk.

## Refresh and lifecycle behavior

- Changes to scenario, boundary, persona, attack path, or affected assets
  invalidate inherent-risk confirmation for that threat.
- Changes to related controls invalidate residual-risk confirmation.
- Policy changes recalculate and invalidate all assessments.
- New threats enter as `PROPOSED` and make overall status provisional.
- Removed attack paths produce retirement proposals; they are never deleted.
- Reopened threats reuse stable IDs but do not restore old approval.
- Human rationale, owner, treatment, acceptance, and evidence are never
  overwritten. Competing generated changes land in `pending_review`.
- Every confirmation creates an immutable snapshot for delta reporting.

## Legacy migration

Threat schema `0.1.0` remains readable and is labelled `legacy_unassessed`.
Existing published documents are preserved. On the next refresh, the workflow
offers a deterministic migration that creates `risk-policy.yaml`,
`risk-assessment.yaml`, and state scaffolding with every score `PROPOSED`.

Migration does not invent, confirm, or overwrite numeric assessments. Only
after human risk confirmation does the project record threat schema `0.2.0`
and resume official publication. Existing requirement exceptions remain in
place until their proposed threat-level migration is reviewed.

## Transactional publication

Build and refresh create all prospective outputs in a staging directory. They
validate profile, threats, policy, assessment digests, active-threat coverage,
requirements, references, internal register, and optional public summary
before replacing publishable files.

Any failure preserves the previous `docs/security/` exactly. Internal proposals
may remain with explicit `PROPOSED` or `STALE` status. Initial publication
requires confirmed inherent risk for every active threat; undetermined
residual risk is allowed. Expired acceptance makes its risk unresolved.

## Validation rules

The risk engine and linter reject:

- unknown criterion IDs;
- criterion and numeric-score disagreement;
- direct model-authored authoritative score or rating;
- empty rationale or required evidence fields;
- a numeric value standing in for `UNDETERMINED` facts;
- consequence selections that are not the high-water mark;
- service-impact expansion without scope evidence;
- residual reduction without valid evidence;
- expired or requirement-stale evidence used as current;
- acceptance without approver, role, owner, rationale, and expiry;
- repository-only confirmation or project-contained authoritative state;
- leaked internal risk fields in public outputs.

Where file-and-line repository evidence is possible but absent, validation
warns rather than fabricating a citation. A human score override requires a
reason. Acceptance and external authority are never inferred.

## Verification strategy

Tests cover:

1. Every rating boundary: 1/4, 5/9, 10/16, and 17/25.
2. Criterion lookup, rationale requirements, canonical calculation, and stable
   digest output.
3. Active-threat confirmation coverage and hard-gate behavior.
4. Threat and policy changes making appropriate approvals stale.
5. Rejection of repository-only or project-contained approval state.
6. Separation of risk rating and requirement priority.
7. Highest-rating aggregation, distribution, provisional status, and ordering.
8. Evidence validity, expiry, requirement drift, and residual reassessment.
9. Acceptance that does not alter scores, plus role and expiry checks.
10. Active, retired, superseded, and reopened threat lifecycle with stable IDs.
11. Transactional build/refresh failure preserving previous public documents.
12. Internal register redaction and opt-in-only public summary.
13. Safe migration from threat schema `0.1.0` to `0.2.0`.
14. Claude and Codex risk adapters resolving the same immutable shared engine.
15. Paths containing spaces and Unicode, hostile cwd/module shadowing, and
    symlink or junction redirects.
16. Full existing regression suite and both host distribution validators.
17. Current-head clean-install host discovery and safe risk-workflow execution.
18. The movie-rating example with eight inherent proposals, batch confirmation,
    overall distribution, undetermined residual risk, an internal register,
    and opt-in summary verification.

Implementation is complete only when these tests and host validations pass and
the prior init, build, and refresh behavior remains intact.

## Deliberate non-goals for the first release

- Enforcing organisation-specific appetite as a publication-blocking threshold.
- Automatically scoring natural-language evidence.
- Fixed arithmetic reductions for named controls.
- Direct CI, corporate IdP, or cryptographic-signature integration.
- Treating local identity strings as authenticated approval.
- Publishing detailed attack paths or accepted-risk records.
- Adding or averaging scores into a portfolio-wide total.
