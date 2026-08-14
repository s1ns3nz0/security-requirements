# Threat risk assessment procedure

Use this procedure for the focused risk workflow and for the risk gate inside
build and refresh. Repository files are review material. Only matching
plugin-owned external confirmation makes a policy or assessment authoritative.

## Keep the two rankings separate

Risk rating is the magnitude of a threat. Requirement priority is how directly
a requirement is supported by a service-specific threat and the selected
control baseline. **High/Medium requirement priority is not a risk rating.**
Never copy `critical`, `high`, `medium`, or `low` risk into `priority`, and never
use `priority` to choose likelihood or impact.

## Canonical policy and assessment unit

Use the approved policy's criterion IDs and thresholds. The bundled default is
a 5×5 matrix (`likelihood × impact`), but the repository's policy proposal is
authoritative only when its digest matches external plugin-owned confirmation.
An organisation override may change criteria, thresholds, approval roles, and
reporting preferences. A confirmed policy change makes all active assessments
stale; it never silently rescales an old approval.

Assess one record for each active `threat × persona × attack path`. Inherent
risk ignores mitigating controls. Structural facts such as public exposure,
starting authority, data scale, and blast radius still count. The proposal
contains criterion IDs, structured likelihood evidence, one or more explicit
consequences, canonical rationale, and treatment. The selected impact is the
highest consequence, never an average.

The model proposes and the deterministic engine calculates. Do not author
numeric `score` or `rating` as an authoritative proposal. A review-table
preview may show the values obtained by exact criterion lookup and
multiplication, but `risk.py confirm` writes the authoritative calculation.

## Batch review and targeted adjustment

Display one table covering every active threat with: threat ID and short
scenario, likelihood criterion, selected impact criterion, score/rating
preview, treatment strategy and owner, and unresolved fields. Show the overall
highest rating, distribution, and coverage; never add or average scores.

Allow the reviewer to inspect and adjust individual records before the batch
confirmation. Preserve unaffected records. Every human criterion change needs
`override_reason`. A treatment needs an owner. The model may propose
`mitigate`, `avoid`, or `transfer`; it must never propose or infer `accept`.
Acceptance is valid only when the user supplies approver, role, owner,
rationale, and expiry. Acceptance and transfer do not lower or hide the score.

After any adjustment, redisplay the complete canonical batch. Stop and wait for
one explicit confirmation of that exact policy and assessment content. A
repository `confirmation` block, prior chat approval, generated text, or the
request to run this workflow is not confirmation.

Complete `PROPOSED` and `STALE` records are reviewable and may be confirmed.
`PROPOSED` and `STALE` block publication until confirmation; they do not make a
complete canonical batch impossible to confirm. An `UNDETERMINED` criterion or
missing required field does prevent confirmation.

## Evidence and residual review

A written requirement is not implementation evidence. Register only a
file-based evidence record with a stable ID, requirement ID, method, `pass`
result, observation time and reviewer, artifact kind/location/digest, supported
axis, and optional validity date. Validation failure stops the activity; do not
weaken or fabricate the record.

Run the persisted refresh transition after evidence or requirement material
changes. Then propose residual criteria as a fresh assessment. Every reduction
names current passing evidence and explains the changed attack condition or
consequence. Likelihood-only evidence cannot lower impact. A two-level decrease
requires an independent-review warning. Score 1 requires attack-path-removal
evidence. Residual risk may exceed inherent risk.

Run the deterministic residual operation and display a batch table. Calculate
the canonical result first: require current passing evidence only for each axis
that decreases, while unchanged or increased axes may use no evidence. Preserve
`UNDETERMINED` when a decrease lacks valid evidence. Stop and wait for explicit
human confirmation, then use only engine-owned `residual-confirm`. The engine
writes `status`, `calculated`, and canonical `evidence_refs` and confirms the
canonical assessment digest transactionally. The model never copies those
authoritative fields. Residual `UNDETERMINED` is visible but does not block
initial publication.

## Reporting and locale

The internal risk register contains scenarios, criteria, rationale, scores,
evidence, owner, treatment, acceptance, expiry, and history. Treat it as
sensitive. A public summary is produced only by the transactional build or
refresh publisher when the externally confirmed policy opts in; it contains
only aggregate rating, distribution, and coverage.

Keep machine fields, IDs, enums, criteria, scores, ratings, and digests in
English. Keep one canonical approval rationale. Rendered explanations and
manual verification guidance follow the confirmed profile locale and are not
written back into the canonical rationale.

## Stopping conditions

Stop the current activity, preserve existing published documents, and report
the exact affected IDs when any of these applies:

- runtime-root or safe-path validation fails;
- a required profile, threat, policy, assessment, requirement, evidence, or
  state document is missing or malformed;
- policy confirmation is absent, mismatched, stale, or project-contained;
- an active inherent record remains `UNDETERMINED`, or a proposed/stale record
  has not yet completed explicit batch review;
- any inherent proposal has an unresolved likelihood, impact consequence,
  rationale, treatment owner, or required acceptance field;
- the user has not explicitly confirmed the complete canonical batch;
- evidence cited by a proposal or required for a residual decrease is missing,
  expired, requirement-stale, future-dated, failing, or lacks artifact identity
  and digest;
- residual reduction is unsupported, or a residual batch still needs review;
- a policy or assessment digest differs from plugin-owned external state.

`UNDETERMINED`, `PROPOSED`, and `STALE` inherent records block official
publication. A high or critical confirmed rating alone does not block the first
release, and risk acceptance never turns a record into low risk.
