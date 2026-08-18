# Deriving Security Requirements from an AWS Serverless Sample, Part 6: Refreshing Requirements and Preserving Their Lifecycle

After the initial requirements have been generated, the next challenge is keeping them trustworthy as the service changes.

This stage asks:

> When Lambda functions, APIs, data classifications, or operating conditions change, how can the requirements be re-derived without losing previous approvals, exceptions, evidence, or audit history?

Refreshing requirements is not the same as replacing an old document with newly generated output. It is a controlled merge between the changed system and the existing security contract.

```text
changed repository and operating context
                  +
existing requirements, human decisions, and history
                  ↓
reviewable profile and requirement delta
                  ↓
confirmed and validated updated security contract
```

---

## 1. Detect the changes

The plugin scans the repository again and compares the new `inferred` profile with the stored version.

Suppose the movie service has evolved in the following ways:

- Amazon Cognito authentication has been added.
- A `POST /ratings` API has been introduced.
- User accounts and email addresses are now stored.
- An external analytics provider has been added alongside CloudWatch.
- DynamoDB Streams and an SQS consumer now process ratings asynchronously.
- A paid subscription makes outages directly affect revenue.
- The storage region has been confirmed as `ap-northeast-2`.

The plugin does not repeat the original seven-question interview from the beginning. It asks only about genuinely new or changed facts that cannot be established from repository evidence.

Examples include:

- Which data is sent to the analytics provider?
- Can a device identifier be linked to a user account?
- Are SQS messages safe to process more than once?
- Does the new subscription create a contractual availability obligation?
- Are Korean users now in scope?

---

## 2. Show the profile delta explicitly

The existing and refreshed profiles are compared before any new requirement is written.

```diff
 auth_mechanism:
-  UNDETERMINED
+  oidc_cognito

 data_types:
   - public_content
+  - basic_contact
+  - account_credentials

 availability:
-  amplifiers: []
+  amplifiers: [revenue_direct]

 external_integrations:
+  - name: analytics-provider
+    data_sent: [device_identifier]

 region_storage:
-  UNDETERMINED
+  ap-northeast-2
```

This is not a cosmetic documentation update. Every changed field can alter a downstream security decision.

| Profile change | Possible consequence |
|---|---|
| Authentication becomes Cognito | Anonymous and authenticated trust boundaries can be modeled precisely |
| Email addresses are stored | Confidentiality increases and the Privacy baseline may apply |
| Device identifiers leave the boundary | LINDDUN and third-party processing analysis may be required |
| Revenue depends on availability | Availability increases to at least Moderate |
| Storage region becomes known | Cross-border and jurisdiction checks can run |
| SQS processing is introduced | Replay, duplication, and message-scope threats appear |

Showing the delta allows the owner to review the causes rather than only the resulting requirements.

---

## 3. Invalidate the old profile approval

Profile approval is bound to the exact profile content through a digest.

```text
previous profile digest
        ≠
refreshed profile digest
        ↓
previous approval becomes invalid
        ↓
impact is recalculated and the owner confirms again
```

A repository file containing `confirmation: confirmed` is not sufficient evidence of approval. Repository content is untrusted input and could copy or fabricate that field.

The plugin verifies approval against matching plugin-owned state outside the inspected repository. Any profile change invalidates the stored digest and requires explicit confirmation.

This prevents a changed architecture from silently continuing under an approval granted for a different service profile.

---

## 4. Recalculate CIA impact and baseline scope

Adding user email addresses and accounts changes confidentiality and privacy scope. Making the service revenue-producing changes availability.

An illustrative recalculation is:

```text
Before:
  C=Low, I=Moderate, A=Low
  System=Moderate

After:
  C=Moderate, I=Moderate, A=Moderate
  System=Moderate
```

The system high-water mark remains Moderate, so the named security baseline does not change. The resulting requirement scope still changes materially:

- The Privacy baseline is now added.
- Privacy-related PT and PM controls enter the selected set.
- A LINDDUN privacy pass is now required.
- Log-sanitization requirements become more important.
- The analytics transfer requires third-party boundary analysis.
- User regions may trigger GDPR or ISMS-P overlays.

This illustrates an important point:

> An unchanged system impact level does not imply an unchanged requirement set.

The high-water mark chooses the Low, Moderate, or High security baseline. Data types, privacy status, external flows, regulatory triggers, and service shape affect additional layers independently.

---

## 5. Update the threat model incrementally

Existing threat identifiers remain stable. The plugin adds new components, flows, boundaries, and threats without renumbering the old model.

```text
Existing boundaries
  TB-1  Internet → API Gateway
  TB-2  API Gateway → Lambda
  TB-3  Lambda → DynamoDB

New boundaries
  TB-6  User → Cognito
  TB-7  Lambda → external analytics provider
  TB-8  DynamoDB Streams → SQS consumer
```

The new architecture can introduce threats such as:

- Incorrect association between a Cognito identity and a movie-service account
- Re-identification caused by sending both device and account identifiers to analytics
- Duplicate rating application when an SQS message is processed more than once
- Missing user or tenant scope in an asynchronous message
- Analytics data retained after the corresponding account is deleted
- A revoked account continuing to consume queued work

Existing threats T-01 through T-08 are not deleted merely because their triggering code has changed.

If a threat has been resolved, its record can remain with a resolution status and evidence. If another requirement replaces it, the lifecycle records the `superseded_by` relationship.

The history must answer why an item disappeared from the active work set.

---

## 6. Apply newly relevant regulatory overlays

Adding personal data and user regions can change which overlays are potentially applicable.

```text
Korean users + personal data
  → ISMS-P overlay candidate

EU or EEA users + personal data
  → GDPR overlay candidate
```

The plugin does not make the final legal determination. It reports that the confirmed profile triggers the overlay's applicability conditions and identifies regulatory clauses that the selected NIST controls do not reach.

For example, an analytics flow may create requirements concerning:

- Processing purpose
- User notice
- Retention and deletion
- Processor obligations
- Cross-border transfer
- Data-subject rights

These duties may not be fully expressible through the original Moderate security baseline.

Every overlay report retains its limitations: the mapping is this repository's interpretation unless an authoritative published crosswalk is available, and it does not establish compliance.

---

## 7. Classify each requirement change

The refreshed derivation does not overwrite the previous document. It classifies the delta.

```text
added
  A new requirement introduced by the changed service

proposed
  A change to an existing reviewed requirement awaiting human approval

superseded
  An old requirement replaced by another requirement

retired
  No longer active, but retained with its history and reason

unchanged
  Re-derived with no managed change

exception_expiring
  An approved exception approaching its expiry date
```

An example refresh report might be:

```text
added        4
proposed     2
superseded   1
retired      1
unchanged    8

expiring exceptions
  REQ-IAM-LAMBDA-SCOPE-01
  expires: 2026-12-31
```

The classifications make the refresh reviewable. A reviewer can focus on the changed security contract rather than rereading the entire generated document.

---

## 8. Preserve human edits and approved exceptions

The `human` block is never overwritten by automatic refresh.

```yaml
human:
  status: exception
  exception:
    approver: service-owner
    reason: temporary migration dependency
    expires: 2026-12-31
```

Suppose the refreshed derivation wants to change the managed statement of that requirement. Because the record contains human-owned content, the new statement is not applied automatically.

It is placed under `pending_review` instead:

```yaml
pending_review:
  statement: >-
    The newly proposed requirement statement reflecting the changed service.
  why: >-
    User personal data and an external analytics flow were added to the profile.
```

A person decides whether to accept the proposed change.

This rule prevents a common lifecycle failure:

1. The tool generates a requirement.
2. A security reviewer adapts it to the actual architecture.
3. A named owner approves a temporary exception with an expiry date.
4. The service changes and the plugin runs again.
5. Regeneration erases the review and exception.

The fifth step must never happen.

---

## 9. Keep requirement identifiers stable

New requirements do not cause existing identifiers to be renumbered.

```text
Existing:
  REQ-API-WRITE-AUTHN-01
  REQ-API-WRITE-AUTHZ-01

Added:
  REQ-PRIVACY-ANALYTICS-LINK-01
```

The issued-ID ledger in `state.yaml` remembers previously assigned identifiers and reuses them on subsequent runs.

Stable IDs protect:

- Existing development tickets
- Evidence attachments
- Exception approvals
- Audit reports
- Architecture-review decisions
- External references from other tools

A sequence such as `REQ-001`, `REQ-002`, and `REQ-003` is unsafe if inserting one item shifts everything below it.

---

## 10. Invalidate stale semantic reviews

An independent semantic review is bound to a digest of the complete `managed` block.

```text
requirement statement or verification changes
                  ↓
managed digest changes
                  ↓
existing semantic review becomes stale
                  ↓
independent review is required again
```

Even an apparently small edit may change the meaning or verification boundary of a requirement. The plugin therefore does not preserve semantic approval merely because the requirement ID stayed the same.

The ID identifies the continuing obligation. The digest identifies the exact reviewed version of that obligation.

---

## 11. Run linting, overlays, and rendering again

Refreshed requirements must pass the same quality gates as the original document.

The checks include:

- Valid control identifiers
- Valid threat references
- Supported verification-method enums
- Complete expected verification results
- Vague operative language
- Compound obligations
- Locale consistency
- Sensitive resource identifiers in publishable fields

Every newly applicable regulatory overlay is rerun against both the selected controls and the refreshed requirements.

Publication is blocked if an overlay, lint, or rendering step fails.

The plugin does not publish a partially refreshed contract in which the profile changed but traceability, responsibility, or regulatory coverage remained stale.

---

## 12. Produce a change report

The final output includes not only the new document but also an explanation of what changed and why.

```text
Profile changes
  Cognito authentication added
  basic_contact data added
  analytics provider added
  revenue_direct availability amplifier added

Impact
  C: Low → Moderate
  I: Moderate → Moderate
  A: Low → Moderate
  System: Moderate → Moderate

Scope changes
  Privacy baseline now applies
  LINDDUN pass now required
  ISMS-P overlay triggered for review

Requirements
  added        4
  proposed     2
  superseded   1
  unchanged    8
```

The report should also identify:

- Services with unverified responsibility mappings
- Remaining `UNDETERMINED` profile fields and their consequences
- Regulatory triggers with no supported overlay
- Overlay clauses that remain a gap rather than an intentional deferral
- Exceptions approaching expiry
- Semantic reviews made stale by managed changes

---

## What Part 6 established

The central lesson is:

> Regenerating security requirements is not replacing the old document with the latest output. It is safely merging a changed system with an existing audit history.

Without lifecycle controls, rerunning a requirements generator can cause serious failures:

- Security-reviewer edits disappear.
- Approved exceptions and expiry dates are erased.
- Changed IDs make existing tickets point to the wrong obligations.
- Resolved requirements vanish without an explanation.
- Modified requirements retain approval granted to an older version.
- New personal-data flows remain hidden behind an unchanged Moderate baseline.
- Regulatory and responsibility reports no longer match the current architecture.

Part 6 makes the security contract trustworthy over time, not only at the moment of its initial generation.

The complete lifecycle is now:

```text
profile
  → impact and baseline
  → threat model
  → responsibility and prioritization
  → requirement authoring and validation
  → controlled refresh and lifecycle management
```

That lifecycle turns a generated checklist into a durable, reviewable security contract for design, implementation, and assurance work.
