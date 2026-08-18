# Deriving Security Requirements from an AWS Serverless Sample, Part 5: Authoring, Validating, and Publishing the Requirements

Part 4 converted the selected control set and eight service-specific threats into an owned and prioritized work list. The next stage turns that work into the artifact the delivery team will actually use: a set of stable, atomic, verifiable security requirements.

This is not a matter of copying NIST control text into Markdown. A useful requirement must explain what must be true for this service, why it matters, who must act, and how a reviewer can decide whether it is satisfied.

```text
prioritized work list
        ↓
atomic requirement records
        ↓
merge with human decisions and prior state
        ↓
lint and reference validation
        ↓
publishable security contract
```

---

## A control, a threat, and a requirement are different things

The three artifacts serve different purposes.

```text
Control
  → a general security objective or safeguard

Threat
  → a concrete failure scenario for this service

Requirement
  → a testable property the service must satisfy
```

For example:

```text
Control:
  Enforce approved authorizations.

Threat:
  An anonymous caller reaches the add-movie operation and changes DynamoDB
  before any authorization decision occurs.

Requirement:
  Every request that changes movie data must be associated with an
  authenticated caller before the DynamoDB operation is invoked.
```

The control supplies traceability. The threat supplies service context. The requirement states the property that can be tested.

---

## The four authoring rules

The plugin applies four rules to every requirement.

### 1. Verifiable

Two competent engineers must be able to reach the same conclusion about whether the requirement is satisfied.

```text
Weak:
  Appropriate authentication must be implemented.

Verifiable:
  Every request that changes movie data must have an authenticated caller
  before the DynamoDB operation is invoked.
```

Words such as `appropriate`, `adequate`, `sufficient`, `secure`, `properly`, and `regularly` do not establish a pass condition.

### 2. Atomic

One requirement should express one obligation.

```text
Not atomic:
  Write operations must authenticate the caller and verify that the caller
  is authorized for the operation.

Atomic:
  REQ-API-WRITE-AUTHN-01 — identify the caller before a write.
  REQ-API-WRITE-AUTHZ-01 — authorize the identified caller for that write.
```

Authentication and authorization often fail independently. Combining them hides partial implementation.

### 3. State a property, not an implementation recipe

The requirement should survive an architecture change.

```text
Implementation recipe:
  Attach a Cognito authorizer named movie-authorizer to every POST route.

Durable property:
  A request that changes movie data must have an authenticated caller before
  the storage operation begins.
```

Cognito may be a suitable implementation, but the confirmed profile still records the authentication mechanism as undetermined. The requirement must not silently make that architecture decision.

The verification block may inspect API Gateway configuration because that is how the current deployment can demonstrate the property.

### 4. Make it executable by the organization described in the profile

The example profile declares no dedicated security function, central identity platform, or established access-review process.

The requirement set must not demand actions by teams that do not exist, such as:

```text
The security function must review movie-service access quarterly.
```

Where an organizational capability is missing, the requirement should state what the current owner can do or identify the missing capability explicitly rather than pretending it already exists.

---

## One threat does not necessarily produce one requirement

Stage 3 produced eight threats, but the authoring result need not contain exactly eight requirements.

T-03 requires both authentication and authorization. They are separate, independently testable properties and therefore become two requirements.

Conversely, two threats may support one requirement when they expose the same underlying property. The mapping is based on obligations, not on preserving a one-to-one count.

For this sample, the high-priority authoring set contains nine requirements:

| Requirement | Primary source |
|---|---|
| No long-lived AWS credentials in application configuration | T-01 |
| Lambda role limited to required actions and the Movies table | T-02 |
| Caller authentication before movie mutation | T-03 |
| Operation-specific authorization before movie mutation | T-03 |
| Input validation before DynamoDB access | T-04 |
| Stable public error response without backend details | T-05 |
| Prohibited sensitive values absent from application logs | T-06 |
| Security audit event for every mutation attempt | T-07 |
| Exact route-and-method matching before operation dispatch | T-08 |

Low-priority baseline work remains in the complete record even though this article focuses on the nine service-specific requirements.

---

## Requirement 1: Remove long-lived credentials from application configuration

T-01 showed that the sample reads AWS access keys from `app_config.json`. The requirement states the prohibited condition directly.

```yaml
- id: REQ-CRED-CONFIG-01
  managed:
    statement: >-
      The deployed application configuration must not contain a long-lived
      AWS access key or secret access key.
    rationale: >-
      Credentials packaged with the function can be disclosed through the
      deployment artifact, a workstation, a backup, or version history and
      then used outside the Lambda execution context.
    threat_refs: [T-01]
    responsibility: team
    team_part: >-
      Remove static credential inputs and obtain AWS credentials from the
      function's execution identity.
    verification:
      method: code_grep
      target: "application configuration and AWS SDK initialization"
      expect: >-
        no configured accessKeyId, secretAccessKey, or equivalent long-lived
        AWS credential input
    priority: high
```

The statement does not require a specific secret scanner or deployment framework. It specifies the property that must hold.

---

## Requirement 2: Constrain the Lambda execution role

T-02 demonstrated how FullAccess policies expand compromise beyond the movie service.

```yaml
- id: REQ-IAM-LAMBDA-SCOPE-01
  managed:
    statement: >-
      The movie Lambda execution role must permit only the AWS actions used by
      the handler and must restrict DynamoDB access to the Movies table.
    rationale: >-
      A dependency or application compromise otherwise gains authority over
      unrelated DynamoDB tables and Lambda resources in the account.
    sources: [AC-6]
    threat_refs: [T-02]
    responsibility: team
    verification:
      method: iac_inspect
      target: "the IAM policies attached to the movie Lambda execution role"
      expect: >-
        no FullAccess managed policy, no unrelated service actions, and a
        DynamoDB resource limited to the Movies table
    priority: high
```

The requirement names the current service boundary—the movie Lambda and Movies table—because those are the assets being protected. It avoids embedding a specific generated ARN in the publishable document.

---

## Requirements 3 and 4: Separate authentication from authorization

T-03 becomes two requirements because identifying a caller and deciding whether that caller may perform an operation are separate concerns.

```yaml
- id: REQ-API-WRITE-AUTHN-01
  managed:
    statement: >-
      Every request that creates, deletes, or changes a movie rating must be
      associated with an authenticated caller before DynamoDB is invoked.
    rationale: >-
      The confirmed profile permits anonymous reads but does not permit an
      anonymous caller to change the movie catalogue.
    threat_refs: [T-03]
    responsibility: team
    verification:
      method: test_case
      target: "each state-changing API operation"
      expect: >-
        an anonymous request receives a 4xx response and produces no DynamoDB
        operation
    priority: high

- id: REQ-API-WRITE-AUTHZ-01
  managed:
    statement: >-
      Every authenticated request that changes movie data must be authorized
      for the requested operation before DynamoDB is invoked.
    rationale: >-
      Authentication identifies a caller but does not establish permission to
      create, delete, or change ratings.
    sources: [AC-3]
    threat_refs: [T-03]
    responsibility: team
    verification:
      method: test_case
      target: "each state-changing API operation using a read-only identity"
      expect: >-
        the request receives a 4xx response and produces no DynamoDB operation
    priority: high
```

The requirements do not choose Cognito because the profile does not yet establish an authentication mechanism. The missing architecture decision remains visible.

---

## Requirement 5: Validate input before storage access

T-04 concerned both malformed persistent data and resource consumption. The atomic property here is the validation boundary: unaccepted input must not reach DynamoDB.

```yaml
- id: REQ-INPUT-DDB-BOUNDARY-01
  managed:
    statement: >-
      A movie API request that violates the declared field type, length, range,
      required-field, path, or method schema must be rejected before any
      DynamoDB operation occurs.
    rationale: >-
      The handler currently converts request fields directly into DynamoDB
      parameters, allowing malformed data and avoidable backend consumption.
    sources: [SI-10]
    threat_refs: [T-04]
    responsibility: team
    verification:
      method: test_case
      target: "invalid-type, oversized, out-of-range, incomplete, and undeclared-route requests"
      expect: "each request returns 4xx and makes no DynamoDB call"
    priority: high
```

The list describes dimensions of one schema-validation decision rather than unrelated obligations.

Rate limiting and Lambda concurrency bounds remain separate requirements because they mitigate request volume rather than input validity.

---

## Requirement 6: Define a public error contract

T-05 showed that backend error objects may cross the external trust boundary.

```yaml
- id: REQ-ERROR-PUBLIC-CONTRACT-01
  managed:
    statement: >-
      An external API error response must contain only a documented public
      error code and a correlation identifier.
    rationale: >-
      Returning the backend SDK error object can disclose AWS request details,
      resource information, stack data, and authorization behavior.
    sources: [SI-11]
    threat_refs: [T-05]
    responsibility: team
    verification:
      method: test_case
      target: "the complete HTTP response produced by a forced DynamoDB AccessDenied failure"
      expect: >-
        a public error code and correlation identifier with no SDK error text,
        table identifier, stack trace, IAM detail, or internal path
    priority: high
```

“Do not leak sensitive information” would be difficult to close consistently. The public response shape supplies a positive, bounded contract.

---

## Requirement 7: Keep prohibited values out of logs

T-06 concerned CloudWatch as a separate data destination.

```yaml
- id: REQ-LOG-SENSITIVE-DATA-01
  managed:
    statement: >-
      Application logs must not contain AWS credentials, authentication tokens,
      cookies, or complete request and response bodies.
    rationale: >-
      Logging copies data into a separately accessible and retained store,
      increasing the impact of log-read access.
    threat_refs: [T-06]
    responsibility: team
    verification:
      method: test_case
      target: "CloudWatch logs after requests containing unique sentinel values"
      expect: >-
        no sentinel placed in a prohibited credential, token, cookie, or body
        field is present in the logs
    priority: high
```

The team portion is clear even though the repository lacks a curated CloudWatch service-responsibility mapping. Provider-specific claims remain marked unverified rather than being invented to complete the record.

---

## Requirement 8: Generate application audit events

T-07 showed that platform invocation records are not application audit events.

```yaml
- id: REQ-AUDIT-MOVIE-MUTATION-01
  managed:
    statement: >-
      Every attempted movie creation, deletion, or rating change must produce
      an audit event containing the caller, operation, target record, result,
      event time, and correlation identifier.
    rationale: >-
      Invocation metrics cannot establish who attempted a state change, what
      object was targeted, or whether the application permitted it.
    sources: [AU-2]
    threat_refs: [T-07]
    responsibility: shared
    csp_part: >-
      Provide the managed invocation and logging infrastructure and retain
      applicable provider control-plane records.
    team_part: >-
      Emit the application event for successful and denied mutation attempts.
    verification:
      method: test_case
      target: "one successful and one denied request for each mutation operation"
      expect: >-
        one audit event per attempt with every required field and the matching
        correlation identifier
    priority: high
```

The next requirement set may separately address protection of the audit destination. Generation and write separation are distinct concerns and should not be hidden in one statement.

---

## Requirement 9: Match the complete route and method

T-08 was the `threat only` result: the baseline did not adequately express the sample's exact route-dispatch failure.

```yaml
- id: REQ-ROUTE-EXACT-DISPATCH-01
  managed:
    statement: >-
      The Lambda handler must dispatch an operation only when the complete API
      resource path and HTTP method match a declared operation.
    rationale: >-
      Selecting an operation from only the final path segment allows routes
      governed by different API Gateway policies to resolve to the same
      privileged operation.
    sources: []
    threat_refs: [T-08]
    responsibility: team
    verification:
      method: test_case
      target: "undeclared prefixes and method-and-path combinations for each privileged operation"
      expect: "the request is rejected and no DynamoDB operation occurs"
    priority: high
```

An empty `sources` list is intentional. The requirement exists because the service-specific threat is not adequately represented by the selected baseline. Inventing a control identifier would weaken rather than improve traceability.

---

## Stable identifiers are part of the contract

Requirement IDs are derived from content rather than assigned as a single running sequence.

```text
REQ-CRED-CONFIG-01
REQ-IAM-LAMBDA-SCOPE-01
REQ-API-WRITE-AUTHN-01
REQ-ROUTE-EXACT-DISPATCH-01
```

If the document used `REQ-001`, `REQ-002`, and so on, inserting a new requirement near the beginning could shift every later identifier. Existing tickets, exception approvals, and evidence links would silently refer to the wrong requirement.

The plugin keeps an issued-ID ledger in `.security-requirements/state.yaml` and reuses an ID across refreshes.

Requirements are also not deleted. A requirement that no longer applies transitions to `retired` or `superseded_by`, with a reason. Audit history must be able to explain why an item disappeared from the active set.

---

## Tool-owned and human-owned fields remain separate

Each requirement has a `managed` block and a `human` block.

```yaml
- id: REQ-IAM-LAMBDA-SCOPE-01
  managed:
    statement: "..."
    rationale: "..."
    sources: [AC-6]
    threat_refs: [T-02]
    verification: {method: iac_inspect, target: "...", expect: "..."}
    priority: high

  human:
    status: exception
    exception:
      approver: "service owner"
      reason: "temporary migration dependency"
      expires: 2026-12-31
```

The plugin may update `managed` content when the profile or architecture changes. It must never overwrite exception approvals, status, evidence links, or semantic-review decisions written by a person.

When a refresh proposes a managed-field change to a requirement carrying human content, the proposal goes under `pending_review` rather than replacing the accepted record.

---

## Merge before publication

The newly authored draft is merged with the existing requirements and ID ledger.

```text
draft.json
    + requirements.yaml
    + state.yaml
            ↓
merged requirements.yaml
```

The merge preserves:

- Stable requirement IDs
- Human status and exceptions
- Evidence links
- Existing semantic-review decisions
- Historical transitions

It also records proposed managed changes for review instead of overwriting human decisions.

---

## Linting is a publication gate

Before anything is rendered under `docs/security/`, the linter checks the merged requirements.

The verification method must come from a closed set:

```text
iac_inspect
config_api
code_grep
test_case
artifact_review
manual
```

A value such as `inspect_aws_somehow` fails rather than being treated as documentation. Downstream automation cannot dispatch on an invented method name.

The linter also checks for:

- Missing verification methods or expected results
- Invalid NIST, CSF, and ASVS identifiers
- References to threats that do not exist
- Vague operative language
- Likely compound obligations
- Locale mismatch
- Potential publication of ARNs, URLs, or internal hostnames

Most importantly, a requirement citing a control ID absent from the bundled catalog fails the build. One fabricated identifier can discredit an otherwise sound compliance document.

---

## Trace linkage is not semantic approval

After linting, a requirement may be trace-linked to a valid control and threat. That still does not prove that the prose accurately captures the control or that its verification method tests the statement.

An independent human reviewer advances the requirement to semantic review by recording:

- The exact control links reviewed
- Any exact regulatory-clause mappings reviewed
- Whether the verification method tests the stated property
- Reviewer identity and review time
- A digest of the complete managed block

Any later managed edit changes the digest and makes that approval stale.

```text
authored
  → trace-linked
  → semantically reviewed
  → implemented
  → evidenced
  → assessed
```

This plugin does not infer implementation, evidence, assessment, or compliance from well-written requirement text.

---

## Publish definitions, protect reconnaissance data

After linting succeeds, the plugin renders the reader-facing documents under:

```text
docs/security/
  requirements.md
  traceability.md
  responsibility.md
```

These documents describe the security contract, its sources, and its ownership.

The internal derivation state remains under:

```text
.security-requirements/
  profile.yaml
  threats.yaml
  requirements.yaml
  status.yaml
  state.yaml
```

The internal directory may reveal data locations, trust boundaries, unimplemented controls, accepted risks, and exception expiry dates. It is a reconnaissance document and should not be published merely because the rendered requirement definitions are publishable.

Published free text should name the kind of resource rather than a production instance.

```text
Do not publish:
  arn:aws:dynamodb:...:table/prod-movies-7c91

Publish:
  the DynamoDB table holding movie records
```

The generic description is safer and survives redeployment.

---

## What Part 5 established

This stage transformed the prioritized work list into a reviewable security contract.

It established that:

1. Requirements state testable properties rather than broad security aspirations.
2. Authentication and authorization become separate obligations because they can fail independently.
3. A threat does not need a fabricated control reference; T-08 remains a valid threat-derived requirement with no baseline source.
4. Every requirement carries a verification method, target, expected result, rationale, responsibility, priority, and trace references.
5. Content-derived IDs remain stable across refreshes.
6. Human decisions and exceptions are never overwritten by regeneration.
7. Invalid control IDs, unsupported verification methods, vague language, and unsafe publication details block or warn before rendering.
8. A trace-linked draft remains distinct from semantic review, implementation, evidence, assessment, and compliance.
9. Publishable requirements stay separate from the sensitive internal profile, threat model, status, and risk history.

The next step is refresh and lifecycle management: rerunning the derivation after the architecture changes without losing stable IDs, human edits, approved exceptions, or audit history.
