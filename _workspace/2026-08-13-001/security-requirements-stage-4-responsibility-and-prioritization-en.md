# Deriving Security Requirements from an AWS Serverless Sample, Part 4: Assigning Responsibility and Prioritizing the Work

Part 3 produced eight concrete threats for the movie-rating service. They covered long-lived AWS credentials in configuration, excessive Lambda permissions, anonymous writes, unvalidated input, verbose error responses, sensitive logging, missing audit events, and inconsistent route interpretation between API Gateway and Lambda.

The next problem is not discovering more threats. It is turning the selected controls and those threats into work that somebody can actually own.

This stage answers two questions:

1. Who must act: AWS, the organization, the delivery team, or both AWS and the team?
2. Which controls deserve immediate attention because they address a concrete service-specific threat?

The result is not yet polished requirement prose. It is a prioritized and responsibility-aware work list from which the requirements will be written.

```text
319 selected NIST controls
        +
8 service threats
        +
AWS service responsibility mappings
        ↓
owned and prioritized requirement work list
```

---

## Why responsibility must be resolved before requirements are written

A control can be relevant without belonging entirely to the application team.

Consider encryption at rest for DynamoDB. AWS operates the storage infrastructure and encrypts DynamoDB tables. The delivery team still decides whether key custody requirements call for a customer-managed KMS key and configures the table accordingly.

Calling this control “implemented by AWS” loses the team's half. Calling it entirely a team responsibility ignores what the managed service provides.

The plugin uses four responsibility categories.

| Category | Meaning |
|---|---|
| `team` | The delivery team implements the control in code or configuration |
| `shared` | AWS provides part of the mechanism and the team must configure or operate its part |
| `org` | An organization-wide policy, process, personnel, or governance responsibility |
| `csp_claimed` | AWS claims to perform the control; the customer must obtain and retain evidence |

The fourth category is deliberately called `csp_claimed`, not `inherited`.

> Cloud-control inheritance is a claim that must be supported by evidence, not a fact inferred from the name of a managed service.

---

## Responsibility is resolved from the most specific evidence available

The plugin does not assign every control using a single generic “serverless” rule. It resolves responsibility from the most specific mapping available.

```text
service-specific curated mapping
        ↓ if absent
deployment-model override
        ↓ if absent
control-specific default
        ↓ if absent
control-family default
```

For this sample, curated mappings exist for:

- Amazon API Gateway
- AWS Lambda
- Amazon DynamoDB

The profile also includes CloudWatch Logs, but the repository does not currently contain a reviewed `aws-cloudwatch` service file. Any generated service-specific mapping for it must therefore be labeled `unverified` rather than silently treated as curated provider knowledge.

That distinction matters. A plausible responsibility split is not the same as a reviewed one.

---

## 1. API Gateway responsibility

API Gateway provides the managed entry point, TLS termination, routing machinery, throttling features, and integration with authorizers. It does not decide the movie service's access policy automatically.

### Route authorization: delivery-team responsibility

The curated mapping places access enforcement for API Gateway routes under the team.

```yaml
control: AC-3
responsibility: team
team_part: >-
  Attach an authorizer to every non-public route and leave a route at
  authorization type NONE only when public access is an explicit requirement.
```

This directly affects T-03, the anonymous-write threat.

API Gateway supports authorizers, but merely using API Gateway does not enable one. An open route is created by omission unless the team makes the authorization decision explicit.

The resulting split is:

```text
AWS
  → provides authorizer integration and route-policy machinery

Delivery team
  → declares which routes are public
  → attaches authentication to protected routes
  → verifies operation-specific authorization before mutation
```

### TLS: shared responsibility

For transport protection, AWS terminates TLS on the managed endpoint. The team still chooses the security policy for a custom domain.

```yaml
control: SC-8
responsibility: shared
csp_part: "TLS termination on the managed endpoint"
team_part: "Require TLS 1.2 or higher on the custom domain"
```

The requirement cannot say only “AWS provides HTTPS.” It must state both halves and identify evidence for each.

### Throttling: shared responsibility

API Gateway can absorb and limit traffic, but the default account limits protect the AWS account rather than necessarily protecting the Lambda function and DynamoDB table behind this API.

```yaml
control: SC-5
responsibility: shared
csp_part: "Managed edge capacity and throttling mechanism"
team_part: "Set route and stage rate and burst limits appropriate for the backend"
```

This responsibility is relevant to T-04. Input validation protects the application from malformed data; throttling limits how quickly an attacker can consume execution and storage capacity. Neither replaces the other.

### Error mapping and request validation: team responsibility

API Gateway supplies request validators and response-mapping mechanisms. The team must configure them.

```text
SI-10 → attach schemas or validators to routes
SI-11 → prevent backend error details from reaching clients
```

These controls connect to T-04 and T-05 respectively.

---

## 2. Lambda responsibility

AWS operates the Lambda execution infrastructure, while the delivery team owns the function package, runtime choice, execution role, dependencies, application events, and most application-level security behavior.

### Execution-role permissions: team responsibility

The curated Lambda mapping places least privilege for the execution role under the delivery team.

```yaml
control: AC-6
responsibility: team
team_part: >-
  Use a function-specific execution role scoped to what this function does,
  without wildcard resources in the attached policy.
```

This directly addresses T-02.

AWS issues and operates the temporary role credentials, but it does not know that this function should access only the `Movies` table. The team owns that resource boundary.

### Runtime and dependencies: shared responsibility

AWS patches the managed operating system and supported language runtime. It does not patch dependencies bundled into the deployment ZIP or a Lambda layer.

```yaml
control: SI-2
responsibility: shared
csp_part: "Patch the managed operating system and language runtime"
team_part: >-
  Use a supported runtime and patch the dependencies shipped with the function.
```

This is important for the `compromised_dependency` persona used in T-02. A managed runtime does not make the application dependency chain provider-owned.

### Invocation records versus application audit events

AWS records platform-level information such as invocations and control-plane activity. Those records do not explain what the function did on behalf of which user.

```yaml
control: AU-2
responsibility: shared
csp_part: "Provide invocation metrics and control-plane events"
team_part: >-
  Emit application audit events containing the actor, action, target,
  outcome, and correlation identifier for state-changing operations.
```

This split addresses T-07.

An invocation count proves that Lambda ran. It does not prove who deleted a movie or whose attempt was denied.

### Isolation of the execution environment: provider claim

Isolation of Lambda execution environments is not implemented by the movie-service team.

```yaml
control: SI-16
responsibility: csp_claimed
csp_part: "Isolation between invocations and tenants"
evidence:
  - current AWS assurance report
  - current Lambda security documentation describing the isolation model
```

The requirement document must not state that this is “already handled” merely because the application runs on Lambda. It records the claim and the evidence needed to substantiate it.

---

## 3. DynamoDB responsibility

DynamoDB provides managed storage, encryption mechanisms, backup features, and access integration. The team still owns table policies, key choices, recovery configuration, and application data design.

### Table access and least privilege: team responsibility

The team must restrict the Lambda role to the required actions and table.

```yaml
control: AC-6
responsibility: team
team_part: >-
  Separate read and write permissions and restrict them to the Movies table.
```

This is the DynamoDB side of T-02. A least-privilege Lambda role and a resource-scoped DynamoDB policy describe the same boundary from two directions.

### Encryption at rest: shared responsibility

DynamoDB encrypts tables at rest and does not allow encryption to be disabled. The key-custody decision remains with the customer.

```yaml
control: SC-28
responsibility: shared
csp_part: "Encrypt all DynamoDB tables at rest"
team_part: >-
  Select a customer-managed key when the confirmed requirements call for
  customer key custody or revocation authority.
```

For this public-content service, a customer-managed key may not be justified by data sensitivity alone. The requirement should not prescribe one without a profile or contractual reason. The durable property is that the encryption and key-custody decision is explicit and verifiable.

### Recovery: shared responsibility

AWS provides point-in-time recovery and on-demand backup mechanisms. Point-in-time recovery must still be enabled by the team.

```yaml
control: CP-9
responsibility: shared
csp_part: "Provide point-in-time recovery and on-demand backups"
team_part: "Enable the recovery mechanism before protected data exists"
```

The Stage 2 profile allowed an RPO of several hours, so point-in-time recovery may not be the only acceptable implementation. The final requirement should reflect the confirmed RPO rather than automatically demanding the strongest available feature.

---

## 4. Organization-level responsibility

The Moderate baseline and Program layer include controls that cannot be satisfied by changing the Lambda function.

Typical organization-owned areas include:

- Security policies and procedures
- Personnel security
- Security awareness and training
- Risk-assessment methodology
- Incident-response process
- Periodic access review
- Supplier and supply-chain governance
- Independent assessment and authorization

These controls are assigned to `org` rather than converted into delivery-team implementation work.

For example:

```text
Organization
  → defines the access-review process
  → approves risk exceptions
  → maintains the incident-response process

Movie-service team
  → supplies the service roles and evidence needed by those processes
  → implements the technical changes resulting from review
```

An `org` classification does not mean the control is optional. It means that a different owner must answer it.

---

## 5. Crossing threats with the selected baseline

After responsibility has been classified, the plugin crosses the Stage 3 threats with the Stage 2 control set.

```text
Threat-related control is in the baseline
  → retain the control and raise its priority

Service-specific threat has no adequate baseline control
  → create an additional requirement

Baseline control is not reached by any threat
  → retain it at lower priority for completeness
```

The operation is mechanical once each threat's `related_controls` field has been reviewed against the bundled catalogs.

```text
threat.related_controls ∩ selected_controls
```

The model decides which controls meaningfully address a threat. The script decides whether those identifiers exist in the selected baseline and places the item into the correct bucket.

---

## The four priority outcomes

The plugin assigns priority according to both threat specificity and baseline coverage.

| Priority | Condition |
|---|---|
| `high` | A selected baseline control is matched by a service-specific threat |
| `high` | A service-specific threat has no adequate baseline control and requires a new requirement |
| `medium` | A selected baseline control is matched only by a generic threat |
| `low` | A selected baseline control has no matching threat but is retained for completeness |

Low-priority controls are not deleted. Their presence is what allows the document to explain why a control family was considered even when the current threat model did not elevate it.

---

## 6. How the eight movie-service threats cross

The exact cross file is a machine-generated work list, but its important outcomes can be understood from the threat scenarios.

### T-01: Long-lived credentials in configuration

T-01 intersects baseline concerns around credential protection and least privilege. It becomes High priority because the scenario is tied to the sample's actual configuration path.

```text
Outcome: baseline + service-specific threat
Priority: High
Responsibility: team
```

The work item must ensure that long-lived AWS credentials are absent from application configuration and deployment artifacts.

### T-02: Broad Lambda permissions

T-02 maps directly to least privilege, including AC-6, and to the curated Lambda and DynamoDB responsibility rules.

```text
Outcome: baseline + service-specific threat
Priority: High
Responsibility: team
```

The work item includes a function-specific role, action scoping, and a resource restriction to the `Movies` table.

### T-03: Anonymous write operations

T-03 reaches access enforcement and identification controls, including the API Gateway mapping for AC-3.

```text
Outcome: baseline + service-specific threat
Priority: High
Responsibility: team
```

AWS provides the authorizer integration, but deciding and enforcing which routes require an authenticated caller remains team work.

### T-04: Unvalidated input and resource consumption

T-04 reaches input-validation and resource-protection controls.

```text
Outcome: baseline + service-specific threat
Priority: High
Responsibility: team/shared
```

The team owns schema and application validation. API Gateway and Lambda provide throttling and concurrency mechanisms, while the team configures the limits.

### T-05: Internal error disclosure

T-05 reaches error-handling controls such as SI-11.

```text
Outcome: baseline + service-specific threat
Priority: High
Responsibility: team
```

The work item must define a public error contract and prevent backend exception text from being interpolated into it.

### T-06: Sensitive data in CloudWatch Logs

T-06 reaches audit-content and information-protection concerns.

```text
Outcome: baseline + service-specific threat
Priority: High
Responsibility: team, with an unverified CloudWatch service mapping
```

The unverified designation matters because the repository lacks a curated CloudWatch responsibility file. The requirement can still state what the application must omit from logs, but any provider-specific inheritance claim requires review.

### T-07: Missing application audit events

T-07 reaches audit-event generation and protection controls such as AU-2 and related audit controls.

```text
Outcome: baseline + service-specific threat
Priority: High
Responsibility: shared
```

AWS supplies platform events and log infrastructure. The team must emit actor-, action-, target-, and outcome-aware application events.

### T-08: Inconsistent route interpretation

T-08 is broadly related to access enforcement, but the specific requirement—that Lambda use the complete path and HTTP method rather than the final segment alone—is not adequately expressed by a general baseline control.

```text
Outcome: threat only
Priority: High
Responsibility: team
```

This item becomes an additional service-specific requirement.

It is the strongest demonstration of why the pipeline does not stop after downloading a Moderate baseline.

---

## An illustrative cross result

A simplified work list may look like this:

```yaml
high:
  - work_id: credential-source
    source: [T-01]
    responsibility: team
    reason: >-
      The sample reads AWS access keys from application configuration.

  - work_id: lambda-least-privilege
    source: [AC-6, T-02]
    responsibility: team
    reason: >-
      FullAccess policies expand compromise beyond the Movies table.

  - work_id: authorize-write-routes
    source: [AC-3, T-03]
    responsibility: team
    reason: >-
      The confirmed profile permits anonymous reads but not anonymous writes.

  - work_id: validate-api-input
    source: [SI-10, T-04]
    responsibility: team

  - work_id: public-error-contract
    source: [SI-11, T-05]
    responsibility: team

  - work_id: sanitize-application-logs
    source: [T-06]
    responsibility: team
    provider_mapping: unverified

  - work_id: application-audit-events
    source: [AU-2, T-07]
    responsibility: shared

  - work_id: exact-route-operation-match
    source: [T-08]
    responsibility: team
    bucket: threat_only

low:
  - source: baseline controls not reached by the current threat model
    disposition: retained_for_completeness
```

This is intentionally not the final requirements schema. It is the input to requirement authoring.

---

## Evidence is part of responsibility

A responsibility assignment is incomplete without saying how the claim can be demonstrated.

For provider claims, evidence may include:

- A current AWS SOC 2 Type II report
- Current AWS service security documentation
- The applicable shared-responsibility description
- Contractual service terms

For team responsibilities, evidence may include:

- IAM policy attached to the Lambda role
- API Gateway route authorization configuration
- Request-validation schema
- Test output for anonymous write attempts
- CloudWatch log searches using sentinel values
- Audit-event examples
- DynamoDB backup configuration and restoration results

Evidence must match the exact claim. An AWS assurance report may support operation of the underlying managed infrastructure. It does not prove that this application attached an authorizer or restricted its execution role.

---

## What the plugin refuses to claim

This stage deliberately avoids several shortcuts.

### “Serverless means AWS owns security”

False. AWS operates the managed infrastructure. The team still owns application logic, identity decisions, route configuration, IAM scope, dependencies, logging content, and data design.

### “Encrypted by default means the encryption requirement is complete”

Not necessarily. Default encryption may satisfy protection against physical media disclosure while leaving key-custody or revocation requirements unanswered.

### “CloudTrail means application actions are audited”

CloudTrail records AWS control-plane activity and selected data events. It does not automatically know which user changed which movie through application logic.

### “A related control means the threat is fully covered”

A trace link says that the control is relevant. It does not prove that the eventual requirement captures the threat adequately, is implemented, or has operating evidence.

---

## The assurance stages remain separate

At this point, the pipeline has selected and trace-linked work. It has not shown that the service satisfies it.

```text
selected
  → authored
  → trace-linked
  → semantically reviewed
  → implemented
  → evidenced
  → assessed
```

Part 4 reaches only the selection and prioritization side of this funnel.

- A selected control is not a written requirement.
- A written requirement is not an implementation.
- A provider claim without current evidence is not inherited assurance.
- A configured control without operating evidence is not an assessment result.

Maintaining these distinctions prevents an automatically generated document from being mistaken for certification.

---

## What Part 4 established

This stage converted a broad control set and eight threats into owned, prioritized work.

It established that:

1. API route authorization, input validation, error mapping, and IAM scope remain delivery-team responsibilities.
2. TLS, throttling, runtime maintenance, audit infrastructure, encryption, and recovery contain both provider and team responsibilities.
3. Lambda isolation and other provider-operated properties remain claims requiring current evidence.
4. Organization-wide policy, risk, personnel, incident-response, and assessment controls belong to organizational owners rather than the movie-service team.
5. Controls reached by service-specific threats become High priority.
6. T-08 produces a High-priority `threat only` item because the baseline does not adequately express the route-interpretation failure.
7. Baseline controls with no matched threat remain at Low priority to preserve completeness.
8. The missing curated CloudWatch service mapping must be disclosed as unverified.

The next stage will turn this work list into atomic, verifiable requirements. Each requirement will state one durable security property, identify its rationale and sources, separate AWS and team responsibilities, and include a concrete verification method and expected result.
