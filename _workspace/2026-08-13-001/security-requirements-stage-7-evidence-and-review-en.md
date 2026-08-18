# Deriving Security Requirements from an AWS Serverless Sample, Part 7: From Requirements to Evidence

Part 6 completed the core derivation lifecycle: profile the service, select a baseline, model threats, assign responsibility, author requirements, and preserve them safely as the system changes.

The next question moves downstream of derivation:

> How do we demonstrate that a well-written requirement is implemented and continues to operate as intended?

A requirement is not proof. It is the criterion against which design, implementation, and evidence can be reviewed.

---

## Keep the assurance stages separate

The assurance funnel is one-way.

```text
authored
  → trace-linked
  → semantically reviewed
  → implemented
  → evidenced
  → assessed
```

| Stage | Meaning |
|---|---|
| `authored` | The requirement statement exists |
| `trace-linked` | It references relevant controls, threats, and regulatory clauses |
| `semantically reviewed` | An independent reviewer checks the meaning and verification method |
| `implemented` | Code or infrastructure appears to implement the property |
| `evidenced` | Current artifacts demonstrate implementation and operation |
| `assessed` | A qualified reviewer evaluates the evidence against the requirement |

The plugin can establish at most the early stages. It does not infer implementation, evidence, assessment, or compliance from convincing prose.

---

## Evidence must match the requirement

Each movie-service requirement needs different evidence.

| Requirement | Relevant evidence |
|---|---|
| No long-lived AWS keys in configuration | Source search and deployed-package inspection |
| Lambda least privilege | IAM policy, resolved IaC plan, and deployed role |
| Anonymous writes rejected | API integration-test results |
| Operation-specific authorization | Tests using a read-only identity |
| Input rejected before DynamoDB | Invalid-request tests and DynamoDB call observation |
| Public error contract | Response from a forced backend failure |
| Sensitive data absent from logs | Sentinel-based CloudWatch search |
| Mutation audit events | Audit records for successful and denied attempts |
| Exact route dispatch | Adversarial path-and-method tests |

Evidence is not merely a related document. It must directly support the pass condition written in the requirement.

An AWS assurance report may support operation of the managed infrastructure. It does not prove that this application attached an authorizer to every protected route.

---

## Separate intended configuration from deployed and operating evidence

Infrastructure as code is useful evidence, but it answers only one layer of the question.

```text
IaC declaration
  → what the team intended to deploy

deployed configuration
  → what is configured now

operating test
  → whether the control behaves as required
```

Consider `REQ-IAM-LAMBDA-SCOPE-01`.

1. Terraform may show a policy limited to the `Movies` table.
2. The deployed IAM role must show the same policy.
3. An attempted access to an unrelated table should fail.

Confidence increases when all three layers agree. A plan that has never been applied is not evidence of deployed state, while a one-time runtime test does not explain whether the configuration will remain reproducible.

---

## Verification metadata is the handoff point

Each requirement already describes how it can be checked.

```yaml
verification:
  method: iac_inspect
  target: "the IAM policies attached to the movie Lambda role"
  expect: >-
    no FullAccess policy and DynamoDB access limited to the Movies table
```

That metadata can be handed to a review tool or a future verification dispatcher.

```text
requirements.yaml
        ↓
verification runner or reviewer
        ↓
IaC, AWS configuration, source, tests, and artifacts
        ↓
pass | conditional | fail | not_applicable | undetermined
        ↓
status.yaml and evidence references
```

The current plugin defines the verification contract. It does not itself provide a general engine that executes every verification method.

---

## Requirement status is evidence-based

| Status | Meaning |
|---|---|
| `pass` | Current evidence supports the requirement |
| `conditional` | The property is partially satisfied or depends on an unresolved condition |
| `fail` | Current evidence contradicts the requirement |
| `not_applicable` | Review establishes that the requirement does not apply |
| `undetermined` | Required information or evidence is unavailable |

Status must not be inferred from repository prose.

A README statement saying that Lambda uses an execution role does not justify marking least privilege as `pass`. The actual IAM policy is needed.

Likewise, failure to obtain production CloudWatch access does not mean the logging requirement failed. It means the result remains `undetermined`.

---

## Manage exceptions without deleting requirements

A requirement that cannot be satisfied immediately remains in the contract.

```yaml
human:
  status: exception
  exception:
    approver: service-owner
    reason: >-
      A migration job temporarily requires access to both the old and new
      DynamoDB tables.
    compensating_controls:
      - "role session duration limited to one hour"
      - "migration role disabled outside the approved window"
    expires: 2026-12-31
```

A useful exception records:

- A named approver
- The risk being accepted
- Why the exception is necessary
- Compensating controls
- An expiry date
- Conditions that trigger earlier review

An exception without an expiry date tends to become an undocumented permanent removal of the control.

---

## Evidence also becomes stale

Evidence is not permanently valid.

```text
August IAM policy evidence
        +
October role-policy change
        ↓
August evidence is stale
```

Changes that may invalidate evidence include:

- A Lambda role-policy update
- A new API Gateway route
- A change to logged fields
- A runtime upgrade
- Replacement of the DynamoDB table
- A new identity provider
- A modified error-response template

The requirement ID may remain stable while the evidence for its current implementation must be collected again.

---

## Design review and implementation review use the same contract differently

### Design review

```text
proposed architecture
  → how will each requirement be satisfied?
```

Questions include:

- Which routes receive the Cognito authorizer?
- How is the Lambda role scoped?
- Where are audit events delivered?
- What is the public error contract?
- How are asynchronous rating messages made idempotent?

### Implementation review

```text
deployed code and configuration
  → does the required property actually exist?
```

Checks include:

- Every mutation route has an authorizer.
- A read-only user cannot delete a movie.
- The Lambda role cannot access an unrelated table.
- Sentinel credentials do not appear in logs.
- Undeclared paths do not dispatch privileged operations.

An acceptable design and a faithful implementation require different evidence.

---

## An illustrative review result

```text
Movie Rating Service Security Review

Requirements
  total           9
  pass            5
  conditional     1
  fail            2
  undetermined    1

High-priority failures
  REQ-IAM-LAMBDA-SCOPE-01
    AmazonDynamoDBFullAccess remains attached.

  REQ-ROUTE-EXACT-DISPATCH-01
    /public/add-movie still resolves to add-movie.

Undetermined
  REQ-LOG-SENSITIVE-DATA-01
    Production CloudWatch evidence was not available.

Expiring exception
  REQ-API-WRITE-AUTHZ-01
    expires 2026-12-31
```

This is not a compliance declaration. It is a requirement-by-requirement review based on the evidence available at that time.

---

## What Part 7 established

> Requirements are not the end of security work. They are the criteria used to evaluate design, implementation, and evidence.

The series now forms this chain:

```text
Part 1  Service profile
Part 2  CIA impact and baseline
Part 3  Data flows and threat model
Part 4  Responsibility and prioritization
Part 5  Requirement authoring and validation
Part 6  Refresh and lifecycle management
Part 7  Implementation evidence and requirements-driven review
```

The next two posts extend the same contract in different directions: Part 8A applies regulatory overlays, while Part 8B shows how verification metadata can drive CI/CD checks.
