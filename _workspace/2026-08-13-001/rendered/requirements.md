# Security requirements

> This document is an automatically generated draft. It does not constitute
> legal advice and does not substitute for compliance certification.
> Qualified review is required.


13 active requirements.

## PROTECT

### REQ-CAPACITY-ISOLATION-01

Tenant onboarding and request handling must enforce quotas or rate limits that prevent one tenant from exhausting shared provisioning or runtime capacity.

*Repeated onboarding and pooled ECS workloads can degrade service for unrelated tenants.*

| | |
|---|---|
| Responsibility | shared |
| Provider | Expose service quotas and throttling controls. |
| Team | Configure tenant-aware throttles, quotas, alarms, and admission checks. |
| Evidence | API throttling configuration; service quota alarms |
| Basis | SC-5 |
| Priority | high |
| Verify | config_api: `API Gateway throttles, ECS capacity settings, and onboarding workflow` — expect a single tenant cannot consume all shared request or provisioning capacity |
| Verify (manual) | Run a controlled burst for one tenant and confirm throttling and alarm behavior. |

### REQ-DEPLOY-SCOPE-01

Deployment identities must be restricted to the stacks, repositories, and environments required by their pipeline stage.

*A compromised CodeBuild or deployment role could modify every tenant environment or shared control-plane resource.*

| | |
|---|---|
| Responsibility | shared |
| Provider | Provide identity, build, and deployment audit capabilities. |
| Team | Use stage-specific roles and resource conditions and review changes before promotion. |
| Evidence | CodeBuild service role; CloudFormation deployment role; pipeline approval record |
| Basis | AC-6, CM-3, SA-10 |
| Priority | high |
| Verify | iac_inspect: `CI/CD IAM policies and CloudFormation execution roles` — expect each role is scoped to its stage and cannot modify unrelated tenant or control-plane resources |
| Verify (manual) | Attempt an out-of-scope deployment with the stage role and record the denial. |

### REQ-LIFECYCLE-AUTH-01

Tenant lifecycle events must be authenticated, authorized, and bound to the requested tenant and isolation tier before provisioning or deprovisioning begins.

*A forged or replayed lifecycle event could provision resources for the wrong tenant or destroy another tenant's environment.*

| | |
|---|---|
| Responsibility | team implements |
| Team | Validate event origin, tenant identity, requested action, tier, and replay protection before invoking lifecycle automation. |
| Basis | AC-3, AC-6, CM-3 |
| Priority | high |
| Verify | test_case: `tenant lifecycle event handler` — expect unauthenticated, mismatched, and replayed events do not change infrastructure state |
| Verify (manual) | Replay a captured lifecycle event and confirm that no second state change occurs. |

### REQ-LOG-SANITIZATION-01

Application and control-plane logs must exclude authentication secrets, raw tokens, and unnecessary tenant customer data.

*Shared CloudWatch and S3 log destinations increase the impact of accidental disclosure across tenants.*

| | |
|---|---|
| Responsibility | team implements |
| Team | Redact sensitive fields at log construction and define a reviewed event schema. |
| Basis | AU-3, AU-9, SI-12 |
| Priority | high |
| Verify | test_case: `application logging tests` — expect tokens, passwords, and unneeded customer fields are absent from emitted records |
| Verify (manual) | Exercise login, tenant routing, and error paths and inspect the resulting logs. |

### REQ-MAPPING-LAMBDA-01

The tenant-mapping custom resource must have only the actions and resource scope required to read and update the mapping table.

*A broad shared Lambda role could rewrite mappings or access unrelated tenant data after compromise.*

| | |
|---|---|
| Responsibility | team implements |
| Team | Keep the custom resource role least-privileged and restrict it to the mapping table and lifecycle operations. |
| Basis | AC-6 |
| Priority | high |
| Verify | iac_inspect: `custom resource Lambda IAM policy` — expect no wildcard actions or unrelated table, queue, bucket, or role resources are granted |
| Verify (manual) | Use the role to attempt an update outside the mapping table and record the denial. |

### REQ-PLATFORM-AUTHZ-01

The tenant management API must authorize platform-level actions separately from tenant-user actions.

*Tenant administrators must not gain onboarding, offboarding, or other-tenant management privileges by reaching a control-plane route.*

| | |
|---|---|
| Responsibility | shared |
| Provider | Provide identity and policy enforcement primitives. |
| Team | Define and enforce distinct platform-operator and tenant-administrator permissions. |
| Evidence | API Gateway authorizer configuration; IAM policy review |
| Basis | AC-3, AC-6 |
| Priority | high |
| Verify | config_api: `API Gateway routes and IAM policies for tenant management` — expect tenant users cannot invoke platform onboarding, offboarding, or cross-tenant operations |
| Verify (manual) | Invoke each management operation with tenant-user and platform-operator identities. |

### REQ-PROVISION-INPUT-01

Tenant provisioning inputs must be validated against an allowlist before they are passed to CloudFormation, CodeBuild, or shell commands.

*Unvalidated tenantId, tier, name, or source-version values can alter deployment targets or execute unintended operations.*

| | |
|---|---|
| Responsibility | team implements |
| Team | Enforce type, length, character, enum, and version validation at the lifecycle boundary. |
| Basis | SI-10, AC-6 |
| Priority | high |
| Verify | test_case: `provision-tenant input validation` — expect invalid identifiers, tiers, names, and source versions are rejected before subprocess or deployment calls |
| Verify (manual) | Supply shell metacharacters and unsupported tiers and retain the rejection evidence. |

### REQ-TENANT-CLAIM-01

The service must derive the tenant identity used for authorization from a verified identity claim or server-side tenant mapping.

*A client-controlled tenantPath can let one tenant address another tenant's data.*

| | |
|---|---|
| Responsibility | team implements |
| Team | Validate the authenticated subject and resolve its tenant mapping before dispatching a tenant operation. |
| Basis | AC-3, AC-4 |
| Priority | high |
| Verify | code_grep: `tenant claim and tenant mapping resolution` — expect the storage tenant key is not accepted directly from the request body or path |
| Verify (manual) | Submit a request with another tenant's identifier and confirm it is rejected. |

### REQ-TENANT-DDB-01

Every tenant-scoped DynamoDB read and write must be constrained by the authenticated tenant key.

*A missing or incorrect LeadingKeys condition creates a direct cross-tenant data access path.*

| | |
|---|---|
| Responsibility | team implements |
| Team | Apply tenant-key conditions to all tenant table access paths and test both positive and negative cases. |
| Basis | AC-3, AC-4, SC-4 |
| Priority | high |
| Verify | code_grep: `DynamoDB access policies and repository queries` — expect all tenant table operations contain an authenticated tenant constraint |
| Verify (manual) | Attempt a read and write using a different tenant key and record the denial. |

### REQ-API-ERROR-01

Public API error responses must not disclose stack traces, credentials, tenant identifiers belonging to another tenant, or internal resource names.

*Error payloads cross the public trust boundary and can disclose data useful for tenant targeting or infrastructure compromise.*

| | |
|---|---|
| Responsibility | team implements |
| Team | Use stable external error codes and keep diagnostic detail in access-controlled logs. |
| Basis | SI-11, SI-12 |
| Priority | medium |
| Verify | test_case: `API Gateway and ECS error response tests` — expect all tested failure paths return stable public errors without internal diagnostics |
| Verify (manual) | Trigger validation, authorization, dependency, and timeout failures and inspect responses. |

### REQ-ROUTE-METHOD-01

Every tenant API operation must enforce an explicit route-and-method allowlist before invoking its handler.

*Ambiguous dispatch or method confusion can bypass intended authorization and invoke an unintended tenant operation.*

| | |
|---|---|
| Responsibility | team implements |
| Team | Define explicit API Gateway and application route mappings and reject unknown methods and paths. |
| Basis | AC-3, AC-4, SI-10 |
| Priority | medium |
| Verify | test_case: `API route and method authorization tests` — expect unknown paths, methods, and route parameters are rejected before business logic executes |
| Verify (manual) | Send method override, path traversal, and unknown-route requests and retain responses. |

## DETECT

### REQ-AUDIT-IMMUTABILITY-01

Security-relevant tenant lifecycle and administrative events must be recorded in a destination that the recording runtime cannot delete or alter.

*An actor who can rewrite lifecycle evidence can hide unauthorized onboarding, offboarding, or privilege changes.*

| | |
|---|---|
| Responsibility | shared |
| Provider | Provide durable, access-controlled log storage. |
| Team | Emit complete lifecycle audit events and separate write and administrative permissions. |
| Evidence | CloudTrail or equivalent audit configuration; runtime IAM policy |
| Basis | AU-3, AU-9, AU-12 |
| Priority | high |
| Verify | iac_inspect: `lifecycle audit destination and runtime IAM policy` — expect the runtime can append events but cannot delete or rewrite retained audit records |
| Verify (manual) | Attempt deletion with the runtime role and verify the denial and audit event. |

## RECOVER

### REQ-OFFBOARD-RECOVERY-01

Tenant offboarding must preserve the approved export, retention, and recovery evidence before destructive resources are removed.

*RemovalPolicy.DESTROY and incomplete deprovisioning can permanently delete customer data without meeting contractual obligations.*

| | |
|---|---|
| Responsibility | shared |
| Provider | Provide backup and deletion capabilities with documented retention semantics. |
| Team | Gate destructive offboarding on export verification, approval, and an auditable retention decision. |
| Evidence | offboarding runbook; backup and export records |
| Basis | CP-9, CP-10, CM-3 |
| Priority | high |
| Verify | manual: `tenant offboarding runbook and executed change record` — expect export, retention decision, approval, and recovery evidence precede destructive deletion |
| Verify (manual) | Review one completed offboarding record end to end. |

## Sources

- NIST SP 800-53 Rev 5 / SP 800-53B (OSCAL version 5.2.0, last modified 2026-05-11T16:01:09.00000-00:00)
- NIST Cybersecurity Framework 2.0 (structure)
- OWASP Application Security Verification Standard (CC BY-SA 4.0)

NIST does not endorse this output. Provider guidance is summarised in the authors' own words with links to the original; it is not reproduced.
