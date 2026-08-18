# Responsibility

> This document is an automatically generated draft. It does not constitute
> legal advice and does not substitute for compliance certification.
> Qualified review is required.


Inheritance is a claim, not a fact. Every provider-claimed control lists the
evidence an auditor will ask for.

## team implements (8)

| Requirement | Statement | Evidence |
|---|---|---|
| REQ-API-ERROR-01 | Public API error responses must not disclose stack traces, credentials, tenant identifiers belonging to another tenant, or internal resource names.<br>**team:** Use stable external error codes and keep diagnostic detail in access-controlled logs. |  |
| REQ-LIFECYCLE-AUTH-01 | Tenant lifecycle events must be authenticated, authorized, and bound to the requested tenant and isolation tier before provisioning or deprovisioning begins.<br>**team:** Validate event origin, tenant identity, requested action, tier, and replay protection before invoking lifecycle automation. |  |
| REQ-LOG-SANITIZATION-01 | Application and control-plane logs must exclude authentication secrets, raw tokens, and unnecessary tenant customer data.<br>**team:** Redact sensitive fields at log construction and define a reviewed event schema. |  |
| REQ-MAPPING-LAMBDA-01 | The tenant-mapping custom resource must have only the actions and resource scope required to read and update the mapping table.<br>**team:** Keep the custom resource role least-privileged and restrict it to the mapping table and lifecycle operations. |  |
| REQ-PROVISION-INPUT-01 | Tenant provisioning inputs must be validated against an allowlist before they are passed to CloudFormation, CodeBuild, or shell commands.<br>**team:** Enforce type, length, character, enum, and version validation at the lifecycle boundary. |  |
| REQ-ROUTE-METHOD-01 | Every tenant API operation must enforce an explicit route-and-method allowlist before invoking its handler.<br>**team:** Define explicit API Gateway and application route mappings and reject unknown methods and paths. |  |
| REQ-TENANT-CLAIM-01 | The service must derive the tenant identity used for authorization from a verified identity claim or server-side tenant mapping.<br>**team:** Validate the authenticated subject and resolve its tenant mapping before dispatching a tenant operation. |  |
| REQ-TENANT-DDB-01 | Every tenant-scoped DynamoDB read and write must be constrained by the authenticated tenant key.<br>**team:** Apply tenant-key conditions to all tenant table access paths and test both positive and negative cases. |  |

## shared (5)

| Requirement | Statement | Evidence |
|---|---|---|
| REQ-AUDIT-IMMUTABILITY-01 | Security-relevant tenant lifecycle and administrative events must be recorded in a destination that the recording runtime cannot delete or alter.<br>**provider:** Provide durable, access-controlled log storage. **team:** Emit complete lifecycle audit events and separate write and administrative permissions. | CloudTrail or equivalent audit configuration; runtime IAM policy |
| REQ-CAPACITY-ISOLATION-01 | Tenant onboarding and request handling must enforce quotas or rate limits that prevent one tenant from exhausting shared provisioning or runtime capacity.<br>**provider:** Expose service quotas and throttling controls. **team:** Configure tenant-aware throttles, quotas, alarms, and admission checks. | API throttling configuration; service quota alarms |
| REQ-DEPLOY-SCOPE-01 | Deployment identities must be restricted to the stacks, repositories, and environments required by their pipeline stage.<br>**provider:** Provide identity, build, and deployment audit capabilities. **team:** Use stage-specific roles and resource conditions and review changes before promotion. | CodeBuild service role; CloudFormation deployment role; pipeline approval record |
| REQ-OFFBOARD-RECOVERY-01 | Tenant offboarding must preserve the approved export, retention, and recovery evidence before destructive resources are removed.<br>**provider:** Provide backup and deletion capabilities with documented retention semantics. **team:** Gate destructive offboarding on export verification, approval, and an auditable retention decision. | offboarding runbook; backup and export records |
| REQ-PLATFORM-AUTHZ-01 | The tenant management API must authorize platform-level actions separately from tenant-user actions.<br>**provider:** Provide identity and policy enforcement primitives. **team:** Define and enforce distinct platform-operator and tenant-administrator permissions. | API Gateway authorizer configuration; IAM policy review |

## Sources

- NIST SP 800-53 Rev 5 / SP 800-53B (OSCAL version 5.2.0, last modified 2026-05-11T16:01:09.00000-00:00)
- NIST Cybersecurity Framework 2.0 (structure)
- OWASP Application Security Verification Standard (CC BY-SA 4.0)

NIST does not endorse this output. Provider guidance is summarised in the authors' own words with links to the original; it is not reproduced.
