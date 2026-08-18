# Security Design Review: AWS ECS SaaS (1) - Service Analysis

Security requirements should not begin with a list of controls. They should begin with a clear description of the service and the environment in which it will operate.

This article applies the first stage of the `security-requirements` plugin to AWS's ECS SaaS reference architecture. The sample is the [AWS ECS SaaS reference architecture](https://github.com/aws-samples/saas-reference-architecture-ecs).

The question for this stage is:

> What does this service do, who uses it, what data does it handle, and what obligations apply to it?

The answers become the service profile. Later stages use that profile to calculate CIA impact, select NIST controls, set the OWASP ASVS level, model threats, and calculate blast radius.

## The first stage is not vulnerability scanning

The plugin first builds a map of the service. It combines facts found in the repository with operating decisions confirmed by the service owner.

```text
Repository evidence
        +
Business and operating context
        ↓
Confirmed service profile
        ↓
CIA impact, baseline, threats, and blast radius
```

This distinction matters. Code can show that Cognito exists, but it cannot show whether a customer administrator may delete a tenant. Infrastructure can show a DynamoDB table, but it cannot show how much data loss the business can tolerate.

The plugin does not silently turn missing information into a guess. It records unresolved items and sends them to a confirmation gate.

## 1. What service does the repository describe?

This is a multi-tenant SaaS platform. A platform operator creates and manages tenants. Each tenant then uses an application that runs on ECS Fargate.

The architecture has two related but different areas:

```text
Control plane
  Creates tenants, manages tenant mappings, and starts lifecycle workflows

Application plane
  Serves tenant users and processes tenant data
```

An apartment-building analogy is useful. The application plane is the apartments where customers live.

The control plane is the building office that can create, reconfigure, or remove apartments. The office needs stronger protection because it can affect the whole building.

The main request and management flow is:

~~~mermaid
flowchart LR
    U[Users] --> CF[CloudFront web sites]
    U --> APIGW[API Gateway]
    APIGW --> COG[Cognito JWT]
    APIGW --> ALB[Application Load Balancer]
    ALB --> ECS[ECS Fargate services]
    ECS --> DDB[(Tenant DynamoDB data)]
    EB[EventBridge] --> CB[CodeBuild]
    CB --> CFN[CloudFormation tenant stacks]
    CFN --> ECS
    CFN --> DDB
~~~

The repository provides evidence for these services:

| Component | Role | Example evidence |
|---|---|---|
| API Gateway | Receives HTTPS APIs | `server/lib/shared-infra/api-gateway.ts` |
| Cognito | Authenticates users and supplies JWTs | `server/lib/tenant-template/identity-provider.ts` |
| ALB | Routes requests to tenant applications | `server/lib/shared-infra/shared-infra-stack.ts` |
| ECS Fargate | Runs tenant services | `server/lib/tenant-template/ecs-cluster.ts` |
| DynamoDB | Stores tenant application data | `server/lib/tenant-template/ecs-dynamodb.ts` |
| EventBridge | Starts tenant lifecycle events | `server/lib/bootstrap-template/core-appplane-stack.ts` |
| CodeBuild and CloudFormation | Builds and provisions tenant infrastructure | bootstrap and provisioning code |

This is more useful than recording only “the application uses ECS.” The security consequences depend on the connections between the services and on which plane owns each connection.

## 2. Who uses the service?

The profile separates user types because they do not have the same authority.

```text
anonymous_public_site
authenticated_tenant_user
authenticated_tenant_admin
platform_operator
service_to_service
```

For example, a tenant administrator may manage users inside one tenant. A platform operator may create or remove tenants.

Both may authenticate through Cognito, but the token claims and authorization rules must lead to different permissions.

The entry points are also different:

- The public and admin web interfaces are delivered through CloudFront.
- Tenant APIs are reached through API Gateway and the ALB.
- Tenant lifecycle operations are started by EventBridge and service-to-service calls.

This actor and entry-point list becomes the starting point for threat modeling. A threat beginning at a tenant order API is not the same as a threat beginning at the tenant-management API.

## 3. Why the isolation tier changes the analysis

The sample supports three tenant-isolation choices:

```text
Basic
  Tenants share ECS services and capacity.

Advanced
  Tenants share a cluster but use separate services.

Premium
  Each tenant receives a separate cluster.
```

Isolation answers a practical question: “If one tenant has a problem, how many other tenants share the same resources?”

In Basic mode, a tenant-routing error or resource exhaustion can affect several tenants.

Premium mode separates more of the application runtime, but it does not remove the control plane's authority to create, update, or delete infrastructure for every tenant.

The tier is therefore recorded as security-relevant service context, not as a deployment detail. The same application code can have a different blast radius at each tier.

## 4. What data does the platform handle?

The profile declares the data types that the service is expected to process:

```yaml
data_types:
  - basic_contact          # name, email, contact details
  - account_credentials    # password hashes, tokens, recovery data
  - transaction_history    # orders and settlement records
  - public_content
  - app_logs
  - audit_logs
  - backups
```

This list is not a claim that every field is visible in one source file. It combines repository evidence with the intended SaaS operating scenario.

The distinction between customer-owned data and platform data is important. The platform may process customer contact and transaction data on the customer's behalf.

That creates obligations such as deletion on the customer's instruction, contractual processing terms, and notification responsibilities.

Logs and backups are included because data does not stay only in the primary table. A tenant record may also appear in application logs, audit records, snapshots, or recovery copies.

## 5. What operating commitments apply?

The repository cannot establish business commitments. For this ECS SaaS analysis, the service owner confirms the following context:

```yaml
users:
  - KR
  - JP

region_storage: ap-northeast-2

availability:
  rto: rto_hours
  rpo: rpo_zero
  amplifiers:
    - revenue_direct
    - single_point_dependency
```

In plain language, the service is expected to recover within hours, and an acknowledged transaction should not be lost. An outage also stops revenue directly, and other platform functions depend on this service.

These decisions raise availability impact to Moderate. The result comes from the business promise, not from the fact that ECS or DynamoDB is a managed AWS service.

The profile also records that customers are in Korea and Japan, while storage is currently planned for Seoul. This is an operating decision that must be reviewed against customer contracts and data-transfer requirements.

## 6. Which compliance and contractual triggers apply?

The plugin treats compliance as an input to requirements derivation, not as a label it can invent from a repository scan.

For this scenario, the owner declares:

```yaml
regulations_declared:
  - customer_data_processing_agreement
  - customer_availability_sla
  - tenant_data_deletion_obligation
```

The service is a processor for some customer data. Security requirements must therefore cover more than preventing a breach.

The platform also needs a reliable way to locate tenant data, delete it when instructed, retain evidence of the action, and notify the customer through the agreed process.

Because the user population includes Korea, the profile activates the repository's PIPA/ISMS-P overlay.

The plugin maps applicable technical and organizational areas to the NIST control catalog. It separately identifies obligations that do not have a direct 800-53 control equivalent.

Examples include:

- Privacy governance and management responsibility
- Information-asset and data-flow identification
- Risk assessment and protection planning
- Access control, logging, incident response, and recovery
- Personal-information deletion and retention handling
- Data-subject rights and privacy notices

The overlay is not a legal opinion and does not prove ISMS-P certification. It is a traceable way to show which declared privacy obligations need requirements, which are inherited from AWS, and which remain organizational or legal work.

Japan is also in the declared user region. The current catalog does not provide a complete Japanese privacy overlay.

The result records a coverage limitation rather than claiming that no Japanese obligation applies. That unresolved item belongs in the review queue.

## 7. What controls are already provided by the organization or AWS?

The service profile records controls that should not be assigned to the application team a second time:

```yaml
existing_org_controls:
  - central_logging
  - cloud_account_guardrails
  - dependency_scanning
  - incident_response_process
  - access_review_process
  - backup_recovery_policy
```

AWS also provides part of the underlying cloud responsibility, such as physical data-center protection and managed-service infrastructure.

The application team still owns tenant authorization, IAM scope, container images, API validation, log content, deletion behavior, and the configuration of recovery mechanisms.

This is why the profile records responsibility as well as technology.

“AWS has a control for this” is not enough. The review must say whether the control is inherited, implemented by the organization, or still required from the product team.

## 8. What does the profile say about impact?

The declared data and operating context lead to the following preliminary result:

| Dimension | Level | Reason |
|---|---|---|
| Confidentiality | Moderate | Customer contact data, transaction records, credentials, logs, and backups are handled for tenants. |
| Integrity | Moderate | Incorrect orders, tenant mappings, or lifecycle actions can affect customer operations and platform trust. |
| Availability | Moderate | The service has an hours-level recovery objective, direct revenue impact, and dependent platform functions. |
| System impact | Moderate | The highest CIA value is Moderate. |

The next stage uses this result to select the NIST SP 800-53B Moderate baseline. Because this is an application-facing service, the profile also selects OWASP ASVS Level 2 as the starting application-security level.

These are not statements that the service is compliant or secure. They are the starting point for choosing requirements from bundled, versioned catalogs.

## 9. The profile becomes a graph for blast-radius analysis

The service profile is also used to build the first version of the blast-radius graph.

```yaml
- id: tenant-service
  tenant_scope: subset
  data_scope: tenant_dataset
  runtime_scope: service
  control_scope: feature
  recovery_scope: tenant_recovery
  responsibility: team
  confidence: inferred
```

The node says that the service can handle a group of tenants, processes tenant data, runs as an ECS service, and is owned by the delivery team. It does not claim that every connection has been proven.

For example, a path from tenant routing to ECS and then to DynamoDB may affect several tenants sharing the service.

A path from a lifecycle event to CodeBuild and CloudFormation can affect tenant stacks or the wider account. The later blast-radius calculation follows these paths and records the broadest reachable scope.

Automatically discovered nodes and edges remain `inferred` until a reviewer confirms them. This prevents an incomplete repository scan from looking like a verified security boundary.

## The resulting first-stage profile

The important profile decisions are:

| Area | Result | Basis |
|---|---|---|
| Service | Multi-tenant SaaS with control and application planes | Repository architecture and owner scenario |
| Deployment | AWS ECS Fargate and managed AWS services | CDK and application code |
| Users | Tenant users, tenant admins, platform operators, service identities | Owner-confirmed operating model |
| Data | Customer contact, transactions, credentials, logs, audits, backups | Repository plus declared SaaS context |
| Regions | Users in KR and JP; storage planned for `ap-northeast-2` | Owner-confirmed context |
| Contracts | Processing agreement, availability SLA, deletion obligation | Declared customer commitments |
| Privacy trigger | PIPA/ISMS-P overlay; Japan coverage requires follow-up | User regions and catalog coverage |
| Existing controls | Logging, guardrails, scanning, IR, access review, backup policy | Organization-confirmed controls |
| CIA impact | Moderate / Moderate / Moderate | Data and recovery analysis |
| Baseline preview | NIST SP 800-53B Moderate; OWASP ASVS Level 2 | Derived from the profile |

## What Part 1 does not prove

This stage does not prove that the deployed ECS service is secure. It does not prove that the PIPA or ISMS-P obligations are satisfied. It does not prove that tenant isolation works or that an attacker can reach the paths in the graph.

It produces a reviewed starting point and makes the remaining uncertainty visible. The next stages use that point to select controls, model threats, test the highest-impact paths, and calculate how far a failure could spread.

The main outcome is simple:

> Before choosing controls, we establish what the SaaS platform is, what it promises to customers, which obligations apply, who owns each part, and where a failure could travel.
