# Security Design Review: AWS ECS SaaS — Using Blast Radius to Prioritize Requirements

Threat models tell us what can go wrong. They do not always tell us how far the failure could spread.

That distinction matters in a multi-tenant SaaS platform. A routing defect that affects one tenant is serious. The same defect in a shared ECS service, a tenant-mapping table, or a deployment role can affect many tenants or the entire control plane.

The `security-requirements` plugin now calculates a blast radius for each threat path. The result is used to prioritize security requirements, identify review work, and detect when a later architecture change widens the possible impact.

This article uses the [AWS ECS SaaS reference architecture](https://github.com/aws-samples/saas-reference-architecture-ecs) as the example. The sample has a control plane, an application plane, and Basic, Advanced, and Premium tenant-isolation tiers. That combination makes it a useful case for explaining why impact scope must be explicit.

## Blast radius is not a vulnerability score

The plugin keeps three ideas separate:

```text
CIA impact
  How harmful would loss of confidentiality, integrity, or availability be?

Threat
  What concrete failure scenario are we considering?

Blast radius
  Which tenants, data, components, and recovery domains could the scenario reach?
```

An application can have Moderate CIA impact and still contain a threat with a platform-wide blast radius. Conversely, a High-impact data store may be protected by a boundary that limits one particular threat to a single tenant.

Blast radius does not replace FIPS 199 impact analysis or threat likelihood. It adds a scope dimension that the baseline alone cannot provide.

## Why the ECS SaaS sample needs it

The architecture supports three isolation tiers:

```text
Basic    shared ECS services and capacity
Advanced shared cluster with a dedicated service per tenant
Premium  dedicated cluster per tenant
```

The same threat can have a different consequence depending on the tier. A missing tenant condition in a Basic shared service may expose data belonging to several tenants. A provisioning error in the Premium tier may affect one tenant’s dedicated stack, but the control plane still has the authority to create or remove that stack.

The architecture also contains shared control-plane components:

```text
API Gateway
EventBridge
CodeBuild
CloudFormation
tenant mapping table
custom resource Lambda
```

A compromise of one of these components can cross the tenant boundary even when the application data stores are separately configured.

## The input is a reviewed graph

The plugin does not calculate impact from a list of AWS services. It consumes a graph with nodes, edges, and threat entry points.

```text
threats.yaml
  Human-authored threats and trust boundaries

blast-graph.yaml
  Reviewed components, connections, scopes, and threat sources

blast-radius.json
  Deterministic derived result
```

A node describes the scope it represents:

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

An edge describes a possible transition:

```yaml
- from: tenant-service
  to: tenant-dynamodb
  confidence: confirmed
  evidence:
    - server/lib/tenant-template/ecs-dynamodb.ts
```

The graph can be written by a reviewer or bootstrapped from repository and IaC evidence. Automatically discovered nodes remain reviewable and are marked as such. The graph is not treated as proof merely because a scanner found a matching service name.

## Five dimensions are calculated for every threat

For each threat, the plugin starts at the declared source node and follows the graph. It takes the broadest reachable value for each dimension.

```text
tenant_scope
  one | subset | all

data_scope
  record | tenant_dataset | shared_dataset | platform_dataset

runtime_scope
  task | service | cluster | account | region

control_scope
  feature | tenant_operations | control_plane | platform

recovery_scope
  local | tenant_recovery | platform_recovery | regional_recovery
```

This is deliberately a bounded vocabulary. A value such as `subset` has a defined position in the ordering, so the calculation is deterministic rather than a model-generated adjective.

The output also contains a coarse summary for reviewers:

```text
contained
tenant
cross_tenant
platform
account_region
```

The five detailed dimensions remain the source of truth. The coarse summary is a quick way to find paths that deserve immediate attention.

## Example: a tenant-key failure

T-02 describes a missing or incorrect DynamoDB `LeadingKeys` condition.

```text
ECS task role
  → tenant application service
  → DynamoDB tenant data
```

The calculated result for the shared service path is:

```yaml
blast_radius:
  tenant_scope: subset
  data_scope: tenant_dataset
  runtime_scope: service
  control_scope: feature
  recovery_scope: tenant_recovery
coarse_scope: cross_tenant
```

This result does not say that every tenant is already exposed. It says that the path can reach the tenant set sharing that service if the tenant condition is bypassed.

The associated requirement can preserve the relationship:

```yaml
id: REQ-TENANT-DDB-01
managed:
  threat_refs: [T-02]
  blast_radius_refs: [T-02]
  priority: high
```

The requirement author can then write a testable property for the data access policy and cross-tenant negative tests.

## Example: a deployment-role failure

T-11 concerns a CodeBuild or deployment role that can modify resources outside its pipeline stage.

```text
deployment role
  → CloudFormation / tenant templates
  → shared and tenant infrastructure
  → AWS account resources
```

Its result is broader:

```yaml
blast_radius:
  tenant_scope: all
  data_scope: platform_dataset
  runtime_scope: account
  control_scope: platform
  recovery_scope: platform_recovery
coarse_scope: account_region
```

That scope raises the work to High even if the underlying baseline control is generic. The reason is recorded explicitly rather than hidden behind a single severity label.

## Confidence and review are part of the result

The plugin distinguishes what the repository proves from what the graph infers.

```text
confirmed
  Directly supported by code, IaC, AWS configuration, or review evidence

inferred
  Derived from a discovered connection or architecture assumption

unknown
  The available information cannot establish the scope
```

Every result carries its basis, affected assets, responsibility, and validation work.

```yaml
confidence: inferred
review_required: true
priority_reasons:
  - platform_control
  - review_required
affected_assets:
  - id: tenant-mapping-table
    responsibility: shared
    confidence: confirmed
```

An unknown dimension receives a temporary High floor and a review task. This is a conservative queueing rule, not a claim that the final business impact is High. A result that is merely `unreviewed` remains Medium unless its actual scope is broad.

Once a reviewer confirms a path, the graph records the reviewer, timestamp, and evidence. The calculation does not infer approval from the existence of a graph file.

## How the result is used

The blast-radius output serves four practical purposes.

### 1. Requirement prioritization

The baseline still supplies completeness. Blast radius tells the author which baseline items need attention first and which additional service-specific requirements should be written.

```text
baseline control
  + service threat
  + broad blast radius
  → high-priority requirement
```

### 2. Review queue generation

An inferred path to the control plane should be reviewed before a contained path to one task. The output creates review work instead of silently presenting the inference as fact.

### 3. Evidence targeting

The scope determines what evidence is needed.

```text
tenant scope
  → tenant isolation and data-access tests

platform scope
  → control-plane authorization, deployment-role, and lifecycle evidence

account or region scope
  → recovery, account guardrail, and deployment-boundary evidence
```

### 4. Change detection

On refresh, the plugin compares the new result with the previous one.

```text
subset → all
service → cluster
tenant_recovery → platform_recovery
medium → high
```

Any widening is reported even when the threat ID remains unchanged. A CI or refresh gate can stop the merge until the change is reviewed.

## What the calculation does not claim

The result is not proof that an exploit works. It is not an incident estimate. It is not a compliance certification. It is not a replacement for runtime testing.

For the ECS SaaS sample, the plugin can say that a threat path reaches a shared ECS service, tenant data, or the control plane under stated conditions. It cannot say that the application is currently exploitable without configuration evidence or a test result.

That boundary is intentional. The blast-radius calculation makes the security design review more useful without pretending that a graph traversal has tested a live system.

## The outcome for the ECS SaaS sample

The current sample analysis contains 13 service-specific threats. The calculated output identifies:

- paths limited to a shared tenant service;
- paths that reach all tenants;
- paths that reach platform or account resources;
- the responsible team or shared owner for affected assets;
- evidence and review work required to confirm inferred paths.

The result is then consumed by the same requirements pipeline that selects the NIST baseline, performs the responsibility split, applies regulatory overlays, and renders the security contract.

Blast radius is therefore not a separate risk score bolted onto the end of the review. It is the connection between a threat scenario and the amount of the platform that scenario could affect.
