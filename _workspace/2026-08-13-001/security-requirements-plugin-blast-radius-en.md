# Extending the Security Requirements Plugin with Blast-Radius Analysis

The security requirements plugin already combines a confirmed service profile, a CIA impact calculation, a baseline, and a threat model. The blast-radius stage adds another question:

> If this threat succeeds, how far can the effect spread?

This is not a vulnerability score or an incident estimate. It is a deterministic scope calculation used to prioritize requirements and review work.

## Why add blast radius?

A threat affecting one request and a threat reaching a shared data store should not receive the same review urgency. CIA impact tells us how harmful a loss would be. The threat model tells us what could go wrong. Blast radius describes the possible scope of that failure.

The plugin keeps these concepts separate:

~~~text
CIA impact   business effect of confidentiality, integrity, or availability loss
Threat       concrete failure scenario at a trust boundary
Blast radius reachable tenants, data, components, and recovery domains
Evidence     proof that the modeled property exists, fails, or is unknown
~~~

## Inputs

The calculation consumes two documents.

~~~text
threats.yaml       human-authored threats and trust boundaries
blast-graph.yaml   components, edges, scopes, and threat entry points
~~~

The threat model describes meaning. The graph describes the paths used for scope calculation.

### Threats

~~~yaml
- id: T-02
  boundary: TB-4
  persona: authenticated_user
  scenario: "A missing tenant condition permits access to another tenant's records."
  affected_assets: [transaction_history]
  related_controls: [AC-3, AC-4]
~~~

### Graph nodes

Each node describes a component or resource domain.

~~~yaml
- id: tenant-service
  tenant_scope: subset
  data_scope: tenant_dataset
  runtime_scope: service
  control_scope: feature
  recovery_scope: tenant_recovery
  responsibility: team
  confidence: inferred
  evidence: [server/application/orders-service.ts]
~~~

### Graph edges and threat sources

~~~yaml
- from: tenant-service
  to: tenant-dynamodb
  confidence: confirmed
  evidence: [infra/tenant-table.ts]

threat_paths:
  T-02:
    sources: [tenant-service]
    condition: "if the tenant key condition is absent"
    required_checks: [inspect_dynamodb_policy, run_cross_tenant_test]
~~~

The condition is preserved as review context. The current calculation does not pretend to evaluate it as a live Boolean expression.

## Five calculation dimensions

For each threat, the plugin starts at its source nodes, follows reachable edges, and selects the broadest value reached in each dimension.

~~~text
tenant_scope   one | subset | all
data_scope     record | tenant_dataset | shared_dataset | platform_dataset
runtime_scope  task | service | cluster | account | region
control_scope  feature | tenant_operations | control_plane | platform
recovery_scope local | tenant_recovery | platform_recovery | regional_recovery
~~~

The vocabularies are ordered. The result does not depend on a model deciding whether one natural-language phrase sounds broader than another.

The plugin also emits a reviewer-friendly summary:

~~~text
contained | tenant | cross_tenant | platform | account_region
~~~

The five detailed values remain the source of truth. The summary is for navigation and reporting.

## Example calculation

Suppose T-02 follows this path:

~~~text
ECS task
  → tenant application service
  → DynamoDB tenant data
~~~

The result can be:

~~~yaml
blast_radius:
  tenant_scope: subset
  data_scope: tenant_dataset
  runtime_scope: service
  control_scope: feature
  recovery_scope: tenant_recovery
coarse_scope: cross_tenant
~~~

This does not claim that every tenant is exposed. It says that the path can reach the tenant set sharing that service if the stated condition occurs.

## Provenance and review

Scope without provenance is easy to over-trust. Results retain confidence, evidence, responsibility, and review state.

~~~text
confirmed   directly supported by code, IaC, provider configuration, or review
inferred    derived from discovered structure or an architectural assumption
unknown     available information cannot establish the value
~~~

Affected assets carry their own owner:

~~~yaml
affected_assets:
  - id: tenant-dynamodb
    responsibility: shared
    confidence: confirmed
~~~

A reviewer can confirm a path with explicit metadata:

~~~yaml
review:
  status: confirmed
  reviewer: security@example.com
  reviewed_at: "2026-08-18T09:00:00Z"
  evidence: [architecture-review-42]
~~~

The plugin does not infer approval from the existence of a graph file.

## Priority calculation

Blast radius is a separate signal from CIA impact and threat novelty. The priority floor is raised for broad or uncertain scope:

~~~text
all tenants
shared or platform data
account or regional runtime
platform or control-plane authority
platform or regional recovery
unknown scope or confidence
~~~

The output records the reason:

~~~yaml
priority_floor: high
priority_reasons: [platform_control, review_required]
review_required: true
~~~

Unknown scope receives a temporary High floor so it enters the review queue. That is not a final High-impact classification. A result that is merely unreviewed remains Medium unless its actual scope is broad.

The cross stage uses the result to raise related control work and to preserve blast_radius_refs in authored requirements.

## Optional tenant sizing

The categorical scope remains stable as deployment size changes. A graph may provide current sizing information:

~~~yaml
affected_tenants:
  estimate: 25
  total: 500
  basis: "tenants sharing the ECS service"
~~~

The plugin calculates a ratio when both values are known. It never invents a tenant count when the deployment does not provide one.

## Outputs

The machine-readable result is blast-radius.json.

~~~json
{
  "threat_id": "T-02",
  "coarse_scope": "cross_tenant",
  "blast_radius": {
    "tenant_scope": "subset",
    "data_scope": "tenant_dataset",
    "runtime_scope": "service",
    "control_scope": "feature",
    "recovery_scope": "tenant_recovery"
  },
  "confidence": "inferred",
  "priority_floor": "high",
  "review_required": true
}
~~~

The plugin can also render a Markdown review table. JSON is the machine-readable source consumed by the cross stage.

## Where it is used

Blast radius has four practical consumers:

1. Requirement prioritization. Broad paths move related controls and service-specific requirements to the front of the queue.
2. Evidence targeting. Feature paths need source and focused-test evidence; platform paths need deployment, lifecycle, and recovery evidence.
3. Review queues. Inferred and unknown paths become explicit human review work.
4. Refresh detection. A change such as subset → all, service → account, or medium → high is reported even when the threat ID is unchanged.

A CI or refresh gate can stop a merge when a path expands until the graph and affected requirements are reviewed.

## What the calculation does not prove

Blast radius does not prove that an exploit succeeds. It does not estimate incident losses, certify compliance, or replace runtime testing.

It answers a narrower question:

> Given the reviewed graph and its stated conditions, what is the broadest scope this threat path can reach?

That answer is enough to prioritize security requirements and evidence without confusing design analysis with live attack validation.


