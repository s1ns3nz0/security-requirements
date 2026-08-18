# Blast-radius graph

Blast radius is a derived view of a reviewed threat model. It is not a finding,
an incident estimate, or proof that a control is implemented.

Keep the source files separate:

```text
threats.yaml       human-authored threats and trust boundaries
blast-graph.yaml   reviewed component graph and threat entry points
blast-radius.json  deterministic derived result
```

Each graph node may provide these fields:

```yaml
id: tenant-service
tenant_scope: subset
data_scope: tenant_dataset
runtime_scope: service
control_scope: feature
recovery_scope: tenant_recovery
responsibility: team
confidence: inferred
```

The allowed values are ordered from narrow to broad. The calculation takes the
widest value reachable from each threat source. The five dimensions are:

```text
tenant_scope   one | subset | all
data_scope     record | tenant_dataset | shared_dataset | platform_dataset
runtime_scope  task | service | cluster | account | region
control_scope  feature | tenant_operations | control_plane | platform
recovery_scope local | tenant_recovery | platform_recovery | regional_recovery
```

The graph maps a threat to one or more source nodes:

```yaml
threat_paths:
  T-02:
    sources: [tenant-service]
    affected_tenants:
      estimate: 25
      total: 500
      basis: "tenants sharing the ECS service"
    condition: "if the tenant key condition is absent"
    required_checks: [inspect_dynamodb_policy]
```

Once a path has been reviewed, record the reviewer and evidence in the graph:

```yaml
review:
  status: confirmed
  reviewer: "alice@example.com"
  reviewed_at: "2026-08-17T09:00:00Z"
  evidence: ["architecture-review-42"]
```

`reviewed` requires a reviewer and timestamp. `confirmed` additionally requires
evidence. The derived result keeps this metadata; it does not infer approval from
the presence of a graph file.

The categorical tenant scope remains stable when deployment size changes. The
optional estimate, total, ratio, and basis describe the current operating shape;
they must not be invented when the tenant population is unknown.

The output preserves the path, confidence, responsibility, and validation work.
It also emits a coarse review scope (`contained`, `tenant`, `cross_tenant`,
`platform`, or `account_region`) and an asset-by-asset responsibility view.
When a result reaches `all`, `account`, `region`, `control_plane`, or `platform`,
the cross stage can raise the affected work to at least High. Shared or platform
data and platform-level recovery also raise the floor. The output records the
reason instead of leaving the reviewer to infer it from a label.

An unknown dimension or unknown confidence receives a temporary High floor and
`review_required: true`. This is a review queue, not a claim that the final
impact is High. The blast-radius signal does not replace CIA impact or threat
likelihood.

If the graph cannot establish a value, use `unknown` and create a validation
task. Do not convert uncertainty into a confirmed platform-wide claim.

The CLI can also emit `blast-radius.md` for reviewers. The JSON file remains the
machine-readable source used by the cross stage.

On refresh, pass the previous JSON result with `--previous`. The comparison
reports added, removed, expanded, and reduced threat paths. A dimension that
widens, or a priority floor that rises, is a review trigger even when the threat
ID remains stable.

Use `--fail-on-expansion` in a CI or refresh gate when a widened path must stop
the merge until a reviewer updates the requirements.

`simulate_blast_paths.py` can walk the same graph and emit negative-test cases.
It reports graph reachability only; it never sends requests, invokes AWS APIs,
or changes infrastructure.

`aws_blast_snapshot.py` is the optional provider adapter. It uses read-only
`Describe`, `List`, and `Get` operations for ECS, DynamoDB, Lambda, API Gateway,
EventBridge, CloudFormation, and ECR. The account identity, region, and API
evidence are retained in the graph. Missing credentials or boto3 is a hard
error, not an empty inventory.
