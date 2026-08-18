# Why We Added Kubernetes Security Design Review Support

The original plugin focused on analyzing AWS-based applications and deriving security requirements and threats from the service design and operating environment. That approach works well for understanding application data flows and AWS resource relationships, but it is incomplete when the application runs on Kubernetes.

In Kubernetes, application code can be secure while the deployment remains exposed because of an overprivileged ServiceAccount, an overly broad ClusterRoleBinding, or an absent NetworkPolicy. A compromised container may also have access to an AWS IAM role, which can extend an incident from the cluster into the cloud account.

For that reason, the plugin now analyzes Kubernetes resources, represents their relationships as a security graph, and uses those relationships to calculate blast radius. The goal is to answer a design question early: if this workload is compromised, how far can the impact spread?

## Turning Kubernetes Resources into a Security Graph

The first change was to treat Kubernetes YAML as a set of security relationships rather than as a list of configuration files. The existence of a Deployment alone says little about its effective exposure. We also need to know which ServiceAccount it uses, which Secrets it reads, which Service exposes it, and which policies govern its traffic.

The plugin recognizes common workloads and platform resources, including Deployments, StatefulSets, DaemonSets, Pods, Services, Ingresses, NetworkPolicies, ServiceAccounts, Roles, ClusterRoles, RoleBindings, ClusterRoleBindings, Secrets, ConfigMaps, persistent storage resources, admission webhooks, and API aggregation services. It also understands CustomResourceDefinitions and their Custom Resources so that operator-based systems can be represented without pretending that every custom kind behaves like a built-in resource.

The result is a graph of resources and relationships. For example, a workload may be connected to a ServiceAccount, that account to a ClusterRoleBinding, and the binding to a ClusterRole that reaches the Kubernetes API:

```text
Deployment
  → ServiceAccount
    → ClusterRoleBinding
      → ClusterRole
        → Kubernetes API
```

An external request can be represented in the same model:

```text
Ingress
  → Service
    → Deployment
      → Secret
```

This is more useful than a resource inventory because it explains how an external request, a workload identity, a Kubernetes permission, and sensitive data are connected.

## Supporting Helm, Kustomize, and Terraform Inputs

Real Kubernetes repositories rarely contain only final YAML files. Helm templates and values, Kustomize bases and overlays, patches, and Terraform resources are often mixed in the same repository.

Reading these files as plain YAML can produce misleading results. A Helm template containing `{{ .Values.image }}` is not yet a deployable resource, and a Kustomize patch is not an independent Deployment. It is a modification applied to another resource.

The plugin therefore accepts raw YAML, rendered Helm output, rendered Kustomize output, and Kubernetes resources extracted from Terraform plans. When a template cannot be rendered, it is not silently treated as safe. The source is recorded as an unrendered or invalid input that requires review. Kustomize patches are also handled as patches rather than as replacement workloads.

This makes the analysis less dependent on the repository's layout and closer to the resources that will actually be deployed.

## Calculating RBAC-Based Blast Radius

One of the most important questions in a Kubernetes security review is what happens if a workload is compromised. The answer depends on the chain between the workload, its ServiceAccount, and the RBAC objects attached to that account.

The plugin follows Role, ClusterRole, RoleBinding, and ClusterRoleBinding relationships. It distinguishes Namespace-scoped permissions from cluster-wide permissions and records whether a permission is read-only or can create, modify, or delete resources.

Consider a tenant workload connected to a ClusterRole that can read Secrets across Namespaces:

```text
Tenant Pod
  → Tenant ServiceAccount
    → ClusterRoleBinding
      → ClusterRole
        → Secrets across namespaces
```

The impact of this compromise is not limited to the tenant Namespace. It may expose other tenants or platform credentials. The plugin therefore records the path, the scope, and the possible cross-tenant impact instead of reporting only that the account has “too many permissions.”

## Reviewing NetworkPolicy Boundaries

RBAC describes the API and resource boundary. NetworkPolicy describes the communication boundary between workloads and Namespaces. Without an effective policy, a compromised Pod may be able to communicate with services that were never part of the intended design.

The plugin checks whether a NetworkPolicy actually selects the intended workloads, whether ingress and egress rules are present, and whether cross-Namespace traffic is restricted. It compares policy selectors with workload labels rather than assuming that the presence of a policy means that the policy is effective.

For example, a policy selecting `app: api` does not protect a Deployment labelled `app: backend`. In that case the policy exists, but it does not select the workload. The plugin records the unresolved boundary as a design concern.

This can be turned into a requirement such as: tenant workloads must communicate only with explicitly approved services, and cross-tenant traffic must be denied by default.

## Reviewing Container Execution Security

Container security settings determine how a workload runs on a Kubernetes node. The plugin checks both Pod-level and container-level security contexts because Kubernetes manifests commonly use either location.

The analysis includes `runAsNonRoot`, `allowPrivilegeEscalation`, Secret and ConfigMap references, init containers, and volume mounts. A container-level setting such as the following is recognized as a valid non-root configuration:

```yaml
containers:
  - name: app
    securityContext:
      runAsNonRoot: true
      allowPrivilegeEscalation: false
```

The analysis also has to deal with imperfect repositories. During public repository testing, manifests were found with `containers` represented as a map instead of a list, or with a null `spec`. Those files now produce an explicit malformed-manifest issue while the rest of the repository continues to be analyzed.

## Treating CRDs and Operators Conservatively

Many Kubernetes platforms rely more heavily on Custom Resources than on built-in resources. Argo Rollouts, KEDA, Crossplane, Strimzi, Cilium, Istio, Rook, and Velero are examples of systems whose effective behavior depends on an operator.

A Custom Resource cannot be fully understood from its YAML alone. The operator may create additional workloads, watch multiple Namespaces, or reconcile resources using permissions that are not visible in the Custom Resource instance.

The plugin links Custom Resources to their CRD definitions using the API group and kind. It does not, however, invent a reconciliation model when the operator behavior is not established. Such cases are recorded as `crd_behavior_unknown`, `operator_behavior_unknown`, or `unsupported_kind` so that they remain visible review work.

This conservative behavior prevents the analysis from treating unknown behavior as safe or from claiming a level of certainty that the input does not support. In large repositories, repeated unsupported kinds are grouped so that the review remains manageable.

## Reviewing Admission Webhooks and API Aggregation

Admission Webhooks can change or reject Kubernetes objects before they are stored. They are therefore control points that can affect the entire cluster, not merely auxiliary configuration.

The plugin records ValidatingWebhookConfiguration and MutatingWebhookConfiguration objects and connects them to the Services that receive webhook calls. It also analyzes APIService objects and their backend Services. If `insecureSkipTLSVerify` is enabled on an APIService, the weakened TLS verification is reported as a separate design issue.

These relationships can support requirements such as: admission webhooks and aggregated APIs must use authenticated TLS, and the system must explicitly define whether webhook failures fail open or fail closed.

## Connecting Kubernetes Identity to Cloud IAM

Kubernetes workloads often access cloud resources through AWS IRSA, GCP Workload Identity, or Azure Workload Identity. This creates a trust relationship between a Kubernetes ServiceAccount and a cloud IAM identity.

The plugin reads the relevant annotations and adds the external identity to the graph:

```text
Pod
  → ServiceAccount
    → AWS IAM Role
      → S3 or Secrets Manager
```

This makes it possible to analyze a compromise path that crosses the Kubernetes and cloud boundaries. A compromised Pod may reach the Kubernetes API, an AWS role, and then cloud data or management APIs. Wildcard IAM actions, wildcard resources, and unresolved identity mappings are also recorded for review.

## Reviewing Image and Deployment Supply Chains

Kubernetes security issues do not begin only after a workload starts. The image selected for deployment and the identity that performs the deployment are also part of the security design.

The plugin checks for mutable image tags such as `latest`, whether images are pinned by digest, whether CI executes `kubectl apply`, and whether Helm deployment permissions are present. These signals help identify whether an attacker who compromises the build or deployment pipeline could replace an approved workload or change the cluster.

The analysis can therefore produce requirements such as: production workloads must use approved immutable image digests, and cluster changes must be performed only by an authorized deployment identity through an approved pipeline.

## Reviewing Service Mesh Policies

In Istio or Cilium environments, Kubernetes NetworkPolicy alone does not describe the complete service-to-service security model. A connection may be allowed at the network layer while mutual TLS or service-level authorization is not enforced.

The plugin checks for permissive Istio mTLS, AuthorizationPolicy coverage, CiliumNetworkPolicy selection, and the privileges assigned to mesh operators. The purpose is to determine not only whether two services can communicate, but whether they authenticate and authorize one another as intended.

This produces a more precise review of service trust boundaries than a simple open-or-closed network check.

## Connecting Design Findings to SOC Detection

Design findings are most valuable when they can be used after deployment. The plugin therefore creates SOC detection candidates from the risks found in the security graph.

If a ClusterRoleBinding is a major design risk, an unexpected ClusterRoleBinding creation or permission change can become an operational detection. If a ServiceAccount-to-Secret relationship is sensitive, unusual Secret access by that account can be monitored. Other candidates include privileged container execution, NetworkPolicy changes, Admission Webhook changes, and unusual cloud IAM role usage.

Each detection candidate can be linked back to the security requirement that motivated it. This creates a trace from design intent to operational monitoring.

## Comparing Design with Runtime State

The intended design and the running cluster can diverge over time. Emergency changes may add permissions, operators may create resources, and administrators may modify policies directly in the cluster.

The runtime snapshot feature compares a read-only cluster snapshot with the design graph. It can identify workloads that were not part of the design, newly added ServiceAccounts, unexpected ClusterRoleBindings, and changed NetworkPolicies. Secret values are not collected or printed; only resource presence and relationships are compared.

This provides a way to review Kubernetes drift without turning the plugin into a mutation tool or exposing sensitive data.

## What This Adds to the Plugin

The Kubernetes work is not intended to be another standalone CIS checklist. Benchmark checks are useful, but they do not by themselves explain tenant boundaries, operator behavior, cloud identity, deployment supply chains, or the path from a compromised Pod to sensitive data.

The added functionality turns Kubernetes resources into a security graph, uses that graph to calculate permissions and communication boundaries, and carries the result forward into blast-radius analysis, security requirements, testing, detection, and runtime drift review.

The overall flow is:

```text
Kubernetes manifests
  → security graph
    → permission and communication analysis
      → blast-radius calculation
        → security requirements
          → test and detection candidates
```

The result is a foundation for reusing Kubernetes design information throughout the SDLC rather than treating security review as a one-time configuration scan. The implementation is backed by 807 regression tests and has been exercised against public repositories including Cilium, Istio, Argo Rollouts, KEDA, Tekton, Rook, Strimzi, and other Kubernetes operators.
