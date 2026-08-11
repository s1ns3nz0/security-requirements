# AWS — provider-specific guidance

**Written by the authors of this repository.** AWS documentation is
copyrighted and is not reproduced here. Every rule below is a summary in our
own words with a link to the original, which is the source of truth.

Scope: patterns that change what a *requirement* should say, not a
configuration checklist. Per-service control responsibility lives in
`responsibility/services/*.yaml`; this file covers the account-wide and
cross-service behaviour that no single service file owns.

---

## The defaults that are not the safe ones

A recurring shape: AWS ships the permissive option because the restrictive one
would break someone's use case. These are the points where a requirement has to
say something, because silence resolves to the wrong answer.

| Behaviour | Why it needs stating |
|---|---|
| S3 accepts plain HTTP | TLS is only enforced if the bucket policy denies `aws:SecureTransport = false` |
| RDS accepts unencrypted connections | The parameter group must force it; most drivers do not verify certificates by default |
| RDS encryption cannot be enabled in place | It is chosen at creation. A design-stage requirement, not a review finding |
| Lambda outside a VPC has unrestricted egress | Nothing inspects what leaves |
| API Gateway routes are open unless an authoriser is attached | An unauthenticated route is created by omission |
| CloudTrail records management events only | Object reads and item reads need data events enabled separately |
| Cognito advanced security is off | Without it there is no lockout or risk response |
| DynamoDB point-in-time recovery is off | It cannot be applied retroactively |
| Access logs are off on ALB, CloudFront, and API Gateway | The requests that never reached the application are the ones with no record |

Reference: [AWS Security Best Practices](https://docs.aws.amazon.com/security/)

---

## Shared responsibility, stated precisely

AWS publishes the model as infrastructure versus customer. That boundary is
correct and too coarse to assign work from: it puts encryption entirely on the
customer side while the key infrastructure is entirely on the provider side.

The four-bucket split in `responsibility/layers.yaml` exists because of this.
When writing a requirement for a control AWS describes as customer
responsibility, state both halves — what AWS operates, and what the team must
configure — or the team will read "customer responsibility" as "build it
yourself" and the reviewer will read it as "AWS handles it".

Evidence for provider-claimed controls comes from AWS Artifact (SOC 2 Type II,
ISO 27001, PCI AOC). Requirements marked `csp_claimed` must name the report,
because obtaining it is the customer's actual obligation.

Reference: [Shared Responsibility Model](https://aws.amazon.com/compliance/shared-responsibility-model/),
[AWS Artifact](https://aws.amazon.com/artifact/)

---

## Identity

**Roles, not users.** Long-lived access keys are the most common credential
leak. Requirements should specify workload identity — task roles, execution
roles, IRSA, or OIDC federation from the CI provider — rather than key rotation
schedules for keys that should not exist.

**The CI role is a production credential.** A pipeline that can deploy can
usually read production data. Scope the OIDC trust policy to the specific
repository *and* ref; a policy trusting the whole organisation lets any
repository in it assume the role.

**Service control policies are the only guardrail a team cannot switch off.**
Where an organisational requirement must hold regardless of what a delivery
team configures — region restriction, mandatory encryption, deny for root
credential use — it belongs in an SCP, and the requirement's responsibility is
`org`, not `team`.

Reference: [IAM best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)

---

## Keys

**AWS-owned, AWS-managed, and customer-managed keys are three different
answers.** Only customer-managed keys give key policy control, grant
visibility, rotation control, and the ability to revoke access by disabling the
key. Where a requirement derives from a control demanding key custody, "the
service encrypts at rest by default" does not satisfy it.

**Key policies are not IAM policies.** A key policy that omits the account
principal cannot be repaired through IAM, and a key with no usable
administrator is unrecoverable.

Reference: [KMS key policies](https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html)

---

## Data location

Most services are regional and data stays in the region unless something moves
it. The exceptions are what a cross-border requirement must name:

- CloudFront caches at edge locations worldwide
- IAM, Route 53, and a few others are global by design
- Cross-region replication, global tables, and cross-region backups move data
  deliberately — usually configured for availability, with the transfer
  consequence unconsidered

When the profile shows storage in a country other than the users' region, the
requirement should name the specific mechanism carrying data across, not the
region setting alone.

Reference: [AWS Regions and data residency](https://aws.amazon.com/compliance/data-privacy/)

---

## Logging that survives its own compromise

An audit log in the same account as the workload can be deleted by whoever
compromises the workload. Requirements for `AU-9` on AWS should specify a
destination outside the workload's trust domain — a separate log archive
account — and, where the retention must survive a compromised administrator,
S3 Object Lock in compliance mode.

CloudTrail organisation trails and log file validation both exist for this and
are both off by default.

Reference: [CloudTrail security best practices](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html)

---

## What this file is not

It is not a benchmark. CIS publishes one, and its terms do not permit
redistribution, so it is not bundled or paraphrased here. If an organisation
uses CIS benchmarks, the mapping from these requirements to benchmark items is
their own work.
