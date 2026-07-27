# Writing the requirements

A requirement that cannot be checked is not a requirement, it is a sentiment.
Model output drifts toward sentiment unless the rules below are enforced, and
`scripts/lint.py` mechanically rejects the most common failures.

---

## Three rules

### 1. Verifiable

Whether the requirement is met must be decidable. If two competent engineers
could disagree about whether it is satisfied, it is not written yet.

| no | yes |
|---|---|
| Appropriate access control must be implemented | Every request for an order must verify that the order belongs to the caller's tenant before the record is returned |
| Logs must be adequately protected | The audit log destination must not be writable by any identity whose actions it records |
| Data must be encrypted where necessary | Personal data at rest must be encrypted with a customer-managed key |

Banned as the operative term: *appropriate, adequate, sufficient, as needed,
where necessary, properly, robust, secure, best practice, regularly*.

### 2. Atomic

One requirement, one concern. Conjunctions joining two obligations mean two
requirements — otherwise the pair can only ever be marked done or not done
together, and partial implementation hides.

| no | yes |
|---|---|
| Data must be encrypted and access must be logged | REQ-A: data at rest encrypted with a customer-managed key<br>REQ-B: read access to that data recorded in the audit log |

### 3. States a property, not an implementation

Say what must be true. How to achieve it belongs in guidance, where the team
can choose.

| no | yes |
|---|---|
| Set `ssl_protocols TLSv1.2 TLSv1.3` in nginx | Traffic carrying personal data must use TLS 1.2 or higher |
| Use Redis with a per-tenant key prefix | Cached entries must not be readable across tenant boundaries |

The failure mode is real: a requirement that names nginx is wrong the moment
the service moves to a managed load balancer, and the document rots. It also
takes an architecture decision away from the team that owns it.

Exception: where a specific mechanism *is* the obligation — a named algorithm
required by a regulation, or a provider setting with no alternative — state it
and record why in `rationale`.

---

## Record shape

```yaml
- id: REQ-DATA-ENC-REST-01
  managed:
    statement: "Personal data at rest must be encrypted with a customer-managed key."
    rationale: >-
      Storage-level encryption with provider-managed keys does not give the
      organisation key custody, which the control requires where the data is
      subject to a separate legal basis.
    csf: [PR.DS-01]
    sources: [SC-28, SC-28(1), SC-13, ASVS-6.2.1]
    threat_refs: [T-03]
    responsibility: shared
    csp_part: "Operates the KMS infrastructure and the encryption mechanism."
    team_part: "Enables default encryption and supplies a customer-managed key."
    evidence: "AWS SOC 2 Type II report, plus terraform state"
    verification:
      method: iac_inspect
      target: "aws_s3_bucket_server_side_encryption_configuration"
      expect: "sse_algorithm = aws:kms with a customer-managed key arn"
      fallback_manual: "Console > S3 > bucket > Properties > Default encryption"
    priority: high
  human: {}
```

### Identifiers

`REQ-<DOMAIN>-<TOPIC>-<NN>`, derived from content. **Never a running number.**

If a requirement is inserted and everything below it shifts, then existing
tickets, audit evidence, and exception approvals all point at the wrong thing.
`scripts/merge.py` keeps the issued identifiers in `state.yaml` and reuses them.

### Field ownership

`managed` belongs to the tool. `human` belongs to the reader and is never
overwritten — status, priority overrides, exception approvals, evidence links.
When a re-run wants to change a `managed` field on a requirement that carries
`human` content, the change goes to `pending_review` for approval rather than
being applied.

### Requirements are not deleted

Status transitions only: `active`, `superseded_by`, `retired`, each with a
reason. A requirement that appeared in last quarter's audit report and is
absent from this one will be asked about, and "the tool did not generate it
this time" is not an answer.

---

## Language

Follow the profile `locale` for `statement`, `rationale`, `team_part`,
`csp_part`, and `fallback_manual`.

Keep in English regardless of locale: identifiers, enum values
(`responsibility`, `method`, `status`), control identifiers and their quoted
text, and code identifiers in `verification.target`.

Control text is never translated. The original is the evidence; a translation
invites an argument about interpretation at audit.

---

## Priority

| priority | when |
|---|---|
| `high` | in the baseline **and** matched by a service-specific threat |
| `high` | derived from a threat with `novelty: service_specific` and no baseline coverage |
| `medium` | in the baseline, matched only by a generic threat |
| `low` | in the baseline with no matching threat — retained for coverage, rationale recorded |

Never drop a `low`. It is the baseline's completeness guarantee, and its
presence is what lets the document answer "why is this family absent?"

---

## Requirements forced by data type

Some entries in `classification.yaml` carry `forces_requirements`. These are
generated regardless of the threat model, because they address failures that
are common and easy to miss:

| trigger | requirement |
|---|---|
| `app_logs` | `log_sanitization` — personal data and credentials must not be written to application logs |
| `user_generated_content` | `upload_validation` — uploaded files must be validated and stored outside any execution path |


## What may be published

`docs/security/` is publishable and `.security-requirements/` is not. The README
gives the reason in one sentence: the internal side records where the data
lives, which trust boundaries exist, which controls are not implemented, and
which risks were accepted until when.

Four `managed` fields reach the published documents as free text -- `evidence`,
`csp_part`, `team_part`, and `verification.target` -- and free text names
buckets, hosts, repositories, and paths. Name the *kind* of thing:

| Instead of | Write |
|---|---|
| `arn:aws:s3:::acme-prod-customer-data` | `the bucket holding customer exports` |
| `https://wiki.internal/soc2` | `the provider's SOC 2 report` |
| `/etc/app/config.yaml` | `the application's configuration file` |
| `10.0.4.12` | `the load balancer` |

A requirement that names a kind of thing also survives the next redeployment,
which is the same reason the style guide asks for properties rather than
products. The linter warns on the five forms that cannot be a kind of thing --
an ARN, a URL, an IP address, an absolute path, an internal hostname -- and
cannot judge the rest.
