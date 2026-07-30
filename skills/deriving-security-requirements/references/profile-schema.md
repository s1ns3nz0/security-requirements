# Service profile: schema and interview procedure

The profile is the single input to requirement derivation. If the profile is
wrong, everything below it is wrong in a precise and convincing way, and the
reader has no way to trace back to the cause. That is why profile confirmation
is a hard gate.

---

## 1. Where each field comes from

Fields fall into two groups. Keeping them separate is what stops the interview
from growing to twenty questions and losing the user on first run.

**Inferred from the repository — never asked**

| Field | Evidence |
|---|---|
| `csp` | `*.tf`, `serverless.yml`, `cdk.json`, SDK dependencies, CI config |
| `managed_services` | IaC resource types, SDK client construction |
| `deployment_model` | container definitions, function handlers, VM provisioning |
| `stack` | manifests (`package.json`, `go.mod`, `pyproject.toml`, …) |
| `auth_mechanism` | auth libraries, middleware, IdP configuration |
| `entrypoints` | route definitions, API specs, event triggers |
| `external_integrations` | SDK dependencies, outbound calls, webhook handlers |
| `region_storage` | region settings in IaC |
| `repo.visibility` | `gh repo view --json visibility` |

**Only a person can answer — always asked**

Code carries no intent. The existence of a `users` table says nothing about
what goes in it, who should reach it, or how long it may be unavailable.

---

## 2. Question budget

**Seven mandatory questions, no more.**

- Inferred values are **confirmed, not asked** — present them together at the gate
- If inference fails and the user does not know, record `UNDETERMINED` and
  continue. Never fill the gap with a guess: a wrong value is worse than an
  empty one, because it becomes the stated basis for dozens of requirements
- Optional questions appear only when the user asks for more precision

---

## 3. The seven questions

Ask in the service owner's vocabulary. "Is your integrity impact Moderate?" is
a practitioner's question; asked that way it either gets no answer or an
inflated one, and an inflated answer doubles the requirement count until the
document is discarded.

Render questions in the profile `locale`. Wording below is illustrative.

---

### Q1 — What data does this service handle?

> Select everything that applies.

Present the `types` list from `catalogs/data-types/classification.yaml`. For
each selection, follow up on modifiers ("do you hold the card number itself, or
only a PSP token?").

Where `account_credentials` or `config_secrets` is selected, the follow-up is
about role rather than state:

> Does this service hold these so it can do something else, or is holding them
> what it is for?

The table's default is the first, because credentials sit in nearly every
service and counting them would put every application with a login on the High
baseline. An identity provider, a secrets manager, or a credential vault is the
second, and for those the default reading derives LOW integrity for the one
thing protecting everything downstream. The answer becomes the `service_content`
modifier. It costs no question -- it is the same per-selection follow-up as the
card-number one.

- **Consumed by**: confidentiality and integrity derivation, regulatory trigger
  detection, threat model asset list
- **Inference aid**: scan schema files and migrations for column names.
  `resident_reg_no`, `card_`, `ssn`, `birth` are strong signals. Use them to
  pre-check boxes only — never to conclude
- **Note**: selections carrying `regulatory_triggers` produce a not-covered
  warning, gated on jurisdiction from Q7

---

### Q2 — How much downtime and data loss is tolerable?

> If this service stops, how quickly must it be back?
> And how much data may be lost?

Present `rto_buckets` and `rpo_buckets` from
`catalogs/data-types/availability.yaml`, then `amplifiers` as a multi-select.

- **Consumed by**: availability derivation, backup and recovery requirements
- **Note**: `safety_critical` sets availability to High regardless of the other
  answers. RTO and RPO are different questions — see the calibration note in
  that file

---

### Q3 — Who uses this service?

```
[ ] anyone, without signing in
[ ] individual registered users
[ ] business customers, data separated per organisation    <- multi-tenant
[ ] internal staff only
[ ] other systems (service to service)
```

- **Consumed by**: threat personas, trust boundary identification, ASVS level
- **Why it matters**: multi-tenancy changes the character of the threat model.
  "An authenticated user reaching another tenant's data" is not a threat the
  baseline surfaces, and it is precisely where this tool earns its place
- **Inference aid**: `tenant_id` / `org_id` columns, row-level security
  policies, scope handling in middleware

---

### Q4 — What is the boundary, and what leaves it?

> How far does our responsibility extend?
> Does data go to any external service?

Present the inferred `external_integrations` and confirm each:

```
detected: Stripe, Sentry, Datadog, SendGrid
  Stripe   -> payment data   [confirm] [no]
  Sentry   -> error reports; may these carry personal data?  [yes] [no] [unsure]
  ...
```

- **Consumed by**: DFD external entities, trust boundaries, processor
  requirements, third-party risk
- **Why it matters**: personal data riding out in a stack trace to an error
  reporting SaaS is among the most common real incidents. Static analysis does
  not find it. Asking does

---

### Q5 — Any regulation or contractual obligation already fixed?

```
[ ] none / unsure      <- default: NIST CSF 2.0 with the 800-53 backend
[ ] yes, namely: ______
```

- **Consumed by**: overlay selection (v1 declares only), baseline elevation
- **Note**: v1 supports no overlays. Record the answer in the profile and state
  plainly in the output that it is not covered. **Do not imply coverage**

---

### Q5b — Is any interface fixed by something outside this service?

```
[ ] no
[ ] yes, namely: ______   <- a protocol, an API someone else defines, a client
                             we do not ship, a wire format we must accept
```

- **Consumed by**: requirement writing (`requirement-style.md`, rule 4)
- **Why it is asked**: a service that implements someone else's protocol cannot
  change what it accepts, and a requirement telling it to is a requirement that
  gets crossed off. This came out of a derivation for a server whose whole
  purpose is API compatibility with a client it does not ship: the requirement
  said the server must refuse weak parameters, and refusing them would have
  broken registration from the official client. The constraint was as binding as
  "the organisation has no second approver" and there was nowhere to write it.
- **Written as**: `declared.fixed_interfaces: ["Bitwarden client API"]`, or an
  empty list. Empty means the service controls its own interfaces, which is the
  common case and worth stating rather than leaving to inference.

---

### Q6 — What controls does the organisation already have?

```
[ ] dedicated security function
[ ] company-wide SSO / identity provider
[ ] centralised log collection
[ ] information security policy set
[ ] periodic access review process
[ ] incident response process
[ ] none of these yet
```

- **Consumed by**: filtering the organisational bucket, suppressing duplicate
  requirements
- **Why it matters**: without this the tool demands things the organisation
  already has. Telling a team that runs company-wide SSO to "introduce
  centralised authentication" tells them the tool does not understand their
  situation, and they stop trusting the rest of the output
- **Note**: an existing control does not delete the requirement. It is
  classified as `org` and annotated. The control still has to be answered at
  audit — just by someone else

---

### Q7 — Where is data stored, and where are the users?

- **Consumed by**: cross-border transfer requirements, regulatory trigger
  gating, region-specific provider rules
- **Inference aid**: storage region comes from IaC. User regions must be asked
- **Note**: jurisdiction gates the regulatory triggers from Q1. A service with
  Korean and Japanese users should not be told GDPR applies — a false trigger
  costs the reader's trust in every other finding. Where the storage country
  differs from the user regions, a cross-border transfer item is raised. v1
  writes the requirement; it does not make the legal determination

---

## 4. Schema

```yaml
version: "0.1.0"
locale: en                        # keeps language consistent across re-runs
generated_at: "2026-07-27"
catalog_versions:
  nist_800_53: r5
  csf: "2.0"
  asvs: "5.0"
  data_types: "0.2.0"

repo:
  visibility: private             # decides where sensitive output may live
  root: "."

# --- inferred; confirmed at the gate ---
inferred:
  csp: aws
  deployment_model: serverless    # iaas | paas | serverless | saas | onprem | hybrid
  managed_services:
    - id: aws-s3
      evidence: "infra/storage.tf:12"
    - id: aws-bedrock
      evidence: "src/llm/client.ts:8"
      curated: false              # no responsibility/services file -> unverified
  stack: [typescript, node20]
  auth_mechanism: oidc_cognito
  entrypoints:
    - "POST /api/v1/orders"
    - "sqs: order-events"
  external_integrations:
    - name: sentry
      purpose: error_reporting
      data_sent: UNDETERMINED     # resolve in Q4
  region_storage: ap-northeast-2

# --- interview ---
declared:
  # Empty means this service controls its own interfaces. A named entry is a
  # protocol or client it must keep accepting, and a requirement that changes
  # what it accepts is refused before it is written.
  fixed_interfaces: []
  data_types:
    - id: basic_contact
    - id: payment_token
      modifiers: [tokenized_external]
    - id: audit_logs
  availability:
    rto: rto_hours
    rpo: rpo_zero
    amplifiers: [revenue_direct, contractual_sla]
  users:
    - authenticated_individual
    - business_tenant             # multi-tenant: forces tenant isolation threats
  regulations_declared: []
  existing_org_controls: [sso, central_logging]
  user_regions: [KR, JP]

# --- derived by select_baseline.py; adjustable at the gate ---
derived:
  impact:
    confidentiality: {level: moderate, because: [...]}
    integrity: {level: moderate, because: [...]}
    availability: {level: moderate, because: [...]}
    system: moderate              # high water mark
    overridden_by_user: false
    # override: {system: low, reason: "..."}
  baseline: nist-800-53b-moderate
  asvs_level: 2
  regulatory_flags: [pipa_general]
  threat_flags: []                # e.g. linddun_linkability

# --- written only after explicit user confirmation ---
confirmation:
  status: confirmed
  confirmed_by: user
  confirmed_at: "2026-07-31T10:00:00Z"
  profile_digest: "sha256:..."     # exact profile, excluding this block
```

---

## 5. Confirmation gate

Show the full derivation before accepting the profile. A bare level gives the
user no way to spot an error.

```
Impact derivation

  Confidentiality MODERATE
      <- member email, name, contact details: moderate
      <- PSP tokens, last four digits [originals held externally]: low

  Integrity       MODERATE
      <- transaction, order, and settlement records: moderate
      <- no tolerable data loss (RPO 0): moderate

  Availability    MODERATE
      <- hours; recovery within the business day is acceptable: moderate
      <- an outage stops revenue directly: moderate

  System impact: MODERATE  (high water mark)
  Baseline: nist-800-53b-moderate

  [confirm]  [adjust level]  [redo answers]
```

An adjustment records `overridden_by_user: true` and the reason. "Why Moderate?"
must have an answer at audit.

After explicit confirmation, use `scripts/confirmation.py --stamp` as directed
by the command. A later change anywhere in the profile invalidates the digest
and requires this gate again. Builds use `--check`; conversation memory is not
an approval record.

---

## 6. Handling UNDETERMINED

Leave unresolved fields empty and continue — but **state the consequence**.

```
Unresolved

  Whether data sent to Sentry includes personal data
  -> effect: no processor requirement was generated.
     Confirm and run refresh.
```

A guessed value becomes the stated basis for dozens of requirements, and the
reader never learns it was a guess.
