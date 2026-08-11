# Threat modeling procedure

## Why this step decides whether the tool is worth using

The derivation runs two paths and crosses them:

```
profile
  |-- FIPS 199 impact -> 800-53B baseline
  |-- DFD -> STRIDE / LINDDUN -> threats
        |
        v  cross
  threat AND baseline  ->  raised priority
  threat only          ->  additional requirement    <- the reason this tool exists
  baseline only        ->  retained, lower priority, rationale recorded
```

If threat modeling returns generic material, the `threat only` bucket is empty
and the tool degrades into a baseline filter. Anyone can download the baseline.

Generic output looks like this, and all of it is already in the baseline:

> - An attacker could attempt SQL injection
> - Authentication bypass could allow unauthorised access
> - Sensitive data might be transmitted in cleartext

Useful output is specific to *this* service:

> - A tenant administrator enumerates sequential `order_id` values and reads
>   another tenant's orders, because authorisation checks that the caller is
>   logged in but not that the caller owns the record
> - A refund is issued twice by replaying the webhook, because idempotency is
>   keyed on an identifier the caller controls
> - Personal data leaves the boundary inside a stack trace, because the error
>   reporter serialises the request context

Judge every threat by one question: **could this be written without knowing
anything about this particular service?** If yes, mark it `novelty: generic`
and expect the baseline to cover it.

---

## Step 1 — Data flow diagram first

Do not start by listing threats. Start by writing down the structure. Threats
found without a structure are recalled, not derived.

Produce, from the profile:

- **external entities** — anyone and anything outside the boundary: end users
  by type, third-party services from Q4, operators
- **processes** — the services, functions, and jobs from `entrypoints`
- **data stores** — from `managed_services`, plus logs, caches, queues, backups
- **trust boundaries** — every point where data crosses between parties with
  different privilege

Boundaries are the interesting part. Common ones that get missed:

| Boundary | Why it is missed |
|---|---|
| tenant to tenant | both sides are authenticated, so it looks internal |
| service to service inside the VPC | "internal network" is treated as trusted |
| application to log pipeline | logs are not thought of as a data flow |
| application to error reporter | crosses to a third party, invisibly |
| runtime to backup or snapshot | different access controls, longer retention |
| admin console to production data | staff are not modelled as a threat source |

---

## Step 2 — STRIDE per boundary crossing

For each flow crossing a boundary, walk the six categories. Do not walk STRIDE
per component — per crossing. That is what produces flow-specific threats
instead of component clichés.

| | category | question at this crossing |
|---|---|---|
| S | spoofing | can the caller claim to be someone else here? |
| T | tampering | can the data be altered in transit or at rest here? |
| R | repudiation | can an actor deny having done this? |
| I | information disclosure | what does the receiving side learn that it should not? |
| D | denial of service | what happens when this flow is flooded or stalled? |
| E | elevation of privilege | can crossing here gain authority not held before? |

When `business_tenant` appears in the profile, elevation and information
disclosure at the tenant boundary are mandatory: work through object reference
handling, cache key construction, background job scoping, and export paths.

---

## Step 3 — LINDDUN when personal data is present

STRIDE does not model privacy harm. Linkability and identifiability appear
nowhere in its six categories. If the profile declares any personal data type,
or carries the `linddun_linkability` flag, run this pass as well.

| category | question |
|---|---|
| Linkability | can two records be tied to the same person without identifying them? |
| Identifiability | can a person be singled out from supposedly anonymous data? |
| Non-repudiation | is someone unable to deny an action they should be able to deny? |
| Detectability | does the existence of a record reveal something? |
| Disclosure of information | is data exposed beyond its purpose? |
| Unawareness | does the person not know this processing happens? |
| Non-compliance | does processing exceed the stated purpose or retention? |

Pseudonymous analytics is the usual finding: a device identifier that persists
across sessions re-identifies a user the system believes it anonymised.

---

## Step 4 — Persona expansion

Take the threats found so far and push them through four attacker positions.
Each has different starting authority, and the same weakness has different
consequences from each.

| persona | starting position |
|---|---|
| `anonymous_external` | no credentials, reaches public entrypoints only |
| `authenticated_tenant` | valid account in another tenant |
| `insider_staff` | operator or support access to production |
| `compromised_dependency` | code execution inside the build or runtime |

`compromised_dependency` is routinely skipped and routinely relevant: a build
step with cloud credentials turns a package compromise into an infrastructure
compromise.

---

## Step 5 — Record

```yaml
boundaries:
  - id: TB-4
    from: order-svc
    to: postgres
    note: "application to primary data store"

threats:
  - id: T-07
    boundary: TB-4
    category: STRIDE:E
    novelty: service_specific        # or: generic
    persona: authenticated_tenant
    scenario: >-
      A tenant administrator enumerates sequential order_id values and reads
      another tenant's orders. Authorisation checks that the caller is
      authenticated but not that the record belongs to their tenant.
    affected_assets: [transaction_history]
    related_controls: [AC-3, AC-4]   # verified against the bundled catalog

  - id: T-11
    boundary: TB-6
    category: LINDDUN:Linkability
    novelty: service_specific
    persona: insider_staff
    scenario: >-
      device_id in the analytics stream persists across sessions and joins to
      the account table, re-identifying users in data held as anonymous.
    affected_assets: [analytics_pseudonymous]
```

Required fields: `boundary`, `category`, `novelty`, `persona`, `scenario`,
`affected_assets`, `related_controls`. A scenario that does not name a concrete
mechanism is not finished — "authorisation may be insufficient" is a category,
not a threat.

`related_controls` is where judgement stops and arithmetic begins. Deciding
which controls address a threat needs understanding; crossing that against the
baseline afterwards does not. Populate it by consulting the bundled catalog, not
from memory — `scripts/lint.py` rejects identifiers the catalog does not
contain, and `scripts/merge.py --cross` uses the field to compute:

- threat with related controls **in** the baseline -> raised priority
- threat with **no** related control in the baseline -> additional requirement
- baseline control referenced by **no** threat -> retained, lower priority

Leave it empty when no existing control addresses the threat. An empty list is
a finding, not an omission: it is exactly how a service-specific requirement
gets created.

---

## Anti-patterns

- **Reciting OWASP Top 10.** Those are vulnerability classes, not threats to
  this system. The baseline already covers them
- **One threat per component.** Threats live on flows across boundaries
- **Stopping at the happy path.** Refunds, exports, admin actions, background
  jobs, and retries are where business logic abuse lives
- **Treating the internal network as a boundary that does not need crossing.**
  It is a boundary; that is the point
- **Skipping data at rest.** Backups, snapshots, and caches carry the same data
  under weaker controls
