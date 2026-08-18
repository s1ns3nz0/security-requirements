# Deriving Security Requirements from an AWS Serverless Sample, Part 2: Determining CIA Impact and the Control Baseline

In Part 1, we built a profile of a movie-rating service based on AWS's `aws-serverless-crud-sample`.

The repository showed a serverless architecture using API Gateway, Lambda, DynamoDB, and CloudWatch Logs. We then added the operating assumptions that the code alone could not establish.

| Area | Confirmed operating context |
|---|---|
| Service | API for browsing, adding, deleting, and rating movies |
| Users | Anonymous internet users |
| Data | Public movie titles, release years, descriptions, and ratings |
| Read policy | Anonymous access allowed |
| Write policy | Authenticated and authorized users only |
| RTO | One day or longer |
| RPO | Several hours or longer |
| Regulation and contracts | No additional obligations declared |
| Storage region | Undetermined |
| Authentication mechanism | Undetermined |

The plugin now converts this profile into the starting point for control selection.

The central question in this stage is:

> If this service discloses or corrupts data, or becomes unavailable, how serious is the harm—and which controls should be considered for that level of impact?

The process has four main parts.

```text
Data types ─────────────────→ confidentiality and integrity impact
Recovery objectives ────────→ availability impact
                              ↓
                  Highest CIA impact level
                              ↓
          NIST 800-53B baseline + ASVS level
```

---

## Why the model does not select the controls directly

One design principle matters especially in this stage: the language model does not calculate the impact level or recall the NIST baseline from memory. The deterministic [`select_baseline.py`](../../scripts/select_baseline.py) script consumes the confirmed profile and performs the calculation.

“Which controls belong to the NIST 800-53B Moderate baseline?” is not a creative judgment. It is a lookup against a published set.

Asking a model to recall that set introduces avoidable failure modes:

- The selected controls may vary between runs.
- The model may invent a control identifier that does not exist.
- A control enhancement may be assigned to the wrong baseline.
- Identical profiles may not produce reproducible results.
- An auditor may be unable to reconstruct why a control was included.

The plugin therefore divides responsibility as follows:

| Work | Responsible component |
|---|---|
| Establish what the data means | Service owner and model |
| Map the data to the classification table | Model interpretation, confirmed by the owner |
| Calculate CIA impact | Deterministic script |
| Select the NIST baseline | Deterministic script |
| Resolve baseline control IDs | Bundled catalog |
| Analyze service-specific threats | Model |
| Write controls as service-specific requirements | Model |
| Validate control identifiers | Linter and bundled catalog |

The model interprets the service and writes requirements. Code handles predefined sets and arithmetic.

---

## 1. Classifying the public movie data

Part 1 classified movie titles, release years, descriptions, and ratings as `public_content`.

The plugin's data classification catalog defines that type as follows:

```yaml
- id: public_content
  label: "public content (notices, catalogue, documentation)"
  confidentiality: low
  integrity: moderate
  rationale: >-
    Confidentiality is irrelevant; tampering creates trust
    and legal problems.
```

This classification matches the service well. Movie information is stored so that it can be shown to users. Reading a public movie title or rating does not disclose an additional secret.

Unauthorized modification is different. If someone can alter titles, manipulate ratings, or delete records, the service loses its central property: trustworthy movie information.

The same data therefore produces different impact levels on different axes:

```text
Confidentiality: Low
Integrity:       Moderate
```

### Why public data still has Moderate integrity impact

“Public” describes who may read the data. It does not describe who may change it.

These are different policies:

```text
Anyone may read movie information.
Anyone may change movie information.
```

The first may be expected behavior for a public service. The second permits catalog tampering and rating manipulation.

The likely consequences include:

- Users receive false movie information.
- Rating results can no longer be trusted.
- An attacker can deliberately promote or suppress a movie.
- Operators must determine which records remain valid.
- Recovery may require an audit investigation or restoration from backup.

This is not a severe or catastrophic consequence comparable to loss of life or systemic financial harm, so High would be excessive. It is more than a limited inconvenience, however. Corruption undermines the service's core purpose and requires recovery work, making Moderate the better fit.

---

## 2. What the `intended_public` modifier changes

The profile records the publication intent explicitly:

```yaml
data_types:
  - id: public_content
    modifiers:
      - intended_public
```

`intended_public` fixes confidentiality at Low. It does not reduce integrity or availability.

```text
Intended for publication
  ├─ Confidentiality: Low
  ├─ Integrity: unchanged
  └─ Availability: unchanged
```

The distinction is important because public-content systems can still suffer from:

- Defacement of public notices
- Replacement of software distribution files
- Unauthorized price changes
- Modification of documentation
- Manipulation of movie ratings
- Forged public API responses

Public information does not need to remain secret, but its accuracy and provenance may remain critical.

For `public_content`, the base classification is already Low confidentiality and Moderate integrity. The modifier therefore does not change the final numbers. Instead, it records that publication is intentional rather than accidental.

The declaration also informs consistency checks around authentication. A service without authentication may consistently expose read access to published content. Any state-changing endpoint still needs a caller it can identify.

---

## 3. Calculating confidentiality impact

The only declared business data is public movie content.

```text
public_content
  → confidentiality: Low
```

The confidentiality result is therefore:

```yaml
confidentiality:
  level: low
  because:
    - "Movie titles, release years, descriptions, and ratings are intended for publication"
```

### Why AWS credentials do not automatically make the system High

The sample's `app_config.json` contains fields for an AWS access key and secret key. Those credentials are unquestionably sensitive.

Even so, the plugin normally excludes application credentials and configuration secrets from the system-impact high-water mark.

The reason is that credentials and API keys exist in almost every service. Counting them like ordinary business data would automatically classify most authenticated applications as High-impact systems.

```text
Public movie data: C=Low
AWS credentials:  C=High

Naive high-water mark:
System confidentiality = High
```

That result appears conservative, but it would produce hundreds of controls for nearly every service and make the output impractical.

The plugin separates two concerns instead:

```text
Business data
  → determines system impact and baseline

System credentials and secrets
  → excluded from the general impact high-water mark
  → still force dedicated secret-management requirements
```

The AWS credentials do not disappear. They lead to requirements such as:

- Do not store long-lived AWS access keys in application configuration.
- Supply short-lived credentials through the Lambda execution role.
- Prevent secrets from reaching logs and error responses.
- Restrict the execution role to the required DynamoDB actions and resources.

The rule changes when holding credentials is the purpose of the service. An identity provider, credential vault, or secrets manager marks them as `service_content`, allowing their High impact to enter the system categorization.

---

## 4. Calculating integrity impact

`public_content` has a default integrity impact of Moderate.

```text
public_content
  → integrity: Moderate
```

The integrity result is:

```yaml
integrity:
  level: moderate
  because:
    - "Tampering with movie information and ratings undermines trust in the service"
```

The write policy defined in Part 1 supports this conclusion:

```text
Anonymous reads:  allowed
Anonymous writes: not allowed
```

If the content truly had only Low integrity importance, there would be less business justification for restricting who may change it. Our operating scenario explicitly distinguishes reading from mutation.

This result will later shape controls concerning:

- Caller authentication before write operations
- Authorization for each operation
- Least privilege for the Lambda execution role
- Auditability of changes
- Input validation
- Recovery of modified data
- Detection of unauthorized changes

No service-specific requirement has been written yet. Stage 2 establishes the control scope. Concrete requirements come after the threat model is crossed with those controls.

---

## 5. Calculating availability impact

Part 1 assumed these recovery objectives:

```yaml
availability:
  rto: rto_day_plus
  rpo: rpo_hours_plus
  amplifiers: []
```

### How RTO contributes to availability

`rto_day_plus` means that an outage of one day or longer is tolerable.

```text
RTO: one day or longer
→ Availability: Low
```

For this operating scenario, an outage does not cause:

- Physical harm or loss of life
- Immediate interruption of payment or settlement
- Failure to meet a statutory filing deadline
- Cascading failure of other critical systems
- Contractual damages for violating an availability SLA

There is no basis for Moderate or High availability impact.

### How RPO contributes to availability and integrity

`rpo_hours_plus` means that daily backups are sufficient and that several hours of changes may be re-entered or lost.

```text
RPO: several hours or longer
→ Availability: Low
→ No additional integrity increase
```

RPO is not only an availability concern. Losing committed data is also an integrity and durability issue.

If the service had declared that no acknowledged transaction could ever be lost—an RPO of zero—the plugin would raise integrity to at least Moderate. This service already has Moderate integrity because of `public_content`, but `rpo_hours_plus` adds no further increase.

### Why no availability amplifier applies

The operating scenario does not select any of these amplifiers:

- `safety_critical`
- `revenue_direct`
- `regulatory_reporting`
- `single_point_dependency`
- `contractual_sla`

Nothing therefore raises availability above the Low result produced by the RTO and RPO.

```yaml
availability:
  level: low
  because:
    - "An outage of one day or longer is tolerable"
    - "Several hours of changed data may be lost"
    - "No safety, revenue, statutory, dependency, or SLA amplifier was declared"
```

---

## 6. Applying the CIA high-water mark

The three calculated axes are:

| Axis | Level | Primary reason |
|---|---:|---|
| Confidentiality | Low | Movie information is intended for publication |
| Integrity | Moderate | Tampering undermines trust in the service |
| Availability | Low | A day-long outage and several hours of data loss are tolerable |

The plugin does not average the values. It selects the highest impact level.

```text
System impact
  = max(Confidentiality, Integrity, Availability)
  = max(Low, Moderate, Low)
  = Moderate
```

This is the high-water-mark rule.

### Why an average would be misleading

Low confidentiality and Low availability do not offset Moderate integrity.

An averaging intuition might produce this incorrect conclusion:

```text
Low + Moderate + Low
→ mostly a Low-impact system
```

An attacker does not cause an average impact across the three axes. If an attacker corrupts the movie catalog and ratings at scale, Low confidentiality and availability provide no protection from that integrity harm.

The highest axis therefore determines the system category.

---

## 7. Why the plugin selects the NIST 800-53B Moderate baseline

The mapping from system impact to security baseline is direct:

| System impact | Security baseline |
|---|---|
| Low | NIST SP 800-53B Low |
| Moderate | NIST SP 800-53B Moderate |
| High | NIST SP 800-53B High |

Because this service has Moderate system impact, the plugin selects:

```yaml
derived:
  impact:
    confidentiality:
      level: low
    integrity:
      level: moderate
    availability:
      level: low

    system:
      level: moderate
      driver:
        - integrity

  baseline: nist-800-53b-moderate
```

The bundled catalogs currently contain these baseline sizes:

| Baseline | Controls |
|---|---:|
| Low | 149 |
| Moderate | 287 |
| High | 370 |

Stage 2 therefore selects 287 controls from the Moderate baseline as the initial review set.

### Are 287 controls excessive for a small movie service?

They would be if all 287 became implementation tickets for the delivery team. That is not what the number means.

At this point, the controls are a completeness-oriented starting set rather than the final requirements.

```text
287 Moderate-baseline controls
  ├─ controls implemented by the delivery team
  ├─ controls shared between AWS and the team
  ├─ provider claims that require assurance evidence
  ├─ organizational policies and processes
  ├─ controls raised in priority by service-specific threats
  └─ controls retained at lower priority when no threat matches
```

Physical data-center access, for example, is not assigned to the Lambda development team. It becomes an AWS provider claim requiring evidence such as a current assurance report.

Controls likely to remain with the team or under shared responsibility include:

- Least privilege for the Lambda execution role
- DynamoDB access control
- Protection of data in transit
- Generation and protection of audit logs
- Safe error handling
- Configuration management
- Backup and recovery configuration
- Application input validation

The baseline is therefore not “287 development tasks.” It is raw material for making sure that 287 control questions are not silently omitted before responsibility and relevance are evaluated.

---

## 8. Why the Privacy baseline does not apply yet

NIST SP 800-53B defines a Privacy baseline in addition to its Low, Moderate, and High security baselines.

The plugin adds the Privacy baseline when personal data is present. The current profile declares only:

```text
Movie title
Release year
Movie description
Public rating
```

It does not declare user accounts, email addresses, IP addresses, device identifiers, or viewing histories that can be connected to a natural person.

The current result is therefore:

```yaml
privacy_baseline_applies: false
privacy_controls: []
```

### Does anonymous use prove that no personal data exists?

No. A service can collect personal data without requiring a login, including:

- IP addresses
- User-Agent strings
- Cookie identifiers
- API Gateway access logs
- Request information written to CloudWatch
- Device identifiers from analytics SDKs

The first-stage profile did not establish whether these values are collected. The plugin must not conclude that anonymous users imply an absence of personal data.

The result should be read narrowly:

> No personal data is declared in the confirmed profile, so the Privacy baseline is not added. If operational logs or analytics contain identifiable information, the profile must be updated and the derivation rerun.

If later threat modeling discovers persistent device identifiers or request context in logs, both the personal-data classification and a LINDDUN privacy pass must be reconsidered.

---

## 9. Adding the 32 Program controls

Not every NIST control belongs to the Low, Moderate, or High security baselines. Some controls describe the organization's overall security program.

They cover areas such as:

- Security program management
- Risk-management strategy
- Organization-wide roles and responsibilities
- Security planning
- Assessment and authorization
- Supply-chain management
- Policies and procedures

The plugin adds this program layer separately.

```text
Moderate security baseline: 287 controls
Additional Program controls:  32 controls
-----------------------------------------
Union passed to the next stage: 319 controls
```

The 319 controls are not all responsibilities of the movie-service developers. Many Program controls will be assigned to the `org` responsibility category.

They remain visible because a responsibility outside the delivery team is still part of the audit picture. An organization-wide incident-response process cannot be implemented in Lambda code, but silently omitting it would leave no accountable owner.

```text
Not implemented by the service team
≠
Not required
```

---

## 10. Why OWASP ASVS Level 2 is selected

NIST 800-53 covers organizational, operational, infrastructure, and application concerns broadly. A web or API service also benefits from more concrete application-security verification criteria for authentication, authorization, sessions, and input validation.

The plugin therefore checks whether the service exposes an application surface to which ASVS applies.

This sample provides clear evidence:

- HTTP requests through API Gateway
- `GET /movies`
- `POST /add-movie`
- A Node.js Lambda processing paths and request bodies
- CRUD operations exposed through an API

An applicable web/API surface exists.

The current implementation maps system impact to a default ASVS level:

| System impact | ASVS level |
|---|---|
| Low | L1 |
| Moderate | L2 |
| High | L3 |

Because the system impact is Moderate, the result is:

```yaml
asvs_level: 2
```

### What ASVS L2 contributes

L2 is the standard verification level for ordinary applications. For this service, it is especially relevant to:

- Authentication of write requests
- Authorization of individual operations
- Validation of request types, lengths, and ranges
- Removal of internal detail from error responses
- Prevention of secrets and request data in logs
- Safe use of AWS SDK and DynamoDB interfaces
- Auditability of state-changing actions

ASVS does not replace NIST.

```text
NIST 800-53B
  → broad system and organizational control scope

OWASP ASVS
  → concrete verification properties for the web/API application

NIST CSF 2.0
  → reader-facing structure for the final requirements document
```

ASVS is also not assigned to every running system. A batch utility or industrial protocol gateway with no web or API application surface may receive no ASVS level even if its system impact is Moderate. This sample has a clear HTTP API, so L2 is appropriate.

---

## 11. Why no regulatory overlay is selected yet

The profile declares no additional regulatory or contractual obligation. It also contains no personal data, health data, raw card data, or payment token that would trigger an overlay automatically.

```yaml
regulations_declared: []
applicable_overlays: []
```

The current profile does not trigger these overlays:

| Overlay | Why it is not applied |
|---|---|
| GDPR | No personal data and EU or EEA user scope is established |
| ISMS-P | Korean user and personal-data scope is not established |
| HIPAA | No electronic health information is processed |
| PCI DSS | No cardholder data or payment token is processed |
| ISO 27001 | The organization has not declared it as an obligation |
| SOC 2 | The organization has not declared that examination scope |

This does not prove that none of these regimes can legally apply. It means that the confirmed profile contains no basis for applying them.

Adding user accounts, behavioral analytics, or payment features would change the result.

---

## 12. Why the calculated result returns to the owner for confirmation

The pipeline does not proceed merely because a script produced an answer. The plugin shows both the result and its reasoning to the service owner.

```yaml
derived:
  impact:
    confidentiality:
      level: low
      because:
        - "Movie content is intended for publication"

    integrity:
      level: moderate
      because:
        - "Tampering with public content undermines trust in the service"

    availability:
      level: low
      because:
        - "RTO is one day or longer"
        - "RPO is several hours or longer"
        - "No availability amplifier applies"

    system: moderate

  baseline: nist-800-53b-moderate
  baseline_control_count: 287

  privacy_baseline_applies: false

  program_control_count: 32
  total_controls_for_next_stage: 319

  asvs_level: 2
  applicable_overlays: []
```

The owner should verify questions such as:

- Does corruption of movie information and ratings really have Moderate impact?
- Can the service actually tolerate an outage of one day or longer?
- Can it tolerate losing several hours of rating and catalog changes?
- Is an outage connected to advertising or paid features?
- Do API Gateway or CloudWatch logs contain personal data?
- Are there truly no applicable contracts or regulatory obligations?

### Can the owner override the level?

Yes, but the reason must be recorded.

If ratings feed revenue settlement, integrity impact may need to increase. If all movie information can be reconstructed automatically from an authoritative external catalog and ratings have no business significance, the Moderate result might be reconsidered.

An override is recorded with its rationale:

```yaml
derived:
  impact:
    system: low
    overridden_by_user: true
    override:
      reason: >-
        All movie information is automatically recoverable from an
        authoritative external catalog, and ratings are not used for
        business decisions or settlement.
```

Without a reason, the organization cannot later answer, “Why was this Low rather than Moderate?”

After confirmation, the plugin binds the approval to the exact profile content. A later change to the data types, RTO, or user regions changes the profile digest and invalidates the previous approval.

---

## 13. The Moderate baseline is not the final requirement set

A common misunderstanding at this stage is:

> If the Moderate baseline has been selected, why not use its 287 controls directly as the requirements?

That would produce a generic control list rather than service-specific requirements.

A NIST access-control statement is intentionally abstract so that it can apply across organizations and systems. It does not fully describe this service's failure condition.

```text
Abstract control:
Enforce access according to approved authorizations.

Service-specific requirement:
Before invoking DynamoDB, every request that creates, deletes,
or changes a rating must verify that the authenticated caller
is authorized for that operation.
```

The baseline alone may also fail to express application-specific problems such as:

- The Lambda function selecting an operation from the last path segment rather than the complete route
- Instructions to place long-lived AWS credentials in a configuration file
- Broad AWS-managed policies attached to the Lambda execution role
- AWS SDK error objects returned directly to the client
- DynamoDB operations occurring before input validation

Stage 2 therefore produces review material rather than a final requirements document.

```text
CIA impact
+ 287 Moderate-baseline controls
+ 32 Program controls
+ ASVS L2
+ no applicable regulatory overlay
= control work set to cross with the threat model
```

---

## What Part 2 established

The movie service has the following CIA impact:

```text
Confidentiality: Low
Integrity:       Moderate
Availability:    Low
System impact:   Moderate
```

Integrity is the axis that determines the system impact.

As a result:

- The plugin selects the 287 controls in the NIST SP 800-53B Moderate baseline.
- It adds 32 organization-level Program controls.
- It does not add the Privacy baseline because no personal data has been confirmed.
- It selects OWASP ASVS L2 because the service exposes an HTTP API and has Moderate impact.
- It applies no regulatory overlay because the profile contains no trigger.
- The union passed to the next stage contains 319 NIST controls.

The numbers alone do not show what matters most. Some of the 319 controls belong to AWS, some belong to the organization, and only some become delivery-team work. Among those, controls connected to actual movie-service threats receive the highest priority.

In Part 3, we will draw the data flows and trust boundaries among API Gateway, Lambda, DynamoDB, the configuration file, and CloudWatch Logs. We will then apply STRIDE at each boundary to derive threats specific to this service, including anonymous write access, excessive Lambda permissions, and inconsistent route interpretation.
