# Deriving Security Requirements from an AWS Serverless Sample, Part 8A: Applying ISMS-P and GDPR Overlays

The original movie service handled only public movie content. Part 6 then introduced user accounts, email addresses, device identifiers, an external analytics provider, and a confirmed Korean deployment region.

Those changes create obligations that a NIST security baseline alone may not express.

This post shows how regulatory overlays extend the existing security contract without pretending that a control mapping proves legal compliance.

---

## Baselines and regulations speak different languages

NIST SP 800-53 primarily describes controls: access enforcement, audit generation, encryption, incident response, and similar safeguards.

Privacy regulations and certification criteria also describe duties such as:

- Tell a person why data is processed.
- Delete data when the purpose ends.
- Respond to access or deletion requests.
- Control international transfer.
- Manage a processor relationship.
- Record the lawful or declared basis for processing.

These obligations are not always reducible to a security control.

```text
NIST baseline
  → which safeguards should be considered

regulatory overlay
  → which regime-specific criteria the derivation reaches or misses
```

The overlay supplements the baseline rather than replacing it.

---

## The evolved movie-service profile

For this example, assume the confirmed profile now contains:

```yaml
declared:
  data_types:
    - id: public_content
    - id: basic_contact
    - id: account_credentials
    - id: app_logs

  users:
    - authenticated_individual

  user_regions: [KR, EU]

inferred:
  region_storage: ap-northeast-2
  external_integrations:
    - name: analytics-provider
      purpose: product_analytics
      data_sent:
        - basic_contact
        - device_identifier
```

The profile now contains personal data and users in both Korea and the EU.

That is enough to trigger overlay review for:

- ISMS-P, based on Korean users and personal-data processing
- GDPR, based on EU or EEA users and personal-data processing

This is a trigger for review, not a final legal determination.

---

## ISMS-P scope selection

The bundled ISMS-P overlay models 101 criteria across three areas.

```text
1. Management-system establishment and operation
2. Requirements for protective measures
3. Personal-data processing requirements
```

For Korean users with personal data, the overlay selects the ISMS-P scope rather than the narrower ISMS scope.

```text
Korean users + personal data
        ↓
ISMS-P scope: all three areas
```

The overlay does not assert that the organization must obtain certification. It says that, if this declared regime is being evaluated, all three areas are relevant to the profile.

### Criteria not represented by NIST controls

Some ISMS-P criteria describe duties that have no direct equivalent in a control catalog. Examples include obligations around:

- Specific identifiers
- Indirect collection
- Application permissions
- Transfer during a business sale
- Cross-border transfer

These are not dropped merely because no NIST control expresses them. They become overlay-derived work items.

For the movie service, the analytics transfer may create a standalone requirement such as:

> Before personal data is sent to the external analytics provider, the service owner must record the recipient, data categories, processing purpose, retention condition, and applicable cross-border transfer basis.

Whether that statement is legally sufficient requires qualified review. The plugin exposes the duty; it does not provide legal advice.

---

## GDPR scope selection

The bundled GDPR overlay covers 46 design-relevant articles from Chapters II through V.

It intentionally excludes institutional, penalty, and final-provision chapters that do not translate into service design work.

```text
EU or EEA users + personal data
        ↓
GDPR overlay review
```

GDPR illustrates why a control-only derivation is incomplete. Article 32 maps naturally to security safeguards, but many other obligations concern what the system must enable or demonstrate:

- Access by the data subject
- Rectification
- Erasure
- Restriction of processing
- Data portability
- Objection
- Automated decision-making safeguards
- Controller and processor duties
- International transfers

A NIST control can support these duties without fully expressing them.

---

## Run the overlay twice

The pipeline applies each relevant overlay at two points.

### Before requirements are written

The first pass compares regulatory criteria with the selected control set.

```text
regulatory criterion
        ↓
is any catalog control mapped to it?
        ↓
is one of those controls in the tailored set?
```

This pass identifies:

- Criteria reached by selected controls
- Criteria only represented by controls outside the selected set
- Criteria for which no control expresses the obligation

The final category produces standalone regulatory work.

### After requirements are written

The second pass compares criteria with the actual requirement document and prioritization work list.

```text
criterion
  → catalog control exists
  → selected control exists
  → candidate requirement is trace-linked
  → semantic mapping independently reviewed
```

This produces the assurance funnel for the document rather than merely for the catalogs.

---

## Gap and deferral are different

An overlay report must not present only the number of trace-linked requirements.

Two missing candidates can have different meanings.

```text
Deferral
  A baseline control was retained at low priority because no current threat or
  data type elevated it. The derivation made an explicit prioritization choice.

Gap
  A threat, data type, or standalone regulatory duty requires work, but no
  candidate requirement was written.
```

A gap is unfinished work. A deferral is a visible tailoring decision.

Without the cross-and-prioritize result, the overlay cannot distinguish them and must conservatively report every missing candidate as a gap.

---

## Example overlay-derived requirements

### Analytics-purpose boundary

```yaml
- id: REQ-PRIVACY-ANALYTICS-PURPOSE-01
  managed:
    statement: >-
      Personal data sent to the analytics provider must be limited to data
      necessary for a documented analytics purpose.
    rationale: >-
      The external flow introduces processing beyond the original public movie
      service and must remain bounded by its declared purpose.
    responsibility: team
    verification:
      method: artifact_review
      target: "the analytics data inventory and processing-purpose record"
      expect: >-
        every transmitted personal-data field maps to a documented analytics
        purpose and fields without a mapping are absent
    priority: high
```

### Account-deletion propagation

```yaml
- id: REQ-PRIVACY-ANALYTICS-DELETE-01
  managed:
    statement: >-
      Deleting a user account must initiate deletion or irreversible
      de-identification of that user's personal data held by the analytics
      provider within the approved retention period.
    responsibility: shared
    csp_part: >-
      The analytics provider supplies the deletion or de-identification
      mechanism described in the service agreement.
    team_part: >-
      Invoke the mechanism and retain evidence of its completion.
    verification:
      method: test_case
      target: "an account-deletion request for a synthetic user"
      expect: >-
        no personal data for the synthetic user remains queryable after the
        approved retention period
    priority: high
```

### Cross-border transfer record

```yaml
- id: REQ-PRIVACY-TRANSFER-RECORD-01
  managed:
    statement: >-
      Each transfer of personal data to a provider in another country must
      have a current record of the recipient, data categories, purpose,
      destination, retention condition, and approved transfer basis.
    responsibility: org
    verification:
      method: artifact_review
      target: "the register of international personal-data transfers"
      expect: "a current entry matching the analytics data flow"
    priority: high
```

These examples still require legal and privacy review. Their value is that regulatory duties become visible, owned, and testable rather than being implied by a security control.

---

## Mapping disclaimers are part of the result

The ISMS-P and GDPR mappings bundled here are interpretive crosswalks. They are not themselves published authoritative crosswalks.

Every report must state that:

- Mapping legal criteria to technical controls is interpretation.
- A trace link does not prove semantic adequacy.
- The overlay does not determine whether the law applies.
- The overlay does not establish certification or compliance.
- Qualified legal, privacy, or certification review remains necessary.

This limitation is not boilerplate to hide. It defines the assurance boundary of the artifact.

---

## An illustrative overlay report

```text
Applicable overlays
  ISMS-P
    scope: all three areas
    trigger: Korean users and personal data
    mapping: repository-authored, not an official crosswalk

  GDPR
    scope: design-relevant Articles 5–50
    trigger: EU users and personal data
    mapping: repository-authored, not an official crosswalk

Document status
  selected controls              reviewed
  standalone regulatory duties   added to work list
  trace-linked candidates        reported with gaps and deferrals
  semantic mappings              require independent review
```

Exact counts should come from the generated overlay report for the confirmed profile, never from a blog example or model memory.

---

## What Part 8A established

1. A NIST security baseline does not express every privacy and regulatory duty.
2. ISMS-P and GDPR applicability is triggered from confirmed profile facts, not guessed from repository names.
3. Criteria with no control mapping become standalone work rather than disappearing.
4. Overlays run both before and after requirement authoring.
5. Reports distinguish true gaps from intentional low-priority deferrals.
6. Trace linkage does not become semantic approval automatically.
7. The resulting mappings are interpretations, not legal advice, certification, or proof of compliance.

Part 8B uses the same verification metadata in a different direction: building CI/CD checks that continuously evaluate selected requirements.
