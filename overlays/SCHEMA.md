# Regulatory overlay schema

An overlay adds a regulation's requirements on top of the core derivation.
**None ship in v1.** The extension point exists so the core can be validated
before a second catalogue is attached, and so the shape is fixed before the
first contribution.

Until an overlay exists for a regulation, detection produces a declaration:

```
Uncovered regulations detected
  ! Raw cardholder data detected. PCI DSS appears to apply and is not
    supported by this tool.
```

That is deliberate. A tool that quietly produces plausible requirements for a
PCI-scoped system, without saying it does not cover PCI DSS, is worse than one
that produces nothing — the reader believes they are covered.

---

## Layout

```
overlays/<id>/
  meta.yaml          identity, licence, and applicability
  mappings.jsonl     regulation clause -> 800-53 controls, or standalone
  LICENSE            when the source text is bundled
  NOTICE             attribution and a statement of changes made
```

## meta.yaml

```yaml
id: pipa-kr
name: "Personal Information Protection Act (Korea)"
version: "2026-03"
source_url: "https://www.law.go.kr/..."
license: "Korean statutes are not protected under Article 7 of the Copyright Act"
bundled_text: true

applies_when:
  user_regions_any: [KR]
  data_types_any: [basic_contact, government_id, sensitive_attributes]

baseline_effect:
  minimum_impact: moderate    # optional; omit if the overlay does not raise it

disclaimer: >-
  Mapping between statutory obligations and technical controls is
  interpretation, not legal advice.
```

## mappings.jsonl

One record per clause.

```json
{
  "clause": "Article 29",
  "title": "Duty of safety measures",
  "statement": "Technical, administrative, and physical measures for safety",
  "controls": ["SC-28", "SC-8", "AC-3", "AU-2"],
  "standalone": false,
  "notes": "The encryption obligation is detailed in the enforcement decree."
}
```

`standalone: true` marks an obligation with no corresponding 800-53 control.
Those become requirements in their own right — the same role the `threat_only`
bucket plays in the core derivation, and the same reason overlays are worth
having at all.

---

## Licence rules

Bundling is decided per source, and getting it wrong is not recoverable once
published.

| Status | Sources |
|---|---|
| Bundle freely | US federal regulations (HIPAA Security Rule, 45 CFR 164), Korean statutes and ministerial notices (Copyright Act Article 7) |
| Bundle with attribution and share-alike | EU legal texts under the EUR-Lex reuse policy; keep them in their own directory with LICENSE and NOTICE |
| **Do not bundle** | PCI DSS (PCI SSC), CIS Benchmarks, ISO/IEC 27001 Annex A, SOC 2 Trust Services Criteria |

For the last group, reference clause identifiers and write the mapping in your
own words. Do not reproduce the text, and do not paraphrase it so closely that
the paraphrase substitutes for the original.

---

## Contribution order

The first overlay should be one whose source is bundleable and whose audience
is real. On both counts that is **PIPA (Korea) plus the ISMS-P certification
criteria** — Korean statutes and ministerial notices fall outside copyright
protection under Article 7, and a Korean team asked to produce security
requirements is far more likely to be answering to ISMS-P than to SP 800-53.

Note that the KISA explanatory guides are separate copyrighted works. The
notice and its schedules are not; the guides are.
