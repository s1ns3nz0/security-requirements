---
name: deriving-security-requirements
description: Use when a service needs security requirements defined for a compliance, design, or architecture-review stage - derives a tailored requirement set from the service itself rather than scanning code for vulnerabilities. Triggers on "security requirements", "compliance requirements", "what controls do we need", "NIST tailoring", "control baseline", "보안 요구사항", "컴플라이언스 요구사항".
---

# Deriving security requirements

Most security tooling is **discovery**: read the code, find the flaw. This is
**prescription**: say what the service must satisfy, before or independently of
any code existing.

The output is upstream of review tools, not in competition with them. A review
tool given `requirements.yaml` stops doing generic checks and starts checking
whether REQ-014 holds for this service.

## Division of labour

Some steps are lookups. Never perform those with judgement — call the script.

| Step | Who | How |
|---|---|---|
| 1. Scan repo, draft profile | model | interpret code and IaC |
| 2. Interview the gaps | model | `references/profile-schema.md`, max 7 questions |
| 3. **Confirm profile** | **user** | hard gate; do not proceed without it |
| 4. Impact and baseline | script | `scripts/select_baseline.py` |
| 5. Threat model | model | `references/threat-modeling.md` |
| 6. Responsibility split | script | `scripts/classify_resp.py` |
| 7. Cross and prioritise | script | `scripts/merge.py` |
| 8. Write requirements | model | `references/requirement-style.md` |
| 9. Merge with existing | script | `scripts/merge.py` |
| 10. Render | script | `scripts/render.py` |
| 11. Lint and link-check | script | `scripts/lint.py` |

"Which controls are in the Moderate baseline" is a table lookup. Answering it
from memory is slower, non-reproducible, and invents identifiers. The catalogs
are bundled precisely so this never happens — and `lint.py` fails the build if a
requirement cites an identifier they do not contain.

## Catalogs to consult, never recall

| Path | Contents |
|---|---|
| `catalogs/nist-800-53r5/<FAMILY>.jsonl` | 1,196 controls; `baselines.json` holds the Low, Moderate, High, and Privacy sets |
| `catalogs/csf-2.0/subcategories.jsonl` | 106 subcategories; use these for the `csf` field and the document's structure |
| `catalogs/asvs-5/V<n>.jsonl` | 345 application requirements with levels; cite as `ASVS-V1.1.1` |
| `catalogs/csp-rules/aws.md` | Provider behaviour that changes what a requirement must say |

Grep them. Every identifier written into a requirement is checked against them,
and there is no CSF-to-800-53 crosswalk to lean on — NIST does not publish one
in a form that can be bundled, so the CSF subcategory is your judgement and only
its existence is verified.

## Non-negotiable rules

**Never assert inheritance as fact.** A control marked `csp_claimed` is a claim
the reader must substantiate with evidence. Always emit the evidence needed.

**Never present an uncurated service as verified.** Services without a file in
`responsibility/services/` are model-generated and must be shown as unverified.

**Never imply coverage you do not have.** Detected regulations outside the
supported set are declared as not covered, explicitly.

**Never overwrite the `human` block.** Exception approvals and status are the
reader's. Proposed changes go to `pending_review`.

**Never delete a requirement.** Transition its status and record why.

## Output placement

```
.security-requirements/     sensitive: profile, threats, status, id ledger
docs/security/              publishable: requirements, traceability, responsibility
```

The sensitive set is a reconnaissance document — architecture, storage
locations, unimplemented controls, accepted risks with expiry dates. On a public
repository, add it to `.gitignore` and say why. Git history survives deletion.

## References

- `references/profile-schema.md` — schema, the seven questions, the gate
- `references/threat-modeling.md` — DFD, STRIDE, LINDDUN, personas
- `references/requirement-style.md` — the three rules, record shape, priority

## Disclaimer

Every rendered document carries, unedited:

> This document is an automatically generated draft. It does not constitute
> legal advice and does not substitute for compliance certification. Qualified
> review is required.
