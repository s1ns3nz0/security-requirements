---
description: Derive security requirements from a confirmed profile - threat model, responsibility split, requirement authoring
---

Requires a confirmed `.security-requirements/profile.yaml`. If it does not
exist, or the gate was not passed, run `/sec-req-init` first.

## 1. Threat model

Follow `skills/deriving-security-requirements/references/threat-modeling.md`.

Build the DFD first. Threats listed without a structure are recalled, not
derived, and recalled threats are the ones the baseline already covers.

Mark every threat `novelty: service_specific` or `generic`. Apply the test:
could this sentence have been written without knowing anything about this
service? If yes, it is generic.

Run the LINDDUN pass when personal data types are declared or a
`linddun_linkability` flag is set.

Write `.security-requirements/threats.yaml`.

## 2. Responsibility split

```
python3 scripts/classify_resp.py \
    .security-requirements/profile.yaml \
    .security-requirements/controls.json \
    --json .security-requirements/responsibility.json
```

Read the uncurated service list from the output. Those need model judgement:
for each, produce a draft mapping and write it to
`responsibility/services/<id>.yaml` with `reviewed: false`. It is cached for
later runs and shown as unverified wherever it appears.

## 3. Regulatory overlay, where one applies

```
python3 scripts/apply_overlay.py pipa-isms-p \
    .security-requirements/profile.yaml \
    .security-requirements/controls.json \
    --json .security-requirements/overlay.json
```

Run this for any overlay the profile triggers. The output has two halves and
the second is the one to read: clauses no control expresses at all. Those are
what an audit asks about and a 800-53 derivation cannot produce, so each needs
a requirement written from the clause rather than from a control.

The mapping is this repository's reading, not a published crosswalk. Say so
when you carry it into the document.

## 4. Cross and prioritise

```
python3 scripts/merge.py --cross \
    --controls .security-requirements/controls.json \
    --responsibility .security-requirements/responsibility.json \
    --threats .security-requirements/threats.yaml \
    --out .security-requirements/draft.json
```

The `threat only` bucket is the point of the exercise. If it is empty, the
threat model was generic — go back to step 1 rather than shipping a filtered
baseline.

## 5. Write the requirements

Follow `references/requirement-style.md`. Verifiable, atomic, property not
implementation.

Write one requirement per item in the crossed set. Every requirement needs a
populated `verification` block: what to look at, what to expect, and a manual
fallback. Requirements are grouped under CSF 2.0 functions for the reader and
carry 800-53 and ASVS identifiers as evidence.

Generate the `forces_requirements` entries from the declared data types even
where no threat matched them.

## 6. Merge and render

```
python3 scripts/merge.py --apply \
    --draft .security-requirements/draft.json \
    --existing .security-requirements/requirements.yaml \
    --state .security-requirements/state.yaml
```

## 7. Lint, then publish

Lint first. `docs/security/` is the publishable output, and rendering before
checking means a requirement naming a production bucket is already in the file
by the time anyone is told about it. `--strict` because the disclosure warnings
are about what leaves the building, and a warning nobody reads is not a control.

```
python3 scripts/lint.py .security-requirements/requirements.yaml --strict

python3 scripts/render.py .security-requirements/requirements.yaml \
    --out docs/security/
```

A failure here is a blocker, not a warning. In particular, a cited control
identifier that is absent from the catalog means the requirement was invented,
and one invented identifier discredits the whole document.

## 8. Report

State plainly:

- how many controls reached the delivery team, out of the baseline
- which services were unverified
- which regulatory overlays applied, at what scope, and which of their
  clauses no control reaches
- which detected regulations have no overlay at all
- what remains UNDETERMINED and what it cost
