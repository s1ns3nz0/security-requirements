---
description: Derive security requirements from a confirmed profile - threat model, responsibility split, requirement authoring
---

```bash
export SECURITY_REQUIREMENTS_ROOT="${CLAUDE_PLUGIN_ROOT}"
if [ -n "${CLAUDE_PLUGIN_DATA:-}" ]; then
  export SECURITY_REQUIREMENTS_DATA="${CLAUDE_PLUGIN_DATA}"
fi
if [ -z "${SECURITY_REQUIREMENTS_DATA:-}" ]; then
  SECURITY_REQUIREMENTS_DATA="$(
    python3 "${SECURITY_REQUIREMENTS_ROOT}/scripts/runtime_paths.py"
  )" || exit
  export SECURITY_REQUIREMENTS_DATA
fi
```

Requires a confirmed `.security-requirements/profile.yaml`. If it does not
exist, or the gate was not passed, run `/sec-req-init` first.

Enforce the persisted gate before doing any work:

```
python3 "${SECURITY_REQUIREMENTS_ROOT}/scripts/confirmation.py" --check \
    .security-requirements/profile.yaml
```

A missing, incomplete, or stale confirmation is a blocker. Do not infer
approval from conversation history or trust a confirmation block stored only in
the repository. `--check` requires its matching plugin-owned record under
`${SECURITY_REQUIREMENTS_DATA}`.

## 1. Threat model

Follow
`${SECURITY_REQUIREMENTS_ROOT}/skills/deriving-security-requirements/references/threat-modeling.md`.

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
python3 "${SECURITY_REQUIREMENTS_ROOT}/scripts/classify_resp.py" \
    .security-requirements/profile.yaml \
    .security-requirements/controls.json \
    --json .security-requirements/responsibility.json
```

Read the uncurated service list from the output. Those need model judgement:
for each, produce a draft mapping and write it to
`${SECURITY_REQUIREMENTS_DATA}/responsibility/services/<id>.yaml` with
`reviewed: false`. Plugin data persists across plugin upgrades; the installed
plugin directory does not. It is shown as unverified wherever it appears.

## 3. Regulatory overlay, where one applies

```
python3 "${SECURITY_REQUIREMENTS_ROOT}/scripts/apply_overlay.py" pipa-isms-p \
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
python3 "${SECURITY_REQUIREMENTS_ROOT}/scripts/merge.py" --cross \
    --controls .security-requirements/controls.json \
    --responsibility .security-requirements/responsibility.json \
    --threats .security-requirements/threats.yaml \
    --out .security-requirements/cross.json
```

The `threat only` bucket is the point of the exercise. If it is empty, the
threat model was generic — go back to step 1 rather than shipping a filtered
baseline.

## 5. Write the requirements

Follow
`${SECURITY_REQUIREMENTS_ROOT}/skills/deriving-security-requirements/references/requirement-style.md`.
Verifiable, atomic, property not
implementation.

Read `.security-requirements/cross.json` and write one requirement per item into
`.security-requirements/draft.json`. Every requirement needs a
populated `verification` block: what to look at, what to expect, and a manual
fallback. Requirements are grouped under CSF 2.0 functions for the reader and
carry 800-53 and ASVS identifiers as evidence.

Generate the `forces_requirements` entries from the declared data types even
where no threat matched them.

## 6. Merge and render

```
python3 "${SECURITY_REQUIREMENTS_ROOT}/scripts/merge.py" --apply \
    --draft .security-requirements/draft.json \
    --existing .security-requirements/requirements.yaml \
    --state .security-requirements/state.yaml
```

## 7. Lint, then publish

Lint first. `docs/security/` is the publishable output, and rendering before
checking means a requirement naming a production bucket is already in the file
by the time anyone is told about it.

No `--strict` here. The disclosure rule is an ERROR and blocks on its own; the
remaining warnings are about how well a requirement is written, and a document
with a clumsy statement is still safe to publish. `--strict` would fail the
build on a statement of four words, which is a style note wearing a blocker's
clothes. Run it when editing the draft, not when publishing it.

Pass the profile's `locale`. The linter's rule sets are per language, and it
refuses to check a document in a language it was not told about rather than
applying English rules to Korean prose and reporting it clean. Omitting the
flag on a Korean document does not produce a weaker check -- it produces
`locale-mismatch` on every requirement and stops the build, which is how a tool
built for a Korean regime came to be unable to publish a Korean document.

```
locale=$(python3 -c "import yaml,sys; print((yaml.safe_load(open(sys.argv[1])) or {}).get('locale','en'))" \
    .security-requirements/profile.yaml)

python3 "${SECURITY_REQUIREMENTS_ROOT}/scripts/lint.py" --locale "$locale" \
    .security-requirements/requirements.yaml \
    --threats .security-requirements/threats.yaml

python3 "${SECURITY_REQUIREMENTS_ROOT}/scripts/render.py" \
    .security-requirements/requirements.yaml \
    --out docs/security/
```

A failure here is a blocker, not a warning. In particular, a cited control
identifier that is absent from the catalog means the requirement was invented,
and one invented identifier discredits the whole document.

## 7b. Re-run each overlay against what was written

Step 3 ran the overlays before any requirement existed, so it could only say
which controls the tailoring selected. Now that `requirements.yaml` is written,
run each applicable overlay again with the document and the work list:

```
python3 "${SECURITY_REQUIREMENTS_ROOT}/scripts/apply_overlay.py" pipa-isms-p \
    .security-requirements/profile.yaml \
    .security-requirements/controls.json \
    --requirements .security-requirements/requirements.yaml \
    --cross .security-requirements/cross.json
```

This adds the funnel, and the funnel is the only part of the report that is
about the document rather than about the derivation:

```
101  assessed criteria
 95  a control in the catalogue expresses it
 94  a selected control addresses it
  8  trace-linked candidate requirements, with a way to check them
  0  independently reviewed semantic clause mappings
```

Trace linkage is not semantic adequacy. A human reviewer advances a candidate
by recording the exact control and overlay-clause links plus verification review
as described in the requirement style reference. Before making any semantic
coverage claim, run:

```
python3 "${SECURITY_REQUIREMENTS_ROOT}/scripts/semantic_review.py" --check \
    .security-requirements/requirements.yaml
```

This gate requires every live requirement to carry a current, digest-bound
independent review. A draft may be published without passing it, but must remain
labeled trace-linked rather than semantically reviewed.

Keep the assurance stages distinct:

```
selected -> authored -> trace-linked -> semantically reviewed
         -> implemented -> evidenced -> assessed
```

This plugin establishes at most the first four stages. It never infers
implemented, evidenced, assessed, or compliant from requirement text.

Read the trace-linked row against the two below it, never on its own. Most of the
difference will be **deferred** — the baseline selected a control and no threat
reached it, so it came out of the cross step at low priority. That is the
tailoring working. What matters is the **gap** row: a control a threat or a
data type prioritised, with nothing written against it. A gap is work; a
deferral is a decision the derivation already made.

Without `--cross` there is no prioritisation to consult, so nothing can be
called deferred and every clause without a candidate is reported as a gap. Pass it.

## 8. Report

State plainly:

- how many controls reached the delivery team, out of the baseline
- which services were unverified
- which regulatory overlays applied, at what scope, and which of their
  clauses no control reaches
- for each overlay, how many clauses have trace-linked candidate requirements, and how
  many are a gap rather than a deferral. Never the trace-linked count alone
- which detected regulations have no overlay at all
- what remains UNDETERMINED and what it cost
