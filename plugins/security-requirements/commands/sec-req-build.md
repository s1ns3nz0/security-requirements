---
description: Derive security requirements from a confirmed profile - threat model, responsibility split, requirement authoring
---

## Trusted runtime paths

Treat every shell tool call as a fresh shell, including calls after a gate.
Capture the exact absolute `${CLAUDE_PLUGIN_ROOT}` value as
`<exact absolute plugin root>`, then resolve persistent state once:

```bash
SECURITY_REQUIREMENTS_ROOT="${CLAUDE_PLUGIN_ROOT}" \
python3 -I "${CLAUDE_PLUGIN_ROOT}/scripts/runtime_paths.py" --project-root "$PWD"
```

Capture its exact absolute stdout as
`<exact absolute data root returned by runtime_paths.py>`. Do not set or
overwrite the neutral `SECURITY_REQUIREMENTS_DATA` before resolution: the helper
gives it precedence over `CLAUDE_PLUGIN_DATA`, then uses the external OS
default. Substitute both exact literals into every block below. Every shell call
independently prefixes them; never rely on an export from another call. For
Read, Write, or Edit, pass the exact literal path because those tools do not
expand shell syntax. Never derive a runtime path from the inspected repository
or cwd.

The only exception is the initial broad check below: preserve this one canonical
broad preflight exactly as written. The Claude host provides
`${CLAUDE_PLUGIN_ROOT}`; the Codex adapter replaces only that token with its
loader-verified literal. Later scoped checks still use both captured exact
literals.

Before reading or writing workflow outputs, reject repository-controlled
symlinked or junction-backed output trees:

```bash
python3 -I "${CLAUDE_PLUGIN_ROOT}/scripts/safe_paths.py" --project-root "$PWD" --check-output .security-requirements docs/security
```

Requires a confirmed `.security-requirements/profile.yaml`. If it does not
exist, or the gate was not passed, run
`/security-requirements:sec-req-init` first.

Enforce the persisted gate before doing any work:

```
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/confirmation.py" --check \
    .security-requirements/profile.yaml
```

A missing, incomplete, or stale confirmation is a blocker. Do not infer
approval from conversation history or trust a confirmation block stored only in
the repository. `--check` requires its matching plugin-owned record under
`<exact absolute data root returned by runtime_paths.py>`.

## 1. Threat model

Follow
`<exact absolute plugin root>/skills/deriving-security-requirements/references/threat-modeling.md`.

Build the DFD first. Threats listed without a structure are recalled, not
derived, and recalled threats are the ones the baseline already covers.

Mark every threat `novelty: service_specific` or `generic`. Apply the test:
could this sentence have been written without knowing anything about this
service? If yes, it is generic.

Run the LINDDUN pass when personal data types are declared or a
`linddun_linkability` flag is set.

Run `safe_paths.py` in a fresh shell call immediately before every direct model
Write or Edit, then pass the same exact checked path to the write tool. A prior
check never authorizes a later write. Preflight the threat model now:

```
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/safe_paths.py" \
    --project-root "$PWD" --check-output .security-requirements/threats.yaml
```

Write `.security-requirements/threats.yaml`.

## 2. Confirm inherent risk before deriving publishable output

Use the bundled default policy unless the user has reviewed an organisation
override. Immediately before writing the policy copy, preflight only that
target, then write `.security-requirements/risk-policy.yaml`:

```
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/safe_paths.py" \
    --project-root "$PWD" --check-output .security-requirements/risk-policy.yaml
```

Propose likelihood criteria, consequences, impact criteria, rationale, owner,
and a non-acceptance treatment for every active threat. Do not write numeric
scores or ratings as authoritative model output. Immediately before writing
the proposal document, preflight it:

```
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/safe_paths.py" \
    --project-root "$PWD" --check-output .security-requirements/risk-assessment.yaml
```

Write `.security-requirements/risk-assessment.yaml`, then display a batch review table
containing every active threat, proposed likelihood, impact, calculated
score/rating preview, treatment, and unresolved field. Stop for explicit confirmation.
If the user adjusts anything, preflight and rewrite the canonical
assessment, redisplay the table, and ask again. Never treat conversation memory
as persisted approval.

After the user explicitly confirms the policy and the one canonical assessment
digest, persist both confirmations and enforce the hard gate in fresh calls:

```
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/risk.py" policy-confirm \
    --project-root "$PWD" \
    --policy .security-requirements/risk-policy.yaml \
    --by user --authority self_declared
```

```
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/risk.py" confirm \
    --project-root "$PWD" \
    --policy .security-requirements/risk-policy.yaml \
    --threats .security-requirements/threats.yaml \
    --assessment .security-requirements/risk-assessment.yaml \
    --by user --authority self_declared
```

```
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/risk.py" check \
    --project-root "$PWD" \
    --policy .security-requirements/risk-policy.yaml \
    --threats .security-requirements/threats.yaml \
    --assessment .security-requirements/risk-assessment.yaml
```

Any `PROPOSED`, `STALE`, or `UNDETERMINED` inherent assessment is a blocker.
Residual `UNDETERMINED` must be displayed but does not block initial
publication.

Before a later risk activity writes evidence, immutable state, or the internal
register, run the matching preflight immediately before that individual write:

```
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/safe_paths.py" \
    --project-root "$PWD" --check-output .security-requirements/risk-evidence.yaml
```

```
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/safe_paths.py" \
    --project-root "$PWD" --check-output .security-requirements/risk-state.yaml
```

```
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/safe_paths.py" \
    --project-root "$PWD" \
    --check-output .security-requirements/reports/risk-register.md
```

## 3. Responsibility split

```
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/classify_resp.py" \
    .security-requirements/profile.yaml \
    .security-requirements/controls.json \
    --json .security-requirements/responsibility.json
```

Read the uncurated service list from the output. Those need model judgement:
for each, produce a draft mapping. Immediately before its Write, substitute the
service id and both captured root literals in this preflight:

```
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/safe_paths.py" \
    --project-root "<exact absolute data root returned by runtime_paths.py>" \
    --check-output "<exact absolute data root returned by runtime_paths.py>/responsibility/services/<id>.yaml"
```

Use Write with the exact literal path returned by the trusted runtime helper:
`<exact absolute data root returned by runtime_paths.py>/responsibility/services/<id>.yaml`, with
`reviewed: false`. Plugin data persists across plugin upgrades; the installed
plugin directory does not. It is shown as unverified wherever it appears.

## 4. Regulatory overlay, where one applies

```
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/apply_overlay.py" pipa-isms-p \
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

## 5. Cross and prioritise

```
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/merge.py" --cross \
    --controls .security-requirements/controls.json \
    --responsibility .security-requirements/responsibility.json \
    --threats .security-requirements/threats.yaml \
    --assessment .security-requirements/risk-assessment.yaml \
    --out .security-requirements/cross.json
```

The `threat only` bucket is the point of the exercise. If it is empty, the
threat model was generic — go back to step 1 rather than shipping a filtered
baseline.

## 6. Write the requirements

Follow
`<exact absolute plugin root>/skills/deriving-security-requirements/references/requirement-style.md`.
Verifiable, atomic, property not
implementation.

Read `.security-requirements/cross.json`. Immediately before authoring the
draft, preflight its exact target:

```
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/safe_paths.py" \
    --project-root "$PWD" --check-output .security-requirements/draft.json
```

Then write one requirement per item into
`.security-requirements/draft.json`. Every requirement needs a
populated `verification` block: what to look at, what to expect, and a manual
fallback. Requirements are grouped under CSF 2.0 functions for the reader and
carry 800-53 and ASVS identifiers as evidence.

Generate the `forces_requirements` entries from the declared data types even
where no threat matched them.

## 7. Merge

```
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/merge.py" --apply \
    --draft .security-requirements/draft.json \
    --existing .security-requirements/requirements.yaml \
    --state .security-requirements/state.yaml \
    --threats .security-requirements/threats.yaml \
    --assessment .security-requirements/risk-assessment.yaml
```

## 8. Lint before staging

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

Run this entire fenced block as one shell tool call. The local `locale` value is
valid only inside that call and must not be reused by a later call.

```
locale="$(
  SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
  SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
  python3 -I "<exact absolute plugin root>/scripts/profile_locale.py" \
      .security-requirements/profile.yaml
)" || exit

SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/lint.py" --locale "$locale" \
    .security-requirements/requirements.yaml \
    --threats .security-requirements/threats.yaml
```

A failure here is a blocker, not a warning. In particular, a cited control
identifier that is absent from the catalog means the requirement was invented,
and one invented identifier discredits the whole document.

## 8b. Re-run each overlay against what was written

Step 3 ran the overlays before any requirement existed, so it could only say
which controls the tailoring selected. Now that `requirements.yaml` is written,
run each applicable overlay again with the document and the work list:

```
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/apply_overlay.py" pipa-isms-p \
    .security-requirements/profile.yaml \
    .security-requirements/controls.json \
    --requirements .security-requirements/requirements.yaml \
    --cross .security-requirements/cross.json
```

This adds the funnel, and the funnel is the only part of the report that is
about the document rather than about the derivation:

```text
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
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/semantic_review.py" --check \
    .security-requirements/requirements.yaml
```

This gate requires every live requirement to carry a current, digest-bound
independent review. A draft may be published without passing it, but must remain
labeled trace-linked rather than semantically reviewed.

Keep the assurance stages distinct:

```text
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

## 8c. Stage, validate, and publish one transaction

Run `mktemp -d` in its own shell call to create a fresh temporary directory
outside repository-controlled output trees. Capture its exact absolute stdout
as `<exact absolute staging directory returned by mktemp>`. Do not rely on a
shell variable in later calls. Preflight that exact staging location immediately
before rendering into it. Rendered files are still prospective output; do not
copy any of them to `docs/security/` directly.

```
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/safe_paths.py" \
    --project-root "<exact absolute staging directory returned by mktemp>" \
    --check-output "<exact absolute staging directory returned by mktemp>"
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/render.py" \
    .security-requirements/requirements.yaml \
    --out "<exact absolute staging directory returned by mktemp>"
```

When the approved policy has `publish_risk_summary: true`, place only the
deterministically rendered aggregate summary in the captured staging directory and
include `risk-summary.md` in the managed-file list. Immediately before that
opt-in publication, preflight its exact final target; the publisher validates
it again at replacement time:

```
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/safe_paths.py" \
    --project-root "$PWD" --check-output docs/security/risk-summary.md
```

Finally call the transactional publisher. The list is the complete desired
plugin-managed set. It rechecks the risk gate, validates all final targets
immediately before its directory swap, preserves unrelated human-owned files,
and removes an omitted summary only when its digest-bound, plugin-owned external
managed-state record proves the plugin owned those exact bytes. A repository
copy of that record has no authority.

```
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/publish.py" \
    --project-root "$PWD" \
    --generated "<exact absolute staging directory returned by mktemp>" \
    --managed-file requirements.md traceability.md responsibility.md
```

Append `risk-summary.md` to that same `--managed-file` invocation only for the
approved opt-in case. A risk, lint, overlay, render, staging, or publication
failure leaves the previous `docs/security/` bytes unchanged.

## 9. Report

State plainly:

- how many controls reached the delivery team, out of the baseline
- which services were unverified
- which regulatory overlays applied, at what scope, and which of their
  clauses no control reaches
- for each overlay, how many clauses have trace-linked candidate requirements, and how
  many are a gap rather than a deferral. Never the trace-linked count alone
- which detected regulations have no overlay at all
- what remains UNDETERMINED and what it cost
