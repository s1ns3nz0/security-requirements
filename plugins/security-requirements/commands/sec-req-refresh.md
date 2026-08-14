---
description: Re-derive requirements after the service changed, preserving human edits and exception approvals
---

## Trusted runtime paths

Treat every shell tool call as a fresh shell, especially the first call after a
renewed confirmation gate. Capture the exact absolute `${CLAUDE_PLUGIN_ROOT}`
value as `<exact absolute plugin root>`, then resolve persistent state once:

```bash
SECURITY_REQUIREMENTS_ROOT="${CLAUDE_PLUGIN_ROOT}" \
python3 -I "${CLAUDE_PLUGIN_ROOT}/scripts/runtime_paths.py" --project-root "$PWD"
```

Capture its exact absolute stdout as
`<exact absolute data root returned by runtime_paths.py>`. Do not set or
overwrite the neutral `SECURITY_REQUIREMENTS_DATA` first: the helper gives it
precedence over `CLAUDE_PLUGIN_DATA`, then uses the external OS default.
Substitute both exact literals everywhere below. Every shell call independently
prefixes them; exports from another call do not persist. For Read, Write, or
Edit, pass the exact literal path because those tools do not expand shell
syntax. Never derive either root from the inspected repository or cwd.

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

Re-runs the derivation against the current state of the repository while
protecting everything a person wrote.

## What must survive

The whole design of the merge exists to stop this sequence:

1. the tool generates a requirement
2. security review rewrites the statement to match the actual key management
3. another requirement is accepted as a risk, approved by name, with an expiry
4. three months later the service gains a component and this command runs
5. **the tool overwrites all of it**

Step 5 is where the tool loses its user. So:

- `human` blocks are never touched
- changes the tool wants to make to a `managed` field on a requirement carrying
  `human` content go to `pending_review`, and the user decides
- requirements are never removed; status transitions to `superseded_by` or
  `retired` with a reason
- `locale` comes from the existing profile, not from the language of this
  session — otherwise the document ends up half translated

## 1. Refresh the profile

Re-run the repository scan. Show a diff of the `inferred` block against the
stored profile.

Ask only about genuinely new things — a new managed service, a new external
integration, a new entrypoint class. Do not re-run the seven questions.

Run `safe_paths.py` in a fresh shell call immediately before every direct model
Write or Edit, then pass the same exact checked path to the write tool. A prior
check never authorizes a later write. After the scan, diff, and any answers,
preflight the profile:

```
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/safe_paths.py" \
    --project-root "$PWD" --check-output .security-requirements/profile.yaml
```

Immediately Edit `.security-requirements/profile.yaml` with the accepted
inferred changes and new answers, using that same exact checked path.

If the change alters the impact derivation, show the recalculation and gate on
it again.

## 2. Re-derive

```
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/select_baseline.py" \
    .security-requirements/profile.yaml \
    --json .security-requirements/controls.json
```

Show the recalculated derivation and complete profile diff. Any profile change
invalidates its stored digest. After explicit confirmation, persist the approval
in plugin-owned state and enforce it. On resume, treat each invocation below as
a fresh shell call and substitute both exact captured literals again:

```
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/confirmation.py" --stamp \
    .security-requirements/profile.yaml --by user
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/confirmation.py" --check \
    .security-requirements/profile.yaml
```

Immediately before updating the threat model, preflight its exact file:

```
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/safe_paths.py" \
    --project-root "$PWD" --check-output .security-requirements/threats.yaml
```

Update the threat model incrementally. New components and new flows get new
threats; existing threats keep their identifiers.

If the stored threat document uses schema `0.1.0`, treat it as
`legacy_unassessed`. Count its active legacy threats and, when the three risk
scaffolding files do not yet exist, run the deterministic migration once:

```
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/risk.py" migrate \
    --project-root "$PWD" \
    --threats .security-requirements/threats.yaml \
    --requirements .security-requirements/requirements.yaml \
    --policy .security-requirements/risk-policy.yaml \
    --assessment .security-requirements/risk-assessment.yaml \
    --state .security-requirements/risk-state.yaml
```

Show the CLI's exact active legacy threat count and its statement,
`Prior published documents were not modified.` The migration creates review-only
internal proposals and preserves existing requirement exceptions. The model
must not edit the threat schema version or invent scores, ratings, approval, or
confirmation. Stop this refresh after scaffolding and direct the user into the
risk confirmation review; do not silently continue to publication. If the
scaffolding already exists, preserve it and resume that same risk confirmation
review instead of running migration again. Only a successful human-confirmed
`risk.py confirm` call may advance the threat schema to `0.2.0`.

For a `0.2.0` project, persist selective stale/new/reopened transitions from
the current threats, requirements, and evidence before displaying the risk
review. This command verifies the externally bound prior risk state before it
uses that state as the comparison baseline:

```
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/risk.py" refresh \
    --project-root "$PWD" \
    --policy .security-requirements/risk-policy.yaml \
    --threats .security-requirements/threats.yaml \
    --assessment .security-requirements/risk-assessment.yaml \
    --requirements .security-requirements/requirements.yaml \
    --evidence .security-requirements/risk-evidence.yaml \
    --state .security-requirements/risk-state.yaml
```

Re-evaluate inherent risk immediately after the threat update. Preserve
unchanged human rationale, treatment, owner, acceptance, and evidence. New or
changed threats remain proposed or stale until reviewed; never silently reuse
conversation memory as approval.

Immediately before a policy proposal write or edit, preflight its exact file:

```
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/safe_paths.py" \
    --project-root "$PWD" --check-output .security-requirements/risk-policy.yaml
```

Immediately before writing or editing the canonical assessment proposal,
preflight it:

```
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/safe_paths.py" \
    --project-root "$PWD" --check-output .security-requirements/risk-assessment.yaml
```

Display a batch review table for all active threats, highlighting only new,
changed, stale, or unresolved records while retaining the full canonical
digest. Show likelihood, impact, score/rating preview, treatment, and unresolved
fields. Stop for explicit confirmation. If the user adjusts anything, preflight
and rewrite the assessment, redisplay the table, and ask again. The persisted
gate, never conversation state, decides whether the workflow resumes.

After explicit policy and assessment confirmation, stamp and check them in
fresh calls:

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
    --requirements .security-requirements/requirements.yaml \
    --evidence .security-requirements/risk-evidence.yaml \
    --state .security-requirements/risk-state.yaml \
    --by user --authority self_declared
```

```
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/risk.py" check \
    --project-root "$PWD" \
    --policy .security-requirements/risk-policy.yaml \
    --threats .security-requirements/threats.yaml \
    --assessment .security-requirements/risk-assessment.yaml \
    --requirements .security-requirements/requirements.yaml \
    --evidence .security-requirements/risk-evidence.yaml \
    --state .security-requirements/risk-state.yaml
```

Any unresolved inherent record blocks publication. Residual `UNDETERMINED` is
reported but does not block publication.

Before any later evidence, history, or internal-register write, use the exact
matching preflight immediately before that individual operation:

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

Only after the risk check succeeds, refresh the responsibility output:

```
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/classify_resp.py" \
    .security-requirements/profile.yaml \
    .security-requirements/controls.json \
    --json .security-requirements/responsibility.json
```

Run every applicable regulatory overlay against the refreshed profile and
controls. Generate the `forces_requirements` entries from the refreshed data
types even when no threat matches them.

## 3. Cross, author, and merge

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

Immediately before updating the draft, preflight its exact file:

```
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/safe_paths.py" \
    --project-root "$PWD" --check-output .security-requirements/draft.json
```

Update `.security-requirements/draft.json` from this work list, including new
overlay-standalone and `forces_requirements` work. Do not reuse the old draft
unchanged.

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

`state.yaml` reissues the identifiers that were already assigned. A requirement
must keep its identifier across runs or every ticket, evidence link, and
exception approval that references it silently starts pointing somewhere else.

## 4. Validate and publish

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
python3 -I "<exact absolute plugin root>/scripts/lint.py" \
    .security-requirements/requirements.yaml \
    --threats .security-requirements/threats.yaml --locale "$locale"
```

Re-run every applicable overlay against the written document:

```
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/apply_overlay.py" <overlay-id> \
    .security-requirements/profile.yaml \
    .security-requirements/controls.json \
    --requirements .security-requirements/requirements.yaml \
    --cross .security-requirements/cross.json
```

Only after every overlay succeeds, run `mktemp -d` in its own shell call to
create a staging directory outside repository-controlled output trees. Capture
its exact absolute stdout as
`<exact absolute staging directory returned by mktemp>`; no shell variable
survives into a later call. Preflight that exact location immediately before
rendering, and keep all prospective documents there until every validation has
succeeded:

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

Never author or copy a summary into staging. If and only if the approved policy
opts in, preflight its exact final target immediately before publication. The
publisher renders the exact aggregate through `risk.render_public_summary` from
the digest-bound inputs and accepts no caller summary or internal fields:

```
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/safe_paths.py" \
    --project-root "$PWD" --check-output docs/security/risk-summary.md
```

Publish the complete three-file base set in one transaction:

```
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/publish.py" \
    --project-root "$PWD" \
    --generated "<exact absolute staging directory returned by mktemp>"
```

For the approved opt-in case, use this exact engine-owned invocation instead:

```
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/publish.py" \
    --project-root "$PWD" \
    --generated "<exact absolute staging directory returned by mktemp>" \
    --risk-summary
```

The flag fails unless the externally confirmed policy opts in. The publisher
checks risk again, preserves unrelated human-owned files, and removes an omitted
summary only when its digest-bound, plugin-owned external managed-state record
proves ownership; a repository copy has no authority. A risk, overlay, lint,
render, or publication failure preserves the previous `docs/security/` bytes
exactly.

## 5. Report the delta

```text
  added        3   (2 from the new component, 1 from a raised data classification)
  proposed     2   pending_review, awaiting your decision
  superseded   1   REQ-LOG-RETENTION-01 -> REQ-LOG-RETENTION-02
  unchanged   44

  expiring exceptions
    REQ-LOG-RETENTION-01  approved by CISO, expires 2026-12-31 (in 5 months)
```

Surface exceptions approaching expiry. Nobody tracks those by hand, and an
expired risk acceptance is an audit finding.
