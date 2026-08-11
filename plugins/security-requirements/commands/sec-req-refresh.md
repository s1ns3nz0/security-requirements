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

Before reading or writing workflow outputs, reject repository-controlled
symlinked output trees:

```bash
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/safe_paths.py" \
    --project-root "$PWD" --check-output .security-requirements docs/security
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

Only then continue:

```
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/classify_resp.py" \
    .security-requirements/profile.yaml \
    .security-requirements/controls.json \
    --json .security-requirements/responsibility.json
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
    --state .security-requirements/state.yaml
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

Only after every overlay succeeds, publish:

```
SECURITY_REQUIREMENTS_ROOT="<exact absolute plugin root>" \
SECURITY_REQUIREMENTS_DATA="<exact absolute data root returned by runtime_paths.py>" \
python3 -I "<exact absolute plugin root>/scripts/render.py" \
    .security-requirements/requirements.yaml --out docs/security/
```

An overlay, lint, or render failure blocks publication.

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
