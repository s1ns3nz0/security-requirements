---
description: Build the service profile - scan the repository, interview the gaps, confirm impact
---

Build the service profile for this repository. Follow
`skills/deriving-security-requirements/references/profile-schema.md` exactly.

## 1. Scan

Populate the `inferred` block from the repository. Record file and line as
`evidence` for each finding — the user has to be able to check them at the gate.

Do not ask about anything you can determine here.

## 2. Detect repository visibility

```
gh repo view --json visibility
```

Record it. It decides where the sensitive outputs may live. If `gh` is
unavailable or the repository has no remote, record `UNDETERMINED` and treat it
as public for safety.

## 3. Interview

Ask the seven questions. Not more.

- Present inferred values for confirmation as a block; do not re-ask them
- Set `locale` to the language the user is answering in
- Where inference failed and the user does not know, write `UNDETERMINED` and
  state what it will cost downstream. Do not guess

## 4. Derive impact

```
python3 scripts/select_baseline.py .security-requirements/profile.yaml \
    --json .security-requirements/controls.json
```

## 5. Gate

Show the derivation with its full reasoning, then stop and wait.

Do not proceed to `/sec-req-build` without an explicit confirmation. If the user
adjusts a level, write `overridden_by_user: true` and the reason into the
profile — "why Moderate?" must have an answer at audit.

## 6. Place the outputs

Write `.security-requirements/profile.yaml`.

If visibility is public or undetermined, add `.security-requirements/` to
`.gitignore` and tell the user plainly:

> The profile and threat model describe where data lives and which controls are
> not yet implemented. On a public repository that is a reconnaissance document,
> and git history survives deletion. Consider an internal repository instead.

If the repository is private, commit them — the history is useful at audit —
but say what changes if the repository is ever made public.
