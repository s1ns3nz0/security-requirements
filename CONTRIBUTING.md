# Contributing

The most useful contribution is a **curated service file**. One managed service,
one file, one pull request.

## Why service curation matters most

Responsibility classification is what makes the output usable. A Moderate
baseline is 287 controls; a delivery team owns a fraction of that. Without a
curated file, a service falls back to the deployment-model layer and is marked
unverified in the output — honest, but coarse.

Curating one service takes a couple of hours and permanently improves every
derivation that touches it.

## Adding a service

Create
`plugins/security-requirements/responsibility/services/<provider>-<service>.yaml`.
Use
`aws-s3.yaml` as the model.

```yaml
service: aws-s3
provider: aws
display_name: "Amazon S3"
reviewed: true
reviewed_on: "2026-07-27"

controls:
  SC-28:
    responsibility: shared
    csp_part: "What the provider operates."
    team_part: "What the team must configure, stated as an action."
    evidence:
      - "The report or artefact that substantiates the provider's half"
    verification:
      method: iac_inspect
      target: "the resource or attribute to look at"
      expect: "the state that satisfies the control"
```

### Rules

**Only list controls where the service changes the answer.** Everything else
falls through to `plugins/security-requirements/responsibility/layers.yaml`. A file restating the layer
defaults adds maintenance and no information.

**Never assert inheritance as fact.** `csp_claimed` means the provider claims
it and the customer must obtain evidence. Always populate `evidence`; `lint.py`
blocks on a claim without it.

**State both halves of `shared`.** This is the bucket that matters. Collapsing
it into `csp_claimed` is how a control ends up owned by nobody — the provider
runs the key infrastructure, and the team still has to turn encryption on.

**Prefer the failure nobody sees.** The valuable entries are not "encryption
should be enabled" but the ones that explain why the obvious configuration is
insufficient: a bucket outside the account-level public access block, a
presigned URL that no bucket policy reveals, a cache key that serves one user's
response to another.

**`reviewed: true` means a person read the control text.** Model-generated
drafts land as `reviewed: false` and are shown as unverified. Do not promote one
without working through it.

## Adding a golden case

`golden/<name>/profile.yaml` plus `expected-coverage.yaml`.

**Golden profiles must be synthetic.** This repository is public. A profile
plus its open requirements is a reconnaissance document, and a real service's
architecture and unimplemented controls must not be in it.

Score by topic, never by wording — phrasing changes on every run, and matching
strings measures paraphrase. `match_any` keyword hints approximate the real
question ("was this subject addressed at all?"). **Widening a hint so a failing
run passes is how the suite stops measuring anything**; investigate the run
first.

Include `must_not_cover`. A case that only checks recall cannot catch the
failure where the tool ignores the profile and emits a generic set.

## Adding an overlay

See `plugins/security-requirements/overlays/SCHEMA.md`. Check the licence table before bundling any source
text — that decision is not recoverable once published.

## Changing the classification tables

`plugins/security-requirements/catalogs/data-types/classification.yaml` decides the baseline size, so a change
here moves every derivation.

Two rules learned by getting them wrong:

**Do not over-assign High.** FIPS 199 reserves it for severe or catastrophic
effect. The high water mark means one inflated axis drags the whole system to
370 controls and the team discards the document — leaving the service with no
requirements at all.

**Do not smuggle requirements through categorisation.** Audit log integrity
matters, but assigning it a fixed Moderate to make the point would put every
system that keeps audit logs at Moderate or above, which is every system, and
would make the Low baseline unreachable. Requirements come from the baseline
and the threat model.

Run all four golden cases after any change. They should land on Low, Moderate,
Moderate, and High respectively; the range being reachable is the point.

## Running things

Development and validation require Python 3.12 or newer and PyYAML. The runtime
uses `pathlib.Path.is_junction()` as a mandatory output-safety check and does not
support older Python versions.

```
python3 -I plugins/security-requirements/scripts/rebuild_catalogs.py  # rebuild from upstream
python3 -m pytest tests/                # deterministic layer
python3 -I plugins/security-requirements/scripts/lint.py <requirements>  # source integrity and style gate
```

## Validating a distributable clone

Before a release, run the clean-clone checks from the repository root:

```bash
python3 -m pytest tests/test_distribution_docs.py -q
python3 scripts/validate_distribution.py .
```

The validator is read-only: it does not install plugins or rewrite either
marketplace. It checks that both host marketplaces resolve to the one payload,
that the host manifests and their relative paths exist, and that all three
Claude commands and Codex skills are present. Keep runtime assets in the shared
payload; do not add symlinks or a second copy of a runtime directory.

Bundled catalogs are committed so the tool works offline and so a change in
upstream data is visible as a diff rather than a silent shift.
