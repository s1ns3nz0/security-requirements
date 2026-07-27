# security-requirements

Derives security requirements for a service. Not a scanner.

Most security tooling is **discovery** — read the code, find the flaw. There is
plenty of it. This is **prescription**: state what the service must satisfy,
before or independently of any code existing. That is the artefact a compliance
or design stage actually needs, and it is the one nothing produces.

> **Status: week 1.** The pipeline runs end to end, but only the AC, AU, and SC
> control families are bundled and only S3 and RDS are curated. See
> [DESIGN.md](DESIGN.md) for what is deliberately missing.

## What it produces

```
docs/security/
  requirements.md      organised by CSF 2.0 function, so it reads as work
  traceability.md      control -> requirement, so an auditor can check coverage
  responsibility.md    who owns what, and what evidence backs each claim
```

Each requirement is verifiable, atomic, states a property rather than an
implementation, and carries the control identifiers it derives from.

## How it works

Two paths, crossed.

```
profile
  |-- FIPS 199 impact -> 800-53B baseline        completeness
  |-- DFD -> STRIDE / LINDDUN -> threats         relevance
        |
        v
  threat AND baseline  ->  raised priority
  threat only          ->  additional requirement    <- why this exists
  baseline only        ->  retained, lower priority
        |
        v  responsibility split
  provider claimed / shared / organisational / team
```

The baseline guarantees nothing is missed. The threat model finds what a
baseline cannot express — tenant isolation, business logic replay, personal data
leaving inside a stack trace. The responsibility split is what makes the result
usable: a Moderate baseline is about 290 controls, and most of them are not the
delivery team's work.

## Design commitments

**Control identifiers are never recalled from memory.** The catalog is derived
mechanically from NIST's OSCAL release, and `scripts/lint.py` fails the build if
a requirement cites an identifier the catalog does not contain. A fabricated
`SC-28(4)` reads exactly like the three enhancements that are real; one of them
in a compliance document discredits all of it.

**Inheritance is a claim, not a fact.** Nothing is asserted to be handled by the
cloud provider. Provider-claimed controls carry the evidence a reader must
obtain to substantiate them.

**Coverage gaps are stated, never implied away.** Detected regulations outside
the supported set are declared as not covered. Services without a curated
responsibility file are shown as unverified. Controls in families that are not
yet bundled are reported as unavailable rather than dropped.

**Human edits survive re-runs.** Exception approvals, rewritten statements, and
status are never overwritten; competing changes land in `pending_review`.
Requirements are retired with a reason, never deleted — last quarter's audit
report has to remain answerable.

**Identifiers are stable.** Derived from content, not sequence. A requirement
inserted in the middle does not silently repoint every existing ticket and
evidence link.

## Usage

```
/sec-req-init      scan the repository, interview the gaps, confirm impact
/sec-req-build     threat model, responsibility split, write requirements
/sec-req-refresh   re-derive after a change, preserving human edits
```

## Output placement

`.security-requirements/` holds the profile, threat model, and implementation
status. Together those describe where the data lives, which trust boundaries
exist, which controls are not implemented, and which risks were accepted until
when. That is a reconnaissance document. On a public repository it is gitignored
with an explanation; git history survives deletion.

`docs/security/` holds the requirement definitions, which are safe to publish
and better for being read.

## Development

```
python3 scripts/rebuild_catalogs.py --families ac,au,sc   # build the catalog
python3 -m pytest tests/                                  # deterministic layer
python3 scripts/eval_golden.py golden/b2b-saas-aws requirements.yaml
```

Contributions of curated service files are the most useful kind: one file under
`responsibility/services/` per managed service, one pull request each.

## Licence

Apache-2.0 for the code. Bundled reference data keeps its own terms — see
[NOTICE](NOTICE). NIST does not endorse this project.

This tool produces drafts. It is not legal advice and does not substitute for
compliance certification.
