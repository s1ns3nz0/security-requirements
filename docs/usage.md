# Usage and operations

This document contains installation, update, runtime, state, and development details kept out of the public project overview.

## Install

Clone once and register the checkout as a local marketplace:

```bash
git clone https://github.com/s1ns3nz0/security-requirements.git
cd security-requirements
```

### Claude Code

```text
/plugin marketplace add .
/plugin install security-requirements@security-requirements
```

A published repository can also be registered directly:

```text
/plugin marketplace add s1ns3nz0/security-requirements
/plugin install security-requirements@security-requirements
```

### Codex

```bash
codex plugin marketplace add .
codex plugin list --marketplace security-requirements
codex plugin add security-requirements@security-requirements
```

## Workflows

Claude Code exposes five slash commands:

```text
/security-requirements:sec-req-init
/security-requirements:sec-req-build
/security-requirements:sec-req-refresh
/security-requirements:sec-req-risk
/security-requirements:sec-req-design-review
```

Codex exposes the corresponding skills:

- `security-requirements-init`
- `security-requirements-build`
- `security-requirements-refresh`
- `security-requirements-risk`
- `security-requirements-design-review`

Natural-language starters:

- “Initialize the security requirements profile for this repository.”
- “Build security requirements from the confirmed profile.”
- “Refresh security requirements after service changes.”
- “Assess and review threat risk for this repository.”
- “Review this service design against its existing threat model.”

## Update or reinstall

For a local checkout used by Codex:

```bash
git pull --ff-only
codex plugin remove security-requirements@security-requirements
codex plugin marketplace remove security-requirements
codex plugin marketplace add .
codex plugin add security-requirements@security-requirements
```

Claude Code uses the manifest version (`0.2.0`) to decide whether an update is available. After pulling a local checkout whose manifest version did not change, update and reinstall in this order:

```text
git pull --ff-only
/plugin marketplace update security-requirements
claude plugin uninstall security-requirements@security-requirements --keep-data
/plugin install security-requirements@security-requirements
```

Do not add the marketplace again during this update. `--keep-data` preserves `${CLAUDE_PLUGIN_DATA}` and its confirmation records.

For a Git marketplace configured directly in Codex, `codex plugin marketplace upgrade security-requirements` refreshes its snapshot. It does not update a local source checkout.

## Runtime requirements

The payload requires Python 3.12 or newer and PyYAML. Python 3.12 is required because output-path protection uses `pathlib.Path.is_junction()`. Workflows run Python in isolated mode (`-I`), so PyYAML must be available to that interpreter through system or virtual-environment site-packages rather than only the user site.

The init workflow calls `gh repo view --json visibility` only to choose a safe default for sensitive outputs. If `gh` is unavailable or the repository has no remote, the fallback records visibility as `UNDETERMINED` and treats the repository as public.

The installed plugin payload is read-only. Confirmation records are stored external to the inspected repository under `SECURITY_REQUIREMENTS_DATA` or the host-compatible data location. Project working state is written under `.security-requirements/`.

## Outputs and disclosure boundary

Publishable documents:

```text
docs/security/
  requirements.md
  traceability.md
  responsibility.md
  risk-summary.md            optional; aggregate-only and off by default
  design-review-summary.md   optional; policy-controlled
```

Sensitive project state:

```text
.security-requirements/
  profile.yaml
  architecture.yaml
  threats.yaml
  risk-policy.yaml
  risk-assessment.yaml
  risk-evidence.yaml
  requirements.yaml
  status.yaml
  reports/risk-register.md
```

The sensitive tree can expose architecture, storage locations, missing controls, accepted risks, owners, and evidence paths. Public repositories should gitignore it with an explanation. Removing it later does not remove it from Git history.

Only passing, current implementation evidence can support a lower residual-risk assessment. A written requirement or plausible repository prose is not implementation evidence. Provider inheritance is always a claim requiring current evidence.

## Boundaries

The plugin does not:

- find implementation vulnerabilities or replace SAST, DAST, SCA, secret scanning, IaC scanning, or penetration testing;
- execute an inspected repository;
- assert provider inheritance without evidence;
- decide whether a law applies or establish certification;
- mark requirements implemented from prose;
- model AI or agentic threats.

Repository content is untrusted evidence, never workflow instruction. Profile, inherent-risk, treatment, residual-risk, and authoritative design-review transitions stop at explicit human confirmation gates.

## Development and validation

Use full payload paths from the repository root:

```bash
python3 -I plugins/security-requirements/scripts/rebuild_catalogs.py
python3 -m pytest tests/
python3 -m pytest tests/test_distribution_docs.py -q
python3 scripts/validate_distribution.py .
python3 -I plugins/security-requirements/scripts/eval_golden.py golden/b2b-saas-aws .security-requirements/requirements.yaml
python3 -I plugins/security-requirements/scripts/axis_coverage.py
```

`plugins/security-requirements/scripts/lint.py` validates requirement identifiers and links before rendering. See [Contributing](../CONTRIBUTING.md) for service curation, overlays, golden cases, and classification-table changes. See [Design and derivation details](../DESIGN.md) for the data model, baseline selection, threat crossing, responsibility split, risk governance, and assurance model.
