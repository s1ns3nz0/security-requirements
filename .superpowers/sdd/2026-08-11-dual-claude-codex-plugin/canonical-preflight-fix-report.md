# Canonical preflight and junction closure report

Date: 2026-08-12

Branch: `feat/dual-claude-codex-plugin`

Implementation commit: `7e2fc56 fix: require canonical output preflights`

## Status

PASS, with Windows execution evidence explicitly qualified below. The broad
safe-output preflight is now a source-level canonical contract instead of a
shell-token reconstruction, scoped safe-path checks remain supported, and
filesystem redirect checks cover supported Windows junctions as well as
symlinks. All current tests and distribution/host-schema validators pass.

## Architectural closure

`scripts/validate_distribution.py` now keeps each workflow's ordered output set
in `SAFE_OUTPUTS` and generates its one canonical broad preflight centrally.
For each command document, validity requires all of the following:

- exactly one raw/logical command equal to that workflow's generated canonical
  source, including quoting and output order;
- that command is the sole line of one executable `bash` fence outside HTML
  comments; and
- no other broad, malformed, path-equivalent, dynamically expanded, dead, or
  duplicate candidate is present.

Shell tokenization is used only as a conservative classifier for additional
candidates. It is not used to prove the canonical command valid. This removes
the old dependency on reconstructing quote provenance and shell control flow.
The `${CLAUDE_PLUGIN_ROOT}` trust exception is limited to the matching command
path and canonical source. Other Claude-root `safe_paths.py` calls, including
quote-spliced scoped calls, remain invalid for the cross-host payload.

The three command documents contain their canonical preflight on one physical
line. They document that Claude supplies `${CLAUDE_PLUGIN_ROOT}` for that one
line and that the Codex adapter replaces only that token with its
loader-verified root. All later scoped checks retain the exact-root binding
contract.

`safe_paths.py` now centralizes redirect detection across symlinks and
`Path.is_junction()` where available. It checks every project-root ancestor,
the root, every output ancestor, and the target. Raw `..` components are
rejected before `abspath()` can erase redirect-sensitive spelling. Lexical and
resolved containment use exact component-prefix comparisons so case-sensitive
NTFS roots cannot be confused with a differently cased sibling.

## TDD evidence

The initial source-mutant and portable-junction tests were written and run
before implementation:

```text
RED: 24 failed, 85 deselected in 3.02s
RED: 4 failed, 111 deselected in 1.08s
```

Adversarial review added regressions for inert fenced source, combined
quote-splicing, path-equivalent outputs, raw parent segments, path-scoped
trust, Windows exact-case containment, dynamic output sets, and quote-spliced
scoped Claude-root calls. Each failed before its implementation; representative
RED runs were:

```text
8 failed, 3 passed, 117 deselected in 1.12s
1 failed in 0.11s
2 failed, 5 deselected in 0.27s
2 failed in 1.45s
```

After the fixes and after moving source mutants into executable `bash` fences
so each mutation is independently meaningful:

```text
GREEN: 40 passed in 9.47s
GREEN: 150 passed, 1 skipped in 24.67s
```

The covered mutations include exact canonical acceptance; unquoted,
single-quoted, escaped, and literal `$PWD`; interpreter and script help/version;
extra interpreter options; `cd`, `env`, `true`, dead `true ||`, status masking,
pipes, semicolons, comments, duplicates, line continuation, output reordering,
legacy roots, quote/escape splicing, path-normalized aliases, dynamic output
sets, and canonical source placed in inert contexts.

## Final verification

Prepared interpreter: Python 3.12.11.

```text
965 tests collected in 0.20s
964 passed, 1 skipped in 46.13s
33 confirmation tests passed in 0.88s
```

Validator results:

```text
scripts/validate_distribution.py .: exit 0, no output
Codex validate_plugin.py: Plugin validation passed
claude plugin validate --strict plugins/security-requirements: Validation passed
claude plugin validate --strict .: Validation passed
```

`git diff --check` was clean before the implementation commit. The durable
verification record was updated in
`docs/superpowers/reports/2026-08-11-dual-plugin-verification.md`, and the README
deterministic test count is now 965.

## Platform qualification and residuals

The real Windows `/J` integration test is skipped on this macOS host. Junction
handling was instead exercised through a platform-independent `Path.is_junction`
seam at project-parent, project-root, output-ancestor, and output-target
boundaries. A `PureWindowsPath` seam verifies the case-sensitive NTFS sibling
comparison. No claim is made that a real Windows junction or case-sensitive
NTFS run occurred.

A preflight followed by a separate model Write/Edit remains a check-then-use
protocol, not an OS-level directory capability. The workflow requires the
exact-target check immediately before the write but cannot eliminate a
concurrent filesystem race. Installed Claude/Codex execution was not repeated
after `7e2fc56`; current adapter behavior is verified structurally and through
the host validators. YAML-using runtime scripts still require PyYAML in the
isolated interpreter's system or virtual environment.

The independent review produced and reproduced the dynamic-output and
quote-spliced scoped-call findings after its first pass; both are covered by
GREEN regressions. Its final automated response was interrupted before a formal
ready verdict, so this report records test and validator evidence rather than
claiming an unreturned approval.
