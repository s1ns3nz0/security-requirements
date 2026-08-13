# Task 10 implementation report

## Outcome

Implemented the versioned dual-host threat-risk distribution contract and its
operator documentation.

- Strengthened `scripts/validate_distribution.py` as a read-only, aggregate-error
  validator. It does not import or execute payload/repository code.
- Required exactly one canonical default policy, risk engine, risk reference,
  Claude risk command, and Codex risk skill.
- Rejected duplicate risk assets, missing assets, unexpected host entrypoints,
  unsupported/unapproved payload components, symlinks, and junctions without
  traversing redirected content.
- Validated the exact bundled 5x5 policy schema and safe public-summary default.
- Enforced both payload manifests at `0.2.0`, the four ordered Codex starter
  prompts, and threat-reference/risk-engine schema version agreement. The two
  marketplace manifests were not version-bumped or otherwise changed.
- Documented exact Claude and Codex risk invocation, 5x5 bands, model proposal
  versus human approval, external digest binding, inherent publication gate,
  residual evidence rules, internal/public opt-in split, legacy migration,
  accepted-risk semantics, and `priority != risk` in `README.md` and `DESIGN.md`.
- Updated the README deterministic-suite count from fresh final collection.

## TDD evidence

RED: 22 focused distribution/documentation contracts initially failed for the
intended missing behavior. Review fix round 1 then added 27 regression cases.
Each of the five review groups was observed failing for the intended reason
before its implementation change:

- a redirected repository root, top-level scripts directory, and simulated
  generic Windows reparse point were not all rejected before traversal;
- nine rogue payload locations plus a missing approved asset were not governed
  by an exact recursive allowlist;
- five malformed `interface` shapes and a malformed `defaultPrompt` could
  escape aggregate validation;
- boolean/float policy scores, a boolean threshold, and duplicate YAML
  criterion keys were accepted;
- three engine mutations retained the right version strings while placing the
  wrong version constant in the active schema gate.

The no-follow audit also parameterized all five canonical risk assets. Those
cases exposed a downstream workflow scan that still followed redirected files;
all five failed before that scan was changed to lexical `lstat` classification.

GREEN:

```text
python -m pytest tests/test_distribution_docs.py -q
192 passed, 1 skipped in 57.51s

python -m pytest tests/test_risk.py -q
145 passed
```

## Final verification

Fresh full-suite execution after the last code/test change:

```text
python -m pytest --collect-only -q
1246 tests collected

python -m pytest tests/ -q \
  --junitxml=/tmp/security-requirements-task10-fix-round1.xml
1244 passed, 2 skipped in 87.82s
JUnit: tests=1246, failures=0, errors=0, skipped=2
```

Fresh validators after that suite:

```text
python scripts/validate_distribution.py .
exit 0

python /Users/s1ns3nz0/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py plugins/security-requirements
Plugin validation passed

claude plugin validate --strict plugins/security-requirements
Validation passed

claude plugin validate --strict .
Validation passed

claude --version
2.1.145 (Claude Code)

git diff --check
exit 0
```

The two skips were explicit environment conditions: a case-sensitive-filesystem
test on this case-insensitive temporary filesystem, and a real junction test
that requires Windows. Both host validators were available and therefore were
not skipped.

## Review fix round 1 implementation notes

- All repository-controlled traversal roots are classified with `Path.lstat()`
  before `os.scandir`; symlinks, Windows junctions, and generic reparse points
  are rejected without reading their targets. Later workflow, entrypoint,
  policy, schema, and manifest-path checks reuse the same lexical classification.
- The recursive payload contract enumerates every approved distributed file and
  directory, including the four Claude commands and four Codex skills. It
  rejects rogue skills, nested commands, arbitrary files, missing assets, and
  unsupported file types while leaving unrelated repository paths out of scope.
- Manifest interface and prompt shapes are type-guarded so malformed input is
  reported alongside other errors instead of raising a traceback.
- The safe YAML loader rejects duplicate mapping keys. Policy numeric fields
  require exact `int` values (therefore excluding `bool`) and canonical ranges.
- The risk engine declares named legacy/current/risk schema constants. The
  distribution validator parses its AST and verifies the active version gates,
  so merely retaining legacy and current string literals cannot satisfy the
  contract.
- The validator only reads metadata and payload source as data; it never imports
  or executes repository code. Marketplace manifests remain unchanged.
