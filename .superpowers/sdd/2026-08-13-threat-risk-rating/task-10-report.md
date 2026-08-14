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

## Review fix round 2

Three further Important findings were reproduced independently before their
fixes. The two redirected-payload-root cases each observed seven downstream
reads, a bundled `__pycache__` plus `.pyc` produced no validation error, a real
`git archive HEAD` extraction was rejected for the three unstorable empty
`agents/` directories, and an unreachable `if False` schema gate satisfied the
generic AST search.

The resulting contract now:

- includes the payload boundary itself in every lexical redirect check and
  stops all payload readers/scanners after a redirected payload root is found;
- treats every `__pycache__` directory and `.pyc` file as an unapproved archive
  path, with no cache exception;
- derives required directories only from enumerated files, so local untracked
  empty directories are not distribution requirements;
- validates the actual extracted `git archive HEAD` shape; and
- accepts an engine version gate only when it is a reachable top-level `if`
  whose condition contains the named comparison and whose body appends a
  validation problem or raises.

Round 2 verification after the final test/code changes:

```text
python -m pytest tests/test_distribution_docs.py -q
197 passed, 1 skipped in 58.39s

python -m pytest --collect-only -q
1251 tests collected

python -m pytest tests/ -q \
  --junitxml=/tmp/security-requirements-task10-fix-round2-final.xml
1249 passed, 2 skipped, 1 pre-existing SyntaxWarning in 86.99s
JUnit: tests=1251, failures=0, errors=0, skipped=2

python /Users/s1ns3nz0/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py \
  plugins/security-requirements
Plugin validation passed

claude plugin validate --strict plugins/security-requirements
Validation passed

claude plugin validate --strict .
Validation passed
```

## Review fix round 3

Two remaining Important findings were reproduced before implementation. A
comprehensive path-operation spy observed twelve descendant `lstat`/
`is_junction` operations for each redirected payload-root variant. Separate
engine mutants showed that both `or False and <legacy-version-comparison>` in
`migrate` and `if False and <risk-version-comparison>` in `_load_risk_state`
were accepted by the descendant AST search.

The validator now validates only the two root marketplace metadata paths before
the redirected-payload early return. Payload manifest metadata traversal starts
after that gate, so a redirected payload produces no descendant `lstat`,
`stat`, `read_text`, `exists`, `is_file`, `is_dir`, `is_junction`, or `scandir`
operation. The AST contract no longer walks condition descendants: `migrate`
must use the live two-operand `not isinstance(...) or version != LEGACY...`
shape with the comparison as a direct operand, while `_validate_threats` and
`_load_risk_state` must use a direct comparison. Each gate must still have a
direct rejection action.

Round 3 verification after the final code/test changes:

```text
python -m pytest tests/test_distribution_docs.py -q
199 passed, 1 skipped in 56.24s

python -m pytest --collect-only -q
1253 tests collected

python -m pytest tests/ -q \
  --junitxml=/tmp/security-requirements-task10-fix-round3.xml
1251 passed, 2 skipped in 87.56s
JUnit: tests=1253, failures=0, errors=0, skipped=2

python scripts/validate_distribution.py .
exit 0

python /Users/s1ns3nz0/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py \
  plugins/security-requirements
Plugin validation passed

claude plugin validate --strict plugins/security-requirements
Validation passed

claude plugin validate --strict .
Validation passed
```

## Review fix round 4

The final two AST findings were reproduced before implementation. Replacing the
canonical `Mapping` type in the `migrate` guard with `str` passed because the
validator checked only the first `isinstance` argument. Prepending a statically
true terminating `if` before the real guard in each of `_validate_threats`,
`migrate`, and `_load_risk_state` also passed because the validator searched
later statements.

Rather than adding partial control-flow analysis, the validator now enforces an
exact executable prefix for each function after removing only its optional
docstring. `migrate` must begin with the two-operand guard containing exactly
`isinstance(threats, Mapping)` and the direct legacy-version comparison.
`_validate_threats` must begin with its canonical problems declaration, Mapping
type guard, and current-version guard. `_load_risk_state` must begin with the
exact project-path load, state load, and risk-version guard. Any inserted
statement changes that prefix and fails closed; every gate still requires a
direct rejection action.

Round 4 verification after the final code/test changes:

```text
python -m pytest tests/test_distribution_docs.py -q
203 passed, 1 skipped in 57.61s

python -m pytest --collect-only -q
1257 tests collected

python -m pytest tests/ -q \
  --junitxml=/tmp/security-requirements-task10-fix-round4.xml
1255 passed, 2 skipped in 88.71s
JUnit: tests=1257, failures=0, errors=0, skipped=2

python scripts/validate_distribution.py .
exit 0

python /Users/s1ns3nz0/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py \
  plugins/security-requirements
Plugin validation passed

claude plugin validate --strict plugins/security-requirements
Validation passed

claude plugin validate --strict .
Validation passed
```

## Review fix round 5 (final)

The last two AST findings were reproduced with six concrete mutants before the
runtime/validator simplification. Each of the three version-gate bodies accepted
an unconditional `return` before its eventual append/raise. The validator also
accepted `problems = 1 / 0`, `_project_document_path(1 / 0, paths, "state")`,
and an extra keyword on the migration `isinstance` call.

The runtime now exposes three small, explicit schema contract helpers:

- `_current_threat_schema_problems` owns current threat type/version problems;
- `_require_legacy_threat_schema` owns the exact legacy Mapping/version guard;
- `_load_validated_risk_state` owns the exact state load, Mapping/version guard,
  snapshot validation, and return.

The three existing callers begin with the corresponding exact helper call (or
return it directly). The distribution validator compares the normalized AST of
each complete helper definition against its canonical AST and separately
compares each caller's first executable statement. It no longer performs
partial condition or reachability inference. Consequently, setup expressions,
arguments, keywords, statement ordering, early returns, and rejection bodies
all fail closed when they depart from the reviewed contract.

During a dirty development tree, the archive regression uses the anonymous
candidate commit produced by `git stash create`; in a clean tree it uses
`HEAD`. The final post-commit verification below additionally archives literal
`HEAD`.

Round 5 verification after the final code/test changes:

```text
python -m pytest tests/test_risk.py -q
145 passed in 7.01s

python -m pytest tests/test_distribution_docs.py -q
209 passed, 1 skipped in 60.05s

python -m pytest --collect-only -q
1263 tests collected

python -m pytest tests/ -q \
  --junitxml=/tmp/security-requirements-task10-fix-round5.xml
1261 passed, 2 skipped in 94.44s
JUnit: tests=1263, failures=0, errors=0, skipped=2

python scripts/validate_distribution.py .
exit 0

python /Users/s1ns3nz0/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py \
  plugins/security-requirements
Plugin validation passed

claude plugin validate --strict plugins/security-requirements
Validation passed

claude plugin validate --strict .
Validation passed
```
