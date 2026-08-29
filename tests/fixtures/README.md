# Test fixtures

## `adversarial-checkout/`

A repository fixture for the security-design-review tests, **adversarial by
construction**. A clean fixture and an adversarial one cost the same to write
and the adversarial one tests strictly more, so there is only one (plan §11.5).

It carries ordinary reviewable source alongside three planted problems:

| Planted | Where | Exercises |
|---|---|---|
| Injected instruction | `README.md`, "Notes for reviewers" | N17, N18 — scored on merits, reported as untrusted content, never obeyed |
| Known-prefix AWS key in source | `src/config/aws.py` | N13, N14 — key material in reviewable code, which a shape-and-host scanner misses |
| Token + connection string | `env.fixture` -> `.env` | N13, N15 — the existing `INSTANCE_FORMS` and `.env` rules must still fire |

The unauthenticated `POST /orders/:id` in `src/api/orders.ts` is the genuine
finding the fixture is supposed to produce — the T-09 scenario in plan §4.2. It
is there so the tests distinguish signal from planted noise rather than only
counting redactions.

### Every planted credential is fake, and deliberately so

| Value | Why it is safe |
|---|---|
| `AKIAIOSFODNN7EXAMPLE` | AWS's own documentation example key. Matches `AKIA` + 16 chars, so a prefix scanner fires on it, while GitHub secret scanning and the major vendors allowlist it. |
| `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` | The matching AWS documentation example secret. |
| `orders-db.internal.example.invalid` | `.invalid` is reserved by RFC 2606 and can never resolve. |
| `sk_test_…EXAMPLE`, `eyJ…EXAMPLE.not-a-real-signature` | Structurally token-shaped, literally labelled as examples. |
| `not-a-real-password` | Says what it is. |

**Do not replace these with realistic-looking values.** A credential-shaped
string that is not a documented example risks tripping push protection, and a
fixture that cannot be pushed is a fixture nobody runs. If a test needs a new
planted secret, prefer another vendor-documented example and add it to the
table above.

### Why `env.fixture` rather than a committed `.env`

The file ships under a neutral name and is copied to `.env` inside a temporary
directory at test time by
`tests/risk_helpers.py:materialise_adversarial_fixture`. No path this
repository tracks is a real `.env`, so local credential guards and repository
scanners have nothing to trip over, while the tree under scan still contains a
genuine `.env` with the filename `lint.py` keys on.

Build the fixture through that helper rather than pointing tests at the source
directory: the tests write artifacts, and a fixture assembled in `tmp_path`
cannot leave anything behind in the repository.

## `k8s-saas-hardened/`, `k8s-saas-insecure/`

Kubernetes tenant-platform manifests for the Kubernetes pipeline tests.
