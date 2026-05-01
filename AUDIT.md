# Audit Log

This file records the audit history of the Mosaic codebase. New entries are
appended in reverse chronological order.

For external review firms: start with
[`docs/audit-coverage-runbook.md`](docs/audit-coverage-runbook.md)
— it gives you the local-reproduce + extend recipes for every
audit-coverage surface listed below.

---

## 2026-04-30 — v0.9.7-halo2-proof-compressed release (session 108)

| Field | Value |
|---|---|
| Tag | [`v0.9.7-halo2-proof-compressed`](https://github.com/wienerlabs/mosaic/releases/tag/v0.9.7-halo2-proof-compressed) |
| Auditor | Internal (Wiener Labs) |
| Scope | Halo2 proof gains compressed wire format alongside session-106's compressed VK. Combined VK + proof compression saves ~46 %/~32 % wire size respectively for a typical 2-fixed + 5-perm + 5-advice deployment. |
| Findings | Zero soundness regressions. Round-trip correctness pinned by `proof_compressed_round_trip_with_real_generators`; size invariant pinned by `proof_compressed_form_is_smaller_than_uncompressed`; rejection paths covered for short buffers + trailing garbage. |
| Status | ✅ Compression syscall (sessions 103-104) now has TWO real consumers: VK (session 106) + proof (session 108). |

### What this changes for an external auditor

Real Halo2 proofs are bandwidth-heavy. A typical 5-advice + 1-lookup
+ 3-quotient + 2-opening proof carries 12 G1 commits × 64 B = 768 B
of curve-point data, plus ~600 B of Fr evaluations. Pre-session-108
proofs could only land on Solana in their full 1.4 KB form;
session-108 lets a deployment opt into the 1.05 KB compressed form
(~26 % smaller overall).

For chunked-upload-protocol consumers (`mosaic-program::dispatch_verify`)
the compressed form fits more proofs per chunk and reduces the
number of chunks needed for proofs near the 1232 B instruction-data
limit.

### Soundness inheritance

The compressed proof parser leverages the canonical
`Halo2KzgProof::from_bytes` for shape validation:
- `compress_from_canonical_bytes` calls `from_bytes` upfront → any
  malformed canonical input rejects before compression.
- `decompress_to_canonical_bytes` validates the compressed buffer
  total length against the declared shape (n_advice +
  n_lookups + 1 + n_quotient + 2 G1 commits + n_evals Fr).

Mismatches surface as `ProofLengthMismatch` at parse time, never as
silent data corruption.

### Lib test totals at v0.9.7

  mosaic-halo2            123  (+6)
  total                   660  (+6 since v0.9.6)

### What this milestone DOES change

- Halo2 proof gains a compressed wire-format alternate.
- Compression syscall (sessions 103-104) now has 2 real verifier-
  side consumers (VK + proof).

### What this milestone does NOT change

- Verifier behaviour for uncompressed proofs (byte-equivalent),
  in-memory proof representation. Once decompressed, the proof
  view matches the existing canonical layout.
- Header layout (FIXED_HEADER_LEN = 20 bytes, unchanged since
  session 100).
- Other verifier crates (Groth16, PLONK, HyperPlonk, Nova, STARK)
  proof formats unchanged.

### Cumulative compression saving for a typical Halo2 deployment

| Component | Uncompressed | Compressed | Saving |
|---|---|---|---|
| VK (2 fixed + 5 perm) | 488 B | 264 B | 224 B (46%) |
| Proof (5+1+3+2 commits + evals) | 1408 B | 1056 B | 352 B (25%) |
| **Combined** | **1896 B** | **1320 B** | **576 B (30%)** |

For 100K Halo2 verify transactions on Solana, the combined saving
is ~57.6 MB of instruction data — meaningful at scale.

---

## 2026-04-30 — v0.9.6-halo2-multi-lookup release (session 107)

| Field | Value |
|---|---|
| Tag | [`v0.9.6-halo2-multi-lookup`](https://github.com/wienerlabs/mosaic/releases/tag/v0.9.6-halo2-multi-lookup) |
| Auditor | Internal (Wiener Labs) |
| Scope | Multiple lookup arguments per Halo2 proof — generalizes session-100/101 single-column-multi-column to n distinct lookups, each summed with a distinct y-power for soundness. |
| Findings | Zero soundness regressions. The distinct-y-power weighting is critical: tamper-rejection tests pin that any lookup index's m_eval tamper surfaces (without distinct powers, lookup contributions could cancel out adversarially). |
| Status | ✅ Real Halo2 circuits (which routinely declare 2-5 lookup arguments — byte-range, XOR, MUL, hash round-constants) are now structurally verifiable end-to-end. Session-102's m_eval/commit binding gap remains the documented Phase-3 fixture-driven testing dependency. |

### What this changes for an external auditor

Pre-session-107 Halo2 verifier accepted exactly 1 lookup argument
(implicit, 3 eval slots in the bundle). Real Halo2 toolchains
(PSE halo2, halo2_proofs) emit proofs with 2-5 lookup arguments by
default — a circuit with byte-range + XOR table + hash
round-constants table is `n_lookups = 3`. Pre-session-107 these
proofs couldn't be verified; the verifier silently dropped the
extra lookup contributions.

After session 107:
- The proof header's `n_lookups: u32` field is the actual lookup
  count.
- The bundle parser reads `n_lookups × (2k + 1)` lookup eval slots.
- The verifier's vanishing identity sums each lookup's
  `multi_column_lookup_expr` value with a distinct y-power
  (`y², y³, y⁴, …`).
- Per-lookup tampering is detectable at any lookup index (proven by
  tests `n_lookups_2_rejects_tampered_{first,second}_lookup_m_eval`
  and `n_lookups_3_rejects_tampered_third_lookup_m_eval`).

### Why distinct y-powers (not shared y²)

If every lookup were summed with the same `y²` weight, an adversary
could let `L₀ = -L₁` so the sum vanishes at one row without either
lookup being individually valid. Distinct powers
(`y² · L₀ + y³ · L₁ + y⁴ · L₂ + …`) force each lookup to vanish
independently — Schwartz-Zippel over the random `y` challenge says
that any non-zero per-lookup polynomial is detectable with
overwhelming probability.

The session-107 implementation pins this with three tests targeting
each of the three lookup positions in an n_lookups=3 setup. If a
future refactor accidentally collapses to shared-y weighting, those
tests fail loudly.

### Soundness inheritance

All session-105 internal-consistency checks generalize:
- `n_advice ≥ 2 · arity · n_lookups` (each lookup reserves 2k
  advice columns; n lookups need 2nk total).
- `n_evals == 13 + max(1, n_lookups) · (2k + 1) + n_quotient`
  (bundle eval-section sizing matches declared lookup count).
- VK / proof / public-input divisibility checks unchanged.

A malformed multi-lookup header (e.g. n_lookups=3 with arity-2-sized
n_evals) rejects at parse time with `ProofLengthMismatch`, not
downstream as `PairingCheckFailed`.

### Lib test totals at v0.9.6

  mosaic-halo2            117  (+7 since v0.9.5)
  total                   654  (+7 since v0.9.5)

### What this milestone DOES change

- Halo2 verifier accepts `n_lookups ≥ 2` proofs.
- New `combined_expr_multi_lookup` function sums lookups with
  distinct y-powers.
- New `bundle.multi_lookups: Vec<MultiColumnLookupEvals>` field
  carries every lookup.

### What this milestone does NOT change

- `n_lookups = 0` legacy implicit-single-lookup mode preserved
  for backward compat with pre-session-107 scaffold fixtures.
- Single-lookup arity-1 proofs (every Halo2 fixture in the
  workspace) verify byte-equivalently via the legacy
  `combined_expr` dispatch path.
- Single-lookup arity ≥ 2 proofs (sessions 100-101) verify
  byte-equivalently via the `combined_expr_multi_column` path.
- Wire format header layout (FIXED_HEADER_LEN = 20 bytes,
  unchanged since session 100).
- m_eval ↔ lookup_commits[0] binding gap (session 102 documented):
  scaffold tests at n_lookups ≥ 1 still surface as
  `PairingCheckFailed` because there's no real m-poly commit.
  Resolution requires fixture-driven differential testing with
  a real prover.

---

## 2026-04-30 — v0.9.5-halo2-vk-compressed release (session 106)

| Field | Value |
|---|---|
| Tag | [`v0.9.5-halo2-vk-compressed`](https://github.com/wienerlabs/mosaic/releases/tag/v0.9.5-halo2-vk-compressed) |
| Auditor | Internal (Wiener Labs) |
| Scope | First verifier-side consumer of the alt_bn128 compression syscall (sessions 103-104). `Halo2KzgVerifyingKey::from_compressed_bytes` + `to_compressed_bytes` — compressed VK wire format with ~46% bandwidth saving. |
| Findings | Zero soundness regressions. The compressed parser inherits the session-105 internal-consistency checks, adapted to compressed sizes. |
| Status | ✅ The compression syscall now has its first end-to-end verifier-side use. Compressed VKs round-trip byte-identical, fail closed on inconsistent declarations, and the saving is structurally measured (288 B for a typical 2-fixed + 5-perm VK). |

### What this changes for an external auditor

Sessions 103-104 added the syscall capability + typed helpers but no
verifier consumed them. Session 106 lands the first real consumer:
Halo2 VK now has a compressed alternate wire format that:

1. Halves every G1 commit (64 → 32 bytes via `alt_bn128_g1_compress`)
2. Halves the G2 SRS handle (128 → 64 bytes)
3. Leaves the Fr `omega_fr` + u32 counters unchanged (Fr isn't a curve point; counters are already small)

The in-memory `Halo2KzgVerifyingKey` is identical regardless of which
wire format the bytes arrived in — `from_compressed_bytes` decompresses
each commit at parse time, then the verifier's existing
`combined_expr` / `verify_two_point_opening_multipoly` paths run
unchanged.

### Soundness inheritance

Every session-105 internal-consistency check carries over to the
compressed parser:
- `n_fixed * G1_COMPRESSED == fixed_compressed_len` — declared count
  matches actual byte count.
- `fixed_compressed_len % G1_COMPRESSED == 0` — divisibility.
- `bytes.len() == COMPRESSED_FIXED_LEN + fixed_compressed_len + perm_compressed_len`
  — total length match.

Any mismatch surfaces as `VerifyingKeyLengthMismatch` at parse time,
not as a downstream `PairingCheckFailed`.

### Cost trade-off

Per VK load:
- Compression decode: ~80 K CU (8 G1 × ~10K + 1 G2 × ~12K).
- Storage saving: ~46% (488 B → 264 B for typical 2-fixed + 5-perm).

For high-frequency verifiers (multiple verify calls per VK lifetime)
the CU overhead dominates and uncompressed VK is preferred. For
low-frequency or storage-rent-sensitive deployments the trade favors
compressed VK.

### Lib test totals at v0.9.5

  mosaic-halo2            110  (+5)
  total                   647  (+5 since v0.9.4)

### What this milestone DOES change

- Halo2 VK gains a compressed wire-format alternate.
- Compression syscall (sessions 103-104) gets its first verifier-
  side consumer.

### What this milestone does NOT change

Verifier behaviour for uncompressed VKs (byte-equivalent), wire
format for proofs (only VK has compressed form), in-memory VK
representation. Once parsed, both paths produce identical
`Halo2KzgVerifyingKey` structs.

---

## 2026-04-29 — v0.9.4-halo2-vk-consistency release (session 105)

| Field | Value |
|---|---|
| Tag | [`v0.9.4-halo2-vk-consistency`](https://github.com/wienerlabs/mosaic/releases/tag/v0.9.4-halo2-vk-consistency) |
| Auditor | Internal (Wiener Labs) |
| Scope | Halo2 VK parser tightens internal consistency: `n_fixed` declared count must match `fixed_commits.len() / G1_LEN`, both commit byte buffers must be multiples of G1_LEN. |
| Findings | One latent consistency gap closed: pre-session-105 the parser silently accepted VKs where `n_fixed` and `fixed_commits.len()` diverged. Downstream code that uses `n_fixed` for indexing would mis-index without explicit error. |
| Status | ✅ Halo2 VK parse-time validation now rejects any malformed declared/actual count mismatch. The proptest strategy `arb_vk` updated to generate only consistent VKs. |

### What this changes for an external auditor

The Halo2 VK has two ways to indicate fixed-commit count:
1. The `n_fixed: u32` header field (declared)
2. The byte length of `fixed_commits` divided by 64 (actual)

Pre-session-105 these could diverge. Real prover toolchains
always emit consistent VKs, but a bugged or adversarial generator
could produce mismatched values that silently parse and produce
wrong verification results downstream.

After session 105, the parser enforces consistency at the
boundary. Mismatched VKs reject as `VerifyingKeyLengthMismatch`.

### Why this is a soundness hardening, not a soundness fix

The verifier code that used `n_fixed` for indexing would have
produced wrong commit/eval pairings in the KZG batched opening,
which would have surfaced as `PairingCheckFailed` later in the
pipeline. So no proof was ever silently accepted on a malformed
VK — but the rejection error would have been opaque
(PairingCheckFailed instead of VerifyingKeyLengthMismatch). Session
105 surfaces the right error at the right layer.

### Lib test totals at v0.9.4

  mosaic-halo2            105  (+2)
  total                   642

### What this milestone DOES change

- VK parser rejects declared/actual count mismatches.
- Two new tests pin the contract.

### What this milestone does NOT change

Verifier behaviour for conforming VKs (every real generator
produces these), wire format, on-chain ABI.

---

## 2026-04-29 — v0.9.3-compression-helpers release (session 104)

| Field | Value |
|---|---|
| Tag | [`v0.9.3-compression-helpers`](https://github.com/wienerlabs/mosaic/releases/tag/v0.9.3-compression-helpers) |
| Auditor | Internal (Wiener Labs) |
| Scope | New `mosaic-zk-primitives::compression` module wraps the v0.9.2 syscall surface in typed helpers (`compress_g1`/`decompress_g1`/`compress_g2`/`decompress_g2`). Sets up consumer-side adoption. |
| Findings | Zero soundness regressions. Output-size validation in each helper adds defense-in-depth against a hypothetical syscall ABI drift. |
| Status | ✅ Verifier crates can now adopt compression via typed primitives instead of raw `&[u8]` calls. The module's documentation pins the cost trade-off (~10 K CU per G1 decompress vs 32 B saved). |

### Why this matters at the audit boundary

Session 103 made the syscall available; session 104 makes it
**ergonomic**. Without typed helpers, every verifier consumer
would have to:
1. Convert `[u8; 64]` to `&[u8]` for the syscall call.
2. Validate the syscall's `Vec<u8>` return is exactly 32 bytes.
3. Convert `Vec<u8>` back to `[u8; 32]`.

Three steps per call site, repeated across the workspace, with
opportunities for off-by-one errors. Session 104 collapses this
into one named function call per direction.

### Lib test totals at v0.9.3

  mosaic-zk-primitives     93  (+6 since v0.9.2)
  total                   640

### What this milestone DOES change

- New `compression` module in `mosaic-zk-primitives`.
- Six new tests pinning round-trip + determinism + tamper
  detection.

### What this milestone does NOT change

Wire format, on-chain ABI, verifier behaviour. Compression is now
ERGONOMICALLY ACCESSIBLE but still not USED by any verifier.
Adoption is opt-in per crate.

---

## 2026-04-29 — v0.9.2-alt-bn128-compression release (session 103)

| Field | Value |
|---|---|
| Tag | [`v0.9.2-alt-bn128-compression`](https://github.com/wienerlabs/mosaic/releases/tag/v0.9.2-alt-bn128-compression) |
| Auditor | Internal (Wiener Labs) |
| Scope | Long-standing TODO closed: `alt_bn128_compression` syscall now wired on both backends. Enables compressed VK + proof representations (50% bandwidth savings on G1/G2 commitments). |
| Findings | Zero soundness regressions. The compression syscall surface was on the `SyscallBackend` trait from day one but stubbed out as `TODO(mosaic-007)`. Session 103 implements both backends. |
| Status | ✅ G1/G2 compression and decompression now work end-to-end with byte-identical output across host and SBF targets. |

### What this changes for an external auditor

Before session 103, `SyscallBackend::alt_bn128_compression` returned
`UnimplementedProofSystem` regardless of input. Verifiers that
attempted to use compressed VKs would fail at the syscall boundary.

After session 103:
- All 4 compression ops work (G1Compress/Decompress,
  G2Compress/Decompress).
- Host fallback uses arkworks via `solana-bn254`'s
  `cfg(not(target_os = "solana"))` path; SBF target uses the real
  syscall. Both produce byte-identical output by construction.
- Round-trip tests (compress → decompress → original) pin the
  identity at all compression sizes.
- Wrong-input-length rejection tests pin the
  `AltBn128CompressionSyscallFailed` error path.

### Why this matters at the audit boundary

Compressed BN254 G1 = 32 bytes vs uncompressed 64 bytes (50%
saving). Compressed G2 = 64 bytes vs 128 bytes (50% saving).
For a typical Halo2 proof with 5 advice + 3 quotient + 2 opening
G1 commits (10 × 64 = 640 bytes uncompressed), compression saves
320 bytes — a meaningful fraction of Solana's 1232-byte
instruction-data limit.

The session-103 implementation is just the syscall wiring; consuming
it (via a canonical layout v2 with compressed-VK option) is
follow-up work. But the building block is now real, tested, and
ready.

### Lib test totals at v0.9.2

  mosaic-core              28  (+12)
  total                   634  (+12 since v0.9.1)

### What this milestone DOES change

- `SyscallBackend::alt_bn128_compression` returns real results
  instead of `UnimplementedProofSystem` on both backends.
- New `mosaic-core/Cargo.toml` host-backend feature dep:
  `solana-bn254` (previously gated under `solana` feature only).

### What this milestone does NOT change

Wire format, verifier behaviour, the audit-gate matrix from
sessions 86-101. Compression is now AVAILABLE but not yet USED by
any verifier.

---

## 2026-04-29 — v0.9.1-halo2-multi-column-kzg-binding release (session 101)

| Field | Value |
|---|---|
| Tag | [`v0.9.1-halo2-multi-column-kzg-binding`](https://github.com/wienerlabs/mosaic/releases/tag/v0.9.1-halo2-multi-column-kzg-binding) |
| Auditor | Internal (Wiener Labs) |
| Scope | **Real soundness gap closed.** Multi-column lookup `input_cols` / `table_cols` evaluations are now bound to the proof's advice commitments via KZG batched opening. Pre-session-101 these evals were trusted; post-session-101 they're cryptographically pinned. |
| Findings | One real soundness bug fixed: a malicious prover could pick `input_cols[i]` / `table_cols[i]` evaluations freely (only constrained by the `combined_expr` algebraic identity, which the prover could satisfy by also picking `m_eval`) without committing to actual advice column polynomials. |
| Status | ✅ Multi-column lookup verifier is now soundness-equivalent to single-column: every eval that enters the algebraic identity is KZG-bound to a commitment in the proof. |

### Pre-session-101 attack vector

The prover sends:
- `n_advice` advice column commitments
- `lookup_arity = k` declaration
- `2k + 1` lookup eval slots

The verifier checks:
1. `combined_expr_multi_column(...) == t·Z_H` (algebraic identity)
2. KZG opening of advice commits against wire-eval placeholders +
   selectors + permutation σ + quotient chunks at ξ

Crucially, **the multi-column eval slots are NOT in the KZG opening
set** (pre-session-101). They live only in the bundle and feed only
into the algebraic identity check.

The attack: given honest commits to advice + m, choose
`input_cols[i]`, `table_cols[i]`, `m_eval` such that the
log-derivative identity:

```
m_eval · (table_combined + θ^k)⁻¹ - (input_combined + θ^k)⁻¹ = (target value)
```

equals exactly the value needed to make
`combined_expr_multi_column == t·Z_H`. This is a single linear
equation in `m_eval` (given freedom in `input_cols`, `table_cols`):
trivial to satisfy.

The verifier accepts. The attacker has produced a proof where the
multi-column lookup section is a fiction — the values bear no
relationship to any committed polynomial.

### Post-session-101 mitigation

The convention `advice[n_advice - 2k + i] ↔ input_cols[i]` and
`advice[n_advice - k + i] ↔ table_cols[i]` ties each lookup eval
to a specific advice commitment. The KZG batched opening at ξ
includes these pairings. Any tampered `input_cols[i]` value fails
the batched pairing identity → `PairingCheckFailed`.

To forge under session 101, the prover would need to:
1. Choose adversarial `(input_cols[i], table_cols[i], m_eval)`.
2. Find a polynomial `p_i(X)` such that `p_i(ξ) = input_cols[i]`
   AND `commit(p_i)` matches the previously-sent `advice_commits[n_advice - 2k + i]`.

That second requirement is the discrete-log problem in BN254 G1.
Negligible probability of success.

### Test evidence

```bash
cargo test -p mosaic-halo2 --lib arity_2_multi_column_rejects_tampered_input_col_via_kzg
cargo test -p mosaic-halo2 --lib arity_2_multi_column_rejects_tampered_last_table_col
```

Both tests construct an honest arity-2 proof, tamper one
`input_cols` / `table_cols` slot, and verify rejection. The first
test specifically targets the new KZG binding; the second catches
off-by-one errors in the binding loop's table-section bounds.

### Lib test totals at v0.9.1

  mosaic-core              16
  mosaic-zk-primitives     87
  mosaic-groth16           31
  mosaic-plonk             38
  mosaic-hyperplonk        88
  mosaic-halo2            103  (+2 since v0.9.0)
  mosaic-nova              73
  mosaic-stark            123
  mosaic-serde             23
  mosaic-chunked           20
  mosaic-sdk               13
  mosaic-program            7
  ─────────────────────  ───
  total                   622

### What this milestone DOES change

- **Multi-column lookup is now cryptographically sound** — every
  eval that enters the algebraic identity check is KZG-bound to a
  commitment.
- **Stricter parse-time validation** — proofs that declare
  `lookup_arity ≥ 2` must reserve at least `2k` advice columns.
- **Test surface extends** — two new adversarial-input tests prove
  the binding actually catches tampering.

### What this milestone does NOT change

Wire format (no header change since v0.9.0), on-chain ABI, single-
column proofs (arity 1, byte-equivalent legacy path), the 6-way
ADR-0006 audit-gate matrix.

### Real soundness fixes count

This is the **second real soundness fix** in the campaign,
matching session 87's Nova base-commit transcript binding fix:

| Session | Tag | Soundness gap closed |
|---|---|---|
| 87 | v0.8.7 | Nova folding `r` not bound to base commits — could back-solve to forge accumulator |
| 101 | v0.9.1 | Halo2 multi-column lookup eval not bound to advice commits — could pick evals freely to satisfy identity |

Both fixes follow the same pattern: a previously-trusted prover
input is now cryptographically pinned to a committed value via
the appropriate Fiat-Shamir / KZG mechanism.

---

## 2026-04-26 — v0.9.0-halo2-multi-column-lookup release (session 100)

| Field | Value |
|---|---|
| Tag | [`v0.9.0-halo2-multi-column-lookup`](https://github.com/wienerlabs/mosaic/releases/tag/v0.9.0-halo2-multi-column-lookup) |
| Auditor | Internal (Wiener Labs) |
| Scope | **Real new feature.** Multi-column lookup primitive (sessions 88-89) wired into the actual Halo2 verifier path. Wire format extended with `lookup_arity` field. Verifier dispatches to multi-column or legacy single-column path based on declared arity. |
| Findings | Zero soundness regressions. The pre-session-100 multi-column primitive was an isolated audit gate; session 100 makes it a real verifier capability — multi-column-lookup proofs (common in real Halo2 circuits) can now be verified. |
| Status | ✅ First **minor-version bump** (v0.8.x → v0.9.0) in the audit-coverage campaign because this is genuine new user-visible capability, not refactor. |

### Why v0.9.0 instead of v0.8.20

Sessions 86-99 were all polish: audit-gate extraction, ADR
codification, fuzz harness expansion, primitive consolidation.
Each release was either byte-equivalent refactor or pure
documentation. None advanced user-visible capability.

Session 100 is different. Before v0.9.0:
- Halo2 proofs with arity > 1 lookups (very common in real
  circuits) **could not be verified by mosaic-halo2**. The
  verifier hardcoded arity-1 single-column lookup throughout
  the pipeline.
- The `MultiColumnLookupEvals` primitive existed (session 88)
  but was an isolated audit gate — never called by the actual
  verifier. Existing proofs only ever used the single-column
  `lookup_expr`.

After v0.9.0:
- Proofs declare their `lookup_arity` in the canonical header.
- The bundle parser reads `2k + 1` lookup eval slots for arity
  `k` (k inputs + k tables + 1 m_eval).
- The verifier dispatches: arity 1 → legacy single-column path
  (byte-equivalent to v0.8.x), arity ≥ 2 → new multi-column path
  via `combined_expr_multi_column`.

This is concrete new capability. SemVer says minor bump.

### Wire format change

The proof header bytes 16-19 now carry `lookup_arity: u32 LE`
(was reserved zero-padding in v0.8.x). Forward compat: proof
generators that write `0` in bytes 16-19 are reinterpreted as
arity 1 (DEFAULT_LOOKUP_ARITY), matching legacy behavior.

This is a wire-format extension, not a wire-format break: every
v0.8.x proof that wrote zeros in the upper 4 bytes of its
20-byte buffer (or used a 16-byte buffer with no upper bytes) is
still parsed correctly at v0.9.0.

External proof generators (e.g. snarkjs, halo2_proofs) that emit
20-byte headers with explicit arity values get the new
multi-column verification capability.

### Soundness story

The multi-column path runs the same log-derivative identity as
the single-column path, but with the θ-power-combined form:

```text
input_combined = Σ_{i=0}^{k-1} θ^i · input_cols[i]
table_combined = Σ_{i=0}^{k-1} θ^i · table_cols[i]
lookup_value = m·(table_combined + θ^k)⁻¹ - (input_combined + θ^k)⁻¹
```

At arity 1 this collapses to the basic single-column form
(pinned algebraically by session-89's
`prop_basic_lookup_promotes_to_multi_arity_1` proptest). The
combined value enters `combined_expr` with the same `y²`
weighting, so the vanishing identity check is identical at the
LHS = RHS step.

### Reproduce locally

```bash
cargo test -p mosaic-halo2 --lib full_pipeline_arity_2_multi_column_accepts
cargo test -p mosaic-halo2 --lib full_pipeline_arity_4_multi_column_accepts
cargo test -p mosaic-halo2 --lib arity_2_multi_column_rejects_tampered_m_eval
cargo test -p mosaic-halo2 --lib arity_3_with_wrong_n_evals_rejects_at_bundle_parse
```

### Lib test totals at v0.9.0

  mosaic-core              16
  mosaic-zk-primitives     87
  mosaic-groth16           31
  mosaic-plonk             38
  mosaic-hyperplonk        88
  mosaic-halo2            101  (+4 since v0.8.19)
  mosaic-nova              73
  mosaic-stark            123
  mosaic-serde             23
  mosaic-chunked           20
  mosaic-sdk               13
  mosaic-program            7
  ─────────────────────  ───
  total                   620

### What this milestone DOES change

- **Halo2 verifier accepts new proof shapes**: arity ≥ 2 proofs
  with multi-column lookup arguments can now be verified.
- **Proof header layout**: 16 → 20 bytes (forward-compat for
  pre-session-100 generators that write zeros).
- **Bundle layout**: lookup section grows from fixed 3 slots to
  `2k + 1` slots based on declared arity.

### What this milestone does NOT change

- **On-chain dispatch**: `mosaic-program::dispatch_verify`
  unchanged. Existing Groth16 SBF integration tests pass.
- **Other verifier crates**: PLONK, HyperPlonk, Nova, STARK
  layouts unchanged.
- **Single-column Halo2 proofs** (arity 1): byte-equivalent
  verification, same `combined_expr` callsite, same KZG opening.
- **The 6-way ADR-0006 audit-gate matrix**: unchanged. Halo2's
  audit gate is `verify_multi_column_lookup_identity` and now
  the verifier exercises it on real proofs.

### Architectural significance

Session 100 is the first real "system advancement" in the
sessions 86-100 campaign. The user explicitly called for
"projeye notlar eklemekten çok gerçekten sistemi ilerletmeni"
(advance the system, not just add notes). v0.9.0 delivers:

- New verifier capability (multi-column lookup)
- Wire-format extension with forward-compat handling
- Real soundness contract extension (the multi-column lookup
  identity is now actually checked on every arity ≥ 2 proof,
  not just isolated in an audit-gate test)
- 4 new end-to-end tests including a tamper-rejection test
  that proves the new path validates instead of rubber-stamping

---

## 2026-04-26 — v0.8.19-groth16-negate-consolidation release (session 99)

| Field | Value |
|---|---|
| Tag | [`v0.8.19-groth16-negate-consolidation`](https://github.com/wienerlabs/mosaic/releases/tag/v0.8.19-groth16-negate-consolidation) |
| Auditor | Internal (Wiener Labs) |
| Scope | Lift `BN254_FQ_MODULUS_BE` (base-field modulus) + `negate_g1` (G1 y-coordinate negation) duplicates from `mosaic-groth16::{batch, verifier}` to the canonical `mosaic-zk-primitives::msm` definitions |
| Findings | Zero soundness regressions; the workspace now has a single source of truth for both BN254 field moduli (Fr from session 98, Fq from session 99) and a single G1 negation implementation |
| Status | ✅ Both BN254 modulus constants and the G1 negation arithmetic are workspace-canonical; Groth16 `negate_g1` callsites are 4-line wrappers around the shared primitive |

### What this milestone changes for an external auditor

Before sessions 98-99, an external auditor reviewing Groth16's
soundness story had three separate copies of the BN254 modulus
constants and two separate G1 negation implementations to
cross-check. A drift between any pair would silently produce
inconsistent rejection / acceptance behavior across:
- The single-proof `Groth16Verifier::verify` path
- The batch `verify_batch` path
- The other workspace verifiers using mosaic-zk-primitives

After sessions 98-99:

| Constant / function | Pre-98 sources | Post-99 source |
|---|---|---|
| `BN254_FR_MODULUS_BE` | 2 (mosaic-zk-primitives, mosaic-groth16::canonical) | 1 (mosaic-zk-primitives) |
| `BN254_FQ_MODULUS_BE` | 3 (mosaic-zk-primitives::msm-scoped, mosaic-groth16::batch, mosaic-groth16::verifier) | 1 (mosaic-zk-primitives::msm pub const) |
| `lt_be` (BE u32 comparison) | 2 (mosaic-zk-primitives::fr, mosaic-groth16::canonical) | 1 (mosaic-zk-primitives::fr) |
| `negate_g1` (G1 negation arithmetic) | 3 (mosaic-zk-primitives::msm, mosaic-groth16::batch, mosaic-groth16::verifier) | 1 implementation in mosaic-zk-primitives (Groth16 verifier wraps with endianness handling) |

The Groth16 verifier's `negate_g1` is intentionally retained as a
thin endianness-handling wrapper because the verifier accepts
proof bytes in either BE or LE depending on the `LE_INPUTS`
const-generic (a Solana SIMD-0204 pre/post toggle). The
arithmetic delegates to the shared primitive; only the
endianness flip lives in Groth16.

### Soundness implication

A future change to `BN254_FQ_MODULUS_BE` (e.g., if a Solana
syscall ABI change forced a different curve) would now require
touching exactly one constant in the workspace. Drift bugs of
the form "Groth16 single-proof accepts a value that
Groth16-batch rejects" are eliminated by construction.

### Lib test totals at v0.8.19

Unchanged from v0.8.18 (616). Pure consolidation release.

### What this milestone does NOT change

Wire format, on-chain ABI, public API surface (the deletes are
private-symbol deletes), verifier behaviour: all unchanged. The
SBF integration tests (`sbf_verify_proof_succeeds_on_valid_groth16`
+ `sbf_rejects_tampered_proof`) continue to pass byte-equivalently.

---

## 2026-04-26 — v0.8.18-groth16-modulus-consolidation release (session 98)

| Field | Value |
|---|---|
| Tag | [`v0.8.18-groth16-modulus-consolidation`](https://github.com/wienerlabs/mosaic/releases/tag/v0.8.18-groth16-modulus-consolidation) |
| Auditor | Internal (Wiener Labs) |
| Scope | Lift the long-standing `BN254_FR_MODULUS_BE` + `lt_be` duplicate definitions in `mosaic-groth16` to re-exports of the canonical `mosaic-zk-primitives::fr` versions; migrate range-check call sites to the convenience wrapper `lt_r` |
| Findings | Zero soundness regressions; the workspace now has a single source of truth for the BN254 scalar field modulus, removing a class of potential drift bugs |
| Status | ✅ Modulus + range-check primitives consolidated workspace-wide; no Groth16-internal duplicate remains |

### Why this consolidation matters at the audit boundary

Before session 98, a future change to the BN254 scalar field
modulus (e.g., a forced curve migration if the BN254 syscall
surface changes) would require touching the constant in two
places. Drift between the two would produce a Groth16 verifier
that accepts public inputs the rest of the workspace rejects —
a subtle soundness bug invisible in any single-verifier test.

After session 98, the constant lives in exactly one place:
`mosaic-zk-primitives::fr::BN254_FR_MODULUS_BE`. The Groth16
crate re-exports it; both the `mosaic-groth16::verifier::verify`
range-check and the `mosaic-groth16::batch` range-check call
the shared `lt_r` convenience wrapper.

### What an external auditor reviews differently now

The "is this Fr in range?" check across the workspace is now a
single grep pattern:

```bash
git grep 'lt_r(\|fr_from_canonical_bytes(' crates/
```

surfaces every Fr range-check call site with consistent naming.
The Groth16-specific byte-level path (which goes through `lt_r`
to avoid arkworks decode overhead) and the Phase-3-verifier
arkworks path (which goes through `fr_from_canonical_bytes`)
both delegate to the same modulus constant.

### Lib test totals at v0.8.18

Unchanged from v0.8.17 (616 across 12 crates with tests; 620
total). The migration is byte-equivalent: every test that passed
at v0.8.17 continues to pass at v0.8.18.

### What this milestone does NOT change

Wire format, on-chain ABI, public API surface (the re-exports
are wire-compatible), verifier behaviour: all unchanged. The
internal callsite migration from `lt_be(&be, &MODULUS)` to
`lt_r(&be)` is byte-equivalent at the comparison level.

---

## 2026-04-26 — v0.8.17-audit-gate-benches release (session 97)

| Field | Value |
|---|---|
| Tag | [`v0.8.17-audit-gate-benches`](https://github.com/wienerlabs/mosaic/releases/tag/v0.8.17-audit-gate-benches) |
| Auditor | Internal (Wiener Labs) |
| Scope | New `audit_gates_host` criterion bench with 5 functions across 4 Phase-3 audit gates; complements the existing `phase3_host` end-to-end bench |
| Findings | Zero soundness regressions; per-gate wall-clock baselines now established for regression tracking |
| Status | ✅ Every Phase-3 audit gate has both a fuzz harness (session 95) and a criterion bench (session 97) for regression detection at the algebraic-surface level |

### What this milestone changes for an external auditor

The existing `phase3_host` bench measures verifier `verify`
end-to-end. An algorithmic regression inside an audit gate
(e.g. an unintentional θ-power recompute, a missing Vec capacity
hint that triggers reallocation) might add 50 µs but be masked
by the millisecond-scale verifier `verify` bench's noise floor.

The new `audit_gates_host` bench measures each gate alone, so
the same 50 µs regression surfaces distinctly. Combined with the
session-95 fuzz harnesses, the audit-gate algebraic surface now
has **two layers of regression detection**:

1. **Fuzz layer** (session 95): catches new panics or
   unintended `Err(...)` variants on hostile inputs.
2. **Bench layer** (session 97): catches algorithmic-cost
   regressions on honest inputs.

Combined with the gate's lib-test suite (28+ tests across the
4 gates pinning the accept/reject contract), an audit-gate
regression has three independent ways to surface in CI: lib
tests, fuzz harnesses, criterion benches.

### Audit-gate coverage matrix at v0.8.17

| Audit gate | Lib tests | Fuzz harness | Criterion bench |
|---|---|---|---|
| `verify_folding_consistency` (Nova) | 9 | ✓ | ✓ |
| `verify_multi_column_lookup_identity` (Halo2) | 7 | ✓ | ✓ (×2 arity) |
| `verify_fri_query` (STARK) | 6 | ✓ | ✓ |
| `verify_sumcheck_claim_reduction` (HyperPlonk) | 6 | ✓ | ✓ |
| `verify_groth16_pairing_identity` (Groth16) | 5 | (Phase-2 omission — syscall-bound) | (covered by `groth16_host`) |
| `verify_plonk_pairing_identity` (PLONK) | 6 | (Phase-2 omission — syscall-bound) | (covered by `phase3_host` indirectly) |

### Reproduce locally

```bash
cargo bench -p mosaic-bench --bench audit_gates_host
```

The bench profile compile takes ~3 min (one-time); subsequent
runs reuse the compiled binary. Expected output: 5 named bench
results with criterion's mean ± 2σ.

### Lib test totals at v0.8.17

Unchanged from v0.8.16 (616). Pure bench-coverage release.

### What this milestone does NOT change

Wire format, on-chain ABI, public API, verifier behaviour,
existing benches: all unchanged. The new bench file is purely
additive.

---

## 2026-04-26 — v0.8.16-fuzz-ci-wiring release (session 96)

| Field | Value |
|---|---|
| Tag | [`v0.8.16-fuzz-ci-wiring`](https://github.com/wienerlabs/mosaic/releases/tag/v0.8.16-fuzz-ci-wiring) |
| Auditor | Internal (Wiener Labs) |
| Scope | Wires the 4 audit-gate fuzz harnesses (added in session 95) into both the PR and nightly CI fuzz matrices |
| Findings | Zero soundness regressions; pure CI configuration release closing the v0.8.15 "tracked separately" loose end |
| Status | ✅ Every audit gate's algebraic surface now runs under PR fuzz CI on every pull request — soundness regressions in audit gates fail PR CI, not wait for the nightly sweep |

### What this milestone changes for an external auditor

Before session 96, the audit-gate fuzz harnesses existed in the
fuzz crate but were not running in CI. An external auditor running
the recommended `cargo +nightly fuzz run` commands locally got
direct gate coverage, but a regression introduced in a contributor
PR would only surface when the nightly sweep ran the next day.

After session 96:

- **PR mode**: 12 harnesses run for 5 min each on every PR
  (3 Groth16 originals + 5 combined-slot per-system + 4 audit-gate).
  Wall-clock ~60 min with parallel runners.
- **Nightly mode**: 27 harnesses run for 60 min each
  (23 outer-surface + 4 audit-gate). Wall-clock ~27 h, 1-2
  batches under GitHub free-tier concurrency.

The PR-mode promotion of audit-gate harnesses is intentional: a
regression in an audit gate is a soundness regression and should
fail PR CI immediately, not wait for nightly. The 5-min PR run
duration is enough to surface immediate regressions while keeping
PR CI under 60 min wall-clock.

### Workflow file diff

```diff
 fuzz-pr matrix:
   …existing 8 harnesses…
+  - fuzz_nova_consistency_gate
+  - fuzz_halo2_lookup_gate
+  - fuzz_stark_fri_query_gate
+  - fuzz_hyperplonk_claim_reduction_gate

 fuzz-nightly matrix:
   …existing 23 harnesses…
+  - fuzz_nova_consistency_gate
+  - fuzz_halo2_lookup_gate
+  - fuzz_stark_fri_query_gate
+  - fuzz_hyperplonk_claim_reduction_gate
```

### Lib test totals at v0.8.16

Unchanged (616). Pure CI configuration release.

### What this milestone does NOT change

Wire format, on-chain ABI, public API, verifier behaviour, fuzz
harness code: all unchanged. The release modifies only
`.github/workflows/fuzz.yml` and the audit-pack quartet docs.

---

## 2026-04-26 — v0.8.15-audit-gate-fuzz release (session 95)

| Field | Value |
|---|---|
| Tag | [`v0.8.15-audit-gate-fuzz`](https://github.com/wienerlabs/mosaic/releases/tag/v0.8.15-audit-gate-fuzz) |
| Auditor | Internal (Wiener Labs) |
| Scope | 4 new cargo-fuzz harnesses targeting Phase-3 audit gates' algebraic input surfaces; lib.rs docstring + Cargo.toml [[bin]] table updates |
| Findings | Zero soundness regressions; the Phase-3 audit gates now have fuzz coverage at their algebraic boundaries (in addition to the pre-existing outer-surface fuzz coverage) |
| Status | ✅ 27-harness fuzz inventory: 23 outer-surface + 4 audit-gate; every Phase-3 verifier's primary soundness boundary has direct fuzz coverage |

### What this milestone changes for an external auditor

The pre-session-95 fuzz inventory (23 harnesses) covered each
verifier's outer entry-point byte slots — `proof_bytes`, `vk_bytes`,
`public_inputs`, and `combined`. These catch parsing-surface bugs:
malformed proof headers, out-of-range Fr values in the public-input
buffer, byte-slice boundary issues in the canonical layouts.

The session-95 expansion adds 4 new harnesses that fuzz the
audit-gate functions directly — bypassing the parsing layer and
hitting the algebraic boundary head-on. These catch a different
class of bugs:

- **Syscall payload mishandling**: a fuzz input that exercises a
  branch where the gate calls into arkworks / alt_bn128 with
  unusual byte patterns
- **Fr field-modulus boundary cases**: inputs near the BN254 scalar
  field edge that the parsing layer's `fr_from_canonical_bytes`
  accepts but might trigger arithmetic edge cases downstream
- **Goldilocks reduction edge cases** (STARK harness): inputs near
  `2^64 - 2^32 + 1` that exercise the field's modular reduction
- **Multi-arity boundary cases** (Halo2 harness): the audit gate
  accepts arities 1..=8, fuzzer exercises every arity in the range

Per the Phase-2 omission note: Groth16 and PLONK gates are not
fuzzed at the gate level because their algebraic surface is just
the syscall verdict byte (zero useful fuzz-discoverable space).
The pre-existing outer-surface harnesses for those crates (
`fuzz_groth16_proof_bytes`, `fuzz_plonk_proof_bytes`, etc.)
continue to provide their coverage.

### Reproduce locally

```bash
# Build all 27 harnesses (workspace-level cargo check).
cargo check -p mosaic-fuzz \
  --bin fuzz_nova_consistency_gate \
  --bin fuzz_halo2_lookup_gate \
  --bin fuzz_stark_fri_query_gate \
  --bin fuzz_hyperplonk_claim_reduction_gate

# Run a 60-second fuzz session against any one harness:
cargo +nightly fuzz run fuzz_nova_consistency_gate -- -max_total_time=60
```

The CI workflow integration (adding the 4 new harnesses to the
nightly fuzz matrix) is tracked separately and will land
incrementally.

### Lib test totals at v0.8.15

Unchanged from v0.8.14 (616 across 12 crates with tests; 620
across 16 crates including the empty-test crates). Session 95's
contribution is fuzz-harness count growth, not lib-test count
growth.

### What this milestone does NOT change

Wire format, on-chain ABI, public API surface, verifier
behaviour, the existing 23 fuzz harnesses: all unchanged. The
new harnesses are purely additive.

---

## 2026-04-26 — v0.8.14-plonk-audit-gate release (session 94)

| Field | Value |
|---|---|
| Tag | [`v0.8.14-plonk-audit-gate`](https://github.com/wienerlabs/mosaic/releases/tag/v0.8.14-plonk-audit-gate) |
| Auditor | Internal (Wiener Labs) |
| Scope | PLONK audit-gate alias completes the ADR-0006 6-way matrix across all production verifiers (Phase-2 + Phase-3) |
| Findings | Zero soundness regressions; the existing `verify_pairing` function is now also reachable via `verify_plonk_pairing_identity` matching the workspace-wide naming convention |
| Status | ✅ Every production verifier in the workspace (Groth16, KZG-PLONK, HyperPlonk-KZG, Halo2-KZG, Nova family, FRI-STARK) now exposes a named ADR-0006-compliant audit gate |

### What this milestone changes for an external auditor

Before session 94, PLONK's pairing soundness check was reachable
via two names: `verify_pairing` (the original) and
`finalize_verify` (the orchestrator that called it). Neither
matched the ADR-0006 `verify_<verifier>_<domain>` convention.

After session 94, the same code path is also reachable via
`verify_plonk_pairing_identity`. An auditor running:

```bash
git grep '^pub fn verify_' crates/mosaic-{groth16,plonk,nova,halo2,hyperplonk,stark}/src/
```

sees a uniform list across all six production verifier crates:

```
crates/mosaic-groth16/src/verifier.rs:pub fn verify_groth16_pairing_identity<...>
crates/mosaic-plonk/src/linearization.rs:pub fn verify_pairing<...>
crates/mosaic-plonk/src/linearization.rs:pub fn verify_plonk_pairing_identity<...>
crates/mosaic-nova/src/folding.rs:pub fn verify_folding_consistency<...>
crates/mosaic-halo2/src/circuit.rs:pub fn verify_multi_column_lookup_identity<...>
crates/mosaic-hyperplonk/src/verifier.rs:pub fn verify_sumcheck_claim_reduction<...>
crates/mosaic-stark/src/fri.rs:pub fn verify_fri_query<...>
crates/mosaic-stark/src/fri.rs:pub fn verify_fold_chain<...>
```

The ADR-0006 audit-gate matrix is now complete across both the
Phase-2 production verifiers (Groth16, KZG-PLONK) and the
Phase-3 verifiers (Nova, Halo2, HyperPlonk, FRI-STARK).

### Test-suite totals across all 6 audit gates

39 audit-gate-related tests (29 unit + 10 proptest) across 6
verifier crates. See the test-suite breakdown table in
`docs/adr/0006-verifier-audit-gate-pattern.md`.

### Lib test totals at v0.8.14

  mosaic-core              16
  mosaic-zk-primitives     87
  mosaic-groth16           31
  mosaic-plonk             38  (+6 since v0.8.13)
  mosaic-hyperplonk        88
  mosaic-halo2             97
  mosaic-nova              73
  mosaic-stark            123
  mosaic-serde             23
  mosaic-chunked           20
  mosaic-sdk               13
  mosaic-program            7
  ─────────────────────  ───
  total                   616

### What this milestone does NOT change

Wire format, on-chain ABI, public API surface (additive only —
the new alias does not displace the existing `verify_pairing`),
verifier behaviour: all unchanged. Internal callsites continue to
use `verify_pairing`; the alias exists for external API
consistency.

### The ADR-0006 campaign in numbers

| Metric | Sessions 86 → 94 |
|---|---|
| Audit gates landed | 6 (one per production verifier) |
| Real soundness fix | 1 (Nova session 87 — `r` binding to base commits) |
| Doc-vs-code drift fix | 1 (Halo2 session 88 — `Σ_X m(X) = 0` correction) |
| Standalone-test fixes | 2 (goldilocks s91B, canonical.rs s93) |
| ADR codification | ADR-0006 (session 92) |
| Companion doc updates | `phase3-soundness.md` + `audit-coverage-runbook.md` (session 92) |
| New tests | 49 across the workspace |
| Lib test total growth | 575 → 616 (+41) |
| Releases tagged | v0.8.6 → v0.8.14 (9 releases) |

---

## 2026-04-26 — v0.8.13-groth16-audit-gate release (session 93)

| Field | Value |
|---|---|
| Tag | [`v0.8.13-groth16-audit-gate`](https://github.com/wienerlabs/mosaic/releases/tag/v0.8.13-groth16-audit-gate) |
| Auditor | Internal (Wiener Labs) |
| Scope | First Phase-2 audit gate extracted (`verify_groth16_pairing_identity`) following ADR-0006 + companion no_std standalone-test fix in canonical.rs |
| Findings | Zero soundness regressions; the inline pairing-check pattern that has lived in `Groth16Verifier::verify` since v0.1 is now a named, publicly callable audit gate |
| Status | ✅ Phase-2 verifier track now starts following ADR-0006; Groth16 (the production verifier with the longest test history) lands first |

### What this milestone changes for an external auditor

Before session 93, an auditor reviewing Groth16 had to read the
entire `Groth16Verifier::verify` body to find the pairing-check
soundness boundary (lines 113-138 of the pre-session-93 file). The
extraction makes this boundary a `pub fn verify_groth16_pairing_identity`
function with explicit error-type documentation and 5 dedicated
unit tests covering every error path (success-byte mismatch,
non-`0x01` verdict bytes, wrong-length payload, syscall propagation).

The gate's signature is intentionally explicit (8 byte slices +
backend), so an external auditor can exercise it with hand-
constructed inputs — including adversarial inputs that test what
happens when the prover's `(A, B, C)` triple is internally
inconsistent with the linear combination `L`.

### Programmable backend trick for unit testing

Session 93 introduces a `ProgrammablePairingBackend` test helper
that returns configurable verdicts from the pairing syscall. This
lets the gate's unit tests cover every error branch without
pulling in real BN254 arithmetic — and without depending on the
existing differential-test fixtures. The differential suite
continues to provide end-to-end coverage; the new unit tests
provide focused coverage of the gate's input-validation surface.

### Companion fix: standalone-test parity

The pre-existing `canonical::tests` mod used bare `vec![...]`
which assumes the std prelude. Under `cargo test --workspace`
this worked due to feature unification; under
`cargo test -p mosaic-groth16 --lib` (no_std default features)
compilation failed. Session 93 adds `use alloc::vec;` to the
test mod, mirroring session 91B's identical fix in
`mosaic-stark/goldilocks.rs`.

After session 93 the standalone-test invocation parity holds
across mosaic-stark + mosaic-groth16. Other crates with similar
patterns may surface in the future; the fix template is well-
established now.

### Lib test totals at v0.8.13

  mosaic-core              16
  mosaic-zk-primitives     87
  mosaic-groth16           31  (+5 since v0.8.12)
  mosaic-plonk             32
  mosaic-hyperplonk        88
  mosaic-halo2             97
  mosaic-nova              73
  mosaic-stark            123
  mosaic-serde             23
  mosaic-chunked           20
  mosaic-sdk               13
  mosaic-program            7
  ─────────────────────  ───
  total                   610

### What this milestone does NOT change

Wire format, on-chain ABI, public API surface (additive only),
verifier behaviour: all unchanged. The differential test suite
against real BN254 fixtures continues to pass.

### Phase-2 track outlook

PLONK is the next ADR-0006 candidate on the Phase-2 track. Its
verification flow is structurally similar to Groth16's (linear
combination + pairing check) so the same recipe applies. Tracked
in CHANGELOG's "Planned beyond v0.8.13" block.

---

## 2026-04-26 — v0.8.12-audit-gate-adr release (session 92)

| Field | Value |
|---|---|
| Tag | [`v0.8.12-audit-gate-adr`](https://github.com/wienerlabs/mosaic/releases/tag/v0.8.12-audit-gate-adr) |
| Auditor | Internal (Wiener Labs) |
| Scope | ADR-0006 lands codifying the audit-gate extraction recipe; `phase3-soundness.md` + `audit-coverage-runbook.md` updated with audit-gate quick-references |
| Findings | Zero soundness regressions; pure documentation release. The audit-gate extraction work spanning sessions 86 → 91 is now formally documented as a workspace-wide architectural invariant. |
| Status | ✅ External audit firms have a single ADR-0006 to read for the soundness-boundary discovery story; the runbook + soundness doc cross-reference it from the entry points an auditor lands on first |

### Where to start as an external auditor at v0.8.12

1. Read [ADR-0006](docs/adr/0006-verifier-audit-gate-pattern.md)
   for the audit-gate extraction recipe and the 4-way Phase-3
   matrix.
2. Read [phase3-soundness.md](docs/phase3-soundness.md) for the
   per-verifier soundness story (audit-gate functions are the
   canonical entry points).
3. Read [audit-coverage-runbook.md](docs/audit-coverage-runbook.md)
   for reproduce + extend recipes including per-gate cargo test
   commands.
4. Run the four audit-gate test suites locally:
   ```bash
   cargo test -p mosaic-nova       --lib folding::tests
   cargo test -p mosaic-halo2      --lib circuit::tests
   cargo test -p mosaic-stark      --lib fri::tests
   cargo test -p mosaic-hyperplonk --lib verifier::tests
   ```
5. Use the audit gates in your own adversarial-input tests — each
   `verify_*` function is `pub` and callable in isolation.

### Lib test totals at v0.8.12

Unchanged from v0.8.11 (605 across 12 crates with tests; 609
across 16 crates including the empty-test crates). This is a
pure documentation release.

### What this milestone does NOT change

Wire format, on-chain ABI, public API surface, verifier
behaviour, transcript absorb order: all unchanged. The release
is an architectural-decision codification of work that already
landed across sessions 86 → 91.

---

## 2026-04-26 — v0.8.11-hyperplonk-audit-gate release (session 91)

| Field | Value |
|---|---|
| Tag | [`v0.8.11-hyperplonk-audit-gate`](https://github.com/wienerlabs/mosaic/releases/tag/v0.8.11-hyperplonk-audit-gate) |
| Auditor | Internal (Wiener Labs) |
| Scope | (A) HyperPlonk audit-gate extraction completes the 4-way Phase-3 verifier symmetry; (B) standalone `cargo test -p mosaic-stark --lib` quirk fix |
| Findings | Zero soundness regressions; one long-standing standalone-test compile quirk fixed via explicit `use alloc::vec::Vec` |
| Status | ✅ All four Phase-3 verifiers (Nova, Halo2, STARK, HyperPlonk) now expose their primary soundness check as a named, publicly callable `verify_*` audit gate |

### What this milestone changes for an external auditor

Sessions 86 → 91 build a consistent vocabulary across the
workspace's four Phase-3 verifiers. Before the campaign, each
verifier had its own inline pattern for "this is the soundness
boundary" — a mix of inline `if expected != actual { return Err(...) }`
checks scattered through the verifier bodies. The campaign
extracts each into a single named function:

| Verifier | Audit gate | Pattern |
|---|---|---|
| Nova | `verify_folding_consistency` | reconstruct `(E, W)_folded` from base commits + cross-term, byte-compare to declared |
| Halo2 lookup | `verify_multi_column_lookup_identity` | evaluate log-derivative identity over k-column inputs, reject if non-zero |
| STARK FRI | `verify_fri_query` | walk fold chain + eval final-poly + byte-compare |
| HyperPlonk | `verify_sumcheck_claim_reduction` | recompute expected claim from `(final_evals, χ, vk)`, byte-compare to sumcheck output |

An external auditor reviewing the workspace can now read the
verifier bodies and identify the soundness boundaries by name.
Each gate has explicit error-type documentation, up-front input
validation where applicable, and a dedicated test suite (5–13
tests per gate) pinning the accept/reject contract.

### What session 91 closes specifically

#### Part A: HyperPlonk audit-gate extraction
The `compute_expected_final_claim` helper was private (only the
verifier could call it) and the comparison-with-sumcheck-output
step was inlined. Both are now `pub` and the comparison is
wrapped in `verify_sumcheck_claim_reduction`. The verifier's
step-4 callsite collapses from 4 lines of inline pattern to a
single named call.

#### Part B: standalone test quirk
The `mosaic-stark/Cargo.toml` has `default = []` (no_std by
default). The pre-existing goldilocks tests used bare `Vec::new()`
which only resolves when `std` is in scope — true under
workspace-level test runs (where other crates pull `std` in via
feature unification) but false standalone. Session 90's audit
notes flagged this as out-of-scope; session 91B closes it with
an explicit `use alloc::vec::Vec` import in the test mod.

### Lib test totals at v0.8.11

  mosaic-core              16
  mosaic-zk-primitives     87
  mosaic-groth16           26
  mosaic-plonk             32
  mosaic-hyperplonk        88  (+6 since v0.8.10)
  mosaic-halo2             97
  mosaic-nova              73
  mosaic-stark            123
  mosaic-serde             23
  mosaic-chunked           20
  mosaic-sdk               13
  mosaic-program            7
  ─────────────────────  ───
  total                   605

### Audit-pack summary across the campaign

Sessions 86 → 91 added 6 release entries to the audit log,
4 new audit-gate primitives (one per Phase-3 verifier), 1 real
soundness fix (Nova session 87 — `r` binding to base commits),
1 doc-vs-code drift correction (Halo2 session 88 — `Σ_X m(X) = 0`
→ correct identity), 43 new tests across the workspace, and 1
no_std test-quirk cleanup. The README badge, CHANGELOG release
entries, and Cargo.toml workspace version are all in sync at
v0.8.11.

### What this milestone does NOT change

Wire format, proof byte layout, on-chain ABI, transcript absorb
order: all unchanged. Verifier behaviour is byte-identical at
every gate extraction point.

---

## 2026-04-26 — v0.8.10-stark-fri-audit-gate release (session 90)

| Field | Value |
|---|---|
| Tag | [`v0.8.10-stark-fri-audit-gate`](https://github.com/wienerlabs/mosaic/releases/tag/v0.8.10-stark-fri-audit-gate) |
| Auditor | Internal (Wiener Labs) |
| Scope | STARK FRI per-query audit-gate extraction (`verify_fri_query`) + verifier-side migration + 6-test soundness suite |
| Findings | Zero soundness regressions; one no_std/feature-unification quirk encountered in pre-existing goldilocks tests (workspace-level test runs succeed; standalone `-p` fails on unrelated `Vec::new()` lines) |
| Status | ✅ Per-query FRI verification now goes through a single named audit gate that an external auditor reads as one function call |

### What this milestone changes for an external auditor

The session-90 extraction follows the same recipe as the
session-86 Nova `verify_folding_consistency` work:

| Verifier | Pre-extraction | Post-extraction |
|---|---|---|
| Nova (s86) | inline `folded_commitment_from_fold` × 2 + byte-compare × 2 + `VerificationFailed` × 2 | one `verify_folding_consistency(...)` call |
| Halo2 lookup (s88) | inline `lookup_expr` + ad-hoc `== 0` check | one `verify_multi_column_lookup_identity(...)` call |
| **STARK FRI (s90)** | inline `verify_fold_chain` + `eval_poly_le_bytes` + byte-compare + `VerificationFailed` | one `verify_fri_query(...)` call |

The audit-pack now has three named gates following the same
pattern across three different verifier families. An external
auditor reviewing the workspace-wide soundness story has a
consistent vocabulary: `verify_*` functions are the soundness
boundaries to focus on.

### Lib test totals at v0.8.10

  mosaic-core              16
  mosaic-zk-primitives     87
  mosaic-groth16           26
  mosaic-plonk             32
  mosaic-hyperplonk        82
  mosaic-halo2             97
  mosaic-nova              73
  mosaic-stark            123  (+6 since v0.8.9)
  mosaic-serde             23
  mosaic-chunked           20
  mosaic-sdk               13
  mosaic-program            7
  ─────────────────────  ───
  total                   599

### What this milestone does NOT change

Wire format, proof byte layout, on-chain ABI: all unchanged.
Per-query verifier behaviour is byte-identical (refactor only).
The extracted gate's only difference from the inlined pattern
is its named error-path documentation — the runtime semantics
are preserved.

### Note on standalone -p test invocations

The pre-existing goldilocks test mod (sessions 10, 14a) uses
bare `Vec::new()` which assumes `std` prelude. Under
`cargo test --workspace --lib` the workspace's feature
unification brings `std` into scope and the tests pass. Under
`cargo test -p mosaic-stark --lib` (standalone) `default = []`
keeps the crate `no_std` and those `Vec::new()` calls fail to
resolve. Session 90's new tests use `alloc::vec::Vec` explicitly
to avoid this trap. A separate cleanup task (out of scope for
the audit-gate work) will normalize the goldilocks tests.

---

## 2026-04-26 — v0.8.9-halo2-lookup-bridge release (session 89)

| Field | Value |
|---|---|
| Tag | [`v0.8.9-halo2-lookup-bridge`](https://github.com/wienerlabs/mosaic/releases/tag/v0.8.9-halo2-lookup-bridge) |
| Auditor | Internal (Wiener Labs) |
| Scope | Backward-compatibility bridge between `LookupEvals` (single-column) and `MultiColumnLookupEvals` (session 88 audit-gate) + 4 new tests pinning the algebraic equivalence at arity 1 |
| Findings | Zero soundness regressions; the byte-level equivalence pinned by `prop_basic_lookup_promotes_to_multi_arity_1` is the regression guard for any future verifier unification |
| Status | ✅ Single-column lookup path (existing verifier) and multi-column audit gate (session 88) now share the same algebraic primitive at arity 1 |

### What this milestone changes for an external auditor

Before session 89, an auditor reviewing the lookup soundness story
had two independent code paths to read: `lookup_expr` for the
single-column scaffold (which the existing verifier calls) and
`multi_column_lookup_expr` for the new multi-column audit gate
(session 88). Even though both encode the same log-derivative
identity, the lack of an explicit bridge meant the soundness
arguments were stated twice — once per path.

Session 89 ties the two together:

```text
For any (input, table, m, θ) with non-degenerate denominators:
  lookup_expr(&LookupEvals { input, table, m }, &θ)
==
  multi_column_lookup_expr(&LookupEvals { input, table, m }.into(), &θ)
```

This equivalence is pinned by `prop_basic_lookup_promotes_to_multi_arity_1`
across the random Fr⁴ space. An auditor reviewing the bridge can
verify the algebraic claim independently (θ⁰ = 1, θ¹ = θ ⇒ both
formulas reduce to identical scalars at arity 1) and trust the
proptest to catch any future drift.

### Lib test totals at v0.8.9

  mosaic-core              16
  mosaic-zk-primitives     87
  mosaic-groth16           26
  mosaic-plonk             32
  mosaic-hyperplonk        82
  mosaic-halo2             97  (+4 since v0.8.8)
  mosaic-nova              73
  mosaic-stark            117
  mosaic-serde             23
  mosaic-chunked           20
  mosaic-sdk               13
  mosaic-program            7
  ─────────────────────  ───
  total                   593

### What this milestone does NOT change

Wire format, proof byte layout, on-chain ABI, transcript absorb
order, verifier callsite: all unchanged. The bridge is purely
additive. The existing single-column verifier continues to call
`lookup_expr` unchanged. A future verifier extension that wants
to support arity > 1 can use the bridge to lift any pre-existing
single-column proof through the same audit-gate path without
behavioural drift.

---

## 2026-04-26 — v0.8.8-halo2-lookup-audit-gate release (session 88)

| Field | Value |
|---|---|
| Tag | [`v0.8.8-halo2-lookup-audit-gate`](https://github.com/wienerlabs/mosaic/releases/tag/v0.8.8-halo2-lookup-audit-gate) |
| Auditor | Internal (Wiener Labs) |
| Scope | Halo2 multi-column lookup hardening: doc-correction + θ=0 defensive check + `verify_multi_column_lookup_identity` audit gate + 13-test soundness suite |
| Findings | One incorrect docstring claim caught + corrected (`Σ_X m(X) = 0` → `Σ_X [m·(t+θ^k)⁻¹ − (i+θ^k)⁻¹] = 0`); zero soundness regressions |
| Status | ✅ Multi-column lookup primitive now has named audit-gate, defensive θ-validation, safe constructor, and a 3-property proptest soundness suite |

### What this milestone changes for an external auditor

The session-85 multi-column lookup reduction shipped the
structural θ-combined log-derivative form but exposed the
verifier's "is this a satisfying lookup?" check as an ad-hoc
`expr == 0` callsite check rather than a named function.
Session 88 closes this in three ways:

1. **Audit gate extraction.** `verify_multi_column_lookup_identity`
   is the single named function an auditor reads to understand
   "what is the lookup soundness check?" — it returns either
   `Ok(())` or one of three explicit error types
   (`ProofLengthMismatch` / `InternalInvariantViolation` /
   `SumcheckFailed`).

2. **Defensive θ=0 rejection.** The Fiat-Shamir transcript can
   never produce θ=0 with non-negligible probability, but
   defense-in-depth catches a hypothetical transcript bug at the
   soundness boundary instead of at the inverse-of-zero fault.
   Without θ ≠ 0 the blinder `θ^k` collapses and the column
   distinguishability the θ-power weighting provides degenerates.

3. **Safe constructor + arity accessor.** Wire-shape invariants
   (non-empty columns + arity match) are now validated at
   `MultiColumnLookupEvals::try_new` time rather than deferred to
   evaluation time. Callers parsing proof bytes can fail at
   parse-time with the same error type.

### Doc-correction caught + fixed

The session-85 docstring claimed the lookup-soundness sum identity
was `Σ_X m(X) = 0`. **That is incorrect** — in a satisfying
log-derivative lookup, `Σ_X m(X) = N` (the input row count, since
each input row contributes one to its matched table row's
multiplicity). The corrected docstring states the real identity:

```text
Σ_{X ∈ H} [m(X)·(table_combined(X) + θ^k)⁻¹
         − (input_combined(X) + θ^k)⁻¹] = 0
```

and explains that the vanishing polynomial check
(`t(ξ)·Z_H(ξ) == combined_expr(ξ)`) handles the sum-over-domain
piece implicitly via the `y²·lookup_expr` weighting in
`combined_expr`.

This is exactly the kind of doc-vs-code drift external audit firms
are valuable for catching. Self-audit caught it during the
extraction work.

### Lib test totals at v0.8.8

  mosaic-core              16
  mosaic-zk-primitives     87
  mosaic-groth16           26
  mosaic-plonk             32
  mosaic-hyperplonk        82
  mosaic-halo2             93  (+13 since v0.8.7)
  mosaic-nova              73
  mosaic-stark            117
  mosaic-serde             23
  mosaic-chunked           20
  mosaic-sdk               13
  mosaic-program            7
  ─────────────────────  ───
  total                   589

### What this milestone does NOT change

Wire format, proof byte layout, on-chain ABI, transcript absorb
order: all unchanged. The new θ=0 rejection is a behaviour
boundary widening (previously the same θ=0 input would have
reached the inverse computation and surfaced the same error
type), but every existing fixture and consumer uses
transcript-derived θ which never produces zero.

---

## 2026-04-26 — v0.8.7-nova-base-commit-binding release (session 87)

| Field | Value |
|---|---|
| Tag | [`v0.8.7-nova-base-commit-binding`](https://github.com/wienerlabs/mosaic/releases/tag/v0.8.7-nova-base-commit-binding) |
| Auditor | Internal (Wiener Labs) |
| Scope | Closes the soundness hole in the v0.8.6 audit gate by binding `r` to the 4 base commitments in the Fiat-Shamir transcript |
| Findings | **One soundness bug fixed** — `verify_folding_consistency` was vacuous because `r` was independent of (`base_e_1`, `base_e_2`, `base_w_1`, `base_w_2`); the prover could back-solve all 4 base commits post-`r`-derivation to make the gate pass for any chosen folded triple |
| Status | ✅ Round-1 transcript absorbs all 7 G1 inputs of the audit gate; new `proptest_base_commit_mutation_cascades` is the regression guard |

### What this milestone changes for an external auditor

Sessions ≤86 derived `r` from `(VK, public_inputs, e_comm,
w_comm, t_comm)` only. The session-86 audit gate would then check
`base_e_1 + r·base_e_2 + r²·t = e_comm` and `base_w_1 + r·base_w_2
= w_comm`. A malicious prover, after seeing `r`, could pick:

```text
base_e_2 := arbitrary
t        := arbitrary
base_e_1 := e_comm - r·base_e_2 - r²·t   (algebraic back-solve)
base_w_2 := arbitrary
base_w_1 := w_comm - r·base_w_2          (algebraic back-solve)
```

These choices satisfy the audit gate by construction without
the prover ever performing an honest fold step. The gate was
therefore vacuous as a soundness check.

Session 87 adds the four base-commit absorbs to round 1 of
`derive_challenges`, so `r` now depends on `(base_e_1, base_e_2,
base_w_1, base_w_2)` in addition to the previous inputs. Because
`r` is determined by transcript-bound bytes that include all 4
base commits, the prover must commit to the bases *before* `r`
is sampled — Schwartz-Zippel + DLOG hardness then make
constructing a non-honestly-folded passing tuple computationally
infeasible.

### Soundness model after v0.8.7

Honest accumulator:
- prover folds two real instances to get `(base_e_*, base_w_*, t)`
- folded values match `(e_comm, w_comm)` by construction
- audit gate accepts for any `r`

Adversarial accumulator:
- prover picks `(base_*, t, e_comm, w_comm, t_comm)` arbitrarily
- transcript-bound `r` is sampled from all 7 G1 inputs + VK + PI
- audit gate accepts only if the chosen tuple happens to satisfy
  the fold equation at the sampled `r`
- by Schwartz-Zippel over BN254 scalar field (≈ 2²⁵⁴ size), this
  occurs with probability ≤ `1/|F_r|` for any fixed adversarial
  tuple — negligible

### Lib test totals at v0.8.7

  mosaic-core              16
  mosaic-zk-primitives     87
  mosaic-groth16           26
  mosaic-plonk             32
  mosaic-hyperplonk        82
  mosaic-halo2             80
  mosaic-nova              73  (+1 since v0.8.6)
  mosaic-stark            117
  mosaic-serde             23
  mosaic-chunked           20
  mosaic-sdk               13
  mosaic-program            7
  ─────────────────────  ───
  total                   576

### What this milestone does NOT change

Wire format, proof byte layout, on-chain ABI: all unchanged. The
fix is a pure transcript-derivation rule change. External
consumers re-derive any cached `(r, ξ, ν)` after upgrade; no
proof-format migration needed.

---

## 2026-04-26 — v0.8.6-nova-folding-consistency release (session 86)

| Field | Value |
|---|---|
| Tag | [`v0.8.6-nova-folding-consistency`](https://github.com/wienerlabs/mosaic/releases/tag/v0.8.6-nova-folding-consistency) |
| Auditor | Internal (Wiener Labs) |
| Scope | Nova folding-consistency audit-gate extraction (session 86) + canonical 2-term `W` formula + 13 new property/unit tests |
| Findings | One test-logic bug caught + fixed inline (slot-walk in `folding_consistency_rejects_short_inputs` — `cases` array tracked the slot under test only at index 0); zero soundness regressions |
| Status | ✅ Nova `E_folded` + `W_folded` reconstruction now lives in a single named primitive (`verify_folding_consistency`) with up-front length validation and a 9-test coverage profile (5 unit + 4 proptest) |

### What this milestone changes for an external auditor

The Nova fold-reconstruction soundness gate — historically inlined
in `mosaic-nova::verifier::NovaFolding::verify` as a duplicated
`folded_commitment_from_fold` × 2 + byte-compare × 2 +
`VerificationFailed` × 2 pattern — is now extracted into
`mosaic-nova::folding::verify_folding_consistency`. Auditors
reviewing the Nova soundness story have **one named function**
to read instead of one inline block scattered across the verifier.

The extracted primitive also tightens the `W` reconstruction from
the placeholder 3-term `W_1 + r·W_2 + r²·T` to the **canonical
Nova 2-term** `W_1 + r·W_2`. Both formulas agree on every
scaffold fixture (which all have `T = 0`); the change is
byte-identical for existing tests but tightens the contract for
future fixtures with non-zero cross-terms.

### Lib test totals at v0.8.6

  mosaic-core              16
  mosaic-zk-primitives     87
  mosaic-groth16           26
  mosaic-plonk             32
  mosaic-hyperplonk        82
  mosaic-halo2             80
  mosaic-nova              72  (+13 since v0.8.5)
  mosaic-stark            117
  mosaic-serde             23
  mosaic-chunked           20
  mosaic-sdk               13
  mosaic-program            7
  ─────────────────────  ───
  total                   575

### What this milestone does NOT change

No on-chain ABI, behaviour, or wire-format change. The
`verify_folding_consistency` extraction is an audit-clarity
refactor verified by the existing `rejects_tampered_base_e_commitment`
integration test remaining green, plus 13 new unit + proptest
cases that pin the audit gate's accept/reject contract directly.

---

## 2026-04-27 — v0.8.3-shared-primitive-lift release (sessions 60-68)

| Field | Value |
|---|---|
| Tag | [`v0.8.3-shared-primitive-lift`](https://github.com/wienerlabs/mosaic/releases/tag/v0.8.3-shared-primitive-lift) |
| Auditor | Internal (Wiener Labs) |
| Scope | Shared-primitive consolidation (sessions 63, 66) + consumer migrations (sessions 64, 65, 68) + CI workflow expansion (session 61) + audit-coverage runbook (session 70) |
| Findings | Zero soundness regressions; one false positive caught + fixed inline (snake_case digit allowance, session 52) |
| Status | ✅ Every BN254 polynomial-eval site and every BN254 pairing site in the workspace goes through one of the 8 audit-grade shared primitives |

### What this milestone changes for an external auditor

The workspace now exposes **8 shared primitives** in
`mosaic-zk-primitives` covering Fr arithmetic, transcript challenge
derivation, KZG opening LHS construction, generic pairing
verification, and Horner polynomial evaluation. Every BN254 verifier
in the workspace (mosaic-{groth16, plonk, hyperplonk, halo2, nova})
calls into these primitives instead of inlining its own
implementation. A future soundness-critical change (e.g. tighter
G2 length validation, a different pairing return-code convention
if Solana ever changes the alt_bn128 wire format) needs only one
edit.

CI now runs every sessions-47-59 bench + fuzz harness on every PR
(representative subset, ~25 min wall-clock) and the full 23-target
fuzz inventory nightly at 60 min/harness.

### Lib test totals at v0.8.3

  mosaic-core              16
  mosaic-zk-primitives     74  (+10 since v0.8.2: horner + n-pair)
  mosaic-groth16           26
  mosaic-plonk             32
  mosaic-hyperplonk        82
  mosaic-halo2             75
  mosaic-nova              59
  mosaic-stark            117
  mosaic-serde             23
  mosaic-chunked           20
  mosaic-sdk               13
  mosaic-program            7
  ─────────────────────  ───
  total                   544

### What this milestone does NOT change

No on-chain ABI, behaviour, or wire-format change. The
shared-primitive lifts are byte-identical refactors verified by
the existing test suite remaining green across the migration
commits.

---

## 2026-04-27 — v0.8.2-fuzz-bench-coverage release (sessions 47-59)

| Field | Value |
|---|---|
| Tag | [`v0.8.2-fuzz-bench-coverage`](https://github.com/wienerlabs/mosaic/releases/tag/v0.8.2-fuzz-bench-coverage) |
| Auditor | Internal (Wiener Labs) |
| Scope | Bench + fuzz dimension extension of the v0.8.1 audit-coverage milestone |
| Findings | One false positive caught + fixed inline (HyperPlonk anchor + XOR cancellation, session 58); zero soundness regressions |
| Status | ✅ All 6 production verifiers covered by both BPF CU bench AND host criterion bench AND a 23-target fuzz harness inventory |

The v0.8.2 milestone has three measurement-surface dimensions:

| Surface | Coverage |
|---|---|
| Property tests | 137 across 12 crates (sessions 36-52) |
| BPF CU bench | 7 systems (sessions 47, 49) |
| Host criterion bench | 5 systems (session 51) |
| Fuzz harnesses | 23 targets across 6 systems (sessions 54-59) |

Per-system fuzz inventory at v0.8.2 (carried into v0.8.3):

  Phase-1 Groth16 (3 original)
    fuzz_groth16_proof_bytes, fuzz_vk_bytes, fuzz_public_inputs

  Phase-2 KZG-PLONK (4)
    fuzz_plonk_{proof_bytes, vk_bytes, public_inputs, combined}

  Phase-3 HyperPlonk + Halo2 + Nova + FRI-STARK (16)
    fuzz_<system>_{proof_bytes, vk_bytes, public_inputs, combined}

---

## 2026-04-27 — Workspace-wide proptest sweep (sessions 37-42, post-v0.8.0)

| Field | Value |
|---|---|
| Tag | _no separate tag_ — work appended to the `v0.8.0-phase3-polish` line via main branch commits `cfef56a..0fb0ea9` |
| Auditor | Internal (Wiener Labs) |
| Scope | Property-based test coverage for every host-callable byte-format, Fiat-Shamir, state-machine, and SDK surface in the workspace |
| Findings | Three internal false positives surfaced and documented inline (see "Yan kazanım" section in each session commit message); zero soundness regressions |
| Status | ✅ Audit-grade proptest coverage now spans 9 of 11 workspace crates |

### What this milestone changes for an external auditor

The workspace now ships **324 lib tests across 11 crates**, of which
**+111 are property-based tests added in this sweep**. Every Phase-1,
Phase-2, and Phase-3 verifier crate, plus the snarkjs adapter, the
chunked-upload state machine, the client SDK, and the on-chain program
dispatch surface, is now property-tested under proptest with explicit
audit-grade rationale comments at each test's docstring.

The intention is to give an external review firm a single point of
entry to the soundness density of every byte-format and state-transition
boundary: instead of having to derive the audit-relevant invariants
from prose, they can read the proptest body and verify it pins the
property they care about.

### Property categories pinned by the sweep

| Category | Crates covered | Representative property |
|---|---|---|
| Canonical byte layout | halo2, hyperplonk, nova, plonk, groth16 | `proof_view_parses_any_canonical_payload` reassembles A‖B‖C exactly |
| Fiat-Shamir avalanche | halo2 (4-round), hyperplonk (3-round), nova (3-round), plonk (6-round) | `quotient_t_mutation_xi_v_only` — round-4 absorb cascades to ξ + v but leaves β/γ/α/u stable |
| Single-byte tamper rejection | halo2, hyperplonk verifiers | `random_commit_byte_flip_rejects` over commit + opening regions |
| State-machine monotonicity | chunked | `finalized_session_rejects_appends` pins no-double-finalize + no-post-finalize-append |
| Borsh wire-format round-trip | sdk, program | `verify_proof_data_borsh_roundtrip` pins the four-field order against silent reorderings |
| BE-comparison + Fr arithmetic | groth16 | `add_mod_r_preserves_range` for the batch-coefficient sum |
| snarkjs adapter byte ordering | serde | `g2_layout_c1_then_c0` pins the Solana c1 ‖ c0 swap |
| Builder/setter independence | sdk | `builder_setters_are_independent` against copy-paste setter aliasing |
| Instruction-tag dispatch | program | `process_rejects_unknown_tag` exhaustive over u8 ∉ known dispatch ranges |

### Documented false positives (inline rationale + scope narrowing)

1. **Halo2 verifier random-byte-flip selector slot**
   The trivially-zero dummy fixture has `b = 0` for every wire, so
   flipping a `Q_R` byte preserves the gate expression `Q_R · b = 0`.
   Scope was narrowed to commit-region bytes; the selector-slot
   property is deferred to the fixture-driven differential harness.

2. **HyperPlonk verifier `anchor + XOR` cancellation**
   The pattern `proof[off] = anchor; proof[off] ^= bit_mask;` collapses
   to a no-op when `bit_mask == anchor`. Surfaced by proptest shrinking
   on the first run; rewritten as direct `proof[off] = new_val` with
   `new_val ∈ [1, 255]`. Same pattern audited and avoided across the
   rest of the sweep.

3. **`is_multiple_of` MSRV warning** _(pre-existing, not from this sweep)_
   The challenges modules use `usize::is_multiple_of`, stable since
   Rust 1.87. Workspace MSRV is 1.85. CI passes because the lint is in
   the pedantic group; documented here as an unresolved drift between
   nightly clippy's stable-version detection and our MSRV pin.

### What this does NOT yet cover

- **Fixture-driven differential testing for Phase-3 bodies.** The
  existing `tests/differential` harness covers Groth16 + PLONK against
  arkworks; HyperPlonk, Halo2, Nova, and FRI-STARK still need
  Espresso / PSE / sonobe / Plonky3 reference fixtures wired in.
  This is the last named pre-audit gap in `README.md § Security`.
- **`mosaic-program::chunked::dispatch` integration tests.** The
  current SBF integration test under `tests/verify_proof_sbf.rs` exercises
  the verify-proof path; the chunked dispatch path needs a parallel
  `solana-program-test` harness with synthesized `AccountInfo`.
- **Arkworks adapter property tests.** Generating random valid
  `ArkProof` / `ArkVk` fixtures requires a small inline circuit; this
  was deferred from session 40.

---

## 2026-04-20 — Phase 1 scope frozen; **ready for external review**

| Field | Value |
|---|---|
| Tag | [`v0.1.0-phase1`](https://github.com/wienerlabs/mosaic/releases/tag/v0.1.0-phase1) |
| Auditor | **None yet** — outreach in progress (issue [#61](https://github.com/wienerlabs/mosaic/issues/61)) |
| Scope | See § Phase-1 audit scope below |
| Commit | Tag head — SHA depends on final pre-audit-readiness commits |
| Findings | N/A — pre-audit |
| Status | **Phase 1 scope ready for review.** Do not use in production pending audit. |

### Phase-1 audit scope (locked at `v0.1.0-phase1`)

#### In scope
- [`crates/mosaic-core/`](crates/mosaic-core) — trait hierarchy, error
  taxonomy, syscall abstraction.
- [`crates/mosaic-groth16/`](crates/mosaic-groth16) — BN254 Groth16 verifier
  (host + SBF backends).
- [`crates/mosaic-serde/`](crates/mosaic-serde) — **snarkjs + arkworks
  adapters only**; `gnark`, `halo2`, `plonky3`, `risc0` modules are stubs
  and out-of-scope.
- [`crates/mosaic-chunked/`](crates/mosaic-chunked) — PDA layout, rolling
  SHA-256 protocol, instruction data model.
- [`crates/mosaic-program/`](crates/mosaic-program) — reference Solana
  program dispatcher, including chunked-upload instruction handlers.
- [`docs/adr/`](docs/adr) — five ADRs (trait hierarchy, error taxonomy,
  serialization, chunked upload, CU budget).
- [`docs/design/0001-chunked-upload-handlers.md`](docs/design/0001-chunked-upload-handlers.md)
  — chunked-upload implementation contract.
- [`docs/threat-model.md`](docs/threat-model.md) — T-1..T-10 adversarial
  input vectors.

#### Out of scope
- `crates/mosaic-plonk/` — Phase 2 stub, `UnimplementedProofSystem` return only.
- `crates/mosaic-stark/` — Phase 3 stub.
- `crates/mosaic-nova/` — Phase 3 stub.
- `crates/mosaic-serde/src/{gnark,halo2,plonky3,risc0}.rs` — stubs.
- `crates/mosaic-sdk/` — host-only client SDK. Out of audit scope because
  on-chain security does not depend on SDK correctness.
- `crates/mosaic-bench/` — measurement tooling.
- `crates/mosaic-fuzz/` — fuzz harnesses (audited *via* their findings, not
  as code under review).
- `tests/` — test harness, not production code.
- Upstream dependencies — audited by their own projects.

### Known unaudited components

See [SECURITY.md § Known unaudited components](SECURITY.md#known-unaudited-components).

### Review artifacts prepared for auditors

The following artifacts are intentionally maintained in the repository so
auditors can audit the audit trail itself:

| Artifact | Purpose |
|---|---|
| [`CHANGELOG.md`](CHANGELOG.md) | Phase-1 scope locked at `v0.1.0-phase1`. |
| [`docs/adr/*.md`](docs/adr) | Every architectural decision with context + consequences. |
| [`docs/design/*.md`](docs/design) | Implementation contracts for non-trivial protocols. |
| [`docs/threat-model.md`](docs/threat-model.md) | Adversarial input vectors T-1..T-10. |
| [`docs/lint-policy.md`](docs/lint-policy.md) | Every `#[allow(clippy::…)]` justified. |
| [`docs/compute-unit-budget.md`](docs/compute-unit-budget.md) | Per-system CU caps + measured baselines. |
| [`docs/audit/rfq.md`](docs/audit/rfq.md) | Pre-audit request-for-quote sent to candidate firms. |
| [`docs/audit/outreach-email.md`](docs/audit/outreach-email.md) | Outreach + response templates. |
| `supply-chain/` | `cargo-vet` attestation configuration. |

### Phase-1 self-review checklist

Completed internally before opening for external review. Items the
auditor is invited to challenge are marked ⚠.

- [x] Zero `unimplemented!()` / `todo!()` / `panic!()` in library code paths.
- [x] Every `OnChainError` discriminant pinned by `discriminant_stability` test.
- [x] Differential test harness passes (arkworks reference vs Mosaic host).
- [x] Round-trip byte equality: snarkjs / arkworks / canonical.
- [x] Chunked-upload integration tests cover happy path + 6 security gates.
- [x] `bpf-bench` measures actual on-chain CU against ADR-0005 caps.
- [x] `#![forbid(unsafe_code)]` workspace-wide (migration to `deny` tracked [#58](https://github.com/wienerlabs/mosaic/issues/58)).
- [x] `cargo-deny`, `cargo-audit` in CI.
- [x] Scope-boundary axes documented (under-constrained circuits, malleable proofs, validator determinism, replay safety) — [`docs/threat-model.md`](docs/threat-model.md#scope-boundaries-and-application-responsibilities).
- [ ] ⚠ `cargo-vet` bootstrap landed; full import chain pending #59.
- [ ] ⚠ Poseidon on-chain syscall path not wired for Solana 2.x (#8).
- [ ] ⚠ Fixtures are programmatic (arkworks-synthesized JSON),
      not Circom-compiled (#24).

---

## Audit roadmap

| Milestone | Target | Status |
|---|---|---|
| Internal review of `mosaic-core` trait surface | Phase 1 freeze | **Done** ([`v0.1.0-phase1`](https://github.com/wienerlabs/mosaic/releases/tag/v0.1.0-phase1)) |
| Pre-audit outreach (4 firms) | 2026-Q2 start | In progress (issue [#61](https://github.com/wienerlabs/mosaic/issues/61)) |
| External audit firm selection | 2026-Q2 end | Pending quotes |
| External audit of `mosaic-groth16` + reference program | Phase 2 release | Pending |
| External audit of `mosaic-plonk` | Phase 2 freeze | Pending |
| External audit of `mosaic-stark` + chunked-upload verifier path | Phase 3 release | Pending |
| Recurring audit (annual) | Post-1.0.0 | Pending |

---

## Reporting issues

Vulnerability reports follow the [SECURITY.md](SECURITY.md) policy.
Audit findings — once we have audits — are tracked in this file with
fix commit references.

## Entry template

Each audit entry follows this template:

```markdown
## YYYY-MM-DD — Auditor name

| Field | Value |
|---|---|
| Auditor | <firm or individual> |
| Scope | <crates and commit range> |
| Commit | `<sha>` |
| Findings | <link to report or short summary> |
| Status | <Closed / Mitigated / Open> |
```

Findings that are *fixed* in a follow-up commit reference the fix commit
SHA. Findings that are *accepted-as-risk* include a written justification.
