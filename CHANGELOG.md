# Changelog

All notable changes to Mosaic are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned beyond v0.9.7-halo2-proof-compressed

- Fixture-driven differential testing for the three remaining Phase-3
  bodies (Espresso HyperPlonk, sonobe Nova, Plonky3 STARK). Halo2 now
  has multi-column lookup wired end-to-end + KZG-bound at v0.9.1.
- HyperPlonk full Zeromorph / PST / Gemini reduction (canonical
  layout breaking change).
- External security audit commission.

## [0.9.7-halo2-proof-compressed] — 2026-04-30

**Halo2 proof gains compressed wire format.** Sister to session
106's compressed VK. The proof's G1 commits (advice, lookup,
permutation_z, quotient, w_xi, w_xiw) compress to 32 B each via the
alt_bn128 syscall; Fr evaluations stay 32 B (not curve points).

### Wire format

```text
| offset | size | field                                  |
|---|---|---|
|   0..20 | unchanged 5-counter header (FIXED_HEADER_LEN) |
|  20..   | 32 × n_advice compressed advice commits       |
|    ..   | 32 × n_lookups compressed lookup commits      |
|    ..   | 32 compressed permutation_z                   |
|    ..   | 32 × n_quotient compressed quotient chunks    |
|    ..   | 32 × n_evals Fr evaluations (unchanged)       |
|    ..   | 32 compressed w_xi                            |
|    ..   | 32 compressed w_xiw                           |
```

For a typical proof with 5 advice + 1 perm_z + 3 quotient + 2
openings = 11 G1 commits at arity-1, the compressed form saves
352 B (11 × 32). Adding lookup commits scales the saving linearly.

### Cost trade-off (per `decompress_to_canonical_bytes` call)

For a 5+0+1+3+2 = 11 G1 proof: ~110 K CU decompression.

For high-frequency verifiers the CU overhead dominates.
For storage-rent-sensitive deployments (compressed proof archives,
on-chain proof records) the bandwidth saving wins.

### Added — session 108

#### `Halo2KzgProof::compress_from_canonical_bytes<B>(backend, canonical)`
Encodes the proof in compressed form. Validates input as a
canonical proof (calling `from_bytes` upfront), then iterates
each G1 commit and replaces it with the compressed equivalent.

#### `Halo2KzgProof::decompress_to_canonical_bytes<B>(backend, compressed)`
Decoder inverse. Parses the header, decompresses every G1 commit
via the alt_bn128 syscall, copies Fr evaluations as-is, and emits
the canonical uncompressed bytes. The caller chains
`Halo2KzgProof::from_bytes(&decoded)` to obtain a borrowed view.

Both methods are `Halo2KzgProof::*` static methods (proof is a
zero-copy view, can't own data; static helpers return `Vec<u8>`).

### New tests at v0.9.7 (mosaic-halo2: 117 → 123)

- `proof_compressed_round_trip_with_real_generators` — proof with
  BN254 G1 generators round-trips through compress + decompress
  byte-for-byte.
- `proof_compressed_form_is_smaller_than_uncompressed` — asserts
  exactly 11·32 = 352 B saving for the 5+0+1+3+2 commit shape.
- `proof_compressed_zero_only_round_trips` — zero G1 short-circuit.
- `proof_compressed_rejects_short_buffer` — < `header + perm_z + 2 openings`
  rejects.
- `proof_compressed_rejects_wrong_total_length` — trailing garbage
  rejects with `ProofLengthMismatch`.
- `proof_decompressed_parses_as_canonical_via_from_bytes` — chained
  decompress → from_bytes path produces a valid proof view with
  expected counter values.

### Lib test totals at v0.9.7

  mosaic-halo2            123  (+6 since v0.9.6)
  total                   660  (+6 since v0.9.6)

### Migration notes

Public API additions (no breakage):
- `mosaic_halo2::Halo2KzgProof::compress_from_canonical_bytes<B>`
- `mosaic_halo2::Halo2KzgProof::decompress_to_canonical_bytes<B>`

The existing `from_bytes` (uncompressed canonical wire format) is
unchanged. To use compressed proofs end-to-end:

```rust
let canonical = Halo2KzgProof::decompress_to_canonical_bytes(
    &backend, &compressed_bytes,
)?;
let proof = Halo2KzgProof::from_bytes(&canonical)?;
verifier.verify(&vk_bytes, &canonical, &public_inputs)?;
```

Combined with the session-106 compressed VK + session-108
compressed proof, a typical Halo2 deployment saves:
- VK:    ~46 % (~224 B for 2-fixed + 5-perm)
- Proof: ~32 % (~352 B for 5-advice + 1-lookup + 3-quotient)

## [0.9.6-halo2-multi-lookup] — 2026-04-30

**Multiple lookup arguments per Halo2 proof.** Sessions 100-101 added
multi-column lookup (single argument with arity ≥ 2 column pairs).
Session 107 generalizes to multiple distinct lookup arguments
(n_lookups ≥ 2), each with its own arity-k input/table column pair
+ multiplicity polynomial. Real Halo2 circuits typically declare
2-5 lookup arguments (byte-range table, XOR table, MUL table, hash
round-constants, …); session 107 makes them all verifiable.

### Why this matters

Real Halo2 toolchains (PSE halo2, halo2_proofs, axiom-halo2) emit
proofs with multiple lookup arguments by default. A circuit with a
byte-range lookup AND an XOR table is `n_lookups = 2`; adding a
hash round-constants table makes it 3. Pre-session-107 the verifier
hardcoded 1 implicit lookup. Session 107 lets the verifier accept
proofs with arbitrary `n_lookups`.

### Wire format

The proof header field `n_lookups: u32` (already present since v0.1)
is now the bundle-side eval-section count too:

- `n_lookups = 0`: legacy implicit single-lookup mode for backward
  compat with pre-session-107 scaffold fixtures. The bundle reads
  1 lookup section but the multi-poly opening skips m-poly pairing
  because the proof's commit section carries no m-commit.
- `n_lookups ≥ 1`: explicit multi-lookup mode. Bundle reads
  `n_lookups × (2k + 1)` lookup eval slots. Multi-poly opening
  pairs each m-commit (in proof's commit section) with the
  corresponding m-eval.

`n_evals` constraint:

```text
n_evals == 13 + max(1, n_lookups) × (2 × lookup_arity + 1) + n_quotient
```

### Soundness — distinct y-powers

The vanishing identity sums each lookup's contribution with a
distinct y-power:

```text
gate(ξ)
  + y · perm(ξ)
  + y² · L₀(ξ)
  + y³ · L₁(ξ)
  + …
  + y^(n+1) · L_{n-1}(ξ)
  = t(ξ) · Z_H(ξ)
```

Distinct y-powers are critical for soundness. With the same y² weight
on every lookup, an adversary could let `L₀ = -L₁` to satisfy the
identity at one row without either lookup being individually valid.
Distinct powers force every lookup to vanish independently
(Schwartz-Zippel argument).

### Added — session 107

#### `circuit::combined_expr_multi_lookup` function
Sums each lookup with `y^(j+2)` weighting. At `lookups.is_empty()`
collapses to `gate + y · perm` (no-lookup case). At
`lookups.len() == 1` produces the same scalar as
`combined_expr_multi_column` (single-lookup multi-column path
unchanged).

#### `bundle::EvaluationBundle::multi_lookups: Vec<MultiColumnLookupEvals>`
New field carrying every lookup's evals. Length = `effective_n_lookups`
(`max(1, proof.n_lookups)`). Existing `lookup` and `multi_lookup`
fields preserved for backwards compat with pre-session-107 callers.

#### `bundle::idx::fixed_slots_for_lookups(arity, n_lookups)` helper
Generalizes session-100's `fixed_slots_for_arity(arity)` to scale
with the lookup count: `13 + n × (2k + 1)`.

#### `n_advice ≥ 2 · arity · n_lookups` proof-parser constraint
Session-101's "last 2k advice columns reserved for lookup" constraint
now scales with the lookup count: each of the `n_lookups` arguments
claims its own 2k advice columns. Insufficient `n_advice` rejects at
proof parse time with `ProofLengthMismatch`.

### Verifier dispatch order

The verifier's vanishing-identity check now dispatches by precedence:

1. `bundle.multi_lookups.len() ≥ 2` → `combined_expr_multi_lookup`
   (session-107 multi-lookup path).
2. `bundle.multi_lookup.is_some()` → `combined_expr_multi_column`
   (session-100 single multi-column lookup path).
3. Otherwise → `combined_expr` (legacy single-column path).

Byte-equivalent for arity = 1 + n_lookups ≤ 1 (every existing
fixture stays on path #3); session-100 multi-column proofs stay on
path #2; new n_lookups ≥ 2 proofs hit path #1.

### New tests at v0.9.6 (mosaic-halo2: 110 → 117)

Multi-lookup end-to-end:
- `n_lookups_2_arity_1_combined_expr_passes_then_pairing_fails` —
  arity-1 × 2 lookups: combined identity passes, opening fails on
  m_eval/commit mismatch (documented Phase-3 gap).
- `n_lookups_3_arity_1_combined_expr_passes` — same pattern at
  n_lookups=3, exercises y⁴ contribution.
- `n_lookups_2_arity_2_multi_column_combined_expr_passes` —
  2 multi-column lookups (arity=2 × n=2), n_advice=8 reserved.

Tamper rejection (proves distinct y-powers detect tampering at any
lookup index):
- `n_lookups_2_rejects_tampered_first_lookup_m_eval` (lookup #0)
- `n_lookups_2_rejects_tampered_second_lookup_m_eval` (lookup #1)
- `n_lookups_3_rejects_tampered_third_lookup_m_eval` (lookup #2 at
  y⁴ weight)

Constraint validation:
- `n_lookups_2_arity_2_rejects_insufficient_n_advice` —
  n_advice=5 < 2·2·2=8 rejects at parse with `ProofLengthMismatch`.

### Lib test totals at v0.9.6

  mosaic-halo2            117  (+7 since v0.9.5)
  total                   654  (+7 since v0.9.5)

### Migration notes

Public API additions (no breakage):
- `mosaic_halo2::combined_expr_multi_lookup`
- `mosaic_halo2::EvaluationBundle::multi_lookups: Vec<MultiColumnLookupEvals>`
- `mosaic_halo2::bundle::idx::fixed_slots_for_lookups`

Wire format:
- `n_lookups = 0` retains its legacy implicit-1-section semantics
  for pre-session-107 scaffold fixtures. Real provers always emit
  `n_lookups ≥ 1`.
- `n_lookups ≥ 2` is the new explicit multi-lookup mode.
- The session-105 internal-consistency checks
  (`n_advice ≥ 2·arity·n_lookups`, `n_evals ==
  13 + max(1,n_lookups)·(2k+1) + n_quotient`) ensure malformed
  multi-lookup headers reject at parse time.

Existing single-lookup proofs (every Halo2 fixture in the workspace)
verify byte-equivalently. New multi-lookup proofs land on the new
dispatch path.

## [0.9.5-halo2-vk-compressed] — 2026-04-30

**First real consumer of the alt_bn128 compression syscall.** Sessions
103-104 wired the syscall and added typed helpers; session 106 lands
the first verifier-side use: `Halo2KzgVerifyingKey::from_compressed_bytes`
+ `to_compressed_bytes`. Compressed VK is ~46% smaller than
uncompressed for a typical 2-fixed + 5-perm circuit.

### Why this matters on Solana

VK accounts pay rent based on size (Solana storage is permanent and
non-trivial — ~7M lamports per MB-year). For a 488-byte uncompressed
VK, the compressed form is ~264 bytes, saving ~46% of the rent bill.

The trade-off: each `from_compressed_bytes` call costs ~80 K CU for
a typical VK (8 G1 + 1 G2 decompressions). For high-frequency
verifiers this adds 16% to the per-tx CU cost; for low-frequency or
storage-sensitive deployments the trade is favorable.

### Added — session 106

#### `Halo2KzgVerifyingKey::from_compressed_bytes<B>(backend, bytes)`
Decodes a compressed VK byte buffer into the in-memory uncompressed
struct. Calls `alt_bn128_compression(G2Decompress)` for `x2_g2` and
`alt_bn128_compression(G1Decompress)` for each fixed and permutation
commit. The rest of the verifier is unchanged — once decompressed,
the in-memory VK matches the existing layout.

#### `Halo2KzgVerifyingKey::to_compressed_bytes<B>(backend)`
Companion encoder. Iterates over the VK's commits, compresses each
via `mosaic_zk_primitives::compression::{compress_g1, compress_g2}`,
and writes the result alongside the unchanged Fr + counter fields.

#### `Halo2KzgVerifyingKey::COMPRESSED_FIXED_LEN` constant
Mirrors the uncompressed `FIXED_LEN` but with G2 halved (64 instead
of 128). Public so external callers can compute compressed-VK
buffer sizes ahead of time.

### Wire format (compressed VK)

```text
| offset | size | field                                    |
|---|---|---|
|   0 |  4 | k                                            |
|   4 |  4 | n_instances                                  |
|   8 |  4 | n_advice                                     |
|  12 |  4 | n_fixed                                      |
|  16 | 64 | x2_g2 compressed (G2_LEN / 2)                |
|  80 | 32 | omega_fr (Fr — uncompressed)                 |
| 112 |  4 | fixed_compressed_len (= n_fixed * 32)        |
| 116 |  4 | perm_compressed_len  (= perm_count * 32)     |
| 120 |  … | compressed commits payload                   |
```

The session-105 internal-consistency checks (declared count ==
actual byte count, divisibility) carry over to the compressed
parser, adapted to the 32-byte G1 / 64-byte G2 sizes.

### New tests at v0.9.5 (mosaic-halo2: 105 → 110)

- `vk_compressed_round_trip_with_real_generators` — VK with BN254
  G1+G2 generators round-trips through compress + decompress
  byte-for-byte.
- `vk_compressed_form_is_smaller_than_uncompressed` — asserts the
  saving equals the structural expectation: `7·32 + 64 = 288 B`
  for a 2-fixed + 5-perm VK; pins compressed/uncompressed ratio
  ≤ 60 %.
- `vk_compressed_zero_only_short_circuits_to_zero_uncompressed` —
  zero G1/G2 points compress to zero (both backends short-circuit).
- `vk_compressed_rejects_short_buffer` — too-short input rejects
  with `VerifyingKeyLengthMismatch`.
- `vk_compressed_rejects_n_fixed_inconsistent_with_payload` —
  bumped `n_fixed` without resizing payload triggers the session-105
  consistency check at the compressed layer.

### Lib test totals at v0.9.5

  mosaic-halo2            110  (+5 since v0.9.4)
  total                   647  (+5 since v0.9.4)

### Migration notes

Public API additions (no breakage):
- `mosaic_halo2::Halo2KzgVerifyingKey::from_compressed_bytes<B>`
- `mosaic_halo2::Halo2KzgVerifyingKey::to_compressed_bytes<B>`
- `mosaic_halo2::Halo2KzgVerifyingKey::COMPRESSED_FIXED_LEN`

The existing `from_bytes` / `to_bytes` for the uncompressed wire
format are unchanged. Verifier code paths that consume
`Halo2KzgVerifyingKey` directly don't need to know whether the VK
arrived compressed or not — once parsed, the in-memory representation
is identical.

## [0.9.4-halo2-vk-consistency] — 2026-04-29

**Halo2 VK parser consistency hardening.** The wire format declares
`n_fixed: u32` separately from the `fixed_commits` byte buffer
length. Pre-session-105 the parser silently accepted VKs where these
two diverged — a bugged or adversarial generator could write
`n_fixed: 5` with only 2 commits worth of bytes, and downstream
verifier code that uses `n_fixed` for indexing would mis-index.

### Fix

`Halo2KzgVerifyingKey::from_bytes` now enforces:

1. `fixed_commits.len() % G1_LEN == 0` (divisibility)
2. `permutation_commits.len() % G1_LEN == 0` (divisibility)
3. `fixed_commits.len() == n_fixed * G1_LEN` (declared count
   matches actual byte count)

A wire payload that violates any of these rejects with
`VerifyingKeyLengthMismatch` at parse time.

### Changed

- `crates/mosaic-halo2/src/canonical.rs::Halo2KzgVerifyingKey::from_bytes`
  adds the three consistency checks above.
- The pre-existing `vk_roundtrip_no_commits` test had `n_fixed: 2`
  with `fixed_commits: vec![]` — a deliberate-or-accidental
  mismatch that the new check catches. Updated to consistent values
  (`n_fixed: 0` matching the empty commits).
- The proptest `arb_vk` strategy was generating `n_fixed` and
  `fixed_count` independently — could produce inconsistent VKs that
  failed the new check. Updated to use a single counter for both.

### Added — session 105 (mosaic-halo2: 103 → 105)

- `vk_rejects_n_fixed_inconsistent_with_commits_len` — VK with
  declared `n_fixed: 2` but empty `fixed_commits` rejects.
- `vk_rejects_non_multiple_g1_payload_lengths` — VK with
  `fixed_len: 65` (not a multiple of `G1_LEN: 64`) rejects.

### Lib test totals at v0.9.4

  mosaic-halo2            105  (+2 since v0.9.3)
  total                   642  (+2 since v0.9.3)

### Migration notes

**Backwards-incompatible for malformed VKs.** Any downstream
consumer that was producing VKs with `n_fixed` ≠
`fixed_commits.len() / G1_LEN` will start getting
`VerifyingKeyLengthMismatch` at parse time. Such VKs were already
producing wrong verification results downstream; the check just
surfaces the bug at the right layer.

Conforming VKs (every real generator we've inspected) are unaffected.

## [0.9.3-compression-helpers] — 2026-04-29

**Verifier-friendly compression API.** Session 103 wired the
`alt_bn128_compression` syscall on both backends but the surface
was raw `&[u8]` slices via `SyscallBackend::alt_bn128_compression`.
Session 104 adds typed helpers in `mosaic-zk-primitives::compression`
that take and return fixed-size `[u8; G1_LEN]` / `[u8; G2_LEN]`
arrays, validate output sizes, and document the cost trade-off.

### Added — `mosaic-zk-primitives::compression` module (new)

Four helper functions wrapping the syscall surface with verifier-
friendly types:

```rust
pub fn compress_g1<B>(backend: &B, point: &[u8; 64])
    -> Result<[u8; 32], OnChainError>;
pub fn decompress_g1<B>(backend: &B, compressed: &[u8; 32])
    -> Result<[u8; 64], OnChainError>;
pub fn compress_g2<B>(backend: &B, point: &[u8; 128])
    -> Result<[u8; 64], OnChainError>;
pub fn decompress_g2<B>(backend: &B, compressed: &[u8; 64])
    -> Result<[u8; 128], OnChainError>;
```

Each helper validates the syscall's return-payload length as
defense-in-depth — a wrong-length return surfaces as
`InternalInvariantViolation` (should never happen with the real
SBF + host backends, but the explicit check is consensus-critical).

The module-level docstring documents the cost trade-off:
- ~2 K CU per G1 compression call.
- ~10 K CU per G1 decompression (square-root mod q to recover y).
- 50% bandwidth saving per point (G1: 64→32, G2: 128→64).

### New tests at v0.9.3 (mosaic-zk-primitives: +6)

- `g1_round_trip_generator` — BN254 generator round-trips.
- `g1_identity_round_trip` — zero short-circuit.
- `g2_identity_round_trip` — zero short-circuit at G2 sizes.
- `g1_round_trip_is_deterministic_across_iterations` — same input
  always yields same output (3 consecutive calls).
- `g1_helper_composition_matches_identity_function` — composition
  contract: `decompress(compress(x)) == x`.
- `g1_compressed_bit_flip_changes_decompressed_or_rejects` —
  tampered compressed point either decompresses to a different
  point OR fails validation; never silently yields the original.

### Lib test totals at v0.9.3

  mosaic-zk-primitives     93  (+6 since v0.9.2; 87 → 93)
  total                   640  (+6 since v0.9.2)

### Migration notes

Public API additions (no breakage):
- `mosaic_zk_primitives::compression::{compress_g1, decompress_g1,
  compress_g2, decompress_g2}`
- Constants: `G1_LEN = 64`, `G1_COMPRESSED_LEN = 32`,
  `G2_LEN = 128`, `G2_COMPRESSED_LEN = 64`.

Verifier-side consumption (a canonical layout v2 with compressed
VK option) lands in subsequent releases.

## [0.9.2-alt-bn128-compression] — 2026-04-29

**Long-standing TODO closed: alt_bn128 compression syscall now wired
on both backends.** The `SyscallBackend::alt_bn128_compression` method
was on the trait surface from day one but both implementations
(Solana SBF + host) returned `UnimplementedProofSystem` with a
`TODO(mosaic-007)` marker. Session 103 implements both.

### What this enables

- **Compressed VK + proof representations** — G1 commitments shrink
  from 64 → 32 bytes; G2 from 128 → 64 bytes. On Solana that's
  a meaningful per-tx bandwidth reduction (instruction data limit
  is 1232 B; a 5-advice-column Halo2 proof drops ~160 bytes).
- **Future canonical layout v2** — verifiers can opt into compressed
  VK formats once a proof generator emits them. Wire format work
  for that lands separately; session 103 just unblocks the syscall.

### Implementation

Both backends route through `solana-bn254::compression::prelude`:

- **Solana SBF**: directly calls the `sol_alt_bn128_compression`
  syscall via the crate's `target_arch="solana"` path.
- **Host**: uses the crate's `cfg(not(target_os = "solana"))`
  fallback that performs the same arithmetic via arkworks. The
  output is byte-identical to the SBF syscall by construction —
  the same trick we use for `sol_poseidon` (session ≤14).

### Changed

- `mosaic-core/Cargo.toml`: `host-backend` feature now also enables
  `solana-bn254` (was only enabled by `solana` feature).
- `crates/mosaic-core/src/syscall.rs`: both backends implement
  `alt_bn128_compression` for all 4 ops (G1Compress/Decompress,
  G2Compress/Decompress).

### New tests at v0.9.2 (mosaic-core: +8)

Round-trip + size + reject:
- `alt_bn128_g1_compress_decompress_round_trip_generator` — BN254
  generator (x=1, y=2) round-trips through compress + decompress
  byte-for-byte.
- `alt_bn128_g1_identity_round_trip` — zero G1 short-circuits.
- `alt_bn128_g2_identity_round_trip` — zero G2 short-circuits.
- `alt_bn128_g1_compressed_size_half_of_uncompressed` — 64 → 32.
- `alt_bn128_g1_compress_rejects_wrong_input_length` — supply 63
  bytes, expect `AltBn128CompressionSyscallFailed`.
- `alt_bn128_g1_decompress_rejects_wrong_input_length` — supply
  33 bytes.
- `alt_bn128_g2_compress_rejects_wrong_input_length` — supply 127.
- `alt_bn128_g2_decompress_rejects_wrong_input_length` — supply 32.

### Lib test totals at v0.9.2

  mosaic-core              28  (+12 since v0.9.1; 16 → 28 includes
                                 prior cfg-gated tests now run under
                                 host-backend)
  total                   634  (+12 since v0.9.1)

### Migration notes

No public API breakage. The `SyscallBackend::alt_bn128_compression`
trait method signature is unchanged; the previously-stubbed
implementations now succeed.

Verifiers that called `alt_bn128_compression` (none in workspace
prior to this release) would have received
`UnimplementedProofSystem` errors; they now succeed. Workspace-
internal consumers of compressed encodings land in subsequent
releases.

## [0.9.1-halo2-multi-column-kzg-binding] — 2026-04-29

**Real soundness gap closed.** Sessions 88-100 added the multi-
column lookup primitive and wired it into `combined_expr_multi_column`,
but the input/table column evaluations were still trusted by the
verifier — only the algebraic identity in `combined_expr` constrained
them. A malicious prover could pick `input_cols[i]` and `table_cols[i]`
freely as long as they happened to make the lookup identity vanish.

Session 101 binds those evals to the proof's advice commitments via
the KZG batched opening: the LAST `2k` advice columns are reserved
for the lookup argument's input + table column references, and the
KZG opening pairs them at exactly those indices.

### The soundness gap (pre-session-101)

The prover sends:
- `n_advice` advice column commitments (G1)
- `lookup_arity = k` declaring multi-column intent
- `2k + 1` lookup eval slots: `input_cols[0..k]`, `table_cols[0..k]`,
  `m_eval`

Pre-session-101, the verifier:
- Checked `combined_expr_multi_column(...) == t·Z_H` ✓
- Opened `advice_commits[i]` against wire-eval placeholders at ξ ✓
- **Did NOT** open `advice_commits[i]` against `input_cols[?]` or
  `table_cols[?]` — those eval slots floated free, only constrained
  by the algebraic identity.

A computationally-bounded prover could exploit this by:
1. Committing to honest advice columns + an honest m polynomial.
2. Choosing `input_cols[i]`, `table_cols[i]`, `m_eval` such that
   `combined_expr_multi_column` evaluates to `t·Z_H` at ξ.
3. The verifier accepts even though the chosen evals don't open
   against the committed advice polynomials at all.

### The fix — KZG-bound multi-column convention

The LAST `2k` advice columns of every multi-column proof are
**reserved for the lookup argument**:

- `advice[n_advice - 2k + i]` ↔ `input_cols[i]` for `i in 0..k`
- `advice[n_advice - k + i]`  ↔ `table_cols[i]` for `i in 0..k`

The first `n_advice - 2k` advice columns continue to pair to
wire-eval placeholders (legacy behavior).

Session 101 enforces:
1. **Parse-time constraint**: `Halo2KzgProof::from_bytes` rejects
   `lookup_arity ≥ 2 ∧ n_advice < 2·lookup_arity` as
   `ProofLengthMismatch`.
2. **KZG binding**: `collect_evals_at_xi` pairs the reserved advice
   slots with the multi-column eval bundle's `input_cols` and
   `table_cols` instead of wire-eval placeholders.

### Added — session 101

#### `Halo2KzgProof::from_bytes` — `n_advice ≥ 2·lookup_arity` check
Returns `ProofLengthMismatch` for arity-≥-2 proofs that don't reserve
enough advice columns. The message documents the soundness rationale
inline.

#### `collect_evals_at_xi` — multi-column-aware eval pairing
Computes `lookup_section_start = n_advice - 2k` and `table_section_start
= n_advice - k`, then dispatches each advice slot:
- `i >= table_section_start` → `multi_lookup.table_cols[i - table_section_start]`
- `i >= lookup_section_start` → `multi_lookup.input_cols[i - lookup_section_start]`
- otherwise → wire-eval placeholder (legacy)

The `multi_lookup.is_none()` branch (arity-1 legacy proofs) is
byte-identical to pre-session-101 behavior.

#### `dummy_vk_bytes_with_n_advice(n_advice: u32)` test helper
Parameterized VK builder so multi-column tests can request the
required `n_advice ≥ 2·arity`.

### New tests at v0.9.1 (mosaic-halo2: 101 → 103)

- `arity_2_multi_column_rejects_tampered_input_col_via_kzg` — tamper
  `input_cols[0]` from 0 to 1 without touching the corresponding
  advice commit; the KZG batched opening fails (or `combined_expr`
  if the identity also breaks). Pre-session-101 this attack would
  silently succeed.
- `arity_2_multi_column_rejects_tampered_last_table_col` — tamper
  `table_cols[k-1]` (last table slot). Catches off-by-one errors in
  the binding loop.

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
  total                   622  (+2 since v0.9.0)

### Migration notes

**No wire format change** — the proof header layout from v0.9.0 is
unchanged. Session 101 adds a stricter parse-time constraint
(`n_advice ≥ 2·lookup_arity` for arity ≥ 2). Pre-session-101 proofs
that satisfied this constraint by accident continue to verify
identically; pre-session-101 proofs that violated it now fail at
parse time with `ProofLengthMismatch`.

**Convention update for proof generators**: arity-k circuits must
allocate at least `2k` advice columns. The convention reserves the
LAST `2k` advice columns for the lookup argument; circuits with
fewer total advice columns must add filler columns or use arity 1.

The patch version bump (v0.9.0 → v0.9.1) reflects: bug fix + new
contract, no breaking changes for proofs that follow the canonical
`n_advice ≥ 2k` convention.

## [0.9.0-halo2-multi-column-lookup] — 2026-04-26

**Real new feature: Halo2 multi-column lookup is now a verifier
capability, not just an isolated audit gate.** Sessions 88-89 added
the `MultiColumnLookupEvals` primitive + `verify_multi_column_lookup_identity`
audit gate, but the Halo2 verifier itself only ever called the
arity-1 `lookup_expr`. Session 100 closes the gap: extends the proof
canonical layout with a `lookup_arity` header field, extends
`EvaluationBundle` to parse multi-column eval slots, and wires the
verifier to dispatch on arity.

This is the first **minor-version bump** in the v0.8.x series
because it adds a genuinely new user-visible capability:
multi-column-lookup proofs (common in real Halo2 circuits) can now
be verified by `mosaic-halo2`.

### Wire format change — `lookup_arity` field added to header

The proof header expands from 16 → 20 bytes by adding a `u32 LE`
`lookup_arity` field at offset 16-19. Forward-compat: a value of `0`
in this field is reinterpreted as `DEFAULT_LOOKUP_ARITY = 1` (legacy
single-column behavior), so pre-session-100 proof generators that
write zero in the upper 4 bytes continue to work.

```text
| 0  | 4 | n_advice (u32 LE)            |
| 4  | 4 | n_lookups (u32 LE)           |
| 8  | 4 | n_quotient (u32 LE)          |
| 12 | 4 | n_evals (u32 LE)             |
| 16 | 4 | lookup_arity (u32 LE) [NEW]  |  ← session 100
```

### Bundle layout — multi-column lookup section

For `lookup_arity = 1` (legacy):

```text
[0..3)   : 3 wire evals (a, b, c)
[3..8)   : 5 selector evals (q_M, q_L, q_R, q_O, q_C)
[8..13)  : 5 permutation evals (z, z_next, σ_1, σ_2, σ_3)
[13..16) : 3 lookup evals (input, table, m)
[16..16+n_quotient) : quotient chunks
```

For `lookup_arity = k ≥ 2` (new):

```text
[0..13)  : 13 wire/selector/permutation evals (unchanged)
[13..13+k)         : k input evals
[13+k..13+2k)      : k table evals
[13+2k..13+2k+1)   : 1 multiplicity eval (m)
[13+2k+1..)        : quotient chunks
```

Required `n_evals = 13 + 2k + 1 + n_quotient` for arity `k`.

### Added — session 100

#### `Halo2KzgProof::lookup_arity: u32` field
Parsed from header byte 16-19. Constants in `canonical::sizes`:
- `MAX_LOOKUP_ARITY = 16` (sanity cap)
- `DEFAULT_LOOKUP_ARITY = 1` (forward-compat)

#### `EvaluationBundle::multi_lookup: Option<MultiColumnLookupEvals>`
Populated for arity ≥ 2 from the new bundle section. The legacy
`lookup` field still populates with column-0 values for arity ≥ 2
(useful for tests + fallback).

#### `circuit::combined_expr_multi_column` function
The multi-column variant of `combined_expr`. Uses
`multi_column_lookup_expr` for the lookup contribution. At arity 1,
algebraically equivalent to `combined_expr` (pinned by session-89
proptest).

#### Verifier dispatch — `match &bundle.multi_lookup`
The verifier's vanishing-identity step now dispatches:
- `Some(multi)` → `combined_expr_multi_column(..., multi, ...)`
- `None` → legacy `combined_expr(..., &bundle.lookup, ...)`

### New tests at v0.9.0 (mosaic-halo2: 97 → 101)

- `full_pipeline_arity_2_multi_column_accepts` — arity-2
  identity-satisfying bundle verifies end-to-end through the new
  dispatch path.
- `full_pipeline_arity_4_multi_column_accepts` — arity-4 stress
  test exercising k=4 θ-power computation + 4-element inner
  products.
- `arity_2_multi_column_rejects_tampered_m_eval` — tampering m_eval
  in an arity-2 proof breaks the log-derivative identity →
  SumcheckFailed (proves the multi-column path actually validates,
  not just rubber-stamps).
- `arity_3_with_wrong_n_evals_rejects_at_bundle_parse` — declared
  arity-3 with arity-2-sized n_evals fails at bundle parse with
  `ProofLengthMismatch` (size-validation contract).

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
  total                   620  (+4 since v0.8.19)

### Migration notes

**Wire format breaking change.** The Halo2 proof header is now 20
bytes, was 16 bytes. Pre-v0.9.0 proof generators must:
- Either write `1u32` (or any sentinel) at byte 16-19 to declare
  legacy single-column behavior explicitly.
- Or rely on the parser's forward-compat handling: a header that
  ends after byte 16 with bytes [16..20] = `[0, 0, 0, 0]` is
  reinterpreted as `lookup_arity = DEFAULT_LOOKUP_ARITY = 1`.

The internal test fixture builders (`dummy_proof_bytes_typical`,
`proof_bytes`, etc.) are updated to write the new field. External
proof generators will need to add 4 bytes to their output.

**No on-chain ABI breakage**: the verifier program reads proofs via
the canonical layout, which now expects 20-byte headers. SBF
integration tests pass byte-equivalently with the updated layout.

The `mosaic-program` SBF integration tests (`sbf_verify_proof_succeeds_on_valid_groth16`,
`sbf_rejects_tampered_proof`) use Groth16 fixtures — unaffected by
the Halo2 layout change.

## [0.8.19-groth16-negate-consolidation] — 2026-04-26

**Second-pass Groth16 primitive consolidation.** Session 99 lifts
the duplicate `BN254_FQ_MODULUS_BE` (BN254 base-field modulus) +
`negate_g1` (G1 y-coordinate negation) implementations from
`mosaic-groth16` to the canonical workspace primitives in
`mosaic-zk-primitives::msm`. Sister to session 98's scalar-field
modulus consolidation.

### Changed — session 99

#### `mosaic-zk-primitives::msm::BN254_FQ_MODULUS_BE` promoted to pub const

Was previously a function-scoped `const` inside the existing
shared `negate_g1`. Promoted to `pub const` at module scope so
other crates can import it for the canonical source of truth:

```rust
/// BN254 base-field modulus `q` in big-endian.
/// q = 21888242871839275222246405745257275088696311157297823662689037894645226208583.
pub const BN254_FQ_MODULUS_BE: [u8; 32] = [...];
```

#### `mosaic-groth16::batch` migrated to shared `negate_g1`

The local `negate_g1` function (lines 270-291 of pre-session-99
`batch.rs`) is deleted. The single call site at line 140 now
imports `mosaic_zk_primitives::msm::negate_g1` directly.
`BN254_FQ_MODULUS_BE` removed from `batch.rs`.

#### `mosaic-groth16::verifier::negate_g1` thinned to a wrapper

The verifier's `negate_g1` accepts byte slices in either BE or LE
(via the `LE_INPUTS` const-generic). Session 99 keeps the
endianness-handling outer wrapper but delegates the actual
arithmetic to the shared primitive:

```rust
fn negate_g1(point: &[u8], le: bool) -> Result<[u8; G1_LEN], OnChainError> {
    if point.len() != G1_LEN {
        return Err(OnChainError::InvalidPointEncoding);
    }
    let mut be_point = [0u8; G1_LEN];
    be_point.copy_from_slice(point);
    if le {
        be_point[32..].reverse();
    }
    let mut out = mosaic_zk_primitives::msm::negate_g1(&be_point);
    if le {
        out[32..].reverse();
    }
    Ok(out)
}
```

20+ lines of inline `(q - y) mod q` arithmetic (with the borrow-
chain loop) collapse to a 4-line wrapper around the shared
function. `BN254_FQ_MODULUS_BE` removed from `verifier.rs`.

### Why this matters

Before session 99, the BN254 base-field modulus `q` was defined
in 3 places (mosaic-zk-primitives::msm, mosaic-groth16::batch,
mosaic-groth16::verifier) and the negation arithmetic was
implemented in 3 places. A future change to either (e.g., a
borrow-chain rewrite for clippy compliance) would require
touching 3 files, with drift risk between them.

After session 99, the modulus is defined once and the negation
is implemented once. Both Groth16 callsites delegate.

### Lib test totals at v0.8.19

Unchanged from v0.8.18 (616 across 12 crates with tests; 620
total). The migration is byte-equivalent.

  mosaic-groth16: 31 (unchanged — same tests, fewer lines of
  duplicated code under test)

### Migration notes

Public API additions (no breakage):
- `mosaic_zk_primitives::msm::BN254_FQ_MODULUS_BE` (was function-scoped)

The `mosaic-groth16::{batch, verifier}::negate_g1` private
functions are still available at their original signatures (they
were never exported). Internal code paths in mosaic-groth16 are
byte-identical at the negation step.

## [0.8.18-groth16-modulus-consolidation] — 2026-04-26

**Long-standing duplicate definition lifted.** Session 98 removes
the `BN254_FR_MODULUS_BE` + `lt_be` duplicates that have lived in
`mosaic-groth16/canonical.rs` since session 1. Both are now
re-exports of the canonical `mosaic-zk-primitives::fr` definitions
that other crates have used since session 21.

### Changed — session 98

#### `mosaic-groth16::canonical` — re-exports instead of duplicates

```diff
-pub const BN254_FR_MODULUS_BE: [u8; 32] = [
-    0x30, 0x64, 0x4e, 0x72, ... // 32 bytes
-];
-#[must_use]
-pub fn lt_be(lhs: &[u8; 32], rhs: &[u8; 32]) -> bool {
-    for (a, b) in lhs.iter().zip(rhs.iter()) { ... }
-}
+pub use mosaic_zk_primitives::fr::BN254_FR_MODULUS_BE;
+pub use mosaic_zk_primitives::fr::lt_be;
```

The byte values and behavior are identical; the workspace now has
a single source of truth for the BN254 scalar field modulus.

#### Internal callsite migration to `lt_r`

The two range-check loops in `mosaic-groth16` (`verifier.rs` line
68, `batch.rs` line 104) now call `mosaic_zk_primitives::fr::lt_r`
which is the convenience wrapper for `lt_be(a, &BN254_FR_MODULUS_BE)`.
Reads more clearly at the verifier callsite — the intent
("is this Fr in range?") is in the function name instead of
inferred from the modulus argument.

#### `mosaic-groth16/Cargo.toml` adds `mosaic-zk-primitives` dep

The dependency was implicit before (via `mosaic-core` features) but
is now explicit. No version pin changes — it's a workspace dep.

### Why this matters

Before session 98, a soundness-critical change to the BN254 scalar
field modulus (e.g., a future curve migration) would require
touching the constant in two places: `mosaic-groth16/canonical.rs`
AND `mosaic-zk-primitives/fr.rs`. A drift between the two would
silently produce a Groth16 verifier that accepts inputs the rest
of the workspace rejects — a subtle soundness bug.

After session 98, there is exactly one source of truth.

### Lib test totals at v0.8.18

Unchanged from v0.8.17 (616 across 12 crates with tests; 620
total). The migration is byte-equivalent.

  mosaic-groth16: 31 (unchanged)

### Migration notes

Public API additions (no breakage):
- `mosaic_groth16::canonical::BN254_FR_MODULUS_BE` continues to
  resolve (now via re-export). External consumers that import
  via this path are unaffected.
- `mosaic_groth16::canonical::lt_be` continues to resolve.
- New: `mosaic_groth16` now transitively re-exports
  `mosaic_zk_primitives::fr::lt_r` via the canonical re-export
  chain.

The `mosaic-groth16/Cargo.toml` change adds an explicit dep that
was already pulled in transitively. No new compile-time deps land
in any downstream crate.

## [0.8.17-audit-gate-benches] — 2026-04-26

**Per-audit-gate criterion bench coverage.** Session 97 adds a
new `audit_gates_host` criterion bench that times each Phase-3
audit gate in isolation. Complements the existing `phase3_host`
bench (which times each verifier's `verify` end-to-end) so
algorithmic regressions inside a gate body surface separately
from regressions in the parsing / transcript / Merkle pipelines.

### Added — session 97

#### `crates/mosaic-bench/benches/audit_gates_host.rs` (new bench)

Five criterion bench functions across the four Phase-3 audit
gates:

| Bench | Audit gate | Fixture |
|---|---|---|
| `nova_consistency_gate_host_honest` | `verify_folding_consistency` | G1 generator at base_e_1 + base_w_1; honest reconstruction |
| `halo2_lookup_gate_host_arity_1_honest` | `verify_multi_column_lookup_identity` | matching column at arity 1 |
| `halo2_lookup_gate_host_arity_4_honest` | `verify_multi_column_lookup_identity` | matching columns at arity 4 (surfaces θ-power growth) |
| `stark_fri_query_gate_host_1_layer_honest` | `verify_fri_query` | honest 1-layer fold of `p(t) = c_0 + c_1·t` |
| `hyperplonk_claim_reduction_gate_host_zero_baseline` | `verify_sumcheck_claim_reduction` | zero `final_evals` ⇒ expected claim 0 |

Each bench builds a minimum honest fixture matching the gate's
unit-test happy-path inputs and times the gate call alone. The
two arity variants on the Halo2 lookup bench make θ-power-cost
growth visible (arity-1 has 1 θ-power; arity-4 has 4 θ-powers
plus a 4-element inner product on each side).

#### Phase-2 omission (intentional, matching session 95)

Groth16 and PLONK pairing-identity gates are not benchmarked at
the gate level because their wall-clock is dominated by the
alt_bn128 pairing syscall (already captured by the existing
`groth16_host` bench). The gate-level bench would just be
"syscall cost + 5 ns of byte-comparison" — no useful signal.

### Why isolate gate benches

| Need | Pre-session-97 | Post-session-97 |
|---|---|---|
| End-to-end verifier wall-clock | `phase3_host` | `phase3_host` (unchanged) |
| Per-gate algorithmic regression detection | masked inside `phase3_host` noise | `audit_gates_host` |
| CU budget allocation per soundness boundary | manual estimation | `audit_gates_host` numbers |
| External-auditor "what does this gate cost?" | grep code, estimate | `cargo bench` then read |

### Reproduce locally

```bash
cargo bench -p mosaic-bench --bench audit_gates_host
```

Expected output: 5 named bench results with criterion's
statistical noise floor (mean ± 2σ). First run takes ~3 min
to compile in `bench` profile; subsequent runs reuse the
compiled binary.

### Bench inventory at v0.8.17

| Bench file | Targets | Coverage |
|---|---|---|
| `groth16_host` | 1 | Phase-1 Groth16 verify end-to-end |
| `phase3_host` | 4 | Phase-3 verify end-to-end (one per system) |
| `audit_gates_host` | 5 | Phase-3 audit gates in isolation (session 97) |

### Lib test totals at v0.8.17

Unchanged from v0.8.16 (616). Pure bench-coverage release.

### Migration notes

No code changes to verifier crates. The bench file is purely
additive. Existing bench invocations
(`cargo bench -p mosaic-bench --bench {groth16_host,phase3_host}`)
continue to work unchanged.

## [0.8.16-fuzz-ci-wiring] — 2026-04-26

**Closes the v0.8.15 CI loose end.** Session 96 wires the 4 new
audit-gate fuzz harnesses (added in session 95) into both the PR
and nightly fuzz CI matrices. The v0.8.15 release notes flagged
this as "tracked separately"; v0.8.16 lands it.

### Changed — session 96

#### `.github/workflows/fuzz.yml` matrix expansion

The PR fuzz matrix grows from 8 → 12 harnesses (5 min each ⇒ 60
min total wall-clock with parallel runners). All four new
audit-gate harnesses run on every PR because:

> A regression in an audit gate is a soundness regression and
> should fail PR CI, not wait for nightly.

The nightly fuzz matrix grows from 23 → 27 harnesses (60 min each).
With GitHub's free-tier 20-runner concurrency limit, the matrix
finishes in 1-2 batches as before.

#### Workflow header comments updated

The PR-mode and nightly-mode banner comments now reference the
session-95 expansion explicitly so a future contributor can
understand at a glance which harnesses cover which surfaces.

### CI matrix at v0.8.16

| Mode | Harnesses | Wall-clock per harness | Total parallel wall-clock |
|---|---|---|---|
| PR (per PR) | 12 | 5 min | ~60 min |
| Nightly (cron) | 27 | 60 min | ~27 h (1-2 batches) |

### Lib test totals at v0.8.16

Unchanged from v0.8.15 (616). Pure CI configuration release.

### Migration notes

No code changes. The CI workflow change is purely additive.
Existing PR runs that were on v0.8.15 will continue to use the
v0.8.15 matrix; new PRs after v0.8.16 will pick up the expanded
matrix automatically (workflow files are read from the PR head).

## [0.8.15-audit-gate-fuzz] — 2026-04-26

**Audit-gate algebraic surface fuzz coverage.** Session 95 adds 4
new cargo-fuzz harnesses, one per Phase-3 audit gate that has a
wide-enough algebraic input surface to benefit from fuzz coverage.
The existing 23 fuzz harnesses (sessions ≤ 59) cover the verifiers'
outer parsing surfaces; the new 4 cover the algebraic soundness
boundaries directly.

### Added — session 95

#### Four new audit-gate fuzz harnesses

| Harness | Audit gate | Input surface |
|---|---|---|
| `fuzz_nova_consistency_gate` | `verify_folding_consistency` | 7 × 64 G1 + 32 Fr = 480 B |
| `fuzz_halo2_lookup_gate` | `verify_multi_column_lookup_identity` | variable arity (1..=8) × 32 Fr |
| `fuzz_stark_fri_query_gate` | `verify_fri_query` | variable layers (0..=8) × 16 Goldilocks + final-poly bytes |
| `fuzz_hyperplonk_claim_reduction_gate` | `verify_sumcheck_claim_reduction` | 12-slot final_evals + α/β/γ + VK cosets + claim |

Every harness asserts the same panic-free invariant: the gate must
return `Ok(())` or `Err(OnChainError::*)` — never panic. Catches:
- Syscall payload mishandling that could panic in arkworks
- Fr deserialization edge cases at the boundary of the field modulus
- Byte-slice boundary issues at the gate's input surface
- Goldilocks reduction edge cases (STARK fuzzer)

#### The Phase-2 omission (intentional)

The Phase-2 pairing-identity gates (Groth16 / PLONK
`verify_*_pairing_identity`) are NOT fuzzed at the gate level.
Their algebraic surface reduces to the syscall verdict byte
(`0x01` ⇒ accept, anything else ⇒ reject), which has zero useful
fuzz-discoverable space. The syscall layer itself is already
covered by the existing `fuzz_groth16_*` and `fuzz_plonk_*`
outer-surface harnesses.

#### Documentation updates

- `mosaic-fuzz/src/lib.rs` docstring expanded with the session-95
  inventory plus an explicit statement of why Phase-2 gates are
  not fuzzed. New "Total inventory at session 95" line: 27
  harnesses (23 outer + 4 audit-gate).
- `mosaic-fuzz/Cargo.toml` adds `[[bin]]` entries for the 4 new
  harnesses, gated under a session-95 banner comment.

### Inventory at v0.8.15

| Category | Harness count |
|---|---|
| Original Groth16 outer (sessions ≤ 54) | 3 |
| Phase-2 + Phase-3 verifier outer (sessions 54-59) | 20 (5 systems × 4 surfaces) |
| **Audit-gate algebraic (session 95)** | **4** |
| **Total** | **27** |

### Lib test totals at v0.8.15

  mosaic-core              16
  mosaic-zk-primitives     87
  mosaic-groth16           31
  mosaic-plonk             38
  mosaic-hyperplonk        88
  mosaic-halo2             97
  mosaic-nova              73
  mosaic-stark            123
  mosaic-serde             23
  mosaic-chunked           20
  mosaic-sdk               13
  mosaic-program            7
  ─────────────────────  ───
  total                   616  (unchanged from v0.8.14; new content is fuzz harnesses, not lib tests)

### Migration notes

No code changes to verifier crates. Pure expansion of the fuzz
harness inventory. Existing 23 fuzz harnesses continue to work
unchanged. New harnesses are runnable via standard cargo-fuzz
invocations:

```bash
cargo +nightly fuzz run fuzz_nova_consistency_gate
cargo +nightly fuzz run fuzz_halo2_lookup_gate
cargo +nightly fuzz run fuzz_stark_fri_query_gate
cargo +nightly fuzz run fuzz_hyperplonk_claim_reduction_gate
```

CI workflow updates (to add the 4 new harnesses to the nightly
fuzz matrix) tracked separately.

## [0.8.14-plonk-audit-gate] — 2026-04-26

**Phase-2 audit-gate symmetry complete.** Session 94 lands the
PLONK audit-gate alias, completing the ADR-0006 4-way matrix
across Groth16 + KZG-PLONK (Phase-2) and Nova + Halo2 + STARK +
HyperPlonk (Phase-3). Every production verifier in the workspace
now exposes a named, publicly callable `verify_*` audit gate
following the same recipe.

### Audit-gate matrix at v0.8.14 — every production verifier covered

| Track | Verifier | Audit gate | Tag |
|---|---|---|---|
| Phase-2 | Groth16 BN254 | `verify_groth16_pairing_identity` | v0.8.13 |
| Phase-2 | KZG-PLONK BN254 | `verify_plonk_pairing_identity` | v0.8.14 |
| Phase-3 | Nova / HyperNova / ProtoStar | `verify_folding_consistency` | v0.8.6 |
| Phase-3 | Halo2-KZG (lookup) | `verify_multi_column_lookup_identity` | v0.8.8 |
| Phase-3 | FRI-STARK (per-query) | `verify_fri_query` | v0.8.10 |
| Phase-3 | HyperPlonk-KZG | `verify_sumcheck_claim_reduction` | v0.8.11 |

External auditors run `git grep '^pub fn verify_'` in
`crates/mosaic-{groth16, plonk, nova, halo2, hyperplonk, stark}/src/`
to find every soundness boundary across the workspace by name.

### Added — session 94

#### `verify_plonk_pairing_identity` audit gate (mosaic-plonk::linearization)
ADR-0006-named alias for the existing `verify_pairing` function.
Both names are byte-equivalent wrappers — the new name follows
the workspace-wide `verify_<verifier>_<domain>` convention so an
auditor scanning for soundness boundaries finds it without
knowing the verifier-specific naming history.

The `verify_pairing` function continues to be exported and
called internally by `finalize_verify`; the alias is purely
additive. The byte-equivalence is pinned by the new
`audit_gate_equivalent_to_verify_pairing` test that exercises
both functions with the same backend + inputs and asserts
identical Ok/Err outcomes across 4 verdict bytes.

#### `ProgrammablePairingBackend` test helper (linearization::tests)
Mirror of the session-93 helper added in mosaic-groth16. Returns
configurable pairing-syscall verdicts so the gate's success/
failure branches can be exercised without real BN254 arithmetic
or differential-test fixtures.

### New tests at v0.8.14 (mosaic-plonk: 32 → 38)

Audit-gate unit tests (6):
- `audit_gate_accepts_when_pairing_returns_success_byte`
- `audit_gate_rejects_when_pairing_returns_failure_byte`
- `audit_gate_rejects_any_non_one_verdict_byte`
- `audit_gate_rejects_wrong_length_pairing_payload`
- `audit_gate_propagates_syscall_error`
- `audit_gate_equivalent_to_verify_pairing`
  (pins byte-equivalence between alias and original across 4
  representative verdict bytes)

### ADR-0006 instance table extended

The Phase-2 section of the ADR now has both Groth16 and PLONK
rows. Test-suite breakdown updated to 6 audit gates totaling
**39 audit-gate-related tests** across the workspace.

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
  total                   616  (+6 since v0.8.13)

### Migration notes

Public API additions (no breakage):
- `mosaic_plonk::verify_plonk_pairing_identity` (new ADR-0006-named alias)
- `mosaic_plonk::verify_pairing` re-exported from crate root
  (was already pub but only via `linearization::` path)

Wire format and on-chain ABI unchanged. The `finalize_verify`
function still calls `verify_pairing` internally; the alias is
purely additive for external API consistency.

## [0.8.13-groth16-audit-gate] — 2026-04-26

**ADR-0006 pattern lands in Phase-2.** Session 93 extracts the
first Phase-2 audit gate — `verify_groth16_pairing_identity` —
following the recipe codified in ADR-0006. The Groth16 verifier's
pairing-equation soundness boundary is now a named, publicly
callable function with 5 dedicated unit tests, mirroring the
sessions 86 → 91 work on Phase-3 verifiers.

Plus a companion fix for the canonical.rs standalone-test quirk
(`vec!` macro not in scope under no_std default features), the
same fix pattern as session 91B's goldilocks fix.

### Added — session 93

#### `verify_groth16_pairing_identity` audit gate (mosaic-groth16::verifier)
Generic over the syscall backend `B` and endianness flag `LE`.
Takes 8 byte slices (proof's A/B/C, the L input commitment, and
the VK's α/β/γ/δ pairs) plus the backend, internally negates A,
assembles the 4-pair pairing input (768 bytes), executes the
`alt_bn128(Pairing)` syscall, and rejects any result that's not
the Fq12 identity (32 bytes ending in `0x01`) as
`OnChainError::PairingCheckFailed`.

This is the audit-grade "is the prover's `(A, B, C)` triple
consistent with the VK at this public-input commitment?" check —
the **only** soundness boundary in Groth16 (the rest of the
verifier is parsing + linear combination + length validation).

#### Verifier-side migration
`Groth16Verifier::verify` now collapses the inline negate-A +
4-pair assembly + result-byte check pattern into a single
`verify_groth16_pairing_identity::<B, LE>(...)` call. The
verifier's `verify` body shrinks by ~25 lines while remaining
byte-equivalent (verified by the existing 26 lib tests + the
SBF integration tests passing across the migration).

#### Standalone-test parity fix (canonical.rs)
The pre-existing `canonical::tests` mod used bare `vec![...]`
which only resolves under std prelude. Workspace-level test
runs masked this with feature unification; standalone
`cargo test -p mosaic-groth16 --lib` failed. Session 93 adds
`use alloc::vec;` for parity, mirroring session 91B's
goldilocks fix. Standalone now passes 26 → 31 tests.

### New tests at v0.8.13 (mosaic-groth16: 26 → 31)

Audit-gate unit tests (5):
- `audit_gate_accepts_when_pairing_returns_success_byte`
- `audit_gate_rejects_when_pairing_returns_failure_byte`
- `audit_gate_rejects_any_non_one_verdict_byte`
  (sweeps 6 representative non-`0x01` bytes)
- `audit_gate_rejects_wrong_length_pairing_payload`
  (catches the failure mode where syscall returns < 32 bytes)
- `audit_gate_propagates_syscall_error`
  (confirms gate doesn't collapse upstream errors to PairingCheckFailed)

These tests use a `ProgrammablePairingBackend` that returns
configurable pairing verdicts, exercising the gate's success/
failure branches without pulling in real BN254 arithmetic.
End-to-end coverage against real BN254 fixtures continues via
the existing `tests/differential/` suite.

### ADR-0006 instance table extended

The ADR now has separate Phase-2 and Phase-3 sections in the
"Pattern instances" table, with Groth16 listed as the first
Phase-2 instance. PLONK is listed in the
"Planned beyond v0.8.13" block as the next ADR-0006 target on
the Phase-2 track.

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
  total                   610  (+5 since v0.8.12)

### Migration notes

Public API additions (no breakage):
- `mosaic_groth16::verify_groth16_pairing_identity` (new)

Wire format and on-chain ABI unchanged. The `Groth16Verifier::verify`
behaviour is byte-identical at the pairing-check step.

## [0.8.12-audit-gate-adr] — 2026-04-26

**Audit-gate pattern ADR-0006 lands.** Session 92 codifies the
extraction recipe that emerged across sessions 86 → 91 (Nova →
Halo2 → STARK → HyperPlonk audit-gate extractions) into a formal
architectural decision record so future verifier additions follow
the same contract. Plus updates to two related design docs that
external auditors land on first.

### Added — session 92

#### `docs/adr/0006-verifier-audit-gate-pattern.md` (new ADR)
Documents the audit-gate extraction pattern with:
- The recipe template (function signature + companion tests +
  lib.rs re-export + audit-pack quartet sync).
- The pattern instances at v0.8.11 (4 Phase-3 verifiers + the
  bridge/binding work in sessions 87/89).
- Test-suite breakdown (37 audit-gate-related tests across the
  campaign).
- A consequences section (positive / negative / neutral).
- A "recipe for adding a new verifier" checklist for future
  contributors adding e.g. `mosaic-bulletproofs` or `mosaic-fflonk`.
- Cross-references to `audit-coverage-runbook.md`,
  `phase3-soundness.md`, `AUDIT.md`, `CHANGELOG.md`.

#### `docs/phase3-soundness.md` updated
Header bumped from `v0.7.0-phase3-primitives` to
`v0.8.11-hyperplonk-audit-gate`. New "Phase-3 audit-gate matrix"
section at the top points external auditors directly at the four
named `verify_*` audit gates as the canonical entry points for
soundness review. Mentions the session-87 soundness fix
explicitly (the folding-challenge `r` was not bound to the four
pre-fold base commits in the Fiat-Shamir transcript).

#### `docs/audit-coverage-runbook.md` updated
Coverage matrix header bumped to v0.8.11. New "Phase-3 audit
gate quick-reference" section with one-row-per-gate cheatsheet:
crate path + test count + tag.New "Reproduce: run all four
audit-gate test suites" section with copy-pasteable cargo test
commands targeting just the gate test mods.

### Why this matters for an external audit firm

The campaign across sessions 86 → 91 added 4 audit-gate primitives
across 4 Phase-3 verifiers. Without ADR-0006 those would be 4
isolated extractions in the git history — discoverable but not
formally named. With ADR-0006 they're a documented architectural
pattern that:

1. External reviewers can grep for (`pub fn verify_*` in
   `crates/mosaic-{nova,halo2,hyperplonk,stark}`) to find every
   soundness boundary.
2. Future contributors know to follow when adding a new verifier
   crate.
3. Tooling (e.g. CI smoke tests, doc generators) can rely on as a
   workspace-wide invariant.

### Lib test totals at v0.8.12

  mosaic-core              16
  mosaic-zk-primitives     87
  mosaic-groth16           26
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
  total                   605  (unchanged from v0.8.11; docs-only release)

### Migration notes

No code changes; pure documentation release. Wire format,
on-chain ABI, public API, and verifier behaviour are all
unchanged.

## [0.8.11-hyperplonk-audit-gate] — 2026-04-26

**Phase-3 audit-gate symmetry complete.** Session 91 lands the
final named audit gate of the Phase-3 verifier family —
`verify_sumcheck_claim_reduction` for HyperPlonk — completing the
4-way symmetry across Nova / Halo2 / STARK / HyperPlonk. Plus a
companion goldilocks test fix lifts a long-standing standalone-
test quirk.

### Audit-gate matrix at v0.8.11

| Verifier | Audit gate | Session |
|---|---|---|
| Nova | `verify_folding_consistency` | 86 |
| Halo2 lookup | `verify_multi_column_lookup_identity` | 88 |
| STARK FRI | `verify_fri_query` | 90 |
| **HyperPlonk** | **`verify_sumcheck_claim_reduction`** | **91** |

Every Phase-3 verifier now exposes its primary soundness check
as a named, publicly callable function. External auditors get a
consistent vocabulary: `verify_*` functions across the workspace
are the soundness boundaries to focus on.

### Added — session 91A (HyperPlonk audit gate)

#### `verify_sumcheck_claim_reduction` (mosaic-hyperplonk::verifier)
Pub function that recomputes the expected sumcheck final-claim
from `(final_evals, challenges, vk)` and byte-compares it
against the sumcheck protocol's actual final claim. Rejects
disagreements as `OnChainError::SumcheckFailed`. Inputs validated
upstream via `compute_expected_final_claim` (which is also
promoted to `pub` for direct auditor access).

#### Verifier-side migration
`HyperPlonkKzgBn254::verify` step 4 (claim reduction) collapses
from a 4-line inline pattern (recompute + byte-compare +
SumcheckFailed return) to a single `verify_sumcheck_claim_reduction(...)?`
call. Existing tests stay green; the refactor is byte-equivalent.

### Added — session 91B (goldilocks test fix)

#### Explicit `alloc::vec::Vec` import in `goldilocks::tests`
The pre-existing test mod (sessions 10, 14a) used bare
`Vec::new()` which assumed the std prelude. Under workspace-
level `cargo test` the std feature unification masked this; under
standalone `cargo test -p mosaic-stark --lib` (no_std default
features) the tests failed to compile. Session 91B adds the
explicit `use alloc::vec::Vec` so both test invocations work.

### New tests at v0.8.11 (mosaic-hyperplonk: 82 → 88)

Audit-gate unit (4):
- `audit_gate_accepts_zero_baseline`
- `audit_gate_rejects_wrong_sumcheck_final_claim`
- `audit_gate_propagates_short_evals_buffer`
- `audit_gate_propagates_empty_evals_buffer`

Audit-gate proptest (2):
- `proptest_audit_gate_accepts_zero_baseline`
  (random α/β/γ × zero evals × zero sumcheck claim → accept)
- `proptest_audit_gate_rejects_nonzero_sumcheck_claim`
  (zero evals → expected claim 0 → any non-zero sumcheck claim
  must reject)

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
  total                   605  (+6 since v0.8.10)

### Migration notes

Public API additions (no breakage):
- `mosaic_hyperplonk::compute_expected_final_claim` (was private)
- `mosaic_hyperplonk::verify_sumcheck_claim_reduction` (new)

Wire format and on-chain ABI unchanged. Verifier behaviour at
the claim-reduction step is byte-identical (refactor only).
The standalone `cargo test -p mosaic-stark --lib` invocation
that was previously broken now passes — useful for incremental
development against a single crate.

## [0.8.10-stark-fri-audit-gate] — 2026-04-26

**STARK FRI per-query audit gate extraction.** Session 90
collapses the verifier's inline `verify_fold_chain + eval_poly +
compare` pattern into a single named primitive
`verify_fri_query`, mirroring the session-86 Nova
`verify_folding_consistency` extraction. External auditors
reading the FRI verification loop now see one named function
call instead of three lines of inline pattern.

### Added — session 90

#### `verify_fri_query` audit gate (mosaic-stark::fri)
High-level per-query soundness gate that:
1. Walks the fold chain via `verify_fold_chain`
2. Evaluates the proof's `fri_final_poly` at the chain's final x
3. Rejects as `OnChainError::VerificationFailed` if the chain's
   computed final value disagrees with the final-poly evaluation

Inputs: `layer_evals`, `betas`, `initial_x`, plus the proof's
`fri_final_poly_le_bytes`. Errors propagate cleanly:
`ProofLengthMismatch` (length disagreements), `InternalInvariantViolation`
(fold arithmetic degeneracy), `VerificationFailed` (the soundness
mismatch — the per-query check's primary "this proof is wrong"
signal).

#### Verifier-side migration (mosaic-stark::verifier)
The per-query loop in `FriStark::verify` (sessions ≤89: 4 lines
of inline pattern per iteration) collapses to a single
`verify_fri_query(layer_evals, &betas, x_0, proof.fri_final_poly)?`
call. Existing per-query Merkle-authentication block remains
unchanged.

### New tests at v0.8.10 (mosaic-stark: 117 → 123)

Audit-gate unit (5):
- `verify_fri_query_accepts_honest_tuple`
- `verify_fri_query_rejects_tampered_final_poly`
- `verify_fri_query_rejects_tampered_layer_eval`
- `verify_fri_query_propagates_length_mismatch`
- `verify_fri_query_zero_layer_chain_corner`

Audit-gate proptest (1):
- `prop_verify_fri_query_accepts_honest_1_layer_fold`
  (random degree-1 polynomial × random β × random x → encode
  symbolic post-fold constant as final-poly → must accept)

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
  total                   599  (+6 since v0.8.9)

### Migration notes

Public API additions (no breakage):
- `mosaic_stark::verify_fri_query`
- Re-exported from crate root.

The wire format and on-chain ABI are unchanged. The verifier
behaviour at the per-query level is byte-identical: the
extraction is a refactor that surfaces the audit story more
clearly without changing the soundness checks themselves.

## [0.8.9-halo2-lookup-bridge] — 2026-04-26

**Single-column → multi-column lookup bridge.** Session 89 lands
the backward-compatibility bridge between the existing scaffold
`LookupEvals` (single-column, used by the current Halo2
verifier) and the new session-88 `MultiColumnLookupEvals` audit-
gate API. Any future verifier path that wants to unify single-
column and multi-column lookup soundness under
`verify_multi_column_lookup_identity` can now do so without
touching the wire format.

### Added — session 89

#### `MultiColumnLookupEvals::from_basic` constructor
Lifts a `LookupEvals` into the equivalent arity-1 multi-column
form. Algebraically transparent — the θ-power vector at arity 1
is `[θ⁰] = [1]`, so input_combined = input and table_combined
= table; the blinder `θ^k = θ¹ = θ` matches the basic form's
additive blinder exactly.

#### `From<LookupEvals> for MultiColumnLookupEvals` impl
Trait-flavored sugar over `from_basic`. Idiomatic call site
becomes `let lifted: MultiColumnLookupEvals = basic.into();`.

#### Backward-compatibility soundness pin
The `prop_basic_lookup_promotes_to_multi_arity_1` proptest pins
the byte-level equivalence: for every (input, table, m, θ) with
non-degenerate denominators,
`lookup_expr(&basic, θ) == multi_column_lookup_expr(&basic.into(), θ)`.
This is the load-bearing invariant for any future verifier
unification — the bridge cannot drift without the proptest
firing first.

#### Audit-gate equivalence pin
The `prop_audit_gate_accepts_satisfying_basic_promotion` proptest
constructs a satisfying basic tuple (m chosen so the basic
identity vanishes), promotes it to the multi-column form, and
verifies the audit gate accepts. Confirms the soundness contract
carries through the bridge end-to-end.

### New tests at v0.8.9 (mosaic-halo2: 93 → 97)

Bridge unit (2):
- `from_basic_preserves_fields`
- `from_trait_matches_from_basic`

Bridge proptest (2):
- `prop_basic_lookup_promotes_to_multi_arity_1`
- `prop_audit_gate_accepts_satisfying_basic_promotion`

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
  total                   593  (+4 since v0.8.8)

### Migration notes

Public API additions (no breakage):
- `mosaic_halo2::MultiColumnLookupEvals::from_basic`
- `From<LookupEvals> for MultiColumnLookupEvals`

The wire format and on-chain ABI are unchanged. The bridge is
purely additive — the existing single-column verifier path
continues to call `lookup_expr` unchanged.

## [0.8.8-halo2-lookup-audit-gate] — 2026-04-26

**Halo2 multi-column lookup hardening.** Session 88 corrects an
incorrect docstring claim, adds a defensive θ=0 check, extracts
a high-level audit-gate function, and lands a 3-property proptest
soundness suite for the multi-column log-derivative lookup
reduction added in session 85.

### Added — session 88

#### `MultiColumnLookupEvals::try_new` safe constructor
Validates wire-shape invariants (non-empty + arity match) at
construction time so callers parsing proof bytes can fail at
parse time, not at evaluation time. Companion `arity()` accessor
returns the column count for downstream sizing decisions.

#### `verify_multi_column_lookup_identity` audit gate
High-level soundness check that runs `multi_column_lookup_expr`
and rejects non-zero results as `OnChainError::SumcheckFailed`
(consistent with Nova's Hadamard residual error). Extraction
mirrors the session-86 `verify_folding_consistency` pattern:
auditors get one named function to read for "this is the lookup
soundness check" instead of an inline `expr == 0` ad-hoc check
scattered through the verifier.

#### θ=0 defensive check (mosaic-halo2::circuit)
`multi_column_lookup_expr` now rejects `θ = 0` up-front with
`InternalInvariantViolation`. Without this, the blinder
`θ^k = 0` collapses and the column-distinguishing θ-power
weighting degenerates (every column weight becomes 0 except the
leading one). The Fiat-Shamir transcript is constructed to make
`θ = 0` computationally infeasible, but defense-in-depth catches
a hypothetical transcript bug at the soundness boundary instead
of at the inverse fault, giving a clearer audit trail.

#### Doc-correction on the multi-column module
The session-85 docstring previously claimed `Σ_X m(X) = 0` as
the lookup-soundness sum identity. **That is incorrect** — in a
satisfying log-derivative lookup, `Σ_X m(X) = N` (the input row
count, since each input row contributes one to its matched
table row's multiplicity). The corrected docstring states the
real identity:

```text
Σ_{X ∈ H} [m(X)·(table_combined(X) + θ^k)⁻¹
         − (input_combined(X) + θ^k)⁻¹] = 0
```

and explains that the vanishing polynomial check
(`t(ξ)·Z_H(ξ) == combined_expr(ξ)`) handles the sum-over-domain
piece implicitly via the `y²·lookup_expr` weighting.

### New tests at v0.8.8 (mosaic-halo2: 80 → 93)

Constructor (4 unit):
- `try_new_accepts_arity_1`
- `try_new_accepts_arity_5`
- `try_new_rejects_empty`
- `try_new_rejects_arity_mismatch`

θ=0 defensive check (2 unit):
- `multi_column_lookup_rejects_theta_zero`
- `multi_column_lookup_rejects_theta_zero_even_for_satisfying_tuple`

Audit gate (4 unit + 3 proptest):
- `verify_lookup_identity_accepts_satisfying_tuple`
- `verify_lookup_identity_rejects_non_satisfying_tuple`
- `verify_lookup_identity_propagates_input_validation_errors`
- `verify_lookup_identity_propagates_theta_zero`
- `proptest_audit_gate_accepts_matching_columns`
  (random arity 1..=8, random θ ≠ 0, satisfying tuple → accept)
- `proptest_audit_gate_rejects_single_column_mismatch`
  (random arity 2..=8, random tampered column → reject as SumcheckFailed)
- `proptest_audit_gate_rejects_wrong_multiplicity`
  (random arity, m ≠ 1 with matching columns → reject as SumcheckFailed)

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
  total                   589  (+13 since v0.8.7)

### Migration notes

Public API additions (no breakage):
- `mosaic_halo2::MultiColumnLookupEvals::try_new`
- `mosaic_halo2::MultiColumnLookupEvals::arity`
- `mosaic_halo2::verify_multi_column_lookup_identity`

The wire format and on-chain ABI are unchanged. The new θ=0
check in `multi_column_lookup_expr` is technically a behaviour
change at the API boundary (previously θ=0 would have failed at
the inverse computation with the same error type), but every
existing test fixture uses transcript-derived θ values which
are computationally guaranteed to be non-zero.

## [0.8.7-nova-base-commit-binding] — 2026-04-26

**Closes a soundness hole introduced in v0.8.6.** The
`verify_folding_consistency` audit gate added in session 86 is
only meaningful if the folding challenge `r` is **bound to the
four pre-fold base commitments** in the Fiat-Shamir transcript.
Sessions ≤86 derived `r` from `(VK, public_inputs, e_comm,
w_comm, t_comm)` only — leaving the prover free to back-solve
`(base_e_1, base_e_2, base_w_1, base_w_2)` post-hoc to make the
gate pass for any chosen `(e_comm, w_comm, t_comm)`.

Session 87 adds the four base-commit absorbs to round 1 of
`derive_challenges` so `r` now binds to all 7 G1 inputs of the
audit gate. By Schwartz-Zippel + DLOG hardness, constructing a
non-honestly-folded passing tuple now requires either an honest
fold step or a discrete-log-equivalent attack.

### Added — session 87

#### Round-1 absorb extension (mosaic-nova::challenges)
The `derive_challenges` round-1 transcript now absorbs the 4
pre-fold base commitments (4 × 64 = 256 additional bytes) before
squeezing `r`. The module-level absorb-order docstring is updated
to reflect the new contract. Existing `r` values change for every
input (the change adds new bytes at the end of round 1) but every
relative property (determinism, cascade, distinctness) is
preserved — all 12 pre-existing challenges-module tests stay
green without modification.

#### `proptest_base_commit_mutation_cascades` (challenges.rs)
Audit-grade soundness invariant: tampering any byte of any of
the 4 base commits (4 slots × 64 bytes × 8 bits = ~2 K mutation
points) MUST shift `r`, and the shift cascades into ξ and ν.
This is the regression guard that fires if a future refactor
removes any of the 4 absorbs — the assertion explicitly calls
out that "missing absorb breaks the fold-consistency soundness
gate" so the failure message is self-explanatory at audit review.

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

### Migration notes

**Behaviour change.** Every Nova / HyperNova / ProtoStar challenge
tuple `(r, ξ, ν)` produced by `derive_challenges` after this
release differs from sessions-≤86 outputs because round 1 now
absorbs 256 additional bytes (the 4 base commits). External
consumers must re-derive any persisted `r`, `ξ`, `ν` cache.
On-chain wire format and proof byte layout are unchanged —
only the challenge derivation rule shifts.

The pre-existing `rejects_tampered_base_e_commitment` integration
test continues to pass because the audit gate still computes E
from the (now-tampered) base_e_1 and rejects on byte mismatch —
session 87 strengthens *why* this rejection is meaningful, not
*whether* it fires.

## [0.8.6-nova-folding-consistency] — 2026-04-26

**Nova fold-reconstruction audit gate extracted + tightened.**
Session 86 lifts the inline `E_folded` / `W_folded` reconstruction
check from `mosaic-nova::verifier::NovaFolding::verify` into a
named, well-documented `verify_folding_consistency` primitive in
`mosaic-nova::folding`, and **promotes the `W` formula from the
placeholder 3-term to the canonical 2-term**:

```text
E_folded ?= E_1 + r·E_2 + r²·T   (3-term, error vector)
W_folded ?= W_1 + r·W_2          (2-term, witness)
```

The two formulas differ because under canonical Nova relaxed-R1CS
the witness vector folds linearly while the error vector picks
up the quadratic cross-term `r²·T` from the relation expansion.
Sessions ≤85 used the 3-term form for both `E` and `W` — that was
algebraically equivalent only because every scaffold fixture has
`T = 0` (the squared `r²·T` vanishes). Switching `W` to the
canonical 2-term tightens the soundness contract for future
fixtures with non-zero cross-terms.

The new `verify_folding_consistency` primitive validates all 7
G1 input slices up-front (single rejection point with uniform
`InvalidPointEncoding` before any syscall fires), then delegates
to `folded_commitment_from_fold` (3-term, for E) and the new
`folded_commitment_two_term` (2-term, for W). The verifier-side
call site shrinks from a 22-line inline duplicated-pattern block
to a single 11-arg primitive call.

### Added — session 86

#### `folded_commitment_two_term` primitive (mosaic-nova::folding)
2-term linear combiner `C_1 + r·C_2` for the canonical Nova
witness folding. Mirrors `folded_commitment_from_fold`'s API
(64-byte G1 inputs, scalar `r`, returns 64-byte folded commit)
but cheaper because there's no squared MSM. 4 unit tests:

- `folded_two_term_zero_r_is_just_c1` (boundary)
- `folded_two_term_identity_inputs_is_identity` (boundary)
- `folded_two_term_rejects_wrong_length` (length validation)
- `folded_two_term_matches_three_term_with_zero_t`
  (cross-check vs. existing 3-term primitive at T=0)

#### `verify_folding_consistency` audit gate (mosaic-nova::folding)
High-level dual-reconstruction check that takes the proof's 4
base commits + cross-term + 2 declared commits + the folding
challenge and rejects any divergence between reconstructed and
declared `e_comm` / `w_comm` as `OnChainError::VerificationFailed`.
Replaces the inline duplicated-pattern block in `verifier.rs`.
5 unit + 4 proptest:

- `folding_consistency_identity_baseline_accepts`
- `folding_consistency_generator_baseline_accepts`
- `folding_consistency_rejects_tampered_e_comm`
- `folding_consistency_rejects_tampered_w_comm`
- `folding_consistency_rejects_short_inputs` (sweeps all 7 slots)
- `proptest_accepts_correctly_folded_tuple` (round-trip identity)
- `proptest_rejects_e_comm_swap`
- `proptest_rejects_w_comm_swap`
- `proptest_rejects_any_base_or_cross_tamper` (5-slot sweep)

#### Verifier-side migration (mosaic-nova::verifier)
`NovaFolding::verify` now calls `verify_folding_consistency`
instead of inlining two `folded_commitment_from_fold` calls + two
byte-comparisons + two `VerificationFailed` returns. The
existing `rejects_tampered_base_e_commitment` integration test
continues to pass (the audit gate is byte-equivalent on
`base_e_1` tampering against the original inline path).

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
  total                   575+ workspace-wide

### Migration notes

Public API additions (no breakage):
- `mosaic_nova::folded_commitment_two_term`
- `mosaic_nova::verify_folding_consistency`

The verifier's wire format and on-chain ABI are unchanged. The `W`
formula switch from 3-term to 2-term is **byte-identical for every
existing test fixture** because all scaffold fixtures have `T = 0`.
External consumers running the verifier against well-formed
sessions-≤85 fixtures see no behaviour change.

## [0.8.5-msm-helper-coverage] — 2026-04-28

**Last batched-opening inline pattern lifted.** Sessions 80-83
add the 11th shared primitive (`msm_g1_fr`), migrate every
remaining inline weighted-MSM site in the workspace, and finish
the deferred-from-s77 `fr_inner_product` Nova migration.

After v0.8.5 the batched-opening stage in HyperPlonk + Halo2 +
Nova is fully delegated to the shared primitives — five primitive
calls cover what used to be ~40 lines of inline arithmetic per
verifier:

```text
let nu_powers = powers_of(&nu, n);
let c_batched = msm_g1_fr(backend, points, &nu_powers)?;
let y_batched = fr_inner_product(&nu_powers[..len], evals)?;
let a1        = compute_kzg_opening_lhs(backend, &c_batched, ...)?;
verify_two_pair_pairing(backend, &a1, ...)?;
```

| Surface | v0.8.4 | v0.8.5 |
|---|---|---|
| Shared primitives | 10 | **11** |
| msm_g1_fr consumer migrations | 0 | 4 sites |
| fr_inner_product consumer migrations | 3 | 4 sites |

The 4 new msm_g1_fr consumer sites:
- mosaic-hyperplonk::kzg                              (s82)
- mosaic-halo2::kzg::verify_two_point ξ-side          (s83)
- mosaic-halo2::kzg::verify_two_point ξω-side         (s83)
- mosaic-nova::kzg::verify_spartan                    (s83)

The 1 new fr_inner_product consumer (deferred from s77):
- mosaic-nova::kzg::verify_spartan y-batched          (s80)

No on-chain ABI or behaviour changes — refactor + tests + docs
only. Every byte-identical refactor verified by the existing
test suite remaining green across the migration commits.

### Added — sessions 78-80 (post-v0.8.4)

#### Session 78 — Halo2 fr_inner_product migration (×2 sites)
mosaic-halo2::kzg::verify_two_point_batched_opening migrated.
Both ξ-side and ξω-side y-batched accumulator loops now use
`fr_inner_product(&v_powers[..len], evals)`. After session 78
the consumer audit was 3 sites: hyperplonk + halo2(×2).

#### Session 79 — `v0.8.4-primitive-consumer-coverage` release
Sessions 60-78 milestone tagged. CHANGELOG promoted [Unreleased]
→ [0.8.4-primitive-consumer-coverage] entry preserving the
10-primitive inventory + 7-migration audit table. README badge
bumped.

#### Session 80 — Nova fr_inner_product migration (deferred from s77)
mosaic-nova::kzg::verify_spartan_batched_opening migrated.
Hand-unrolled 5-term `v_powers[0]*a_eval + … + v_powers[4]*w_eval`
chain replaced with `fr_inner_product(&v_powers, &evals)?`.
Byte-identical at the Fr level; 59 nova lib tests still pass.

After session 80 the `fr_inner_product` consumer audit is
**4 production sites**:
- mosaic-hyperplonk::kzg                        (s77)
- mosaic-halo2::kzg::verify_two_point ξ-side    (s78)
- mosaic-halo2::kzg::verify_two_point ξω-side   (s78)
- mosaic-nova::kzg::verify_spartan              (s80)

Every BN254 weighted-sum site in the workspace now goes through
the shared primitive. The "Planned beyond v0.8.4" block loses
its third item.

### (Sessions 78-80 planning block superseded by v0.8.5 release entry above.)

## [0.8.4-primitive-consumer-coverage] — 2026-04-28

**Primitive consolidation reaches the production verifier surface.**
Sessions 60-78 add 4 more shared primitives (7-10), migrate every
remaining inline weighted-sum / Horner / pairing site in the
workspace to the shared helpers, ship a runbook for external
auditors, wire the v0.8.2 bench + fuzz harnesses into CI matrices,
and add the 8th chunked-handlers integration test that proves the
verifier dispatch path is reached end-to-end from the chunked
upload protocol.

| Surface | v0.8.3 | v0.8.4 |
|---|---|---|
| Shared primitives | 8 | **10** |
| Consumer migrations using shared helpers | 0 explicit | 7 sites |
| chunked-handlers integration tests | 7 | 8 |
| Audit runbook | — | `docs/audit-coverage-runbook.md` |
| CI matrix coverage | partial | full (PR + nightly) |

The 4 new shared primitives:
- `fr_horner_eval` (s63) — polynomial Horner evaluation
- `verify_n_pair_pairing` (s66) — N-pair generic pairing
- `powers_of` (s72) — geometric sequence
- `fr_inner_product` (s77) — dot product

Combined with the 6 from sessions 21-35
(fr_from_be_bytes_reduced, fr_be_from_u64,
derive_fr_challenge, verify_two_pair_pairing,
commitment_minus_scalar_g1, compute_kzg_opening_lhs), the
mosaic-zk-primitives crate now ships **10 audit-grade helpers**.

The 7 consumer migrations (sessions 64, 65, 68, 72, 74×2, 77, 78×2):
- mosaic-hyperplonk::sumcheck::eval_at → fr_horner_eval (s64)
- mosaic-halo2::vanishing::compute_t_from_chunks → fr_horner_eval (s65)
- mosaic-hyperplonk::kzg pairing → verify_two_pair_pairing (s68)
- mosaic-hyperplonk::kzg ν-powers → powers_of (s72)
- mosaic-halo2::kzg ν-powers → powers_of (s74)
- mosaic-nova::kzg ν-powers → powers_of (s74)
- mosaic-hyperplonk::kzg y-batched → fr_inner_product (s77)
- mosaic-halo2::kzg y-batched (×2 sites) → fr_inner_product (s78)

After the migrations every BN254 polynomial-eval site, every BN254
pairing site, every BN254 ν-powers site, and every BN254 weighted-
sum site in the workspace goes through one of the 10 audit-grade
shared primitives.

No on-chain ABI or behaviour changes — refactor + tests + CI
infrastructure + docs only.

### Added — sessions 70-72 (post-v0.8.3)

#### Session 70 — audit-coverage runbook
`docs/audit-coverage-runbook.md` — entry point for an external
review firm that wants to reproduce the Mosaic audit-coverage
matrix locally and extend it with their own tests. Covers:
- Coverage matrix at v0.8.3 with per-surface session ranges.
- Local-reproduce recipes (property tests, BPF CU bench, host
  criterion bench, fuzz harnesses).
- Extension recipes (add a new property test, fuzz harness,
  bench, shared primitive).
- Three explicit caveats about what the coverage does NOT pin
  (real prover output, full Phase-3 cryptographic soundness,
  chunked dispatch integration).

#### Session 71 — AUDIT.md release entries
Recorded both v0.8.2 and v0.8.3 release milestones in AUDIT.md
with per-release scope, findings, and lib-test counts. Top-of-
file pointer to `docs/audit-coverage-runbook.md` so external
reviewers find the local-reproduce workflow immediately.

#### Session 72 — `powers_of` 9th shared primitive + first consumer
`mosaic_zk_primitives::field::powers_of` lifts the multi-poly
batched-opening ν-powers accumulator loop that surfaces in
HyperPlonk session 3e, Halo2 session 17, and Nova Spartan
session 22.

+5 proptest tests (mosaic-zk-primitives lib total 74 → 79):
- prop_powers_of_length / prop_powers_of_first_is_one /
  prop_powers_of_recurrence / prop_powers_of_one_is_all_ones
- prop_powers_of_matches_pow — closed-form cross-check against
  `fr_pow_u64`. The soundness invariant that justifies the lift.

First consumer migration: `mosaic_hyperplonk::kzg` replaces an
inline 11-step accumulator loop with `powers_of(&nu, 12)`. 82
hyperplonk lib tests still pass; byte-identical refactor.

After session 72 the shared-primitive count is **9 helpers** in
mosaic-zk-primitives.

#### Session 73 — docs sweep
Recorded sessions 70-72 in CHANGELOG + README; lib test total
bumped 544 → 549, "+147 proptest + shared-primitive coverage" →
"+152 proptest + 9 shared primitives lifted", new "Audit runbook"
row in the README Status table.

#### Session 74 — `powers_of` consumer migrations (halo2 + nova)
Two more consumer migrations for the session-72 `powers_of`
primitive:

- mosaic-halo2::kzg::verify_two_point_batched_opening — replaces
  inline 2-line accumulator loop with `powers_of(v, max_len)`
  for the asymmetric ξ vs ξω commitment counts.
- mosaic-nova::kzg::verify_spartan_batched_opening — replaces
  hand-unrolled `[v⁰, v¹, v², v³, v⁴]` chain with
  `powers_of(v, 5)`. The byte-conversion stage stays unrolled
  because msm_g1's signature wants `&[[u8; 32]; 5]`.

Both migrations byte-identical at the Fr level. After session 74
the `powers_of` consumer audit:
- mosaic-hyperplonk::kzg (session 72)
- mosaic-halo2::kzg::verify_two_point (session 74)
- mosaic-nova::kzg::verify_spartan (session 74)

No more BN254-Fr ν-powers inline sites in the workspace.

#### Session 75 — chunked commit_and_verify dispatch path coverage
8th chunked-handlers integration test, closing the "chunked
dispatch reaches verifier hand-off" gap on the audit-coverage
planned-beyond list. Drives the full lifecycle —
init → append → finalize-with-correct-hash → dispatch_verify —
and asserts the error surfaces from dispatch_verify (not from
the chunked state machine).

Test approach
- Sham VK account (16 bytes, structurally too small) reaches
  the verifier dispatch step.
- Asserts `Custom(2)` == `OnChainError::VerifyingKeyLengthMismatch`
  in the program log, proving the verifier hand-off works and
  the verifier surface fails closed on the structurally invalid
  VK.

Test inventory in chunked_handlers.rs after session 75: 8 tests.

The remaining gap on the chunked path is a *real* commit_and_verify
happy-path test (genuine Groth16 proof + VK uploaded via chunked
flow); that's deferred to the fixture-driven differential testing
item.

### (Planning block superseded by v0.8.4 release entry above.)

#### v0.8.3 planning block (kept for historical reference)

- Fixture-driven differential testing for the four Phase-3 bodies
  (Espresso HyperPlonk, PSE Halo2, sonobe Nova, Plonky3 STARK).
  **Last named pre-audit gap on the Phase-3 verifier track.**
- HyperPlonk full Zeromorph / PST / Gemini reduction (canonical
  layout breaking change).
- `mosaic-program::chunked::dispatch` integration tests via
  `solana-program-test` with synthesized `AccountInfo`.
- External security audit commission.

## [0.8.3-shared-primitive-lift] — 2026-04-27

**Shared-primitive consolidation + CI activation.** Sessions 61-68
extend the v0.8.2 fuzz/bench coverage with two cross-cutting work
streams:

- **Shared primitives 7 + 8** (`fr_horner_eval`, `verify_n_pair_pairing`)
  added to `mosaic-zk-primitives`, joining the six lifted in
  sessions 21-35.
- **Consumer migrations** in mosaic-{hyperplonk, halo2} replace
  inline Horner loops + 384-byte alt_bn128_pairing buffer
  construction with calls to the shared helpers. After the sweep,
  every BN254 polynomial-eval site and every BN254 pairing site
  in the workspace goes through one of the eight audit-grade
  primitives.
- **CI workflow expansion** wires every sessions-47-59 bench +
  fuzz harness into GitHub Actions matrices. PR mode runs a
  representative subset (~25 min wall-clock); nightly runs the
  full 23-target fuzz inventory at 60 min/harness.

No on-chain ABI or behaviour changes — refactor + tests +
infrastructure only.

### Added — sessions 61-64 (post-v0.8.2)

#### Session 61 — CI workflow expansion
`.github/workflows/{fuzz,bench}.yml` rewritten to invoke every
sessions-47-59 bench + fuzz harness:
- fuzz.yml — PR mode runs a representative 8-target subset
  (1 per system, combined-slot variant) at 5 min/harness;
  nightly runs the full 23-target sweep at 60 min/harness.
- bench.yml — criterion job is now a matrix over
  `[groth16_host, phase3_host]` with per-bench artifact uploads.
- Both workflows' `paths:` triggers expanded to all five
  Phase-2/3 verifier crates plus mosaic-zk-primitives.

#### Session 63 — `fr_horner_eval` 7th shared primitive
`mosaic-zk-primitives::field::fr_horner_eval` lifts the polynomial
Horner-evaluation pattern out of every Phase-3 verifier's inline
sumcheck/identity code into a single audit-grade helper. Joins the
existing six shared primitives extracted in sessions 21-35.

+6 proptest tests (mosaic-zk-primitives lib total 64 → 70):
- `prop_horner_matches_naive_eval` — Horner equals
  Σ a_i · x^i for any polynomial up to degree 8 and any in-range
  Fr challenge. **The soundness invariant** that justifies the
  lift.
- `prop_horner_empty_is_zero`, `prop_horner_constant_polynomial`,
  `prop_horner_linear_polynomial`,
  `prop_horner_at_zero_returns_constant`,
  `prop_horner_at_one_returns_sum`.

#### Session 64 — first `fr_horner_eval` consumer migration
`mosaic-hyperplonk::sumcheck::RoundPolynomial::eval_at` migrated
from an inline Horner loop to `fr_horner_eval`. All 82 hyperplonk
lib tests still pass; the migration is byte-identical at the Fr
level. Tracked as the first of 5+ in-tree consumer sites that
will gradually move to the shared primitive.

#### Session 65 — second `fr_horner_eval` consumer migration
`mosaic-halo2::vanishing::compute_t_from_chunks` migrated. The
"evaluation point" for this Horner reduction is `ξ^n` rather
than `ξ` (each chunk is the i-th coefficient of the polynomial
that takes `ξ^n` as its variable). 75 halo2 lib tests still pass.

Per-site survey of remaining BN254-Fr Horner sites in the
workspace after sessions 64-65: zero. mosaic-stark uses the
Goldilocks field, not BN254 Fr; the shared primitive doesn't
apply there.

#### Session 66 — `verify_n_pair_pairing` 8th shared primitive
Generalizes `verify_two_pair_pairing` (session 25) from a fixed
2-pair API to an arbitrary-N-pair API. `verify_two_pair_pairing`
rewritten to delegate to the new generic version with `N=2`.

Why both APIs

- 2-pair specialization stays in the workspace for the hot
  canonical KZG opening pattern (avoids a slice allocation by
  passing fixed-arity arguments).
- N-pair generic version lifts the inline pair-list construction
  pattern that surfaces in Halo2's multi-poly batched opening
  (session 17) and Nova's Spartan-batched 5-way opening (session
  22). Both currently inline a loop that concatenates pair bytes
  into the syscall input buffer; future migrations can replace
  the loops with `verify_n_pair_pairing` calls.

+4 unit tests for the new primitive (mosaic-zk-primitives lib
total 70 → 74):

- empty-pair vacuous identity case
- 2-pair specialization equivalence with the new generic API
- 3-pair canceling combination
  `e(G1,G2)·e(G1,G2)·e(-2G1,G2) = e(0,G2) = 1`
- pre-syscall G2-length validation pass

After sessions 63-66 the shared-primitive count is **8 helpers**
in `mosaic-zk-primitives` covering Fr arithmetic, transcript
challenge derivation, KZG opening LHS construction, generic
pairing verification, and Horner polynomial evaluation.

#### Session 68 — last in-tree pairing-helper consumer migration
`mosaic-hyperplonk::kzg::verify_kzg_batched_opening` migrated
from an inline 384-byte `alt_bn128_pairing` buffer + return-byte
inspection to the shared `verify_two_pair_pairing` (which, per
session 66, now itself delegates to `verify_n_pair_pairing` with
`N=2`). HyperPlonk was the last in-tree consumer that hand-rolled
the buffer construction; mosaic-{halo2, nova} already used the
helper.

After session 68 every BN254 pairing site in the workspace goes
through one centralized audit-grade primitive — a future
soundness-critical change (e.g. additional G2 length validation
or a different return-code convention) needs only one edit.

## [0.8.2-fuzz-bench-coverage] — 2026-04-27

**Audit-coverage extension: bench + fuzz dimension.** Sessions 47-59
extend the v0.8.1 proptest sweep with two complementary measurement
surfaces:

- **Benches** — `bpf-bench` grew from 3 to 7 systems (HyperPlonk,
  Halo2, Nova, FRI-STARK BPF benches added in sessions 47, 49); a
  new `phase3_host` Criterion benchmark covers the same 4 Phase-3
  systems plus Groth16 on the host side (session 51).
- **Fuzz harnesses** — `mosaic-fuzz` grew from 3 to 23 targets
  across 6 production verifiers in 4 dimensions per system: proof
  bytes, VK bytes, public-input bytes, and a length-prefixed
  combined-slot fuzzer that explores cross-slot interaction
  surface (sessions 54-59).

`mosaic-core` (the workspace foundation crate) was lifted from 0
to 16 lib tests with the `ALL_VARIANTS` const table that external
indexers can copy as the source of truth for the on-chain ABI
(session 52).

No behaviour changes — test, bench, and fuzz code only, plus
README / AUDIT / CHANGELOG entries.

### Added — sessions 47-49 (audit-coverage extension, first wave)

**Phase-3 BPF bench coverage + arkworks adapter property tests.**
Pushes the `bpf-bench` regression harness from 3 to 7 measured
systems and closes the arkworks adapter's 0-test gap from session 40.

#### Session 47 — HyperPlonk + Halo2 + Nova BPF benches
`crates/mosaic-bench/src/bin/bpf_bench.rs` gains 3 new
`SystemTarget` entries, 3 inline scaffold-acceptance fixture
builders, and 3 dispatch arms. The fixture builders mirror each
verifier's own `verifier::tests` dummy fixtures (zero-wire +
LOOKUP_M=1 trick for Halo2; real G2 generator for the pairing
syscall on all three). Hard caps derived from each verifier's
`estimated_compute_units` × 1.30 regression headroom.

| Target | Hard cap | Baseline |
|---|---:|---:|
| `hyperplonk_kzg_bn254_scaffold` | 660K | tbd (first run) |
| `halo2_kzg_bn254_scaffold` | 760K | tbd (first run) |
| `nova_folding_bn254_scaffold` | 1.15M | tbd (first run) |

#### Session 48 — arkworks adapter property tests
`crates/mosaic-serde/src/arkworks.rs` gains 11 proptest tests
covering encode_proof / encode_vk / encode_public_inputs:
- Length invariants (256 B proof, `64 + 3·128 + 64·n` VK,
  `32·n` public inputs).
- Determinism (same struct → same bytes across two calls).
- A‖B‖C and `alpha (G1) ‖ beta (G2) ‖ gamma (G2) ‖ delta (G2) ‖
  ic[0..n] (G1)` byte-region pinning.
- G1 + G2 identity-element handling (point at infinity → all-zero
  bytes, matches Solana alt_bn128 convention).
- `format()` tag stability.
- decode/encode equivalence: bytes from ark-serialize +
  `decode_proof` match `encode_proof` of the original struct.

Fixtures are constructed by multiplying G1/G2 generators by
random Fr scalars from `ark_std::test_rng()` — no inline circuit
required. Closes the "arkworks adapter property tests" item from
v0.8.1's planned-beyond list.

mosaic-serde lib tests: 12 → 23.

#### Session 49 — FRI-STARK BPF bench
Closes the deferred Phase-3 BPF bench gap from session 47.
`build_stark_scaffold_fixture` reproduces the canonical proof
layout inline (mirrors `mosaic_stark::canonical::tests::proof_bytes`
for the smallest Goldilocks shape: trace_width=1,
trace_log_height=10, log_blowup=1, num_fri_layers=4, num_queries=8,
pow_bits=0). Hard cap = 7.8M (estimate × 1.20; lower headroom
because the work is dominated by syscall counts rather than
polynomial codegen).

| Target | Hard cap | Baseline |
|---|---:|---:|
| `fri_stark_goldilocks_scaffold` | 7.8M | tbd (first run) |

After sessions 47-49 `bpf-bench` covers all 6 productionish
verifier surfaces (Groth16 single + batch, KZG-PLONK, HyperPlonk,
Halo2, Nova, FRI-STARK).

### Added — sessions 50-52 (audit-coverage extension, second wave)

#### Session 50 — docs sweep
Recorded sessions 47-49 in CHANGELOG + README Status table; added
new "BPF CU regression bench" row covering the 7 measured systems.

#### Session 51 — host-side Criterion benches for Phase-3
`crates/mosaic-bench/benches/phase3_host.rs` — new file with 4
criterion targets (HyperPlonk, Halo2, Nova, FRI-STARK) using the
same scaffold-acceptance fixtures as the bpf-bench counterparts.
Wall-clock numbers from this bench are the canary for host-side
CPU regressions before they hit on-chain CU; criterion's noise
floor lets a real algorithmic change surface distinctly from
JIT/codegen drift on the runner.

After sessions 47-51 the host-side criterion bench coverage is
groth16 + 4 Phase-3 = 5 systems.

#### Session 52 — proptest coverage for the workspace foundation
`mosaic-core` had 0 proptest pre-session — the workspace's
foundation crate (trait hierarchy, error taxonomy, proof-system
discriminant enum) was the last unaudited surface. Added 10
property-based tests pinning the two consensus-critical ABI
structures:

- `proof_system.rs` (+5 proptest):
  * `known_byte_round_trip` — every byte 0x01..=0x08 round-trips
  * `unknown_byte_rejected` — exhaustive over u8 ∉ {0x01..=0x08}
  * `from_byte_is_pure` — same byte → same variant across two calls
  * `slugs_pairwise_distinct` — no two variants share a slug
  * `discriminants_pairwise_distinct` — no two variants share a byte

- `error.rs` (+5 proptest, all backed by an `ALL_VARIANTS` const
  table that external indexers can copy as the ABI source of truth):
  * `all_discriminants_stable` — every variant's `code()` matches
    the committed value (pin the on-chain ABI exhaustively)
  * `all_slugs_stable` — every variant's `slug()` matches the
    committed identifier
  * `all_slugs_snake_case` — ASCII lowercase + digit + '_' allowed
    (digit allowance pinned because curve names embed digits like
    `alt_bn128`, `bn254`, `mersenne31`)
  * `discriminant_codes_pairwise_distinct` — no aliasing
  * `slugs_pairwise_distinct` — no aliasing

Yan kazanım — false positive caught + documented inline:
- `is_ascii_lowercase()` snake-case check rejected curve-name
  digits. Surfaced by proptest shrinking on the first run at
  idx = 23 (AltBn128SyscallFailed). Corrected to allow
  `is_ascii_digit()`, with explicit comment explaining why.

Sessions 37-52 cumulative: every host-callable workspace crate
under audit-grade proptest coverage. **Total +137 proptest tests
across 12 crates** (was +111 across 9 after session 42; +9 in
session 47 are bpf-bench `SystemTarget` entries; +11 in session 48,
+11 in session 51 + criterion benches; +10 in session 52).

### Added — sessions 54-56 (fuzz harness expansion)

#### Session 54 — Phase-2 + Phase-3 proof-bytes fuzzers
`crates/mosaic-fuzz` grew from 3 harnesses (all Groth16) to 8.
The new Phase-2/3 targets are `fuzz_{plonk, hyperplonk, halo2,
nova, stark}_proof_bytes`, each pinning the panic-free invariant
on its system's verify pipeline. Per-system `*Fixtures` structs
in `mosaic-fuzz/src/lib.rs` build scaffold-acceptance
`(vk, proof, public_inputs)` triples, mirroring the inline
fixture builders in `bpf-bench` (sessions 47, 49) and
`phase3_host` criterion benches (session 51).

#### Session 55 — per-system VK fuzzers
Added 5 more harnesses targeting the verifying-key parser of
each Phase-2/Phase-3 system: `fuzz_{plonk, hyperplonk, halo2,
nova, stark}_vk_bytes`. Mirrors the proof-bytes harness pattern
but flips the libfuzzer input into the VK slot. Each pins
system-specific invariants:

- PLONK + HyperPlonk: 744-byte fixed envelope.
- Halo2: variable-length tail (fixed_commits ‖ permutation_commits).
- Nova: 235-byte fixed envelope + 3-way `FoldingVariant` tag rejection.
- STARK: 48-byte fixed envelope + 3-way `StarkFieldId` tag
  rejection + structural cross-check against the proof shape.

#### Session 56 — combined-slot Halo2 fuzzer
`fuzz_halo2_combined` is the first multi-slot harness — splits
the libfuzzer input into three length-prefixed sub-buffers
(vk, proof, public_inputs) and feeds all three to the verifier.
Explores a coordinate in `(vk, proof, pi)` space rather than the
1-D slice the per-slot harnesses cover; catches bugs that only
surface when two slots lie about the same shape parameter in a
coordinated way that the structural cross-check missed.

Halo2 chosen as the first combined target because it has the
richest VK shape (variable tail) AND the richest proof shape
(4 dynamic header counters) → widest cross-slot interaction
surface. Pattern is template-able for the other 4 systems
(tracked as session 57+ follow-up).

After sessions 54-56 the fuzz harness inventory is **14 targets**:
- 3 original Groth16 (proof, vk, public_inputs)
- 5 per-system proof_bytes (PLONK + HyperPlonk + Halo2 + Nova + STARK)
- 5 per-system vk_bytes (same five)
- 1 combined-slot Halo2

### Added — sessions 58-59 (fuzz harness completion)

#### Session 58 — per-system public-input fuzzers
Added 5 more harnesses targeting the public-input parser of each
Phase-2 / Phase-3 system: `fuzz_{plonk, hyperplonk, halo2, nova,
stark}_public_inputs`. Each pins its system's PI invariants:

- PLONK + HyperPlonk + Halo2 + Nova: `len % 32 == 0`,
  `len / 32 == vk.n_public`, every 32-byte chunk in Fr range.
- STARK: length must be a multiple of
  `field_id.field_elem_bytes()` (8 for Goldilocks, 4 for
  BabyBear / Mersenne31).

Halo2's PI feeds round-1 of the Fiat-Shamir absorb sequence — a
regression in PI parsing would cascade into every challenge and
break the verifier's identity check. The session-37 challenges
proptests already pin the cascade for valid PI; this fuzzer pins
the rejection path for invalid PI across the full byte-buffer space.

#### Session 59 — combined-slot fuzzers for the remaining 4 systems
Adds combined-slot harnesses for PLONK, HyperPlonk, Nova, and
FRI-STARK, completing the cross-slot interaction surface coverage
the session-56 Halo2 template demonstrated. Refactored the
`split_three_slots` helper out of the Halo2 dump-target into
`mosaic-fuzz::lib` so all 5 combined-fuzzer binaries share the
same length-prefix parser.

Each new combined fuzzer pins system-specific cross-checks that
single-slot harnesses can't reach (because both slots must lie
in a coordinated way for the bug to surface):

- PLONK: 744 B / 768 B fixed envelopes (narrowest cross-slot
  surface; value is in catching parser confusions between the
  two envelopes).
- HyperPlonk: `vk.num_variables == proof.sumcheck_rounds`
  cross-check.
- Nova: `vk.variant == proof.variant` (FoldingVariant 3-way) +
  `vk.n_public == proof.n_public == public_inputs.len() / 32`.
- STARK: richest cross-check fingerprint of any verifier:
  `vk.field_id == proof.field_id`,
  `vk.trace_log_height == proof.trace_log_height`,
  `vk.trace_width == proof.trace_width`,
  `vk.log_blowup == proof.log_blowup`. A coordinated lie on any
  of these would route the verifier to a wrong-shape Merkle path
  or FRI fold chain.

After sessions 58-59 the fuzz harness inventory is **23 targets**
across all 6 production verifier surfaces:

  Phase-1 Groth16 (3 original)
    fuzz_groth16_proof_bytes, fuzz_vk_bytes, fuzz_public_inputs

  Phase-2 KZG-PLONK (4)
    fuzz_plonk_{proof_bytes, vk_bytes, public_inputs, combined}

  Phase-3 HyperPlonk + Halo2 + Nova + FRI-STARK (16)
    fuzz_hyperplonk_{proof_bytes, vk_bytes, public_inputs, combined}
    fuzz_halo2_{proof_bytes, vk_bytes, public_inputs, combined}
    fuzz_nova_{proof_bytes, vk_bytes, public_inputs, combined}
    fuzz_stark_{proof_bytes, vk_bytes, public_inputs, combined}

## [0.8.1-audit-coverage] — 2026-04-27

**Workspace-wide property-based test sweep.** Sessions 37-42 bring
every Phase-1, Phase-2, Phase-3, adapter, state-machine, SDK, and
on-chain program crate under audit-grade proptest coverage. **No
behaviour changes** — test code only, plus README / AUDIT /
CHANGELOG entries documenting the milestone.

### Added — audit-coverage sweep (sessions 37-42, post-v0.8.0)

Workspace-wide property-based test sweep brings every Phase-1,
Phase-2, Phase-3, adapter, state-machine, SDK, and on-chain program
crate under audit-grade proptest coverage. **+111 proptest tests**
across nine crates:

| Crate | Δ proptest | Total tests |
|---|---:|---:|
| `mosaic-halo2` | +16 | 75 |
| `mosaic-hyperplonk` | +17 | 82 |
| `mosaic-nova` | +14 | 59 |
| `mosaic-plonk` | +15 | 32 |
| `mosaic-groth16` | +15 | 26 |
| `mosaic-serde` | +9 | 12 |
| `mosaic-chunked` | +11 | 20 |
| `mosaic-sdk` | +7 | 11 |
| `mosaic-program` | +7 | 7 |

Property categories pinned:

- **Canonical byte layout invariants** — proof / VK round-trip,
  trailing-garbage rejection, truncation rejection, oversized-counter
  rejection (cap enforced before `checked_mul`), variant-tag rejection
  for systems with enum discriminants (Nova folding variant).
- **Fiat-Shamir avalanche** — round-by-round cascade properties for
  Halo2 (4 rounds), HyperPlonk (3 rounds), Nova (3 rounds), and PLONK
  (6 rounds). The PLONK sweep includes an audit-grade pin on the
  snarkjs-compatibility bit "u absorbs only `W_xi` and `W_xiω`,
  NOT `v`" — a past subtle bug rediscovered as a property.
- **Single-byte tamper rejection** — random byte flip in any commit
  or opening witness must fail verification. Scope was narrowed away
  from selector-eval slots after a documented false positive surfaced
  (see "Documented false positives" below).
- **State-machine monotonicity** — chunked-upload session: no append
  after finalize, no double-finalize, no out-of-order chunk index,
  no oversized chunk, no total-len overflow.
- **Borsh wire-format round-trip** — `VerifyProofData`,
  `VerifyProofBatchData`, and the SDK payload pin the four-field
  order against silent reorderings that would swap proof and
  public_inputs on the wire.
- **BE-comparison + Fr arithmetic primitives** — `lt_be` is
  anti-reflexive, asymmetric, and decided by the first differing
  byte; `add_mod_r` is commutative, has 0 as identity, preserves Fr
  range; `reduce_mod_r` lands in [0, r), is idempotent, and identity
  on already-reduced inputs.
- **snarkjs adapter byte ordering** — the Solana c1 ‖ c0 G2 layout
  swap (different from snarkjs's native c0 ‖ c1) is pinned, as is
  the `decimal_to_be_32` envelope (rejects `≥ 2^256`, pads small
  u128 values to 32 bytes with leading zeros).
- **Builder/setter independence + idempotence** — `with_vk(x)` only
  mutates `vk`; calling a setter twice equals calling it once with
  the second value (pure replacement, not append).
- **Instruction-tag dispatch routing** — exhaustive byte-space check
  for `process_instruction` returning `InvalidInstructionData` on
  unknown tags, plus a wrong-program-id rejection invariant.

#### Documented false positives (audit-grade trace)

Three internal false positives surfaced and were resolved with
inline rationale comments rather than silent suppressions:

1. **Halo2 verifier random-byte-flip in selector slots** — the
   trivially-zero dummy fixture has `b = 0` for every wire, so
   flipping a `Q_R` byte preserves `gate_expr = Q_R · b = 0`. Scope
   narrowed to commit + opening byte regions; the selector-slot
   property is deferred to the fixture-driven differential harness.

2. **HyperPlonk verifier `anchor + XOR` cancellation** — the pattern
   `proof[off] = anchor; proof[off] ^= bit_mask;` collapses to a
   no-op when `bit_mask == anchor`. Surfaced by proptest shrinking
   on the first run; rewritten as direct `proof[off] = new_val`
   with `new_val ∈ [1, 255]`. Same anti-pattern audited and avoided
   across the rest of the sweep.

3. **`is_multiple_of` MSRV warning** _(pre-existing, not introduced
   by this sweep)_ — challenges modules use `usize::is_multiple_of`,
   stable since Rust 1.87. Workspace MSRV is 1.85. CI passes because
   the lint is in the pedantic group; documented in `AUDIT.md`.

### Added — earlier in v0.8.0

- **HyperPlonk univariate-point full-vector binding (session 28)** —
  The KZG opening's univariate evaluation point is now derived via
  `derive_fr_challenge(backend, "mosaic-hyperplonk/univ-point",
  &r_0 ‖ r_1 ‖ … ‖ r_{n-1})` — a domain-separated keccak over the
  FULL sumcheck challenge vector. Sessions ≤27 used only the last
  challenge `r_{n-1}`. This closes the scaffold "earlier-challenge
  binding gap" that would have mattered once a real Zeromorph / PST
  / Gemini reduction lands; the univariate opening is now bound to
  every multivariate sumcheck output scalar, not just the trailing
  one. The reduction itself (intermediate commitments + fold
  consistency) stays on the roadmap.

## [0.7.0-phase3-primitives] — 2026-04-23

**Shared-primitive consolidation.** Sessions 21-26 extract every
duplicated arithmetic pattern from the four Phase-3 verifiers into
`mosaic-zk-primitives`. Five new primitives land in the shared
crate; Halo2, HyperPlonk, and Nova verifier `kzg.rs` files shed
110+ lines of boilerplate without any behavior change. Gate count
unchanged at 14 (session 23 tightens Nova's Spartan opening with a
dedicated `w_eval` slot but doesn't add a new gate class).

### Added

- **Nova `w_eval` dedicated canonical slot (session 23)** —
  `NovaFoldingProof` gained a dedicated 32-byte `w_eval` field
  between `hadamard_evals` and `aux_commits`. Sessions ≤22 derived
  the witness evaluation from the first public input as a scaffold
  stand-in; session 23 lifts it into a first-class slot carrying
  the prover's claimed `W̃(ξ)`. The Spartan-batched opening
  consumes `fr_from_canonical_bytes(proof.w_eval)` instead of
  reusing `public_inputs[..32]`. Proof canonical layout grows by
  32 B (+`W_EVAL_LEN`). New session-23 tamper test
  `spartan_rejects_tampered_w_eval_slot` flips the dedicated slot
  with `u=1, a=b=c=e=0` Hadamard-satisfying setup → the tampered
  w_eval alone propagates into `y_batched ≠ 0` while
  `C_batched = 0`, failing the batched pairing identity.

- **Shared `commitment_minus_scalar_g1` primitive (session 26)** —
  The `C - y·G1` KZG opening-minus-claim step was duplicated at 6
  sites across all KZG-based verifiers. Lifted into
  `mosaic-zk-primitives::msm::commitment_minus_scalar_g1`. Call-
  site delta: 4 lines of boilerplate → 1 function call each. Two
  new unit tests: `commitment_minus_zero_returns_commitment` and
  `commitment_minus_one_equals_negate`.

- **Shared `verify_two_pair_pairing` primitive (session 25)** —
  The 2-pair BN254 pairing identity check (build 384-byte input,
  call `AltBn128Op::Pairing`, inspect result[31]) was duplicated
  at 5 sites. Lifted into
  `mosaic-zk-primitives::msm::verify_two_pair_pairing`. Four new
  unit tests cover zero pair, canceling pair, non-trivial pair,
  and G2 length validation.

- **Shared `fr_be_from_u64` primitive (session 24)** —
  `HyperPlonkVerifyingKey::fr_be_from_u64` (session 18) lifted to
  `mosaic-zk-primitives::field::fr_be_from_u64` as a `const fn`.
  The HyperPlonk static method stays as a thin wrapper for
  discoverability. Two new unit tests compare against
  `fr_to_canonical_bytes(&Fr::from(n))` across small, boundary,
  and `u64::MAX` inputs.

- **Shared `derive_fr_challenge` primitive (session 22)** —
  Halo2 (session 17/20) and Nova (session 19) had three inlined
  copies of the `keccak256(domain || inputs) → Fr` one-shot
  challenge pattern for auxiliary challenges outside the main
  round-based `Transcript`. Lifted into
  `mosaic-zk-primitives::transcript::derive_fr_challenge`; each
  verifier passes its own domain separator string so challenges
  can't collide across protocols. Internally wraps
  `SyscallBackend::keccak256` +
  [`fr_from_be_bytes_reduced`]. Three
  new unit tests exercise determinism, domain-separation, and
  input-sensitivity.

- **Shared `fr_from_be_bytes_reduced` primitive (session 21)** —
  Halo2 (session 17) and Nova (session 19) had duplicated
  `into_fr` private helpers wrapping `Fr::from_be_bytes_mod_order`.
  Lifted into `mosaic-zk-primitives::field::fr_from_be_bytes_reduced`
  for keccak-to-Fr reduction of auxiliary challenges. Two new unit
  tests exercise in-range agreement with
  `fr_from_canonical_bytes` and out-of-range reduction.

### Breaking changes

- `NovaFoldingProof` canonical layout grows by 32 B (new `w_eval`
  slot between `hadamard_evals` and `aux_commits`). Previously-
  serialized Nova proofs require re-encoding with the additional
  slot. Fixture helpers in `canonical.rs`, `challenges.rs`,
  `kzg.rs`, and `verifier.rs` tests have all been updated.

### Gate inventory (unchanged from v0.6.0)

| Verifier | Gates | Session-21+ changes |
|---|---|---|
| HyperPlonk-KZG | 2 | `fr_be_from_u64` hoisted to shared primitive (session 24) |
| Halo2-KZG | 2 | 5 helpers (1 MSM, 2 commit/eval collectors + 2 shared primitives) share code-path with Nova |
| Nova / HyperNova / ProtoStar | 3 | `w_eval` dedicated slot (session 23); Spartan opening uses 2 shared primitives |
| FRI-STARK | 7 | unchanged |

### Test counts (post-v0.7.0)

| Crate | Passing |
|---|---|
| `mosaic-halo2` | 58 |
| `mosaic-hyperplonk` | 64 |
| `mosaic-nova` | 44 |
| `mosaic-plonk` | 17 |
| `mosaic-zk-primitives` | 51 |

Total 234 tests across the Phase-3 verifier + shared-primitives
crates (14 new unit tests + 1 new tamper test added in sessions
21-26).

## [0.6.0-phase3-extended] — 2026-04-23

**Phase-3 protocol depth extended.** Sessions 17-21 tighten every
multi-poly KZG scaffold: Halo2's batched opening now folds in all
committed polys (proof-side + VK-side preprocessed commits),
HyperPlonk lifts the permutation coset triple into the VK, and
Nova upgrades to a 5-way Spartan-batched opening spanning
`(A·z, B·z, C·z, E, W)`. Project-wide soundness gate count went
from 12 → 14 across 4 Phase-3 bodies.

### Added

- **Halo2 multi-poly MSM opening (session 17)** —
  `mosaic-halo2::kzg::verify_two_point_opening_multipoly` replaces
  the session-16 single-commitment scaffold with full v-weighted
  multi-poly batching matching PSE `halo2_proofs::plonk::verify_proof`
  semantics. Advice commits + lookup commits + permutation_z +
  quotient chunks all enter the MSM at ξ; permutation_z alone enters
  at ξω (the only shifted poly in vanilla Halo2). Tampering any
  commit or paired evaluation at either point now propagates into
  the batched pairing identity. Two new dedicated tamper tests:
  `multipoly_rejects_tampered_advice_commit` (swap advice[0] to the
  G1 generator → `PairingCheckFailed`) and
  `multipoly_rejects_tampered_wire_a_evaluation` (non-zero `a(ξ)`
  with zero commit → `PairingCheckFailed`). `v` and `u` batching
  challenges derive via domain-separated keccak over current
  transcript state + opening-proof bytes.

- **HyperPlonk VK-side permutation cosets (session 18)** —
  `HyperPlonkVerifyingKey` gained three canonical 32-byte Fr fields
  `k_1`, `k_2`, `k_3` replacing the sessions-≤17 hardcoded `(1, 2, 3)`
  coset triple in `permutation_term`. The identity factor for wire
  `a` is now `β·k_1 + γ` drawn from the VK rather than the compiled
  verifier binary — tampering a VK's `k_1` flips the reconstructed
  permutation term and therefore the sumcheck's expected final claim,
  which the verifier surfaces as `SumcheckFailed`. `SERIALIZED_LEN`
  grew from 648 B → 744 B (+96 B for 3 × Fr). A new const
  `HyperPlonkVerifyingKey::fr_be_from_u64` produces canonical BE Fr
  bytes for small integer cosets. New session-18 unit tests:
  `permutation_term_depends_on_k_cosets` (distinct triples yield
  distinct perm_term values) and `tampered_k_1_breaks_expected_claim`
  (swapping `vk.k_1` produces a different final claim).

- **Nova Spartan-batched multi-poly opening (session 19)** —
  `mosaic-nova::kzg::verify_spartan_batched_opening` replaces the
  single-commit scaffold (`verify_opening_scaffold`, which only
  opened `w_comm` at the first public input) with a 5-way batched
  MSM spanning (A·z, B·z, C·z) from the VK + (E, W) from the proof.
  A `v` challenge is domain-separated-keccak-derived from the
  Spartan point + hadamard evals + w_comm + e_comm; v-powers
  `[1, v, v², v³, v⁴]` weight the batched MSM and Fr dot product.
  Tampering any of the five commits (in VK or proof) or their
  paired evaluations now propagates into the batched pairing
  identity → `PairingCheckFailed`. Two new session-19 tamper tests:
  `spartan_rejects_tampered_vk_a_comm` (VK a_comm → G1 generator)
  and `spartan_rejects_tampered_hadamard_a_eval` (non-zero a_eval
  with u=1, b=c=0 Hadamard-satisfying bundle).

- **Halo2 VK-side commits in multi-poly MSM (session 20)** —
  `collect_commits_at_xi` and `collect_evals_at_xi` now fold VK-side
  preprocessed commits (`fixed_commits` = selector polynomials
  Q_M..Q_C, `permutation_commits` = σ_1..σ_3) into the multi-poly
  MSM alongside the session-17 proof-side commits. Any tampered VK
  selector or σ commitment now breaks the batched pairing identity
  — sessions-≤17 silently tolerated VK-side tampering because those
  commits never entered the MSM. Two new session-20 tamper tests:
  `multipoly_rejects_tampered_vk_selector_commit` (swap q_M commit
  to G1 generator) and `multipoly_rejects_tampered_vk_permutation_commit`
  (swap σ_1 commit to G1 generator).

- **Shared `fr_from_be_bytes_reduced` primitive (session 21)** —
  Session-17 and session-19 had independently duplicated an
  `into_fr` helper wrapping `Fr::from_be_bytes_mod_order` for
  reducing keccak digests into Fr challenges. Lifted into
  `mosaic-zk-primitives::field::fr_from_be_bytes_reduced`; both
  halo2 and nova verifiers now call the shared primitive. Two new
  unit tests exercise the in-range agreement with
  `fr_from_canonical_bytes` and the out-of-range reduction.

### Changed

- **CU baselines re-measured** across Phase-2 production systems under
  the `opt-level = "z"` SBF profile (v0.4.1 → v0.5.0 drift). Groth16
  single +4.1 % (80 296 → 83 574), Groth16 batch N=5 +12.0 % (230 626
  → 258 397), KZG-PLONK BN254 +29.5 % (747 666 → 968 457). PLONK's
  polynomial-heavy path absorbs the size-optimizer tradeoff
  disproportionately because the linearization MSM and transcript Fr
  arithmetic relied on inlined helpers that now share tail-call
  destinations after the v0.5.0 STARK body + `mosaic-zk-primitives`
  extraction. KZG-PLONK hard cap raised 800K → 1 100K (13 %
  regression headroom); Groth16 caps retained. ADR-0005 targets
  table updated with `Hard cap | Last-measured` columns and a
  "Re-measurement" note. `docs/compute-unit-budget.md` rewritten
  with the v0.5.0 drift table and measured baselines.
  `Cargo.toml` `[profile.release]` comment refreshed to match.
  `README.md` verifier matrix numbers updated.

### Removed — superseded helpers

- `mosaic-halo2::verifier::into_fr` private helper (replaced by
  shared `fr_from_be_bytes_reduced`).
- `mosaic-nova::verifier::into_fr` private helper (replaced by
  shared `fr_from_be_bytes_reduced`).

### Breaking changes

- `HyperPlonkVerifyingKey::SERIALIZED_LEN` grew 648 B → 744 B.
  Any previously-serialized HyperPlonk VK must be re-encoded with
  the additional `(k_1, k_2, k_3)` coset triple. Test fixtures in
  the `mosaic-hyperplonk` crate initialize these to the legacy
  `(1, 2, 3)` defaults via `HyperPlonkVerifyingKey::fr_be_from_u64`
  to preserve existing sumcheck behavior.

- `mosaic-halo2::verifier::collect_commits_at_xi` / `collect_evals_at_xi`
  signatures extended. Internal helpers; external code that reaches
  the public `Halo2KzgBn254::verify` API is unaffected.

### Gate inventory (post-v0.6.0)

| Verifier | Gates | Sessions covering |
|---|---|---|
| HyperPlonk-KZG | 2 | sumcheck identity, permutation term at ξ (coset tamper in session 18) |
| Halo2-KZG | 2 | vanishing identity, multi-poly batched two-point opening (sessions 16 → 17 → 20) |
| Nova / HyperNova / ProtoStar | 3 | Hadamard residual, folded-commitment reconstruction, Spartan-batched opening (session 19) |
| FRI-STARK | 7 | query indices, trace + constraint Merkle, PoW, FRI fold chain, OOD quotient, per-layer Merkle auth |

## [0.5.0-phase3-complete] — 2026-04-22

**Phase-3 protocol-layer soundness is complete.** All four Phase-3
verifier bodies (HyperPlonk-KZG, Halo2-KZG, Nova family, FRI-STARK)
now run end-to-end with **12 independent cryptographic soundness
gates** covering the primary attack surfaces of each protocol. In
just 18 focused sessions post-v0.4.1, the library went from
"structural validation with single gates" to "production-grade
scaffolds at audit-ready depth for every body."

### Soundness gate inventory

| Verifier | Gates | Coverage |
|---|---|---|
| HyperPlonk-KZG | 2 | Sumcheck identity, permutation term at ξ |
| Halo2-KZG | 1 + two-point opening | Vanishing identity, batched (ξ, ξω) |
| Nova/HyperNova/ProtoStar | 2 | Hadamard residual, folded-commitment reconstruction |
| FRI-STARK | 7 | Structural, trace Merkle, constraint Merkle, PoW, FRI fold chain, OOD quotient, per-layer Merkle |

**FRI-STARK reached production parity** with Plonky3/Winterfell
semantics (modulo real AIR-specific constraint evaluators). Nova
gained a second soundness gate via `folded_commitment_from_fold`
reconstruction. Halo2's opening upgraded from single-point (ξ) to
PSE-compatible two-point batched (ξ, ξω). HyperPlonk's permutation
term moved from zero-placeholder to structurally correct PLONK-
style grand-product.

### Added — primitive modules

- `mosaic-stark::goldilocks` — `Goldilocks(u64)` field arithmetic
  with `add`, `sub`, `mul`, `neg`, `inverse` (Fermat), `pow`,
  `from_bytes_le`, `to_bytes_le`, and `eval_poly_le_bytes` for
  coefficient-vector polynomial evaluation via Horner.
- `mosaic-stark::fri` — `compute_next_layer_value`,
  `fold_relation_holds`, `verify_fold_chain`. Standalone FRI
  fold arithmetic; callable independent of canonical layout.
- `mosaic-stark::merkle` — `verify_path` walks SHA-256 trees
  already shipped in session 7; used by trace, constraint, and
  per-FRI-layer path verification.

### Added — soundness gate wirings (18 sessions)

Commits in-order: `b025c44`, `ee9ed73`, `19a81f5`, `9b0ef58`,
`82eb114`, `3a94839`, `d991079`, `fe642b7`, `0218d1d`, `4aba3b8`,
`919c57f`, `44c182f`, `d9d2be6`, `ed9363c`, `c0e6280`.

Each gate has a paired `rejects_tampered_*` test exercising the
specific class of attack it defends against. Full map in
`docs/phase3-soundness.md` (session 9b+).

### Changed — canonical layouts (breaking vs v0.4.1)

- **Nova `NovaFoldingProof`**: +128 B `hadamard_evals` (session 13b);
  +256 B `base_e_1 / base_e_2 / base_w_1 / base_w_2` (session 15-nova).
  Minimum proof: 368 → 624 → 880 B.
- **Halo2 `Halo2KzgVerifyingKey`**: +32 B `omega_fr` domain
  generator (session 16).
- **FRI-STARK `FriStarkProof`**: +var-tail `fri_layer_openings`
  (session 13b); +var-tail `fri_layer_auth_paths` (session 15);
  removed deprecated `final_layer_value` slot (session 14b).
  `MAX_TAIL_LEN` bumped 1 MiB → 32 MiB to accommodate realistic
  auth-paths buffers.
- **FRI-STARK `FriStarkVerifyingKey`**: +8 B `omega_g` Goldilocks
  domain generator.

Downstream provers must regenerate proofs against the new layouts.
Phase-2 production verifiers (Groth16, KZG-PLONK) are unchanged and
byte-compatible with `v0.2.0-phase2`.

### Changed — workspace

- Tests: 321 → **378** passing (+57).
- SBF binary: 292 KB → **319 KB** (+27 KB for the full wired
  cryptographic machinery). 30.4% of 1 MB Solana program limit with
  ~730 KB headroom.
- Per-crate test counts:
  - mosaic-stark: 40 → **103** (+63; FRI-STARK went from scaffold
    to production parity).
  - mosaic-nova: 38 → **41** (+3 soundness).
  - mosaic-halo2: 47 → **53** (+6 bundle + soundness).
  - mosaic-hyperplonk: 61 → 62 (+1 perm tamper test; unchanged
    this release).

### Not changed

- Phase-2 CU measurements (Groth16, Groth16 batch, KZG-PLONK)
  retain their `v0.2.0-phase2` baselines pending CU re-measurement
  follow-up.
- Phase-2 canonical layouts (Groth16, KZG-PLONK) byte-compatible.

## [0.4.1-phase3-soundness] — 2026-04-22

- **Fixture-driven final tightening** across all four Phase-3 bodies:
  Espresso HyperPlonk, PSE Halo2, sonobe Nova, Plonky3 STARK.
  Requires external prover tooling out-of-scope for in-tree work.
- **FRI-STARK session 8 extensions**: constraint-commitment paths,
  per-FRI-layer consistency checks, Goldilocks arithmetic, PoW
  grinding verification.
- **CU re-measurement post opt-level = "z"**: compare mosaic-bench
  targets `groth16_single`, `groth16_batch_n5`, `plonk_bn254`
  between speed-optimized baseline and size-optimized current.
- **gnark format adapter** (issue
  [#10](https://github.com/wienerlabs/mosaic/issues/10)).
- **External security audit** (issue
  [#19](https://github.com/wienerlabs/mosaic/issues/19)).

## [0.4.1-phase3-soundness] — 2026-04-22

**Phase-3 cryptographic soundness gates complete.** All four Phase-3
verifier bodies now surface tampered prover data with specific error
codes — soundness gates wired uniformly across BN254 + hash-based
families. Combined with a 72% SBF binary reduction, this release
restores ~760 KB of on-chain headroom for continued work and delivers
deploy-ready verifier surfaces for adapter authors to integrate
against.

### Added — cryptographic soundness gates

Four verifier bodies gained real cryptographic soundness checks that
detect tampered prover data before the final KZG/Merkle acceptance:

| Verifier | Soundness gate | Error | Commit |
|---|---|---|---|
| HyperPlonk-KZG | permutation term at ξ | `SumcheckFailed` | `ad299f1` |
| Halo2-KZG | vanishing identity `t(ξ)·Z_H(ξ) == gate + y·perm + y²·lookup` | `SumcheckFailed` | `3b83cc6` |
| Nova / HyperNova / ProtoStar | Hadamard residual `a·b − u·c − e` | `SumcheckFailed` | `2bf8ba2` |
| FRI-STARK | per-query Merkle path vs trace commitment | `VerificationFailed` | `034cbd6` |

Four scaffold caveats from v0.4.0 are now closed to different
degrees. Remaining items tracked under each verifier's issue.

### Added — `mosaic-zk-primitives` crate

Extracted `fr`, `field`, `msm`, `transcript`, `g1_consts` modules
from `mosaic-plonk` into their own crate so all four BN254
verifiers share the primitive layer without carrying a transitive
PLONK dependency (commits `8e848e4`, `0fa017d`).

- 38 tests migrated from mosaic-plonk to mosaic-zk-primitives.
- mosaic-plonk retains backward-compat re-exports; downstream code
  importing via `mosaic_plonk::*` continues to work.
- mosaic-hyperplonk / mosaic-halo2 / mosaic-nova now depend on
  mosaic-zk-primitives directly.

### Added — canonical layout extensions (breaking from v0.4.0)

- **Halo2 `EvaluationBundle` layout** — fixed 16-slot ordering
  (wires, selectors, permutation, lookup) + `n_quotient` trailing
  chunk evaluations. Required `n_evals == 16 + n_quotient`.
- **Nova `hadamard_evals` field** — fixed 128-byte slot carrying
  `(a, b, c, e)` at the Spartan evaluation point for the Hadamard
  relation check. Proof size grew 128 B; still fits single-tx.
- **FRI-STARK structured `query_responses`** — each query's response
  is now `leaf (32 B) ‖ auth_path (depth × 32 B)` where
  `depth = trace_log_height + log_blowup`. Required length:
  `num_queries × (1 + depth) × 32 B`.

### Changed — SBF binary optimization

`[profile.release]` switched from `opt-level = 3` (speed) to
`opt-level = "z"` (size) — commit `5ac8858`.

| | Before | After | Delta |
|---|---|---|---|
| SBF binary | 1,027,000 B | **288,544 B** | −72% |
| % of 1 MB Solana cap | 97.9% | 27.5% | |
| Headroom for new work | 21 KB | **760 KB** | ×36 |

Expected CU trade-off: 5–15% runtime growth. Per-system re-measurement
listed in "Planned" above. Benchmark profile (`[profile.bench]`)
retained at `opt-level = 3` so host-side microbenchmarks reflect
production-equivalent arithmetic throughput.

### Changed — workspace

- Crate count: 14 → **15** (adds `mosaic-zk-primitives`).
- Test count: 303 → **314** (+11 soundness + bundle tests,
  maintaining all 303 prior tests).
- Test redistribution:
  - mosaic-plonk: 55 → 17 (primitives tests moved out).
  - mosaic-zk-primitives: 0 → 38 (inherited).
  - mosaic-hyperplonk: 61 → 62 (+1 σ tamper test).
  - mosaic-halo2: 47 → 53 (+5 bundle + 1 gate tamper tests).
  - mosaic-nova: 38 → 40 (+2 Hadamard soundness tests).
  - mosaic-stark: 38 → 40 (+2 Merkle soundness tests - 1 renamed).
- SBF binary: **288,544 B** (from 564 KB at v0.3.0-phase3-scaffolds;
  net +28% binary for +140 tests and full Phase-3 body pipelines).

### Not changed

- Phase-2 CU measurements (Groth16 single, Groth16 batch, KZG-PLONK)
  are frozen at their `v0.2.0-phase2` baselines pending the CU
  re-measurement follow-up.
- All canonical layouts from v0.2.0-phase2 (Groth16, KZG-PLONK)
  unchanged. Phase-2-only consumers can stay pinned.

## [0.4.0-phase3-bodies] — 2026-04-22

- **Fixture-driven tightening** across all four Phase-3 bodies:
  - HyperPlonk: permutation term integration + multi-point opening
    reduction, Espresso reference fixture (issue
    [#2](https://github.com/wienerlabs/mosaic/issues/2)).
  - Halo2: vanishing-identity composition + two-point batched
    multipoint opening, PSE `halo2_proofs` fixture (issue
    [#64](https://github.com/wienerlabs/mosaic/issues/64)).
  - Nova: Hadamard relation wiring + folded-commitment
    reconstruction + Spartan multi-opening, `sonobe` fixture
    (issue [#4](https://github.com/wienerlabs/mosaic/issues/4)).
  - FRI-STARK: per-query Merkle path verification + FRI-layer fold
    check + Goldilocks reduction + PoW grinding verification,
    Plonky3/Winterfell fixture (issue
    [#3](https://github.com/wienerlabs/mosaic/issues/3)).
- **`mosaic-zk-primitives` extraction** — all three BN254 bodies
  (HyperPlonk, Halo2, Nova) now reuse `mosaic-plonk`'s
  Fr/MSM/transcript primitives; the extraction threshold has
  clearly been crossed. Follow-up refactor.
- **gnark** format adapter for Groth16 + PLONK (issue
  [#10](https://github.com/wienerlabs/mosaic/issues/10)).
- CU optimization: zero/one-scalar shortcut + pre-reduced IC
  aggregation (rescoped from Pippenger, issue
  [#37](https://github.com/wienerlabs/mosaic/issues/37)).
- Real Circom-sourced Groth16 fixtures (issue
  [#24](https://github.com/wienerlabs/mosaic/issues/24)).
- External security audit (issue
  [#19](https://github.com/wienerlabs/mosaic/issues/19)).

## [0.4.0-phase3-bodies] — 2026-04-22

**All four Phase-3 verifier bodies now run end-to-end.** HyperPlonk,
Halo2, Nova, and FRI-STARK all have full verifier pipelines returning
`Ok(())` on structurally well-formed proofs. No `UnimplementedProofSystem`
returns remain for any Phase-3 family at the top level.

This is the scaffold-to-body transition milestone for Phase 3.
Each verifier composes parse → transcript challenges → cryptographic
checks (KZG pairing or SHA-256 Merkle/FRI structural) → Ok(()).
Scaffold caveats per family are documented in the module rustdoc
and the per-commit CHANGELOG notes below.

This tag is the reference point for "Phase-3 verifier bodies wired" —
ecosystem collaborators building adapters can now integration-test
against these verifiers (albeit with the scaffold caveats noted).
The fixture-driven tightening in upcoming 0.4.x releases pins
cryptographic soundness against reference implementations.

### Added — Phase-3 body modules

**HyperPlonk** (sessions 3a-e, crate `mosaic-hyperplonk`):
- `sumcheck.rs` — round polynomial verification + transcript-driven
  challenge squeezing. 15 tests.
- `mle.rs` — `eq_poly_eval` (on-chain) + `mle_eval_from_cube` (host).
  10 tests.
- `gate.rs` — PLONK-style arithmetic gate at ξ. 9 tests.
- `challenges.rs` — three pre-sumcheck challenges `(β, γ, α)` with
  snarkjs-style per-round transcript reset.
- `kzg.rs` — 12-term MSM + `alt_bn128_pairing` batched-opening
  scaffold at univariate point.
- Canonical VK expanded: 8 preprocessing commits (Q_M/Q_L/Q_R/Q_O/Q_C +
  σ_1/σ_2/σ_3). FINAL_EVALS: 4 → 12.
- Crate totals: 11 scaffold → **61 tests**.

**Halo2** (sessions 4a-d, crate `mosaic-halo2`):
- `challenges.rs` — five-challenge Halo2 transcript
  `(θ, β, γ, y, ξ)`.
- `vanishing.rs` — `Z_H(ξ)` + `compute_t_from_chunks` + identity
  check primitive.
- `circuit.rs` — gate + permutation + lookup evaluators (log-
  derivative form) + combined expression.
- `kzg.rs` — single-commitment pairing check at ξ.
- Crate totals: 14 scaffold → **47 tests**.

**Nova / HyperNova / ProtoStar** (sessions 5a-c, crate `mosaic-nova`):
- `challenges.rs` — three-challenge transcript `(r, ξ, ν)`.
- `folding.rs` — `hadamard_residual` + `folded_commitment_from_fold`
  + `folded_error_commitment` primitives.
- `kzg.rs` — single-commitment pairing check.
- Crate totals: 19 scaffold → **38 tests**.

**FRI-STARK** (sessions 6a-c, crate `mosaic-stark`):
- `challenges.rs` — **SHA-256 based** transcript producing
  `(α, z, query_seed)` + `derive_query_indices` helper.
- `merkle.rs` — SHA-256 Merkle authentication path verification
  + test-only tree constructors.
- Structural verifier pipeline (Merkle integration pending real
  canonical layout extension for per-query structured responses).
- Crate totals: 18 scaffold → **38 tests**.

### Added — error variants

`OnChainError::VerifyingKeyProofMismatch = 0x0008` was added during
v0.3.x for STARK/Nova VK/proof cross-check. No further ABI additions
in this release.

### Changed

- **Workspace version** 0.3.0-phase3-scaffolds → 0.4.0-phase3-bodies.
- **Test count**: 163 (v0.3.0) → **303** passing, zero failures
  (+140 from Phase-3 body work across all four families).
- **SBF binary size**: 564 KB → **700 KB** (+136 KB). Breakdown:
  - HyperPlonk body: ~83 KB (arkworks Fr arithmetic, sumcheck loop,
    12-term MSM, pairing).
  - Halo2 body: ~10 KB (no MSM hot path in scaffold opening).
  - Nova body: ~8 KB.
  - FRI-STARK body: ~7 KB (SHA-256 path walker).
  - Still well under Solana's 1 MB program limit.
- **mosaic-program dispatcher** now routes all six Phase-3 discriminants
  (HyperPlonkKzgBn254, Halo2KzgBn254, FriStark, NovaFolding, ProtoStarFolding)
  to integrated bodies; only Risc0Stark remains in the
  `UnimplementedProofSystem` catchall.

### Not changed

- No production Phase-2 verifier or protocol surface modified —
  Groth16 and KZG-PLONK byte layouts, CU measurements, and audit
  scope remain authoritative at their `v0.2.0-phase2` tag.
- Phase-3 canonical layouts may still adjust in the 0.4.x series
  as fixture integration pins exact byte orderings. Consumers
  building adapters today should expect minor breaking changes in
  Phase-3 wire formats before 0.5.0.

## [0.3.0-phase3-scaffolds] — 2026-04-20

**Phase-3 scaffold surface is frozen at this tag.** Three new verifier
scaffolds (HyperPlonk-KZG, Halo2-KZG, FRI-STARK) ship with full
canonical byte layouts, `ProofSystem` trait implementations, and
`mosaic-program` dispatcher wire-up. Full verifier bodies (round
transcripts, MSM/FRI inner loops, final pairing/hash check) land in
subsequent 0.3.x releases.

This tag is the reference point for "Phase-3 scope entered" —
ecosystem collaborators building adapters against any of these three
systems can target the canonical layouts documented here with
confidence the wire formats are stable modulo ADR amendments.

### Added — verifier scaffolds

- **`mosaic-hyperplonk`** — HyperPlonk-KZG over BN254 (eprint
  2022/1355, multilinear-extension PLONK variant). Wire format,
  round-by-round plan documented in module rustdoc, 11 tests green.
  CU estimate: ~505K under 900K cap (ADR-0005).
- **`mosaic-halo2`** — Halo2-KZG over BN254 (Privacy Scaling
  Explorations fork). Placeholder layout parametrized by 4 u32
  counters (advice columns / lookups / quotient chunks / evaluations)
  plus variable-length G1/Fr sections. 14 tests green. CU estimate:
  ~580K under 700K cap.
- **`mosaic-stark`** — FRI-STARK over Goldilocks / BabyBear /
  Mersenne31 (Plonky3 family, eprint 2025/1741 envelope). Upgraded
  from a single-file stub to a full scaffold with `StarkFieldId` tag
  byte, variable-length proof decoder, `FriStarkVerifyingKey`, and
  VK-vs-proof cross-checks. 18 tests green. Depends only on
  `mosaic-core` — no BN254 primitives reused since STARKs are purely
  hash-based.

### Added — infrastructure

- **New `OnChainError::VerifyingKeyProofMismatch = 0x0008`** variant
  for VK/proof configuration disagreement. ABI-stable append (no
  existing discriminants changed). Locked in `discriminant_stability`
  test.
- **Dispatcher 0x04 and 0x05 arms** in `mosaic-program` route to
  Halo2 and FRI-STARK scaffolds respectively. HyperPlonk was already
  wired at 0x03 in the late-Phase-2 landing.
- **GitHub labels** `crate: mosaic-halo2` and `crate: mosaic-hyperplonk`
  added; Phase-3 scaffold tracking issue [#64] opened for Halo2.

### Changed

- **Workspace version** 0.2.0-phase2 → 0.3.0-phase3-scaffolds.
- **Crate count**: 12 → **13** (adds `mosaic-halo2`; `mosaic-stark`
  was already a member but is now fleshed out).
- **Test count**: 131 → **163** passing, 0 failed (+32 new scaffold
  tests: 11 HyperPlonk + 14 Halo2 + 7 STARK, plus one error-ABI test).
- **SBF binary size**: 557 KB → **564 KB** (three scaffold verifiers
  add wire-format validation paths; cryptographic hot paths still
  Phase-2 only, so binary growth is minimal).

### Not changed

- No production verifier or protocol surface was modified — Phase-2
  byte layouts, CU measurements, and audit scope remain the
  authoritative reference for `v0.2.0-phase2`. Downstream consumers
  that only care about Groth16 / PLONK can stay pinned to the
  previous tag until Phase-3 bodies land.

## [0.2.0-phase2] — 2026-04-20

**Phase 2 technical scope is frozen at this tag.** Production PLONK
verifier, Groth16 batch verification, snarkjs PLONK adapter, and
Poseidon syscall wiring all shipping with measured on-chain CU.

Audit firms, grant reviewers, and ecosystem collaborators should cite
this tag as the reference point for Phase-2 scope. Subsequent commits
start Phase 3 (HyperPlonk, Halo2-KZG, FRI-STARK).

### Added — verifiers

- **`mosaic-plonk` full KZG-PLONK BN254 verifier** (issue
  [#1](https://github.com/wienerlabs/mosaic/issues/1)). Byte-for-byte
  compatible with snarkjs 0.7.x. Ships as five modules:
  - `canonical` — 768-byte proof + 744-byte VK layout (ADR-0003).
  - `fr` — byte-level range ops; `field` — full arkworks Fr arithmetic.
  - `transcript` — Keccak-256 Fiat-Shamir with snarkjs absorb order.
  - `challenges` — six-round challenge derivation (β γ α ξ v u).
  - `linearization` — d1/d2/d3/d4 MSMs + F/E commitment build + KZG
    batched opening pairing.
  - `msm` + `g1_consts` — shared scalar mul + G1/G2 generator bytes.
- **`mosaic-groth16::batch` — Bowe-Gabizon batched verification**
  (issue [#5](https://github.com/wienerlabs/mosaic/issues/5)). One
  `alt_bn128_pairing` syscall collapses N proofs sharing a VK.
  Independent SHA-256 challenges (no Fr multiplication on-chain);
  break-even at N=2, 42.6% savings at N=5.
- **`VerifyProofBatch` instruction** (tag `0x02`) exposes batch
  verification to on-chain callers and CPI.

### Added — infrastructure

- **Poseidon syscall wired** via `solana-poseidon 2.3`
  (issue [#8](https://github.com/wienerlabs/mosaic/issues/8)) — unblocks
  Circom-compatible transcripts for future KZG-based systems.
- **Real snarkjs 0.7.6 PLONK fixtures** committed under
  `tests/fixtures/plonk/mul-circuit/{snarkjs,canonical}/`. Pipeline
  documented for reproduction.
- **`SnarkjsPlonkCodec`** — full JSON → canonical bytes decoder for
  proofs + VKs + public inputs, including snarkjs projective-identity
  handling.
- **bpf-bench target `groth16_batch_n5_mul_circuit_1pi`** — measured
  230 626 CU baseline + 300K hard cap.
- **bpf-bench target `plonk_bn254_mul_circuit_1pi`** — measured
  747 666 CU baseline + 800K hard cap.

### Added — documentation

- `docs/audit/rfq.md` + `docs/audit/outreach-email.md` — pre-audit
  outreach package for Zellic / Veridise / OtterSec / Asymmetric
  Research.
- `supply-chain/` directory with real `cargo-vet` attestation chain
  (issue [#59](https://github.com/wienerlabs/mosaic/issues/59)).
  74 audited, 2 partial, 689 exempted baseline.
- `docs/lint-policy.md` — audit-facing registry of every clippy
  suppression.
- `docs/responsible-disclosure-timeline.md` — 5-stage SLA spec
  referenced from SECURITY.md.
- `docs/threat-model.md` expanded with 4 scope-boundary axes:
  under-constrained circuits, malleable proofs, validator determinism,
  replay safety (issue
  [#63](https://github.com/wienerlabs/mosaic/issues/63)).
- `AUDIT.md` Phase-1 scope frozen and marked "ready for external
  review".

### Changed

- **On-chain CU measurements (2026-04-20 baselines):**
  | System | Measured | Cap | Headroom |
  |---|---|---|---|
  | Groth16 BN254 single | 80 296 CU | 180 000 | 55.4% |
  | Groth16 BN254 batch N=5 | 230 626 CU (46 125/proof) | 300 000 | 23% |
  | KZG-PLONK BN254 | 747 666 CU | 800 000 | 6.5% |
- **SBF binary size**: 112 KB → **557 KB** (arkworks Fr arithmetic,
  PLONK linearization, batch path). Well under Solana 1 MB limit.
- **Test count**: 36 → **119** passing, 0 failed.
- **Host backend `SyscallBackend::poseidon`** replaced the
  `UnimplementedProofSystem` stub with a `solana-poseidon::hashv` call
  that routes through `light-poseidon` on host targets and the
  `sol_poseidon` syscall under SBF — byte-identical by construction.
- **Host G1 decode accepts `(0, 0)` as identity** rather than
  rejecting as off-curve — matches Solana `alt_bn128` convention and
  handles snarkjs zero-polynomial selector commitments.
- `mosaic-program` dispatcher: `0x02` arm routes to
  `Groth16Verifier::batch_verify` (Bowe-Gabizon). Unsupported
  proof-system batches return `UnsupportedOperation`, not silent loop.

### Fixed

- **PLONK u-challenge absorb order** was incorrectly including `v`.
  snarkjs only absorbs `Wxi + Wxiω`. Silent pre-fix failure mode:
  all valid PLONK proofs would have failed the pairing check.
- **snarkjs projective-identity decode** (`[0, 1, 0]` → G1 identity)
  handled in both `mosaic-serde::snarkjs` and
  `mosaic-core::syscall::host`. Zero-polynomial selector commitments
  (e.g. Qr for a circuit with no right-operand gates) now decode
  correctly.
- **SBF stack-frame overflow** in PLONK linearization resolved by
  splitting monolithic `compute_d` and `ComputedScalars::derive` into
  `#[inline(never)]` sub-helpers (compute_d1/d2/d3/d4, compute_e3,
  compute_r0_scalar, compute_d2a, compute_d2_coeff, etc.). Each frame
  now under 4 KB; was >10 KB at worst pre-split.

### Issues closed

- [#1](https://github.com/wienerlabs/mosaic/issues/1) KZG-PLONK BN254 verifier.
- [#5](https://github.com/wienerlabs/mosaic/issues/5) Groth16 batch_verify with MSM amortization.
- [#8](https://github.com/wienerlabs/mosaic/issues/8) Wire sol_poseidon syscall.
- [#33](https://github.com/wienerlabs/mosaic/issues/33) Devnet integration test.
- [#59](https://github.com/wienerlabs/mosaic/issues/59) `cargo-vet` supply chain attestation.
- [#60](https://github.com/wienerlabs/mosaic/issues/60) Audit-readiness PR.
- [#63](https://github.com/wienerlabs/mosaic/issues/63) Threat model expansion.

### Compatibility

- Host: Rust **1.85.0** stable (unchanged).
- SBF: `cargo-build-sbf --tools-version v1.52` (unchanged).
- Solana program SDK: `^2.1` (unchanged, tested against 2.3.0).
- **Wire format**: all Phase-1 canonical byte layouts stable; PLONK
  adds its own 768/744 B layout documented in ADR-0003.
- **InstructionTag ABI**: Phase-1 `0x01` VerifyProof unchanged; new
  `0x02` VerifyProofBatch is additive.
- **`OnChainError` discriminants**: all Phase-1 values unchanged;
  no new variants in this release.

## [0.1.0-phase1] — 2026-04-20

First public pre-release. **Phase 1 technical scope is frozen at this tag.**

Audit firms, grant reviewers, and ecosystem collaborators should cite this
tag as the reference point for "what exists today". Subsequent commits land
audit-readiness documentation, supply-chain attestation, and outreach
artifacts — none of which change the runtime surface.

### Runtime deliverables

#### `mosaic-core`
- `ProofSystem` trait (object-safe for SDK; monomorphic dispatch on-chain).
- `ProofSystemId` enum with 8 discriminants (Groth16 + 7 future systems).
- `ProofCodec` trait + `FormatTag` for upstream-format adapters.
- `TranscriptHash` trait for Fiat-Shamir abstraction.
- `SyscallBackend` trait with host (arkworks) and Solana-SBF implementations.
- Two-layer error taxonomy: `OnChainError` (deterministic `repr(u32)` ABI)
  and `DiagnosticError` (rich, `std`-feature-gated). 29 `OnChainError`
  variants at stable discriminants (0x0001..0x00FF), pinned by test.
- `BumpArena` stack-bounded scratch allocator (safe single-borrow).

#### `mosaic-groth16`
- BN254 Groth16 verifier with `LE_INPUTS` const generic for SIMD-0204
  forward compatibility.
- Dual-endian support; big-endian default matches current
  `sol_alt_bn128_group_op` convention.
- Host backend via `ark-bn254`; SBF backend via `solana-bn254` syscalls.
- `estimated_compute_units` returns a tight upper bound (algorithmic).
- Internal `A`-negation so the pairing check runs as one syscall call.
- Batch verification API (defaults to looped; issue [#5](https://github.com/wienerlabs/mosaic/issues/5) tracks MSM amortization).

#### `mosaic-serde`
- `snarkjs` JSON adapter: decimal-string G1/G2 decoding with correct
  c0/c1 layout swap to Solana wire bytes.
- `arkworks` `CanonicalSerialize` adapter.
- Stub modules for `gnark`, `halo2-kzg`, `plonky3`, `risc0` (Phase 2/3).

#### `mosaic-chunked`
- `ProofUploadSession` PDA layout with explicit `layout_version` byte.
- Rolling SHA-256 hash commitment with 16-byte domain separation tag.
- Bound to `(session_id, payer)` PDA seeds — defends front-running
  griefing.
- 48-hour `EXPIRY_SLOTS` for permissionless GC.
- Wire-format instructions: `InitializeSession`, `AppendChunk`,
  `CommitAndVerify`, `CancelSession`, `CancelExpiredSession`.

#### `mosaic-program` (reference Solana program)
- Top-level dispatcher: `VerifyProof` (tag 0x01) + chunked range
  (0x10..=0x1F).
- Shared `dispatch_verify` helper bridging both single-tx and
  chunked-upload verification paths.
- Five chunked-upload instruction handlers with explicit state-machine
  enforcement, owner validation, and permissionless GC.
- Compiles to **112 KB** SBF ELF via `cargo build-sbf --tools-version v1.52`.

#### `mosaic-sdk`
- `VerifyRequest` + `build_verify_proof_ix` for client transaction construction.
- `preflight()` runs the host backend locally for fast-fail before submission.

#### `mosaic-bench`
- Criterion micro-benchmark for host Groth16 verification.
- `bpf-bench` binary drives `solana-program-test` against the actual SBF
  ELF, parses CU from program logs, compares to per-system hard caps.
  Phase-1 Groth16-BN254 mul-circuit (1 public input) measurement:
  **80,296 CU** (against 180,000 CU ADR-0005 cap).

#### `mosaic-fuzz`
- Three `libfuzzer-sys` harnesses: proof bytes, VK bytes, public inputs.

### Test coverage
- **36 tests passing**: 6 mosaic-core, 9 mosaic-chunked, 5 mosaic-groth16,
  3 mosaic-serde lib, 4 mosaic-serde round-trip, 2 differential, 7
  mosaic-program on-chain integration.
- Round-trip tests verify snarkjs / arkworks / canonical paths produce
  byte-equal output.
- Proptest differential harness (16 cases per run) cross-verifies
  arkworks reference vs Mosaic host backend.

### Fixtures
- `tests/fixtures/groth16/mul-circuit/` — deterministic proof in three
  formats (snarkjs JSON, arkworks canonical, Mosaic canonical).
- Regen command: `MOSAIC_REGEN_FIXTURES=1 cargo test -p mosaic-serde --features host-backend`.

### Documentation
- **5 ADRs**: trait hierarchy, error taxonomy, serialization, chunked
  upload, CU budget policy.
- **1 design document**: chunked-upload handler implementation contract
  (12 sections, state machine, security reduction, DoS analysis).
- **Threat model** with T-1..T-10 adversarial input vectors.
- **Compute-unit budget** per-system table with measured baselines.
- **Lint policy** (audit-facing) cataloguing every clippy `allow`.
- **SECURITY.md**, **AUDIT.md**, **CONTRIBUTING.md**.

### CI / tooling
- 4 GitHub Actions workflows: `ci`, `bench`, `audit`, `fuzz`.
- Strict clippy: `correctness`, `suspicious`, `todo`, `unimplemented`
  hard-deny; `pedantic`, `nursery`, `cargo` visible warnings.
- `cargo build-sbf` in CI with `--tools-version v1.52` pinning.
- `cargo-deny` weekly scheduled run.
- `bpf-bench` gate on CU regressions in PR workflow.
- MSRV 1.85 enforced (host); Solana SBF toolchain pinned separately.

### Security posture
- `#![forbid(unsafe_code)]` workspace-wide (migration to `deny` tracked
  in issue [#58](https://github.com/wienerlabs/mosaic/issues/58)).
- Zero `unimplemented!()` / `todo!()` / `panic!()` in library code paths.
- Every on-chain error code is deterministic; discriminants pinned.
- Domain-separated SHA-256 rolling hash for chunked-upload protocol.
- Per-system CU hard caps with CI gating.

### Known limitations
- **No external audit yet** (issue [#19](https://github.com/wienerlabs/mosaic/issues/19)).
- **Fixtures are programmatic, not Circom-sourced** (issue [#24](https://github.com/wienerlabs/mosaic/issues/24)).
- **Poseidon syscall path for Solana 2.x not wired** — blocks PLONK/Halo2
  with Circom-compatible transcripts (issue [#8](https://github.com/wienerlabs/mosaic/issues/8)).
- **Only Groth16 is implemented**; PLONK / STARK / Nova verifiers are
  stubs returning `UnimplementedProofSystem` (issues [#1](https://github.com/wienerlabs/mosaic/issues/1),
  [#3](https://github.com/wienerlabs/mosaic/issues/3), [#4](https://github.com/wienerlabs/mosaic/issues/4)).
- **Chunked-upload permissionless GC bounty** not implemented — caller
  pays only tx fee (design doc § 12, Q6).

### Compatibility
- Host: Rust **1.85.0** stable.
- SBF target: `cargo-build-sbf --tools-version v1.52` (rustc 1.89.0-dev).
  Default v1.51 (rustc 1.84.1) fails on `edition2024` transitive deps.
- Solana program SDK: `solana-program ^2.1` (tested against 2.3.0).

[Unreleased]: https://github.com/wienerlabs/mosaic/compare/v0.2.0-phase2...HEAD
[0.2.0-phase2]: https://github.com/wienerlabs/mosaic/releases/tag/v0.2.0-phase2
[0.1.0-phase1]: https://github.com/wienerlabs/mosaic/releases/tag/v0.1.0-phase1
