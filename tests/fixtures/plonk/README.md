# PLONK fixtures

Real snarkjs 0.7.6 PLONK fixtures for the mul-circuit (`a * b == c`,
with `c` as the single public input).

## Layout

```
plonk/
└── mul-circuit/
    └── snarkjs/
        ├── mul.circom          # source circuit (compiled with circom 2.2.3)
        ├── input.json          # witness inputs (a=7, b=6, c=42)
        ├── proof.json          # PLONK proof (9 G1 commitments + 6 Fr evaluations)
        ├── public.json         # public signals: ["42"]
        └── verification_key.json
```

## Witness

```
a = 7     (private)
b = 6     (private)
c = 42    (public; c === a * b)
```

## Pipeline (reproduction)

### Tool versions
- `circom` 2.2.3
- `snarkjs` 0.7.6
- Node 24.4.1

### Commands
```bash
# 1. Compile circuit
circom mul.circom --r1cs --wasm

# 2. Powers of Tau ceremony (2^8 = 256 domain, plenty for a 1-constraint circuit)
npx snarkjs powersoftau new bn128 8 pot.ptau -v
npx snarkjs powersoftau contribute pot.ptau pot_1.ptau --name="test" -v -e="random text"
npx snarkjs powersoftau prepare phase2 pot_1.ptau pot_final.ptau -v

# 3. PLONK setup
npx snarkjs plonk setup mul.r1cs pot_final.ptau mul.zkey
npx snarkjs zkey export verificationkey mul.zkey verification_key.json

# 4. Witness + prove
node mul_js/generate_witness.js mul_js/mul.wasm input.json witness.wtns
npx snarkjs plonk prove mul.zkey witness.wtns proof.json public.json

# 5. Self-verify (sanity check)
npx snarkjs plonk verify verification_key.json public.json proof.json
# → OK!
```

## Why a real snarkjs fixture (not programmatic)

PLONK's linearization polynomial reconstruction depends on matching the
exact byte-for-byte transcript absorb order and coefficient signs of the
reference prover. Programmatic fixtures via arkworks would be *a* valid
PLONK proof but not necessarily byte-compatible with what snarkjs emits
— and snarkjs is the overwhelmingly dominant Circom-PLONK source in
production.

The differential test in `mosaic-plonk` verifies this fixture against
the `mosaic-groth16::snarkjs` + `PlonkKzgBn254` host path, so when we
say "snarkjs-compatible" it's verified empirically, not just
algorithmically.

## Proof structure (snarkjs 0.7.x)

```json
{
  "A": ["<fq_x>", "<fq_y>", "1"],
  "B": [...], "C": [...], "Z": [...],
  "T1": [...], "T2": [...], "T3": [...],
  "Wxi": [...], "Wxiw": [...],
  "eval_a": "<fr>", "eval_b": "<fr>", "eval_c": "<fr>",
  "eval_s1": "<fr>", "eval_s2": "<fr>", "eval_zw": "<fr>",
  "protocol": "plonk", "curve": "bn128"
}
```

9 × G1 commitments + 6 × Fr evaluations = 768 bytes after canonical
encoding (big-endian, 64 B per G1, 32 B per Fr).

## VK structure

```json
{
  "protocol": "plonk", "curve": "bn128",
  "nPublic": 1, "power": 3,            // 2^3 = 8 evaluation domain
  "k1": "2", "k2": "3",
  "Qm": [...], "Ql": [...], "Qr": [...], "Qo": [...], "Qc": [...],
  "S1": [...], "S2": [...], "S3": [...],
  "X_2": [[...], [...], [1, 0]],        // G2 SRS element
  "w": "<omega>"                        // primitive domain generator
}
```

8 × G1 + 1 × G2 + scalar constants.

## Non-regeneration guarantee

Unlike our Groth16 fixture (programmatic, regenerable via env var),
this fixture is **committed static**. Regenerating would produce a
different proof (PLONK proving uses fresh randomness each time) and
break the differential test. To refresh: re-run the pipeline above
and commit the resulting three JSON files as a new mul-circuit
variant.
