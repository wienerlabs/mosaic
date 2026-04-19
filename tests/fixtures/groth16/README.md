# Groth16 fixtures

Sample Groth16 proofs in each supported upstream format. Used by
`mosaic-serde` adapter tests and the differential test harness.

## Layout

```
groth16/
├── snarkjs/
│   ├── circuit-mul/
│   │   ├── proof.json
│   │   ├── verification_key.json
│   │   └── public.json
│   └── README.md
├── arkworks/
│   ├── circuit-mul/
│   │   ├── proof.bin
│   │   ├── vk.bin
│   │   └── public_inputs.bin
│   └── README.md
└── canonical/
    ├── circuit-mul/
    │   ├── proof.bin
    │   ├── vk.bin
    │   └── public_inputs.bin
    └── README.md
```

## Generating fixtures

### snarkjs

```bash
# Compile the multiplication circuit from circom.
circom circuit-mul.circom --r1cs --wasm --sym -o snarkjs/circuit-mul

# Powers of tau (use a public ceremony for production).
snarkjs powersoftau new bn128 12 pot12_0000.ptau -v
# … phase-2 ceremony …

snarkjs groth16 setup circuit-mul.r1cs pot12_final.ptau circuit-mul.zkey
snarkjs zkey export verificationkey circuit-mul.zkey verification_key.json

# Witness generation + proving.
node generate_witness.js circuit-mul.wasm input.json witness.wtns
snarkjs groth16 prove circuit-mul.zkey witness.wtns proof.json public.json
```

### arkworks

The differential-test crate (`tests/differential/src/lib.rs`) constructs an
equivalent circuit programmatically; copy its setup + prove output into
`arkworks/circuit-mul/` to commit a static fixture.

### canonical

Run `mosaic_serde::arkworks::ArkworksCodec::encode_proof(&proof)` (and
likewise for VK + public inputs) on the arkworks-format fixture and write
the bytes here.

## Status

**Phase 1**: this directory only contains this README. Static fixtures land
with the Phase 2 release once the snarkjs round-trip test matrix is in CI.
Tracking issue: TODO(mosaic-015).
