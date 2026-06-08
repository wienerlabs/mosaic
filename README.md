# Mosaic

> **Proof-system-agnostic on-chain verification for Solana.**
> One API. Multiple proving systems. No Groth16 wrapping required.

[![CI](https://img.shields.io/github/actions/workflow/status/wienerlabs/mosaic/ci.yml?branch=main)](.github/workflows/ci.yml)
[![License: Apache-2.0 OR MIT](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg)](LICENSE-APACHE)
[![MSRV: 1.85.0](https://img.shields.io/badge/MSRV-1.85.0-orange.svg)](rust-toolchain.toml)
[![Release: v0.9.16-multi-system-demo](https://img.shields.io/badge/release-v0.9.16--multi--system--demo-green.svg)](https://github.com/wienerlabs/mosaic/releases/tag/v0.9.16-multi-system-demo)
[![Demo: /demo/sudoku](https://img.shields.io/badge/demo-zk--sudoku-blue.svg)](https://github.com/wienerlabs/mosaic/tree/main/site/app/demo/sudoku)
[![Roadmap](https://img.shields.io/badge/roadmap-mainnet--ladder-orange.svg)](ROADMAP.md)
[![Audit: ready for review](https://img.shields.io/badge/audit-ready%20for%20review-yellow.svg)](AUDIT.md)

The Solana ecosystem has exactly one production-grade ZK verifier today
(Light Protocol's `groth16-solana`). Every other proof system — PLONK,
HyperPlonk, Halo2-KZG, FRI-STARK, Risc0, Nova, ProtoStar — either requires
awkward Groth16 wrapping (see Bonsol/Anagram's Risc0-in-Circom workaround)
or cannot be verified on Solana L1 at all.

Mosaic fixes that. Pick a proving system via a generic parameter; swap
systems without touching program logic.