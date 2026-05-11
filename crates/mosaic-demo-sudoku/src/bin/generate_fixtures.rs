// generate-fixtures: produce the ZK-Sudoku demo's real artifacts.
//
// Reads the Inkala puzzle from `mosaic_demo_sudoku::puzzles`, runs
// arkworks Groth16 setup + prove + verify, then verifies the same
// proof bytes through `mosaic-groth16`, and writes the JSON payload
// that the demo site loads.
//
// Output (under `site/public/demo/sudoku/`):
//
//   evidence.json     — main artifact, machine + human readable
//   vk.bin            — canonical VK bytes (binary, 1024 B for this circuit)
//   proof_valid.bin   — canonical proof bytes (256 B for Groth16/BN254)
//   proof_tampered.bin — same proof with proof.a's low bit flipped
//   public_inputs.bin — canonical Fr-array bytes (81 × 32 = 2592 B)
//
// The .bin files are reproducible byte-for-byte across runs (the
// setup + prove use deterministic seeds). The evidence.json is
// regenerated each time and carries the capture timestamp + content
// digests so the demo can show fresh provenance.

#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::{fs, io::Write, path::Path, time::Instant};

use anyhow::Result;
use ark_serialize::CanonicalSerialize;
use mosaic_demo_sudoku::{
    circuit::{ConstraintBreakdown, SudokuCircuit},
    prover::{public_inputs, prove, setup, verify_arkworks, verify_mosaic, PROVE_SEED, SETUP_SEED},
    puzzles::{validate, PUZZLE_INKALA_2010, SOLUTION_INKALA_2010},
};
use mosaic_serde::arkworks::ArkworksCodec;
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Where the demo site reads the artifacts from.
const OUTPUT_DIR: &str = "site/public/demo/sudoku";

#[derive(Serialize)]
struct Evidence {
    schema_version: u32,
    generated_at: String,
    workspace_version: String,
    repo_commit_sha: String,
    /// Source of the puzzle/solution pair (e.g. "Inkala 2010").
    puzzle_source: &'static str,
    /// Row-major 9×9 puzzle. 0 = blank, 1..=9 = clue. Public input.
    puzzle: Vec<u8>,
    /// Row-major 9×9 solution. Only used as the prover's witness;
    /// included here in plain so the page can render the "reveal"
    /// state for visitors who want to see the post-proof state. The
    /// proof remains zero-knowledge — verifier never sees this.
    solution: Vec<u8>,
    /// Number of clues filled in (i.e. count of non-zero puzzle cells).
    clue_count: usize,
    /// Constraint-count breakdown for the audit panel.
    constraint_breakdown: ConstraintBreakdownJson,
    /// Number of R1CS constraints in the synthesized circuit.
    constraint_count: usize,
    /// Number of public inputs the verifier sees.
    public_input_count: usize,
    /// Deterministic seeds used so a re-run produces identical bytes.
    setup_seed: String,
    prove_seed: String,
    /// Timing measured wall-clock on the build machine.
    timings: Timings,
    /// Byte sizes (canonical Mosaic format) of each artifact.
    sizes_bytes: Sizes,
    /// SHA-256 digests of each artifact byte stream.
    digests_sha256: Digests,
    /// Outcomes from both verifiers.
    verifier_outcomes: VerifierOutcomes,
}

#[derive(Serialize)]
struct ConstraintBreakdownJson {
    in_range_chain: usize,
    in_range_terminator: usize,
    square_allocation: usize,
    clue_match: usize,
    clue_match_zero: usize,
    group_sum: usize,
    group_sum_of_squares: usize,
    total: usize,
}

#[derive(Serialize)]
struct Timings {
    setup_ms: u128,
    prove_ms: u128,
    verify_arkworks_ms: u128,
    verify_mosaic_valid_ms: u128,
    verify_mosaic_tampered_ms: u128,
}

#[derive(Serialize)]
struct Sizes {
    vk: usize,
    proof: usize,
    public_inputs: usize,
}

#[derive(Serialize)]
struct Digests {
    vk: String,
    proof_valid: String,
    proof_tampered: String,
    public_inputs: String,
    puzzle: String,
}

#[derive(Serialize)]
struct VerifierOutcomes {
    /// `"accept"` if the reference arkworks verifier accepted the proof,
    /// `"reject"` otherwise.
    arkworks_valid: &'static str,
    /// `"accept"` (Ok(_)) or the Mosaic [`OnChainError`] variant name.
    mosaic_valid: String,
    /// Always rejects — included so the audit log demonstrates the
    /// soundness boundary, not just the happy path.
    mosaic_tampered: String,
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

fn main() -> Result<()> {
    // Sanity-check the hardcoded puzzle / solution pair before we
    // commit any setup work.
    validate(&PUZZLE_INKALA_2010, &SOLUTION_INKALA_2010)
        .map_err(|e| anyhow::anyhow!("puzzle constants invalid: {e}"))?;

    eprintln!("mosaic-sudoku: running setup (deterministic seed {SETUP_SEED:#018x})");
    let t = Instant::now();
    let (pk, vk) = setup(PUZZLE_INKALA_2010);
    let setup_ms = t.elapsed().as_millis();
    eprintln!("  setup: {setup_ms} ms");

    eprintln!("mosaic-sudoku: proving (deterministic seed {PROVE_SEED:#018x})");
    let t = Instant::now();
    let proof = prove(&pk, PUZZLE_INKALA_2010, SOLUTION_INKALA_2010);
    let prove_ms = t.elapsed().as_millis();
    eprintln!("  prove: {prove_ms} ms");

    let public = public_inputs(PUZZLE_INKALA_2010);

    // Reference arkworks verifier — must accept.
    let t = Instant::now();
    let ark_ok = verify_arkworks(&vk, &proof, &public);
    let verify_arkworks_ms = t.elapsed().as_millis();
    eprintln!("  verify (arkworks): {verify_arkworks_ms} ms → {}", if ark_ok { "OK" } else { "REJECT" });

    // Convert to Mosaic canonical bytes (the same byte format
    // `mosaic-program` accepts on chain).
    let canonical_vk = ArkworksCodec::encode_vk(&vk);
    let canonical_proof = ArkworksCodec::encode_proof(&proof);
    let canonical_pi = ArkworksCodec::encode_public_inputs(&public);

    // Mosaic verifier on the canonical bytes — must accept.
    let t = Instant::now();
    let mosaic_valid_result =
        verify_mosaic(&canonical_vk, &canonical_proof, &canonical_pi);
    let verify_mosaic_valid_ms = t.elapsed().as_millis();
    eprintln!(
        "  verify (Mosaic, valid): {verify_mosaic_valid_ms} ms → {:?}",
        mosaic_valid_result,
    );

    // Tampered proof: flip the low bit of proof.a's first byte. The
    // resulting bytes are bit-distinct from the valid proof at offset
    // 0 only. Mosaic must reject.
    let mut canonical_proof_tampered = canonical_proof.clone();
    canonical_proof_tampered[0] ^= 0x01;

    let t = Instant::now();
    let mosaic_tampered_result =
        verify_mosaic(&canonical_vk, &canonical_proof_tampered, &canonical_pi);
    let verify_mosaic_tampered_ms = t.elapsed().as_millis();
    eprintln!(
        "  verify (Mosaic, tampered): {verify_mosaic_tampered_ms} ms → {:?}",
        mosaic_tampered_result,
    );

    if !ark_ok || mosaic_valid_result.is_err() || mosaic_tampered_result.is_ok() {
        anyhow::bail!(
            "verifier divergence — investigate before publishing artifacts",
        );
    }

    // ── Write .bin artifacts.
    let out_dir = Path::new(OUTPUT_DIR);
    fs::create_dir_all(out_dir)?;

    fs::write(out_dir.join("vk.bin"), &canonical_vk)?;
    fs::write(out_dir.join("proof_valid.bin"), &canonical_proof)?;
    fs::write(out_dir.join("proof_tampered.bin"), &canonical_proof_tampered)?;
    fs::write(out_dir.join("public_inputs.bin"), &canonical_pi)?;

    // ── Build the evidence.json payload.
    let breakdown = ConstraintBreakdown::SUDOKU_9X9;
    let clue_count = PUZZLE_INKALA_2010.iter().filter(|&&c| c != 0).count();

    // We don't make Cargo-the-tool query workspace.toml — read the
    // version from env at compile time via Cargo's package version.
    // The package shares workspace.package.version with the rest of
    // the workspace.
    let workspace_version = env!("CARGO_PKG_VERSION").to_string();

    // Snapshot the repo commit so the demo page shows the live
    // provenance. If git rev-parse fails (no git, tarball install,
    // etc.), record "unknown" rather than panicking.
    let repo_commit_sha = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".to_string());

    // Round-trip arkworks VK/proof through arkworks CanonicalSerialize
    // so we have ark-native sizes too (the canonical Mosaic sizes are
    // separate and shown in the UI).
    let mut ark_vk_bytes = Vec::new();
    vk.serialize_uncompressed(&mut ark_vk_bytes)?;
    let mut ark_proof_bytes = Vec::new();
    proof.serialize_uncompressed(&mut ark_proof_bytes)?;
    eprintln!(
        "  arkworks-native sizes: vk={} B, proof={} B (Mosaic canonical: vk={} B, proof={} B)",
        ark_vk_bytes.len(),
        ark_proof_bytes.len(),
        canonical_vk.len(),
        canonical_proof.len(),
    );

    let evidence = Evidence {
        schema_version: 1,
        generated_at: chrono_now_iso(),
        workspace_version,
        repo_commit_sha,
        puzzle_source: "Inkala 2010 (21-clue hardest-class)",
        puzzle: PUZZLE_INKALA_2010.to_vec(),
        solution: SOLUTION_INKALA_2010.to_vec(),
        clue_count,
        constraint_breakdown: ConstraintBreakdownJson {
            in_range_chain: breakdown.in_range_chain,
            in_range_terminator: breakdown.in_range_terminator,
            square_allocation: breakdown.square_allocation,
            clue_match: breakdown.clue_match,
            clue_match_zero: breakdown.clue_match_zero,
            group_sum: breakdown.group_sum,
            group_sum_of_squares: breakdown.group_sum_of_squares,
            total: breakdown.total(),
        },
        constraint_count: breakdown.total(),
        public_input_count: 81,
        setup_seed: format!("{SETUP_SEED:#018x}"),
        prove_seed: format!("{PROVE_SEED:#018x}"),
        timings: Timings {
            setup_ms,
            prove_ms,
            verify_arkworks_ms,
            verify_mosaic_valid_ms,
            verify_mosaic_tampered_ms,
        },
        sizes_bytes: Sizes {
            vk: canonical_vk.len(),
            proof: canonical_proof.len(),
            public_inputs: canonical_pi.len(),
        },
        digests_sha256: Digests {
            vk: sha256_hex(&canonical_vk),
            proof_valid: sha256_hex(&canonical_proof),
            proof_tampered: sha256_hex(&canonical_proof_tampered),
            public_inputs: sha256_hex(&canonical_pi),
            puzzle: sha256_hex(&PUZZLE_INKALA_2010),
        },
        verifier_outcomes: VerifierOutcomes {
            arkworks_valid: if ark_ok { "accept" } else { "reject" },
            mosaic_valid: result_to_token(&mosaic_valid_result),
            mosaic_tampered: result_to_token(&mosaic_tampered_result),
        },
    };

    let evidence_json = serde_json::to_string_pretty(&evidence)?;
    let mut f = fs::File::create(out_dir.join("evidence.json"))?;
    f.write_all(evidence_json.as_bytes())?;
    f.write_all(b"\n")?;

    eprintln!("mosaic-sudoku: wrote {} artifacts under {OUTPUT_DIR}", 5);
    eprintln!(
        "  → vk.bin, proof_valid.bin, proof_tampered.bin, public_inputs.bin, evidence.json",
    );
    eprintln!(
        "  → constraint count: {}, clue count: {}",
        breakdown.total(),
        clue_count,
    );
    Ok(())
}

fn result_to_token(r: &Result<(), mosaic_core::OnChainError>) -> String {
    match r {
        Ok(()) => "accept".to_string(),
        Err(e) => format!("reject:{e:?}"),
    }
}

/// Hand-rolled ISO-8601 timestamp without pulling chrono into the
/// crate's dependency surface.
fn chrono_now_iso() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Very simple UTC formatter. Good enough for a provenance line.
    let (year, month, day, hour, minute, second) = unix_to_ymdhms(now as i64);
    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z",
    )
}

fn unix_to_ymdhms(mut secs: i64) -> (i32, u32, u32, u32, u32, u32) {
    let s = (secs.rem_euclid(60)) as u32;
    secs = secs.div_euclid(60);
    let m = (secs.rem_euclid(60)) as u32;
    secs = secs.div_euclid(60);
    let h = (secs.rem_euclid(24)) as u32;
    let mut days = secs.div_euclid(24);
    let mut year = 1970i32;
    loop {
        let leap = is_leap(year);
        let yd = if leap { 366 } else { 365 };
        if days < yd {
            break;
        }
        days -= yd;
        year += 1;
    }
    let mdays = if is_leap(year) {
        [31u32, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31u32, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 1u32;
    let mut day_in_year = days as u32;
    for (i, dim) in mdays.iter().enumerate() {
        if day_in_year < *dim {
            month = (i + 1) as u32;
            return (year, month, day_in_year + 1, h, m, s);
        }
        day_in_year -= dim;
    }
    (year, month, day_in_year + 1, h, m, s)
}

fn is_leap(y: i32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}
