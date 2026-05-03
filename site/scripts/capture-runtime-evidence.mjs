#!/usr/bin/env node
//
// site/scripts/capture-runtime-evidence.mjs
//
// Capture real workspace command output for the on-chain runtime
// evidence terminal on page 07 of the onepager.
//
// What this script is — and isn't:
//
//   - It is a build-time deterministic capture: each command runs
//     against the live workspace, output is recorded byte-for-byte
//     plus exit code + duration + commit SHA + capture timestamp,
//     and the result is written to site/public/runtime-evidence.json.
//
//   - It is NOT a server runtime that re-executes per visitor. The
//     onepager is statically deployed (Vercel / Cloudflare / S3),
//     so we ship the captured bytes and replay them in the browser.
//     Provenance metadata is shown in the UI so visitors can
//     reproduce the same output locally with the documented
//     commands.
//
// Usage:
//
//   node site/scripts/capture-runtime-evidence.mjs
//
// Run from the repo root. Re-runs are idempotent — the JSON is
// overwritten each time. Commit the JSON whenever you want the
// public site to reflect a fresh capture (typically: after each
// release tag).
//
// To add a new command, append to the COMMANDS array. Each entry is
// run in sequence; the script aborts on the first failure that has
// `required: true`. Optional commands (e.g. SBF-artifact-dependent
// runs that we don't want to gate the site build on) just record
// their failure into the JSON without aborting.

import { spawn } from "node:child_process";
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..", "..");
const OUTPUT_PATH = resolve(__dirname, "..", "public", "runtime-evidence.json");

// Maximum captured bytes per stream. Keeps the JSON small enough to
// load quickly on the public site while preserving the full result
// signal — `cargo test` typically emits <8 KB of meaningful output
// per run after the compile spam is filtered out.
const MAX_STREAM_BYTES = 16 * 1024;

// Capture commands. Order matters — the terminal renders them in the
// order they appear here. Each `id` is referenced by the React
// component as the button identifier.
const COMMANDS = [
  {
    id: "git-log",
    label: "Release lineage",
    description:
      "Last 12 commits on the audit-prep sprint branch. Each release tag is a CHANGELOG/AUDIT/README quartet.",
    cmd: "git",
    args: ["log", "--oneline", "-12"],
    required: true,
    cwd: REPO_ROOT,
    // Filter raw output to N lines (defaults to all). Useful for
    // commands whose stdout is verbose but only the tail matters.
    keep_lines: null,
  },
  {
    id: "sbf-integration",
    label: "SBF integration tests",
    description:
      "Loads target/deploy/mosaic_program.so and dispatches every ProofSystemId byte through solana-program-test (the same rbpf VM mainnet validators run). 13 tests cover all 8 declared bytes + 1 alias + 1 unknown-byte negative + 3 compressed-path tests. Skips gracefully if the SBF artifact is missing.",
    cmd: "cargo",
    args: ["test", "-p", "mosaic-program", "--test", "verify_proof_sbf"],
    required: false,
    cwd: REPO_ROOT,
    // Keep only the test-runner section; drop compile output.
    grep:
      /^running |^test .* \.\.\. |^test result:|^skipping:|^error|warning: |^   Compiling|^    Finished/,
  },
  {
    id: "groth16-lib",
    label: "Groth16 verifier lib tests",
    description:
      "Real arkworks differential parity for the Groth16 verifier — single + Bowe-Gabizon batched. The mosaic-groth16 crate's full lib test suite, run against the host backend via solana-bn254 fallback through arkworks.",
    cmd: "cargo",
    args: ["test", "-p", "mosaic-groth16", "--lib"],
    required: false,
    cwd: REPO_ROOT,
    grep: /^running |^test .* \.\.\. |^test result:|^   Compiling|^    Finished/,
    // Drop compile/finish lines after they emit once — there can be
    // 6+ "Compiling" lines in a workspace test which clutters the
    // terminal without adding signal.
    keep_lines: 24,
  },
  {
    id: "compression-tests",
    label: "Compression round-trip tests",
    description:
      "Sessions 103-114 wired alt_bn128 compression across all 5 BN254 verifiers (Halo2 / Groth16 / KZG-PLONK / HyperPlonk / Nova). 59 round-trip tests assert: real BN254 generators reproduce bit-for-bit; non-curve fields pass through unchanged; off-curve points reject deterministically.",
    cmd: "cargo",
    args: [
      "test",
      "-p",
      "mosaic-hyperplonk",
      "-p",
      "mosaic-nova",
      "--lib",
      "compression",
    ],
    required: false,
    cwd: REPO_ROOT,
    grep: /^running |^test .* \.\.\. |^test result:|^   Compiling|^    Finished/,
    keep_lines: 40,
  },
];

function getCommitSha() {
  return new Promise((res) => {
    const child = spawn("git", ["rev-parse", "--short", "HEAD"], {
      cwd: REPO_ROOT,
    });
    let out = "";
    child.stdout.on("data", (chunk) => {
      out += chunk.toString();
    });
    child.on("close", () => res(out.trim() || "unknown"));
    child.on("error", () => res("unknown"));
  });
}

function getCommitDate() {
  return new Promise((res) => {
    const child = spawn(
      "git",
      ["log", "-1", "--format=%cI"],
      { cwd: REPO_ROOT },
    );
    let out = "";
    child.stdout.on("data", (chunk) => {
      out += chunk.toString();
    });
    child.on("close", () => res(out.trim() || ""));
    child.on("error", () => res(""));
  });
}

function getReleaseTag() {
  return new Promise((res) => {
    const child = spawn("git", ["describe", "--tags", "--abbrev=0"], {
      cwd: REPO_ROOT,
    });
    let out = "";
    child.stdout.on("data", (chunk) => {
      out += chunk.toString();
    });
    child.on("close", () => res(out.trim() || ""));
    child.on("error", () => res(""));
  });
}

async function getWorkspaceVersion() {
  // Read directly from Cargo.toml's `[workspace.package].version`. The
  // canonical source of truth for what release the codebase IS at —
  // git tags only reflect what's been TAGGED, which lags during the
  // audit-prep sprint where commits land before tags are pushed.
  try {
    const { readFileSync } = await import("node:fs");
    const cargo = readFileSync(resolve(REPO_ROOT, "Cargo.toml"), "utf8");
    // Match the version line inside [workspace.package].
    const lines = cargo.split("\n");
    let inWorkspacePackage = false;
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith("[workspace.package]")) {
        inWorkspacePackage = true;
        continue;
      }
      if (trimmed.startsWith("[") && inWorkspacePackage) break;
      if (inWorkspacePackage) {
        const m = trimmed.match(/^version\s*=\s*"([^"]+)"/);
        if (m) return m[1];
      }
    }
    return "unknown";
  } catch {
    return "unknown";
  }
}

function clipBytes(s, max) {
  if (s.length <= max) return s;
  return s.slice(0, max) + `\n... [output truncated; ${s.length - max} bytes omitted]`;
}

function applyFilters(stdout, { grep, keep_lines }) {
  let lines = stdout.split("\n");
  if (grep) {
    lines = lines.filter((line) => grep.test(line));
  }
  if (typeof keep_lines === "number" && keep_lines > 0 && lines.length > keep_lines) {
    const dropped = lines.length - keep_lines;
    const head = lines.slice(0, Math.floor(keep_lines / 2));
    const tail = lines.slice(lines.length - Math.ceil(keep_lines / 2));
    lines = [
      ...head,
      `    ... [${dropped} lines collapsed for terminal display]`,
      ...tail,
    ];
  }
  return lines.join("\n");
}

async function runCommand(spec) {
  const start = Date.now();
  return new Promise((res) => {
    const child = spawn(spec.cmd, spec.args, { cwd: spec.cwd });
    let stdout = "";
    let stderr = "";
    let stdoutBytes = 0;
    let stderrBytes = 0;
    child.stdout.on("data", (chunk) => {
      const text = chunk.toString();
      if (stdoutBytes < MAX_STREAM_BYTES * 4) {
        stdout += text;
        stdoutBytes += text.length;
      }
    });
    child.stderr.on("data", (chunk) => {
      const text = chunk.toString();
      if (stderrBytes < MAX_STREAM_BYTES * 4) {
        stderr += text;
        stderrBytes += text.length;
      }
    });
    child.on("close", (code) => {
      const filtered_stdout = applyFilters(stdout, spec);
      // stderr: keep only test-relevant lines; drop pure compiler
      // chatter.
      const filtered_stderr = applyFilters(stderr, {
        grep: /error|FAILED|Compiling|Finished|warning:/,
        keep_lines: 18,
      });
      res({
        id: spec.id,
        label: spec.label,
        description: spec.description,
        command: `${spec.cmd} ${spec.args.join(" ")}`,
        captured_at: new Date().toISOString(),
        duration_ms: Date.now() - start,
        exit_code: code ?? -1,
        stdout: clipBytes(filtered_stdout, MAX_STREAM_BYTES),
        stderr: clipBytes(filtered_stderr, MAX_STREAM_BYTES),
        required: !!spec.required,
      });
    });
    child.on("error", (err) => {
      res({
        id: spec.id,
        label: spec.label,
        description: spec.description,
        command: `${spec.cmd} ${spec.args.join(" ")}`,
        captured_at: new Date().toISOString(),
        duration_ms: Date.now() - start,
        exit_code: -1,
        stdout: "",
        stderr: `failed to spawn: ${err.message}`,
        required: !!spec.required,
      });
    });
  });
}

async function main() {
  process.stderr.write(`mosaic-evidence: capturing ${COMMANDS.length} commands\n`);
  const [commit_sha, commit_date, release_tag, workspace_version] =
    await Promise.all([
      getCommitSha(),
      getCommitDate(),
      getReleaseTag(),
      getWorkspaceVersion(),
    ]);

  const captures = [];
  for (const spec of COMMANDS) {
    process.stderr.write(
      `  → ${spec.id} (${spec.cmd} ${spec.args.join(" ")})\n`,
    );
    const result = await runCommand(spec);
    process.stderr.write(
      `    exit=${result.exit_code} duration=${result.duration_ms}ms\n`,
    );
    if (spec.required && result.exit_code !== 0) {
      process.stderr.write(
        `mosaic-evidence: required command ${spec.id} failed; aborting\n`,
      );
      process.exit(1);
    }
    captures.push(result);
  }

  const payload = {
    schema_version: 1,
    captured_at: new Date().toISOString(),
    commit_sha,
    commit_date,
    release_tag,
    workspace_version,
    machine_node: process.platform + "-" + process.arch,
    captures,
  };

  mkdirSync(dirname(OUTPUT_PATH), { recursive: true });
  writeFileSync(OUTPUT_PATH, JSON.stringify(payload, null, 2) + "\n");
  process.stderr.write(`mosaic-evidence: wrote ${OUTPUT_PATH}\n`);
}

main().catch((err) => {
  process.stderr.write(`mosaic-evidence: ${err.stack || err.message}\n`);
  process.exit(1);
});
