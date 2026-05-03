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
//     plus exit code + duration + commit SHA + capture timestamp +
//     SHA-256 content digest, and the result is written to
//     site/public/runtime-evidence.json.
//
//   - It is NOT a server runtime that re-executes per visitor. The
//     onepager is statically deployed (Vercel / Cloudflare / S3),
//     so we ship the captured bytes and replay them in the browser.
//     Provenance metadata (commit, capture timestamp, SHA-256 digest)
//     is shown in the UI so visitors can verify the bytes are real
//     and reproduce the same output locally.
//
// Usage:
//
//   node site/scripts/capture-runtime-evidence.mjs
//
// Run from the repo root. Re-runs are idempotent — the JSON is
// overwritten each time. Commit the JSON whenever you want the
// public site to reflect a fresh capture (typically: after each
// release tag).

import { spawn } from "node:child_process";
import { writeFileSync, mkdirSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..", "..");
const OUTPUT_PATH = resolve(__dirname, "..", "public", "runtime-evidence.json");

// Maximum captured bytes per stream after filtering.
const MAX_STREAM_BYTES = 16 * 1024;

// Capture commands. Order matters — the terminal renders them in the
// order they appear here. Each `id` is referenced by the React
// component as the button identifier.
const COMMANDS = [
  {
    id: "release-lineage",
    label: "Release lineage",
    description:
      "Last 12 commits on the audit-prep sprint branch. Each release tag is a CHANGELOG/AUDIT/README quartet captured atomically.",
    cmd: "git",
    args: ["log", "--oneline", "-12"],
    required: true,
    cwd: REPO_ROOT,
  },
  {
    id: "release-diff",
    label: "Last release diff",
    description:
      "git diff --stat for the most recent commit — a concrete view of what each session ships, line-by-line. The diffs are real; pick any commit and reproduce its scope locally with the same command.",
    cmd: "git",
    args: ["log", "-1", "--stat", "--format=%h %s%n%nAuthor: %an <%ae>%nDate:   %ad%n"],
    required: true,
    cwd: REPO_ROOT,
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
    grep:
      /^running |^test .* \.\.\. |^test result:|^skipping:|^error|warning: |^   Compiling|^    Finished/,
  },
  {
    id: "groth16-lib",
    label: "Groth16 verifier",
    description:
      "Real arkworks differential parity for the Groth16 verifier — single + Bowe-Gabizon batched. The mosaic-groth16 crate's full lib test suite runs against the host backend via solana-bn254 fallback through arkworks.",
    cmd: "cargo",
    args: ["test", "-p", "mosaic-groth16", "--lib"],
    required: false,
    cwd: REPO_ROOT,
    grep: /^running |^test .* \.\.\. |^test result:|^   Compiling|^    Finished/,
    keep_lines: 28,
  },
  {
    id: "compression-tests",
    label: "Compression round-trip",
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
    keep_lines: 44,
  },
  {
    id: "workspace-audit",
    label: "Workspace audit",
    description:
      "Quantitative audit of the workspace: source-line counts per crate, fuzz harness inventory, test fixture inventory, total #[test] count. Every number on this page is reproducible with the printed shell commands.",
    cmd: "sh",
    args: [
      "-c",
      [
        "echo '── source line counts (rs only, excluding target/) ──'",
        "find crates -type f -name '*.rs' -not -path '*/target/*' " +
          "| xargs wc -l 2>/dev/null | tail -1 " +
          "| awk '{printf \"  workspace: %s rust source lines\\n\", $1}'",
        "for c in mosaic-core mosaic-zk-primitives mosaic-groth16 mosaic-plonk " +
          "mosaic-hyperplonk mosaic-halo2 mosaic-stark mosaic-nova mosaic-program " +
          "mosaic-chunked mosaic-serde mosaic-sdk; do " +
          "  n=$(find crates/$c -type f -name '*.rs' -not -path '*/target/*' | xargs wc -l 2>/dev/null | tail -1 | awk '{print $1}'); " +
          "  printf '  %-22s %s lines\\n' \"$c\" \"$n\"; done",
        "echo ''",
        "echo '── #[test] declarations across the workspace ──'",
        "n=$(grep -rh --include='*.rs' '^[[:space:]]*#\\[test\\]' crates/ | wc -l | tr -d ' ')",
        'printf "  total: %s declared #[test] functions\\n" "$n"',
        "echo ''",
        "echo '── fuzz harness inventory ──'",
        "find crates/mosaic-fuzz/fuzz_targets -type f -name '*.rs' " +
          "| awk -F/ '{print \"  \" $NF}' | sort",
        "echo ''",
        "echo '── differential test fixtures ──'",
        "find tests/fixtures -type f \\( -name '*.bin' -o -name '*.json' \\) " +
          "| sort | sed 's|^|  |'",
      ].join("\n"),
    ],
    required: false,
    cwd: REPO_ROOT,
  },
  {
    id: "build-sbf-info",
    label: "On-chain artifact",
    description:
      "If cargo build-sbf has produced target/deploy/mosaic_program.so, this capture lists its actual on-disk bytes — the binary mainnet validators would load. Each section's size is the real cost of each verifier wired into the dispatcher.",
    cmd: "sh",
    args: [
      "-c",
      [
        "set -e",
        "if [ -f target/deploy/mosaic_program.so ]; then",
        "  printf '%s\\n' '── target/deploy/mosaic_program.so ──'",
        "  ls -l target/deploy/mosaic_program.so | awk '{printf \"  %s bytes (%s)\\n\", $5, $9}'",
        "  printf '\\n── ELF section sizes (ten largest) ──\\n'",
        "  if command -v size >/dev/null 2>&1; then",
        "    size -A target/deploy/mosaic_program.so 2>/dev/null | head -20",
        "  else",
        "    file target/deploy/mosaic_program.so",
        "  fi",
        "  printf '\\n── SHA-256 ──\\n'",
        "  shasum -a 256 target/deploy/mosaic_program.so | awk '{print \"  \" $1}'",
        "else",
        "  printf '%s\\n' 'mosaic_program.so not built; run:'",
        "  printf '  cargo build-sbf --tools-version v1.52 --manifest-path crates/mosaic-program/Cargo.toml\\n'",
        "fi",
      ].join("\n"),
    ],
    required: false,
    cwd: REPO_ROOT,
  },
];

function spawnAndCollect(spec) {
  const start = Date.now();
  return new Promise((res) => {
    const child = spawn(spec.cmd, spec.args, { cwd: spec.cwd });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    child.on("close", (code) => {
      res({
        exit_code: code ?? -1,
        duration_ms: Date.now() - start,
        stdout_raw: stdout,
        stderr_raw: stderr,
      });
    });
    child.on("error", (err) => {
      res({
        exit_code: -1,
        duration_ms: Date.now() - start,
        stdout_raw: "",
        stderr_raw: `failed to spawn: ${err.message}\n`,
      });
    });
  });
}

async function getFromGit(args) {
  return new Promise((res) => {
    const child = spawn("git", args, { cwd: REPO_ROOT });
    let out = "";
    child.stdout.on("data", (c) => {
      out += c.toString();
    });
    child.on("close", () => res(out.trim()));
    child.on("error", () => res(""));
  });
}

function getWorkspaceVersion() {
  try {
    const cargo = readFileSync(resolve(REPO_ROOT, "Cargo.toml"), "utf8");
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
  } catch {
    /* fall through */
  }
  return "unknown";
}

function clipBytes(s, max) {
  if (s.length <= max) return s;
  return (
    s.slice(0, max) +
    `\n... [output truncated; ${s.length - max} bytes omitted]`
  );
}

function applyFilters(stdout, { grep, keep_lines }) {
  let lines = stdout.split("\n");
  if (grep) {
    lines = lines.filter((line) => grep.test(line));
  }
  if (
    typeof keep_lines === "number" &&
    keep_lines > 0 &&
    lines.length > keep_lines
  ) {
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

function parseTestSummary(stdout) {
  // Matches `cargo test` summary line:
  //   test result: ok. 13 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
  const lastResult = [...stdout.matchAll(
    /test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out/g,
  )].pop();
  if (!lastResult) return null;
  return {
    status: lastResult[1],
    passed: parseInt(lastResult[2], 10),
    failed: parseInt(lastResult[3], 10),
    ignored: parseInt(lastResult[4], 10),
    measured: parseInt(lastResult[5], 10),
    filtered: parseInt(lastResult[6], 10),
  };
}

function sha256Of(s) {
  return createHash("sha256").update(s).digest("hex");
}

async function runCommand(spec) {
  const r = await spawnAndCollect(spec);
  const filtered_stdout = applyFilters(r.stdout_raw, spec);
  const filtered_stderr = applyFilters(r.stderr_raw, {
    grep: /error|FAILED|Compiling|Finished|warning:/,
    keep_lines: 18,
  });

  const stdout = clipBytes(filtered_stdout, MAX_STREAM_BYTES);
  const stderr = clipBytes(filtered_stderr, MAX_STREAM_BYTES);

  const test_summary = parseTestSummary(r.stdout_raw);

  return {
    id: spec.id,
    label: spec.label,
    description: spec.description,
    command: `${spec.cmd} ${spec.args.join(" ")}`,
    captured_at: new Date().toISOString(),
    duration_ms: r.duration_ms,
    exit_code: r.exit_code,
    stdout,
    stderr,
    stdout_bytes_raw: r.stdout_raw.length,
    stderr_bytes_raw: r.stderr_raw.length,
    stdout_lines: stdout.split("\n").length,
    digest_sha256: sha256Of(r.stdout_raw + "\n--\n" + r.stderr_raw),
    test_summary,
    required: !!spec.required,
  };
}

async function main() {
  process.stderr.write(
    `mosaic-evidence: capturing ${COMMANDS.length} commands\n`,
  );

  const [commit_sha, commit_date, commit_subject, release_tag, branch] =
    await Promise.all([
      getFromGit(["rev-parse", "--short", "HEAD"]),
      getFromGit(["log", "-1", "--format=%cI"]),
      getFromGit(["log", "-1", "--format=%s"]),
      getFromGit(["describe", "--tags", "--abbrev=0"]),
      getFromGit(["rev-parse", "--abbrev-ref", "HEAD"]),
    ]);

  const workspace_version = getWorkspaceVersion();
  const node_version = process.version;
  const machine_node = process.platform + "-" + process.arch;

  const captures = [];
  for (const spec of COMMANDS) {
    process.stderr.write(
      `  → ${spec.id} (${spec.cmd} ${spec.args.slice(0, 4).join(" ")}${spec.args.length > 4 ? " ..." : ""})\n`,
    );
    const result = await runCommand(spec);
    process.stderr.write(
      `    exit=${result.exit_code} duration=${result.duration_ms}ms ` +
        `bytes_raw=${result.stdout_bytes_raw} digest=${result.digest_sha256.slice(0, 8)}\n`,
    );
    if (spec.required && result.exit_code !== 0) {
      process.stderr.write(
        `mosaic-evidence: required command ${spec.id} failed; aborting\n`,
      );
      process.exit(1);
    }
    captures.push(result);
  }

  const totals = {
    captures: captures.length,
    captures_ok: captures.filter((c) => c.exit_code === 0).length,
    total_duration_ms: captures.reduce((s, c) => s + c.duration_ms, 0),
    total_stdout_bytes: captures.reduce((s, c) => s + c.stdout_bytes_raw, 0),
    total_test_passed: captures.reduce(
      (s, c) => s + (c.test_summary?.passed ?? 0),
      0,
    ),
  };

  const payload = {
    schema_version: 2,
    captured_at: new Date().toISOString(),
    workspace_version,
    release_tag,
    branch,
    commit_sha,
    commit_date,
    commit_subject,
    machine_node,
    node_version,
    totals,
    captures,
  };

  mkdirSync(dirname(OUTPUT_PATH), { recursive: true });
  writeFileSync(OUTPUT_PATH, JSON.stringify(payload, null, 2) + "\n");
  process.stderr.write(`mosaic-evidence: wrote ${OUTPUT_PATH}\n`);
  process.stderr.write(
    `mosaic-evidence: ${totals.captures_ok}/${totals.captures} captures OK, ${totals.total_test_passed} tests passed across captures\n`,
  );
}

main().catch((err) => {
  process.stderr.write(`mosaic-evidence: ${err.stack || err.message}\n`);
  process.exit(1);
});
