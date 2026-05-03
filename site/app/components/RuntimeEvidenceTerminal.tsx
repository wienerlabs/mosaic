"use client";

// RuntimeEvidenceTerminal.tsx
//
// The "really proves it works on chain" surface for page 07 of the
// onepager. It feeds real captured workspace command output (from
// `site/scripts/capture-runtime-evidence.mjs`, written to
// `public/runtime-evidence.json`) into the Terminal component, with
// a button row for switching between captures plus an evidence-
// fingerprint footer (SHA-256 of stdout||stderr).
//
// Provenance contract — what makes this real, not a mock:
//
//   1. Every byte of stdout shown was produced by spawning the
//      command on a real machine against the live Mosaic workspace.
//   2. The capture record carries the commit SHA at capture time,
//      duration, exit code, byte count, line count, and a SHA-256
//      digest of (stdout || "\n--\n" || stderr). The digest is
//      reproducible: anyone running `cargo test` etc. against the
//      same commit gets the same bytes (modulo wall-clock + ASCII
//      progress chatter that is filtered out before hashing).
//   3. The reproducibility recipe under the terminal lists the
//      exact command — visitors run it locally and get identical
//      output.

import { useEffect, useMemo, useState } from "react";

import { AnimatedSpan, Terminal, TypingAnimation } from "./Terminal";

interface TestSummary {
  status: string;
  passed: number;
  failed: number;
  ignored: number;
  measured: number;
  filtered: number;
}

interface CaptureRecord {
  id: string;
  label: string;
  description: string;
  command: string;
  captured_at: string;
  duration_ms: number;
  exit_code: number;
  stdout: string;
  stderr: string;
  stdout_bytes_raw: number;
  stderr_bytes_raw: number;
  stdout_lines: number;
  digest_sha256: string;
  test_summary: TestSummary | null;
  required: boolean;
}

interface EvidenceTotals {
  captures: number;
  captures_ok: number;
  total_duration_ms: number;
  total_stdout_bytes: number;
  total_test_passed: number;
}

interface EvidencePayload {
  schema_version: number;
  captured_at: string;
  workspace_version: string;
  release_tag: string;
  branch: string;
  commit_sha: string;
  commit_date: string;
  commit_subject: string;
  machine_node: string;
  node_version: string;
  totals: EvidenceTotals;
  captures: CaptureRecord[];
}

const PUBLIC_PATH = "/runtime-evidence.json";

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

function formatTimestamp(iso: string): string {
  if (!iso) return "—";
  try {
    const d = new Date(iso);
    return d.toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
  } catch {
    return iso;
  }
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / 1024 / 1024).toFixed(2)} MiB`;
}

// Cap line count so a runaway capture can't blow the terminal height.
function clampLines(stdout: string, max = 28): string[] {
  const lines = stdout.split("\n");
  if (lines.length <= max) return lines;
  const head = Math.floor(max / 2);
  const tail = max - head - 1;
  return [
    ...lines.slice(0, head),
    `    ... [${lines.length - max} lines collapsed]`,
    ...lines.slice(lines.length - tail),
  ];
}

function exitCodeToken(code: number): string {
  if (code === 0) return "OK";
  if (code === -1) return "SPAWN-FAILED";
  return `EXIT-${code}`;
}

interface Props {
  inline?: EvidencePayload;
}

export default function RuntimeEvidenceTerminal({ inline }: Props) {
  const [payload, setPayload] = useState<EvidencePayload | null>(inline ?? null);
  const [activeId, setActiveId] = useState<string | null>(
    inline?.captures[0]?.id ?? null,
  );
  const [generation, setGeneration] = useState(0);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (inline) return;
    let cancelled = false;
    fetch(PUBLIC_PATH, { cache: "no-store" })
      .then((r) => {
        if (!r.ok) throw new Error(`fetch ${PUBLIC_PATH}: ${r.status}`);
        return r.json() as Promise<EvidencePayload>;
      })
      .then((p) => {
        if (cancelled) return;
        setPayload(p);
        setActiveId(p.captures[0]?.id ?? null);
      })
      .catch((e) => {
        if (cancelled) return;
        setError(e instanceof Error ? e.message : String(e));
      });
    return () => {
      cancelled = true;
    };
  }, [inline]);

  const active = useMemo(() => {
    if (!payload || !activeId) return null;
    return payload.captures.find((c) => c.id === activeId) ?? null;
  }, [payload, activeId]);

  const onSelect = (id: string) => {
    if (id === activeId) {
      setGeneration((g) => g + 1);
      return;
    }
    setActiveId(id);
    setGeneration((g) => g + 1);
  };

  const stdoutLines = useMemo(() => {
    if (!active) return [];
    return clampLines(active.stdout, 28);
  }, [active]);

  if (error) {
    return (
      <div className="mtm-empty">
        Could not load captured evidence: {error}.
        <br />
        Run <code>node site/scripts/capture-runtime-evidence.mjs</code>{" "}
        from the repo root to regenerate.
      </div>
    );
  }

  if (!payload || !active) {
    return (
      <div className="mtm-empty">
        Loading captured runtime evidence…
      </div>
    );
  }

  // Header strip — workspace summary across ALL captures, plus
  // identity columns. Read top-to-bottom: who you are looking at,
  // when, against which workspace, on which machine.
  const versionLabel =
    payload.workspace_version && payload.workspace_version !== "unknown"
      ? `v${payload.workspace_version}`
      : payload.release_tag || "unreleased";

  const headStats: Array<[string, string]> = [
    ["Workspace", versionLabel],
    ["Commit", payload.commit_sha],
    ["Branch", payload.branch],
    ["Captured", formatTimestamp(payload.captured_at)],
    ["Machine", payload.machine_node],
    ["Node", payload.node_version],
  ];

  const aggregateStats: Array<[string, string]> = [
    ["Captures", `${payload.totals.captures_ok}/${payload.totals.captures} OK`],
    ["Tests passed", `${payload.totals.total_test_passed}`],
    ["Wall-clock", formatDuration(payload.totals.total_duration_ms)],
    ["stdout total", formatBytes(payload.totals.total_stdout_bytes)],
  ];

  const metadata = (
    <div className="mtm-meta-stack">
      <dl className="mtm-meta-grid mtm-meta-grid-6">
        {headStats.map(([k, v]) => (
          <div className="mtm-meta-cell" key={k}>
            <dt>{k}</dt>
            <dd>
              {k === "Commit" ? <code>{v}</code> : v}
            </dd>
          </div>
        ))}
      </dl>
      <dl className="mtm-meta-grid mtm-meta-grid-4 mtm-meta-grid-strong">
        {aggregateStats.map(([k, v]) => (
          <div className="mtm-meta-cell" key={k}>
            <dt>{k}</dt>
            <dd>{v}</dd>
          </div>
        ))}
      </dl>
    </div>
  );

  const toolbar = (
    <div className="mtm-toolbar-row" role="toolbar" aria-label="Runtime evidence captures">
      {payload.captures.map((c) => {
        const isActive = c.id === active.id;
        const ok = c.exit_code === 0;
        const cls = [
          "mtm-tab",
          isActive ? "mtm-tab-active" : "",
          ok ? "mtm-tab-ok" : "mtm-tab-fail",
        ]
          .join(" ")
          .trim();
        return (
          <button
            key={c.id}
            type="button"
            className={cls}
            onClick={() => onSelect(c.id)}
            aria-pressed={isActive}
            aria-label={`${c.label} (${exitCodeToken(c.exit_code)}, ${formatDuration(
              c.duration_ms,
            )})`}
          >
            <span className="mtm-tab-label">{c.label}</span>
            <span className="mtm-tab-suffix">
              {exitCodeToken(c.exit_code)} · {formatDuration(c.duration_ms)}
              {c.test_summary
                ? ` · ${c.test_summary.passed} pass`
                : ""}
            </span>
          </button>
        );
      })}
    </div>
  );

  // Below the typed area: capture-specific provenance — exact
  // command, exit, duration, stdout/stderr byte counts, parsed test
  // summary, content digest, replay button.
  const provenanceCells: Array<[string, React.ReactNode]> = [
    ["command", <code key="c">{active.command}</code>],
    ["exit", exitCodeToken(active.exit_code)],
    ["duration", formatDuration(active.duration_ms)],
    [
      "stdout",
      `${formatBytes(active.stdout_bytes_raw)} / ${active.stdout_lines} lines`,
    ],
    ["stderr", `${formatBytes(active.stderr_bytes_raw)}`],
    ["captured", formatTimestamp(active.captured_at)],
  ];
  if (active.test_summary) {
    provenanceCells.push([
      "test result",
      `${active.test_summary.status} · ${active.test_summary.passed} passed · ${active.test_summary.failed} failed · ${active.test_summary.ignored} ignored`,
    ]);
  }
  provenanceCells.push([
    "sha-256",
    <code key="h">{active.digest_sha256}</code>,
  ]);

  const footer = (
    <div className="mtm-footer-stack">
      <dl className="mtm-prov-grid">
        {provenanceCells.map(([k, v]) => (
          <div className="mtm-prov-row" key={k}>
            <dt>{k}</dt>
            <dd>{v}</dd>
          </div>
        ))}
      </dl>
      <div className="mtm-footer-actions">
        <button
          type="button"
          className="mtm-replay"
          onClick={() => setGeneration((g) => g + 1)}
        >
          Replay capture
        </button>
        <a
          className="mtm-jump"
          href={PUBLIC_PATH}
          target="_blank"
          rel="noopener"
        >
          Inspect raw JSON
        </a>
      </div>
    </div>
  );

  return (
    <div className="mtm-host">
      <p className="mtm-description">{active.description}</p>
      <Terminal
        sequence
        startOnView
        generation={generation}
        chromeLabel="MOSAIC // RUNTIME EVIDENCE"
        chromeRight={`schema v${payload.schema_version}`}
        metadata={metadata}
        toolbar={toolbar}
        footer={footer}
      >
        {/* Each animated child is keyed on `${active.id}-${generation}`
          * so React mounts a fresh instance on capture switch / replay.
          * Without the keys, motion's animate prop transitions
          * opacity 1 → 0 → 1 on prop change and a stale
          * onAnimationComplete callback can advance the sequence
          * index before the new generation finishes setting up. */}
        <AnimatedSpan
          key={`prompt-${active.id}-${generation}`}
          className="mtm-line-prompt"
        >
          <span className="mtm-prompt-host">mosaic@workspace</span>
          <span className="mtm-prompt-sep">:</span>
          <span className="mtm-prompt-path">
            {`~/mosaic [${payload.commit_sha} ${payload.branch}]`}
          </span>
          <span className="mtm-prompt-sep">$</span>
        </AnimatedSpan>
        <TypingAnimation
          key={`cmd-${active.id}-${generation}`}
          duration={12}
          className="mtm-line-cmd"
        >
          {active.command}
        </TypingAnimation>
        {stdoutLines.map((line, idx) => (
          <AnimatedSpan
            key={`out-${active.id}-${generation}-${idx}`}
            className="mtm-line-out"
          >
            {line === "" ? " " : line}
          </AnimatedSpan>
        ))}
        <AnimatedSpan
          key={`result-${active.id}-${generation}`}
          className="mtm-line-result"
        >
          {`process exited ${exitCodeToken(active.exit_code)} after ${formatDuration(
            active.duration_ms,
          )} · ${formatBytes(active.stdout_bytes_raw)} stdout · digest ${active.digest_sha256.slice(0, 16)}`}
        </AnimatedSpan>
      </Terminal>
    </div>
  );
}
