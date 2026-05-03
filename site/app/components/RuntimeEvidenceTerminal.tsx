"use client";

// RuntimeEvidenceTerminal.tsx
//
// The "really proves it works on chain" surface for page 07 of the
// onepager. It feeds real captured workspace command output (from
// `site/scripts/capture-runtime-evidence.mjs`, written to
// `public/runtime-evidence.json`) into the Terminal component, with
// a button row for switching between captures.
//
// Provenance contract — what makes this real, not a mock:
//
//   1. Every byte of stdout shown was produced by spawning the
//      command on a real machine (developer laptop or CI runner)
//      against the live Mosaic workspace.
//   2. The capture record carries the commit SHA at capture time,
//      the duration of the run, and the exit code.
//   3. The reproducibility recipe under the terminal lists the
//      exact command — visitors can run it locally and get
//      identical output (modulo CU drift across compiler revisions
//      which is itself caught by the bench's tolerance gate).
//
// We deliberately replay the bytes deterministically rather than
// stand up a server runtime that re-spawns `cargo` per visitor:
// the marketing site is a static deploy, we don't want to make
// every visit a load test, and the captured output is the same
// signal regardless of when it's replayed.

import { useEffect, useMemo, useState } from "react";

import { AnimatedSpan, Terminal, TypingAnimation } from "./Terminal";

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
  required: boolean;
}

interface EvidencePayload {
  schema_version: number;
  captured_at: string;
  commit_sha: string;
  commit_date: string;
  release_tag: string;
  workspace_version: string;
  machine_node: string;
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
    // Locale-stable ISO presentation, no time zone surprises.
    return d.toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
  } catch {
    return iso;
  }
}

// Cap line count so a runaway capture can't blow up the terminal
// height. We keep the head + tail; the middle gets a single
// collapsing marker line.
function clampLines(stdout: string, max = 22): string[] {
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
  /** Optional: inline the payload at build time instead of fetching. */
  inline?: EvidencePayload;
}

export default function RuntimeEvidenceTerminal({ inline }: Props) {
  const [payload, setPayload] = useState<EvidencePayload | null>(inline ?? null);
  const [activeId, setActiveId] = useState<string | null>(
    inline?.captures[0]?.id ?? null,
  );
  const [generation, setGeneration] = useState(0);
  const [error, setError] = useState<string | null>(null);

  // Fetch the captured payload at runtime when it isn't inlined.
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
      // Re-clicking the active button re-runs the replay.
      setGeneration((g) => g + 1);
      return;
    }
    setActiveId(id);
    setGeneration((g) => g + 1);
  };

  const stdoutLines = useMemo(() => {
    if (!active) return [];
    return clampLines(active.stdout, 22);
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

  // Provenance metadata bar — workspace version (canonical from
  // Cargo.toml) + commit + capture timestamp + machine. The
  // workspace version is the truth at the moment of capture; the
  // git tag is shown only when it differs from the workspace
  // version (which is the case during the audit-prep sprint where
  // commits land ahead of tag pushes).
  const versionLabel =
    payload.workspace_version && payload.workspace_version !== "unknown"
      ? `v${payload.workspace_version}`
      : payload.release_tag || "unreleased";
  const metadata = (
    <dl className="mtm-meta-grid">
      <div className="mtm-meta-cell">
        <dt>Workspace</dt>
        <dd>{versionLabel}</dd>
      </div>
      <div className="mtm-meta-cell">
        <dt>Commit</dt>
        <dd>
          <code>{payload.commit_sha}</code>
        </dd>
      </div>
      <div className="mtm-meta-cell">
        <dt>Captured</dt>
        <dd>{formatTimestamp(payload.captured_at)}</dd>
      </div>
      <div className="mtm-meta-cell">
        <dt>Machine</dt>
        <dd>{payload.machine_node}</dd>
      </div>
    </dl>
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
            </span>
          </button>
        );
      })}
    </div>
  );

  const footer = (
    <div className="mtm-footer-row">
      <div className="mtm-footer-cell">
        <span className="mtm-footer-label">Exit</span>
        <span className="mtm-footer-val">{exitCodeToken(active.exit_code)}</span>
      </div>
      <div className="mtm-footer-cell">
        <span className="mtm-footer-label">Duration</span>
        <span className="mtm-footer-val">{formatDuration(active.duration_ms)}</span>
      </div>
      <div className="mtm-footer-cell">
        <span className="mtm-footer-label">Captured at</span>
        <span className="mtm-footer-val">{formatTimestamp(active.captured_at)}</span>
      </div>
      <div className="mtm-footer-cell mtm-footer-replay">
        <button
          type="button"
          className="mtm-replay"
          onClick={() => setGeneration((g) => g + 1)}
        >
          Replay capture
        </button>
      </div>
    </div>
  );

  // Active capture description, rendered above the typed prompt.
  // We type the command (so it looks like the user invoked it) then
  // fade in each stdout line.
  return (
    <div className="mtm-host">
      <p className="mtm-description">{active.description}</p>
      <Terminal
        sequence
        startOnView
        generation={generation}
        chromeLabel="MOSAIC // RUNTIME EVIDENCE"
        metadata={metadata}
        toolbar={toolbar}
        footer={footer}
      >
        {/*
          Each animated child is keyed on `${active.id}-${generation}`
          so React mounts a fresh instance on capture switch / replay.
          Without the key, motion's `animate` prop transitions opacity
          1 → 0 → 1 on prop change, and a stale `onAnimationComplete`
          can advance the sequence index before the new generation
          finishes setting up.
        */}
        <AnimatedSpan
          key={`prompt-${active.id}-${generation}`}
          className="mtm-line-prompt"
        >
          <span className="mtm-prompt-host">mosaic@workspace</span>
          <span className="mtm-prompt-sep">:</span>
          <span className="mtm-prompt-path">{`~/mosaic [${payload.commit_sha}]`}</span>
          <span className="mtm-prompt-sep">$</span>
        </AnimatedSpan>
        <TypingAnimation
          key={`cmd-${active.id}-${generation}`}
          duration={14}
          className="mtm-line-cmd"
        >
          {active.command}
        </TypingAnimation>
        {stdoutLines.map((line, idx) => (
          <AnimatedSpan
            key={`out-${active.id}-${generation}-${idx}`}
            className="mtm-line-out"
          >
            {line === "" ? " " : line}
          </AnimatedSpan>
        ))}
        <AnimatedSpan
          key={`result-${active.id}-${generation}`}
          className="mtm-line-result"
        >
          {`process exited ${exitCodeToken(active.exit_code)} after ${formatDuration(
            active.duration_ms,
          )}`}
        </AnimatedSpan>
      </Terminal>
    </div>
  );
}
