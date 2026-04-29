"use client";

/**
 * @author: @kokonutui (original)
 * @adapted: Mosaic palette port — Tailwind → plain CSS, monochrome
 *           blue circles instead of rainbow. Used as the loading
 *           fallback for the dynamically-imported PixelTrail hero
 *           background.
 * @license: MIT
 */

import { useEffect, useRef, useState } from "react";

import "./AILoadingState.css";

const TASK_SEQUENCES = [
  {
    status: "Compiling shaders",
    lines: [
      "Initializing WebGL context...",
      "Compiling vertex shader...",
      "Compiling fragment shader...",
      "Linking shader program...",
      "Allocating mouse-trail texture...",
    ],
  },
  {
    status: "Verifying primitives",
    lines: [
      "Loading BN254 curve parameters...",
      "Initializing Fr field arithmetic...",
      "Configuring KZG SRS handles...",
      "Warming up alt_bn128 syscalls...",
      "Validating audit-gate matrix...",
      "Checking Fiat-Shamir transcripts...",
      "Calibrating compute-unit budgets...",
      "Finalizing primitive checks...",
    ],
  },
  {
    status: "Tuning the hero",
    lines: [
      "Initializing pixel grid...",
      "Configuring trail interpolation...",
      "Applying gooey filter...",
      "Honoring reduced-motion preference...",
      "Synchronizing pointer capture...",
      "Optimizing render loop...",
      "Validating color contrast...",
      "Locking color palette...",
      "Hero ready.",
    ],
  },
];

interface LoadingAnimationProps {
  progress: number;
}

const LoadingAnimation = ({ progress }: LoadingAnimationProps) => (
  <div className="ai-loader-spinner">
    <svg
      aria-label={`Loading progress: ${Math.round(progress)}%`}
      viewBox="0 0 240 240"
      xmlns="http://www.w3.org/2000/svg"
    >
      <title>Loading Progress Indicator</title>

      <defs>
        <mask id="ai-loader-progress-mask">
          <rect fill="black" height="240" width="240" />
          <circle
            cx="120"
            cy="120"
            fill="white"
            r="120"
            strokeDasharray={`${(progress / 100) * 754}, 754`}
            transform="rotate(-90 120 120)"
          />
        </mask>
      </defs>

      <g
        className="ai-loader-rings"
        mask="url(#ai-loader-progress-mask)"
        strokeDasharray="18% 40%"
        strokeWidth="16"
      >
        {/* Mosaic monochrome blue palette: deep navy → off-white through
         * the accent + PixelTrail blue. All hues sit inside the brand
         * surface so the loader reads as part of the editorial layout
         * rather than as a generic spinner. */}
        <circle cx="120" cy="120" opacity="0.95" r="150" stroke="#112d4e" />
        <circle cx="120" cy="120" opacity="0.95" r="130" stroke="#1f4670" />
        <circle cx="120" cy="120" opacity="0.95" r="110" stroke="#3f72af" />
        <circle cx="120" cy="120" opacity="0.95" r="90" stroke="#6e9cee" />
        <circle cx="120" cy="120" opacity="0.95" r="70" stroke="#a8c4f0" />
        <circle cx="120" cy="120" opacity="0.95" r="50" stroke="#dbe2ef" />
      </g>
    </svg>
  </div>
);

interface VisibleLine {
  text: string;
  number: number;
}

export default function AILoadingState() {
  const [sequenceIndex, setSequenceIndex] = useState(0);
  const [visibleLines, setVisibleLines] = useState<VisibleLine[]>([]);
  const [scrollPosition, setScrollPosition] = useState(0);
  const codeContainerRef = useRef<HTMLDivElement>(null);
  const lineHeight = 28;

  const currentSequence = TASK_SEQUENCES[sequenceIndex];
  const totalLines = currentSequence.lines.length;

  useEffect(() => {
    const initialLines: VisibleLine[] = [];
    for (let i = 0; i < Math.min(5, totalLines); i++) {
      initialLines.push({
        text: currentSequence.lines[i],
        number: i + 1,
      });
    }
    setVisibleLines(initialLines);
    setScrollPosition(0);
  }, [sequenceIndex, currentSequence.lines, totalLines]);

  // Advance one line at a fixed cadence; wrap to the next sequence
  // when the visible window reaches the end of the current set.
  useEffect(() => {
    const advanceTimer = setInterval(() => {
      const firstVisibleLineIndex = Math.floor(scrollPosition / lineHeight);
      const nextLineIndex = (firstVisibleLineIndex + 3) % totalLines;

      if (nextLineIndex < firstVisibleLineIndex && nextLineIndex !== 0) {
        setSequenceIndex(
          (prevIndex) => (prevIndex + 1) % TASK_SEQUENCES.length
        );
        return;
      }

      if (nextLineIndex >= visibleLines.length && nextLineIndex < totalLines) {
        setVisibleLines((prevLines) => [
          ...prevLines,
          {
            text: currentSequence.lines[nextLineIndex],
            number: nextLineIndex + 1,
          },
        ]);
      }

      setScrollPosition((prevPosition) => prevPosition + lineHeight);
    }, 2000);

    return () => clearInterval(advanceTimer);
  }, [
    scrollPosition,
    visibleLines,
    totalLines,
    sequenceIndex,
    currentSequence.lines,
  ]);

  useEffect(() => {
    if (codeContainerRef.current) {
      codeContainerRef.current.scrollTop = scrollPosition;
    }
  }, [scrollPosition]);

  return (
    <div className="ai-loader-root">
      <div className="ai-loader-stack">
        <div className="ai-loader-status">
          <LoadingAnimation
            progress={(sequenceIndex / TASK_SEQUENCES.length) * 100}
          />
          <span className="ai-loader-status-text">
            {currentSequence.status}…
          </span>
        </div>

        <div className="ai-loader-code-wrap">
          <div
            className="ai-loader-code"
            ref={codeContainerRef}
            style={{ scrollBehavior: "smooth" }}
          >
            <div>
              {visibleLines.map((line) => (
                <div
                  className="ai-loader-line"
                  key={`${line.number}-${line.text}`}
                >
                  <div className="ai-loader-line-num">{line.number}</div>
                  <div className="ai-loader-line-text">{line.text}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="ai-loader-fade" aria-hidden="true" />
        </div>
      </div>
    </div>
  );
}
