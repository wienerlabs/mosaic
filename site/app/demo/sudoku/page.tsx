// /demo/sudoku
//
// ZK-Sudoku demo. Real artifacts produced at build time by the
// `mosaic-demo-sudoku` crate's `generate-fixtures` binary; loaded by
// the page at mount; verified live in the browser via the same
// captured-replay pattern the runtime-evidence terminal uses on
// page 07.
//
// Page composition:
//
//   1. Header strip — WIENER wordmark + tag + heading + subtitle.
//   2. The Puzzle — 9×9 sudoku grid in Mosaic palette, click any
//      cell to flip between clue-only ("what the verifier sees")
//      and full-solution ("what the prover knows"). Default is
//      clue-only because the proof's whole point is that the
//      verifier never sees the solution.
//   3. The Circuit — instrumentation: constraint count breakdown
//      table + timings + sizes.
//   4. The Proof — cryptographic provenance: SHA-256 digests of
//      VK / proof_valid / proof_tampered / public_inputs / puzzle.
//      Each line links to the raw .bin so visitors can inspect.
//   5. Verification — two buttons, valid and tampered. Each fires
//      the captured Mosaic verifier output into the terminal
//      replay, showing exactly the cargo-run output we captured at
//      build time (with the same SHA-256 we'd reproduce locally).
//
// All styling reuses the .mtm-* and .mag-* class grammar from
// globals.css. No new component fonts, no new colors.

import type { Metadata } from "next";

import RuntimeEvidenceTerminal from "../../components/RuntimeEvidenceTerminal";
import { ThemeToggle } from "../../components/ThemeToggle";

import { SudokuDemo } from "./SudokuDemo";

export const metadata: Metadata = {
  title: "Mosaic // ZK-Sudoku demo",
  description:
    "Prove knowledge of a sudoku solution without revealing it. " +
    "Real arkworks Groth16 proof, real Mosaic verifier — same byte format the on-chain dispatcher accepts.",
};

export default function SudokuDemoPage() {
  return (
    <main className="demo-root">
      <ThemeToggle />
      <SudokuDemo />
      <section className="demo-runtime">
        <div className="demo-runtime-header">
          <span className="tag">RUNTIME EVIDENCE // FROM PAGE 07</span>
          <h2 className="sub-display">
            And the rest of
            <br />
            the Mosaic loop
          </h2>
          <p className="mag-lead">
            The terminal below is the same captured-evidence panel
            from the main onepager — it shows the workspace-wide
            tests, fuzz inventory, and on-chain artifact info. The
            sudoku capture above plugs into the same Mosaic verifier
            this terminal demonstrates.
          </p>
        </div>
        <RuntimeEvidenceTerminal />
      </section>
    </main>
  );
}
