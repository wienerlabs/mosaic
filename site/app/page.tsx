import { AnimatedMosaic } from "./components/AnimatedMosaic";
import { CheckerboardInterlude } from "./components/CheckerboardInterlude";
import { GsapAnimations } from "./components/GsapAnimations";
// LazyPixelTrail wraps `dynamic(() => import("./PixelTrail"), { ssr: false })`
// inside a client component so this server component can import it
// without crossing the SSR boundary. The wrapper renders the
// Mosaic-palette AILoadingState while the three.js chunk loads.
import LazyPixelTrail from "./components/LazyPixelTrail";
import { NavMenu } from "./components/NavMenu";
import RuntimeEvidenceTerminal from "./components/RuntimeEvidenceTerminal";
import { ThemeToggle } from "./components/ThemeToggle";

const cargoSnippet = `[dependencies]
mosaic-core    = { version = "0.5.0-phase3-complete", features = ["solana"] }
mosaic-groth16 = { version = "0.5.0-phase3-complete", features = ["solana"] }
solana-program = "2.1"`;

const processInstructionSnippet = `use mosaic_core::{
    proof_system::ProofSystem,
    syscall::solana::SolanaSyscallBackend,
};
use mosaic_groth16::Groth16Verifier;

pub fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let backend  = SolanaSyscallBackend::new();
    let verifier = Groth16Verifier::<_, false>::new(&backend);

    let (vk, rest)    = decode_lp(instruction_data)?;
    let (proof, pi)   = decode_lp(rest)?;

    verifier.verify(vk, proof, pi).map_err(Into::into)
}`;

const clientSnippet = `let cu_ix = ComputeBudgetInstruction::set_compute_unit_limit(200_000);
transaction.add(&cu_ix);
transaction.add(&mosaic_sdk::build_verify_proof_ix(&request)?);`;


const architectureTree = ` mosaic-program
       │
       │ dispatch_verify(ProofSystemId, vk, proof, pi)
       │
       ├── Groth16        ──┐
       ├── KZG-PLONK      ──┤
       ├── HyperPlonk     ──┼── mosaic-zk-primitives
       ├── Halo2-KZG      ──┤   (fr, field, msm,
       ├── Nova           ──┘    transcript, g1_consts)
       └── FRI-STARK   ────── mosaic-stark
                              (Goldilocks, Merkle, FRI fold)
`;

type PageColor = "cream" | "wheat" | "navy";

function Page({
  num,
  tag,
  title,
  color,
  children,
}: {
  num: string;
  tag: string;
  title?: React.ReactNode;
  color: PageColor;
  children: React.ReactNode;
}) {
  return (
    <section className={`page page-${color}`} id={`page-${num}`}>
      <div className="page-content">
        <header className="page-header">
          <span className="tag">{tag}</span>
          {title ? <h2 className="sub-display">{title}</h2> : null}
        </header>
        {children}
      </div>
      <aside className="side-strip">
        <span className="rotated">MOSAIC × WIENERLABS.XYZ</span>
      </aside>
      <span className="page-num">{num}</span>
    </section>
  );
}

function MagCodeBlock({
  lang,
  children,
}: {
  lang: string;
  children: React.ReactNode;
}) {
  return (
    <div className="mag-code-block">
      <span className="code-lang">{lang}</span>
      <pre>{children}</pre>
    </div>
  );
}

export default function HomePage() {
  return (
    <>
      <GsapAnimations />
      <ThemeToggle />
      <NavMenu />

      <div className="scroll-progress" aria-hidden="true" />

      {/* PAGE 01 — SPLASH */}
      <main className="magazine">
        <section className="block block-tl">
          <div className="pixel-trail-layer" aria-hidden="true">
            <LazyPixelTrail
              gridSize={50}
              trailSize={0.1}
              maxAge={250}
              interpolate={5}
              color="#6e9cee"
              gooeyFilter={{ id: "mosaic-hero-goo", strength: 2 }}
            />
          </div>
          <div className="block-tl-content">
            <span className="tag">MOSAIC.2026 // INDEX 01</span>
            <h1 className="display" data-split="chars">
              {"MOSAIC".split("").map((ch, i) => (
                <span key={i} className="char">
                  {ch}
                </span>
              ))}
            </h1>
            <a
              className="wiener-stamp"
              href="https://www.wienerlabs.xyz/"
              target="_blank"
              rel="noopener"
            >
              <span className="wiener-stamp-prefix">A</span>
              <span className="wiener-stamp-name">WIENER LABS</span>
              <span className="wiener-stamp-suffix">PRODUCT</span>
            </a>
            <p className="hero-sub">
              An applied cryptography studio shipping open-source
              verifier infrastructure for Solana.
            </p>
            <p className="body-copy">
              Proof-system-agnostic on-chain verification rendered as
              structural primitives. Minimizing the verifier surface to
              expose the underlying cryptographic arrangement of Groth16,
              KZG-PLONK, HyperPlonk, Halo2-KZG, Nova family, and
              FRI-STARK.
            </p>
          </div>
        </section>

        <section className="block block-tr">
          <AnimatedMosaic />
        </section>

        <section className="block block-bl">
          <span className="tag">23. APR 2026</span>
          <h2 className="sub-display">
            Structural
            <br />
            Soundness
          </h2>
          <p className="body-copy">
            The architecture of the verifier is defined not by monolithic
            binaries, but by the explicit boundary traits{" "}
            <span className="circ">④</span> that divide it. This approach
            rejects the invisible dispatcher in favor of the systematic
            <strong> ProofSystem</strong>.
          </p>
        </section>

        <section className="block block-br">
          <p className="body-copy">
            When cryptographic verification is stripped back to primitive
            components, soundness is achieved through gate isolation
            rather than whole-proof compression.{" "}
            <span className="circ">①</span> Twelve independent gates across
            four bodies create soundness density, while scaffold bodies
            hold structural parity.
          </p>
          <p className="body-copy">
            This iteration explores the sustained tension outside of
            Groth16-only paradigms. The focus remains explicitly on the
            emergent properties of proof-system plurality and rigid
            on-chain framing within the Solana compute-unit envelope.
          </p>
        </section>

        <aside className="side-strip">
          <span className="rotated">MOSAIC × WIENERLABS.XYZ</span>
        </aside>
        <span className="page-num">01</span>
      </main>

      {/* PAGE 02 — RELEASE STATE */}
      <Page num="02" tag="INDEX 02 // RELEASE STATE" title="State" color="wheat">
        <p className="mag-lead">
          v0.9.15-onchain-compressed-verify — the current release.
          Six ADR-0006 audit gates across all production verifiers,
          alt_bn128 compression now end-to-end on chain (sessions
          103-116), 712 lib tests + 13 SBF integration tests + 37
          fuzz harnesses + 14 criterion benches workspace-wide.
        </p>
        <div className="stats-grid">
          <div className="stat">
            <span className="stat-label">Lib tests</span>
            <span className="stat-val">712 passing</span>
          </div>
          <div className="stat">
            <span className="stat-label">SBF integration tests</span>
            <span className="stat-val">13 passing</span>
          </div>
          <div className="stat">
            <span className="stat-label">Audit gates</span>
            <span className="stat-val">6 / 6 verifiers</span>
          </div>
          <div className="stat">
            <span className="stat-label">Soundness fixes</span>
            <span className="stat-val">2 real</span>
          </div>
          <div className="stat">
            <span className="stat-label">Compression infra</span>
            <span className="stat-val">5 / 5 BN254 verifiers</span>
          </div>
          <div className="stat">
            <span className="stat-label">Mainnet-ready</span>
            <span className="stat-val">Groth16 + KZG-PLONK</span>
          </div>
        </div>

      </Page>

      {/* PAGE 03 — VERIFIER MATRIX */}
      <Page
        num="03"
        tag="INDEX 03 // VERIFIER MATRIX"
        title="Systems"
        color="cream"
      >
        <p className="mag-lead">
          Six proving systems behind one dispatch surface; Groth16 and
          KZG-PLONK production, the remaining four frozen as Phase-3
          bodies pending external audit.
        </p>
        <table className="mag-table">
          <thead>
            <tr>
              <th>System</th>
              <th>Curve / Field</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Groth16</td>
              <td>BN254</td>
              <td>Production</td>
            </tr>
            <tr>
              <td>KZG-PLONK</td>
              <td>BN254</td>
              <td>Production</td>
            </tr>
            <tr>
              <td>HyperPlonk-KZG</td>
              <td>BN254</td>
              <td>Phase-3 body</td>
            </tr>
            <tr>
              <td>Halo2-KZG (PSE)</td>
              <td>BN254</td>
              <td>Phase-3 body</td>
            </tr>
            <tr>
              <td>Nova / HyperNova / ProtoStar</td>
              <td>BN254</td>
              <td>Phase-3 body</td>
            </tr>
            <tr>
              <td>FRI-STARK</td>
              <td>Goldilocks</td>
              <td>Phase-3 body</td>
            </tr>
          </tbody>
        </table>
      </Page>

      {/* PAGE 04 — WHEN TO USE WHICH */}
      <Page
        num="04"
        tag="INDEX 04 // DECISION MATRIX"
        title={
          <>
            When to use <br />
            which
          </>
        }
        color="wheat"
      >
        <table className="mag-table">
          <thead>
            <tr>
              <th>Need</th>
              <th>Pick</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Fixed circuit, smallest CU + smallest proof</td>
              <td>Groth16</td>
            </tr>
            <tr>
              <td>Universal setup, no per-circuit trusted ceremony</td>
              <td>KZG-PLONK</td>
            </tr>
            <tr>
              <td>Verify N proofs under one VK cheaply</td>
              <td>Groth16 batch (Bowe-Gabizon)</td>
            </tr>
            <tr>
              <td>Custom gates + lookup tables</td>
              <td>Halo2-KZG</td>
            </tr>
            <tr>
              <td>No FFT-friendly domain constraint; flexible shape</td>
              <td>HyperPlonk-KZG</td>
            </tr>
            <tr>
              <td>Recursive proofs / IVC / zkVM accumulator</td>
              <td>Nova / HyperNova / ProtoStar</td>
            </tr>
            <tr>
              <td>Large computation, no trusted setup, hash-only</td>
              <td>FRI-STARK</td>
            </tr>
          </tbody>
        </table>
      </Page>

      {/* INTERLUDE — CHECKERBOARD */}
      <CheckerboardInterlude />

      {/* PAGE 05 — SOUNDNESS GATES */}
      <Page
        num="05"
        tag="INDEX 05 // SOUNDNESS"
        title={
          <>
            Cryptographic
            <br />
            Gates
          </>
        }
        color="navy"
      >
        <p className="mag-lead">
          Each verifier surfaces tampered prover data with specific error
          codes before the final structural check. A gate is a
          cryptographic pre-filter — an audit firm traces soundness
          through these per-system.
        </p>
        <table className="mag-table">
          <thead>
            <tr>
              <th>Verifier</th>
              <th>Gate</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>HyperPlonk-KZG</td>
              <td>Sumcheck identity, permutation term at ξ (2 gates)</td>
            </tr>
            <tr>
              <td>Halo2-KZG</td>
              <td>Vanishing identity, two-point batched KZG at (ξ, ξω)</td>
            </tr>
            <tr>
              <td>Nova / HyperNova / ProtoStar</td>
              <td>Hadamard residual, folded-commitment reconstruction (2)</td>
            </tr>
            <tr>
              <td>FRI-STARK</td>
              <td>
                Query indices, trace + constraint Merkle, PoW, FRI fold
                chain, OOD quotient, per-layer Merkle auth (7 gates)
              </td>
            </tr>
          </tbody>
        </table>
      </Page>

      {/* PAGE 06 — CU BUDGETS */}
      <Page
        num="06"
        tag="INDEX 06 // COMPUTE UNITS"
        title={
          <>
            CU budgets
            <br />
            per system
          </>
        }
        color="cream"
      >
        <p className="mag-lead">
          Phase-2 rows measured on the real Solana SBF rbpf VM via
          bpf-bench. Phase-3 rows currently use scaffold-acceptance
          fixtures pending session-118 prover-emitted reference
          fixtures. All rows fit within Solana's per-tx
          MAX_COMPUTE_UNIT_LIMIT = 1.4M except FRI-STARK, which
          requires chunked execution per ADR-0005.
        </p>
        <table className="mag-table">
          <thead>
            <tr>
              <th>System</th>
              <th>Measured (CU)</th>
              <th>Hard cap</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Groth16 single</td>
              <td>83,574</td>
              <td>180,000</td>
            </tr>
            <tr>
              <td>Groth16 batch, N=5</td>
              <td>258,397 (52K / proof)</td>
              <td>300,000</td>
            </tr>
            <tr>
              <td>KZG-PLONK</td>
              <td>968,457</td>
              <td>1,100,000</td>
            </tr>
            <tr>
              <td>HyperPlonk-KZG (scaffold)</td>
              <td>target ≤ 505K</td>
              <td>660,000</td>
            </tr>
            <tr>
              <td>Halo2-KZG (scaffold)</td>
              <td>target ≤ 580K</td>
              <td>760,000</td>
            </tr>
            <tr>
              <td>Nova family (scaffold)</td>
              <td>target ≤ 885K</td>
              <td>1,150,000</td>
            </tr>
            <tr>
              <td>FRI-STARK (production shape)</td>
              <td>target ≤ 7.8M</td>
              <td>chunked only</td>
            </tr>
          </tbody>
        </table>
      </Page>

      {/* PAGE 07 — RUNTIME EVIDENCE */}
      {/* Audience: skeptical mainnet integrator + audit-firm scope reviewer. */}
      {/* Goal: prove the program actually executes under the real Solana    */}
      {/* SBF runtime today — no live mainnet deployment yet, but every      */}
      {/* dispatch path has runtime evidence under solana-program-test       */}
      {/* (the same rbpf VM mainnet validators run). Numbers below are       */}
      {/* reproducible from the repository at v0.9.15.                       */}
      <Page
        num="07"
        tag="INDEX 07 // RUNTIME EVIDENCE"
        title={
          <>
            On-chain
            <br />
            Runtime
            <br />
            Evidence
          </>
        }
        color="navy"
      >
        <p className="mag-lead">
          Mosaic is not yet live on Solana mainnet. What follows is the
          full runtime-evidence ledger every audit firm asks for —
          enumerated, reproducible, and pinned to v0.9.15. The program
          binary executes against Solana&apos;s real rbpf VM via
          solana-program-test (the same VM mainnet validators run); each
          dispatch byte has a passing integration test that loads
          mosaic_program.so and asserts dispatch + verification + CU
          consumption.
        </p>

        <div className="stats-grid">
          <div className="stat">
            <span className="stat-label">SBF integration tests</span>
            <span className="stat-val">13 passing</span>
          </div>
          <div className="stat">
            <span className="stat-label">Dispatch bytes covered</span>
            <span className="stat-val">8 / 8 declared</span>
          </div>
          <div className="stat">
            <span className="stat-label">Real-prover fixtures</span>
            <span className="stat-val">snarkjs CIRCOM + PLONK 0.7.6</span>
          </div>
          <div className="stat">
            <span className="stat-label">Differential parity</span>
            <span className="stat-val">arkworks ↔ snarkjs</span>
          </div>
        </div>

        <p className="mag-lead">
          Per-byte runtime evidence (file:
          crates/mosaic-program/tests/verify_proof_sbf.rs):
        </p>
        <table className="mag-table">
          <thead>
            <tr>
              <th>Byte</th>
              <th>System</th>
              <th>Test asserts</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>0x01</td>
              <td>Groth16Bn254</td>
              <td>Real snarkjs fixture verifies + tampered proof rejects</td>
            </tr>
            <tr>
              <td>0x02</td>
              <td>PlonkKzgBn254</td>
              <td>Real snarkjs PLONK 0.7.6 fixture verifies + CU drift gate</td>
            </tr>
            <tr>
              <td>0x03</td>
              <td>HyperPlonkKzgBn254</td>
              <td>Scaffold-acceptance fixture dispatches + accepts</td>
            </tr>
            <tr>
              <td>0x04</td>
              <td>Halo2KzgBn254</td>
              <td>Scaffold-acceptance fixture dispatches + accepts</td>
            </tr>
            <tr>
              <td>0x05</td>
              <td>FriStark</td>
              <td>Depth-zero scaffold dispatches + accepts (single-tx fit)</td>
            </tr>
            <tr>
              <td>0x06</td>
              <td>Risc0Stark</td>
              <td>Returns UnimplementedProofSystem (deterministic reject)</td>
            </tr>
            <tr>
              <td>0x07</td>
              <td>NovaFolding</td>
              <td>Scaffold-acceptance fixture dispatches + accepts</td>
            </tr>
            <tr>
              <td>0x08</td>
              <td>ProtoStarFolding</td>
              <td>Routes through Nova verifier (alias) + accepts</td>
            </tr>
            <tr>
              <td>0xFE</td>
              <td>(unknown)</td>
              <td>Returns UnknownProofSystem (deterministic reject)</td>
            </tr>
            <tr>
              <td>0x03 (compressed)</td>
              <td>Groth16 via VerifyCompressedProof</td>
              <td>Compress on host → decompress on chain → verify</td>
            </tr>
          </tbody>
        </table>

        <p className="mag-lead">
          Live evidence — actual workspace command output from the
          machine that built this site, captured byte-for-byte at the
          commit shown in the chrome. Pick a capture; the terminal
          replays the recorded bytes deterministically. Visitors can
          reproduce identical output locally with the documented
          commands.
        </p>
        <RuntimeEvidenceTerminal />

        <p className="mag-lead">
          Deployment ladder — what blocks each rung:
        </p>
        <dl className="mag-kv">
          <dt>SBF runtime evidence</dt>
          <dd>
            <strong>Live</strong> at v0.9.15 — 13 integration tests
            load mosaic_program.so and execute it under the real
            rbpf VM. Output captured above.
          </dd>
          <dt>Devnet pilot</dt>
          <dd>
            <strong>Pending session 119</strong> — declare PROGRAM_ID
            on devnet, deploy from cargo-build-sbf artifact, run a
            soak harness that submits one Groth16 verify per slot for
            24 hours.
          </dd>
          <dt>External audit</dt>
          <dd>
            <strong>Pending</strong> — AUDIT-CHECKLIST.md ready for
            scoping quote. Target firms: Trail of Bits, OtterSec,
            Zellic, Halborn, ChainSecurity.
          </dd>
          <dt>Mainnet deployment</dt>
          <dd>
            <strong>Gated</strong> on completed external audit +
            devnet pilot success metrics.
          </dd>
        </dl>
      </Page>

      {/* PAGE 08 — QUICK START */}
      <Page
        num="08"
        tag="INDEX 08 // QUICK START"
        title="Integrate"
        color="wheat"
      >
        <p className="mag-lead">Add Mosaic to your program's Cargo.toml:</p>
        <MagCodeBlock lang="toml">{cargoSnippet}</MagCodeBlock>
        <p className="mag-lead">Dispatch inside process_instruction:</p>
        <MagCodeBlock lang="rust">{processInstructionSnippet}</MagCodeBlock>
        <p className="mag-lead">Set the compute-unit budget client-side:</p>
        <MagCodeBlock lang="rust">{clientSnippet}</MagCodeBlock>
      </Page>

      {/* PAGE 09 — ARCHITECTURE */}
      <Page
        num="09"
        tag="INDEX 09 // ARCHITECTURE"
        title="Dispatch Tree"
        color="navy"
      >
        <p className="mag-lead">
          BN254 primitives live in mosaic-zk-primitives, shared across
          four verifier crates. STARK-specific Goldilocks + Merkle + FRI
          primitives stay local to mosaic-stark.
        </p>
        <pre className="mag-ascii">{architectureTree}</pre>
      </Page>

      {/* PAGE 10 — RELEASE LINEAGE */}
      <Page
        num="10"
        tag="INDEX 10 // LINEAGE"
        title="Release Timeline"
        color="cream"
      >
        <dl className="mag-kv">
          <dt>v0.1.0-phase1</dt>
          <dd>Workspace bootstrap, 11 crates, trait surface.</dd>
          <dt>v0.2.0-phase2</dt>
          <dd>Production Groth16 + KZG-PLONK + Bowe-Gabizon batching.</dd>
          <dt>v0.3.0-phase3-scaffolds</dt>
          <dd>
            Four wire-format scaffolds for HyperPlonk, Halo2, Nova,
            FRI-STARK.
          </dd>
          <dt>v0.4.0-phase3-bodies</dt>
          <dd>Four verifier bodies end-to-end.</dd>
          <dt>v0.4.1-phase3-soundness</dt>
          <dd>
            Cryptographic soundness gates across all four families; SBF
            binary reduced 72 %.
          </dd>
          <dt>v0.5.0-phase3-complete</dt>
          <dd>
            12 independent soundness gates; FRI-STARK at
            Plonky3/Winterfell production parity; Halo2 two-point
            opening; Nova fold reconstruction.
          </dd>
          <dt>v0.9.0-halo2-multi-column-lookup</dt>
          <dd>
            Halo2 multi-column lookup wired end-to-end; 549 lib tests.
          </dd>
          <dt>v0.9.2-alt-bn128-compression</dt>
          <dd>
            alt_bn128 compression syscall wired on host + SBF backends
            with typed helpers in mosaic-zk-primitives::compression.
          </dd>
          <dt>v0.9.5..0.9.13 — compression rollout</dt>
          <dd>
            Halo2 / Groth16 / KZG-PLONK / HyperPlonk / Nova proof + VK
            compressed wire formats; 59 round-trip tests + 10 fuzz
            harnesses + 14 criterion benches.
          </dd>
          <dt>v0.9.12-sbf-coverage</dt>
          <dd>
            10 SBF integration tests across all 8 declared
            ProofSystemId bytes; bpf-bench Nova/FriStark byte-mapping
            fix.
          </dd>
          <dt>v0.9.14-audit-checklist</dt>
          <dd>
            AUDIT-CHECKLIST.md scope handoff doc; T-11 + T-12 threat
            model expansion; SECURITY.md refresh.
          </dd>
          <dt>v0.9.15-onchain-compressed-verify</dt>
          <dd>
            VerifyCompressedProof = 0x03 instruction — alt_bn128
            compression now end-to-end on chain across 5 BN254
            verifiers; 13 SBF integration tests.
          </dd>
        </dl>
      </Page>

      {/* PAGE 11 — DOCUMENTATION */}
      <Page
        num="11"
        tag="INDEX 11 // REFERENCES"
        title="Documentation"
        color="wheat"
      >
        <dl className="mag-kv">
          <dt>Soundness gates</dt>
          <dd>
            <a
              href="https://github.com/wienerlabs/mosaic/blob/main/docs/phase3-soundness.md"
              target="_blank"
              rel="noopener"
            >
              docs/phase3-soundness.md
            </a>
          </dd>
          <dt>CU budget per system</dt>
          <dd>
            <a
              href="https://github.com/wienerlabs/mosaic/blob/main/docs/compute-unit-budget.md"
              target="_blank"
              rel="noopener"
            >
              docs/compute-unit-budget.md
            </a>
          </dd>
          <dt>Threat model</dt>
          <dd>
            <a
              href="https://github.com/wienerlabs/mosaic/blob/main/docs/threat-model.md"
              target="_blank"
              rel="noopener"
            >
              docs/threat-model.md
            </a>
          </dd>
          <dt>Disclosure SLA</dt>
          <dd>
            <a
              href="https://github.com/wienerlabs/mosaic/blob/main/docs/responsible-disclosure-timeline.md"
              target="_blank"
              rel="noopener"
            >
              docs/responsible-disclosure-timeline.md
            </a>
          </dd>
          <dt>ADRs</dt>
          <dd>
            <a
              href="https://github.com/wienerlabs/mosaic/tree/main/docs/adr"
              target="_blank"
              rel="noopener"
            >
              docs/adr/
            </a>
          </dd>
          <dt>Changelog</dt>
          <dd>
            <a
              href="https://github.com/wienerlabs/mosaic/blob/main/CHANGELOG.md"
              target="_blank"
              rel="noopener"
            >
              CHANGELOG.md
            </a>
          </dd>
          <dt>Security policy</dt>
          <dd>
            <a
              href="https://github.com/wienerlabs/mosaic/blob/main/SECURITY.md"
              target="_blank"
              rel="noopener"
            >
              SECURITY.md
            </a>
          </dd>
        </dl>
      </Page>

      {/* PAGE 12 — CONSTRAINTS */}
      <Page
        num="12"
        tag="INDEX 12 // CONSTRAINTS"
        title="Operating Envelope"
        color="cream"
      >
        <dl className="mag-kv">
          <dt>Rust</dt>
          <dd>MSRV 1.85.0, edition 2021</dd>
          <dt>Solana</dt>
          <dd>program SDK 2.1.x, cargo-build-sbf tools v1.52</dd>
          <dt>Safety</dt>
          <dd>#![forbid(unsafe_code)] across the tree</dd>
          <dt>External audit</dt>
          <dd>Not yet commissioned — tree audit-ready at the protocol layer</dd>
          <dt>License</dt>
          <dd>Apache-2.0 OR MIT</dd>
        </dl>
      </Page>

      {/* PAGE 13 — BUILT BY WIENER LABS */}
      <Page
        num="13"
        tag="INDEX 13 // BUILT BY"
        title={
          <>
            Wiener
            <br />
            Labs
          </>
        }
        color="navy"
      >
        <div className="studio-monogram-row">
          <div className="studio-monogram studio-monogram-logo">
            {/* Real WIENER wordmark from the studio brand kit, copied
             * to public/wiener-logo.png. Inverted on the navy page-13
             * background so the black wordmark resolves to cream. */}
            <img
              src="/wiener-logo.png"
              alt="Wiener Labs"
              width={1000}
              height={1000}
            />
          </div>
          <div className="studio-monogram-meta">
            <span className="tag">STUDIO MARK // SINCE 2026</span>
            <p>Wiener Labs · applied cryptography</p>
            <p className="muted-foot">Istanbul · Open-source · Audit-first</p>
          </div>
        </div>

        <p className="mag-lead">
          Mosaic ships under the Wiener Labs umbrella, an applied
          cryptography studio building open-source infrastructure for
          on-chain verification, settlement, and zero-knowledge primitives.
        </p>

        <blockquote className="studio-quote">
          <p>
            Cryptography ships when its surface area is auditable,
            plural, and open. Soundness is a property of the build, not
            a property of the brand on top of it.
          </p>
          <cite>— Wiener Labs · studio working thesis</cite>
        </blockquote>

        <p className="body-copy">
          The studio's working thesis: production-grade cryptographic
          systems should not depend on a single proving framework, a
          single curve, or a single trust assumption. Mosaic is the
          on-chain verifier surface of that thesis. Adjacent projects
          cover prover orchestration, fixture generation, and audit
          tooling, all designed to compose with the same canonical byte
          layouts and the same SyscallBackend abstraction.
        </p>

        <p className="body-copy">
          Everything the studio publishes is dual-licensed under
          Apache 2.0 or MIT and developed in the open. Issues, PRs, and
          design discussions land on the public repository. Audit notes,
          ADRs, and threat models live next to the code.
        </p>

        <div className="studio-manifesto">
          <span className="tag">STUDIO PRINCIPLES // 04</span>
          <div className="studio-grid">
            <div className="studio-card">
              <span className="studio-num">P · 01</span>
              <h4>Plurality over monoculture</h4>
              <p>
                One proving system is a bet on a single team's audit
                trail. Four systems behind one trait surface gives the
                ecosystem optionality and the studio a research lane.
              </p>
            </div>
            <div className="studio-card">
              <span className="studio-num">P · 02</span>
              <h4>Soundness as a build artifact</h4>
              <p>
                Gates, fixtures, differential oracles, and CU budgets
                live in the same repository as the verifier they protect.
                Audit firms read the same source the runtime executes.
              </p>
            </div>
            <div className="studio-card">
              <span className="studio-num">P · 03</span>
              <h4>Open by construction</h4>
              <p>
                Apache 2.0 or MIT, no proprietary forks, no closed-source
                primitives. Studio output is reference material first,
                product surface second.
              </p>
            </div>
            <div className="studio-card">
              <span className="studio-num">P · 04</span>
              <h4>Solana-native, curve-agnostic</h4>
              <p>
                BN254 syscalls, Goldilocks for STARK, Pasta-ready for
                Halo2 PSE. The verifier surface treats the curve as a
                generic parameter, not a vendor lock.
              </p>
            </div>
          </div>
        </div>

        <div className="studio-roster">
          <span className="tag">ADJACENT WORK // STUDIO BENCH</span>
          <ul className="roster-list">
            <li>
              <span className="roster-mark">[ on-chain ]</span>
              <strong>Mosaic verifier crates</strong>
              <em>
                Six proof-system bodies, fourteen soundness gates,
                shared zk-primitives, audit-mode toggles. This site.
              </em>
            </li>
            <li>
              <span className="roster-mark">[ prover-side ]</span>
              <strong>Mosaic SDK preflight</strong>
              <em>
                Host-side serializer, byte-layout validator, fixture
                exporter, differential test generator against arkworks.
              </em>
            </li>
            <li>
              <span className="roster-mark">[ research ]</span>
              <strong>Studio research notes</strong>
              <em>
                ADRs, threat models, soundness proofs and CU
                re-measurement reports published alongside each release.
              </em>
            </li>
          </ul>
        </div>

        <div className="studio-roadmap">
          <span className="tag">NOW · NEXT · LATER // STUDIO ROADMAP</span>
          <ol className="roadmap-list">
            <li className="roadmap-now">
              <span className="roadmap-step">NOW</span>
              <div>
                <strong>v0.8.0 — Phase-3 polish</strong>
                <em>
                  HyperPlonk + Halo2-KZG + Nova-folding + FRI-STARK
                  bodies live behind shared zk-primitives. CU budgets
                  re-measured under opt-level=z. Audit-mode preflight
                  hardened.
                </em>
              </div>
            </li>
            <li className="roadmap-next">
              <span className="roadmap-step">NEXT</span>
              <div>
                <strong>v0.9.0 — Batch verifier expansion</strong>
                <em>
                  Cross-system proof aggregation, vectorized pairing
                  paths, multi-tenant fixture catalogs and a public
                  differential corpus.
                </em>
              </div>
            </li>
            <li className="roadmap-later">
              <span className="roadmap-step">LATER</span>
              <div>
                <strong>v1.0.0 — Audit-ready release candidate</strong>
                <em>
                  Frozen on-chain ABI, third-party security review
                  pack, governance for ProofSystemId reservations,
                  long-term ADR archive.
                </em>
              </div>
            </li>
          </ol>
        </div>

        <dl className="mag-kv">
          <dt>Studio</dt>
          <dd>
            <a
              href="https://www.wienerlabs.xyz/"
              target="_blank"
              rel="noopener"
            >
              wienerlabs.xyz
            </a>
          </dd>
          <dt>Mosaic repository</dt>
          <dd>
            <a
              href="https://github.com/wienerlabs/mosaic"
              target="_blank"
              rel="noopener"
            >
              github.com/wienerlabs/mosaic
            </a>
          </dd>
          <dt>Mosaic on X</dt>
          <dd>
            <a href="https://x.com/mosaiczk" target="_blank" rel="noopener">
              x.com/mosaiczk
            </a>
          </dd>
          <dt>Founder</dt>
          <dd>Wiener Labs · Istanbul, TR</dd>
          <dt>Contact</dt>
          <dd>via the studio site or GitHub Issues</dd>
        </dl>

        <footer className="mag-footer">
          <div className="links">
            <a
              href="https://www.wienerlabs.xyz/"
              target="_blank"
              rel="noopener"
            >
              wienerlabs.xyz
            </a>
            <a
              href="https://github.com/wienerlabs/mosaic"
              target="_blank"
              rel="noopener"
            >
              github.com/wienerlabs/mosaic
            </a>
            <a href="https://x.com/mosaiczk" target="_blank" rel="noopener">
              x.com/mosaiczk
            </a>
          </div>
          <div>
            <div>Wiener Labs · 2026</div>
            <div className="muted-foot">A Wiener Labs product</div>
          </div>
        </footer>
      </Page>
    </>
  );
}
