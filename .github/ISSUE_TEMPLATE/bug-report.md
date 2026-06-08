---
name: Bug report
about: Report a bug in mosaic-program
title: "[Bug] "
labels: bug
assignees: ''

---

**Describe the bug**
A clear and concise description of what the bug is.

**To Reproduce**
Steps to reproduce the behavior:
1. Go to '...'
2. Click on '....'
3. Scroll down to '....'
4. See error

**Expected behavior**
A clear and concise description of what you expected to happen.

**Screenshots / Logs**
If applicable, add screenshots or log output to help explain your problem.

**Environment (please complete the following information):**
- OS: [e.g. macOS 14.0, Ubuntu 22.04]
- Solana CLI version: [e.g. 1.18.26]
- mosaic-program version / commit: [e.g. v0.1.0 or abc1234]
- Network: [e.g. mainnet-beta, devnet]

**Additional context**
Add any other context about the problem here.

---

### ⚠️ Bounty Program Check
- [ ] I have verified that this bug is **not already covered** by the active bug bounty program.
- [ ] If this bug is within the scope of the bounty program, I will submit it through the official bounty platform (Immunefi / Cantina) rather than this public issue tracker.

> **Note:** For bugs that qualify under the bounty program, please submit via the designated platform to ensure eligibility for rewards. Public disclosure of in-scope vulnerabilities before resolution may result in disqualification.

---

### 🛡️ Security & Bounty Program Information

#### Platform Selection
- **Primary Platform:** [Immunefi](https://immunefi.com/) — recommended for ZK-focused projects; largest ZK security researcher community
- **Alternative:** [Cantina](https://cantina.xyz/) — preferred if Solana ecosystem alignment is critical (Light Protocol reference)
- **Decision Criteria:** ZK maturity (Immunefi) vs. Solana-native tooling (Cantina)

#### Bounty Tiers (USDC Payouts)
| Severity | Payout Range (USDC) | Example |
|----------|-------------------|---------|
| **Critical** | $50,000 - $250,000 | Direct loss of funds, permanent network compromise |
| **High** | $10,000 - $50,000 | Theft of unclaimed yield, temporary consensus failure |
| **Medium** | $2,500 - $10,000 | Griefing attacks, state manipulation without direct loss |
| **Low** | $500 - $2,500 | Informational disclosures, minor logic errors |

*Tier sizing reference: Light Protocol's Cantina program (similar ZK-SNARK verification complexity)*

#### Scope Definition
- **In-Scope:** `mosaic-program` on mainnet-beta only (production deployment)
- **Out-of-Scope:** 
  - Third-party dependencies (Solana runtime, Anchor framework)
  - Already disclosed vulnerabilities (see `SECURITY.md`)
  - Social engineering attacks
  - Physical security threats
  - Economic attacks requiring >$10M capital
  - Issues requiring privileged validator set compromise

#### Funding Requirements
- **Treasury Allocation:** Minimum 3x projected annual bounty payouts
- **Escrow Mechanism:** Multi-sig controlled USDC vault (4-of-7 signers)
- **Launch Condition:** Treasury funded ≥72 hours before mainnet launch (#66)

#### Program Rules
1. **Submission Window:** Continuous, 24/7
2. **Response SLA:** 48 hours for Critical/High, 7 days for Medium/Low
3. **Payout Timeline:** Within 14 days of validation
4. **Disclosure Policy:** 90-day embargo for Critical/High, 30-day for Medium/Low
5. **Duplicate Handling:** First valid reporter receives 100% reward; subsequent duplicates receive 10% at discretion

#### Integration Checklist
- [ ] Platform contract signed (Immunefi or Cantina)
- [ ] Scope document finalized and published
- [ ] Treasury funded (minimum $500k USDC)
- [ ] Payout tiers approved by governance
- [ ] Security contact published (security@mosaicprogram.com)
- [ ] Bug bounty badge added to README
- [ ] Automated payout triggers tested on devnet
- [ ] Legal review completed (liability waivers, tax implications)
- [ ] Researcher onboarding documentation published
- [ ] Mainnet launch (#66) gated on bounty program live status

#### Risk Mitigation