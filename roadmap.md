# ReconnV2 Max-Bounty Roadmap

## Goal
Shift ReconnV2 from detection-heavy recon into a hunter-centric system that finds and proves:
- business-logic flaws,
- auth abuse chains,
- race-condition and state-desync bugs,
- high-quality manual exploitation paths.

## Success Criteria (North Star)
- Higher accepted-report rate per 100 scans.
- Lower duplicate/out-of-scope rate.
- Faster time from finding -> reproducible submission.
- More multi-step, high-impact findings (not just surface misconfigs).

## Phase 1: Workflow Capture and Replay
- [ ] Add authenticated/unauthenticated workflow recorder (request/response sequence + state transitions).
- [ ] Add deterministic flow replay engine (with token/session refresh support).
- [ ] Add flow templates for common bounty domains: signup, reset, checkout, coupon, wallet, transfer, payout.
- [ ] Add endpoint state snapshots before/after each workflow step.
- [ ] Add tests for replay determinism and session continuity.
- [ ] **Done when:** we can replay real app workflows reliably and diff outcomes per run.

## Phase 2: Authorization Abuse Chains
- [ ] Extend role matrix to support cross-role chain scenarios (A creates -> B reads/updates/deletes).
- [ ] Add forced-browse path traversal across roles and tenants.
- [ ] Add object-lifecycle abuse checks (orphaned objects, stale references, cross-tenant IDs).
- [ ] Add privilege-boundary mutation checks on hidden parameters and headers.
- [ ] Add tests for role confusion, horizontal/vertical abuse, and tenant breakout.
- [ ] **Done when:** auth findings include chain evidence, not single-request anomalies.

## Phase 3: Business Invariant Engine
- [ ] Add `config/invariants.yaml` for per-target business rules.
- [ ] Support numeric, enum, monotonic, and transition invariants (e.g. `balance >= 0`, valid status graph).
- [ ] Add invariant evaluation at every replay step with diff context.
- [ ] Add auto-generated PoC traces when invariant is violated.
- [ ] Add tests for invariant parsing, evaluation, and false-positive suppression.
- [ ] **Done when:** logic violations are explicitly proven via invariant break events.

## Phase 4: Race and TOCTOU Validation
- [ ] Add race harness for high-risk actions: redeem, withdraw, refund, purchase, reset, invite.
- [ ] Add concurrent replay with timing jitter and sequence perturbation.
- [ ] Add idempotency and double-spend assertions.
- [ ] Add state-desync detector (API/UI mismatch and cross-endpoint inconsistency).
- [ ] Add tests with deterministic mock race fixtures.
- [ ] **Done when:** race findings include timing profile, winning sequence, and reproducible script.

## Phase 5: Manual Exploitation Assist
- [ ] Generate exploit packs per finding: raw HTTP, `curl`, replay script, and expected success checks.
- [ ] Add Burp-compatible import bundle and step-by-step chain instructions.
- [ ] Add “next pivot” suggestions from graph context (what to try after initial foothold).
- [ ] Add confidence gates: `candidate`, `chain-verified`, `submission-ready`.
- [ ] Add tests for exploit pack completeness and replayability.
- [ ] **Done when:** hunter can move from signal to report with minimal manual setup.

## Phase 6: Target-Aware Intelligence
- [ ] Add per-program playbooks (`config/playbooks/*.yaml`) for known bounty patterns.
- [ ] Add endpoint criticality model for money/account/admin/auth surfaces.
- [ ] Add novelty scoring to prioritize newly introduced risky paths.
- [ ] Add anti-dup heuristics tuned for bug-bounty report uniqueness.
- [ ] Add tests for prioritization stability and playbook correctness.
- [ ] **Done when:** top-ranked leads align with likely payout-worthy paths.

## Cross-Cutting Safety and Quality
- [ ] Keep safe defaults for non-destructive probing; explicit opt-in for risky checks.
- [ ] Expand redaction and secrets hygiene in artifacts and logs.
- [ ] Add strict per-host budgets, kill-switches, and emergency stop for aggressive stages.
- [ ] Maintain regression suites for logic engine and race harness.
- [ ] Add CI quality gates for proof completeness and false-positive thresholds.

## Execution Plan
- [ ] Week 1: Phase 1 foundations (recorder + replay core).
- [ ] Week 2: Phase 2 auth-chain engine.
- [ ] Week 3: Phase 3 invariants and proofs.
- [ ] Week 4: Phase 4 race/TOCTOU harness.
- [ ] Week 5: Phase 5 exploit packs + Burp integration.
- [ ] Week 6: Phase 6 prioritization and anti-dup tuning.
- [ ] Week 7: Hardening, scale tests, and docs.

## Release Readiness Checklist
- [ ] End-to-end flow replay works on at least 3 real programs (staging/safe scopes).
- [ ] Invariant violations produce reproducible PoCs with clear business impact.
- [ ] Race harness produces deterministic evidence artifacts.
- [ ] Hunter-mode output includes submission-ready chain summaries.
- [ ] Documentation updated (`README`, examples, config schemas, playbooks).
- [ ] Performance and safety budgets validated under load.
