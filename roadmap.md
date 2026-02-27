# ReconnV2 Bug Bounty Hardening Roadmap

## Phase 1: Noise Reduction and Signal Quality
- [x] Add global deduplication across stages (host, path, param, vuln fingerprint).
- [x] Add confidence scoring per finding (`low`, `medium`, `high`, `verified`).
- [x] Add `--verified-only` output mode.
- [x] Add `--proof-required` mode to suppress unverified high-risk claims.
- [x] Add result quality metrics (noise ratio, duplicate ratio, verified ratio).
- [x] Add tests for dedupe collisions and confidence classification edge cases.
- [x] **Done when:** repeated runs produce stable, low-noise findings with measurable improvement.

## Phase 2: Exploitable Finding Output
- [x] For each high/critical finding, generate reproducible request/response artifacts.
- [x] Attach PoC steps (exact command + expected success condition).
- [x] Include affected asset context (host, endpoint, auth requirement, environment).
- [x] Add impact hypothesis template (why it matters from bounty perspective).
- [x] Add structured export format for triage (`finding_id`, `severity`, `proof`, `repro_cmd`).
- [x] Add tests to ensure artifact generation for every verified high/critical finding.
- [x] **Done when:** a hunter can reproduce top findings directly from output without extra digging.

## Phase 3: Vulnerability-Class Validation Stages
- [x] Add dedicated SSRF validator (outbound callback + internal target checks).
- [x] Add dedicated IDOR validator (object ownership/access control checks).
- [x] Add auth-bypass validator (forced-browse and privilege-boundary checks).
- [x] Add open-redirect validator (redirect chain and sink confirmation).
- [x] Add subdomain takeover validator hardening (fingerprint + DNS state + claimability).
- [x] Add secret exposure validator (live token sanity checks with safe guards).
- [x] Add tests per validator with real/false-positive fixtures.
- [x] **Done when:** each supported vuln class has explicit confirmation logic, not just detection.

## Phase 4: Bounty-Centric Prioritization
- [x] Add risk score formula: severity + exposure + exploitability + business context.
- [x] Prioritize sensitive asset types (`auth`, `admin`, `api`, `payment`, `account`).
- [x] Add internet exposure weighting (publicly reachable > internal-only).
- [x] Add recency/novelty weighting to surface newly introduced risks.
- [x] Add “top targets first” queue mode for high-value attack surface.
- [x] Add tests that validate ranking determinism and priority ordering.
- [x] **Done when:** top-ranked issues consistently match what a skilled hunter would triage first.

## Phase 5: Attack Surface Depth
- [x] Improve JS endpoint extraction (dynamic routes, API patterns, hidden parameters).
- [x] Improve API discovery (OpenAPI/GraphQL/gRPC/websocket path enrichment).
- [x] Expand parameter mining and candidate mutation strategy.
- [x] Improve auth-aware crawling with session continuity and role awareness.
- [x] Correlate passive + active intel into attack paths (entrypoint -> vulnerable sink).
- [x] Add benchmarks to compare discovered unique actionable surfaces before/after.
- [x] **Done when:** scans reveal deeper, exploitable paths instead of just broad asset lists.

## Phase 6: Hunter Mode Reporting
- [x] Add `hunter-mode` report preset (verified-only, high signal, PoC-focused).
- [x] Output “Top 10 Actionable Bugs” with proof links and rerun commands.
- [x] Add one-click rerun command per finding (stage-scoped replay).
- [x] Add concise submission-ready summaries per finding.
- [x] Add report sections for duplicates/out-of-scope filtering hints.
- [x] Add end-to-end tests for hunter-mode report generation.
- [x] **Done when:** output is directly usable for triage and bug bounty submission workflow.

## Cross-Cutting Hardening
- [x] Standardize timeout/retry/circuit-breaker defaults per tool class.
- [x] Add strict input validation for all web/API mutation endpoints.
- [x] Add sensitive data redaction checks in logs/reports/artifacts.
- [x] Add safe-failure behavior (partial results + clear error taxonomy).
- [x] Add dependency health checks in `doctor` for all critical scanners/modules.
- [x] Add CI gates: quality thresholds + regression suites for false positives.

## Operational Reliability and Job Control
- [x] Add `recon.sh` support for rerunning a job by ID.
- [x] Define rerun behavior (resume from failing stage vs. full restart) and implement it.
- [x] Expose last-failing stage and log path in CLI output for quicker triage.
- [x] Add `doctor` checks for `dnspython`, `interactsh-client`, and `playwright`.

## Execution Plan
- [x] Week 1: Phase 1 + initial metrics dashboard.
- [x] Week 2: Phase 2 + artifact schemas.
- [x] Week 3: Phase 3 validators (SSRF/IDOR/auth bypass first).
- [x] Week 4: Phase 4 prioritization + ranking tests.
- [x] Week 5: Phase 5 discovery depth improvements.
- [x] Week 6: Phase 6 hunter-mode reporting + release checklist.

## Release Readiness Checklist
- [x] All new features covered by unit/integration tests.
- [x] Full suite passes (`pytest`) in project venv.
- [x] No sensitive leakage in logs/reports under test fixtures.
- [x] Documentation updated (`README`, examples, flags, report fields).
- [x] Backward compatibility verified for existing CLI/web API flows.
