# ReconnV2 Objective V2

> Purpose: turn ReconnV2 from a broad recon and heuristic validation tool into a trustworthy autonomous bug finder.

This document is not a marketing rewrite. It is a build plan based on the current codebase.

The current repository already has real strengths:

- The main execution path is implemented in `recon_cli/cli.py`, `recon_cli/pipeline/runner.py`, and `recon_cli/pipeline/context.py`.
- Discovery, probing, result deduplication, scoring, and correlation are real in `recon_cli/pipeline/stage_passive.py`, `recon_cli/pipeline/stage_http_probe.py`, `recon_cli/jobs/results.py`, `recon_cli/pipeline/stage_scoring.py`, and `recon_cli/pipeline/stage_correlation.py`.
- Several bug-oriented validators exist in `recon_cli/pipeline/stage_idor.py`, `recon_cli/pipeline/stage_ssrf_validator.py`, `recon_cli/pipeline/stage_auth_bypass_validator.py`, and `recon_cli/pipeline/stage_api_schema_probe.py`.

The current repository is not yet an autonomous bug finder because the system is still weak in four places:

- Runtime truthfulness: failed stages can still lead to finished jobs.
- Session and auth durability: auth capture and replay are inconsistent and partly broken.
- Stateful exploit logic: many validators are still single-pass probes, not adaptive exploit loops.
- Evaluation discipline: tests are wide, but too many of them validate mocks and scaffolding instead of real runtime behavior.

## Objective

Build a CLI-first autonomous web bug finding system that can:

1. Discover attack surface.
2. Build a target model from observed behavior.
3. Generate exploit hypotheses.
4. Execute safe validation loops.
5. Decide whether a bug is real based on evidence, not just signatures.
6. Produce reproducible proof with low false positive rates.

The standard is not "many findings".

The standard is:

- low-noise, evidence-backed bug reports
- correct job state and replayability
- durable auth-aware exploration
- benchmarked progress against real vulnerable targets

## What "Autonomous Bug Finder" Means Here

For ReconnV2, autonomy should mean:

- The system can choose what to test next based on observed state.
- The system can preserve and compare identity, role, object, and workflow state.
- The system can retry with alternate hypotheses when the first probe fails.
- The system can stop calling something a bug unless it has enough evidence.

It does not mean:

- blindly fuzzing everything forever
- claiming speculative issues as confirmed bugs
- using benchmark-specific shortcuts

## Current State Summary

### Already solid

- `recon_cli/pipeline/runner.py`
  Real orchestration, retries, tracing, and dependency-aware parallel execution.
- `recon_cli/jobs/results.py`
  Strong deduplication, merge rules, and finding fingerprinting.
- `recon_cli/pipeline/stage_http_probe.py`
  Real HTTP probing, fallback async probing, additional-path discovery, and soft-404 handling.
- `recon_cli/pipeline/stage_correlation.py`
  Real graph building, clustering, attack-path synthesis, and cross-result scoring support.

### Implemented but fragile

- `recon_cli/pipeline/stage_idor.py`
  Real logic-aware probes exist, but record typing and response parsing are fragile.
- `recon_cli/pipeline/stage_ssrf_validator.py`
  OAST and internal-target validation exist, but candidate selection and execution flow are still narrow.
- `recon_cli/pipeline/stage_auth_bypass_validator.py`
  Forced-browse and boundary checks exist, but auth replay is inconsistent.
- `recon_cli/pipeline/stage_active_auth.py`
  Real signup/login/session ideas exist, but the response model and persistence path are not robust enough.

### Blocking weaknesses

- `recon_cli/pipeline/runner.py`
  Stage failures can be recorded while the job still ends as finished.
- `recon_cli/jobs/manager.py`
  DB sync failure logging is unsafe and can raise inside metadata updates.
- `recon_cli/pipeline/context.py`
  Runtime overrides are applied after components that depend on them are built.
- `recon_cli/utils/rate_limiter.py`
  Sync sleeps are used from async validator code paths.
- `tests/integration/test_full_pipeline.py`
  The "full pipeline" test mostly validates mock stages, not the real pipeline.

## V2 Plan

## Phase 0: Make The Runtime Trustworthy

Goal: the system must tell the truth before it tries to be autonomous.

Priority work:

1. Fix job outcome semantics.
   Files: `recon_cli/pipeline/runner.py`, `recon_cli/cli.py`, `recon_cli/jobs/models.py`, `recon_cli/jobs/lifecycle.py`
   Requirement:
   - a job is `finished` only if all required stages succeeded or were intentionally skipped
   - a job with stage failures becomes `failed` or `partial`
   - the CLI and worker must respect runner outcome, not just exception presence

2. Fix metadata update safety.
   File: `recon_cli/jobs/manager.py`
   Requirement:
   - DB sync failures never break filesystem state updates
   - logging in exception paths must use a valid logger

3. Fix runtime config ordering.
   File: `recon_cli/pipeline/context.py`
   Requirement:
   - `runtime_config` is finalized before stealth, proxy, limiter, auth, and scope-dependent helpers are created

4. Stop swallowing schema failures silently.
   Files: `recon_cli/jobs/results.py`, `recon_cli/db/schemas.py`
   Requirement:
   - invalid finding payloads are rejected or quarantined
   - validation errors are counted and surfaced in job stats

5. Replace sync rate limiting in async paths.
   Files: `recon_cli/utils/rate_limiter.py`, `recon_cli/pipeline/stage_api_schema_probe.py`, `recon_cli/pipeline/stage_auth_matrix.py`, `recon_cli/pipeline/stage_tls_hygiene.py`
   Requirement:
   - no blocking `time.sleep()` on async exploit paths

Exit criteria:

- job states are reliable
- retries and partial failures are visible in metadata
- proxy/auth/limiter overrides actually take effect
- invalid result payloads cannot silently contaminate the corpus

## Phase 1: Build A Durable Auth And Identity Engine

Goal: the system must be able to hold multiple identities and replay them correctly.

Priority work:

1. Replace the current ad hoc session model with a unified auth/session layer.
   Files: `recon_cli/pipeline/stage_active_auth.py`, `recon_cli/utils/auth.py`, `recon_cli/utils/async_http.py`, `recon_cli/pipeline/context.py`
   Requirement:
   - sessions support cookies, bearer tokens, basic auth, and role labels
   - session storage is per-job, not global plaintext state in `data/accounts.json`
   - the HTTP client exposes what validators need to replay auth correctly

2. Introduce identity records.
   New concept:
   - `identity_id`
   - `role`
   - `auth_material`
   - `source`
   - `verified`
   - `last_seen`
   - `reachable_surfaces`

3. Add session health checks and renewal.
   Requirement:
   - detect expiry
   - renew if possible
   - invalidate stale sessions explicitly

4. Add role-aware crawling and role-aware API replay as first-class behavior.
   Current starting point:
   - `recon_cli/pipeline/stage_runtime_crawl.py`
   - `recon_cli/pipeline/stage_active_auth.py`

Exit criteria:

- at least two identities can be captured or supplied and replayed correctly
- cookies are replayed as cookies, not converted into `Authorization`
- validators can compare anonymous vs low-privilege vs high-privilege behavior on the same endpoint

## Phase 2: Build A Persistent Target State Graph

Goal: autonomy needs memory richer than a flat stream of findings.

Priority work:

1. Add a normalized state model.
   Build persistent entities for:
   - hosts
   - URLs
   - endpoints
   - parameters
   - forms
   - schemas
   - identities
   - objects and object identifiers
   - workflow transitions

2. Promote correlation from reporting logic into planner input.
   Current base:
   - `recon_cli/pipeline/stage_correlation.py`
   - `recon_cli/correlation/graph.py`
   Requirement:
   - attack paths and clusters become machine-usable scheduling signals

3. Add object graph extraction.
   Start from:
   - API responses
   - HTML forms
   - GraphQL schemas
   - crawl results
   Requirement:
   - store object IDs, parent-child relationships, ownership signals, and role boundaries

4. Add workflow graph extraction.
   Requirement:
   - model multi-step flows like signup -> verify -> login -> profile -> billing -> admin

Exit criteria:

- the system can answer "what objects exist, who can access them, and through which surfaces?"
- validators can consume structured target state instead of only raw results

## Phase 3: Upgrade Validators Into Adaptive Exploit Loops

Goal: validators stop being mostly one-shot probes and become planners with memory.

Priority work:

1. Refactor IDOR into a role-and-object engine.
   File: `recon_cli/pipeline/stage_idor.py`
   Requirement:
   - compare object access across identities
   - learn object families from API and HTML responses
   - retry with harvested identifiers, path mutations, body mutations, and workflow-aware transitions
   - distinguish missing object, forbidden object, other-user object, and soft-404 behavior

2. Refactor SSRF into a sink classification engine.
   File: `recon_cli/pipeline/stage_ssrf_validator.py`
   Requirement:
   - classify sinks by fetch behavior
   - vary protocol, DNS form, redirect shape, and callback pattern
   - correlate OAST, internal fetch signatures, and response deltas

3. Refactor auth bypass into a boundary engine.
   File: `recon_cli/pipeline/stage_auth_bypass_validator.py`
   Requirement:
   - test unauthenticated, low-role, alternate headers, path confusion, reverse-proxy header confusion, and stale session behavior
   - compare response equivalence across roles

4. Refactor API schema probing into a contract-driven attack generator.
   File: `recon_cli/pipeline/stage_api_schema_probe.py`
   Requirement:
   - infer auth expectations
   - generate stateful endpoint sequences
   - feed IDOR, mass assignment, auth bypass, and workflow tests automatically

5. Create a common exploit trial framework.
   New concept:
   - candidate
   - hypothesis
   - probe sequence
   - observation
   - judge result
   - proof artifact

Exit criteria:

- validators support multi-step retries
- every confirmed bug class has explicit proof criteria
- every rejected hypothesis leaves behind structured reasoning

## Phase 4: Add Planner / Executor / Judge Separation

Goal: make autonomy explicit instead of embedding planning into every stage by hand.

Design:

1. Planner
   Input:
   - target graph
   - identities
   - prior findings
   - current confidence gaps
   Output:
   - prioritized bug hypotheses

2. Executor
   Input:
   - a hypothesis and probe plan
   Output:
   - observations and artifacts

3. Judge
   Input:
   - baseline behavior
   - probe behavior
   - cross-role comparisons
   - OAST events
   Output:
   - confirmed
   - rejected
   - needs more evidence

Implementation target:

- keep the current stage model, but add a shared hypothesis engine under `recon_cli/` instead of hardcoding all planning inside stages

Exit criteria:

- a bug class can be improved by changing planner logic without rewriting the entire validator
- evidence thresholds are centralized and testable

## Phase 5: Build Real Evaluation Gates

Goal: progress must be measurable against real behavior, not broad test counts.

Priority work:

1. Add a benchmark harness.
   Suggested targets:
   - OWASP Juice Shop
   - DVWA
   - WebGoat
   - crAPI
   - a small internal corpus of purpose-built auth/IDOR/SSRF fixtures

2. Replace mock-heavy integration coverage with runtime coverage.
   Current weak point:
   - `tests/integration/test_full_pipeline.py`
   Requirement:
   - real stages run against deterministic fixtures
   - auth/session flows are tested end-to-end
   - bug validators are measured on precision and recall

3. Add release gates.
   Minimum gates:
   - no finished jobs with recorded stage failures
   - no schema validation failures in benchmark runs
   - deterministic replay for confirmed findings
   - precision target per bug class

4. Add benchmark anti-cheating rules.
   Requirement:
   - no target-specific hardcoding
   - no benchmark-only signatures that bypass normal logic

Exit criteria:

- every release has benchmark numbers
- regressions in precision, recall, or proof quality fail CI

## Phase 6: Harden Output Into Analyst-Grade Proof

Goal: a confirmed bug must be reviewable and reproducible without reading raw internals.

Priority work:

1. Standardize proof artifacts.
   Each confirmed finding should contain:
   - target
   - role or identity used
   - exact request sequence
   - exact differential observation
   - replay command
   - confidence rationale

2. Unify report generation.
   Current code has two report stacks:
   - `recon_cli/reports/generator.py`
   - `recon_cli/utils/reporter.py`
   Requirement:
   - one reporting pipeline
   - one finding schema

3. Add triage metadata.
   Required fields:
   - exploit preconditions
   - likely duplicate markers
   - likely out-of-scope markers
   - evidence source chain

Exit criteria:

- every confirmed bug is replayable
- report output is generated from one normalized finding model

## Priority Order

Build order should be:

1. Runtime truthfulness and state integrity
2. Session and identity engine
3. Target graph and object/workflow memory
4. Adaptive validators
5. Planner / executor / judge separation
6. Benchmark gates
7. Reporting unification

Do not invert this order.

If runtime truthfulness and auth durability are still weak, adding more bug classes will increase noise faster than capability.

## Success Metrics For V2

ReconnV2 V2 is successful when:

- finished jobs are trustworthy
- confirmed findings always include replayable proof
- at least two auth identities can be replayed reliably
- IDOR, SSRF, and auth bypass precision are measured and stable
- benchmark-driven regressions block merges
- the planner can prioritize hypotheses based on target state, not just static stage order

Suggested target metrics:

- false positive rate for confirmed findings: under 5%
- replay success rate for confirmed findings: over 90%
- auth replay success rate: over 90%
- benchmark precision for IDOR / SSRF / auth bypass: tracked per release

## Final Standard

The V2 standard is:

> ReconnV2 should behave like a serious junior-to-mid analyst that remembers state, holds multiple identities, tests hypotheses carefully, and refuses to call something a bug without evidence.

That is the threshold for "autonomous bug finder" in this repository.
