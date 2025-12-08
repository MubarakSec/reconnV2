# Roadmap: recon-cli hardening and quality

## Security & Privacy
- [x] Enforce TLS verification in networked probes (IDOR/AuthMatrix/Takeover) and add `--insecure` opt-in flag so tokens aren’t sent without validation.
- [x] Mask secret values before writing artifacts/results; limit previews to hashes; add redact step when exporting.
- [x] Harden result deduping to allow multiple sources per URL/host (merge metadata instead of drop) so findings are not lost.

## Reliability & Safety
- [x] Add timeouts and cancellation for external tools (subfinder, amass, ffuf, httpx, playwright crawl, scanners) to prevent worker hangs.
- [x] Make job/spec/metadata loading resilient to corrupt JSON (fallback defaults + repair/backup) to avoid CLI crashes.
- [x] Treat config initialization as explicit (opt-in) instead of implicit side effect of importing `config`.

## Usability
- [x] Improve error messaging around missing binaries or skipped stages with actionable hints in `results.txt` and CLI output.
- [x] Add `recon-cli doctor --fix` to regenerate default configs/resolvers and verify external tool versions.
- [x] Expand summary to highlight high-risk findings first and include a brief “next actions” section per job.

## Performance & Scale
- [ ] Add concurrency guardrails and per-stage limits (esp. crawl/fuzz/scanners) configurable via profiles.
- [ ] Stream correlation and trimming to reduce memory use on large jobs; include progress logging.
- [ ] Cache enrichment and HTTP probe responses across jobs when `RECON_HOME` is shared.

## Testing & QA
- [ ] Add integration tests that cover failure modes: corrupt spec/metadata, hung external tool (timeout), TLS validation on/off.
- [x] Add unit tests for dedupe/merge logic, secret redaction, and config initialization behavior.
- [ ] Provide a lightweight “no-tools” smoke test path that asserts graceful skips without external binaries.

## Release & Operations
- [ ] Document “secure defaults” profile (strict TLS, redaction, conservative limits).
- [ ] Add metrics/telemetry hooks (opt-in) for job duration, stage failures, and skipped stages to guide tuning.
- [ ] Ship example CI recipe to run lint/tests and the smoke pipeline before releases.

## Context & Mental Model
- [x] Mini recon platform: targets + profiles → job dirs (spec/metadata/artifacts/logs) → deterministic pipeline (passive → DNS → HTTP → fuzz/active/secrets/correlation/learning) with external tools and append-only JSONL + summaries. (Reference section only.)

## Functional Requirements (F)
- [x] FR1 Job lifecycle: create jobs with spec/metadata/paths; states queued/running/finished/failed in separate dirs.
- [x] FR2 Scope validation: hostnames by default; IPs allowed only with `--allow-ip`; IDNA/label normalization.
- [x] FR3 Pipeline stages: normalize_scope, passive_enumeration, dedupe_canonicalize, dns_resolve, asset_enrichment, http_probe, scoring_tagging, fuzzing, active_intelligence, secrets_detection, correlation, optional learning.
- [x] FR4 Profiles & overrides: profiles from config; runtime overrides via CLI/env.
- [x] FR5 Active integrations: optional scanners (nuclei/WPScan) and active modules gated by flags.
- [x] FR6 Results & summaries: JSONL storage, trimmed results, text summaries, correlation artifacts.
- [x] FR7 Job monitoring: list/status/tail/requeue commands.
- [ ] FR8 Projects layer: group jobs into projects with shared configs/scope manifests/reporting.
- [ ] FR9 Incremental recon: reuse artifacts from prior jobs and focus on deltas.
- [ ] FR10 Rules engine: configurable tagging/prioritization/enabling modules per tag/env.
- [ ] FR11 Automation hook: machine-consumable interface (schema/API) for scheduling/retrieval.
- [ ] FR12 Multi-target orchestration: choose one job per target vs single multi-target job with per-target correlation.

## Usability Requirements (U)
- [x] UR1 CLI discoverability with help per command/flag.
- [x] UR2 Human-friendly logs and summaries per job.
- [x] UR3 Docs: README/usage/installation/command guides.
- [x] UR4 JSONL results for jq/grep-friendly consumption.
- [x] UR5 Doctor command to check dependencies and suggest installs (`--fix` regenerates defaults).
- [x] UR6 Actionable missing-tool messages recorded in stats/summary.
- [x] UR7 Quickstart profile/flag with minimal passive defaults and post-run guidance.
- [ ] UR8 Per-stage progress/status display including skipped stages.
- [x] UR9 `report` command to emit shareable reports (txt/md/json).
- [x] UR10 Defaults protect beginners: passive-first, active modules explicit.

## Reliability Requirements (R)
- [x] R1 Atomic JSON writes with temp files.
- [x] R2 Job state separation on disk.
- [x] R3 Graceful missing-tool handling with skips.
- [x] R4 Log redaction.
- [x] R5 Stage checkpoints & reruns.
- [x] R6 Timeouts for external commands with clear errors.
- [ ] R7 Configurable retries/backoff spelled out per stage.
- [x] R8 Job load resilience to corrupt JSON.
- [ ] R9 Concurrency/locking so one worker owns a job.
- [ ] R10 Distinct exit codes for automation.
- [ ] R11 Config/profile validation with helpful errors.

## Performance Requirements (P)
- [x] P1 Expose limits for max targets/hosts/screenshots/crawl depth/concurrency.
- [x] P2 Default profile tuned for small scopes on modest hardware (document target runtime/resources).
- [x] P3 Worker mode should ensure slow jobs don’t block listing/creation; controlled parallelism.
- [x] P4 Streaming/incremental JSONL results.
- [x] P5 Heavy modules off by default; clearly gated in profiles.
- [x] P6 Per-tool concurrency caps configurable.

## Supportability Requirements (S)
- [x] S1 Modular architecture by domain (pipeline/active/scanners/secrets/etc.).
- [x] S2 Typing/dataclasses for core models.
- [x] S3 Tests for pipeline pieces, active modules, limits, redaction, merging.
- [x] S4 Centralized logging/redaction utilities.
- [x] S5 Config module with env vars and profile loading.
- [ ] S6 Formal config/profile schema + validation.
- [ ] S7 Plugin interface for stages/active modules/scanners.
- [ ] S8 Optional structured logging (JSON) toggle.
- [ ] S9 Broader automated tests: per-stage success/failure, artifact corruption handling.
- [ ] S10 Schema versioning in results and job metadata.

## Design / Implementation / Interface / Physical (FURPS+ “+”)
- [x] D1 Layered architecture: CLI, job lifecycle, pipeline orchestrator, tools/integrations, utils.
- [x] D2 Pipeline abstraction: Stage classes with uniform interface.
- [x] D3 Active modules respect config gating.
- [x] D4 Security by design: redaction/secrets baked into defaults.
- [x] I1 Python 3.10+ with type hints.
- [x] I2 Dependencies: Typer, Rich, requests, numpy/sklearn; external binaries subfinder/amass/massdns/httpx/ffuf/nuclei/WPScan/Playwright.
- [x] I3 Coding standards: consistent style, no literal ellipsis (enforced by tests).
- [x] I4 Error handling via CommandExecutor/CommandError wrappers.
- [x] IF1 CLI interface (`scan`, `worker-run`, `list-jobs`, `status`, `tail-logs`, `requeue`).
- [x] IF2 File interface: predictable layout under `RECON_HOME`.
- [x] IF3 JSON/JSONL schema stability.
- [ ] IF4 Future API interface for job submission/retrieval.
- [x] PH1 Platform: works on typical Python 3.10+ envs (tested locally).
- [ ] PH2 External tool install guidance consolidated (doctor already hints; needs formal doc).
- [ ] PH3 Hardware baseline documented (CPU/RAM/disk expectations).
- [x] PH4 Network: requires outbound connectivity for recon/enrichment.
- [x] PH5 Storage layout restricted to `RECON_HOME`.
