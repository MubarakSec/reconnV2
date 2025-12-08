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
