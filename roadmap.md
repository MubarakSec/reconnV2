# ReconnV2 Security & Stability Overhaul Roadmap (Phase 2)

Following the initial async transformation, this roadmap focuses on resolving critical security vulnerabilities, architectural bottlenecks, and logic errors identified during the security review.

## Phase 1: Security Hardening & API Integrity
- [ ] **Fix API Auth Bypass**: Change `_maybe_authenticate` to `_require_authenticate` for all sensitive endpoints.
- [ ] **Harden CORS Policy**: Remove wildcard methods/headers and restrict to specific, safe defaults.
- [ ] **Nmap Command Guard**: Implement argument sanitization for `nmap_args` to prevent script/file injection.
- [ ] **Secure JSONL I/O**: Complete the migration to `context.get_results()` to eliminate redundant disk reads.

## Phase 2: Correctness & Verification
- [ ] **Origin Verification Upgrade**: Add CDN IP range filtering to `OriginDiscoveryStage` to eliminate false positives.
- [ ] **Stricter Takeover Scoring**: Require evidence-provider alignment before marking findings as Critical.
- [ ] **Async DNS Fix**: Migrate all remaining blocking `socket.gethostbyname` calls to `run_in_executor`.

## Phase 3: Feature Enablement & OSINT
- [ ] **Enable Hidden Stages**: Expose `secrets`, `crawl`, `screenshots`, and `github_recon` flags in `default.yaml`.
- [ ] **Wayback CDX API**: Finalize the httpx-based fallback for historical endpoint discovery.
- [ ] **Bulk Reverse WHOIS**: Integrate production-ready API keys for registrar-based expansion.

## Phase 4: Code Quality
- [ ] **Error Visibility**: Replace remaining `except Exception: pass` with debug logging.
- [ ] **Refactor Long Methods**: Continue breaking down logic in discovery stages into testable units.

## Phase 5: Delta & Deduplication Intelligence
- [ ] Build DeltaStage: diff current run against last finished run for same target, tag new findings with "delta:new"
- [ ] Persist result fingerprints per-target across runs so re-scans surface only new attack surface
- [ ] Add delta summary to Telegram notifications (X new findings, Y new hosts since last run)

## Phase 6: Active Validation Pipeline
- [ ] Wire nuclei to auto-select templates based on what earlier stages found (CMS tags → CMS templates, exposed ports → CVE templates)
- [ ] Add missing takeover fingerprints: Acquia, Bitbucket, DigitalOcean Spaces, Kinsta, Squarespace, Tumblr, UserVoice, Webflow, Launchrock (12 providers total)

## Phase 7: Performance
- [ ] Replace synchronous requests.get() with httpx.AsyncClient in all 15 stages that still use it (js_intel, html_forms, security_headers, auth_discovery, cms_scan, verify_findings, ws_grpc_discovery, open_redirect_validator, cloud_assets)