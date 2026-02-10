# ReconnV2 Roadmap (Bug Bounty Focus)

This is a **living roadmap** for ReconnV2.  
Checked items are **already implemented in the repo**.  
Un‑checked items are **future or continuous improvements**.

## Foundation (Implemented)
- [x] Single profile runs full pipeline (`bugbounty`).
- [x] Long timeouts for heavy tools (2h tool/scanner timeouts).
- [x] Signal bus in `results.jsonl` used for cross‑stage prioritization.
- [x] Stage ordering enforced in pipeline (`stages.py`, `parallel.py`).
- [x] Passive subdomains (`subfinder`, `amass`).
- [x] Passive URL discovery (`waybackurls` / `gau`).
- [x] DNS resolution with massdns fallback.
- [x] Vhost discovery (Host header fuzzing).
- [x] Subdomain permutations (prefix/suffix).
- [x] CT + ASN pivot expansion.
- [x] Cloud asset discovery (S3/GCS/Azure).
- [x] HTTP probing + tech detection (httpx).
- [x] JS intel (endpoint extraction + classification).
- [x] Runtime crawl (Playwright).
- [x] API recon + schema probing.
- [x] GraphQL recon + exploit probing.
- [x] OAuth/OIDC discovery.
- [x] WS/GRPC discovery.
- [x] HTML form mining (general).
- [x] Upload surface probing.
- [x] CMS scanning (Drupal/Joomla/Magento + WP via wpscan).
- [x] Fuzzing + param fuzzing (ffuf).
- [x] Vuln scanners (dalfox + sqlmap).
- [x] Nuclei scanner integration.
- [x] WAF probing + bypass signals.
- [x] Verification stage for findings.
- [x] Extended auto‑confirmation: SSRF/XXE via OAST (Interactsh).
- [x] Extended auto‑confirmation: Open Redirect via Location header.
- [x] Extended auto‑confirmation: LFI via response signature.
- [x] Exploit validation (nuclei‑based).
- [x] WAF detection requires multiple indicators.
- [x] JS intel filters static assets and normalizes endpoints.
- [x] LFI confirmation requires baseline‑free signatures.
- [x] Candidate scoring boosted by param value heuristics.
- [x] Soft‑404 penalties applied to fuzzing/vuln scans.
- [x] Noise tagging reduces false positives.
- [x] Global retries/backoff support for HTTP.
- [x] Rate limiting for high‑impact stages.
- [x] OAST session lifecycle hardened (safe stop + output parsing).
- [x] Graceful fallback when tools missing.
- [x] `results.jsonl` as single source of truth.
- [x] `results.txt` summary with stage health and confirmed section.
- [x] `results_bigger.txt` (score ≥ 60) with CONFIRMED/CANDIDATE labels.
- [x] `results_confirmed.txt` (confirmed only).
- [x] Artifacts per stage under `artifacts/`.
- [x] Runs full pipeline + scanners.
- [x] Long tool timeouts (2h).
- [x] Strong API/GraphQL coverage.
- [x] Auto‑confirmation enabled.
- [x] Proper scope + allowlist handling.

---

## Continuous Improvement Loop (Always‑On)
- [ ] Track false‑positive rate per run and reduce it over time.
- [ ] Track confirmed‑finding rate per run and improve it over time.
- [ ] Refresh external tool versions regularly (nuclei/httpx/katana/ffuf).
- [ ] Update wordlists quarterly (bug bounty program specific).
- [ ] Review `results_confirmed.txt` for quality feedback each run.
- [ ] Keep a small benchmark scope to regression‑test signal quality.

## Expansion Targets (Optional, If Needed)
- [ ] Add more passive subdomain sources (assetfinder/findomain/chaos).
- [ ] Stronger permutation engine (dnsgen/alterx style).
- [ ] Dedicated param discovery tools (paramspider/arjun).
- [ ] Auto‑update/check for nuclei templates.
- [ ] Authenticated testing flows (if needed later).
