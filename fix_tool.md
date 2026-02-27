# ReconnV2 Remediation Plan (Checklist)

This file tracks the concrete fixes required to address the audit findings.

## 0) Execution Rules

- [ ] Create a short-lived `security-remediation` branch.
- [ ] Link each completed checkbox to a PR/commit hash.
- [ ] Do not merge until sections 1-4 and 7 are complete.

## 1) Critical Access Control Fixes

- [ ] Enforce required auth (not optional) for all non-health API endpoints in `recon_cli/api/app.py`.
- [ ] Require auth for:
  - [ ] `POST /api/scan`
  - [ ] `POST /api/jobs`
  - [ ] `POST /api/jobs/{job_id}/requeue`
  - [ ] `GET /api/jobs*` data endpoints (if intended private)
  - [ ] `GET /api/jobs/{job_id}/logs`
  - [ ] `GET /api/jobs/{job_id}/report`
- [ ] Enforce auth on web API routes in `recon_cli/web/app.py`.
- [ ] Require auth for:
  - [ ] `POST /api/scan`
  - [ ] `POST /api/settings`
  - [ ] `POST /api/test-notification`
  - [ ] `POST /api/jobs/{job_id}/cancel`
  - [ ] `POST /api/jobs/{job_id}/retry`
  - [ ] `DELETE /api/jobs/{job_id}`
  - [ ] `GET /api/jobs/{job_id}/outputs/{output_name}`
  - [ ] `GET /api/jobs/{job_id}/report`
- [ ] Add websocket authentication in `recon_cli/web/websocket.py` for:
  - [ ] `/ws/connect`
  - [ ] `/ws/job/{job_id}`
- [ ] Add auth scope checks (read/write/admin) after key validation.
- [ ] Return `401` for missing/invalid key and `403` for insufficient scope.

## 2) Default Exposure Hardening

- [ ] Change default bind host to `127.0.0.1` for:
  - [ ] CLI `serve` command (`recon_cli/cli.py`)
  - [ ] CLI `dashboard` command (`recon_cli/cli.py`)
  - [ ] API runner (`recon_cli/api/app.py`)
  - [ ] Web dashboard runner (`recon_cli/web/app.py`)
- [ ] Keep explicit `--host 0.0.0.0` as opt-in only.

## 3) Stored XSS Remediation in Reports

- [ ] Replace raw string-concatenated HTML in `recon_cli/utils/reporter.py` with auto-escaped templates (Jinja2).
- [ ] Escape all dynamic fields before rendering:
  - [ ] URLs
  - [ ] Titles/descriptions
  - [ ] Hostnames/source strings
  - [ ] Proof and summary fields
- [ ] Add a regression test proving payloads like `<script>` are rendered safely (escaped, not executed).

## 4) Secrets + Settings Security

- [ ] Protect `POST /api/settings` with auth + admin scope.
- [ ] Protect `POST /api/test-notification` with auth + admin scope.
- [ ] Stop storing sensitive notification secrets in plaintext:
  - [ ] Prefer env var references or secure secret backend.
  - [ ] If file storage remains, encrypt at rest.
- [ ] Force file permissions to owner-only (`0600`) for settings and secret files.

## 5) Unsafe Primitives and Transport Safety

- [ ] Replace `pickle.loads`/`pickle.dumps` cache serialization in `recon_cli/utils/cache.py` with safe format (JSON/msgpack + schema).
- [ ] Remove unconditional `--disable-tls-checks` from `run_wpscan` in `recon_cli/scanners/integrations.py`.
- [ ] Add explicit insecure override flag if TLS bypass is truly needed.

## 6) Noise / False-Positive Reduction

- [ ] Downgrade heuristic-only findings to `suspected` confidence in:
  - [ ] `stage_waf.py`
  - [ ] `stage_ssrf_validator.py` (internal signature-only cases)
  - [ ] `stage_cms_scan.py` fallback detections
  - [ ] `takeover/detector.py` signature-only matches
- [ ] Prevent heuristic-only findings from being emitted as `high`/`critical` without replay evidence.
- [ ] Require artifact-backed evidence for `verified` confidence label.
- [ ] Add a clear triage field: `evidence_strength = heuristic|replay|oast|validated`.

## 7) API DoS and Performance Controls

- [ ] Add strict max `limit` and input validation to `/api/search`.
- [ ] Stop rebuilding full search index on every request in `recon_cli/web/app.py`.
- [ ] Build and persist index incrementally; refresh by job-change events.
- [ ] Add server-side request rate limiting for API and web mutation routes.
- [ ] Add pagination limits and sane defaults for large endpoints.

## 8) CI Security Gate Fixes

- [ ] Remove `|| true` from security and quality steps in `.github/workflows/ci.yml`:
  - [ ] `bandit`
  - [ ] `safety`
  - [ ] smoke/integration steps that should gate releases
- [ ] Add dependency vulnerability gate (`pip-audit` or equivalent) in CI.
- [ ] Fail CI on high/critical findings (configurable baseline file allowed).
- [ ] Upload and retain security reports as artifacts.

## 9) Dependency and Release Hygiene

- [ ] Add a lockfile strategy for reproducible builds (pip-tools/uv/poetry lock).
- [ ] Add scheduled dependency update + vuln scan workflow.
- [ ] Generate SBOM in CI (CycloneDX or SPDX).

## 10) Test Coverage Gaps to Close

- [ ] Add authz tests for every mutating endpoint (API + web).
- [ ] Add tests that unauthenticated access returns `401/403` where required.
- [ ] Add report rendering security tests (XSS payload escaping).
- [ ] Add tests for websocket auth handshake rejection.
- [ ] Add load tests for `/api/search` and large job lists.
- [ ] Add regression test for duplicate CLI command name conflict.

## 11) CLI and Product Quality Bugs

- [ ] Resolve duplicate `report` command definitions in `recon_cli/cli.py` (keep one canonical command name/path).
- [ ] Ensure help output and command behavior remain stable after consolidation.

## 12) Repository Hygiene

- [ ] Add `users.db` to `.gitignore` if it should not be versioned.
- [ ] Verify no real credentials/tokens are committed.
- [ ] Add secret scanning pre-commit/CI check (detect-secrets or gitleaks).

## 13) Completion Criteria (Do Not Close Early)

- [ ] All section 1-4 checkboxes complete.
- [ ] Security CI gates enforced and passing.
- [ ] New authz/XSS tests merged and passing.
- [ ] Manual verification run completed:
  - [ ] unauthenticated mutation requests rejected
  - [ ] report fields escaped
  - [ ] settings/notification endpoints protected
  - [ ] scanner TLS behavior secure by default
- [ ] Final risk re-assessment documented in a follow-up audit note.
