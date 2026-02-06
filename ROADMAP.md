# ReconnV2 Roadmap

This roadmap focuses on stability, coverage, and operator experience for personal recon runs.

**Now (Stability & Safety)**
- [x] Normalize finding metadata (type + severity) across stages
- [x] Add subdomain takeover checks with CNAME verification
- [x] Add authenticated scanning support (headers, cookies, login flow)
- [x] Add safe, opt-in parallel pipeline execution with dependency map + locks
- [x] Add regression tests for parallel pipeline mode
- [x] Add per-stage rate limit knobs for active probes
- [ ] Add optional artifact retention/cleanup policy for large jobs

**Next (Coverage & Signal)**
- [ ] Expand takeover fingerprints and false-positive guards
- [x] Add HTTP security headers checks (CSP, HSTS, XFO, etc.)
- [x] Add TLS and cipher hygiene checks (protocols, weak ciphers)
- [ ] Add tech stack fingerprinting for non-HTTP services
- [ ] Improve dedupe and noise filtering for API endpoints

**Later (Usability & Automation)**
- [ ] Configurable alert rules for high-impact findings
- [ ] Scan diff view for regression tracking across runs
- [ ] Job templates for repeatable scans
- [ ] Exportable JSON schema for findings + assets
