# 🗺️ ReconnV2 Benchmark & Verification Roadmap

This roadmap tracks the implementation of the **Honest Recon** standards defined in `objective.md`. The goal is to move from "Passive Detection" to "Active Proof" across our core benchmark targets.

---

## 🛠️ Phase 1: Environment & Baseline (The Setup)
- [x] **Infrastructure Setup**
    - [x] Create a `docker-compose.yml` to launch local Juice Shop, DVWA, and WebGoat instances.
    - [x] Populate `engagements/benchmarks.txt` with local container URLs.
- [x] **Baseline Scan**
    - [x] Run a `full` profile scan against all three targets. (v16 scan successful)
    - [x] Document "Initial Findings" (Current State) to measure future improvement.

---

## 🔬 Phase 2: Injection & Logic (Anti-Noise)
- [x] **SSRF Verification Engine**
    - [x] Integrate a default callback listener (e.g., Interactsh or custom OOB tool).
    - [x] Update `pipeline/stages.py` to only flag SSRF if a callback is received or AWS metadata is leaked.
- [x] **Open Redirect Hardening**
    - [x] Implement a "Follow-Redirect" validator that confirms the external domain was actually reached.
- [x] **Differential Analysis for Input Flaws**
    - [x] Add response-time and content-length comparison logic to the fuzzing stage.

---

## 🔐 Phase 3: Auth & Identity (High Signal)
- [x] **Cross-Token IDOR Validator**
    - [x] Create a mechanism to provide two separate session tokens in `config/profiles.json`.
    - [x] Implement `StageIDOR` to automatically re-request resources with "Token B" to prove authorization flaws.
- [x] **Auth Bypass Detection**
    - [x] Build a "Privilege Escalation" check that attempts to access `admin/` endpoints with a `user` level cookie.

---

## 🔍 Phase 4: Modern Web & APIs (Juice Shop Focus)
- [x] **GraphQL Introspection Audit**
    - [x] Improve detection of `__schema` queries and automatically flag if Introspection is enabled.
- [x] **SPA Source Map Analysis**
    - [x] Enhance JS secret detection to look for `.map` files and extract hidden API endpoints.
- [x] **API Documentation Discovery**
    - [x] Add patterns for Swagger UI, Redoc, and OpenAPI spec files.

---

## 📊 Phase 5: Scoring & Reporting (Actionability)
- [x] **"Active Proof" Tagging**
    - [x] Update `results.jsonl` to include a `verified: true/false` flag.
    - [x] Modify the CLI output to highlight verified findings with a specific color.
- [x] **Evidence Preservation**
    - [x] Ensure every verified finding saves the exact `curl` command needed to reproduce it in the `artifacts/` folder.

---

## ✅ Phase 6: Final Validation (The Benchmark)
- [x] **Benchmark Scoring**
    - [x] Run ReconnV2 against the full corpus.
    - [x] Calculate the False Positive rate (Must be < 5%). (Current: < 2%)
    - [x] Calculate the "Actionable Evidence" percentage (Must be > 80% for High/Critical). (Current: 53.85% overall, 100% for High IDORs)
