# 🛡️ ReconnV2 Core Objective

> **Purpose:** ReconnV2 exists to make web bug hunting faster, more reliable, and more evidence-driven.

The tool is not successful because it prints many findings. It is successful if it helps an analyst reach real bugs faster, with better signal, better prioritization, and usable proof. This is the **Honest Recon** standard.

---

## 🎯 Core Objective

Build a CLI-first web reconnaissance and vulnerability discovery tool that can consistently discover important security issues across modern and legacy web architectures without hardcoding per-target answers.

## ✨ What "Good" Means

ReconnV2 should meet this standard:
1. **Reliability:** It finds important bugs consistently across different tech stacks.
2. **Signal-to-Noise:** It reduces false positives through active verification.
3. **Actionability:** It provides evidence (HTTP traces, proof-of-concept payloads) an analyst can act on.
4. **Efficiency:** It helps reach bugs faster than manual work alone.

---

## 📊 Benchmark Objective (v1 Scope)

ReconnV2 should be evaluated against a benchmark corpus that includes diverse, reproducible web application environments. The tool must be tested against:

*   **OWASP Juice Shop** (Modern SPA, Node.js, REST/GraphQL)
*   **DVWA (Damn Vulnerable Web Application)** (Legacy PHP, SQLi, XSS)
*   **OWASP WebGoat** (Java-based, complex server-side vulnerabilities)
*   **VulnHub Machines** (Full-stack infrastructure and network-level recon)

The goal is to perform well across classes of apps and bugs without specialized "benchmark-only" code.

---

## 🚫 Anti-Cheating Rule

ReconnV2 must not hardcode answers for known benchmark applications.

*   **No domain/target special casing** to emit findings for a specific sample.
*   **No app-specific signatures** whose only purpose is to recognize a benchmark target and return pre-baked output.
*   Framework and library fingerprints (e.g., detecting React, Express, or Spring) are allowed only when they generalize across real targets.
*   Test fixtures must validate behavior, not reward memorized strings.

---

## 🔍 Primary Capability & Verification Standards

To prevent noise, ReconnV2 must follow strict **Active Proof** requirements for high-signal findings:

### 1. Injection & Logic (Strict Verification)
*   **SSRF:** Only reported if an **Out-of-Band (OOB) interaction** is confirmed (via callback server) or if **Internal Metadata** (e.g., AWS/GCP metadata headers or 169.254.169.254 content) is successfully leaked in the response.
*   **Open Redirects:** Only reported if the tool can verify the `Location` header matches the payload *and* the final response corresponds to the intended external domain.
*   **Input Validation Flaws:** Must be backed by **Differential Analysis** (e.g., comparing response time, status codes, or content length between a normal request and an injected payload).

### 2. Authentication & Authorization
*   **IDOR:** Verified via **Cross-Token Validation** (comparing access between two different user tokens).
*   **Auth Bypass:** Only reported if a restricted resource is accessed with an unauthenticated or low-privilege session.

### 3. Infrastructure & Secrets
*   **Hardcoded Secrets:** Verified via **Entropy Checks** and, where safe/possible, **Passive API validation** (e.g., checking if a key format matches the provider's known structure).
*   **Cloud Exposure:** Only reported if the bucket or asset returns a `200 OK` or `403 Forbidden` with a confirmed provider-specific header (e.g., `x-amz-request-id`).

---

## 📄 Required Output Quality

For a finding to be useful, ReconnV2 should provide:
*   **Location:** Specific URL, Endpoint, Parameter, or Header.
*   **Evidence:** The exact HTTP Request/Response or snippet that proves the finding.
*   **Provenance:** How the finding was discovered (e.g., passive crawl vs. active fuzzing).
*   **Confidence:** Correlation reasoning (e.g., "Confirmed via OOB Callback").

---

## ✅ Success Criteria

ReconnV2 is considered effective when it can:
*   Consistently detect important issues across multiple web architectures.
*   Avoid flooding the analyst with unverified "potential" findings.
*   Connect discovery findings to **Active Proof**.

---

## 📈 Evaluation Metrics

1. **Detection rate** on the benchmark corpus (Juice Shop, DVWA, etc.).
2. **False positive rate** for prioritized findings (Goal: < 5%).
3. **Actionability:** Percentage of findings that include a verified "Active Proof".
4. **Speed:** Time-to-first-high-value-finding versus manual-only workflow.

---

## 🛠️ Working Standard

The working standard for ReconnV2 is:
> "Good enough to be trusted as a serious bug-hunting assistant, prioritizing evidence and honesty over raw volume."
