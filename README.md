# 🔍 ReconnV2 - Elite Bug Bounty Reconnaissance Pipeline

<div align="center">

![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)
![Kali](https://img.shields.io/badge/Kali-Linux-557C94.svg)
![Status](https://img.shields.io/badge/Status-Elite-gold.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

**The "God-Mode" Orchestrator for Professional Bug Hunters**

[Quickstart](#-quickstart) •
[Interactive](#-interactive-wrapper) •
[Elite Features](#-elite-god-mode-capabilities) •
[Verification Standards](#-honest-recon-standards) •
[Git-Ops Diffing](#-git-ops-monitoring)

</div>

---

## ⚡ Elite / God-Mode Capabilities (2026 Upgrades)

ReconnV2 has been upgraded with professional-grade features that bypass standard protections and find deep logic flaws.

| Feature | Description |
|:--- |:--- |
| 🌐 **Autonomous Auth** | Automatic Signup/Signin using **1secmail & GuerrillaMail** APIs for authenticated reconnaissance. |
| 🧬 **API Reconstructor** | Automatically builds **OpenAPI/Swagger specs** from observed traffic and JS hints. |
| 🎯 **Logic Fuzzer** | Intelligent **BOLA** and **Mass Assignment** detection using reconstructed schemas. |
| 🕵️ **Stealth & Evasion** | **Proxy Rotation**, User-Agent randomization, and **Jitter** to bypass WAFs/Rate Limits. |
| 🏁 **Race Condition** | Sync-burst request testing for state-changing endpoints (Turbo-Intruder style). |
| 🕸️ **Headless Crawl** | Playwright-powered rendering (skips binary downloads) to fix the **"SPA Gap"**. |
| 🛰️ **SSRF Pivot Pro** | Pivots confirmed SSRF to perform **Internal Port Scanning** (Redis, DBs, Localhost). |
| 🧪 **Cache Destruction** | Tests for **Web Cache Deception** and **Cache Poisoning** via unkeyed headers. |
| 🎯 **Wordlist Miner** | Generates **Target-Aware** dictionaries by scraping keywords from the target site. |
| 🐍 **Auto-POC Gen** | Automatically generates standalone **Python exploit scripts** for confirmed bugs. |
| ⚡ **QUIC Bypass** | Identifies **HTTP/3 (QUIC)** support and probes for **WAF Bypasses** over UDP. |

---

## 🛡️ "Honest Recon" Standards (Active Proof Only)

ReconnV2 follows the **Honest Recon** standard: it prioritizes **Proof** over volume.

- **SPA Soft-404 Destroyer**: Uses dynamic fingerprinting to eliminate false positives on modern Single Page Apps.
- **Cross-Token Validation**: Confirms IDORs by comparing access between User A and User B sessions.
- **Origin IP Discovery**: Bypasses Cloudflare/CDNs using **50+ Favicon Fingerprints**, **Censys SSL**, and **IPv6 Leaks**.
- **OOB Integration**: Confirms Blind RCE, SQLi, and SSRF via **Interactsh** real-time interactions.
- **Statistical Timing**: Detects **User Enumeration** via high-precision timing delta comparison (Valid vs Invalid).

---

## 📁 Project Structure

```
reconnV2/
├── 📜 recon.sh             # Ultimate Interactive Wrapper (Bug Bounty Edition)
├── 📜 ROADMAP_ELITE.md     # Future goals (Distributed Celery, LLM Validation)
├── 📜 objective.md         # The "Honest Recon" core standards
├── 📁 recon_cli/           # The Engine
│   ├── pipeline/           # 60+ Autonomous Stages (BOLA, Mass Assignment, QUIC, etc.)
│   ├── utils/              # Stealth, OAST, and Captcha utilities
│   └── ...
├── 📁 config/              # Elite Profiles (ultra-deep, local-benchmark)
├── 📁 data/                # Persistence (Accounts, Favicon Fingerprints)
├── 📁 jobs/                # Job state (SQLite-backed for fault tolerance)
└── 📁 tests/               # Elite Feature Test Suite (test_elite_features.py)
```

---

## 🚀 Quickstart

### 1. The Interactive Experience (Recommended)
```bash
./recon.sh
```
Choose Option **[5] Ultra-Deep Hunter** for the full God-Mode experience on a BBP target.

### 2. Manual CLI God-Mode
```bash
# Full pipeline with logic fuzzing, headless crawl, and hunter-mode scoring
recon scan target.com --profile ultra-deep --mode hunter --inline
```

### 3. Local Benchmarking (Juice Shop / DVWA)
```bash
# Optimized for localhost: avoids public DNS starvation
recon scan http://localhost:3000 --profile local-benchmark --inline
```

---

## 🗄️ Git-Ops Monitoring (`recon diff`)

Professional hunters monitor targets daily. ReconnV2 supports continuous monitoring:

```bash
# Compare yesterday's scan with today's to find the DELTA
recon diff job_yesterday job_today
```
*Outputs only new subdomains, new APIs, and new vulnerabilities.*

---

## 🔄 The Pipeline (Execution Flow)

1.  **Passive Discovery**: Subfinder, Amass, CRT.sh.
2.  **Infrastructure**: IPv6 leak detection, Censys Origin Discovery, Nmap.
3.  **Active Surface**: Headless rendering, JS Secret Harvesting, API Reconstruction.
4.  **Logical Attack**: BOLA Fuzzing, **Mass Assignment**, Race Conditions, Auth Bypass, Cache Poisoning.
5.  **Evidence**: POC Generation, Screenshotting (optimized for media), OAST Interaction collection.
6.  **Reporting**: Git-Ops Diffing and Live War-Room Notifications.

---

## 🔔 Live Notifications

Configure your `.env` to get "shouted" at the second a High/Critical bug is confirmed:
```bash
RECON_TELEGRAM_TOKEN="bot_token"
RECON_TELEGRAM_CHAT_ID="chat_id"
RECON_DISCORD_WEBHOOK="webhook_url"
```

---

## 🤖 Reliability & Fault Tolerance

- **SQLite State Sync**: Every finding is synced to a local database. If your machine crashes, your progress is saved.
- **Smart Circuit Breaker**: Dynamically lowers request speed if WAF blocks are detected.
- **Memory Efficient**: Streams results line-by-line; capable of scanning targets with 1,000,000+ assets.

---

<div align="center">
  <b>Built for Professional Bug Hunters by Engineers who understand the "SPA Gap."</b>
</div>
