# 🏗️ ReconnV2 Architecture | الهيكل المعماري

<div dir="rtl">

## 📋 نظرة عامة

ReconnV2 مبني على معمارية **Pipeline-based** مع فصل واضح للمسؤوليات.

</div>

---

## 📊 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         User Interfaces                              │
├─────────────────┬─────────────────┬─────────────────────────────────┤
│   CLI (typer)   │  REST API       │   Web Dashboard                 │
│   recon_cli/    │  (FastAPI)      │   (Jinja2 + JS)                 │
│   cli.py        │  api/app.py     │   web/app.py                    │
└────────┬────────┴────────┬────────┴────────────┬────────────────────┘
         │                 │                      │
         └─────────────────┼──────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       Job Management Layer                           │
├─────────────────────────────────────────────────────────────────────┤
│  JobManager          JobLifecycle         JobRecord                  │
│  - create_job()      - start()            - spec                     │
│  - load_job()        - finish()           - metadata                 │
│  - update_metadata() - fail()             - paths                    │
│  jobs/manager.py     jobs/lifecycle.py    jobs/models.py             │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       Pipeline Engine                                │
├─────────────────────────────────────────────────────────────────────┤
│  PipelineRunner                  PipelineContext                     │
│  - run()                         - targets                           │
│  - stages[]                      - executor                          │
│                                  - runtime_config                    │
│  pipeline/runner.py              pipeline/context.py                 │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       Pipeline Stages (18)                           │
├─────────────────────────────────────────────────────────────────────┤
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐        │
│  │ Normalize  │→│ Passive    │→│ Dedupe     │→│ DNS        │        │
│  │ Scope      │ │ Enum       │ │            │ │ Resolve    │        │
│  └────────────┘ └────────────┘ └────────────┘ └────────────┘        │
│        ↓              ↓              ↓              ↓                │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐        │
│  │ Enrichment │→│ HTTP       │→│ Scoring    │→│ IDOR       │        │
│  │            │ │ Probe      │ │            │ │ Check      │        │
│  └────────────┘ └────────────┘ └────────────┘ └────────────┘        │
│        ↓              ↓              ↓              ↓                │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐        │
│  │ Auth       │→│ Fuzzing    │→│ Active     │→│ Secrets    │        │
│  │ Matrix     │ │            │ │ Intel      │ │ Detection  │        │
│  └────────────┘ └────────────┘ └────────────┘ └────────────┘        │
│        ↓              ↓              ↓              ↓                │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐        │
│  │ Runtime    │→│ Correlation│→│ Learning   │→│ Scanner    │        │
│  │ Crawl      │ │            │ │            │ │ (Nuclei)   │        │
│  └────────────┘ └────────────┘ └────────────┘ └────────────┘        │
│        ↓              ↓                                              │
│  ┌────────────┐ ┌────────────┐                                       │
│  │ Screenshots│→│ Finalize   │                                       │
│  └────────────┘ └────────────┘                                       │
│                                                                      │
│  pipeline/stages.py (2400+ lines)                                    │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       External Tools Integration                     │
├─────────────────────────────────────────────────────────────────────┤
│  CommandExecutor               Tool Wrappers                         │
│  - run()                       - subfinder                           │
│  - run_to_file()               - amass                               │
│  - available()                 - httpx                               │
│                                - nuclei                              │
│  tools/executor.py             - ffuf, katana, dnsx                  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 📁 Module Structure

```
recon_cli/
├── __init__.py           # Package exports
├── __main__.py           # Entry point: python -m recon_cli
├── cli.py                # CLI commands (typer)
├── config.py             # Configuration & paths
├── metrics.py            # Metrics collection
├── plugins.py            # Plugin loader
├── projects.py           # Project management
├── rules.py              # Rules engine
│
├── api/                  # REST API
│   ├── __init__.py
│   └── app.py            # FastAPI application
│
├── web/                  # Web Dashboard
│   ├── __init__.py
│   ├── app.py            # Jinja2 templates
│   ├── templates/        # HTML templates
│   └── static/           # CSS, JS
│
├── jobs/                 # Job Management
│   ├── __init__.py
│   ├── manager.py        # CRUD operations
│   ├── models.py         # Data models
│   ├── lifecycle.py      # State transitions
│   ├── results.py        # Results handling
│   ├── summary.py        # Summary generation
│   └── validator.py      # Validation
│
├── pipeline/             # Pipeline Engine
│   ├── __init__.py
│   ├── runner.py         # Pipeline executor
│   ├── context.py        # Execution context
│   ├── stages.py         # All stages (2400+ LOC)
│   ├── progress.py       # Progress tracking
│   ├── stage_idor.py     # IDOR detection
│   └── stage_auth_matrix.py
│
├── tools/                # External Tools
│   ├── __init__.py
│   └── executor.py       # Command executor
│
├── scanners/             # Scanner Integrations
│   ├── __init__.py
│   └── integrations.py   # nuclei, wpscan
│
├── secrets/              # Secret Detection
│   ├── __init__.py
│   └── detector.py       # Pattern matching
│
├── takeover/             # Subdomain Takeover
│   ├── __init__.py
│   └── detector.py       # Takeover detection
│
├── correlation/          # Result Correlation
│   ├── __init__.py
│   └── graph.py          # Graph analysis
│
├── learning/             # Machine Learning
│   ├── __init__.py
│   ├── collector.py      # Data collection
│   └── model.py          # ML model
│
├── active/               # Active Modules
│   ├── __init__.py
│   └── modules.py        # JS secrets, backups
│
├── crawl/                # Web Crawling
│   ├── __init__.py
│   └── runtime.py        # Playwright crawler
│
├── db/                   # Database
│   ├── __init__.py
│   ├── models.py         # SQLite models
│   └── storage.py        # CRUD operations
│
├── plugins/              # Plugin System
│   └── __init__.py       # Plugin interfaces
│
└── utils/                # Utilities
    ├── __init__.py
    ├── cache.py          # Caching system
    ├── rate_limiter.py   # Rate limiting
    ├── notify.py         # Notifications
    ├── reporter.py       # HTML reports
    ├── pdf_reporter.py   # PDF reports
    ├── structured_logging.py  # JSON logging
    ├── sanitizer.py      # Data redaction
    ├── validation.py     # Input validation
    ├── jsonl.py          # JSONL handling
    ├── enrich.py         # Data enrichment
    ├── fs.py             # File system
    ├── time.py           # Time utilities
    └── performance.py    # Performance utils
```

---

## 🔄 Data Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                           Input                                      │
│  target.com  OR  targets.txt  →  JobSpec                            │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        Job Creation                                  │
│  JobManager.create_job() → JobRecord (spec + metadata + paths)      │
│  Stored in: jobs/queued/{job_id}/                                   │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      Pipeline Execution                              │
│                                                                      │
│  Stage 1: Normalize → targets.txt                                   │
│  Stage 2: Passive   → subfinder.txt, amass.json                     │
│  Stage 3: Dedupe    → unique hosts                                  │
│  Stage 4: DNS       → resolved hosts                                │
│  Stage 5: HTTP      → httpx.json (live hosts)                       │
│  ...                                                                 │
│  Stage N: Finalize  → summary, report                               │
│                                                                      │
│  Each stage:                                                         │
│  1. Check if enabled (profile-based)                                │
│  2. Check if already done (checkpoint)                              │
│  3. Execute with retry                                              │
│  4. Save checkpoint                                                 │
│  5. Update metadata                                                 │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         Output                                       │
│                                                                      │
│  jobs/finished/{job_id}/                                            │
│  ├── metadata.json    # Job status, timing, stats                   │
│  ├── spec.json        # Original request                            │
│  ├── results.jsonl    # All findings (JSONL)                        │
│  ├── results.txt      # Human-readable                              │
│  ├── artifacts/       # Tool outputs                                │
│  │   ├── targets.txt                                                │
│  │   ├── subfinder.txt                                              │
│  │   ├── httpx.json                                                 │
│  │   ├── nuclei.json                                                │
│  │   └── ...                                                        │
│  └── logs/                                                          │
│      └── pipeline.log                                               │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 🔌 Plugin Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                      Plugin Interface                                │
├─────────────────────────────────────────────────────────────────────┤
│  PluginInterface (ABC)                                               │
│  ├── METADATA: PluginMetadata                                       │
│  ├── execute(context) -> PluginResult                               │
│  ├── initialize() -> bool                                           │
│  ├── cleanup() -> None                                              │
│  └── validate_config() -> bool                                      │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
         ┌───────────────────────┼───────────────────────┐
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
│  ScannerPlugin  │   │  EnricherPlugin │   │  ReporterPlugin │
│  - scan()       │   │  - enrich()     │   │  - generate()   │
└─────────────────┘   └─────────────────┘   └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
│  NotifierPlugin │   │  ProcessorPlugin│   │  StagePlugin    │
│  - send()       │   │  - process()    │   │  - run()        │
└─────────────────┘   └─────────────────┘   └─────────────────┘
```

---

## 🗄️ Database Schema

```sql
-- Jobs table
CREATE TABLE jobs (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    profile TEXT NOT NULL,
    status TEXT NOT NULL,
    stage TEXT,
    queued_at TEXT,
    started_at TEXT,
    finished_at TEXT,
    error TEXT,
    stats TEXT,  -- JSON
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Hosts table
CREATE TABLE hosts (
    id INTEGER PRIMARY KEY,
    job_id TEXT NOT NULL,
    hostname TEXT NOT NULL,
    ip TEXT,
    source TEXT,
    resolved BOOLEAN DEFAULT FALSE,
    live BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (job_id) REFERENCES jobs(id),
    UNIQUE(job_id, hostname)
);

-- URLs table
CREATE TABLE urls (
    id INTEGER PRIMARY KEY,
    job_id TEXT NOT NULL,
    url TEXT NOT NULL,
    status_code INTEGER,
    content_type TEXT,
    source TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (job_id) REFERENCES jobs(id)
);

-- Vulnerabilities table
CREATE TABLE vulnerabilities (
    id INTEGER PRIMARY KEY,
    job_id TEXT NOT NULL,
    host TEXT NOT NULL,
    template_id TEXT,
    name TEXT,
    severity TEXT,
    description TEXT,
    matched_at TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (job_id) REFERENCES jobs(id)
);

-- Secrets table
CREATE TABLE secrets (
    id INTEGER PRIMARY KEY,
    job_id TEXT NOT NULL,
    url TEXT,
    pattern TEXT,
    value_hash TEXT,
    confidence TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (job_id) REFERENCES jobs(id)
);
```

---

## ⚡ Performance Optimizations

### Rate Limiting

```
Token Bucket Algorithm:
├── Global bucket (10 req/s default)
├── Per-host bucket (5 req/s default)
└── Cooldown on 429 responses
```

### Caching

```
Hybrid Cache:
├── Memory cache (LRU, TTL)
├── SQLite cache (persistent)
└── Automatic cleanup
```

### Concurrency

```
Current:
├── Sequential stage execution
└── Tool-level parallelism (some tools)

Future:
├── Async HTTP with aiohttp
├── Parallel stage execution
└── Worker pool for tools
```

---

## 🔐 Security Features

| Feature | Implementation |
|---------|----------------|
| Secrets Detection | Regex patterns + Shannon entropy |
| Data Redaction | Sanitizer module for logs |
| TLS Verification | Configurable per-request |
| Rate Limiting | Prevent target overload |
| Input Validation | Target validation |

---

## 📈 Metrics & Observability

```
Metrics Collection:
├── Stage duration
├── Tool execution time
├── Findings count
├── Error rates
└── Resource usage

Logging:
├── Structured JSON logging
├── Trace IDs
├── Stage context
└── Error details

Notifications:
├── Telegram
├── Slack
├── Discord
└── Email
```

---

## 🚀 Extension Points

| Extension | Location | Purpose |
|-----------|----------|---------|
| Custom Stages | `plugins/__init__.py` | New pipeline stages |
| Custom Scanners | `ScannerPlugin` | New scanning tools |
| Custom Reports | `ReporterPlugin` | New report formats |
| Custom Notifiers | `NotifierPlugin` | New notification channels |
| Profiles | `config/profiles.json` | Scan configurations |

---

<div align="center">

**ReconnV2 Architecture v0.1.0**

</div>
