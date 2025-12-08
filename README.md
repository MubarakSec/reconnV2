# recon-cli

`recon-cli` orchestrates reconnaissance jobs through a deterministic pipeline (passive discovery -> dedupe -> resolution -> HTTP probing -> optional fuzzing/screenshotting) while persisting machine-readable JSONL data, human summaries, metadata, and raw artifacts.

## Features
- Queue-based job lifecycle with inline execution or background workers.
- Stage checkpoints with retry/backoff and resumable artifacts.
- Append-only `results.jsonl` plus scored `results.txt` summaries.
- Built-in enrichment and prioritisation: optional ASN/org lookups, heuristic tagging (env/service/internal), noise suppression, and priority scoring for URLs.
- Optional active intelligence modules (backup hunting, CORS checks, response diffing, JS secret harvesting) gated per job.
- Secrets/token detector (regex + entropy) with revocation guidance.
- Runtime JavaScript crawl via Playwright that captures DOM snapshots, network telemetry, and JavaScript asset inventories for high-priority URLs.
- Smart scanner triggers (nuclei, WPScan) based on detected surfaces and tech signals.
- Graph correlation across domains/IPs/ASNs/tech to highlight shared infrastructure and API surface.
- Learning mode that captures features and produces vulnerability probability hints.
- Configurable performance knobs via `RECON_*` environment variables and SecLists integration.
- Management commands for status, log tailing, requeueing, pruning, and exporting jobs.

## Roadmap
- Graph-based asset correlation (domains -> IPs -> ASNs -> tech stacks) with shared asset detection and JS/API linking.
- Integration with exploit/scanner APIs: trigger nuclei/WPScan/etc. based on detected surfaces, store findings with risk tags.
- Optional external intelligence feeds (crt.sh, urlscan.io, favfreak) to enrich the graph.

## Installation
1. Ensure Python 3.10+ is installed.
2. Install the package (editable is convenient during development):
   ```bash
   python -m pip install -e .
   ```
   You can alternatively install dependencies with `python -m pip install typer rich`.
3. Provide external binaries in your `PATH` as needed (subfinder, amass, massdns, httpx, ffuf, waybackurls/gau, playwright). Override paths with `RECON_HOME`, `SECLISTS_ROOT`, or other `RECON_*` variables if required.

## CLI commands
```text
recon-cli scan <target> [--profile passive|full|fuzz-only] [--inline] [--wordlist PATH] \
                 [--max-screenshots N] [--force] [--allow-ip] [--targets-file PATH] \
                 [--active-module MODULE] [--quickstart]
recon-cli worker-run [--poll-interval 5] [--max-workers 1]
recon-cli status <job_id>
recon-cli tail-logs <job_id>
recon-cli list-jobs [status]
recon-cli requeue <job_id>
recon-cli prune --days N [--archive]
recon-cli export <job_id> --format jsonl|txt|zip
recon-cli report <job_id> --format txt|md|json
recon-cli verify-job <job_id>
```

`scan --inline` runs the pipeline immediately and prints the finished results path. Without `--inline`, jobs land in `jobs/queued/` for a worker to process. `--targets-file` accepts one host per line; `--force` reruns stages even if checkpoints exist.

## Profiles
- `passive` (default): conservative, passive-only recon.
- `full`: enables fuzzing/runtime crawl/screenshots (respecting limits).
- `fuzz-only`: fuzzing-centric runs.
- `quick`: minimal passive scan with tight limits.
- `secure`: safe defaults with TLS verification enforced, active modules off, low concurrency/limits.
- `deep`: aggressive/full run with higher limits.
- `api-only`: focuses on API paths and related modules.

## Pipeline stages
1. `normalize_scope` - strict hostname validation, punycode normalization, and target manifest creation.
2. `passive_enumeration` - subfinder/amass/waybackurls (or gau) with JSONL hostname/URL emission.
3. `dedupe_canonicalize` - normalization/deduplication into `artifacts/dedupe_hosts.txt`.
4. `dns_resolve` - massdns (or system resolver fallback) producing `asset` objects.
5. `asset_enrichment` - ASN/org/country lookups, CDN/cloud heuristics, and hostname tagging with environment/service hints.
6. `http_probe` - httpx (or built-in HTTP client fallback) emitting URL metadata.
7. `scoring_tagging` - false-positive filtering, service tagging, and priority scoring.
8. `fuzzing` - ffuf + SecLists when enabled by profile or CLI flags.
9. `active_intelligence` - optional active modules (backup hunt, CORS, response diffing, JS secret extraction).
10. `secrets_detection` - regex + entropy analysis for tokens/credentials with revocation guidance.
11. `runtime_crawl` - Playwright runtime crawl that records DOM snapshots, network activity, and JavaScript assets for top-scoring URLs.
12. `correlation` - builds the internal asset graph (domains -> IPs -> ASNs -> tech) and detects reuse/api clusters.
13. `learning` - captures host features and predicts probability of follow-up vulnerabilities.
14. `scanner` - smart triggers for nuclei/WPScan based on detected surfaces and tech stack.
15. `screenshots` - Playwright screenshots and HAR capture (profile `full` or explicit limit).
16. `finalize` - summary generation, stats roll-up, and final metadata write.

Each stage logs to `jobs/<state>/<job_id>/logs/pipeline.log`, records checkpoints in `metadata.json`, and respects `RECON_RETRY_COUNT` (default 1).

The runtime crawl stage stores artifacts under `artifacts/runtime_crawl/`, including `runtime_crawl.json` with network/console data and deterministic `dom_<sha1>.html` snapshots for each crawled URL. It also appends `runtime_crawl` entries to `results.jsonl` summarising JavaScript discovery and errors.

## Job layout
```
jobs/
  queued/<job_id>/
  running/<job_id>/
  finished/<job_id>/
  failed/<job_id>/
```
Inside each job directory:
```
spec.json
metadata.json
results.jsonl
results.txt
artifacts/
logs/pipeline.log
```
Artifacts include raw outputs such as `subfinder.txt`, `amass.json`, `massdns.out`, `httpx_raw.json`, `ffuf_*.json`, `artifacts/active/`, `artifacts/runtime_crawl/`, and optional `artifacts/screenshots/` and `artifacts/hars/`.

## Configuration knobs
Tune behaviour via environment variables:
- `RECON_MAX_GLOBAL_CONCURRENCY`, `RECON_HTTPX_THREADS`, `RECON_MAX_FUZZ_HOSTS`, `RECON_FFUF_THREADS`, `RECON_MAX_SCREENSHOTS`, `RECON_RETRY_COUNT`, `RECON_TIMEOUT_HTTP`, `RECON_FALLBACK_DNS_LIMIT`.
- `IPINFO_TOKEN` for optional IP enrichment via ipinfo.io (leave unset to use local heuristics only).
- `RECON_SUMMARY_TOP` to control how many findings appear in `results.txt`.
- `RECON_ACTIVE_MODULES` comma-separated defaults for `--active-module`.
- `RECON_SCANNERS` comma-separated defaults for `--scanner`.
- `RECON_MAX_SCANNER_HOSTS` to cap the number of hosts scanned per job.
- `RECON_SCANNER_TIMEOUT` to control scanner command timeouts (seconds).
- `RECON_RUNTIME_CRAWL_MAX_URLS`, `RECON_RUNTIME_CRAWL_PER_HOST`, `RECON_RUNTIME_CRAWL_TIMEOUT`, `RECON_RUNTIME_CRAWL_CONCURRENCY` to tune the Playwright runtime crawl scope, per-host limits, and resource usage.
- `RECON_MAX_TARGETS_PER_JOB`, `RECON_MAX_PROBE_HOSTS`, `RECON_HTTPX_MAX_HOSTS` to cap workload size for targets/HTTP probing.
- `RECON_ENABLE_FUZZ`, `RECON_ENABLE_RUNTIME_CRAWL`, `RECON_ENABLE_SCREENSHOTS`, `RECON_ENABLE_SECRETS` to toggle heavy modules (fuzzing/crawl/screenshots default off, secrets on).
- `RECON_LOG_FORMAT` to choose `text` (default) or `json` structured logs.
- `RECON_PLUGIN_STAGES` to load extra pipeline stages as `module:Class` entries (comma-separated).
- `SECLISTS_ROOT` to override the SecLists base directory.
- RECON_TELEGRAM_TOKEN, RECON_TELEGRAM_CHAT_ID, RECON_TELEGRAM_TIMEOUT to push Telegram alerts when jobs finish or fail.
- `RECON_HOME` to relocate job storage.
- `RECON_CORRELATION_MAX_RECORDS` to cap how many results are processed in the correlation stage (default 10k); `RECON_CORRELATION_SVG_NODE_LIMIT` to skip SVG rendering when the graph exceeds this node count (default 2500).
- `RECON_RETRY_BACKOFF_BASE`, `RECON_RETRY_BACKOFF_FACTOR` to control retry delays between failed stage attempts.
- `RECON_METRICS` to emit per-job metrics JSON under `artifacts/metrics.json`.

## Notes
- Missing external binaries trigger warnings and the stage is skipped; the pipeline still completes so you can test locally without the full toolchain.
- Heavy modules (fuzzing, runtime crawl, screenshots) are disabled by default; enable via profiles or `RECON_ENABLE_*` flags.
- The initial target is always seeded into the host list so fallback resolution/probing will still run even when enumeration tools are absent.
- Requeued jobs retain completed checkpoints but reset attempts and rerun from the last stage, making recovery from transient failures predictable.
- `worker-run` currently processes jobs sequentially; run multiple workers for concurrency if required.
- Only scan targets you are authorized to assess.

## Performance defaults & hardware
- Default profiles are conservative: fuzzing/runtime crawl/screenshots are disabled unless explicitly enabled; caps exist for targets/job and probe/httpx hosts.
- Recommended minimum: 2 vCPUs, 4 GB RAM, 10 GB free disk; quick profile should finish a 1–5 target job in minutes on this footprint.
- Worker concurrency: `recon-cli worker-run --max-workers N` starts N worker loops; jobs are locked per worker to avoid double-processing.

