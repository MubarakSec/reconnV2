# recon-cli Usage Guide

End-to-end walkthrough for running the reconnaissance pipeline with every capability enabled.

## 1. Prerequisites

1. **Python**: 3.10 or newer.
2. **External tools on PATH**:
   - subfinder, amass, waybackurls or gau, massdns, httpx, ffuf.
   - Playwright browsers (Chromium): `playwright install chromium`.
   - Optional smart scanners: nuclei, wpscan.
3. **Environment secrets** (export before scanning):
   ```bash
   export WPSCAN_API_TOKEN="..."             # Unlock WPScan API checks
   export IPINFO_TOKEN="..."                 # Optional ASN/geo enrichment
   export RECON_HOME="$HOME/recon-jobs"      # Custom job storage root
   ```

## 2. Installation

```bash
python -m pip install -e .
playwright install chromium
```
The editable install keeps the CLI bound to this workspace.

## 3. Quick start

Inline full-profile scan with maximum modules:
```bash
recon-cli -vv scan example.com --profile full --inline \
  --active-module js-secrets --active-module backup \
  --scanner nuclei --scanner wpscan
```
Highlights:
- Pipeline runs immediately; artifacts land in `jobs/finished/<job_id>/`.
- Runtime JS crawl gathers DOM, network, and console telemetry for top URLs.
- Smart scanners fire; WPScan leverages `WPSCAN_API_TOKEN` when exported.

## 4. Pipeline at a glance

Stages execute in this order:
1. `normalize_scope`
2. `passive_enumeration`
3. `dedupe_canonicalize`
4. `dns_resolve`
5. `asset_enrichment`
6. `http_probe`
7. `scoring_tagging`
8. `fuzzing`
9. `active_intelligence`
10. `secrets_detection`
11. `runtime_crawl`
12. `correlation`
13. `learning`
14. `scanner`
15. `screenshots`
16. `finalize`

Every stage checkpoints progress, emits artifacts under `artifacts/`, and appends structured records to `results.jsonl`.

### Runtime crawl stage
- Uses Playwright to visit high-priority URLs with bounded concurrency (see `RECON_RUNTIME_CRAWL_*`).
- Saves combined telemetry to `artifacts/runtime_crawl/runtime_crawl.json` and deterministic DOM snapshots (`dom_<sha1>.html`).
- Appends `runtime_crawl` items to `results.jsonl` detailing success state, JS inventory, console output, and errors.

### Smart scanners
- Opt-in via repeated `--scanner` flags (`nuclei`, `wpscan`).
- Nuclei currently runs with `-tags api`; tweak command flags by editing `recon_cli/scanners/integrations.py` or forking the helper.
- WPScan automatically consumes `WPSCAN_API_TOKEN` when present to unlock vulnerability enrichment.

### Active intelligence modules
Repeat `--active-module` or set `RECON_ACTIVE_MODULES`. Available modules (e.g. `backup`, `cors`, `diff`, `js-secrets`) come from `recon_cli.active.modules.available_modules()`.

## 5. Managing jobs

Queue and process asynchronously:
```bash
recon-cli scan --targets-file scope.txt --profile full --scanner nuclei
recon-cli worker-run --poll-interval 10
```
Monitor and troubleshoot:
```bash
recon-cli list-jobs running
recon-cli status <job_id>
recon-cli tail-logs <job_id>
```
Recovery and cleanup:
```bash
recon-cli requeue <job_id>
recon-cli prune --days 30 --archive
```
Export results:
```bash
recon-cli export <job_id> --format jsonl > results.jsonl
recon-cli export <job_id> --format txt
recon-cli export <job_id> --format zip
```

## 6. Artifact layout

```
jobs/<state>/<job_id>/
  spec.json
  metadata.json
  results.jsonl
  results.txt
  artifacts/
    passive_hosts.txt
    dedupe_hosts.txt
    massdns.out
    httpx_raw.json
    fuzz/
    active/
    runtime_crawl/
      runtime_crawl.json
      dom_<sha1>.html
    scanners/
      nuclei_<host>.json
      wpscan_<host>.json
    screenshots/
    hars/
  logs/pipeline.log
```

## 7. High-value environment variables

| Variable | Purpose |
| --- | --- |
| `RECON_HOME` | Root directory for jobs, logs, and artifacts. |
| `RECON_HTTPX_THREADS`, `RECON_TIMEOUT_HTTP` | HTTP probe concurrency and timeout. |
| `RECON_MAX_GLOBAL_CONCURRENCY` | Ceiling for overall stage concurrency. |
| `RECON_MAX_FUZZ_HOSTS`, `RECON_FFUF_THREADS` | Fuzzing scope controls. |
| `RECON_MAX_SCANNER_HOSTS`, `RECON_SCANNER_TIMEOUT` | Smart scanner target cap and runtime. |
| `RECON_RUNTIME_CRAWL_MAX_URLS`, `RECON_RUNTIME_CRAWL_PER_HOST`, `RECON_RUNTIME_CRAWL_TIMEOUT`, `RECON_RUNTIME_CRAWL_CONCURRENCY` | Runtime crawl breadth, per-host cap, timeout, and concurrency. |
| `RECON_SECRETS_MAX_FILES`, `RECON_SECRETS_TIMEOUT` | Secrets detector fetch limits. |
| `RECON_ACTIVE_MODULES`, `RECON_SCANNERS` | Default modules and scanners applied to `scan`. |
| `RECON_SUMMARY_TOP` | How many findings surface in `results.txt`. |
| `IPINFO_TOKEN` | Enables ASN/geolocation enrichment. |
| `WPSCAN_API_TOKEN` | Unlocks WPScan vulnerability intelligence. |

## 8. Usage patterns

### Full-power authorised assessment
```bash
export RECON_HOME="$PWD/jobs"
export WPSCAN_API_TOKEN="..."
recon-cli scan target.tld --profile full --inline \
  --active-module backup --active-module js-secrets \
  --scanner nuclei --scanner wpscan
```
- Passive, active, and runtime stages light up the full surface.
- Nuclei runs with API-focused templates; WPScan uses your API token when set.
- Artifacts and findings are ready for downstream processing.

### Continuous monitoring loop
1. Queue nightly scope refresh:
   ```bash
   recon-cli scan scope.tld --profile passive
   ```
2. Schedule a worker (cron/systemd):
   ```bash
   recon-cli worker-run --poll-interval 60
   ```
3. Export `results.jsonl` on completion for SIEM or data-lake ingestion.

## 9. Troubleshooting tips

- Missing tool or binary: pipeline log records a warning; stage is skipped without failing the job.
- Re-run everything: add `--force` to `scan` to ignore existing checkpoints.
- Validate install: `python -m compileall recon_cli` catches syntax/import issues.
- Watch progress live: combine `-vv` with `recon-cli tail-logs <job_id>`.

## 10. Next steps

- Extend `recon_cli/scanners/integrations.py` to onboard more scanners or custom scripts.
- Loop runtime crawl discoveries into bespoke modules or external alerting.
- Build dashboards on top of `results.jsonl` to visualise exposure trends over time.

export RECON_TELEGRAM_TOKEN=8174728253:AAH7M-4CjOT70Al8CNteSid7R-jMOmXDybg
export RECON_TELEGRAM_CHAT_ID=-4850083830
(Optional) export RECON_TELEGRAM_TIMEOUT=5

Happy hunting!
