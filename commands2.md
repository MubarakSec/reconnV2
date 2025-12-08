# recon-cli Command Recipes (v2)

Curated snippets that complement `command.md` with heavier-duty workflows, trim tuning, and post-processing helpers.

## 1. Kick off scans with runtime overrides
```bash
# Trim aggressively (top 150 URLs/host, findings >=30) for a huge scope
RECON_TRIM_URL_MAX_PER_HOST=150 \
RECON_TRIM_FINDING_MIN_SCORE=30 \
recon-cli scan mega.example --profile full --inline

# Allow more findings/tags when chasing in-depth leads
RECON_TRIM_FINDING_MAX_PER_HOST=250 \
RECON_TRIM_TAG_PER_HOST=120 \
recon-cli scan api.example --profile deep --active-module js-secrets

# API-only profile with forced crawl concurrency
RECON_RUNTIME_CRAWL_CONCURRENCY=6 \
recon-cli -v scan api.example --profile api-only --inline
```

## 2. Queue, monitor, and resume jobs
```bash
# Queue passive job for a targets file
recon-cli scan --targets-file scope.txt --profile passive

# Worker consuming queued jobs with tighter polling
recon-cli worker-run --poll-interval 3 --max-workers 2

# Inspect checkpoints / trim stats mid-run
recon-cli status <job_id>
recon-cli tail-logs <job_id>
recon-cli export <job_id> --format jsonl | head
```

## 3. Correlation-friendly trimming workflow
```bash
# After a job finishes, review the trimmed dataset
JOB_ROOT=$(recon-cli status <job_id> --format json | jq -r '.paths.root')
cat "$JOB_ROOT/results_trimmed.jsonl" | jq '.' | head

# Inspect findings suppressed for being low priority
cat "$JOB_ROOT/artifacts/trim/low_priority_findings.jsonl" | jq '.' | head

# Re-run correlation only, using existing trim results
recon-cli rerun-stage <job_id> trim_results
recon-cli rerun-stage <job_id> correlation
```

## 4. Artifact hygiene and export
```bash
# Copy only trimmed results + correlation report into a bundle
JOB_ROOT=$(recon-cli status <job_id> --format json | jq -r '.paths.root')
mkdir -p /tmp/reports/$JOB_ROOT
cp "$JOB_ROOT/results_trimmed.jsonl" /tmp/reports/$JOB_ROOT/
cp "$JOB_ROOT/artifacts/correlation/correlation_report.json" /tmp/reports/$JOB_ROOT/
cp "$JOB_ROOT/artifacts/correlation/graph.svg" /tmp/reports/$JOB_ROOT/

# Ship a summarized zip (results.txt + trimmed + graph)
cd "$JOB_ROOT" && zip -r summary.zip results.txt results_trimmed.jsonl artifacts/correlation/graph.svg
```

## 5. Troubleshooting & cleanup
```bash
# Requeue a failed job after tweaking env vars
RECON_HTTPX_THREADS=30 RECON_MAX_GLOBAL_CONCURRENCY=40 recon-cli requeue <job_id>

# Remove stale finished jobs older than 10 days but keep archives
recon-cli prune --days 10 --archive

# Force-delete everything older than a month (irreversible)
recon-cli prune --days 30 --force
```

## 6. Handy environment knobs recap
- `RECON_TRIM_URL_MAX_PER_HOST`, `RECON_TRIM_FINDING_MAX_PER_HOST`, `RECON_TRIM_FINDING_MIN_SCORE`, `RECON_TRIM_TAG_PER_HOST`
- `RECON_HTTPX_THREADS`, `RECON_TIMEOUT_HTTP`, `RECON_MAX_GLOBAL_CONCURRENCY`
- `RECON_RUNTIME_CRAWL_MAX_URLS`, `RECON_RUNTIME_CRAWL_PER_HOST`, `RECON_RUNTIME_CRAWL_CONCURRENCY`
- `RECON_SECRETS_MAX_FILES`, `RECON_SECRETS_TIMEOUT`
- `RECON_SCANNER_TIMEOUT`, `RECON_MAX_SCANNER_HOSTS`

Adjust these per job via `VAR=value recon-cli ...` or persist them in profile overrides (`config/profiles.json`).


RECON_TRIM_URL_MAX_PER_HOST=150 \
RECON_TRIM_FINDING_MIN_SCORE=70 \
RECON_RUNTIME_CRAWL_CONCURRENCY=4 \
RECON_SECRETS_MAX_FILES=60 \
recon-cli scan example.com \
  --profile deep \
  --inline \
  --wordlist /opt/recon-tools/seclists/Discovery/Web-Content/common.txt \
  --allow-ip \
  --force \
  --active-module js-secrets \
  --active-module backup \
  --scanner nuclei \
  --scanner wpscan
