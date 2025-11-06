# recon-cli Command Cheatsheet

Common CLI invocations for day-to-day recon job management.

## Global flags
- `-v`, `-vv`, `-vvv` - increase log verbosity (more `-v` = more detail).
- `--profile` - select pipeline profile (`passive`, `full`, `fuzz-only`).
- `--inline` - run the job immediately instead of queueing.
- `--targets-file` - file containing one target per line.
- `--force` - rerun stages even if checkpoints/artifacts already exist.
- `--allow-ip` - allow IP addresses as targets (default requires hostnames).
- `--active-module` - enable active intelligence modules (repeatable: backup, cors, diff, js-secrets).
- `--scanner` - trigger smart scanners such as nuclei/WPScan (repeatable).

## Core commands

### Launch scans
```bash
recon-cli -v scan example.com --profile passive --inline
recon-cli scan example.com --profile full --wordlist /opt/recon-tools/seclists/Discovery/Web-Content/common.txt
recon-cli scan --targets-file /path/to/hosts.txt --profile passive
recon-cli scan example.com --profile full --scanner nuclei --scanner wpscan --active-module js-secrets
```

### Worker lifecycle
```bash
recon-cli worker-run --poll-interval 5 --max-workers 1
```
Run in background (e.g. systemd) to process queued jobs.

### Job insight
```bash
recon-cli list-jobs
recon-cli list-jobs queued
recon-cli status <job_id>
recon-cli tail-logs <job_id>
```

### Recovery & cleanup
```bash
recon-cli requeue <job_id>
recon-cli prune --days 7            # delete finished jobs older than 7 days
recon-cli prune --days 30 --archive # archive instead of delete
```

### Export artifacts
```bash
recon-cli export <job_id> --format jsonl > results.jsonl
recon-cli export <job_id> --format txt
recon-cli export <job_id> --format zip
```

## Environment knobs (set via `export ...` or profile)
- `RECON_HOME` - override job storage root.
- `RECON_HTTPX_THREADS` - limit HTTP probe concurrency.
- `RECON_FALLBACK_DNS_LIMIT` - cap the slow DNS fallback host count.
- `RECON_MAX_GLOBAL_CONCURRENCY`, `RECON_MAX_FUZZ_HOSTS`, etc. - see `README.md` for the full table.
- `IPINFO_TOKEN` - enable ASN/geo enrichment through ipinfo.io.
- `RECON_SUMMARY_TOP` - change how many findings appear in `results.txt`.
- `RECON_ACTIVE_MODULES` - comma separated defaults for `--active-module`.
- `RECON_SCANNERS` - comma separated defaults for `--scanner`.
- `RECON_MAX_SCANNER_HOSTS` - limit how many hosts smart scanners hit per job.
- `RECON_SCANNER_TIMEOUT` - per-scanner execution timeout (seconds).
- `RECON_RUNTIME_CRAWL_MAX_URLS`, `RECON_RUNTIME_CRAWL_PER_HOST`, `RECON_RUNTIME_CRAWL_TIMEOUT`, `RECON_RUNTIME_CRAWL_CONCURRENCY` - control how many URLs the runtime crawl inspects, per-host caps, timeouts, and concurrency.
- `RECON_SECRETS_MAX_FILES` - cap how many files the secrets detector downloads per job.
- `RECON_SECRETS_TIMEOUT` - request timeout for secrets detector downloads (seconds).

## Helpful combos
- Quick passive inline scan with debug logs:
  ```bash
  recon-cli -vv scan example.com --profile passive --inline
  ```
- Queue a full profile job, then have worker consume it:
  ```bash
  recon-cli scan example.com --profile full
  recon-cli worker-run --poll-interval 10
  ```
- Restart a stuck job after tuning environment vars:
  ```bash
  export RECON_HTTPX_THREADS=10
  recon-cli requeue <job_id>
  recon-cli tail-logs <job_id>
  ```

* Active modules require caution; only enable when authorised.
