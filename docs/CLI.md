# ReconnV2 CLI Reference | مرجع أوامر CLI

<div dir="rtl">

مرجع عملي للأوامر الحالية في `recon` / `recon-cli`.

> ملاحظة: هذا الملف يعكس الواجهة الحالية كما تظهر من `python -m recon_cli --help`.

</div>

---

## Getting Help

```bash
recon --help
recon scan --help
recon report --help
```

---

## Scan Commands

### `recon scan`

Launch a reconnaissance job.

```bash
recon scan [TARGET] [OPTIONS]
```

Key options:
- `--profile` (base: `passive`, `full`, `fuzz-only`; presets: `quick`, `secure`, `deep`, `api-only`, `ultra-deep`)
- `--inline`
- `--project`
- `--incremental-from`
- `--wordlist`
- `--max-screenshots`
- `--force`
- `--allow-ip`
- `--targets-file`
- `--split-targets`
- `--active-module` (`backup`, `cors`, `diff`, `js-secrets`)
- `--scanner` (`nuclei`, `wpscan`)
- `--insecure`
- `--quickstart`

Examples:

```bash
# Passive baseline
recon scan example.com --profile passive --inline

# Deep scan + nuclei
recon scan example.com --profile deep --scanner nuclei --inline

# Maximum depth preset
recon scan example.com --profile ultra-deep --inline

# Multiple targets
recon scan --targets-file targets.txt --profile full --split-targets
```

### `recon worker-run`

Run queue worker(s).

```bash
recon worker-run --poll-interval 5 --max-workers 1 --top-targets-first
```

---

## Job Management

### `recon list-jobs`

```bash
recon list-jobs [STATUS] [--project NAME]
```

`STATUS`: `queued` | `running` | `finished` | `failed`

### `recon status`

```bash
recon status JOB_ID
```

### `recon tail-logs`

```bash
recon tail-logs JOB_ID
```

### `recon rerun`

```bash
recon rerun JOB_ID [--restart] [--stages STAGE1,STAGE2] [--clean-results|--keep-results]
```

### `recon requeue`

```bash
recon requeue JOB_ID
```

### `recon cancel`

```bash
recon cancel JOB_ID [--requeue|--no-requeue] [--wait 30] [--hard]
```

### `recon verify-job`

```bash
recon verify-job JOB_ID
```

---

## Reports and Exports

### `recon report`

```bash
recon report [JOB_ID] [--format html|json|csv|markdown|xml|pdf] [--output PATH] \
  [--executive] [--title TEXT] [--verified-only] [--proof-required] [--hunter-mode]
```

### `recon export`

```bash
recon export JOB_ID [--format jsonl|triage|txt|zip] [--verified-only] [--proof-required] [--hunter-mode] [--limit N]
```

### `recon pdf`

```bash
recon pdf [JOB_ID] [--output PATH] [--title TEXT]
```

---

## Health and Cleanup

### `recon doctor`

```bash
recon doctor [--fix] [--fix-deps]
```

### `recon prune`

```bash
recon prune [--days N] [--archive]
```

---

## UI and API

### Web dashboard

```bash
recon web --host 127.0.0.1 --port 8080 --reload
# alias command:
recon dashboard --host 0.0.0.0 --port 8080
```

### REST API server

```bash
recon serve --host 0.0.0.0 --port 8080
```

---

## Utility Commands

```bash
recon wizard
recon interactive
recon quickstart
recon completions --shell bash --install
recon schema --format json
recon projects
recon plugins
recon run-plugin PLUGIN_NAME
```

---

## Profiles (Current)

- `passive`
- `full`
- `fuzz-only`
- `quick`
- `secure`
- `deep`
- `api-only`
- `ultra-deep`

---

## Notes

- `recon` and `recon-cli` point to the same CLI entrypoint.
- For the complete, exact option list, always prefer `--help` on each command.
