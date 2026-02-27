# ReconnV2 API Documentation | توثيق API

<div dir="rtl">

توثيق REST API الحالي كما يُعرّفه `recon_cli/api/app.py`.

</div>

---

## Quick Start

```bash
# Start API server (default port from CLI help: 8080)
recon serve --host 0.0.0.0 --port 8080

# Health check
curl http://localhost:8080/api/status
```

Base URL:
- `http://localhost:8080`

Swagger/OpenAPI:
- `/docs`
- `/redoc`
- `/openapi.json`

---

## Authentication

- Some endpoints accept optional `X-API-Key`.
- `DELETE /api/jobs/{job_id}` requires valid `X-API-Key`.
- If API key is missing/invalid on protected endpoints, response is `401`.

Example:

```bash
curl -H "X-API-Key: <your_api_key>" http://localhost:8080/api/jobs
```

---

## Endpoints

### System

### `GET /api/status`
Returns API status, version, uptime.

### `GET /api/health`
Returns health summary and component checks.

### `GET /api/version`
Returns version/build metadata.

### `GET /api/stats`
Returns queued/running/finished/failed counters.

### `GET /api/metrics`
Returns Prometheus text metrics.

---

### Jobs

### `GET /api/jobs`
List jobs.

Query params:
- `status` (optional)
- `limit` (default `50`, max `500`)
- `offset` (default `0`)
- `page` (optional, 1-based)

Example:

```bash
curl "http://localhost:8080/api/jobs?status=finished&limit=20"
```

### `GET /api/jobs/{job_id}`
Get single job metadata.

### `GET /api/jobs/{job_id}/results`
Get job results.

Query params:
- `limit` (default `100`, max `1000`)
- `result_type` (optional)

### `GET /api/jobs/{job_id}/summary`
Get computed job summary.

### `GET /api/jobs/{job_id}/logs`
Download/read pipeline logs (`text/plain`).

### `POST /api/jobs/{job_id}/requeue`
Move job back to queued state.

### `DELETE /api/jobs/{job_id}`
Delete job (requires API key).

---

### Scan Creation

### `POST /api/scan`
Create scan job (optionally inline).

Request body:

```json
{
  "target": "example.com",
  "profile": "ultra-deep",
  "inline": false,
  "scanners": ["nuclei"],
  "active_modules": ["js-secrets"],
  "force": false,
  "allow_ip": false
}
```

Profile notes:
- Accepts base profiles and configured presets (e.g. `passive`, `full`, `fuzz-only`, `deep`, `api-only`, `quick`, `secure`, `ultra-deep`).

Example:

```bash
curl -X POST http://localhost:8080/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "profile": "ultra-deep",
    "inline": false,
    "scanners": ["nuclei"],
    "active_modules": ["js-secrets"]
  }'
```

### `POST /api/jobs`
Create generic queued job from target list/stage list/options.

Request body:

```json
{
  "targets": ["example.com", "api.example.com"],
  "stages": ["normalize_scope", "http_probe", "verify_findings"],
  "options": {
    "allow_ip": false
  }
}
```

---

### Reports

### `GET /api/jobs/{job_id}/report`
Download HTML report for job.

Example:

```bash
curl "http://localhost:8080/api/jobs/<job_id>/report" -o report.html
```

---

## Typical Workflow

```bash
# 1) Create scan
JOB_ID=$(curl -s -X POST http://localhost:8080/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"example.com","profile":"deep"}' | jq -r .job_id)

# 2) Check job
curl "http://localhost:8080/api/jobs/${JOB_ID}"

# 3) Fetch results
curl "http://localhost:8080/api/jobs/${JOB_ID}/results?limit=200"

# 4) Fetch summary
curl "http://localhost:8080/api/jobs/${JOB_ID}/summary"
```

---

## Common Errors

- `400`: invalid input (profile/target/options/stage format)
- `401`: missing or invalid API key on protected endpoint
- `404`: job not found
- `413`: options payload too large
- `500`: internal server error

---

## Keep Docs in Sync

When CLI/API evolves, regenerate behavior truth from:
- `python -m recon_cli serve --help`
- `python -m recon_cli web --help`
- `recon_cli/api/app.py`
