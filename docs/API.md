# ReconnV2 API Documentation | توثيق API

<div dir="rtl">

## 📋 نظرة عامة

ReconnV2 يوفر REST API كامل للتكامل مع أنظمة أخرى. الـ API يدعم:

- إدارة مهام الفحص
- استرجاع النتائج
- إنشاء التقارير
- إحصائيات النظام

**Base URL:** `http://localhost:8000/api`

</div>

---

## 🚀 Quick Start

### Start the API Server

```bash
# Using CLI
recon serve --port 8000

# Or directly
python -m recon_cli.api.app
```

### Test Connection

```bash
curl http://localhost:8000/api/status
```

---

## 📡 Endpoints

### Status & Health

#### GET /api/status

Check API health status.

**Response:**
```json
{
  "status": "ok",
  "version": "1.0.0",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

---

#### GET /api/stats

Get system statistics.

**Response:**
```json
{
  "total_jobs": 150,
  "running": 2,
  "finished": 140,
  "failed": 8,
  "queued": 0,
  "total_hosts": 5420,
  "total_urls": 12000,
  "total_vulnerabilities": 85
}
```

---

### Jobs Management

#### GET /api/jobs

List all jobs with optional filtering.

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `status` | string | Filter by status: `queued`, `running`, `finished`, `failed` |
| `limit` | int | Max results (default: 50) |
| `offset` | int | Pagination offset |

**Example:**
```bash
curl "http://localhost:8000/api/jobs?status=finished&limit=10"
```

**Response:**
```json
{
  "jobs": [
    {
      "id": "20240115_abc123",
      "target": "example.com",
      "status": "finished",
      "profile": "full",
      "created_at": "2024-01-15T10:00:00Z",
      "finished_at": "2024-01-15T10:45:00Z",
      "duration": 2700
    }
  ],
  "total": 140,
  "limit": 10,
  "offset": 0
}
```

---

#### GET /api/jobs/{job_id}

Get job details.

**Response:**
```json
{
  "id": "20240115_abc123",
  "target": "example.com",
  "status": "finished",
  "profile": "full",
  "created_at": "2024-01-15T10:00:00Z",
  "started_at": "2024-01-15T10:00:05Z",
  "finished_at": "2024-01-15T10:45:00Z",
  "duration": 2695,
  "stats": {
    "hosts": 45,
    "urls": 320,
    "vulnerabilities": 12,
    "secrets": 3
  },
  "stages_completed": [
    "subdomain_enum",
    "dns_resolve",
    "http_probe",
    "vuln_scan"
  ]
}
```

---

#### POST /api/scan

Start a new scan.

**Request Body:**
```json
{
  "target": "example.com",
  "profile": "full",
  "notify": true,
  "options": {
    "threads": 20,
    "timeout": 30
  }
}
```

**Response:**
```json
{
  "success": true,
  "job_id": "20240115_def456",
  "message": "Scan started successfully",
  "estimated_duration": 3600
}
```

**Example:**
```bash
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "profile": "bugbounty"}'
```

---

#### DELETE /api/jobs/{job_id}

Cancel a running job.

**Response:**
```json
{
  "success": true,
  "message": "Job cancelled"
}
```

---

### Results

#### GET /api/jobs/{job_id}/results

Get job results.

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `type` | string | Filter by type: `host`, `url`, `vulnerability`, `secret` |
| `limit` | int | Max results |

**Response:**
```json
{
  "job_id": "20240115_abc123",
  "results": [
    {
      "type": "host",
      "host": "api.example.com",
      "ip": "93.184.216.34",
      "status_code": 200,
      "source": "subfinder"
    },
    {
      "type": "vulnerability",
      "host": "example.com",
      "name": "SQL Injection",
      "severity": "high",
      "template_id": "sqli-error-based"
    }
  ],
  "total": 500
}
```

---

#### GET /api/jobs/{job_id}/hosts

Get discovered hosts.

**Response:**
```json
{
  "job_id": "20240115_abc123",
  "hosts": [
    {
      "host": "api.example.com",
      "ip": "93.184.216.34",
      "status_code": 200,
      "title": "API Server",
      "technologies": ["nginx", "python"],
      "source": "subfinder"
    }
  ],
  "total": 45
}
```

---

#### GET /api/jobs/{job_id}/vulnerabilities

Get discovered vulnerabilities.

**Response:**
```json
{
  "job_id": "20240115_abc123",
  "vulnerabilities": [
    {
      "name": "SQL Injection",
      "severity": "high",
      "host": "api.example.com",
      "url": "https://api.example.com/search?q=test",
      "template_id": "sqli-error-based",
      "description": "Error-based SQL injection detected",
      "remediation": "Use parameterized queries"
    }
  ],
  "summary": {
    "critical": 1,
    "high": 3,
    "medium": 5,
    "low": 2,
    "info": 1
  }
}
```

---

#### GET /api/jobs/{job_id}/secrets

Get discovered secrets.

**Response:**
```json
{
  "job_id": "20240115_abc123",
  "secrets": [
    {
      "type": "aws_access_key",
      "location": "https://example.com/config.js",
      "line": 45,
      "severity": "critical",
      "redacted_value": "AKIA***************"
    }
  ],
  "total": 3
}
```

---

### Reports

#### GET /api/jobs/{job_id}/report

Generate and download report.

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `format` | string | Report format: `html`, `json`, `pdf` |

**Example:**
```bash
# HTML Report
curl "http://localhost:8000/api/jobs/abc123/report?format=html" -o report.html

# PDF Report
curl "http://localhost:8000/api/jobs/abc123/report?format=pdf" -o report.pdf
```

---

### Database

#### GET /api/db/stats

Get database statistics.

**Response:**
```json
{
  "jobs": {
    "total": 150,
    "finished": 140,
    "running": 2,
    "failed": 8
  },
  "hosts": 5420,
  "urls": 12000,
  "vulnerabilities": {
    "critical": 5,
    "high": 20,
    "medium": 35,
    "low": 15,
    "info": 10
  },
  "secrets": 25,
  "database_size": "15.2 MB"
}
```

---

## 🔐 Authentication

Currently, the API does not require authentication. For production use, it's recommended to:

1. Run behind a reverse proxy (nginx)
2. Use API keys or JWT tokens
3. Enable HTTPS

### Example with API Key (future)

```bash
curl -H "X-API-Key: your_api_key" http://localhost:8000/api/stats
```

---

## ❌ Error Handling

### Error Response Format

```json
{
  "error": true,
  "code": "JOB_NOT_FOUND",
  "message": "Job with ID 'abc123' not found",
  "details": {}
}
```

### HTTP Status Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 201 | Created |
| 400 | Bad Request |
| 404 | Not Found |
| 422 | Validation Error |
| 500 | Internal Server Error |

### Common Errors

```json
// 404 - Job not found
{
  "error": true,
  "code": "JOB_NOT_FOUND",
  "message": "Job not found"
}

// 400 - Invalid profile
{
  "error": true,
  "code": "INVALID_PROFILE",
  "message": "Profile 'invalid' does not exist"
}

// 422 - Validation error
{
  "error": true,
  "code": "VALIDATION_ERROR",
  "message": "Target is required"
}
```

---

## 📊 Rate Limiting

Default limits:
- **100 requests/minute** per IP
- **10 concurrent scans** per user

Headers in response:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1705312800
```

---

## 🔄 Webhooks

### Configure Webhook

```bash
curl -X POST http://localhost:8000/api/webhooks \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://your-server.com/webhook",
    "events": ["scan.started", "scan.completed", "vulnerability.found"]
  }'
```

### Webhook Events

| Event | Description |
|-------|-------------|
| `scan.started` | Scan job started |
| `scan.completed` | Scan job finished |
| `scan.failed` | Scan job failed |
| `vulnerability.found` | New vulnerability discovered |
| `secret.found` | New secret discovered |

### Webhook Payload

```json
{
  "event": "vulnerability.found",
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {
    "job_id": "abc123",
    "vulnerability": {
      "name": "SQL Injection",
      "severity": "high",
      "host": "example.com"
    }
  }
}
```

---

## 💻 Code Examples

### Python

```python
import requests

BASE_URL = "http://localhost:8000/api"

# Start a scan
response = requests.post(f"{BASE_URL}/scan", json={
    "target": "example.com",
    "profile": "bugbounty"
})
job_id = response.json()["job_id"]

# Check status
status = requests.get(f"{BASE_URL}/jobs/{job_id}")
print(status.json())

# Get results
results = requests.get(f"{BASE_URL}/jobs/{job_id}/results")
for item in results.json()["results"]:
    print(item)
```

### JavaScript

```javascript
const API_URL = 'http://localhost:8000/api';

// Start scan
async function startScan(target, profile = 'full') {
  const response = await fetch(`${API_URL}/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target, profile })
  });
  return response.json();
}

// Get results
async function getResults(jobId) {
  const response = await fetch(`${API_URL}/jobs/${jobId}/results`);
  return response.json();
}

// Usage
const job = await startScan('example.com', 'bugbounty');
console.log(`Job started: ${job.job_id}`);
```

### cURL

```bash
# Start scan
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "profile": "full"}'

# Get stats
curl http://localhost:8000/api/stats

# Get job results
curl http://localhost:8000/api/jobs/abc123/results

# Download HTML report
curl http://localhost:8000/api/jobs/abc123/report?format=html -o report.html
```

---

## 🔗 OpenAPI/Swagger

The API provides OpenAPI documentation at:

```
http://localhost:8000/docs      # Swagger UI
http://localhost:8000/redoc     # ReDoc
http://localhost:8000/openapi.json  # OpenAPI JSON
```

---

## 📝 Changelog

### v1.0.0
- Initial API release
- Basic CRUD operations
- Report generation
- Webhook support

---

<div align="center">

Made with ❤️ for Security Researchers

</div>
