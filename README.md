# ReconnV2

ReconnV2 is an autonomous, CLI-first web vulnerability discovery tool. It is designed to act like a junior analyst: it maps the target, holds multiple identities, formulates hypotheses, executes multi-step validation loops, and requires cryptographic or differential proof before declaring a bug.

It focuses heavily on logic flaws (IDOR, Auth Bypass, SSRF) rather than relying solely on static signature spraying.

## Core Architecture

ReconnV2 operates on a decentralized pipeline architecture driven by an autonomous engine.

### 1. The Autonomous Engine (`recon_cli/engine/`)
The system does not just run a list of payloads. It uses a separated planning and execution model:
*   **Planner:** Analyzes the `TargetGraph` (see below) to formulate `Hypothesis` objects (e.g., "User B can access User A's object at this endpoint").
*   **Executor:** Takes a `Hypothesis` and executes the necessary network requests, returning raw `Observation` data. It automatically handles identity rotation.
*   **Judge:** Evaluates the `Observations`. It requires strict differential proof (e.g., matching response hashes across security boundaries) or out-of-band (OAST) correlation to confirm a bug.

### 2. Target State Graph (`recon_cli/pipeline/context.py`)
Instead of a flat list of URLs, ReconnV2 builds a relational map of the target.
*   It tracks `hosts`, `api_endpoints`, `object_ids`, and `ssrf_sinks`.
*   The Planner uses this graph to understand relationships. If it finds an ID `1001` belonging to Alice, it will attempt to substitute that ID into endpoints requested by Bob.

### 3. Unified Auth & Identity (`recon_cli/utils/auth.py`)
Authentication is durable and per-job.
*   **Identities:** The system holds multiple `IdentityRecord` objects per scan (e.g., `admin`, `user`, `anonymous`).
*   **Replay:** The `AsyncHTTPClient` allows stages and the Executor to request resources as specific identities simply by passing `identity_id="bob"`.
*   **Boundary Testing:** The engine uses these identities to construct matrices of who can see what, automatically flagging cross-tenant leaks (IDOR) and unauthenticated data exposure.

## Key Workflows & Validators

*   **API Schema Reconstructor & Attacker:** Discovers or infers OpenAPI specs, extracts endpoints, and feeds the graph with structured attack surface data.
*   **IDOR Validator:** Harvests real object IDs using a legitimate identity, then attempts to access them using lower-privileged or alternate identities. Uses semantic diffing to prevent soft-404 false positives.
*   **SSRF Validator:** A sink classification engine. Identifies parameters, injects OAST and internal IPs (e.g., `169.254.169.254`), and correlates out-of-band DNS/HTTP interactions or differential internal responses.
*   **Auth Bypass Validator:** Tests forced browsing and privilege boundaries. Compares responses from unauthenticated users against authenticated users to find publicly exposed restricted data.

## Installation

```bash
# Requires Python 3.12+
git clone https://github.com/MubarakSec/reconnV2.git
cd reconnV2
./install.sh
source .venv/bin/activate
```

## Usage

### Basic Scan
Run the pipeline against a target.
```bash
recon scan https://target.com --profile full
```

### Providing Identities
To utilize the autonomous IDOR and Auth Bypass engines, provide at least two session tokens. The engine will automatically map these to identities.
```bash
# Provide tokens in config/profiles.json or via overrides
recon scan https://target.com --override '{"idor_token_a": "Bearer token1", "idor_token_b": "Bearer token2"}'
```

### Continuous Monitoring (Git-Ops)
Compare two jobs to find new attack surface.
```bash
recon diff job_id_yesterday job_id_today
```

### Viewing Results
View verified findings and their analyst-grade proofs.
```bash
recon report <job_id> --format html --verified-only
```
Or view the raw JSON line stream:
```bash
cat jobs/finished/<job_id>/results.jsonl | jq 'select(.type=="finding")'
```

## Output Format (Analyst-Grade Proof)

When the Judge confirms a bug, it outputs a standardized proof artifact in `results.jsonl`:

```json
{
  "finding_type": "idor",
  "severity": "high",
  "confidence_label": "verified",
  "proof": {
    "target": "https://api.example.com/users/1",
    "role_or_identity_used": ["token-b"],
    "exact_request_sequence": [
      {"method": "GET", "url": "https://api.example.com/users/1", "identity": "token-a"},
      {"method": "GET", "url": "https://api.example.com/users/1", "identity": "token-b"}
    ],
    "exact_differential_observation": {
      "baseline_status": 200,
      "test_status": 200,
      "baseline_length": 1500,
      "test_length": 1500
    },
    "replay_command": "reconn scan https://api.example.com/users/1 --identity token-b",
    "confidence_rationale": "Identical successful response received across different identity boundaries."
  }
}
```

## Internal Tools

*   `scripts/run_benchmarks.py`: Evaluates the engine against local docker instances (Juice Shop, DVWA).
*   `recon.sh`: An interactive wrapper around the CLI.
