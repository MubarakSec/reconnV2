# ReconnV2 Architecture

ReconnV2 is structured as a decentralized pipeline that transitions from **Passive Discovery** to **Autonomous Validation**.

## The Data Flow

The core data structure is the `PipelineContext`. It holds:
1. `record`: The current Job metadata and configuration overrides.
2. `target_graph`: The relational map of the target.
3. `_auth_manager`: The `UnifiedAuthManager` handling identities.
4. `results`: A stream of JSONL findings that are continuously flushed to disk.

Data flows through the pipeline in this order:
`Raw Targets` -> `Discovery Stages` -> `TargetGraph Population` -> `Autonomous Engine (Planner -> Executor -> Judge)` -> `Results`

## Core Components

### 1. UnifiedAuthManager (`recon_cli/utils/auth.py`)
Replaces the legacy, global `accounts.json` with a per-job identity engine.
* Stores `IdentityRecord` objects containing cookies, bearer tokens, or basic auth credentials.
* Exposes `get_auth_headers(identity_id)` which the `AsyncHTTPClient` uses automatically.

### 2. AsyncHTTPClient (`recon_cli/utils/async_http.py`)
A wrapper around `aiohttp` integrated tightly with the pipeline.
* Automatically applies Rate Limits (via the async `RateLimiter`).
* Automatically rotates identities based on the `identity_id` parameter.
* Handles auto-re-auth if a `401 Unauthorized` is hit.

### 3. TargetGraph (`recon_cli/pipeline/context.py`)
A thread-safe, in-memory graph representing the discovered attack surface.
* **Nodes:** `hosts`, `api_endpoints`, `object_ids`, `ssrf_sinks`.
* Replaces the flat `results.jsonl` file as the primary memory structure for complex validators.

### 4. The Autonomous Engine (`recon_cli/engine/`)
Instead of hardcoding logic loops into a single stage, Phase 4 introduced a separated engine:

#### Planner
Scans the `TargetGraph` to formulate `Hypothesis` objects.
* Example: If it finds `api_endpoint` `/users/{id}` and an `object_id` `1001`, it creates an IDOR `Hypothesis` for URL `/users/1001` requiring an authenticated identity.

#### Executor
Takes a `Hypothesis` and blindly executes the necessary HTTP requests across all available identities, returning raw `Observation` objects.

#### Judge
Takes the `Hypothesis` and the array of `Observations` and evaluates the evidence.
* Example: If the Observation from the baseline owner identity perfectly matches the Observation from a lower-privileged identity (checked via status code and body hashing), the Judge confirms the IDOR and generates an Analyst-Grade Proof.

## The Stages

The pipeline is composed of many `Stage` objects defined in `recon_cli/pipeline/stages.py`.
Each stage must implement:
* `is_enabled(context)`: Should this stage run based on the profile?
* `run_async(context)`: The main logic loop.

**Legacy vs Engine Stages:**
Older stages (like `PassiveEnumeration`) still push directly to `context.results`. Newer logic stages (like `ApiSchemaProbeStage`) push to `context.target_graph`, which is then consumed by the `DecisionEngineStage`.

## Error Handling & Integrity

*   **No Silent Failures:** If a stage throws an exception, the `PipelineRunner` catches it, records a partial failure in `context._any_stage_failed`, and ensures the Job ends with a `failed` status, moving the artifact folder to `jobs/failed/`.
*   **Thread-Safety:** All modifications to `context.record.metadata.stats` are protected by a lock via `context.update_stats()`.
*   **SQLite Fallback:** While `results.jsonl` is the primary record, high-level job metadata and final vulnerabilities are synced to an SQLite database for fast dashboard querying.
