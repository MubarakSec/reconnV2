# ReconnV2 Upgrade Roadmap

This document outlines the strategic upgrades required to transform the current ReconnV2 tool from a rigid, synchronous pipeline into a modern, high-performance, asynchronous reconnaissance engine.

## Phase 1: Performance & Deep Concurrency
**Goal**: Eliminate sequential bottlenecks inside individual pipeline stages and drastically reduce process spawning overhead.

- [x] **Audit Core Network Stages**: Identify all stages relying on sequential `for` loops (e.g., `stage_http_probe.py`, `stage_upload_probe.py`, `stage_api_recon.py`).
- [x] **Integrate AsyncHTTPClient**: Replace synchronous `requests` and `http.client` fallbacks with the existing `AsyncHTTPClient` (via `aiohttp`).
- [x] **Implement TaskGroups**: Rewrite internal stage loops to use `asyncio.gather` or `asyncio.TaskGroup` to process targets concurrently.
- [x] **Reduce Subprocess Overhead**: Native python implementations for lightweight tasks instead of shelling out to basic commands (like single-shot `curl` or `dig` equivalents) where an async python library exists (e.g., `aiodns`).

## Phase 2: Architecture & Data Flow
**Goal**: Move away from disk I/O bottlenecks and rigid execution graphs.

- [ ] **In-Memory Event Bus**: Replace the "Pass-by-File" (`results.jsonl`) architecture with an `asyncio.Queue` or lightweight local broker (e.g., Redis/SQLite pub-sub).
- [ ] **Real-time Stage Triggers**: Enable stages like `crawler` or `vuln_scan` to subscribe to the event bus and trigger immediately when an upstream stage publishes a finding, rather than waiting for the entire upstream stage to finish.
- [ ] **Dynamic Dependency Resolution**: Refactor `DependencyResolver.STAGE_DEPENDENCIES`. Stages should dynamically declare `requires = [...]` and `provides = [...]` so the DAG can optimize itself based on available tools and user profiles.

## Phase 3: State Management & Intelligence
**Goal**: Prevent redundant work across scans and ensure data consistency.

- [x] **Global Command Caching**: Implement a caching layer for `CommandExecutor` that hashes target + command arguments. If fingerprints haven't changed since the last run, skip expensive operations (like full `nuclei` or `nmap` scans).
- [ ] **Strict Data Typing (Pydantic)**: Eradicate bare `Dict[str, Any]` usage for findings and signals. Define strict Pydantic schemas for all data models flowing through the pipeline to prevent runtime parsing bugs.
- [ ] **Global Rate Limiting Service**: Unify the scattered, stage-specific rate limiters into a single, global service aware of target IPs to prevent accidental self-DoS across concurrent stages.

## Phase 4: Integration & Cleanup
**Goal**: Wire up orphaned logic and finalize structural stability.

- [x] **Consolidate Error Handling**: Systematically replace all remaining bare `except Exception:` blocks with specific exception catching to prevent masking critical network/system errors.
- [x] **Integrate Learning & Correlation**: Fully weave the `correlation` and `learning` modules into the core dependency graph so their heuristic models train consistently across all deep scans.
- [x] **Remove Mixed Paradigms**: Deprecate the thread-based `_run_parallel_threaded` orchestrator entirely in favor of a purely asynchronous `_run_parallel` engine.