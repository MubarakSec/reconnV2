# ReconnV2 Upgrade Roadmap

This document outlines the strategic upgrades required to transform the current ReconnV2 tool from a rigid, synchronous pipeline into a modern, high-performance, asynchronous reconnaissance engine.

## Phase 1: Performance & Deep Concurrency
**Goal**: Eliminate sequential bottlenecks inside individual pipeline stages and drastically reduce process spawning overhead.

- [x] **Audit Core Network Stages**: Identify all stages relying on sequential `for` loops.
- [x] **Integrate AsyncHTTPClient**: Replace synchronous `requests` with `AsyncHTTPClient`.
- [x] **Implement TaskGroups**: Rewrite internal stage loops to use `asyncio.gather`.
- [x] **Reduce Subprocess Overhead**: Native python implementations for lightweight tasks.

## Phase 2: Architecture & Data Flow
**Goal**: Move away from disk I/O bottlenecks and rigid execution graphs.

- [x] **In-Memory Event Bus**: Replace "Pass-by-File" architecture with an `asyncio.Queue`.
- [x] **Real-time Stage Triggers**: Enable inter-stage streaming via event bus subscription.
- [x] **Dynamic Dependency Resolution**: Refactor `DependencyResolver` for dynamic stage declarations.

## Phase 3: State Management & Intelligence
**Goal**: Prevent redundant work across scans and ensure data consistency.

- [x] **Global Command Caching**: Caching layer for `CommandExecutor` implemented.
- [x] **Strict Data Typing (Pydantic)**: Foundation implemented in `recon_cli/db/schemas.py`.
- [x] **Global Rate Limiting Service**: Unify stage-specific limiters into a single, global service.

## Phase 4: Integration & Cleanup
**Goal**: Wire up orphaned logic and finalize structural stability.

- [x] **Consolidate Error Handling**: Systematically replaced bare except blocks.
- [x] **Integrate Learning & Correlation**: Fully woven into core dependency graph.
- [x] **Remove Mixed Paradigms**: Deprecated thread-based orchestrator in favor of async runner.
- [x] **Unified Observability**: Fixed trace context propagation across async/thread boundaries.
- [x] **Scalable Results Engine**: Implemented streaming LRU buffering for results.
