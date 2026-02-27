# ReconnV2 Quality Gate Fix Plan

This checklist replaces the old plan and is based on current code checks only.

Baseline captured on 2026-02-27:
- `pytest tests -v`: `471 passed`
- `ruff check recon_cli`: `131 errors` (`94` auto-fixable)
- `mypy recon_cli --ignore-missing-imports`: `1128 errors in 103 files`

## 1) Critical (must fix first)

- [ ] Resolve broken/duplicated tracing implementation in `recon_cli/utils/tracing.py`.
- [ ] Remove duplicate definitions: `Span` (`:78` and `:766`), `Trace` (`:183` and `:850`), `get_tracer` (`:714` and `:1025`).
- [ ] Move late import to module top (`recon_cli/utils/tracing.py:738`) to clear `E402`.
- [ ] Decide one canonical tracing API surface and delete the shadow copy.

- [ ] Fix import-order/runtime hygiene in `recon_cli/tools/executor.py`.
- [ ] Remove `E402` sequence at `:19-:28` by keeping imports at top only.

- [ ] Fix undefined-name and import-shadow issues in `recon_cli/utils/diff.py`.
- [ ] Resolve `timedelta` undefined use (`:571`) and duplicate/late import (`:573`).
- [ ] Rename loop variable shadowing imported symbol (`:182`, `F402`).

- [ ] Fix undefined `requests` references in `recon_cli/pipeline/stage_idor_validator.py`.
- [ ] Address `F821` for session annotations at `:279` and `:336`.
- [ ] Use `TYPE_CHECKING` import or real import and consistent annotation style.

- [ ] Fix API bootstrap type violations in `recon_cli/api/app.py`.
- [ ] Remove illegal type/method assignments reported at `:22`, `:23`, `:111`.

- [ ] Fix CLI type contract issues in `recon_cli/cli.py`.
- [ ] Replace invalid `BadParameter(..., param_name=...)` call (`:126`).
- [ ] Fix `JobRecord.path` vs `JobRecord.paths` mismatch (`:1260`).
- [ ] Fix report config type mixing (`:1540`, `:1543`).

## 2) High (stability and correctness)

- [ ] Eliminate high-volume nullability errors in pipeline core.
- [ ] `recon_cli/pipeline/runner.py`: fix `union-attr`/`arg-type` cluster (`:41`, `:61`, `:131`, `:220`, `:347`, etc.).
- [ ] `recon_cli/pipeline/stage_runtime_crawl.py`: enforce non-null `JobRecord`/`JobManager` before use (`:26`, `:58`, `:149`, `:264`, `:292`, etc.).
- [ ] Introduce guard helpers (for example `_require_record`, `_require_manager`) instead of repeated unchecked access.

- [ ] Fix parallel runner typing in `recon_cli/pipeline/parallel.py`.
- [ ] Resolve missing model attributes at `:23`.
- [ ] Correct executor callable signature issue at `:244`.
- [ ] Correct result assignment type at `:301`.

- [ ] Fix top mypy error classes by count:
- [ ] `union-attr` (438)
- [ ] `arg-type` (239)
- [ ] `attr-defined` (120)
- [ ] `call-overload` (101)
- [ ] `assignment` (66)

- [ ] Fix remaining non-trivial ruff issues by type:
- [ ] `F821` undefined names
- [ ] `F811` redefinition
- [ ] `E402` imports not at top
- [ ] `F402` import shadowing

## 3) Medium (cleanup and maintainability)

- [ ] Apply safe auto-fixes first: `ruff check recon_cli --fix`.
- [ ] Re-run and manually address unresolved lint categories.

- [ ] Clean unused imports/variables and f-strings without placeholders across high-churn files:
- [ ] `recon_cli/secrets/detector.py` (11 lint hits)
- [ ] `recon_cli/utils/pdf_reporter.py` (10)
- [ ] `recon_cli/tools/executor.py` (9)
- [ ] `recon_cli/utils/config_migrate.py` (6)
- [ ] `recon_cli/cli.py` (6)
- [ ] `recon_cli/utils/tracing.py` (5)
- [ ] `recon_cli/utils/diff.py` (5)

- [ ] Add type stubs/dependency typing policy:
- [ ] Install and pin `types-requests`.
- [ ] Install and pin `types-PyYAML`.
- [ ] Decide whether to keep `--ignore-missing-imports` or move to per-module overrides.

- [ ] Fix implicit optional defaults flagged by mypy:
- [ ] `recon_cli/exceptions.py` (`completed_stages`, `searched_paths`)
- [ ] `recon_cli/plugins/__init__.py` (`options` defaults)

## 4) Execution order

- [ ] Phase A: remove redefinitions/undefined names/import-order issues (`tracing`, `diff`, `stage_idor_validator`, `executor`).
- [ ] Phase B: harden pipeline nullability (`runner`, `stage_runtime_crawl`, `parallel`).
- [ ] Phase C: normalize CLI/API typing (`cli`, `api/app.py`, report config types).
- [ ] Phase D: run `ruff --fix`, then manual lint cleanup, then mypy pass.

## 5) Verification gates (must all pass)

- [ ] `.venv/bin/python -m pytest tests -v`
- [ ] `.venv/bin/ruff check recon_cli`
- [ ] `.venv/bin/mypy recon_cli --ignore-missing-imports`

## 6) Done criteria

- [ ] Ruff errors = 0.
- [ ] Mypy errors = 0 (or documented, approved baseline file with explicit exclusions).
- [ ] No duplicate core runtime implementations (`tracing` single source of truth).
- [ ] Pipeline core modules (`runner`, `parallel`, `stage_runtime_crawl`) are null-safe and typed.
- [ ] CI uses the same three gates and blocks merges on failure.
