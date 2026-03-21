from __future__ import annotations

import heapq
import json
from collections import Counter, defaultdict
from typing import Dict, List
from urllib.parse import urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.pipeline.progress import ProgressLogger


class TrimResultsStage(Stage):
    name = "trim_results"

    def execute(self, context: PipelineContext) -> None:
        results_path = context.record.paths.results_jsonl
        trimmed_path = context.record.paths.trimmed_results_jsonl
        if not results_path.exists():
            if trimmed_path.exists():
                try:
                    trimmed_path.unlink()
                except OSError:
                    pass
            context.logger.info("No results available for trimming")
            return

        runtime = context.runtime_config
        url_limit = max(runtime.trim_url_max_per_host, 0)
        finding_limit = max(runtime.trim_finding_max_per_host, 0)
        finding_min_score = max(runtime.trim_finding_min_score, 0)
        tag_limit = max(runtime.trim_tag_per_host_limit, 0)
        progress = ProgressLogger(context.logger, interval=2.0)

        order = 0
        url_best: Dict[str, tuple[int, int, Dict[str, object], str]] = {}
        finding_buckets: Dict[str, List[tuple[int, int, Dict[str, object], str]]] = (
            defaultdict(list)
        )
        low_priority_handle = None
        other_entries: List[tuple[int, Dict[str, object]]] = []

        stats: Dict[str, int] = {
            "urls_total": 0,
            "urls_unique": 0,
            "urls_retained": 0,
            "urls_dropped": 0,
            "findings_total": 0,
            "findings_retained": 0,
            "findings_low_priority": 0,
            "findings_dropped_limit": 0,
        }

        for entry in context.iter_results():
            if not isinstance(entry, dict):
                continue
            order += 1
            progress.maybe(f"Trim progress: processed {order} entries")
            etype = entry.get("type")
            if etype == "url":
                stats["urls_total"] += 1
                cloned = self._clone_entry(entry)
                host = self._extract_host(cloned)
                if host and not cloned.get("hostname"):
                    cloned["hostname"] = host
                url_value = cloned.get("url")
                if not isinstance(url_value, str):
                    continue
                score = self._coerce_int(cloned.get("score", 0))
                existing = url_best.get(url_value)
                host_key = host or ""
                if existing:
                    prev_score, prev_order, _, _ = existing
                    if score > prev_score or (
                        score == prev_score and order < prev_order
                    ):
                        url_best[url_value] = (score, order, cloned, host_key)
                else:
                    url_best[url_value] = (score, order, cloned, host_key)
                continue
            if etype == "finding":
                stats["findings_total"] += 1
                score = self._coerce_int(entry.get("score", 0))
                if score < finding_min_score:
                    if low_priority_handle is None:
                        trim_dir = context.record.paths.ensure_subdir("trim")
                        low_priority_path = trim_dir / "low_priority_findings.jsonl"
                        low_priority_handle = low_priority_path.open(
                            "w", encoding="utf-8"
                        )
                    json.dump(
                        entry,
                        low_priority_handle,
                        separators=(",", ":"),
                        ensure_ascii=True,
                    )
                    low_priority_handle.write("\n")
                    stats["findings_low_priority"] += 1
                    continue
                cloned = self._clone_entry(entry)
                host = cloned.get("hostname") or ""  # type: ignore[assignment]
                bucket = finding_buckets[host]
                item = (score, order, cloned, host)
                if finding_limit > 0:
                    if len(bucket) < finding_limit:
                        heapq.heappush(bucket, item)
                    else:
                        worst = bucket[0]
                        if score > worst[0] or (score == worst[0] and order < worst[1]):
                            heapq.heapreplace(bucket, item)
                            stats["findings_dropped_limit"] += 1
                        else:
                            stats["findings_dropped_limit"] += 1
                else:
                    bucket.append(item)
                continue
            other_entries.append((order, self._clone_entry(entry)))

        per_host_urls: Dict[str, List[tuple[int, int, Dict[str, object]]]] = (
            defaultdict(list)
        )
        for score, order_idx, entry_data, host in url_best.values():
            bucket = host or "__unknown__"  # type: ignore[assignment]
            per_host_urls[bucket].append((score, order_idx, entry_data))  # type: ignore[index]

        selected_urls: List[tuple[int, Dict[str, object]]] = []
        urls_dropped = 0
        for entries in per_host_urls.values():
            entries.sort(key=lambda item: (-item[0], item[1]))
            limit = len(entries) if url_limit <= 0 else min(url_limit, len(entries))
            keep = entries[:limit]
            urls_dropped += len(entries) - len(keep)
            for _, order_idx, entry_data in keep:
                selected_urls.append((order_idx, entry_data))
        stats["urls_unique"] = len(url_best)
        stats["urls_retained"] = len(selected_urls)
        stats["urls_dropped"] = urls_dropped

        selected_findings: List[tuple[int, Dict[str, object]]] = []
        for bucket in finding_buckets.values():
            ordered = sorted(bucket, key=lambda item: (-item[0], item[1]))
            for _, order_idx, entry_data, _ in ordered:
                selected_findings.append((order_idx, entry_data))
        stats["findings_retained"] = len(selected_findings)

        final_entries = other_entries + selected_findings + selected_urls
        final_entries.sort(key=lambda item: item[0])

        tag_tracker: Dict[str, Counter] = defaultdict(Counter)
        for _, entry in final_entries:
            host = self._extract_host(entry)
            if host:
                self._apply_tag_limit(entry, host, tag_tracker, tag_limit)

        with trimmed_path.open("w", encoding="utf-8") as handle:
            for _, entry in final_entries:
                json.dump(entry, handle, separators=(",", ":"), ensure_ascii=True)
                handle.write("\n")

        trim_dir = context.record.paths.ensure_subdir("trim")
        low_priority_path = trim_dir / "low_priority_findings.jsonl"
        if low_priority_handle:
            low_priority_handle.close()
        elif low_priority_path.exists():
            low_priority_path.unlink()

        stats["entries_written"] = len(final_entries)
        context.record.metadata.stats["trim"] = stats
        context.manager.update_metadata(context.record)
        context.logger.info(
            "Trimmed results to %s entries (%s/%s URLs, %s/%s findings)",
            stats["entries_written"],
            stats["urls_retained"],
            stats["urls_total"],
            stats["findings_retained"],
            stats["findings_total"],
        )

    @staticmethod
    def _clone_entry(entry: Dict[str, object]) -> Dict[str, object]:
        cloned = dict(entry)
        tags = entry.get("tags")
        if isinstance(tags, list):
            cloned["tags"] = list(tags)
        return cloned

    @staticmethod
    def _extract_host(entry: Dict[str, object]) -> str:
        host = entry.get("hostname")
        if isinstance(host, str) and host:
            return host
        url_value = entry.get("url")
        if isinstance(url_value, str):
            try:
                parsed = urlparse(url_value)
            except ValueError:
                return ""
            return parsed.hostname or ""
        return ""

    @staticmethod
    def _apply_tag_limit(
        entry: Dict[str, object], host: str, tracker: Dict[str, Counter], limit: int
    ) -> None:
        if limit <= 0:
            return
        tags = entry.get("tags")
        if not isinstance(tags, list) or not host:
            return
        counter = tracker.setdefault(host, Counter())
        filtered: List[str] = []
        mutated = False
        for tag in tags:
            count = counter[tag]
            if count >= limit:
                mutated = True
                continue
            counter[tag] = count + 1
            filtered.append(tag)
        if filtered:
            if mutated:
                entry["tags"] = filtered
        else:
            entry.pop("tags", None)

    @staticmethod
    def _coerce_int(value: object) -> int:
        try:
            return int(value) if value is not None else 0  # type: ignore[call-overload]
        except (TypeError, ValueError):
            return 0
