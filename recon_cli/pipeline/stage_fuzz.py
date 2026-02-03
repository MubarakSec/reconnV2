from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Set
from urllib.parse import urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage, note_missing_tool
from recon_cli.tools.executor import CommandError
from recon_cli.utils.jsonl import read_jsonl


class FuzzStage(Stage):
    name = "fuzzing"

    def is_enabled(self, context: PipelineContext) -> bool:
        spec = context.record.spec
        if not context.runtime_config.enable_fuzz and not spec.wordlist:
            return False
        return spec.profile in {"full", "fuzz-only"} or bool(spec.wordlist)

    def execute(self, context: PipelineContext) -> None:
        executor = context.executor
        runtime = context.runtime_config
        tool_timeout = runtime.tool_timeout
        per_host_limit = max(runtime.trim_url_max_per_host, 0)
        per_host_counts: Dict[str, int] = defaultdict(int)
        stage_seen: Set[str] = set()
        if not executor.available("ffuf"):
            context.logger.warning("ffuf not available; skipping fuzzing stage")
            note_missing_tool(context, "ffuf")
            return
        spec = context.record.spec
        wordlist_override = Path(spec.wordlist) if spec.wordlist else None
        if wordlist_override and not wordlist_override.exists():
            context.logger.warning("Wordlist not found: %s", wordlist_override)
            return
        targets = self._select_hosts_for_fuzz(context)
        if not targets:
            context.logger.info("No hosts qualified for fuzzing")
            return
        host_tags = self._tags_for_hosts(context)
        for host in targets[: context.runtime_config.max_fuzz_hosts]:
            wordlist_path = wordlist_override or self._select_wordlist_for_host(
                runtime, host, host_tags.get(host, set())
            )
            if not wordlist_path.exists():
                context.logger.warning("Wordlist not found: %s", wordlist_path)
                continue
            artifact = context.record.paths.artifact(f"ffuf_{host}.json")
            cmd = [
                "ffuf",
                "-w",
                str(wordlist_path),
                "-u",
                f"https://{host}/FUZZ",
                "-t",
                str(context.runtime_config.ffuf_threads),
                "-mc",
                "200,301,302,401,403",
                "-ac",
                "-of",
                "json",
                "-o",
                str(artifact),
            ]
            try:
                ffuf_maxtime = max(0, int(getattr(runtime, "ffuf_maxtime", 0)))
                if ffuf_maxtime:
                    cmd.extend(["-maxtime", str(ffuf_maxtime)])
                timeout = tool_timeout
                if ffuf_maxtime:
                    timeout = ffuf_maxtime + max(0, int(getattr(runtime, "ffuf_timeout_buffer", 30)))
                executor.run(cmd, check=False, timeout=timeout)
            except CommandError as exc:
                retried = False
                if getattr(runtime, "ffuf_retry_on_timeout", True) and "timeout" in str(exc).lower():
                    retry_maxtime = max(
                        ffuf_maxtime + int(getattr(runtime, "ffuf_retry_extra_time", 120)),
                        ffuf_maxtime,
                    )
                    retry_threads = max(10, int(context.runtime_config.ffuf_threads // 2) or 10)
                    retry_cmd = [part for part in cmd if part not in {"-maxtime", str(ffuf_maxtime)}]
                    retry_cmd = list(retry_cmd)
                    if "-t" in retry_cmd:
                        t_idx = retry_cmd.index("-t") + 1
                        if t_idx < len(retry_cmd):
                            retry_cmd[t_idx] = str(retry_threads)
                    if retry_maxtime:
                        retry_cmd.extend(["-maxtime", str(retry_maxtime)])
                    retry_timeout = retry_maxtime + max(0, int(getattr(runtime, "ffuf_timeout_buffer", 30)))
                    try:
                        executor.run(retry_cmd, check=False, timeout=retry_timeout)
                        retried = True
                    except CommandError:
                        pass
                if not retried:
                    context.logger.warning("ffuf failed for %s", host)
                continue
            if artifact.exists():
                try:
                    data = json.loads(artifact.read_text(encoding="utf-8"))
                except json.JSONDecodeError:
                    continue
                for result in data.get("results", []):
                    payload = {
                        "type": "url",
                        "source": "ffuf",
                        "url": result.get("url"),
                        "status_code": result.get("status"),
                        "length": result.get("length"),
                        "tags": ["fuzz"],
                        "score": 50,
                    }
                    entry_url = payload.get("url")
                    if not entry_url:
                        continue
                    if not context.url_allowed(entry_url):
                        continue
                    if entry_url in stage_seen:
                        continue
                    host = payload.get("hostname") or urlparse(entry_url).hostname
                    if host:
                        payload.setdefault("hostname", host)
                    if host and per_host_limit > 0 and per_host_counts[host] >= per_host_limit:
                        continue
                    appended = context.results.append(payload)
                    if appended:
                        stage_seen.add(entry_url)
                        if host:
                            per_host_counts[host] += 1

    def _select_hosts_for_fuzz(self, context: PipelineContext) -> List[str]:
        hosts = defaultdict(int)
        results_path = context.record.paths.results_jsonl
        if not results_path.exists():
            return []
        for entry in read_jsonl(results_path):
            if entry.get("type") == "url" and entry.get("status_code") in {200, 204}:
                url_value = entry.get("url")
                if url_value and not context.url_allowed(url_value):
                    continue
                host = entry.get("hostname")
                if host:
                    hosts[host] = max(hosts[host], int(entry.get("score", 0)))
        sorted_hosts = sorted(hosts.items(), key=lambda item: item[1], reverse=True)
        return [host for host, _ in sorted_hosts]

    def _tags_for_hosts(self, context: PipelineContext) -> Dict[str, set[str]]:
        tags_by_host: Dict[str, set[str]] = defaultdict(set)
        results_path = context.record.paths.results_jsonl
        if not results_path.exists():
            return tags_by_host
        for entry in read_jsonl(results_path):
            if entry.get("type") != "url":
                continue
            url_value = entry.get("url")
            host = entry.get("hostname") or (urlparse(url_value).hostname if url_value else None)
            if not host:
                continue
            for tag in entry.get("tags", []):
                tags_by_host[host].add(tag)
            if url_value:
                path = urlparse(url_value).path.lower()
                if "/api" in path:
                    tags_by_host[host].add("service:api")
                if any(token in path for token in ("/wp-", "/wp-admin", "/wp-content", "/wp-json", "/xmlrpc.php")):
                    tags_by_host[host].add("cms:wordpress")
        return tags_by_host

    def _select_wordlist_for_host(self, runtime, host: str, tags: set[str]) -> Path:
        base = runtime.seclists_root
        candidates: List[Path] = []
        if "cms:wordpress" in tags or "tech:wordpress" in tags:
            candidates.append(base / "Discovery" / "Web-Content" / "CMS" / "wordpress.fuzz.txt")
        if "service:api" in tags:
            candidates.append(base / "Discovery" / "Web-Content" / "api" / "common-api-endpoints.txt")
        if tags.intersection({"surface:login", "surface:password-reset", "surface:register"}):
            candidates.append(base / "Discovery" / "Web-Content" / "Logins.fuzz.txt")
        if "surface:admin" in tags:
            candidates.append(base / "Discovery" / "Web-Content" / "admin.txt")
        for candidate in candidates:
            if candidate.exists():
                return candidate
        return base / "Discovery" / "Web-Content" / "common.txt"
