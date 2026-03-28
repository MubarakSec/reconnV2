from __future__ import annotations

import asyncio
import json
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Set
from urllib.parse import urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stages.core.stage_base import Stage, note_missing_tool
from recon_cli.tools.executor import CommandError


class FuzzStage(Stage):
    name = "fuzzing"

    def is_enabled(self, context: PipelineContext) -> bool:
        spec = context.record.spec
        if (
            not context.runtime_config.enable_fuzz
            and not context.runtime_config.enable_param_fuzz
            and not spec.wordlist
        ):
            return False
        return spec.profile in {"full", "fuzz-only"} or bool(spec.wordlist)

    def execute(self, context: PipelineContext) -> None:
        executor = context.executor
        runtime = context.runtime_config
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
        host_meta = self._collect_fuzz_metadata(context)
        param_wordlist_words = self._load_param_wordlist(runtime)

        per_host_counts: Dict[str, int] = defaultdict(int)
        stage_seen: Set[str] = set()
        per_host_limit = max(runtime.trim_url_max_per_host, 0)

        async def _run_all():
            semaphore = asyncio.Semaphore(3)
            tasks = []
            for host in targets[: context.runtime_config.max_fuzz_hosts]:
                tasks.append(
                    self._run_ffuf_for_host(
                        context,
                        host,
                        semaphore,
                        wordlist_override,
                        host_tags,
                        host_meta,
                        param_wordlist_words,
                        stage_seen,
                        per_host_counts,
                        per_host_limit,
                    )
                )
            await asyncio.gather(*tasks)

        try:
            loop = asyncio.get_running_loop()
            if loop.is_running():
                # We are already in an event loop, possibly in a different thread
                # or the same thread. Since execute is sync, we use run_coroutine_threadsafe.
                asyncio.run_coroutine_threadsafe(_run_all(), loop).result()
            else:
                asyncio.run(_run_all())
        except RuntimeError:
            asyncio.run(_run_all())

    async def _run_ffuf_for_host(
        self,
        context: PipelineContext,
        host: str,
        semaphore: asyncio.Semaphore,
        wordlist_override: Path | None,
        host_tags: Dict[str, Set[str]],
        host_meta: Dict[str, Dict[str, object]],
        param_wordlist_words: Set[str],
        stage_seen: Set[str],
        per_host_counts: Dict[str, int],
        per_host_limit: int,
    ) -> None:
        async with semaphore:
            runtime = context.runtime_config
            tool_timeout = runtime.tool_timeout
            enable_param_fuzz = bool(getattr(runtime, "enable_param_fuzz", False))
            fuzz_custom_max_words = int(getattr(runtime, "fuzz_custom_max_words", 1500))
            fuzz_combined_max_words = int(
                getattr(runtime, "fuzz_combined_max_words", 6000)
            )
            fuzz_param_max_words = int(getattr(runtime, "fuzz_param_max_words", 500))

            wordlist_path = wordlist_override or self._select_wordlist_for_host(
                runtime, host, host_tags.get(host, set())
            )
            if not wordlist_path.exists():
                context.logger.warning("Wordlist not found: %s", wordlist_path)
                return

            meta = host_meta.get(host, {})
            base_url = self._base_url_for_host(host, meta)
            base_root = self._root_url(base_url)
            path_words = meta.get("path_words", set())
            param_words = meta.get("param_words", set())
            combined_wordlist = self._build_combined_wordlist(
                context,
                host,
                wordlist_path,
                path_words,  # type: ignore[arg-type]
                max_custom=fuzz_custom_max_words,
                max_combined=fuzz_combined_max_words,
            )
            artifact = context.record.paths.artifact(f"ffuf_{host}.json")
            cmd = [
                "ffuf",
                "-w",
                str(combined_wordlist),
                "-u",
                f"{base_root}/FUZZ",
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
            if await self._run_ffuf(context, cmd, tool_timeout, runtime, host=host):
                self._ingest_ffuf_results(
                    context,
                    artifact,
                    stage_seen,
                    per_host_counts,
                    per_host_limit,
                    tag="fuzz",
                )
            
            # 2.1 Leak Fuzzing (Sensitive Files)
            await self._run_leaks_fuzz(context, host, base_root, semaphore, stage_seen, per_host_counts, per_host_limit)

            # 2.2 Extension Fuzzing on discovered paths (if any)
            if path_words:
                ext_wordlist = self._write_wordlist(
                    context, f"ffuf_{host}_extensions.txt",
                    {f"{w}{ext}" for w in path_words for ext in [".bak", ".old", ".php", ".jsp", ".zip", ".tar.gz", ".swp"]},
                    limit=500
                )
                if ext_wordlist:
                    ext_artifact = context.record.paths.artifact(f"ffuf_ext_{host}.json")
                    ext_cmd = [
                        "ffuf", "-w", str(ext_wordlist), "-u", f"{base_root}/FUZZ",
                        "-t", str(context.runtime_config.ffuf_threads),
                        "-mc", "200,301,302,401,403", "-ac", "-of", "json", "-o", str(ext_artifact)
                    ]
                    if await self._run_ffuf(context, ext_cmd, tool_timeout, runtime, host=host):
                        self._ingest_ffuf_results(context, ext_artifact, stage_seen, per_host_counts, per_host_limit, tag="ext-fuzz")

            if enable_param_fuzz:
                if param_wordlist_words:
                    param_words.update(param_wordlist_words)  # type: ignore[attr-defined]
            if enable_param_fuzz and param_words:
                param_wordlist = self._write_wordlist(
                    context,
                    f"ffuf_{host}_params.txt",
                    param_words,  # type: ignore[arg-type]
                    limit=fuzz_param_max_words,
                )
                if param_wordlist and param_wordlist.exists():
                    param_artifact = context.record.paths.artifact(
                        f"ffuf_params_{host}.json"
                    )
                    param_cmd = [
                        "ffuf",
                        "-w",
                        str(param_wordlist),
                        "-u",
                        f"{base_root}/?FUZZ=1",
                        "-t",
                        str(max(5, int(context.runtime_config.ffuf_threads // 2) or 5)),
                        "-mc",
                        "200,301,302,401,403",
                        "-ac",
                        "-of",
                        "json",
                        "-o",
                        str(param_artifact),
                    ]
                    if await self._run_ffuf(
                        context, param_cmd, tool_timeout, runtime, host=host
                    ):
                        self._ingest_ffuf_results(
                            context,
                            param_artifact,
                            stage_seen,
                            per_host_counts,
                            per_host_limit,
                            tag="param-fuzz",
                        )

    async def _run_leaks_fuzz(self, context: PipelineContext, host: str, base_root: str, semaphore: asyncio.Semaphore, stage_seen: Set[str], per_host_counts: Dict[str, int], per_host_limit: int) -> None:
        """Focused fuzzing for highly sensitive leak files."""
        leaks = {
            ".env", ".git/config", "backup.zip", "database.sql", ".php.bak", ".jsp.bak", 
            "config.php", "web.config", ".htpasswd", "docker-compose.yml", ".npmrc"
        }
        leak_wordlist = self._write_wordlist(context, f"ffuf_{host}_leaks.txt", leaks, limit=0)
        if not leak_wordlist: return
        
        artifact = context.record.paths.artifact(f"ffuf_leaks_{host}.json")
        cmd = [
            "ffuf", "-w", str(leak_wordlist), "-u", f"{base_root}/FUZZ",
            "-t", "5", "-mc", "200", "-ac", "-of", "json", "-o", str(artifact)
        ]
        if await self._run_ffuf(context, cmd, 30, context.runtime_config, host=host):
            self._ingest_ffuf_results(context, artifact, stage_seen, per_host_counts, per_host_limit, tag="leak-fuzz")

    def _select_hosts_for_fuzz(self, context: PipelineContext) -> List[str]:
        hosts: Dict[str, int] = defaultdict(int)
        soft_404_hosts = set(
            context.record.metadata.stats.get("soft_404", {}).get("hosts", [])
        )
        for entry in context.iter_results():
            if entry.get("type") == "url" and entry.get("status_code") in {200, 204}:
                url_value = entry.get("url")
                if url_value and not context.url_allowed(url_value):
                    continue
                host = entry.get("hostname")
                if host:
                    hosts[host] = max(hosts[host], int(entry.get("score", 0)))
        signals = context.signal_index()
        adjusted: Dict[str, int] = {}
        for host, score in hosts.items():
            host_signals = signals.get("by_host", {}).get(host, set())
            if (
                "waf_detected" in host_signals
                and "waf_bypass_possible" not in host_signals
            ):
                score = max(score - 20, 0)
            if "api_surface" in host_signals:
                score += 10
            if "auth_surface" in host_signals:
                score += 5
            if host in soft_404_hosts:
                score = max(score - 40, 0)
            adjusted[host] = score
        sorted_hosts = sorted(adjusted.items(), key=lambda item: item[1], reverse=True)
        return [host for host, _ in sorted_hosts]

    def _collect_fuzz_metadata(
        self, context: PipelineContext
    ) -> Dict[str, Dict[str, object]]:
        metadata: Dict[str, Dict[str, object]] = defaultdict(
            lambda: {
                "path_words": set(),
                "param_words": set(),
                "base_url": None,
                "base_score": -1,
            }
        )
        for entry in context.iter_results():
            etype = entry.get("type")
            if etype == "url":
                url_value = entry.get("url")
                if not url_value:
                    continue
                host = entry.get("hostname") or urlparse(url_value).hostname
                if not host:
                    continue
                score = int(entry.get("score", 0))
                if score > int(metadata[host].get("base_score", -1)):  # type: ignore[call-overload]
                    metadata[host]["base_url"] = url_value
                    metadata[host]["base_score"] = score
                self._add_path_words(
                    metadata[host]["path_words"],  # type: ignore[arg-type]
                    urlparse(url_value).path,  # type: ignore[arg-type]
                )
            elif etype == "form":
                action = entry.get("action") or entry.get("url")
                if not action:
                    continue
                host = urlparse(action).hostname
                if not host:
                    continue
                self._add_path_words(
                    metadata[host]["path_words"],  # type: ignore[arg-type]
                    urlparse(action).path,  # type: ignore[arg-type]
                )
            elif etype == "parameter":
                name = entry.get("name")
                if not name:
                    continue
                examples = entry.get("examples") or []
                if not isinstance(examples, list) or not examples:
                    continue
                for example in examples:
                    if not isinstance(example, str):
                        continue
                    host = urlparse(example).hostname
                    if host:
                        metadata[host]["param_words"].add(str(name))  # type: ignore[attr-defined]
        js_endpoints = context.get_data("js_endpoints", []) or []
        for endpoint in js_endpoints:  # type: ignore[attr-defined]
            if not isinstance(endpoint, str) or not endpoint:
                continue
            host = urlparse(endpoint).hostname
            if not host:
                continue
            self._add_path_words(metadata[host]["path_words"], urlparse(endpoint).path)  # type: ignore[arg-type]
        return metadata

    @staticmethod
    def _add_path_words(word_set: Set[str], path: str) -> None:

        if not path:
            return
        stripped = path.strip("/")
        if not stripped:
            return
        word_set.add(stripped)
        for part in stripped.split("/"):
            if part:
                word_set.add(part)

    @staticmethod
    def _root_url(url: str) -> str:
        parsed = urlparse(url)
        scheme = parsed.scheme or "https"
        netloc = parsed.netloc or parsed.hostname or ""
        if not netloc:
            return url
        return f"{scheme}://{netloc}".rstrip("/")

    def _base_url_for_host(self, host: str, meta: Dict[str, object]) -> str:
        base = meta.get("base_url")
        if isinstance(base, str) and base:
            return base
        return f"https://{host}"

    def _write_wordlist(
        self,
        context: PipelineContext,
        filename: str,
        words: Set[str],
        *,
        limit: int,
    ) -> Path | None:
        if not words:
            return None
        cleaned: List[str] = []
        seen: Set[str] = set()
        for word in sorted(words):
            if not word:
                continue
            normalized = str(word).strip().lstrip("/")
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            cleaned.append(normalized)
            if limit > 0 and len(cleaned) >= limit:
                break
        if not cleaned:
            return None
        wordlist_dir = context.record.paths.ensure_subdir("wordlists")
        path = wordlist_dir / filename
        path.write_text("\n".join(cleaned) + "\n", encoding="utf-8")
        return path

    def _build_combined_wordlist(
        self,
        context: PipelineContext,
        host: str,
        base_wordlist: Path,
        custom_words: Set[str],
        *,
        max_custom: int,
        max_combined: int,
    ) -> Path:
        all_custom = set(custom_words)
        mined_words = context.get_data("custom_target_words", [])
        if mined_words and isinstance(mined_words, list):
            all_custom.update(mined_words)

        if not all_custom:
            return base_wordlist
        custom_path = self._write_wordlist(
            context,
            f"ffuf_{host}_custom.txt",
            all_custom,
            limit=max_custom,
        )
        if custom_path is None or not custom_path.exists():
            return base_wordlist
        combined: List[str] = []
        seen: Set[str] = set()
        for line in custom_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line in seen:
                continue
            combined.append(line)
            seen.add(line)
        if base_wordlist.exists():
            for line in base_wordlist.read_text(
                encoding="utf-8", errors="ignore"
            ).splitlines():
                line = line.strip()
                if not line or line in seen:
                    continue
                combined.append(line)
                seen.add(line)
                if max_combined > 0 and len(combined) >= max_combined:
                    break
        wordlist_dir = context.record.paths.ensure_subdir("wordlists")
        combined_path = wordlist_dir / f"ffuf_{host}_combined.txt"
        combined_path.write_text("\n".join(combined) + "\n", encoding="utf-8")
        return combined_path

    async def _run_ffuf(
        self,
        context: PipelineContext,
        cmd: List[str],
        tool_timeout: int,
        runtime,
        host: str = None,
    ) -> bool:
        try:
            ffuf_maxtime = max(0, int(getattr(runtime, "ffuf_maxtime", 0)))
            if ffuf_maxtime:
                cmd.extend(["-maxtime", str(ffuf_maxtime)])

            # ELITE: Inject Auth Headers from Context
            auth_headers = context.auth_headers()
            if auth_headers:
                for name, value in auth_headers.items():
                    cmd.extend(["-H", f"{name}: {value}"])

            # Apply soft 404 filters if detected for this host
            if host:
                soft_404_data = (
                    context.record.metadata.stats.get("soft_404", {})
                    .get("fingerprints", {})
                    .get(host)
                )
                if soft_404_data:
                    size = soft_404_data.get("length")
                    words = soft_404_data.get("word_count")
                    if size and str(size) not in cmd:
                        cmd.extend(["-fs", str(size)])
                    if words and str(words) not in cmd:
                        cmd.extend(["-fw", str(words)])

            timeout = tool_timeout
            if ffuf_maxtime:
                timeout = ffuf_maxtime + max(
                    0, int(getattr(runtime, "ffuf_timeout_buffer", 30))
                )
            await context.executor.run_async(cmd, check=False, timeout=timeout)
            return True
        except CommandError as exc:
            retried = False
            if (
                getattr(runtime, "ffuf_retry_on_timeout", True)
                and "timeout" in str(exc).lower()
            ):
                retry_maxtime = max(
                    ffuf_maxtime + int(getattr(runtime, "ffuf_retry_extra_time", 120)),
                    ffuf_maxtime,
                )
                retry_threads = max(
                    10, int(context.runtime_config.ffuf_threads // 2) or 10
                )
                retry_cmd = [
                    part for part in cmd if part not in {"-maxtime", str(ffuf_maxtime)}
                ]
                retry_cmd = list(retry_cmd)
                if "-t" in retry_cmd:
                    t_idx = retry_cmd.index("-t") + 1
                    if t_idx < len(retry_cmd):
                        retry_cmd[t_idx] = str(retry_threads)
                if retry_maxtime:
                    retry_cmd.extend(["-maxtime", str(retry_maxtime)])
                retry_timeout = retry_maxtime + max(
                    0, int(getattr(runtime, "ffuf_timeout_buffer", 30))
                )
                try:
                    await context.executor.run_async(
                        retry_cmd, check=False, timeout=retry_timeout
                    )
                    retried = True
                except CommandError as retry_exc:
                    context.logger.error(
                        "ffuf retry failed for %s: %s", host, retry_exc
                    )
            if not retried:
                context.logger.warning(
                    "ffuf failed for %s",
                    cmd[cmd.index("-u") + 1] if "-u" in cmd else "target",
                )
            return retried

    def _ingest_ffuf_results(
        self,
        context: PipelineContext,
        artifact: Path,
        stage_seen: Set[str],
        per_host_counts: Dict[str, int],
        per_host_limit: int,
        *,
        tag: str,
    ) -> None:
        if not artifact.exists():
            return
        try:
            data = json.loads(artifact.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            context.logger.error(
                "Failed to decode ffuf results for %s: %s", artifact, exc
            )
            return
        for result in data.get("results", []):
            payload = {
                "type": "url",
                "source": "ffuf",
                "url": result.get("url"),
                "status_code": result.get("status"),
                "length": result.get("length"),
                "tags": ["fuzz", tag],
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

    def _tags_for_hosts(self, context: PipelineContext) -> Dict[str, set[str]]:
        tags_by_host: Dict[str, set[str]] = defaultdict(set)
        
        for entry in context.iter_results():
            entry_type = entry.get("type")
            url_value = entry.get("url")
            host = None
            if entry_type == "url":
                host = entry.get("hostname") or (
                    urlparse(url_value).hostname if url_value else None
                )
            elif entry_type in {"hostname", "cms"}:
                host = entry.get("hostname")
            if not host:
                continue
            
            for tag in entry.get("tags", []):
                tags_by_host[host].add(tag)
            
            if entry_type == "url" and url_value:
                path = urlparse(url_value).path.lower()
                
                # Tech Detection via Extensions/Paths
                if ".jsp" in path or ".do" in path or "web-inf" in path:
                    tags_by_host[host].add("tech:java")
                if ".php" in path:
                    tags_by_host[host].add("tech:php")
                if "node_modules" in path or "package.json" in path:
                    tags_by_host[host].add("tech:node")
                if ".asp" in path or ".aspx" in path:
                    tags_by_host[host].add("tech:asp")
                
                if "/api" in path:
                    tags_by_host[host].add("service:api")
                if any(token in path for token in ("/wp-", "/wp-admin", "/wp-content", "/wp-json", "/xmlrpc.php")):
                    tags_by_host[host].add("cms:wordpress")
        
        signals = context.signal_index()
        for host, host_signals in signals.get("by_host", {}).items():
            if "cms_drupal" in host_signals: tags_by_host[host].add("cms:drupal")
            if "cms_joomla" in host_signals: tags_by_host[host].add("cms:joomla")
            if "api_surface" in host_signals: tags_by_host[host].add("service:api")
            
        return tags_by_host

    def _select_wordlist_for_host(self, runtime, host: str, tags: set[str]) -> Path:
        base = runtime.seclists_root
        candidates: List[Path] = []
        
        # Technology-specific wordlists
        if "tech:php" in tags:
            candidates.append(base / "Discovery" / "Web-Content" / "PHP.fuzz.txt")
        if "tech:java" in tags:
            candidates.append(base / "Discovery" / "Web-Content" / "Java.fuzz.txt")
        if "tech:node" in tags:
            candidates.append(base / "Discovery" / "Web-Content" / "NodeJS.fuzz.txt")
        if "tech:asp" in tags:
            candidates.append(base / "Discovery" / "Web-Content" / "IIS.fuzz.txt")
            
        if "cms:wordpress" in tags or "tech:wordpress" in tags:
            candidates.append(
                base / "Discovery" / "Web-Content" / "CMS" / "wordpress.fuzz.txt"
            )
        if "cms:drupal" in tags:
            candidates.append(base / "Discovery" / "Web-Content" / "CMS" / "drupal.txt")
        if "cms:joomla" in tags:
            candidates.append(base / "Discovery" / "Web-Content" / "CMS" / "joomla.txt")
        if "service:api" in tags:
            candidates.append(
                base / "Discovery" / "Web-Content" / "api" / "common-api-endpoints.txt"
            )
        if tags.intersection(
            {"surface:login", "surface:password-reset", "surface:register"}
        ):
            candidates.append(base / "Discovery" / "Web-Content" / "Logins.fuzz.txt")
        if "surface:admin" in tags:
            candidates.append(base / "Discovery" / "Web-Content" / "admin.txt")
        candidates.append(base / "Discovery" / "Web-Content" / "raft-medium-words.txt")
        candidates.append(
            base / "Discovery" / "Web-Content" / "raft-medium-directories.txt"
        )
        for candidate in candidates:
            if candidate.exists():
                return candidate
        fallback_path = base / "Discovery" / "Web-Content" / "common.txt"
        if not fallback_path.exists():
            import tempfile

            tmp_path = Path(tempfile.gettempdir()) / "recon_default_wordlist.txt"
            if not tmp_path.exists():
                tmp_path.write_text(
                    "admin\nlogin\napi\nconfig\n.env\ntest\nbackup\n", encoding="utf-8"
                )
            return tmp_path
        return fallback_path

    @staticmethod
    def _load_param_wordlist(runtime) -> Set[str]:
        base = runtime.seclists_root
        candidates = [
            base / "Discovery" / "Web-Content" / "burp-parameter-names.txt",
            base / "Discovery" / "Web-Content" / "parameter-names.txt",
        ]
        for candidate in candidates:
            if candidate.exists():
                words: Set[str] = set()
                for line in candidate.read_text(
                    encoding="utf-8", errors="ignore"
                ).splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    words.add(line)
                return words
        return set()
