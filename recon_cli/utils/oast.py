from __future__ import annotations

import json
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional


DOMAIN_RE = re.compile(
    r"([a-z0-9]{4,}\\.[a-z0-9.-]*(?:interactsh|oast|oast\\.live|oast\\.site|oast\\.fun|oast\\.pro))",
    re.IGNORECASE,
)
SERVER_RE = re.compile(r"(?:server|host)[:=]\\s*([a-z0-9.-]+)", re.IGNORECASE)
CLIENT_RE = re.compile(r"(?:client id|client-id|identifier)[:=]\\s*([a-z0-9-]+)", re.IGNORECASE)


@dataclass
class OastInteraction:
    token: str
    protocol: str
    raw: Dict[str, object]


class InteractshSession:
    def __init__(
        self,
        output_path: Path,
        *,
        logger=None,
        wait_seconds: int = 60,
        poll_interval: int = 5,
        timeout: int = 8,
        domain_override: Optional[str] = None,
    ) -> None:
        self.output_path = output_path
        self.logger = logger
        self.wait_seconds = wait_seconds
        self.poll_interval = poll_interval
        self.timeout = timeout
        self.domain_override = domain_override
        self.process: Optional[subprocess.Popen[str]] = None
        self.base_domain: Optional[str] = None
        self.server: Optional[str] = None
        self.client_id: Optional[str] = None

    def start(self) -> bool:
        if self.domain_override:
            self.base_domain = self.domain_override
            return True
        cmd = ["interactsh-client", "-json", "-o", str(self.output_path)]
        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except Exception as exc:
            if self.logger:
                self.logger.warning("Failed to start interactsh-client: %s", exc)
            return False
        ready = self._wait_for_domain()
        if not ready and self.logger:
            self.logger.warning("Interactsh domain not discovered (check interactsh-client output)")
        return ready

    def _wait_for_domain(self) -> bool:
        if self.base_domain:
            return True
        if not self.process or not self.process.stdout:
            return False
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            if self.process.poll() is not None:
                break
            line = self.process.stdout.readline()
            if not line:
                time.sleep(0.1)
                continue
            lowered = line.strip().lower()
            match = DOMAIN_RE.search(lowered)
            if match:
                self.base_domain = match.group(1)
                return True
            server_match = SERVER_RE.search(lowered)
            if server_match:
                self.server = server_match.group(1)
            client_match = CLIENT_RE.search(lowered)
            if client_match:
                self.client_id = client_match.group(1)
            if self.server and self.client_id:
                self.base_domain = f"{self.client_id}.{self.server}"
                return True
        return bool(self.base_domain)

    def make_url(self, token: str) -> str:
        if not self.base_domain:
            return ""
        return f"http://{token}.{self.base_domain}"

    def collect_interactions(self, tokens: Iterable[str]) -> List[OastInteraction]:
        token_list = list(tokens)
        if not token_list:
            return []
        seen_raw: set[str] = set()
        interactions: List[OastInteraction] = []
        deadline = time.time() + self.wait_seconds

        def _ingest_entries(entries: List[Dict[str, object]]) -> None:
            for entry in entries:
                raw_blob = json.dumps(entry, sort_keys=True)
                if raw_blob in seen_raw:
                    continue
                seen_raw.add(raw_blob)
                protocol = str(entry.get("protocol") or entry.get("type") or "")
                payload_str = raw_blob.lower()
                matched_token = None
                for token in token_list:
                    if token in payload_str:
                        matched_token = token
                        break
                if matched_token:
                    interactions.append(
                        OastInteraction(
                            token=matched_token,
                            protocol=protocol,
                            raw=entry,
                        )
                    )

        # If no process (domain override), just parse the output once.
        if not self.process:
            _ingest_entries(self._load_interactions())
            return interactions

        while time.time() < deadline:
            _ingest_entries(self._load_interactions())
            if interactions:
                break
            if self.process.poll() is not None:
                # Process exited; do one more read then stop waiting.
                _ingest_entries(self._load_interactions())
                break
            time.sleep(self.poll_interval)
        return interactions

    def stop(self) -> None:
        if not self.process:
            return
        if self.process.poll() is not None:
            return
        try:
            self.process.terminate()
        except Exception:
            pass
        try:
            self.process.wait(timeout=2)
        except Exception:
            try:
                self.process.kill()
            except Exception:
                pass

    def _load_interactions(self) -> List[Dict[str, object]]:
        if not self.output_path.exists():
            return []
        try:
            content = self.output_path.read_text(encoding="utf-8").strip()
        except Exception:
            return []
        if not content:
            return []
        entries: List[Dict[str, object]] = []
        # Try parse as full JSON
        try:
            data = json.loads(content)
            if isinstance(data, list):
                entries.extend([item for item in data if isinstance(item, dict)])
            elif isinstance(data, dict):
                for key in ("data", "interactions", "items"):
                    value = data.get(key)
                    if isinstance(value, list):
                        entries.extend([item for item in value if isinstance(item, dict)])
            if entries:
                return entries
        except json.JSONDecodeError:
            pass
        # Fallback to JSONL
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(data, dict):
                entries.append(data)
        return entries
