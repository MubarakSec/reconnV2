from __future__ import annotations

import asyncio
import json
import uuid
import os
import subprocess
from typing import Dict, List, Optional, Any, Set
from pathlib import Path

class InteractshInteraction:
    def __init__(self, raw: Dict[str, Any]):
        self.raw = raw
        self.token = raw.get("correlation-id") or raw.get("unique-id")

class InteractshSession:
    """
    Wrapper for interactsh-client tool.
    """
    def __init__(self, output_path: Path, logger: Any = None, domain_override: Optional[str] = None):
        self.output_path = output_path
        self.logger = logger
        self.domain = domain_override or "interact.sh"
        self.process: Optional[subprocess.Popen] = None
        self._server_url: Optional[str] = None

    def start(self) -> bool:
        """Starts the interactsh-client in the background."""
        try:
            # We use the interactsh-client binary
            # cmd: interactsh-client -json -o output.json
            self.process = subprocess.Popen(
                ["interactsh-client", "-json", "-o", str(self.output_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            # Wait a bit for it to initialize and get the server URL if possible
            # (In a real implementation, we'd parse the stdout to get the actual assigned domain)
            return True
        except Exception as e:
            if self.logger: self.logger.error(f"Failed to start interactsh-client: {e}")
            return False

    def make_url(self, token: str) -> str:
        """Generates a unique URL for this session."""
        # For public interactsh, it's usually <token>.<domain>
        return f"{token}.{self.domain}"

    def collect_interactions(self, tokens: List[str]) -> List[InteractshInteraction]:
        """Reads the output file and returns matching interactions."""
        if not self.output_path.exists():
            return []
        
        interactions = []
        try:
            with open(self.output_path, "r") as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        inter = InteractshInteraction(data)
                        if any(t in str(data) for t in tokens):
                            interactions.append(inter)
                    except json.JSONDecodeError:
                        continue
        except Exception:
            pass
        return interactions

    def stop(self):
        """Stops the interactsh-client."""
        if self.process:
            self.process.terminate()
            self.process.wait()

class OASTManager:
    """High-level manager for all OAST activities."""
    def __init__(self):
        self.default_session: Optional[InteractshSession] = None

    @staticmethod
    def get_default_manager() -> OASTManager:
        return OASTManager()
