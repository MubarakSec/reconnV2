from __future__ import annotations

import json
from pathlib import Path
from typing import List, Dict, Any, Iterable
from urllib.parse import urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.tools.executor import CommandError


class NucleiEngine:
    """A centralized engine for running Nuclei scans."""

    def __init__(self, context: PipelineContext):
        self.context = context
        self.executor = context.executor

    def is_enabled(self) -> bool:
        """Check if Nuclei is enabled in the runtime configuration."""
        return bool(getattr(self.context.runtime_config, "enable_nuclei", True))

    def run(self, targets: Iterable[str], tags: Iterable[str], severity: str = "critical,high", output_file: Path | None = None) -> Path:
        """
        Run a Nuclei scan with the given parameters.
        
        Args:
            targets: A list of target URLs or hostnames.
            tags: A list of Nuclei template tags to use.
            severity: The minimum severity of templates to use.
            output_file: The file to write the JSONL output to.

        Returns:
            The path to the output file.
        """
        if not self.is_enabled():
            self.context.logger.info("Nuclei is disabled, skipping scan.")
            raise RuntimeError("Nuclei is disabled")

        if not self.executor.available("nuclei"):
            self.context.logger.warning("nuclei not available; skipping scan")
            raise RuntimeError("nuclei not available")
        
        target_list = list(targets)
        if not target_list:
            self.context.logger.info("No targets provided for Nuclei scan.")
            raise ValueError("No targets for Nuclei")

        if output_file is None:
            output_file = self.context.record.paths.artifact(f"nuclei_{self.context.record.metadata.stage}.json")

        target_file = self.context.record.paths.artifact(f"nuclei_{self.context.record.metadata.stage}_targets.txt")
        target_file.write_text("
".join(target_list))

        cmd = [
            "nuclei",
            "-list", str(target_file),
            "-severity", severity,
            "-tags", ",".join(tags),
            "-jsonl",
            "-o", str(output_file),
            "-silent"
        ]

        # Calculate dynamic timeout
        timeout_base = int(getattr(self.context.runtime_config, "nuclei_batch_timeout_base", 300))
        timeout_per_target = int(getattr(self.context.runtime_config, "nuclei_batch_timeout_per_target", 45))
        timeout_max = int(getattr(self.context.runtime_config, "nuclei_batch_timeout_max", 1800))
        timeout = min(timeout_base + (len(target_list) * timeout_per_target), timeout_max)

        self.context.logger.info("Running nuclei against %d targets with tags: %s (timeout: %ds)", len(target_list), ",".join(tags), timeout)
        
        try:
            self.executor.run(cmd, check=False, timeout=timeout)
        except CommandError as e:
            self.context.logger.error("Nuclei execution failed: %s", e)
            raise

        return output_file
