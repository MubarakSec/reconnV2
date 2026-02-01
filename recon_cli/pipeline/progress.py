from __future__ import annotations

import time
from typing import Optional


class ProgressLogger:
    def __init__(self, logger, interval: float = 2.0) -> None:
        self.logger = logger
        self.interval = interval
        self.last_emit = time.perf_counter()

    def maybe(self, message: str) -> None:
        now = time.perf_counter()
        if now - self.last_emit >= self.interval:
            self.logger.info(message)
            self.last_emit = now
