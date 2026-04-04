from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional
from logging import Logger
from recon_cli.utils.sanitizer import redact
import json


class RedactingFormatter(logging.Formatter):
    def format(self, record):
        formatted = super().format(record)
        return redact(formatted)


class JsonRedactingFormatter(logging.Formatter):
    def format(self, record):
        payload = {
            "timestamp": self.formatTime(record, _DATEFMT),
            "level": record.levelname,
            "message": record.getMessage(),
        }
        return redact(json.dumps(payload, ensure_ascii=True))


_LOG_FORMAT = "%(asctime)s | %(levelname)s | %(message)s"
_DATEFMT = "%Y-%m-%dT%H:%M:%S"


def build_file_logger(
    name: str, logfile: Path, level: int = logging.INFO, log_format: str = "text"
) -> Logger:
    logfile.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.handlers.clear()

    if log_format == "json":
        formatter = JsonRedactingFormatter()
    else:
        formatter = RedactingFormatter(_LOG_FORMAT, datefmt=_DATEFMT)  # type: ignore[assignment]

    file_handler = logging.FileHandler(logfile, encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    return logger


def silence_logger(logger: Logger) -> None:
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()


def child_logger(parent: Logger, name: str, logfile: Optional[Path] = None) -> Logger:
    logger = parent.getChild(name)
    if logfile:
        logfile.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(logfile, encoding="utf-8")
        fh.setFormatter(RedactingFormatter(_LOG_FORMAT, datefmt=_DATEFMT))
        logger.addHandler(fh)
    return logger


def get_pipeline_logger() -> Optional[Logger]:
    """Get the pipeline logger if it exists."""
    try:
        logger = logging.getLogger("recon.pipeline")
        # Check if logger has any handlers
        if logger.handlers or logger.parent.handlers:
            return logger
    except Exception:
        pass
    return None
