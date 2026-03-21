from __future__ import annotations

from datetime import datetime, timezone

ISO_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def format_ts(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).strftime(ISO_FORMAT)


def iso_now() -> str:
    return format_ts(utc_now())  # type: ignore[return-value]
