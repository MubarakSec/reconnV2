from __future__ import annotations

import textwrap
from typing import Optional

from recon_cli.utils.sanitizer import redact

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None  # type: ignore


def send_telegram_message(token: Optional[str], chat_id: Optional[str], text: str, timeout: int = 5) -> bool:
    if not token or not chat_id:
        return False
    if not text:
        return False
    if requests is None:
        return False
    safe_text = redact(text)
    if not safe_text:
        return False
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": safe_text}
    try:
        response = requests.post(url, json=payload, timeout=timeout)
        response.raise_for_status()
    except Exception:  # pragma: no cover
        return False
    return True


def send_pipeline_notification(context, status: str, error: Optional[str] = None) -> None:
    runtime = getattr(context, "runtime_config", None)
    if runtime is None:
        return
    token = getattr(runtime, "telegram_token", None)
    chat_id = getattr(runtime, "telegram_chat_id", None)
    timeout = getattr(runtime, "telegram_timeout", 5)
    if not token or not chat_id:
        return

    spec = context.record.spec
    metadata = context.record.metadata
    result_paths = context.record.paths

    headline = f"[recon-cli] Job {spec.job_id} {status.upper()}"
    body_lines = [headline]
    if spec.target:
        body_lines.append(f"Target: {spec.target}")
    body_lines.append(f"Profile: {spec.profile}")
    body_lines.append(f"Stage: {metadata.stage}")
    if status.lower() == "finished":
        body_lines.append(f"Results: {result_paths.results_txt}")
    if error:
        snippet = textwrap.shorten(error, width=280, placeholder="[snip]")
        body_lines.append(f"Error: {snippet}")

    message = "\n".join(body_lines)
    safe_message = redact(message)
    if not safe_message:
        return
    send_telegram_message(token, chat_id, safe_message, timeout=timeout)
