from __future__ import annotations

import textwrap
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field

from recon_cli.utils.sanitizer import redact

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None  # type: ignore


@dataclass
class NotificationConfig:
    """Configuration for notifications."""
    # Telegram
    telegram_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    telegram_timeout: int = 5
    
    # Slack
    slack_webhook_url: Optional[str] = None
    slack_channel: Optional[str] = None
    slack_timeout: int = 5
    
    # Discord
    discord_webhook_url: Optional[str] = None
    discord_timeout: int = 5
    
    # Email (SMTP)
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_from: Optional[str] = None
    smtp_to: Optional[List[str]] = None
    smtp_use_tls: bool = True
    
    # General
    enabled_channels: List[str] = field(default_factory=lambda: ["telegram"])


def send_telegram_message(token: Optional[str], chat_id: Optional[str], text: str, timeout: int = 5) -> bool:
    """Send a message via Telegram."""
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


def send_slack_message(webhook_url: Optional[str], text: str, channel: Optional[str] = None, timeout: int = 5) -> bool:
    """Send a message via Slack webhook."""
    if not webhook_url or not text:
        return False
    if requests is None:
        return False
    
    safe_text = redact(text)
    if not safe_text:
        return False
    
    payload: Dict[str, Any] = {"text": safe_text}
    if channel:
        payload["channel"] = channel
    
    try:
        response = requests.post(webhook_url, json=payload, timeout=timeout)
        response.raise_for_status()
        return True
    except Exception:
        return False


def send_discord_message(webhook_url: Optional[str], text: str, timeout: int = 5) -> bool:
    """Send a message via Discord webhook."""
    if not webhook_url or not text:
        return False
    if requests is None:
        return False
    
    safe_text = redact(text)
    if not safe_text:
        return False
    
    payload = {"content": safe_text}
    
    try:
        response = requests.post(webhook_url, json=payload, timeout=timeout)
        response.raise_for_status()
        return True
    except Exception:
        return False


def send_email(
    host: str,
    port: int,
    user: str,
    password: str,
    from_addr: str,
    to_addrs: List[str],
    subject: str,
    body: str,
    use_tls: bool = True,
) -> bool:
    """Send an email via SMTP."""
    if not all([host, user, password, from_addr, to_addrs, subject, body]):
        return False
    
    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        
        msg = MIMEMultipart()
        msg["From"] = from_addr
        msg["To"] = ", ".join(to_addrs)
        msg["Subject"] = subject
        
        safe_body = redact(body)
        if not safe_body:
            return False
        
        msg.attach(MIMEText(safe_body, "plain", "utf-8"))
        
        if use_tls:
            server = smtplib.SMTP(host, port)
            server.starttls()
        else:
            server = smtplib.SMTP(host, port)
        
        server.login(user, password)
        server.sendmail(from_addr, to_addrs, msg.as_string())
        server.quit()
        return True
    except Exception:
        return False


class NotificationManager:
    """Unified notification manager for multiple channels."""
    
    def __init__(self, config: Optional[NotificationConfig] = None):
        self.config = config or NotificationConfig()
    
    def send(self, message: str, channels: Optional[List[str]] = None) -> Dict[str, bool]:
        """Send notification to specified channels."""
        channels = channels or self.config.enabled_channels
        results = {}
        
        for channel in channels:
            if channel == "telegram":
                results["telegram"] = send_telegram_message(
                    self.config.telegram_token,
                    self.config.telegram_chat_id,
                    message,
                    self.config.telegram_timeout,
                )
            elif channel == "slack":
                results["slack"] = send_slack_message(
                    self.config.slack_webhook_url,
                    message,
                    self.config.slack_channel,
                    self.config.slack_timeout,
                )
            elif channel == "discord":
                results["discord"] = send_discord_message(
                    self.config.discord_webhook_url,
                    message,
                    self.config.discord_timeout,
                )
            elif channel == "email":
                if self.config.smtp_to:
                    results["email"] = send_email(
                        self.config.smtp_host or "",
                        self.config.smtp_port,
                        self.config.smtp_user or "",
                        self.config.smtp_password or "",
                        self.config.smtp_from or "",
                        self.config.smtp_to,
                        "ReconnV2 Notification",
                        message,
                        self.config.smtp_use_tls,
                    )
        
        return results
    
    def send_job_notification(
        self,
        job_id: str,
        status: str,
        target: Optional[str] = None,
        profile: str = "passive",
        stage: Optional[str] = None,
        error: Optional[str] = None,
        stats: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, bool]:
        """Send a job status notification."""
        emoji = {
            "started": "🚀",
            "running": "⏳",
            "finished": "✅",
            "failed": "❌",
        }.get(status.lower(), "📋")
        
        lines = [
            f"{emoji} [ReconnV2] Job {status.upper()}",
            f"Job ID: {job_id[:20]}...",
        ]
        
        if target:
            lines.append(f"Target: {target}")
        lines.append(f"Profile: {profile}")
        
        if stage:
            lines.append(f"Stage: {stage}")
        
        if stats:
            if "hosts_discovered" in stats:
                lines.append(f"Hosts: {stats['hosts_discovered']}")
            if "http_urls" in stats:
                lines.append(f"URLs: {stats['http_urls']}")
            if "vulnerabilities" in stats:
                lines.append(f"Vulns: {stats['vulnerabilities']}")
        
        if error:
            snippet = textwrap.shorten(error, width=200, placeholder="[snip]")
            lines.append(f"Error: {snippet}")
        
        message = "\n".join(lines)
        return self.send(message)


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
