"""
Alerting System - نظام التنبيهات

نظام تنبيهات متقدم مع قواعد وعتبات.

Features:
- قواعد التنبيه
- عتبات متعددة
- قنوات إشعار متعددة
- تجميع التنبيهات

Example:
    >>> alerter = Alerter()
    >>> alerter.add_rule(AlertRule(
    ...     name="high-vulns",
    ...     condition=lambda ctx: ctx["critical_vulns"] > 0,
    ...     severity=AlertSeverity.CRITICAL,
    ...     message="Critical vulnerabilities found!"
    ... ))
    >>> alerter.check({"critical_vulns": 5})
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import smtplib
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Union

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════
#                     Alert Types
# ═══════════════════════════════════════════════════════════

class AlertSeverity(Enum):
    """خطورة التنبيه"""
    CRITICAL = "critical"  # فوري - يتطلب تدخل
    HIGH = "high"          # مهم جداً
    MEDIUM = "medium"      # مهم
    LOW = "low"            # للعلم
    INFO = "info"          # معلومات


class AlertStatus(Enum):
    """حالة التنبيه"""
    FIRING = "firing"       # نشط
    RESOLVED = "resolved"   # تم حله
    SILENCED = "silenced"   # مكتوم


class AlertChannel(Enum):
    """قناة الإشعار"""
    CONSOLE = "console"
    EMAIL = "email"
    SLACK = "slack"
    DISCORD = "discord"
    WEBHOOK = "webhook"
    TELEGRAM = "telegram"


@dataclass
class Alert:
    """تنبيه"""
    
    id: str = ""
    name: str = ""
    message: str = ""
    
    severity: AlertSeverity = AlertSeverity.INFO
    status: AlertStatus = AlertStatus.FIRING
    
    rule_name: str = ""
    source: str = ""
    
    labels: Dict[str, str] = field(default_factory=dict)
    annotations: Dict[str, str] = field(default_factory=dict)
    context: Dict[str, Any] = field(default_factory=dict)
    
    fired_at: datetime = field(default_factory=datetime.now)
    resolved_at: Optional[datetime] = None
    
    # Notification tracking
    notified_channels: Set[str] = field(default_factory=set)
    notification_count: int = 0
    
    def __post_init__(self):
        if not self.id:
            self.id = self._generate_id()
    
    def _generate_id(self) -> str:
        """توليد ID"""
        content = f"{self.name}-{self.rule_name}-{json.dumps(self.labels, sort_keys=True)}"
        return hashlib.sha256(content.encode()).hexdigest()[:12]
    
    def resolve(self) -> None:
        """حل التنبيه"""
        self.status = AlertStatus.RESOLVED
        self.resolved_at = datetime.now()
    
    def silence(self, duration: timedelta) -> None:
        """كتم التنبيه"""
        self.status = AlertStatus.SILENCED
    
    @property
    def duration(self) -> timedelta:
        """مدة التنبيه"""
        end = self.resolved_at or datetime.now()
        return end - self.fired_at
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "message": self.message,
            "severity": self.severity.value,
            "status": self.status.value,
            "rule_name": self.rule_name,
            "source": self.source,
            "labels": self.labels,
            "annotations": self.annotations,
            "fired_at": self.fired_at.isoformat(),
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "duration_seconds": self.duration.total_seconds(),
        }


@dataclass
class AlertRule:
    """
    قاعدة تنبيه.
    
    تحدد متى يجب إطلاق تنبيه.
    
    Example:
        >>> rule = AlertRule(
        ...     name="high-error-rate",
        ...     condition=lambda ctx: ctx["error_rate"] > 0.1,
        ...     severity=AlertSeverity.HIGH,
        ...     message="Error rate exceeded 10%",
        ... )
    """
    
    name: str
    condition: Callable[[Dict[str, Any]], bool]
    message: Union[str, Callable[[Dict[str, Any]], str]]
    severity: AlertSeverity = AlertSeverity.MEDIUM
    
    # Throttling
    cooldown_seconds: int = 300  # 5 minutes between alerts
    
    # Labels added to alerts
    labels: Dict[str, str] = field(default_factory=dict)
    
    # Channels to notify
    channels: List[AlertChannel] = field(default_factory=list)
    
    enabled: bool = True
    
    # State
    last_fired: Optional[datetime] = None
    fire_count: int = 0
    
    def evaluate(self, context: Dict[str, Any]) -> Optional[Alert]:
        """تقييم القاعدة"""
        if not self.enabled:
            return None
        
        # Check cooldown
        if self.last_fired:
            elapsed = (datetime.now() - self.last_fired).total_seconds()
            if elapsed < self.cooldown_seconds:
                return None
        
        try:
            if self.condition(context):
                self.last_fired = datetime.now()
                self.fire_count += 1
                
                # Get message
                if callable(self.message):
                    message = self.message(context)
                else:
                    message = self.message
                
                return Alert(
                    name=self.name,
                    message=message,
                    severity=self.severity,
                    rule_name=self.name,
                    labels=self.labels.copy(),
                    context=context,
                )
        except Exception as e:
            logger.error("Rule evaluation error (%s): %s", self.name, e)
        
        return None


# ═══════════════════════════════════════════════════════════
#                     Notification Channels
# ═══════════════════════════════════════════════════════════

class NotificationChannel(ABC):
    """قناة إشعار"""
    
    @abstractmethod
    async def send(self, alert: Alert) -> bool:
        """إرسال التنبيه"""
        pass
    
    @abstractmethod
    def name(self) -> str:
        """اسم القناة"""
        pass


class ConsoleChannel(NotificationChannel):
    """إشعار الكونسول"""
    
    SEVERITY_ICONS = {
        AlertSeverity.CRITICAL: "🔴",
        AlertSeverity.HIGH: "🟠",
        AlertSeverity.MEDIUM: "🟡",
        AlertSeverity.LOW: "🔵",
        AlertSeverity.INFO: "⚪",
    }
    
    async def send(self, alert: Alert) -> bool:
        icon = self.SEVERITY_ICONS.get(alert.severity, "•")
        print(f"\n{icon} ALERT [{alert.severity.value.upper()}]: {alert.name}")
        print(f"   {alert.message}")
        if alert.labels:
            print(f"   Labels: {alert.labels}")
        print()
        return True
    
    def name(self) -> str:
        return "console"


class EmailChannel(NotificationChannel):
    """إشعار البريد الإلكتروني"""
    
    def __init__(
        self,
        smtp_host: str,
        smtp_port: int,
        username: str,
        password: str,
        from_addr: str,
        to_addrs: List[str],
        use_tls: bool = True,
    ):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.from_addr = from_addr
        self.to_addrs = to_addrs
        self.use_tls = use_tls
    
    async def send(self, alert: Alert) -> bool:
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[{alert.severity.value.upper()}] {alert.name}"
            msg["From"] = self.from_addr
            msg["To"] = ", ".join(self.to_addrs)
            
            # Text version
            text = f"""
Alert: {alert.name}
Severity: {alert.severity.value}
Message: {alert.message}
Time: {alert.fired_at.isoformat()}
Labels: {json.dumps(alert.labels)}
            """
            
            # HTML version
            html = f"""
<html>
<body>
<h2 style="color: {'red' if alert.severity == AlertSeverity.CRITICAL else 'orange'};">
    Alert: {alert.name}
</h2>
<p><strong>Severity:</strong> {alert.severity.value}</p>
<p><strong>Message:</strong> {alert.message}</p>
<p><strong>Time:</strong> {alert.fired_at.isoformat()}</p>
<p><strong>Labels:</strong> <code>{json.dumps(alert.labels)}</code></p>
</body>
</html>
            """
            
            msg.attach(MIMEText(text, "plain"))
            msg.attach(MIMEText(html, "html"))
            
            # Send
            if self.use_tls:
                server = smtplib.SMTP(self.smtp_host, self.smtp_port)
                server.starttls()
            else:
                server = smtplib.SMTP(self.smtp_host, self.smtp_port)
            
            server.login(self.username, self.password)
            server.sendmail(self.from_addr, self.to_addrs, msg.as_string())
            server.quit()
            
            return True
            
        except Exception as e:
            logger.error("Email send failed: %s", e)
            return False
    
    def name(self) -> str:
        return "email"


class SlackChannel(NotificationChannel):
    """إشعار Slack"""
    
    SEVERITY_COLORS = {
        AlertSeverity.CRITICAL: "#dc3545",
        AlertSeverity.HIGH: "#fd7e14",
        AlertSeverity.MEDIUM: "#ffc107",
        AlertSeverity.LOW: "#17a2b8",
        AlertSeverity.INFO: "#6c757d",
    }
    
    def __init__(self, webhook_url: str, channel: str = "#alerts"):
        self.webhook_url = webhook_url
        self.channel = channel
    
    async def send(self, alert: Alert) -> bool:
        try:
            import aiohttp
            
            payload = {
                "channel": self.channel,
                "username": "ReconnV2 Alerts",
                "icon_emoji": ":warning:",
                "attachments": [{
                    "color": self.SEVERITY_COLORS.get(alert.severity, "#6c757d"),
                    "title": f"[{alert.severity.value.upper()}] {alert.name}",
                    "text": alert.message,
                    "fields": [
                        {"title": k, "value": v, "short": True}
                        for k, v in alert.labels.items()
                    ],
                    "footer": f"Fired at {alert.fired_at.isoformat()}",
                }],
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(self.webhook_url, json=payload) as resp:
                    return resp.status == 200
                    
        except ImportError:
            logger.warning("aiohttp required for Slack notifications")
            return False
        except Exception as e:
            logger.error("Slack send failed: %s", e)
            return False
    
    def name(self) -> str:
        return "slack"


class DiscordChannel(NotificationChannel):
    """إشعار Discord"""
    
    SEVERITY_COLORS = {
        AlertSeverity.CRITICAL: 0xdc3545,
        AlertSeverity.HIGH: 0xfd7e14,
        AlertSeverity.MEDIUM: 0xffc107,
        AlertSeverity.LOW: 0x17a2b8,
        AlertSeverity.INFO: 0x6c757d,
    }
    
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
    
    async def send(self, alert: Alert) -> bool:
        try:
            import aiohttp
            
            payload = {
                "embeds": [{
                    "title": f"[{alert.severity.value.upper()}] {alert.name}",
                    "description": alert.message,
                    "color": self.SEVERITY_COLORS.get(alert.severity, 0x6c757d),
                    "fields": [
                        {"name": k, "value": v, "inline": True}
                        for k, v in alert.labels.items()
                    ],
                    "footer": {"text": f"Fired at {alert.fired_at.isoformat()}"},
                }],
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(self.webhook_url, json=payload) as resp:
                    return resp.status in (200, 204)
                    
        except ImportError:
            logger.warning("aiohttp required for Discord notifications")
            return False
        except Exception as e:
            logger.error("Discord send failed: %s", e)
            return False
    
    def name(self) -> str:
        return "discord"


class TelegramChannel(NotificationChannel):
    """إشعار Telegram"""
    
    def __init__(self, bot_token: str, chat_id: str):
        self.bot_token = bot_token
        self.chat_id = chat_id
    
    async def send(self, alert: Alert) -> bool:
        try:
            import aiohttp
            
            severity_emoji = {
                AlertSeverity.CRITICAL: "🔴",
                AlertSeverity.HIGH: "🟠",
                AlertSeverity.MEDIUM: "🟡",
                AlertSeverity.LOW: "🔵",
                AlertSeverity.INFO: "⚪",
            }
            
            emoji = severity_emoji.get(alert.severity, "⚪")
            
            text = f"""
{emoji} *{alert.severity.value.upper()}*: {alert.name}

{alert.message}

_Labels:_ `{json.dumps(alert.labels)}`
_Time:_ {alert.fired_at.strftime("%Y-%m-%d %H:%M:%S")}
            """
            
            url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json={
                    "chat_id": self.chat_id,
                    "text": text,
                    "parse_mode": "Markdown",
                }) as resp:
                    return resp.status == 200
                    
        except ImportError:
            logger.warning("aiohttp required for Telegram notifications")
            return False
        except Exception as e:
            logger.error("Telegram send failed: %s", e)
            return False
    
    def name(self) -> str:
        return "telegram"


class WebhookChannel(NotificationChannel):
    """إشعار Webhook عام"""
    
    def __init__(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        method: str = "POST",
    ):
        self.url = url
        self.headers = headers or {}
        self.method = method
    
    async def send(self, alert: Alert) -> bool:
        try:
            import aiohttp
            
            async with aiohttp.ClientSession() as session:
                async with session.request(
                    self.method,
                    self.url,
                    json=alert.to_dict(),
                    headers=self.headers,
                ) as resp:
                    return resp.status < 400
                    
        except ImportError:
            logger.warning("aiohttp required for webhook notifications")
            return False
        except Exception as e:
            logger.error("Webhook send failed: %s", e)
            return False
    
    def name(self) -> str:
        return f"webhook:{self.url}"


# ═══════════════════════════════════════════════════════════
#                     Alerter
# ═══════════════════════════════════════════════════════════

class Alerter:
    """
    نظام التنبيهات.
    
    Example:
        >>> alerter = Alerter()
        >>> 
        >>> # إضافة قناة
        >>> alerter.add_channel(ConsoleChannel())
        >>> alerter.add_channel(SlackChannel(webhook_url="..."))
        >>> 
        >>> # إضافة قاعدة
        >>> alerter.add_rule(AlertRule(
        ...     name="critical-vulns",
        ...     condition=lambda ctx: ctx.get("critical_count", 0) > 0,
        ...     severity=AlertSeverity.CRITICAL,
        ...     message=lambda ctx: f"Found {ctx['critical_count']} critical vulnerabilities!",
        ... ))
        >>> 
        >>> # تقييم
        >>> await alerter.check({"critical_count": 5})
    """
    
    def __init__(self):
        self._rules: Dict[str, AlertRule] = {}
        self._channels: Dict[str, NotificationChannel] = {}
        self._active_alerts: Dict[str, Alert] = {}
        self._history: List[Alert] = []
        self._lock = threading.Lock()
        
        self._max_history = 1000
    
    def add_rule(self, rule: AlertRule) -> None:
        """إضافة قاعدة"""
        self._rules[rule.name] = rule
        logger.debug("Added alert rule: %s", rule.name)
    
    def remove_rule(self, name: str) -> bool:
        """إزالة قاعدة"""
        if name in self._rules:
            del self._rules[name]
            return True
        return False
    
    def add_channel(self, channel: NotificationChannel) -> None:
        """إضافة قناة"""
        self._channels[channel.name()] = channel
        logger.debug("Added notification channel: %s", channel.name())
    
    def remove_channel(self, name: str) -> bool:
        """إزالة قناة"""
        if name in self._channels:
            del self._channels[name]
            return True
        return False
    
    async def check(self, context: Dict[str, Any]) -> List[Alert]:
        """
        تقييم جميع القواعد.
        
        Args:
            context: بيانات السياق للتقييم
            
        Returns:
            قائمة التنبيهات المُطلقة
        """
        fired_alerts = []
        
        for rule in self._rules.values():
            alert = rule.evaluate(context)
            
            if alert:
                # Check if already active
                if alert.id in self._active_alerts:
                    continue
                
                with self._lock:
                    self._active_alerts[alert.id] = alert
                    self._history.append(alert)
                    
                    # Trim history
                    if len(self._history) > self._max_history:
                        self._history = self._history[-self._max_history:]
                
                # Send notifications
                await self._notify(alert, rule.channels)
                
                fired_alerts.append(alert)
        
        return fired_alerts
    
    async def _notify(
        self,
        alert: Alert,
        channels: Optional[List[AlertChannel]] = None,
    ) -> None:
        """إرسال الإشعارات"""
        target_channels = []
        
        if channels:
            for ch in channels:
                if ch.value in self._channels:
                    target_channels.append(self._channels[ch.value])
        else:
            target_channels = list(self._channels.values())
        
        for channel in target_channels:
            try:
                success = await channel.send(alert)
                if success:
                    alert.notified_channels.add(channel.name())
                    alert.notification_count += 1
            except Exception as e:
                logger.error("Notification failed (%s): %s", channel.name(), e)
    
    def resolve(self, alert_id: str) -> bool:
        """حل تنبيه"""
        with self._lock:
            if alert_id in self._active_alerts:
                alert = self._active_alerts[alert_id]
                alert.resolve()
                del self._active_alerts[alert_id]
                return True
        return False
    
    def silence(self, alert_id: str, duration: timedelta) -> bool:
        """كتم تنبيه"""
        with self._lock:
            if alert_id in self._active_alerts:
                self._active_alerts[alert_id].silence(duration)
                return True
        return False
    
    def get_active_alerts(self) -> List[Alert]:
        """التنبيهات النشطة"""
        with self._lock:
            return list(self._active_alerts.values())
    
    def get_history(
        self,
        severity: Optional[AlertSeverity] = None,
        limit: int = 100,
    ) -> List[Alert]:
        """سجل التنبيهات"""
        with self._lock:
            alerts = self._history.copy()
        
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        
        return sorted(alerts, key=lambda a: a.fired_at, reverse=True)[:limit]
    
    def stats(self) -> Dict[str, Any]:
        """إحصائيات"""
        with self._lock:
            active = self._active_alerts.values()
            
            by_severity = {}
            for alert in active:
                sev = alert.severity.value
                by_severity[sev] = by_severity.get(sev, 0) + 1
            
            return {
                "active_alerts": len(self._active_alerts),
                "total_history": len(self._history),
                "rules_count": len(self._rules),
                "channels_count": len(self._channels),
                "by_severity": by_severity,
            }


# ═══════════════════════════════════════════════════════════
#                     Predefined Rules
# ═══════════════════════════════════════════════════════════

def create_default_rules() -> List[AlertRule]:
    """
    قواعد افتراضية.
    
    Returns:
        قائمة القواعد الافتراضية
    """
    return [
        AlertRule(
            name="critical-vulnerabilities",
            condition=lambda ctx: ctx.get("critical_vulns", 0) > 0,
            severity=AlertSeverity.CRITICAL,
            message=lambda ctx: f"Found {ctx.get('critical_vulns', 0)} critical vulnerabilities!",
            cooldown_seconds=60,
        ),
        
        AlertRule(
            name="high-vulnerabilities",
            condition=lambda ctx: ctx.get("high_vulns", 0) > 5,
            severity=AlertSeverity.HIGH,
            message=lambda ctx: f"Found {ctx.get('high_vulns', 0)} high severity vulnerabilities",
            cooldown_seconds=300,
        ),
        
        AlertRule(
            name="scan-failed",
            condition=lambda ctx: ctx.get("scan_status") == "failed",
            severity=AlertSeverity.HIGH,
            message=lambda ctx: f"Scan failed: {ctx.get('error_message', 'Unknown error')}",
            cooldown_seconds=60,
        ),
        
        AlertRule(
            name="high-error-rate",
            condition=lambda ctx: ctx.get("error_rate", 0) > 0.2,
            severity=AlertSeverity.MEDIUM,
            message=lambda ctx: f"Error rate is {ctx.get('error_rate', 0)*100:.1f}%",
            cooldown_seconds=600,
        ),
        
        AlertRule(
            name="scan-timeout",
            condition=lambda ctx: ctx.get("timed_out", False),
            severity=AlertSeverity.MEDIUM,
            message=lambda ctx: f"Scan timed out after {ctx.get('duration', 0)} seconds",
            cooldown_seconds=300,
        ),
        
        AlertRule(
            name="new-subdomain",
            condition=lambda ctx: ctx.get("new_subdomains", 0) > 0,
            severity=AlertSeverity.INFO,
            message=lambda ctx: f"Discovered {ctx.get('new_subdomains', 0)} new subdomains",
            cooldown_seconds=3600,
        ),
        
        AlertRule(
            name="secrets-exposed",
            condition=lambda ctx: ctx.get("secrets_count", 0) > 0,
            severity=AlertSeverity.CRITICAL,
            message=lambda ctx: f"Found {ctx.get('secrets_count', 0)} exposed secrets!",
            cooldown_seconds=60,
        ),
    ]


# ═══════════════════════════════════════════════════════════
#                     Global Alerter
# ═══════════════════════════════════════════════════════════

# Default alerter
alerter = Alerter()

# Add console channel by default
alerter.add_channel(ConsoleChannel())


def get_alerter() -> Alerter:
    """الحصول على المُنبه"""
    return alerter


def configure_alerter(
    channels: Optional[List[NotificationChannel]] = None,
    rules: Optional[List[AlertRule]] = None,
) -> Alerter:
    """تكوين المُنبه"""
    global alerter
    alerter = Alerter()
    
    for channel in (channels or [ConsoleChannel()]):
        alerter.add_channel(channel)
    
    for rule in (rules or create_default_rules()):
        alerter.add_rule(rule)
    
    return alerter
