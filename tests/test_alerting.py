"""
Unit Tests for Alerting System

اختبارات:
- Alert channels
- Alert rules
- Alert manager
- Rate limiting
"""

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ═══════════════════════════════════════════════════════════
#                     Import Module
# ═══════════════════════════════════════════════════════════

try:
    from recon_cli.utils.alerting import (
        Alert,
        AlertLevel,
        SlackChannel,
        DiscordChannel,
        TelegramChannel,
        WebhookChannel,
        EmailChannel,
        AlertRule,
        AlertManager,
    )

    HAS_ALERTING = True
except ImportError:
    HAS_ALERTING = False


pytestmark = [
    pytest.mark.skipif(not HAS_ALERTING, reason="alerting not available"),
]


# ═══════════════════════════════════════════════════════════
#                     Alert Tests
# ═══════════════════════════════════════════════════════════


class TestAlert:
    """اختبارات Alert"""

    def test_create_alert(self):
        """إنشاء تنبيه"""
        alert = Alert(
            level=AlertLevel.WARNING,
            title="Test Alert",
            message="This is a test alert",
        )

        assert alert.level == AlertLevel.WARNING
        assert alert.title == "Test Alert"
        assert alert.message == "This is a test alert"

    def test_alert_with_metadata(self):
        """تنبيه مع metadata"""
        alert = Alert(
            level=AlertLevel.ERROR,
            title="Error Alert",
            message="An error occurred",
            metadata={
                "job_id": "123",
                "error_code": "E001",
            },
        )

        assert alert.metadata["job_id"] == "123"
        assert alert.metadata["error_code"] == "E001"

    def test_alert_timestamp(self):
        """timestamp التنبيه"""
        before = datetime.now()
        alert = Alert(
            level=AlertLevel.INFO,
            title="Test",
            message="Test",
        )
        after = datetime.now()

        assert before <= alert.timestamp <= after

    def test_alert_levels(self):
        """مستويات التنبيه"""
        assert AlertLevel.DEBUG.value < AlertLevel.INFO.value
        assert AlertLevel.INFO.value < AlertLevel.WARNING.value
        assert AlertLevel.WARNING.value < AlertLevel.ERROR.value
        assert AlertLevel.ERROR.value < AlertLevel.CRITICAL.value


# ═══════════════════════════════════════════════════════════
#                     Slack Channel Tests
# ═══════════════════════════════════════════════════════════


class TestSlackChannel:
    """اختبارات Slack Channel"""

    @pytest.mark.asyncio
    async def test_send_alert(self):
        """إرسال تنبيه"""
        with patch("aiohttp.ClientSession") as mock_session:
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.__aenter__ = AsyncMock(return_value=mock_response)
            mock_response.__aexit__ = AsyncMock()

            session_instance = MagicMock()
            session_instance.post.return_value = mock_response
            session_instance.close = AsyncMock()
            session_instance.__aenter__ = AsyncMock(return_value=session_instance)
            session_instance.__aexit__ = AsyncMock()
            mock_session.return_value = session_instance

            channel = SlackChannel(webhook_url="https://hooks.slack.com/test")

            alert = Alert(
                level=AlertLevel.WARNING,
                title="Test Alert",
                message="Test message",
            )

            result = await channel.send(alert)

            assert result is True

    def test_format_message(self):
        """تنسيق الرسالة"""
        channel = SlackChannel(webhook_url="https://hooks.slack.com/test")

        alert = Alert(
            level=AlertLevel.ERROR,
            title="Error Alert",
            message="An error occurred",
        )

        payload = channel.format_payload(alert)

        assert "Error Alert" in str(payload) or "error" in str(payload).lower()


# ═══════════════════════════════════════════════════════════
#                     Discord Channel Tests
# ═══════════════════════════════════════════════════════════


class TestDiscordChannel:
    """اختبارات Discord Channel"""

    @pytest.mark.asyncio
    async def test_send_alert(self):
        """إرسال تنبيه"""
        with patch("aiohttp.ClientSession") as mock_session:
            mock_response = MagicMock()
            mock_response.status = 204
            mock_response.__aenter__ = AsyncMock(return_value=mock_response)
            mock_response.__aexit__ = AsyncMock()

            session_instance = MagicMock()
            session_instance.post.return_value = mock_response
            session_instance.close = AsyncMock()
            session_instance.__aenter__ = AsyncMock(return_value=session_instance)
            session_instance.__aexit__ = AsyncMock()
            mock_session.return_value = session_instance

            channel = DiscordChannel(
                webhook_url="https://discord.com/api/webhooks/test"
            )

            alert = Alert(
                level=AlertLevel.CRITICAL,
                title="Critical Alert",
                message="Critical issue detected",
            )

            result = await channel.send(alert)

            assert result is True


# ═══════════════════════════════════════════════════════════
#                     Telegram Channel Tests
# ═══════════════════════════════════════════════════════════


class TestTelegramChannel:
    """اختبارات Telegram Channel"""

    @pytest.mark.asyncio
    async def test_send_alert(self):
        """إرسال تنبيه"""
        with patch("aiohttp.ClientSession") as mock_session:
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={"ok": True})
            mock_response.__aenter__ = AsyncMock(return_value=mock_response)
            mock_response.__aexit__ = AsyncMock()

            session_instance = MagicMock()
            session_instance.post.return_value = mock_response
            session_instance.close = AsyncMock()
            session_instance.__aenter__ = AsyncMock(return_value=session_instance)
            session_instance.__aexit__ = AsyncMock()
            mock_session.return_value = session_instance

            channel = TelegramChannel(
                bot_token="123456:ABC-DEF",
                chat_id="-1001234567890",
            )

            alert = Alert(
                level=AlertLevel.INFO,
                title="Info Alert",
                message="Information message",
            )

            result = await channel.send(alert)

            assert result is True


# ═══════════════════════════════════════════════════════════
#                     Webhook Channel Tests
# ═══════════════════════════════════════════════════════════


class TestWebhookChannel:
    """اختبارات Webhook Channel"""

    @pytest.mark.asyncio
    async def test_send_alert(self):
        """إرسال تنبيه"""
        with patch("aiohttp.ClientSession") as mock_session:
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.__aenter__ = AsyncMock(return_value=mock_response)
            mock_response.__aexit__ = AsyncMock()

            session_instance = MagicMock()
            session_instance.post.return_value = mock_response
            session_instance.close = AsyncMock()
            session_instance.__aenter__ = AsyncMock(return_value=session_instance)
            session_instance.__aexit__ = AsyncMock()
            mock_session.return_value = session_instance

            channel = WebhookChannel(url="https://example.com/webhook")

            alert = Alert(
                level=AlertLevel.WARNING,
                title="Webhook Alert",
                message="Custom webhook message",
            )

            result = await channel.send(alert)

            assert result is True

    def test_custom_headers(self):
        """headers مخصصة"""
        channel = WebhookChannel(
            url="https://example.com/webhook",
            headers={"Authorization": "Bearer token123"},
        )

        assert channel.headers.get("Authorization") == "Bearer token123"


# ═══════════════════════════════════════════════════════════
#                     Alert Rule Tests
# ═══════════════════════════════════════════════════════════


class TestAlertRule:
    """اختبارات Alert Rule"""

    def test_create_rule(self):
        """إنشاء قاعدة"""
        rule = AlertRule(
            name="high_cpu",
            condition=lambda metrics: metrics.get("cpu", 0) > 80,
            alert_level=AlertLevel.WARNING,
            message="High CPU usage detected",
        )

        assert rule.name == "high_cpu"
        assert rule.alert_level == AlertLevel.WARNING

    def test_rule_matches(self):
        """مطابقة القاعدة"""
        rule = AlertRule(
            name="high_cpu",
            condition=lambda metrics: metrics.get("cpu", 0) > 80,
            alert_level=AlertLevel.WARNING,
            message="High CPU usage",
        )

        # Should match
        assert rule.matches({"cpu": 90})

        # Should not match
        assert not rule.matches({"cpu": 50})

    def test_rule_cooldown(self):
        """فترة التهدئة"""
        rule = AlertRule(
            name="test_rule",
            condition=lambda m: True,
            alert_level=AlertLevel.INFO,
            message="Test",
            cooldown_seconds=60,
        )

        # First trigger should work
        assert rule.should_fire()
        rule.record_fire()

        # Second trigger within cooldown should not work
        assert not rule.should_fire()


# ═══════════════════════════════════════════════════════════
#                     Alert Manager Tests
# ═══════════════════════════════════════════════════════════


class TestAlertManager:
    """اختبارات Alert Manager"""

    def test_add_channel(self):
        """إضافة channel"""
        manager = AlertManager()

        channel = WebhookChannel(url="https://example.com/webhook")
        manager.add_channel("webhook", channel)

        assert "webhook" in manager.channels

    def test_add_rule(self):
        """إضافة قاعدة"""
        manager = AlertManager()

        rule = AlertRule(
            name="test_rule",
            condition=lambda m: True,
            alert_level=AlertLevel.INFO,
            message="Test",
        )
        manager.add_rule(rule)

        assert len(manager.rules) == 1

    @pytest.mark.asyncio
    async def test_send_alert(self):
        """إرسال تنبيه"""
        with patch("aiohttp.ClientSession") as mock_session:
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.__aenter__ = AsyncMock(return_value=mock_response)
            mock_response.__aexit__ = AsyncMock()

            session_instance = MagicMock()
            session_instance.post.return_value = mock_response
            session_instance.close = AsyncMock()
            session_instance.__aenter__ = AsyncMock(return_value=session_instance)
            session_instance.__aexit__ = AsyncMock()
            mock_session.return_value = session_instance

            manager = AlertManager()
            channel = WebhookChannel(url="https://example.com/webhook")
            manager.add_channel("webhook", channel)

            alert = Alert(
                level=AlertLevel.WARNING,
                title="Test",
                message="Test message",
            )

            results = await manager.send_alert(alert)

            assert results == {"webhook": True}

    @pytest.mark.asyncio
    async def test_filter_by_level(self):
        """تصفية حسب المستوى"""
        manager = AlertManager(min_level=AlertLevel.WARNING)

        # Add mock channel
        mock_channel = MagicMock()
        mock_channel.send = AsyncMock(return_value=True)
        manager.add_channel("mock", mock_channel)

        # Info alert should be filtered
        info_alert = Alert(
            level=AlertLevel.INFO,
            title="Info",
            message="Info message",
        )

        await manager.send_alert(info_alert)

        # Should not send (filtered)
        mock_channel.send.assert_not_called()

    @pytest.mark.asyncio
    async def test_check_rules(self):
        """التحقق من القواعد"""
        manager = AlertManager()

        # Add mock channel
        mock_channel = MagicMock()
        mock_channel.send = AsyncMock(return_value=True)
        manager.add_channel("mock", mock_channel)

        # Add rule
        rule = AlertRule(
            name="high_value",
            condition=lambda m: m.get("value", 0) > 100,
            alert_level=AlertLevel.WARNING,
            message="High value detected",
        )
        manager.add_rule(rule)

        # Check with matching metrics
        await manager.check_rules({"value": 150})

        # Should have sent alert
        mock_channel.send.assert_called()


# ═══════════════════════════════════════════════════════════
#                     Rate Limiting Tests
# ═══════════════════════════════════════════════════════════


class TestAlertRateLimiting:
    """اختبارات Rate Limiting"""

    @pytest.mark.asyncio
    async def test_rate_limit_alerts(self):
        """Rate limit للتنبيهات"""
        manager = AlertManager(rate_limit_per_minute=5)

        mock_channel = MagicMock()
        mock_channel.send = AsyncMock(return_value=True)
        manager.add_channel("mock", mock_channel)

        # Send 10 alerts
        for i in range(10):
            alert = Alert(
                level=AlertLevel.WARNING,
                title=f"Alert {i}",
                message="Test",
            )
            await manager.send_alert(alert)

        assert mock_channel.send.call_count == 5

    @pytest.mark.asyncio
    async def test_deduplication(self):
        """إزالة التكرار"""
        manager = AlertManager(dedupe_window_seconds=60)

        mock_channel = MagicMock()
        mock_channel.send = AsyncMock(return_value=True)
        manager.add_channel("mock", mock_channel)

        # Send same alert twice
        alert = Alert(
            level=AlertLevel.WARNING,
            title="Duplicate Alert",
            message="Same message",
        )

        await manager.send_alert(alert)
        await manager.send_alert(alert)

        assert mock_channel.send.call_count == 1


# ═══════════════════════════════════════════════════════════
#                     Email Channel Tests
# ═══════════════════════════════════════════════════════════


class TestEmailChannel:
    """اختبارات Email Channel"""

    @pytest.mark.asyncio
    async def test_send_alert(self):
        """إرسال تنبيه"""
        with patch("smtplib.SMTP") as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value = mock_server

            channel = EmailChannel(
                smtp_host="smtp.example.com",
                smtp_port=587,
                username="user@example.com",
                password="password",
                from_addr="alerts@example.com",
                to_addrs=["admin@example.com"],
            )

            alert = Alert(
                level=AlertLevel.CRITICAL,
                title="Critical Alert",
                message="Critical issue",
            )

            result = await channel.send(alert)

            assert result is True
            mock_server.starttls.assert_called_once()
            mock_server.login.assert_called_once_with("user@example.com", "password")
            mock_server.sendmail.assert_called_once()
            mock_server.quit.assert_called_once()

    def test_format_email(self):
        """تنسيق البريد"""
        channel = EmailChannel(
            smtp_host="smtp.example.com",
            smtp_port=587,
            username="user@example.com",
            password="password",
            from_addr="alerts@example.com",
            to_addrs=["admin@example.com"],
        )

        alert = Alert(
            level=AlertLevel.ERROR,
            title="Error Alert",
            message="An error occurred",
        )

        subject, body = channel.format_email(alert)
        assert subject == "[HIGH] Error Alert"
        assert "An error occurred" in body
