from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List

import aiohttp
from recon_cli.jobs.manager import JobManager
from recon_cli.jobs import summary as jobs_summary

logger = logging.getLogger(__name__)


class TelegramBot:
    """
    Lightweight Telegram Bot for ReconnV2.
    Uses long polling via aiohttp to avoid extra dependencies.
    """

    def __init__(self, token: str, allowed_chat_id: str):
        self.token = token
        # Support comma-separated list of IDs
        self.allowed_chat_ids = {
            str(i).strip() for i in str(allowed_chat_id).split(",") if str(i).strip()
        }
        self.discovery_mode = "discover" in self.allowed_chat_ids

        self.base_url = f"https://api.telegram.org/bot{token}"
        self.manager = JobManager()
        self.offset = 0
        self.running = False

    async def send_message(
        self, chat_id: str, text: str, parse_mode: str = "Markdown"
    ) -> None:
        url = f"{self.base_url}/sendMessage"
        payload = {"chat_id": chat_id, "text": text, "parse_mode": parse_mode}
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload) as resp:
                    if resp.status != 200:
                        logger.error(
                            "Failed to send telegram message: %s", await resp.text()
                        )
        except Exception as e:
            logger.error("Telegram send error: %s", e)

    async def get_updates(self) -> List[Dict[str, Any]]:
        url = f"{self.base_url}/getUpdates"
        params = {"offset": self.offset, "timeout": 30}
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get("result", [])
                    else:
                        logger.error("Failed to get updates: %s", await resp.text())
        except Exception as e:
            logger.error("Telegram update error: %s", e)
        return []

    async def handle_command(self, chat_id: str, text: str) -> None:
        s_chat_id = str(chat_id)

        if s_chat_id not in self.allowed_chat_ids:
            if self.discovery_mode:
                print(
                    f"\n[bold cyan]TELEGRAM DISCOVERY:[/bold cyan] Received message from Chat ID: {s_chat_id}"
                )
                await self.send_message(
                    s_chat_id,
                    f"🆔 Your Telegram Chat ID is: `{s_chat_id}`\n\nTo authorize this ID, restart the bot with this ID added to the Chat ID list.",
                )
                return

            logger.warning("Unauthorized access attempt from chat_id: %s", s_chat_id)
            await self.send_message(
                s_chat_id, "⚠️ Unauthorized. This bot is locked to specific chat IDs."
            )
            return

        parts = text.split()
        if not parts:
            return

        command = parts[0].lower()
        args = parts[1:]

        if command == "/start":
            await self.send_message(
                chat_id,
                "🚀 *ReconnV2 Honest Bot Ready*\n\n"
                "Available commands:\n"
                "/status - Global job status\n"
                "/list - List last 5 jobs\n"
                "/scan <target> [profile] - Start a new scan\n"
                "/report <job_id> - Get job summary\n"
                "/cancel <job_id> - Stop a running job",
            )
        elif command == "/status":
            await self._cmd_status(chat_id)
        elif command == "/list":
            await self._cmd_list(chat_id)
        elif command == "/scan":
            await self._cmd_scan(chat_id, args)
        elif command == "/report":
            await self._cmd_report(chat_id, args)
        elif command == "/cancel":
            await self._cmd_cancel(chat_id, args)
        else:
            await self.send_message(
                chat_id, "❓ Unknown command. Use /start to see available commands."
            )

    async def _cmd_status(self, chat_id: str) -> None:
        counts = self.manager.get_job_counts()
        text = "*📊 ReconnV2 Status*\n\n"
        text += f"🕒 Queued: {counts.get('queued', 0)}\n"
        text += f"🔄 Running: {counts.get('running', 0)}\n"
        text += f"✅ Finished: {counts.get('finished', 0)}\n"
        text += f"❌ Failed: {counts.get('failed', 0)}\n"
        await self.send_message(chat_id, text)

    async def _cmd_list(self, chat_id: str) -> None:
        job_ids = self.manager.list_jobs()
        if not job_ids:
            await self.send_message(chat_id, "No jobs found.")
            return

        text = "*📝 Recent Jobs (Last 5)*\n\n"
        # Take last 5 and load records
        for jid in reversed(job_ids[-5:]):
            job = self.manager.load_job(jid)
            if not job:
                continue
            status_emoji = (
                "✅"
                if job.metadata.status == "finished"
                else "🔄"
                if job.metadata.status == "running"
                else "❌"
                if job.metadata.status == "failed"
                else "🕒"
            )
            text += f"{status_emoji} `{job.metadata.job_id}`\n   Target: {job.spec.target} ({job.spec.profile})\n\n"
        await self.send_message(chat_id, text)

    async def _cmd_scan(self, chat_id: str, args: List[str]) -> None:
        if not args:
            await self.send_message(chat_id, "Usage: `/scan <target> [profile]`")
            return

        target = args[0]
        profile = args[1] if len(args) > 1 else "passive"

        try:
            record = self.manager.create_job(
                target=target, profile=profile, initiator="telegram"
            )
            await self.send_message(
                chat_id, f"✅ Scan queued!\nJob ID: `{record.metadata.job_id}`"
            )
        except Exception as e:
            await self.send_message(chat_id, f"❌ Error launching scan: {str(e)}")

    async def _cmd_report(self, chat_id: str, args: List[str]) -> None:
        if not args:
            await self.send_message(chat_id, "Usage: `/report <job_id>`")
            return

        job_id = args[0]
        record = self.manager.load_job(job_id)
        if not record:
            await self.send_message(chat_id, f"❌ Job `{job_id}` not found.")
            return

        try:
            summary_data = jobs_summary.generate_summary_data(record)
            counts = summary_data.get("counts", {})

            text = f"*📋 Report: {record.spec.target}*\n"
            text += f"Status: {record.metadata.status}\n"
            text += f"Profile: {record.spec.profile}\n\n"

            text += "*Stats:*\n"
            for k, v in counts.items():
                if v > 0:
                    text += f" - {k}: {v}\n"

            await self.send_message(chat_id, text)
        except Exception as e:
            await self.send_message(chat_id, f"❌ Error generating report: {str(e)}")

    async def _cmd_cancel(self, chat_id: str, args: List[str]) -> None:
        if not args:
            await self.send_message(chat_id, "Usage: `/cancel <job_id>`")
            return

        job_id = args[0]
        # Simplistic cancel: write stop.request
        record = self.manager.load_job(job_id)
        if not record:
            await self.send_message(chat_id, f"❌ Job `{job_id}` not found.")
            return

        stop_file = record.paths.root / "stop.request"
        stop_file.touch()
        await self.send_message(chat_id, f"🛑 Stop request sent for `{job_id}`.")

    async def start(self) -> None:
        self.running = True
        logger.info(
            "Telegram Bot started. Authorized IDs: %s", ", ".join(self.allowed_chat_ids)
        )
        if self.discovery_mode:
            logger.info(
                "Discovery Mode is ENABLED. Message the bot to see your Chat ID."
            )

        while self.running:
            updates = await self.get_updates()
            for update in updates:
                self.offset = update["update_id"] + 1
                message = update.get("message")
                if not message:
                    continue

                chat = message.get("chat")
                text = message.get("text")
                if chat and text:
                    await self.handle_command(chat["id"], text)

            await asyncio.sleep(1)

    def stop(self) -> None:
        self.running = False
