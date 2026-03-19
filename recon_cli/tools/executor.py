from __future__ import annotations

import logging


"""
Command Executor Module - تنفيذ الأوامر الخارجية

هذا الموديول مسؤول عن تشغيل الأدوات الخارجية مثل subfinder, nuclei, httpx
مع دعم:
- Timeout للأوامر الطويلة
- Redaction للبيانات الحساسة في الـ logs
- Error handling شامل
- كتابة النتائج لملفات

Example:
    >>> executor = CommandExecutor(logger)
    >>> result = executor.run(["subfinder", "-d", "example.com"])
    >>> print(result.stdout)
"""


_MODULE_LOGGER = logging.getLogger(__name__)
_DEFAULT_SESSION_MAX_OUTPUT_CHARS = 262144
_MIN_SESSION_MAX_OUTPUT_CHARS = 128
_DEFAULT_SESSION_MAX_FINISHED = 32
_MIN_SESSION_MAX_FINISHED = 0
_DEFAULT_SESSION_FINISHED_TTL_SECONDS = 86400.0
