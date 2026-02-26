from __future__ import annotations

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

import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Iterable, Mapping, Optional

from recon_cli.utils.sanitizer import redact as redact_text


class CommandError(RuntimeError):
    """
    استثناء لأخطاء تنفيذ الأوامر.
    
    Attributes:
        message: رسالة الخطأ
        returncode: كود الخروج من الأمر (None إذا لم يبدأ)
    
    Example:
        >>> try:
        ...     executor.run(["nonexistent-tool"])
        ... except CommandError as e:
        ...     print(f"Failed with code {e.returncode}: {e}")
    """
    
    def __init__(self, message: str, returncode: int | None = None) -> None:
        super().__init__(message)
        self.returncode = returncode


class CommandExecutor:
    """
    منفذ الأوامر الخارجية مع دعم كامل للـ logging والـ error handling.
    
    يوفر واجهة موحدة لتشغيل أي أداة خارجية مع:
    - تسجيل الأوامر في الـ log
    - إخفاء البيانات الحساسة (API keys, tokens)
    - التعامل مع Timeout
    - كتابة النتائج لملفات
    
    Attributes:
        logger: كائن الـ logger للتسجيل
    
    Example:
        >>> import logging
        >>> logger = logging.getLogger("recon")
        >>> executor = CommandExecutor(logger)
        >>> 
        >>> # تشغيل أمر بسيط
        >>> result = executor.run(["echo", "hello"])
        >>> 
        >>> # تشغيل مع timeout
        >>> result = executor.run(["nuclei", "-u", "target.com"], timeout=300)
        >>> 
        >>> # كتابة النتائج لملف
        >>> executor.run_to_file(["subfinder", "-d", "target.com"], Path("subs.txt"))
    """
    
    def __init__(self, logger) -> None:
        """
        تهيئة المنفذ.
        
        Args:
            logger: كائن logging.Logger للتسجيل
        """
        self.logger = logger

    @staticmethod
    def available(command: str) -> bool:
        """
        التحقق من وجود أداة في النظام.
        
        Args:
            command: اسم الأداة (مثل "subfinder", "nuclei")
            
        Returns:
            True إذا كانت الأداة متاحة، False خلاف ذلك
            
        Example:
            >>> if CommandExecutor.available("subfinder"):
            ...     print("Subfinder is installed")
        """
        return shutil.which(command) is not None

    def run(
        self,
        command: Iterable[str],
        cwd: Optional[Path] = None,
        env: Optional[Mapping[str, str]] = None,
        timeout: Optional[int] = None,
        check: bool = True,
        capture_output: bool = False,
        redact: bool = True,
    ) -> subprocess.CompletedProcess:
        """
        تشغيل أمر خارجي.
        
        Args:
            command: الأمر كقائمة من السلاسل النصية
            cwd: المجلد الذي سيُنفذ فيه الأمر
            env: متغيرات البيئة الإضافية
            timeout: الحد الأقصى للتنفيذ بالثواني
            check: رفع استثناء عند الفشل
            capture_output: التقاط stdout و stderr
            redact: إخفاء البيانات الحساسة في الـ logs
            
        Returns:
            subprocess.CompletedProcess مع نتيجة التنفيذ
            
        Raises:
            CommandError: عند فشل الأمر أو انتهاء الوقت
            
        Example:
            >>> result = executor.run(
            ...     ["httpx", "-l", "urls.txt", "-sc"],
            ...     timeout=120,
            ...     capture_output=True
            ... )
            >>> print(result.stdout)
        """
        cmd_list = [str(part) for part in command]
        command_str = " ".join(shlex.quote(part) for part in cmd_list)
        message = redact_text(command_str) if redact else command_str
        self.logger.info("Executing: %s", message)
        try:
            completed = subprocess.run(
                cmd_list,
                cwd=str(cwd) if cwd else None,
                env=dict(env) if env else None,
                timeout=timeout,
                capture_output=capture_output,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=check,
            )
        except subprocess.TimeoutExpired as exc:
            self.logger.error("Command timed out after %ss: %s", timeout, message)
            raise CommandError(f"Command timeout after {timeout or 'unknown'}s") from exc
        except FileNotFoundError as exc:
            missing = redact_text(cmd_list[0]) if redact else cmd_list[0]
            self.logger.error("Command not found: %s", missing)
            raise CommandError(f"Command not found: {cmd_list[0]}") from exc
        except subprocess.CalledProcessError as exc:
            if capture_output:
                stderr_text = exc.stderr or ""
                if redact:
                    stderr_text = redact_text(stderr_text) or ""
                self.logger.error("Command failed (%s): %s", exc.returncode, stderr_text)
            else:
                self.logger.error("Command failed (%s)", exc.returncode)
            if check:
                raise CommandError(f"Command failed ({exc.returncode})", exc.returncode) from exc
            completed = exc
        return completed

    def run_to_file(
        self,
        command: Iterable[str],
        output_path: Path,
        cwd: Optional[Path] = None,
        env: Optional[Mapping[str, str]] = None,
        redact: bool = True,
        timeout: Optional[int] = None,
    ) -> subprocess.CompletedProcess:
        """
        تشغيل أمر وكتابة النتائج لملف.
        
        يُنفذ الأمر ويكتب stdout (و stderr) لملف محدد.
        مفيد للأوامر التي تُنتج كمية كبيرة من البيانات.
        
        Args:
            command: الأمر كقائمة
            output_path: مسار الملف للكتابة
            cwd: مجلد التنفيذ
            env: متغيرات البيئة
            redact: إخفاء البيانات الحساسة
            timeout: الحد الأقصى للتنفيذ
            
        Returns:
            subprocess.CompletedProcess مع النتيجة
            
        Example:
            >>> executor.run_to_file(
            ...     ["subfinder", "-d", "example.com", "-silent"],
            ...     Path("subdomains.txt"),
            ...     timeout=300
            ... )
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)
        cmd_list = [str(part) for part in command]
        command_str = " ".join(shlex.quote(part) for part in cmd_list)
        message = redact_text(command_str) if redact else command_str
        self.logger.info("Executing: %s", message)
        try:
            with output_path.open("w", encoding="utf-8") as handle:
                completed = subprocess.run(
                    cmd_list,
                    cwd=str(cwd) if cwd else None,
                    env=dict(env) if env else None,
                    stdout=handle,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    check=False,
                    timeout=timeout,
                )
        except subprocess.TimeoutExpired as exc:
            self.logger.error("Command timed out after %ss: %s", timeout, message)
            raise CommandError(f"Command timeout after {timeout or 'unknown'}s") from exc
        except FileNotFoundError as exc:
            missing = redact_text(cmd_list[0]) if redact else cmd_list[0]
            self.logger.error("Command not found: %s", missing)
            raise CommandError(f"Command not found: {cmd_list[0]}") from exc

        if redact:
            tmp_path = output_path.with_suffix(f"{output_path.suffix}.redacted")
            with output_path.open("r", encoding="utf-8", errors="ignore") as src, tmp_path.open(
                "w", encoding="utf-8"
            ) as dst:
                for line in src:
                    redacted = redact_text(line) if line else line
                    dst.write(redacted or "")
            tmp_path.replace(output_path)

        completed.stdout = ""
        if completed.returncode != 0:
            self.logger.warning("Command exited with %s (non-zero)", completed.returncode)
        return completed
