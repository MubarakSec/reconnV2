"""
Tool Mocks - Mocks للأدوات الخارجية

مثل:
- subfinder, nuclei, httpx
- naabu, dalfox, sqlmap
- uncover, katana
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple
from unittest.mock import AsyncMock, MagicMock, patch


# ═══════════════════════════════════════════════════════════
#                     Base Mock Tool
# ═══════════════════════════════════════════════════════════


@dataclass
class MockToolBase:
    """قاعدة Mock للأدوات"""

    tool_name: str
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""
    delay: float = 0.0
    should_fail: bool = False

    async def run(
        self,
        *args: str,
        stdin: Optional[bytes] = None,
        **kwargs,
    ) -> Tuple[bytes, bytes]:
        """تشغيل الأداة"""
        if self.delay:
            await asyncio.sleep(self.delay)

        if self.should_fail:
            return (b"", f"Error: {self.tool_name} failed".encode())

        return (self.stdout.encode(), self.stderr.encode())

    def create_process_mock(self) -> MagicMock:
        """إنشاء process mock"""
        process = MagicMock()
        process.returncode = 1 if self.should_fail else self.returncode
        process.communicate = AsyncMock(return_value=self.run_sync())
        process.wait = AsyncMock(return_value=process.returncode)
        process.kill = MagicMock()
        return process

    def run_sync(self) -> Tuple[bytes, bytes]:
        """نسخة متزامنة"""
        if self.should_fail:
            return (b"", f"Error: {self.tool_name} failed".encode())
        return (self.stdout.encode(), self.stderr.encode())


# ═══════════════════════════════════════════════════════════
#                     Mock Subfinder
# ═══════════════════════════════════════════════════════════


@dataclass
class MockSubfinder(MockToolBase):
    """Mock لـ subfinder"""

    tool_name: str = "subfinder"
    domains: List[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.domains:
            self.domains = [
                "www.example.com",
                "api.example.com",
                "admin.example.com",
                "mail.example.com",
                "blog.example.com",
            ]
        self.stdout = "\n".join(self.domains)

    @classmethod
    def with_domains(cls, domains: List[str]) -> "MockSubfinder":
        """إنشاء مع domains محددة"""
        mock = cls()
        mock.domains = domains
        mock.stdout = "\n".join(domains)
        return mock

    @classmethod
    def empty(cls) -> "MockSubfinder":
        """إنشاء فارغ"""
        mock = cls()
        mock.domains = []
        mock.stdout = ""
        return mock


# ═══════════════════════════════════════════════════════════
#                     Mock Nuclei
# ═══════════════════════════════════════════════════════════


@dataclass
class MockNuclei(MockToolBase):
    """Mock لـ nuclei"""

    tool_name: str = "nuclei"
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        if not self.vulnerabilities:
            self.vulnerabilities = [
                {
                    "template-id": "xss-reflected",
                    "info": {"name": "Reflected XSS", "severity": "high"},
                    "host": "https://example.com/search?q=test",
                    "matched-at": "https://example.com/search?q=<script>",
                },
                {
                    "template-id": "sql-injection",
                    "info": {"name": "SQL Injection", "severity": "critical"},
                    "host": "https://example.com/user?id=1",
                    "matched-at": "https://example.com/user?id=1'",
                },
            ]
        self.stdout = "\n".join(json.dumps(v) for v in self.vulnerabilities)

    @classmethod
    def with_vulns(cls, vulns: List[Dict[str, Any]]) -> "MockNuclei":
        """إنشاء مع ثغرات محددة"""
        mock = cls()
        mock.vulnerabilities = vulns
        mock.stdout = "\n".join(json.dumps(v) for v in vulns)
        return mock

    @classmethod
    def clean(cls) -> "MockNuclei":
        """إنشاء بدون ثغرات"""
        mock = cls()
        mock.vulnerabilities = []
        mock.stdout = ""
        return mock


# ═══════════════════════════════════════════════════════════
#                     Mock Httpx
# ═══════════════════════════════════════════════════════════


@dataclass
class MockHttpx(MockToolBase):
    """Mock لـ httpx-toolkit"""

    tool_name: str = "httpx"
    responses: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        if not self.responses:
            self.responses = [
                {
                    "url": "https://www.example.com",
                    "status_code": 200,
                    "title": "Example Domain",
                    "content_length": 1256,
                    "technologies": ["nginx"],
                },
                {
                    "url": "https://api.example.com",
                    "status_code": 200,
                    "title": "API",
                    "content_length": 256,
                    "technologies": ["nginx", "express"],
                },
            ]
        self.stdout = "\n".join(json.dumps(r) for r in self.responses)

    @classmethod
    def with_responses(cls, responses: List[Dict[str, Any]]) -> "MockHttpx":
        """إنشاء مع responses محددة"""
        mock = cls()
        mock.responses = responses
        mock.stdout = "\n".join(json.dumps(r) for r in responses)
        return mock


# ═══════════════════════════════════════════════════════════
#                     Mock Naabu
# ═══════════════════════════════════════════════════════════


@dataclass
class MockNaabu(MockToolBase):
    """Mock لـ naabu (port scanner)"""

    tool_name: str = "naabu"
    ports: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        if not self.ports:
            self.ports = [
                {"host": "example.com", "port": 80, "protocol": "tcp"},
                {"host": "example.com", "port": 443, "protocol": "tcp"},
                {"host": "example.com", "port": 22, "protocol": "tcp"},
                {"host": "example.com", "port": 8080, "protocol": "tcp"},
            ]
        self.stdout = "\n".join(json.dumps(p) for p in self.ports)

    @classmethod
    def with_ports(cls, ports: List[Dict[str, Any]]) -> "MockNaabu":
        """إنشاء مع ports محددة"""
        mock = cls()
        mock.ports = ports
        mock.stdout = "\n".join(json.dumps(p) for p in ports)
        return mock


# ═══════════════════════════════════════════════════════════
#                     Mock Dalfox
# ═══════════════════════════════════════════════════════════


@dataclass
class MockDalfox(MockToolBase):
    """Mock لـ dalfox (XSS scanner)"""

    tool_name: str = "dalfox"
    xss_results: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        if not self.xss_results:
            self.xss_results = [
                {
                    "type": "reflected",
                    "url": "https://example.com/search?q=test",
                    "param": "q",
                    "payload": "<script>alert(1)</script>",
                    "verified": True,
                },
            ]
        self.stdout = "\n".join(json.dumps(x) for x in self.xss_results)

    @classmethod
    def with_xss(cls, xss: List[Dict[str, Any]]) -> "MockDalfox":
        """إنشاء مع XSS محددة"""
        mock = cls()
        mock.xss_results = xss
        mock.stdout = "\n".join(json.dumps(x) for x in xss)
        return mock


# ═══════════════════════════════════════════════════════════
#                     Mock Sqlmap
# ═══════════════════════════════════════════════════════════


@dataclass
class MockSqlmap(MockToolBase):
    """Mock لـ sqlmap"""

    tool_name: str = "sqlmap"
    sqli_results: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        if not self.sqli_results:
            self.sqli_results = [
                {
                    "target": "https://example.com/user?id=1",
                    "parameter": "id",
                    "type": "error-based",
                    "dbms": "MySQL",
                    "injectable": True,
                },
            ]
        # sqlmap outputs to stderr mostly
        output = "\n".join(json.dumps(s) for s in self.sqli_results)
        self.stdout = output


# ═══════════════════════════════════════════════════════════
#                     Mock Tool Executor
# ═══════════════════════════════════════════════════════════


class MockToolExecutor:
    """Mock لـ ToolExecutor"""

    def __init__(self):
        self.tools: Dict[str, MockToolBase] = {
            "subfinder": MockSubfinder(),
            "nuclei": MockNuclei(),
            "httpx": MockHttpx(),
            "naabu": MockNaabu(),
            "dalfox": MockDalfox(),
            "sqlmap": MockSqlmap(),
        }
        self.call_history: List[Tuple[str, List[str]]] = []

    def register_tool(self, name: str, mock: MockToolBase) -> None:
        """تسجيل أداة"""
        self.tools[name] = mock

    async def run(
        self,
        tool: str,
        args: List[str],
        stdin: Optional[bytes] = None,
        timeout: float = 300.0,
    ) -> Dict[str, Any]:
        """تشغيل أداة"""
        self.call_history.append((tool, args))

        if tool not in self.tools:
            return {
                "success": False,
                "error": f"Tool not found: {tool}",
                "stdout": "",
                "stderr": "",
            }

        mock = self.tools[tool]
        stdout, stderr = await mock.run(*args, stdin=stdin)

        return {
            "success": not mock.should_fail,
            "stdout": stdout.decode(),
            "stderr": stderr.decode(),
            "returncode": mock.returncode,
        }

    async def run_streaming(
        self,
        tool: str,
        args: List[str],
        on_line: Callable[[str], None],
        stdin: Optional[bytes] = None,
    ) -> Dict[str, Any]:
        """تشغيل مع streaming"""
        result = await self.run(tool, args, stdin)

        if result["success"]:
            for line in result["stdout"].split("\n"):
                if line.strip():
                    on_line(line)

        return result

    def is_available(self, tool: str) -> bool:
        """التحقق من توفر أداة"""
        return tool in self.tools and not self.tools[tool].should_fail

    def get_calls(self, tool: str) -> List[List[str]]:
        """الحصول على استدعاءات أداة"""
        return [args for t, args in self.call_history if t == tool]

    def reset(self) -> None:
        """إعادة تعيين"""
        self.call_history.clear()


# ═══════════════════════════════════════════════════════════
#                     Context Managers
# ═══════════════════════════════════════════════════════════


def mock_tool_available(tool_name: str):
    """Mock لأداة متوفرة"""
    return patch("shutil.which", return_value=f"/usr/bin/{tool_name}")


def mock_tool_unavailable(tool_name: str):
    """Mock لأداة غير متوفرة"""
    original_which = __import__("shutil").which

    def selective_which(name):
        if name == tool_name:
            return None
        return original_which(name)

    return patch("shutil.which", side_effect=selective_which)


def mock_subprocess_exec(*mocks: MockToolBase):
    """Mock لـ subprocess.exec"""
    mock_map = {m.tool_name: m for m in mocks}

    async def create_mock_process(*args, **kwargs):
        tool = args[0] if args else ""

        # Extract tool name from path
        tool_name = tool.split("/")[-1] if "/" in tool else tool

        if tool_name in mock_map:
            return mock_map[tool_name].create_process_mock()

        # Default mock
        process = MagicMock()
        process.returncode = 0
        process.communicate = AsyncMock(return_value=(b"", b""))
        process.wait = AsyncMock(return_value=0)
        return process

    return patch("asyncio.create_subprocess_exec", side_effect=create_mock_process)


# ═══════════════════════════════════════════════════════════
#                     Fixtures (for conftest.py)
# ═══════════════════════════════════════════════════════════


def create_mock_executor() -> MockToolExecutor:
    """إنشاء mock executor"""
    return MockToolExecutor()


def create_failing_executor() -> MockToolExecutor:
    """إنشاء failing executor"""
    executor = MockToolExecutor()
    for tool in executor.tools.values():
        tool.should_fail = True
    return executor


def create_slow_executor(delay: float = 1.0) -> MockToolExecutor:
    """إنشاء slow executor"""
    executor = MockToolExecutor()
    for tool in executor.tools.values():
        tool.delay = delay
    return executor
