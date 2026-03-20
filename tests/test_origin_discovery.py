from unittest.mock import MagicMock
from pathlib import Path
import pytest
from recon_cli.pipeline.stage_origin_discovery import OriginDiscoveryStage
from recon_cli.pipeline.context import PipelineContext

def test_origin_discovery_stage_no_hosts(tmp_path: Path):
    stage = OriginDiscoveryStage()
    record = MagicMock()
    record.paths.artifact.return_value = tmp_path / "dedupe_hosts.txt"
    record.paths.job_dir = tmp_path
    
    class DummyManager:
        pass
        
    context = MagicMock()
    context.record = record
    context.logger = MagicMock()
    context.results = []
    
    stage.execute(context)
    # Should not raise any errors, should just log and return

def test_origin_discovery_stage_with_mock_hosts(tmp_path: Path, monkeypatch):
    stage = OriginDiscoveryStage()
    record = MagicMock()
    hosts_path = tmp_path / "dedupe_hosts.txt"
    hosts_path.write_text("example.com\nwww.example.com\n", encoding="utf-8")
    record.paths.artifact.return_value = hosts_path
    record.paths.job_dir = tmp_path
    
    context = MagicMock()
    context.record = record
    context.logger = MagicMock()
    context.results = []
    
    import dns.resolver
    class DummyResolver:
        def __init__(self, *args, **kwargs):
            self.timeout = 3
            self.lifetime = 3
        def resolve(self, qname, rdtype):
            class RData:
                def __init__(self, txt=None, ex=None):
                    self.txt = txt
                    self.exchange = ex
                def to_text(self):
                    return self.txt or ""
            if rdtype == 'TXT':
                return [RData(txt='"v=spf1 ip4:192.168.1.1"')]
            elif rdtype == 'MX':
                return [RData(ex="mail.example.com.")]
            elif rdtype == 'A':
                if qname == "direct.example.com":
                    return ["10.0.0.2"]
                elif qname == "mail.example.com":
                    return ["10.0.0.1"]
            raise Exception("not found")

    monkeypatch.setattr(dns.resolver, "Resolver", DummyResolver)
    
    import socket
    def fake_gethostbyname_ex(hostname):
        if hostname == "mail.example.com":
            return ("mail.example.com", [], ["10.0.0.1"])
        elif hostname == "direct.example.com":
            return ("direct.example.com", [], ["10.0.0.2"])
        raise socket.error("not found")
    
    monkeypatch.setattr(socket, "gethostbyname_ex", fake_gethostbyname_ex)
    
    # Mock httpx.AsyncClient for verification
    class MockResponse:
        def __init__(self, status_code):
            self.status_code = status_code
    
    class MockAsyncClient:
        def __init__(self, *args, **kwargs): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def get(self, url, headers=None):
            return MockResponse(200)
            
    import httpx
    monkeypatch.setattr(httpx, "AsyncClient", MockAsyncClient)
    
    stage.execute(context)
    
    # Assert findings were added
    findings = context.results
    assert any(f.get("finding_type") == "origin_ip_leak" and f.get("details", {}).get("ip") == "192.168.1.1" for f in findings)
    assert any(f.get("finding_type") == "origin_ip_leak" and f.get("details", {}).get("ip") == "10.0.0.1" for f in findings)
    assert any(f.get("finding_type") == "origin_ip_leak" and f.get("details", {}).get("ip") == "10.0.0.2" for f in findings)
