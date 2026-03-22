import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from pathlib import Path
import json

from recon_cli.pipeline.stage_fuzz import FuzzStage
from recon_cli.pipeline.context import PipelineContext
from recon_cli.cli_wizard import (
    ScanWizard, JobWizard, ToolConfigWizard, 
    InteractiveMode
)
from recon_cli.utils.oast import InteractshSession
from recon_cli.tools.executor import CommandError


# ==========================================
# 1. Tests for stage_fuzz.py
# ==========================================
@pytest.fixture
def fuzz_context(tmp_path):
    context = MagicMock(spec=PipelineContext)
    context.record = MagicMock()
    context.record.spec = MagicMock()
    context.record.spec.profile = "full"
    context.record.spec.wordlist = ""
    context.record.metadata.stats = {"soft_404": {"hosts": ["example.com"], "fingerprints": {"example.com": {"length": 100, "word_count": 10}}}}
    context.runtime_config = MagicMock()
    context.runtime_config.enable_fuzz = True
    context.runtime_config.enable_param_fuzz = True
    context.runtime_config.ffuf_threads = 10
    context.runtime_config.trim_url_max_per_host = 5
    context.runtime_config.max_fuzz_hosts = 2
    context.runtime_config.seclists_root = tmp_path / "seclists"
    context.executor = MagicMock()
    context.executor.available.return_value = True
    context.executor.run_async = AsyncMock(return_value=True)
    
    # Setup Paths
    context.record.paths = MagicMock()
    context.record.paths.artifact.side_effect = lambda x: tmp_path / x
    context.record.paths.ensure_subdir.return_value = tmp_path / "wordlists"
    (tmp_path / "wordlists").mkdir(exist_ok=True)
    
    context.logger = MagicMock()
    context.results = MagicMock()
    context.results.append.return_value = True
    
    # _select_hosts_for_fuzz
    context.get_results.return_value = [
        {"type": "url", "url": "https://example.com/api/v1", "hostname": "example.com", "status_code": 200, "score": 50},
        {"type": "form", "action": "https://example.com/login", "hostname": "example.com"},
        {"type": "parameter", "name": "id", "examples": ["https://example.com/?id=1"]}
    ]
    context.get_data.return_value = ["https://example.com/api/v2"]
    context.signal_index.return_value = {
        "by_host": {
            "example.com": {"api_surface", "cms_wordpress"}
        }
    }
    context.url_allowed.return_value = True
    
    # Mock data for ffuf output
    artifact_path = tmp_path / "ffuf_example.com.json"
    artifact_path.write_text(json.dumps({
        "results": [
            {"url": "https://example.com/api/v1/users", "status": 200, "length": 123, "hostname": "example.com"}
        ]
    }))
    
    param_artifact = tmp_path / "ffuf_params_example.com.json"
    param_artifact.write_text(json.dumps({
        "results": [
            {"url": "https://example.com/?id=1", "status": 200, "length": 123, "hostname": "example.com"}
        ]
    }))
    return context

def test_fuzz_stage_is_enabled(fuzz_context):
    stage = FuzzStage()
    assert stage.is_enabled(fuzz_context) is True
    
    fuzz_context.record.spec.profile = "quick"
    fuzz_context.runtime_config.enable_fuzz = False
    fuzz_context.runtime_config.enable_param_fuzz = False
    assert stage.is_enabled(fuzz_context) is False

def test_fuzz_stage_execute(fuzz_context, tmp_path):
    stage = FuzzStage()
    
    # Create wordlists
    seclists_root = tmp_path / "seclists"
    seclists_root.mkdir(parents=True, exist_ok=True)
    wp_list = seclists_root / "Discovery" / "Web-Content" / "CMS" / "wordpress.fuzz.txt"
    wp_list.parent.mkdir(parents=True, exist_ok=True)
    wp_list.write_text("wp-admin\nwp-login.php\n")
    
    param_list = seclists_root / "Discovery" / "Web-Content" / "burp-parameter-names.txt"
    param_list.parent.mkdir(parents=True, exist_ok=True)
    param_list.write_text("id\nuser\ntoken\n")
    
    fuzz_context.runtime_config.seclists_root = seclists_root

    # Run
    # Avoid deadlock in pytest-asyncio by hiding the event loop
    with patch("asyncio.get_running_loop", side_effect=RuntimeError):
        stage.execute(fuzz_context)
    
    # run_async gets called for normal fuzz and param fuzz
    assert fuzz_context.executor.run_async.call_count >= 2
    fuzz_context.results.append.assert_called()

# ==========================================
# 2. Tests for cli_wizard.py
# ==========================================
@pytest.mark.asyncio
async def test_scan_wizard():
    wizard = ScanWizard()
    
    # We will simulate exactly what prompt gets asked and what to answer.
    # We mock out the prompt ask methods.
    def mock_ask(*args, **kwargs):
        prompt_text = str(args[0]) if args else ""
        if "Scan name" in prompt_text: return "test-scan"
        if "Item" in prompt_text: 
            if not hasattr(mock_ask, 'targets_done'):
                mock_ask.targets_done = True
                return "example.com"
            return ""
        if "Concurrency" in prompt_text: return 10
        if "Timeout" in prompt_text: return 300
        if "Select option" in prompt_text: return 2 # standard
        if "Select options" in prompt_text: return "1,2" # array
        return kwargs.get("default", "")
        
    def mock_confirm(*args, **kwargs):
        return True

    with patch("rich.prompt.Prompt.ask", side_effect=mock_ask), \
         patch("rich.prompt.IntPrompt.ask", side_effect=mock_ask), \
         patch("rich.prompt.Confirm.ask", side_effect=mock_confirm):
        
        result = await wizard.run()
        assert result.completed is True
        assert result.data["name"] == "test-scan"

@pytest.mark.asyncio
async def test_job_wizard():
    wizard = JobWizard()
    def mock_ask(*args, **kwargs):
        prompt_text = str(args[0]) if args else ""
        if "Select option" in prompt_text: return 1 # create
        return kwargs.get("default", "")

    def mock_confirm(*args, **kwargs):
        return False
        
    with patch("rich.prompt.Prompt.ask", side_effect=mock_ask), \
         patch("rich.prompt.IntPrompt.ask", side_effect=mock_ask), \
         patch("rich.prompt.Confirm.ask", side_effect=mock_confirm):
        
        result = await wizard.run()
        # Not confirmed, should be cancelled
        assert result.completed is False
        assert result.cancelled is True

@pytest.mark.asyncio
async def test_tool_wizard():
    wizard = ToolConfigWizard()
    def mock_ask(*args, **kwargs):
        prompt_text = str(args[0]) if args else ""
        if "Select option" in prompt_text: return 1
        if "Path" in prompt_text: return "/usr/bin/tool"
        if "Execution timeout" in prompt_text: return 100
        return kwargs.get("default", "")

    with patch("rich.prompt.Prompt.ask", side_effect=mock_ask), \
         patch("rich.prompt.IntPrompt.ask", side_effect=mock_ask), \
         patch("rich.prompt.Confirm.ask", return_value=True):
        
        result = await wizard.run()
        assert result.completed is True
        assert "tool" in result.data

@pytest.mark.asyncio
async def test_interactive_mode_commands():
    mode = InteractiveMode()
    mode.history = []
    
    # Mock console print
    with patch.object(mode.console, "print") as mock_print:
        await mode._process_command("help")
        assert mock_print.call_count > 0
        
        await mode._process_command("scan example.com")
        assert mock_print.call_count > 0
        
        await mode._process_command("jobs")
        assert mock_print.call_count > 0
        
        await mode._process_command("profile list")
        assert mock_print.call_count > 0

        await mode._process_command("status")
        assert mock_print.call_count > 0
        
        await mode._process_command("history")
        assert mock_print.call_count > 0
        
        with patch("recon_cli.cli_wizard.WizardRegistry.run_wizard", new_callable=AsyncMock) as mock_wizard:
            mock_wizard.return_value = MagicMock(completed=True)
            await mode._process_command("wizard scan")
            mock_wizard.assert_called_with("scan")
            
        await mode._process_command("exit")
        assert mode.running is False


# ==========================================
# 3. Tests for utils/oast.py
# ==========================================
def test_interactsh_session_override(tmp_path):
    from recon_cli.utils.oast import InteractshSession
    output_path = tmp_path / "oast_out.json"
    session = InteractshSession(output_path, wait_seconds=1, poll_interval=0.1)
    
    # Test start with domain override
    session.domain_override = "example.oast.me"
    assert session.start() is True
    assert session.base_domain == "example.oast.me"
    
    assert session.make_url("test_token") == "http://test_token.example.oast.me"
    
    # Write interactions
    output_path.write_text(json.dumps([
        {"protocol": "dns", "full-id": "test_token.example.oast.me", "raw": "test_token in payload"}
    ]))
    
    interactions = session.collect_interactions(["test_token"])
    assert len(interactions) == 1
    assert interactions[0].token == "test_token"
    assert interactions[0].protocol == "dns"
    
    session.stop()

def test_interactsh_session_subprocess(tmp_path):
    from recon_cli.utils.oast import InteractshSession
    output_path = tmp_path / "oast_out2.json"
    session = InteractshSession(output_path, wait_seconds=1, poll_interval=0.1, timeout=1)
    
    # Mock subprocess
    mock_process = MagicMock()
    mock_process.poll.return_value = None
    
    with patch("subprocess.Popen", return_value=mock_process):
        # We need to write to the payload file to simulate readiness
        def write_payload(*args, **kwargs):
            session.payload_file.write_text("test.oast.me")
            return mock_process
            
        with patch("subprocess.Popen", side_effect=write_payload):
            assert session.start() is True
            assert session.base_domain == "test.oast.me"
        
        # Test full JSON format output parsing
        output_path.write_text(json.dumps({
            "data": [
                {"protocol": "http", "full-id": "token123.test.oast.me", "raw": "token123 request"}
            ]
        }))
        
        interactions = session.collect_interactions(["token123"])
        assert len(interactions) == 1
        assert interactions[0].token == "token123"
        
        # Test stop
        session.stop()
        mock_process.terminate.assert_called_once()

def test_interactsh_session_jsonl_parsing(tmp_path):
    from recon_cli.utils.oast import InteractshSession
    output_path = tmp_path / "oast_out3.jsonl"
    session = InteractshSession(output_path, wait_seconds=1, poll_interval=0.1)
    session.domain_override = "example.oast.me"
    session.start()
    
    # JSONL format output
    content = '{"protocol": "dns", "full-id": "tokena.example.oast.me", "raw": "tokena"}\n'
    content += '{"protocol": "http", "full-id": "tokenb.example.oast.me", "raw": "tokenb"}\n'
    output_path.write_text(content)
    
    interactions = session.collect_interactions(["tokena", "tokenb"])
    assert len(interactions) == 2
