import asyncio
from unittest.mock import AsyncMock, MagicMock
from recon_cli.pipeline.stage_fuzz import FuzzStage
from recon_cli.pipeline.context import PipelineContext
from recon_cli.tools.executor import CommandError
import json
from pathlib import Path

async def main():
    context = MagicMock(spec=PipelineContext)
    context.logger = MagicMock()
    context.runtime_config = MagicMock()
    context.runtime_config.ffuf_maxtime = 10
    context.runtime_config.ffuf_retry_on_timeout = True
    context.runtime_config.ffuf_threads = 10
    # explicitly set this to avoid TypeError
    context.runtime_config.ffuf_retry_extra_time = 120
    context.runtime_config.ffuf_timeout_buffer = 30
    
    stage = FuzzStage()
    
    call_count = 0
    async def mock_run_async(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise CommandError("command timed out", returncode=1)
        return True
        
    context.executor = MagicMock()
    context.executor.run_async = mock_run_async
    
    # Check the condition BEFORE calling _run_ffuf!
    exc = CommandError("command timed out", returncode=1)
    cond1 = getattr(context.runtime_config, "ffuf_retry_on_timeout", True)
    cond2 = "timeout" in str(exc).lower()
    print("cond1:", cond1, "cond2:", cond2)
    
    ret = await stage._run_ffuf(context, ["ffuf", "-u", "http://example.com"], 10, context.runtime_config, "example.com")
    print("retried:", ret)
    print("call_count:", call_count)

asyncio.run(main())
