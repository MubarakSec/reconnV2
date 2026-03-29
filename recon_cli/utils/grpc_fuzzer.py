from __future__ import annotations

import asyncio
import httpx
import struct
from typing import List, Dict, Any, Optional, Tuple


class GRPCFuzzer:
    """
    gRPC Fuzzer and Reflection Probe.
    Uses raw HTTP/2 to check for reflection and attempt basic service enumeration.
    """

    def __init__(self, timeout: float = 5.0, verify_tls: bool = False):
        self.timeout = timeout
        self.verify_tls = verify_tls

    async def check_reflection(self, host: str, port: int) -> Tuple[bool, str, List[str]]:
        """
        Attempts to check if gRPC reflection is enabled.
        Standard reflection service: grpc.reflection.v1alpha.ServerReflection
        Method: ServerReflectionInfo
        """
        url = f"https://{host}:{port}/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"
        if port == 80: url = f"http://{host}:{port}/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"

        # gRPC wire format: 1 byte (compressed flag) + 4 bytes (length) + message
        # We'll try to send a 'list_services' request.
        # This is a bit complex without protobuf, so we send a 'best effort' pre-calculated blob
        # or just check if the endpoint exists and doesn't return UNIMPLEMENTED (12).
        
        headers = {
            "content-type": "application/grpc",
            "te": "trailers",
            "user-agent": "recon-cli/2.0 grpc-fuzzer"
        }

        # Empty reflection request might be enough to see if it's there
        # (Actually, a real request is better, but even a 200 OK + gRPC-Status != 12 is a hint)
        try:
            async with httpx.AsyncClient(http2=True, verify=self.verify_tls, timeout=self.timeout) as client:
                # Send empty data to trigger a response
                resp = await client.post(url, headers=headers, content=b"\x00\x00\x00\x00\x00")
                
                grpc_status = resp.headers.get("grpc-status")
                if grpc_status == "12": # UNIMPLEMENTED
                    return False, "Reflection service not implemented", []
                
                if resp.status_code == 200:
                    # If it's not 12, it might be enabled or require specific protobuf
                    return True, "Reflection service potentially enabled (returned status 200, not unimplemented)", []
                
        except Exception as e:
            return False, str(e), []

        return False, "No response", []

    async def fuzz_methods(self, host: str, port: int, services: List[str]) -> List[Dict[str, Any]]:
        """Attempts to fuzz exposed gRPC methods."""
        findings = []
        # Without full proto parsing, we can only do shallow fuzzing
        # e.g. guessing common service names
        common_services = [
            "grpc.health.v1.Health/Check",
            "grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"
        ]
        
        headers = {
            "content-type": "application/grpc",
            "te": "trailers"
        }

        async with httpx.AsyncClient(http2=True, verify=self.verify_tls, timeout=2.0) as client:
            for svc in common_services:
                url = f"https://{host}:{port}/{svc}"
                try:
                    resp = await client.post(url, headers=headers, content=b"\x00\x00\x00\x00\x00")
                    g_status = resp.headers.get("grpc-status")
                    if g_status and g_status != "12":
                         findings.append({
                             "service": svc,
                             "status": g_status,
                             "description": f"Service {svc} responded with gRPC-Status {g_status} (potentially exposed)"
                         })
                except Exception as e:
                    logger.debug(f"Silent failure suppressed: {e}", exc_info=True)
                    try:
                        from recon_cli.utils.metrics import metrics
                        metrics.stage_errors.labels(stage="unknown", error_type=type(e).__name__).inc()
                    except: pass
        
        return findings
