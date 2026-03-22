from __future__ import annotations

import json
from collections import defaultdict
from typing import Dict, List, Set, Any
from urllib.parse import urlparse, parse_qsl

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage


class ApiSchemaReconstructorStage(Stage):
    """
    Reconstructs API Schemas (OpenAPI/Swagger) from observed URLs and parameters.
    Helps visualize the hidden attack surface of the target.
    """
    name = "api_reconstructor"

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_api_reconstructor", True))

    def execute(self, context: PipelineContext) -> None:
        results = context.get_results()
        
        # Group paths and params by host
        schemas_by_host: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "openapi": "3.0.0",
            "info": {"title": "Reconstructed API", "version": "1.0.0"},
            "paths": defaultdict(dict)
        })

        urls_processed = 0
        for entry in results:
            if entry.get("type") != "url":
                continue
            
            url = entry.get("url")
            if not url: continue
            
            parsed = urlparse(url)
            host = parsed.hostname
            if not host: continue
            
            path = parsed.path or "/"
            method = entry.get("method", "get").lower()
            
            # Add to schema
            host_schema = schemas_by_host[host]
            
            # Prepare parameters
            parameters = []
            if parsed.query:
                for name, value in parse_qsl(parsed.query):
                    parameters.append({
                        "name": name,
                        "in": "query",
                        "schema": {"type": self._infer_type(value)}
                    })

            # Check if this path/method combo already exists
            if method not in host_schema["paths"][path]:
                host_schema["paths"][path][method] = {
                    "summary": f"Discovered via {entry.get('source', 'recon')}",
                    "responses": {"200": {"description": "OK"}},
                    "parameters": parameters
                }
                urls_processed += 1

        # Save artifacts per host
        if schemas_by_host:
            for host, schema in schemas_by_host.items():
                # Clean up defaultdict for JSON serialization
                schema["paths"] = dict(schema["paths"])
                
                path = context.record.paths.artifact(f"openapi_reconstructed_{host}.json")
                path.write_text(json.dumps(schema, indent=2))
                
                context.logger.info("Reconstructed API schema for %s with %d paths", host, len(schema["paths"]))
                context.emit_signal("api_reconstructed", "host", host, confidence=0.8, source=self.name, evidence={"artifact": path.name})

    def _infer_type(self, value: str) -> str:
        if value.isdigit():
            return "integer"
        if value.lower() in ["true", "false"]:
            return "boolean"
        # Check for UUID pattern
        if len(value) == 36 and value.count("-") == 4:
            return "string" # uuid format in openapi
        return "string"
