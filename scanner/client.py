"""Lightweight Python SDK for standalone agents to consume the AI Security Scanner Service."""
import os
import json
import urllib.request
from typing import Dict, Any, Optional


class SecurityScannerClient:
    def __init__(self, endpoint: Optional[str] = None, api_key: Optional[str] = None):
        self.endpoint = (endpoint or os.environ.get("SCANNER_URL", "http://127.0.0.1:8901")).rstrip("/")
        self.api_key = api_key

    def _post(self, path: str, payload: dict, timeout: int = 5) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        req = urllib.request.Request(
            f"{self.endpoint}/{path}",
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def check_health(self) -> dict:
        req = urllib.request.Request(f"{self.endpoint}/health")
        with urllib.request.urlopen(req, timeout=3) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def scan_prompt(self, text: str, session_id: Optional[str] = None) -> dict:
        """Returns {block: bool, rule?: str, detail?: str, advisory?: str, sanitized_text?: str}"""
        return self._post("scan/prompt", {"text": text, "session_id": session_id})

    def redact_pii(self, text: str) -> tuple[str, dict]:
        """Returns (redacted_text, rehydration_map)."""
        res = self._post("redact", {"text": text})
        return res.get("text", text), res.get("rehydration_map", {})

    def scan_tool_input(self, tool_name: str, tool_input: dict, is_egress: bool = False) -> dict:
        """Returns {deny: bool, reason?: str, updated_input?: dict}"""
        return self._post("scan/tool-input", {"tool": tool_name, "input": tool_input, "egress": is_egress})

    def scan_tool_output(self, tool_name: str, text: str, session_id: Optional[str] = None) -> dict:
        """Returns {block: bool, rule?: str, redacted_text?: str}"""
        return self._post("scan/tool-output", {"tool": tool_name, "text": text, "session_id": session_id})

    def record_budget(self, session_id: str, tokens: int, cost: float = 0.0) -> dict:
        return self._post("scan/budget/record", {"session_id": session_id, "tokens": tokens, "cost": cost})

    def get_budget(self, session_id: str) -> dict:
        req = urllib.request.Request(f"{self.endpoint}/scan/budget/{session_id}")
        with urllib.request.urlopen(req, timeout=3) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def scan_image(self, base64_data: str) -> dict:
        return self._post("scan/image", {"base64_data": base64_data})

    def execute_sandbox(self, command: Optional[str] = None, python_code: Optional[str] = None, timeout: int = 30) -> dict:
        return self._post("sandbox/execute", {"command": command, "python_code": python_code, "timeout": timeout})
