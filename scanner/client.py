"""Lightweight Python SDK for standalone agents to consume the AI Security Scanner Service."""
import json
import urllib.request
from typing import Dict, Any, Optional


class SecurityScannerClient:
    def __init__(self, endpoint: str = "http://127.0.0.1:8901", api_key: Optional[str] = None):
        self.endpoint = endpoint.rstrip("/")
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

    def scan_prompt(self, text: str) -> dict:
        """Returns {block: bool, rule?: str, detail?: str, advisory?: str}"""
        return self._post("scan/prompt", {"text": text})

    def redact_pii(self, text: str) -> str:
        """Returns redacted string with <PERSON>, <EMAIL_ADDRESS>, <PL_PESEL>, etc."""
        res = self._post("redact", {"text": text})
        return res.get("text", text)

    def scan_tool_input(self, tool_name: str, tool_input: dict, is_egress: bool = False) -> dict:
        """Returns {deny: bool, reason?: str, updated_input?: dict}"""
        return self._post("scan/tool-input", {"tool": tool_name, "input": tool_input, "egress": is_egress})

    def scan_tool_output(self, tool_name: str, text: str) -> dict:
        """Returns {block: bool, rule?: str, redacted_text?: str}"""
        return self._post("scan/tool-output", {"tool": tool_name, "text": text})
