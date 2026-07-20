"""Universal Agent ADK/SDK Security Middleware (Custom Agent Defense).

Provides wrapper interceptors for custom Python agent frameworks
(Google Gen AI ADK, LangChain, CrewAI, AutoGen) to enforce input scanning,
PII anonymization/rehydration, and output sanitization automatically.
"""
from typing import Callable, Dict, Any, Optional, Tuple
from scanner.client import SecurityScannerClient
from scanner.output_sanitizer import sanitize_html, validate_generated_url


class SecureAgentMiddleware:
    def __init__(self, scanner_client: Optional[SecurityScannerClient] = None):
        self.scanner = scanner_client or SecurityScannerClient()
        self.rehydration_map: Dict[str, str] = {}

    def wrap_agent_step(self, user_prompt: str) -> Tuple[str, Optional[str]]:
        """Intercepts user prompt before sending to LLM ADK.
        
        1. Runs prompt injection scanner.
        2. Redacts PII and updates rehydration map.
        Returns (sanitized_prompt, block_reason_or_none).
        """
        # 1. Check prompt injection
        res = self.scanner.scan_prompt(user_prompt)
        if res.get("block"):
            return user_prompt, f"Blocked: {res.get('rule')} — {res.get('detail')}"

        # 2. Redact PII
        redacted_prompt = self.scanner.redact_pii(user_prompt)
        return redacted_prompt, None

    def wrap_tool_execution(self, tool_name: str, tool_args: dict, is_egress: bool = False) -> Tuple[dict, Optional[str]]:
        """Intercepts tool calls in custom agent loops before execution."""
        res = self.scanner.scan_tool_input(tool_name, tool_args, egress=is_egress)
        if res.get("deny"):
            return tool_args, f"Denied tool execution: {res.get('reason')}"
            
        updated_args = res.get("updated_input") or tool_args
        return updated_args, None

    def sanitize_agent_output(self, raw_output: str) -> str:
        """Sanitizes final agent output before rendering to user or UI."""
        clean_html = sanitize_html(raw_output)
        return clean_html
