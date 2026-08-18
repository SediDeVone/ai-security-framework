"""Universal Agent ADK/SDK Security Middleware (Custom Agent Defense).

Provides wrapper interceptors for custom Python agent frameworks
(Google Gen AI ADK, LangChain, CrewAI, AutoGen) to enforce input scanning,
PII anonymization/rehydration, and output sanitization automatically.
"""
from typing import Callable, Dict, Any, Optional, Tuple
from scanner.client import SecurityScannerClient
from scanner.output_sanitizer import sanitize_html, validate_generated_url


class SecureAgentMiddleware:
    def __init__(self, scanner_client: Optional[SecurityScannerClient] = None, session_id: Optional[str] = None):
        self.scanner = scanner_client or SecurityScannerClient()
        self.rehydration_map: Dict[str, str] = {}
        self.session_id = session_id

    def wrap_agent_step(self, user_prompt: str) -> Tuple[str, Optional[str]]:
        """Intercepts user prompt before sending to LLM ADK.
        
        1. Runs prompt injection scanner.
        2. Redacts PII and updates rehydration map.
        Returns (sanitized_prompt, block_reason_or_none).
        """
        # 1. Check prompt injection & Budget
        res = self.scanner.scan_prompt(user_prompt, session_id=self.session_id)
        if res.get("block"):
            return user_prompt, f"Blocked: {res.get('rule')} — {res.get('detail')}"

        clean_prompt = res.get("sanitized_text") or user_prompt

        # 2. Redact PII
        redacted_prompt, remap = self.scanner.redact_pii(clean_prompt)
        self.rehydration_map.update(remap)
        return redacted_prompt, None

    def rehydrate(self, text: str) -> str:
        """Replaces PII tokens with original values."""
        rehydrated = text
        for token, original in self.rehydration_map.items():
            rehydrated = rehydrated.replace(token, original)
        return rehydrated

    def wrap_tool_execution(self, tool_name: str, tool_args: dict, is_egress: bool = False) -> Tuple[dict, Optional[str]]:
        """Intercepts tool calls in custom agent loops before execution."""
        res = self.scanner.scan_tool_input(tool_name, tool_args, egress=is_egress)
        if res.get("deny"):
            return tool_args, f"Denied tool execution: {res.get('reason')}"
            
        updated_args = res.get("updated_input") or tool_args
        return updated_args, None

    def sanitize_agent_output(self, raw_output: str) -> str:
        """Sanitizes final agent output before rendering to user or UI."""
        # 1. Call scanner for output sanitization (Unicode, Spotlighting, PII, HTML)
        res = self.scanner.scan_tool_output("final_output", raw_output, session_id=self.session_id)
        clean_output = res.get("redacted_text") or raw_output
        
        # 2. Local HTML cleaning as double-check
        final_clean = sanitize_html(clean_output)
        return final_clean

    def run_secure_code(self, python_code: str) -> dict:
        """Executes generated code in the scanner's sandbox."""
        return self.scanner.execute_sandbox(python_code=python_code)

    def report_usage(self, tokens: int, cost: float = 0.0):
        """Logs token usage to the central budget guard."""
        if self.session_id:
            self.scanner.record_budget(self.session_id, tokens, cost)
