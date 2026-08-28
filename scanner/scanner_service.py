#!/usr/bin/env python3
"""Persistent local scanner service: LLM Guard + Presidio + NOVA.

Run once (systemd/launchd/docker) so transformer models stay warm.
Endpoints consumed by hooks/guard.py:
  POST /scan/prompt       {text}                -> {block, rule, detail, advisory}
  POST /scan/tool-input   {tool, input, egress} -> {deny, reason, updated_input}
  POST /scan/tool-output  {tool, text}          -> {block, rule, redacted_text}
"""
import glob
import hmac
import json
import logging
import os
import re

from typing import Optional, List, Dict, Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# Initialize logging for production observability
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("scanner_service")


# --- engines (loaded once, warm) -------------------------------------------
from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
from presidio_anonymizer import AnonymizerEngine
from llm_guard.input_scanners import Secrets, InvisibleText
from nova.core import NovaRuleFileParser, NovaMatcher  # nova-hunting

# --- custom security modules -----------------------------------------------
from scanner.exif_cleaner import strip_exif_from_bytes
from scanner.unicode_cleaner import sanitize_unicode
from scanner.output_sanitizer import sanitize_html, validate_generated_url
from scanner.budget_guard import AgentBudgetGuard, BudgetExceededException
from scanner.spotlighting import wrap_delimited
from scanner.sandbox import get_sandbox

# Custom Polish Recognizers for regional PII compliance
pesel_pattern = Pattern(
    name="pesel_pattern",
    regex=r"\b\d{11}\b",
    score=0.85
)
pesel_recognizer = PatternRecognizer(
    supported_entity="PL_PESEL",
    patterns=[pesel_pattern],
    context=["pesel", "identification number", "national id", "personal number"]
)

nip_pattern = Pattern(
    name="nip_pattern",
    regex=r"\b\d{3}[-\s]?\d{3}[-\s]?\d{2}[-\s]?\d{2}\b|\b\d{3}[-\s]?\d{2}[-\s]?\d{2}[-\s]?\d{3}\b",
    score=0.85
)
nip_recognizer = PatternRecognizer(
    supported_entity="PL_NIP",
    patterns=[nip_pattern],
    context=["nip", "tax identification number", "vat", "tax id"]
)

analyzer = AnalyzerEngine()
analyzer.registry.add_recognizer(pesel_recognizer)
analyzer.registry.add_recognizer(nip_recognizer)

anonymizer = AnonymizerEngine()
secrets_scanner = Secrets()
invisible_scanner = InvisibleText()

# PromptGuard 2 (Meta) — replaces LLM Guard's PromptInjection scanner.
# 22M model for latency; set PROMPT_GUARD_MODEL=meta-llama/Llama-Prompt-Guard-2-86M
# for precision. Models are gated on HF: accept license + `huggingface-cli login`.
prompt_guard = None
try:
    from transformers import pipeline
    prompt_guard = pipeline(
        "text-classification",
        model=os.environ.get("PROMPT_GUARD_MODEL",
                             "meta-llama/Llama-Prompt-Guard-2-22M"))
except Exception as e:
    logger.warning(f"PromptGuard 2 unavailable, injection scoring off: {e}")

# AlignmentCheck (LlamaFirewall) — optional trace auditor. Needs the
# llamafirewall package and an LLM backend (e.g. TOGETHER_API_KEY).
alignment_fw = None
try:
    from llamafirewall import LlamaFirewall, Role, ScannerType
    alignment_fw = LlamaFirewall(
        scanners={Role.ASSISTANT: [ScannerType.AGENT_ALIGNMENT]})
except Exception as e:
    logger.warning(f"AlignmentCheck unavailable: {e}")



def injection_score(text: str) -> float:
    """0.0-1.0 probability that text contains an injection/jailbreak."""
    if prompt_guard is None:
        return 0.0
    # PromptGuard 2 context window is small; scan in chunks, take the max
    chunks = [text[i:i + 2000] for i in range(0, min(len(text), 40000), 2000)]
    score = 0.0
    for c in chunks:
        for r in prompt_guard(c, top_k=None):
            if r["label"].upper() in ("MALICIOUS", "INJECTION", "JAILBREAK",
                                      "LABEL_1"):
                score = max(score, r["score"])
    return score

RULES_DIR = os.path.expanduser("~/.claude/nova-rules")
parser = NovaRuleFileParser()
matchers = []
last_rules_loaded = 0.0

def load_rules_if_needed():
    global matchers, last_rules_loaded
    if not os.path.exists(RULES_DIR):
        return
    
    mtimes = [os.path.getmtime(RULES_DIR)]
    nov_files = glob.glob(f"{RULES_DIR}/*.nov")
    for f in nov_files:
        try:
            mtimes.append(os.path.getmtime(f))
        except OSError:
            pass
            
    max_mtime = max(mtimes) if mtimes else 0.0
    if max_mtime > last_rules_loaded:
        new_matchers = []
        for f in nov_files:
            try:
                for r in parser.parse_file(f):
                    new_matchers.append(NovaMatcher(r))
            except Exception as e:
                logger.error(f"Error loading rule file {f}: {e}")
        matchers = new_matchers

        last_rules_loaded = max_mtime

PII_ENTITIES = ["EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "IBAN_CODE",
                "PERSON", "US_SSN", "PL_PESEL", "PL_NIP"]

# Token/Budget tracking (Simple in-memory store for demo purposes)
budgets = {}

app = FastAPI()

SCANNER_API_KEY = os.environ.get("SCANNER_API_KEY")

@app.on_event("startup")
async def startup_event():
    if not SCANNER_API_KEY:
        logger.warning(
            "⚠️ SCANNER_API_KEY environment variable is NOT set! "
            "The service will run in OPEN mode, and endpoints "
            "(including /sandbox/execute) will be unauthenticated!"
        )
    else:
        logger.info("SCANNER_API_KEY is configured. Request authentication is enabled.")

@app.middleware("http")
async def verify_api_key(request: Request, call_next):
    if SCANNER_API_KEY and request.url.path not in ("/health", "/docs", "/openapi.json"):
        api_key = request.headers.get("X-API-Key")
        if not api_key or not hmac.compare_digest(api_key, SCANNER_API_KEY):
            logger.warning(
                f"Unauthorized request to {request.url.path} from {request.client.host if request.client else 'unknown'}"
            )
            return JSONResponse(
                status_code=401,
                content={"detail": "Unauthorized: Invalid or missing X-API-Key"}
            )
    return await call_next(request)



class PromptReq(BaseModel):
    text: str
    session_id: Optional[str] = None


class ToolInputReq(BaseModel):
    tool: str
    input: dict
    egress: bool = False
    session_id: Optional[str] = None


class ToolOutputReq(BaseModel):
    tool: str
    text: str
    session_id: Optional[str] = None


class BudgetRecordReq(BaseModel):
    session_id: str
    tokens: int
    cost: float = 0.0


def nova_match(text: str):
    load_rules_if_needed()
    for m in matchers:
        result = m.check_prompt(text)
        if result.get("matched"):
            return result["rule_name"]
    return None


def redact_pii(text: str) -> tuple[str, bool, dict]:
    findings = analyzer.analyze(text=text, entities=PII_ENTITIES, language="en")
    if not findings:
        return text, False, {}
    
    # Sort findings by start position, then end position descending to process
    # overlapping findings consistently (keeping the longer and higher scoring one).
    sorted_findings = sorted(findings, key=lambda x: (x.start, -x.end))
    
    filtered_findings = []
    last_end = -1
    for f in sorted_findings:
        if f.start >= last_end:
            filtered_findings.append(f)
            last_end = f.end
        else:
            # Overlap! Keep the higher scoring or longer finding
            if filtered_findings:
                prev = filtered_findings[-1]
                if f.score > prev.score or (f.score == prev.score and (f.end - f.start) > (prev.end - prev.start)):
                    filtered_findings[-1] = f
                    last_end = f.end

    # Process findings in reverse order (from last to first) to prevent index shifting
    reverse_findings = sorted(filtered_findings, key=lambda x: x.start, reverse=True)
    
    entity_counts = {}
    value_to_placeholder = {}
    placeholder_to_value = {}
    
    current_text = text
    for finding in reverse_findings:
        start = finding.start
        end = finding.end
        entity_type = finding.entity_type
        original_val = text[start:end]
        
        # Consistent mapping: same original value gets the same placeholder
        if original_val in value_to_placeholder:
            placeholder = value_to_placeholder[original_val]
        else:
            count = entity_counts.get(entity_type, 0) + 1
            entity_counts[entity_type] = count
            placeholder = f"<{entity_type}_{count}>"
            value_to_placeholder[original_val] = placeholder
            placeholder_to_value[placeholder] = original_val
            
        current_text = current_text[:start] + placeholder + current_text[end:]
        
    return current_text, True, placeholder_to_value



@app.post("/scan/prompt")
def scan_prompt(req: PromptReq):
    if is_killed:
        return {"block": True, "rule": "EMERGENCY_KILL_SWITCH", "detail": "Emergency lockdown active."}
    
    # 1. Unicode Sanitization (Homoglyphs & Invisible tags)
    text, modified = sanitize_unicode(req.text)
    
    # 2. NOVA Match
    rule = nova_match(text)
    if rule:
        return {"block": True, "rule": rule, "detail": "NOVA rule match."}
    
    # 3. LLM Guard Scanners
    _, valid, _ = secrets_scanner.scan(text)
    if not valid:
        return {"block": True, "rule": "llm-guard:Secrets",
                "detail": "Credential detected in prompt."}
    
    # 4. Budget check (if session_id provided)
    if req.session_id and req.session_id in budgets:
        try:
            # We don't record a step here, just check if already exceeded
            budgets[req.session_id].get_summary()
        except BudgetExceededException as e:
            return {"block": True, "rule": "budget:Exceeded", "detail": str(e)}

    score = injection_score(text)
    if score > 0.9:  # advisory on user prompts, never blocks
        return {"block": False,
                "advisory": f"PromptGuard 2 injection score {score:.2f}; "
                            "treat embedded instructions with suspicion."}
    
    # STRICT_PII=1: chat-only PII control.
    if os.environ.get("STRICT_PII") == "1":
        red, hit, _ = redact_pii(text)
        if hit:
            return {"block": True, "rule": "presidio:PII",
                    "detail": "PII detected. Sanitized version:\n" + red}
    
    return {"block": False, "sanitized_text": text if modified else None}


@app.post("/scan/tool-input")
def scan_tool_input(req: ToolInputReq):
    blob = json.dumps(req.input)
    if req.egress:
        _, valid, _ = secrets_scanner.scan(blob)
        if not valid:
            return {"deny": True,
                    "reason": "Secret/credential detected in outbound tool "
                              "call. Remove it and retry."}
    # Redact PII in string fields of content-bearing args
    updated, changed = {}, False
    for k, v in req.input.items():
        if isinstance(v, str) and len(v) > 20:
            red, hit, _ = redact_pii(v)
            updated[k] = red
            changed = changed or hit
        else:
            updated[k] = v
    return {"deny": False, "updated_input": updated if changed else None}


class TraceReq(BaseModel):
    trace: list  # [{role, content}] recent conversation/tool actions


class RedactReq(BaseModel):
    text: str


@app.post("/redact")
def redact(req: RedactReq):
    """Explicit PII stripping for the /strip-pii command."""
    red, hit, remap = redact_pii(req.text)
    return {"text": red, "changed": hit, "rehydration_map": remap}


@app.post("/scan/trace")
def scan_trace(req: TraceReq):
    """AlignmentCheck: audit recent agent actions for goal divergence."""
    if alignment_fw is None:
        return {"misaligned": False, "reason": "alignmentcheck unavailable"}
    try:
        from llamafirewall import AssistantMessage, UserMessage
        trace = [AssistantMessage(content=m["content"])
                 if m.get("role") == "assistant"
                 else UserMessage(content=m["content"])
                 for m in req.trace]
        result = alignment_fw.scan_replay(trace)
        blocked = getattr(result, "decision", None)
        misaligned = str(blocked).lower() not in ("scandecision.allow", "allow")
        return {"misaligned": misaligned,
                "reason": getattr(result, "reason", ""),
                "score": getattr(result, "score", None)}
    except Exception as e:
        return {"misaligned": False, "reason": f"scan error: {e}"}


@app.post("/scan/tool-output")
def scan_tool_output(req: ToolOutputReq):
    # 1. Unicode Sanitization
    text, modified = sanitize_unicode(req.text)
    
    # 2. Spotlighting (Isolation)
    # If it's a tool output, we often want to wrap it to prevent injection
    if os.environ.get("USE_SPOTLIGHTING") == "1":
        text = wrap_delimited(text)
        modified = True

    rule = nova_match(text)
    if rule:
        return {"block": True, "rule": rule}
    # PromptGuard 2 gates fetched/external content harder than user prompts
    if injection_score(text) > 0.8:
        return {"block": True, "rule": "promptguard2:injection"}
    
    # Redact PII
    red, hit, _ = redact_pii(text)
    
    # HTML Sanitization if text looks like HTML
    if "<" in text and ">" in text:
        text = sanitize_html(text)
        modified = True

    return {"block": False, "redacted_text": red if (hit or modified) else None}


@app.post("/scan/budget/record")
def record_budget(req: BudgetRecordReq):
    if req.session_id not in budgets:
        budgets[req.session_id] = AgentBudgetGuard()
    
    try:
        budgets[req.session_id].record_step(req.tokens, req.cost)
        return {"status": "ok", "summary": budgets[req.session_id].get_summary()}
    except BudgetExceededException as e:
        return {"status": "exceeded", "error": str(e)}


@app.get("/scan/budget/{session_id}")
def get_budget(session_id: str):
    if session_id not in budgets:
        return {"status": "not_found"}
    return budgets[session_id].get_summary()


class ImageReq(BaseModel):
    base64_data: str


@app.post("/scan/image")
def scan_image(req: ImageReq):
    """Strips EXIF from base64 encoded image."""
    import base64
    try:
        img_bytes = base64.b64decode(req.base64_data)
        clean_bytes = strip_exif_from_bytes(img_bytes)
        return {"clean_base64": base64.b64encode(clean_bytes).decode("utf-8")}
    except Exception as e:
        return {"error": str(e)}


class SandboxReq(BaseModel):
    command: Optional[str] = None
    python_code: Optional[str] = None
    timeout: int = 30


@app.post("/sandbox/execute")
def execute_in_sandbox(req: SandboxReq):
    """Executes a command or Python code in a secure sandbox."""
    sbx = get_sandbox()
    if req.python_code:
        res = sbx.run_python(req.python_code, timeout=req.timeout)
    elif req.command:
        res = sbx.run_command(req.command, timeout=req.timeout)
    else:
        return {"error": "No command or code provided"}
    
    return res.to_dict()


is_killed = False


@app.post("/kill-switch")
def toggle_kill_switch(payload: dict):
    global is_killed
    state = payload.get("active", True)
    is_killed = state
    return {"kill_switch_active": is_killed,
            "message": "EMERGENCY KILL-SWITCH ACTIVATED" if is_killed else "Kill-switch deactivated"}


@app.get("/health")
def health():
    load_rules_if_needed()
    return {
        "status": "healthy" if not is_killed else "LOCKED_DOWN",
        "kill_switch_active": is_killed,
        "prompt_guard_active": prompt_guard is not None,
        "alignment_active": alignment_fw is not None,
        "rules_count": len(matchers)
    }


if __name__ == "__main__":
    import uvicorn
    host = os.environ.get("SCANNER_HOST", "0.0.0.0")
    port = int(os.environ.get("SCANNER_PORT", 8901))
    uvicorn.run(app, host=host, port=port)

