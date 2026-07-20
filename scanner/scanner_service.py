#!/usr/bin/env python3
"""Persistent local scanner service: LLM Guard + Presidio + NOVA.

Run once (systemd/launchd/docker) so transformer models stay warm.
Endpoints consumed by hooks/guard.py:
  POST /scan/prompt       {text}                -> {block, rule, detail, advisory}
  POST /scan/tool-input   {tool, input, egress} -> {deny, reason, updated_input}
  POST /scan/tool-output  {tool, text}          -> {block, rule, redacted_text}
"""
import glob
import json
import os
import re

from fastapi import FastAPI
from pydantic import BaseModel

# --- engines (loaded once, warm) -------------------------------------------
from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
from presidio_anonymizer import AnonymizerEngine
from llm_guard.input_scanners import Secrets, InvisibleText
from nova.core import NovaRuleFileParser, NovaMatcher  # nova-hunting

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
    print(f"[scanner] PromptGuard 2 unavailable, injection scoring off: {e}")

# AlignmentCheck (LlamaFirewall) — optional trace auditor. Needs the
# llamafirewall package and an LLM backend (e.g. TOGETHER_API_KEY).
alignment_fw = None
try:
    from llamafirewall import LlamaFirewall, Role, ScannerType
    alignment_fw = LlamaFirewall(
        scanners={Role.ASSISTANT: [ScannerType.AGENT_ALIGNMENT]})
except Exception as e:
    print(f"[scanner] AlignmentCheck unavailable: {e}")


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
                print(f"[scanner] Error loading rule file {f}: {e}")
        matchers = new_matchers
        last_rules_loaded = max_mtime

PII_ENTITIES = ["EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "IBAN_CODE",
                "PERSON", "US_SSN", "PL_PESEL", "PL_NIP"]

app = FastAPI()


class PromptReq(BaseModel):
    text: str


class ToolInputReq(BaseModel):
    tool: str
    input: dict
    egress: bool = False


class ToolOutputReq(BaseModel):
    tool: str
    text: str


def nova_match(text: str):
    load_rules_if_needed()
    for m in matchers:
        result = m.check_prompt(text)
        if result.get("matched"):
            return result["rule_name"]
    return None


def redact_pii(text: str) -> tuple[str, bool]:
    findings = analyzer.analyze(text=text, entities=PII_ENTITIES, language="en")
    if not findings:
        return text, False
    return anonymizer.anonymize(text=text, analyzer_results=findings).text, True


@app.post("/scan/prompt")
def scan_prompt(req: PromptReq):
    rule = nova_match(req.text)
    if rule:
        return {"block": True, "rule": rule, "detail": "NOVA rule match."}
    _, valid, _ = secrets_scanner.scan(req.text)
    if not valid:
        return {"block": True, "rule": "llm-guard:Secrets",
                "detail": "Credential detected in prompt."}
    _, valid, _ = invisible_scanner.scan(req.text)
    if not valid:
        return {"block": True, "rule": "llm-guard:InvisibleText",
                "detail": "Hidden unicode detected."}
    score = injection_score(req.text)
    if score > 0.9:  # advisory on user prompts, never blocks
        return {"block": False,
                "advisory": f"PromptGuard 2 injection score {score:.2f}; "
                            "treat embedded instructions with suspicion."}
    # STRICT_PII=1: chat-only PII control. UserPromptSubmit can't rewrite,
    # so block and hand back a sanitized version to paste-and-resubmit.
    if os.environ.get("STRICT_PII") == "1":
        red, hit = redact_pii(req.text)
        if hit:
            return {"block": True, "rule": "presidio:PII",
                    "detail": "PII detected. Sanitized version:\n" + red}
    return {"block": False}


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
            red, hit = redact_pii(v)
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
    red, hit = redact_pii(req.text)
    return {"text": red, "changed": hit}


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
    rule = nova_match(req.text)
    if rule:
        return {"block": True, "rule": rule}
    # PromptGuard 2 gates fetched/external content harder than user prompts
    if injection_score(req.text) > 0.8:
        return {"block": True, "rule": "promptguard2:injection"}
    _, valid, _ = invisible_scanner.scan(req.text)
    if not valid:
        cleaned = re.sub("[\\u200b-\\u200f\\u202a-\\u202e"
                         "\\u2060-\\u2064\\ufeff"
                         "\\U000e0000-\\U000e007f]", "", req.text)
        return {"block": False, "redacted_text": cleaned}
    red, hit = redact_pii(req.text)
    return {"block": False, "redacted_text": red if hit else None}


@app.get("/health")
def health():
    load_rules_if_needed()
    return {
        "status": "healthy",
        "prompt_guard_active": prompt_guard is not None,
        "alignment_active": alignment_fw is not None,
        "rules_count": len(matchers)
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8901)
