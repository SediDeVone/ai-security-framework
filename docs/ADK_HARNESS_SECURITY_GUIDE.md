# Comprehensive Guide: Securing Agentic Harnesses & Custom ADK/SDK Agents

This guide details security best practices and repository components for protecting both **Interactive Developer Harnesses** (Claude Code, Antigravity CLI) and **Custom Agents** built via ADKs/SDKs (Google Gen AI ADK, LangChain, CrewAI).

---

## 🏎️ Dual Security Model Overview

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                DUAL AGENTIC SECURITY MODEL                             │
├────────────────────────────────────────────────────────┬───────────────────────────────┤
│  1. CLI AGENTIC HARNESSES                              │  2. CUSTOM ADK / SDK AGENTS   │
│  (Claude Code / Antigravity CLI / Cursor)              │  (Google Gen AI ADK, LangChain│
├────────────────────────────────────────────────────────┼───────────────────────────────┤
│  - Hooks (`harness/hooks/guard.py`)                    │  - Middleware (`adk_middleware`)│
│  - Hard Deny (`harness/settings.json`)                 │  - Budget Guard (`budget_guard`)│
│  - Instruction Hash Integrity (`skill_integrity_check`)│  - PII Anonymize & Rehydrate   │
│  - Slopsquatting Defense (`slopsquatting_guard.py`)    │  - Python SDK Client (`client.py`)│
└────────────────────────────────────────────────────────┴───────────────────────────────┘
```

---

## Part 1: Interactive Agent Harnesses (Claude Code / Antigravity CLI)

### 1. Hardened Permissions (`harness/settings.json`)
* **Rule**: *Hooks can fail or time out; permissions enforced by the CLI binary are absolute.*
* **Configuration**: Restrict destructive bash commands, `.env` file reads, AWS/SSH key accesses, and unpinned curl pipes in `permissions.deny`.

### 2. Skill & Instruction Integrity (`harness/hooks/skill_integrity_check.py`)
* **Risk**: Attackers commit poisoned `CLAUDE.md` or `.cursorrules` files into a Git repository to alter agent behavior.
* **Defense**: SHA256 checksum lock files audit instruction modification at `SessionStart`.

### 3. Slopsquatting Prevention (`harness/hooks/slopsquatting_guard.py`)
* **Risk**: 19.7% of AI-generated code snippets contain hallucinated package names. Attackers register them on PyPI/npm for supply-chain attacks.
* **Defense**: Automatically queries PyPI API during `pip install` commands and blocks execution if the package does not exist (404).

---

## Part 2: Custom ADK / SDK Agents (Google Gen AI ADK, LangChain, CrewAI)

### 1. Interceptor Middleware (`scanner/adk_middleware.py`)
Wrap custom agent loops with `SecureAgentMiddleware`:

```python
from scanner.adk_middleware import SecureAgentMiddleware

middleware = SecureAgentMiddleware()

# 1. Sanitize user prompt before sending to Gen AI ADK
clean_prompt, block_reason = middleware.wrap_agent_step(raw_user_prompt)
if block_reason:
    raise ValueError(block_reason)

# 2. Intercept tool arguments before execution
clean_args, deny_reason = middleware.wrap_tool_execution(tool_name, tool_args, is_egress=True)

# 3. Sanitize final output before rendering to user
safe_output = middleware.sanitize_agent_output(raw_agent_response)
```

### 2. Budget & Rate Limits (`scanner/budget_guard.py`)
Protect custom agents against runaway loops, infinite tool calling recursion, and Denial of Wallet:

```python
from scanner.budget_guard import AgentBudgetGuard, BudgetExceededException

budget = AgentBudgetGuard(max_cost_usd=1.0, max_tokens=50_000, max_steps=10)

for step in agent_execution_loop:
    # Record step tokens and cost
    budget.record_step(tokens_used=1200, estimated_cost=0.015)
```

---

## 📊 Feature Comparison Matrix

| Feature | CLI Harness (Claude Code) | Custom ADK/SDK Agent |
| :--- | :--- | :--- |
| **Prompt Injection Protection** | Hook (`guard.py`) | Middleware (`adk_middleware.py`) |
| **PII Anonymization** | Hook rewrite (`updatedInput`) | Middleware (`redact_pii()`) |
| **Runaway Loop Mitigation** | CLI timeout in `settings.json` | `AgentBudgetGuard` quota cap |
| **Emergency Lockdown** | `/kill-switch` endpoint | `/kill-switch` endpoint |
