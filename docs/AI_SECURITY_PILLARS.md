# AI Security Framework — 6 Pillars Alignment

This document maps the repository architecture directly to the **6 Pillars of Secure AI Applications** derived from enterprise threat models and security standards (OWASP, MITRE ATLAS, NIST AI RMF).

---

## 🏛️ Architecture Overview: The 6 Pillars

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                               THE 6 PILLARS OF AI SECURITY                             │
├───────────────────┬───────────────────┬───────────────────┬────────────────────────────┤
│ 1. AI Architecture│ 2. Injection      │ 3. Data & Secrets │ 4. Secure RAG              │
│    - Dual LLM     │    - Spotlighting │    - Presidio PII  │    - Pre-retrieval Filter │
│    - CaMeL        │    - PromptGuard  │    - Custom PESEL │    - Vector RBAC           │
│    - Sandboxing   │    - HiTL         │    - Secrets Vault│    - Anomaly Detection     │
├───────────────────┴───────────────────┴───────────────────┴────────────────────────────┤
│ 5. Agent & MCP Security                   6. Monitoring, Detection & IR                │
│    - OAuth 2.1 + PKCE                      - Pre-deploy Red-Teaming (garak/promptfoo)  │
│    - Tool Scope & Per-call Auth            - Kill Switch Endpoint                      │
│    - Audit Logging                         - MITRE ATLAS / OWASP / NIST Mapping       │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Pillar 1: Secure AI Architecture & Least Privilege
* **Principle**: *Never elevate trust or permissions simply because data came from a model or external input.*
* **CaMeL Pattern (DeepMind 2025 / Dual LLM)**:
  - **Privileged LLM**: Sees user intent, plans actions, and calls tools. Has NO direct exposure to raw untrusted data.
  - **Quarantined LLM**: Processes untrusted data (web pages, PDFs, emails) with **zero tool access**. Returns sanitized data/symbols.
* **Implementation in Repo**:
  - `harness/agents/untrusted-reader.md` — Quarantined subagent definition.
  - `scanner/camel.py` — Python helper enforcing Dual LLM execution flow.
  - Hard sandbox execution in Docker containers via `scanner/docker-compose.yml`.

---

## Pillar 2: Prompt Injection Defense in Depth
* **Principle**: *No single defense stops 100% of injections; build layered defenses.*
* **Layers**:
  1. **Spotlighting**: Delimit, datamark, and encode untrusted inputs so the model distinguishes DATA from INSTRUCTIONS (`scanner/spotlighting.py`).
  2. **Input Scanners**: `Llama-Prompt-Guard-2-86M` (97.5% recall @ 1% FP) and `nova-hunting` pattern matching (`scanner/scanner_service.py`).
  3. **Source Validation**: Treat RAG, web, email, and calendar content as permanently untrusted.
  4. **Human-in-the-Loop (HiTL)**: Mandate explicit human confirmation for destructive/non-reversible actions (file deletion, payment, config change). `harness/hooks/guard.py` enforces `permissionDecision: "ask"` on outbound MCP/Bash calls.
  5. **Output Scanning**: Redact PII, secrets, XSS, and malicious URLs before rendering results.

---

## Pillar 3: Data Protection & PII Masking
* **Principle**: *Mask data BEFORE it reaches the LLM model and BEFORE tool results re-enter context.*
* **Implementation**:
  - **Microsoft Presidio**: `presidio-analyzer` + `presidio-anonymizer` integrated into `scanner/scanner_service.py`.
  - **Regional Compliance**: Pre-configured custom recognizers for Polish **PESEL** (11-digit national ID) and **NIP** (tax identification number).
  - **Anonymization Strategies**: Supported modes: `replace` (`<PERSON>`), `hash` (SHA-256), `encrypt`, and `fake`.
  - **Zero Data Retention (ZDR)**: Guidelines for using enterprise ZDR endpoints to avoid 30-day provider logging.

---

## Pillar 4: Secure RAG & Vector Database Hygiene
* **Principle**: *System prompt as access control is "security theater." Enforce access controls at the database layer.*
* **Pre-Retrieval Filtering**: Enforce FGAC (Fine-Grained Access Control) and JWT tenant filters inside vector DB queries (Milvus, Elasticsearch, Qdrant, Pinecone) before nearest-neighbor search.
* **Ingest Hygiene**: AES-256 encrypted vector storage, tenant namespaces, signed document chunks, and embedding anomaly detection.

---

## Pillar 5: Agent & MCP Security
* **Principle**: *Apply zero-trust principles to MCP tools and agentic workflows.*
* **OAuth 2.1 + PKCE**: Standard authorization for remote MCP servers with Resource Indicators (RFC 8707).
* **Tool-Level Scopes**: Grants per tool (e.g. `read` scope does not grant `delete`).
* **Supply Chain Scans**: Daily automated `mcp-scan` and `sketchy` checks on MCP servers and skillpacks (`harness/hooks/supply_chain_check.sh`).
* **Emergency Kill Switch**: Instant agent cut-off endpoint (`/kill-switch`) in `scanner/scanner_service.py`.

---

## Pillar 6: Monitoring, Detection & Response (IR)
* **Principle**: *Continuous security lifecycle: Red-team $\rightarrow$ Guard $\rightarrow$ Detect $\rightarrow$ Respond.*
* **Pre-Deploy Red-Teaming**: Automated evaluation with `garak` and `promptfoo` (`redteam/promptfoo.yaml`).
* **Runtime Guardrails**: FastAPI scanner microservice exposing `/scan/prompt`, `/scan/tool-input`, `/scan/tool-output`, `/scan/trace`.
* **Incident Response (IR)**:
  - Anomaly billing detection (LLM Jacking mitigation).
  - Emergency key rotation & session isolation.
  - IR logging: Audit log of prompts, tool calls, costs, and tokens saved to `logs/security_audit.jsonl`.
