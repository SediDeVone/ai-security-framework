# Architectural Evaluation & Refactoring Plan: Splitting the AI Security Framework

This document validates the concept of decoupling the **Claude Code Workstation Harness** from the **Standalone Security Scanner Service / Proxy** and outlines actionable restructuring options.

---

## 1. Concept Validation: Why Split?

Currently, the `ai-security-framework` repository combines two fundamentally different architectural concerns:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          CURRENT HYBRID REPOSITORY                          │
│                                                                             │
│  [Client-side Workstation Harness]     [Heavyweight Security Scanner]       │
│  - hooks/guard.py                      - scanner/scanner_service.py         │
│  - hooks/sf_scan.sh                    - PyTorch / Transformers             │
│  - settings.json (permissions.deny)    - SpaCy / Presidio                   │
│  - commands/ & agents/                 - Dockerfile & docker-compose.yml     │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Key Differences & Pain Points:

| Aspect | Workstation Harness (Client) | Scanner Service (Daemon/Proxy) |
| :--- | :--- | :--- |
| **Primary Target** | Local developer CLI (Claude Code) | Server / NAS / Ephemeral Container |
| **Dependencies** | Minimal (`bash`, `python3` stdlib, `jq`) | Heavy (`torch`, `spacy`, `fastapi`, `llm-guard`) |
| **Deployment Frequency**| Installed once into `~/.claude/` | Deployed as Docker container or 24/7 daemon |
| **Use Cases** | Intercepting CLI tool calls & prompts | Central scanning API for CLI, proxies, & agents |

### Concept Validation: **YES, DECOUPLING IS HIGHLY RECOMMENDED.**
Keeping heavy ML model dependencies in the same folder as lightweight shell hooks creates maintenance confusion. Separating them allows:
1. **Lightweight developer installs**: Developers who only want client-side permission enforcement don't need a 3GB Python venv with PyTorch.
2. **Flexible Service Hosting**: The scanner service can be deployed on Synology NAS, Kubernetes, or Cloud VPS independently of the local workstation config.
3. **Multi-Client Support**: Other agent frameworks (LangChain, CrewAI, custom Python bots) can consume the scanner API without pulling Claude Code hook files.

---

## 2. Refactoring Strategies

We evaluate three potential architectural paths:

### Strategy A: Monorepo with Clean Subdirectories (Logical Split)
*Keep one Git repository, but reorganize it into decoupled packages.*

```
ai-security-framework/
├── harness/                  # Client-side Claude Code integration
│   ├── hooks/                # guard.py, sf_scan.sh, supply_chain_check.sh
│   ├── commands/             # strip-pii.md
│   ├── agents/               # untrusted-reader.md
│   └── settings.json         # Base permissions.deny and event wiring
├── scanner/                  # Standalone Security Microservice
│   ├── scanner_service.py    # FastAPI service
│   ├── update_locks.py       # Checksum utility
│   ├── scanner.service       # systemd unit
│   ├── com.aisecurity.scanner.plist # launchd agent
│   ├── requirements.txt
│   ├── Dockerfile
│   └── docker-compose.yml
├── rules/                    # Shared threat intelligence rules (.nov)
│   └── injection_basics.nov
├── docs/                     # Architectural & assessment docs
│   ├── security_assessment_and_plan.md
│   └── repository_split_plan.md
└── README.md
```

* **Pros**: Simple to maintain; single repository to star/clone; shared `rules/` directory.
* **Cons**: Repository still contains all files in one Git history.

---

### Strategy B: Full Physical Split into Two Repositories (Multi-Repo)
*Split into two distinct Git repositories with independent release cycles.*

#### Repository 1: `claude-code-security-harness`
* **Purpose**: Ultra-lightweight workstation security layer for Claude Code.
* **Contents**: `hooks/`, `settings.json`, `commands/`, `agents/`, setup scripts.
* **Config**: Point `guard.py` to a configurable `SCANNER_URL` (default `http://localhost:8901` or `http://synology:8901`).

#### Repository 2: `ai-security-scanner-service` (or `ai-security-gateway`)
* **Purpose**: 24/7 containerized security microservice exposing REST APIs (`/scan/prompt`, `/scan/tool-input`, `/redact`, `/health`).
* **Contents**: `scanner_service.py`, `Dockerfile`, `docker-compose.yml`, `rules/`, Presidio custom recognizers.

* **Pros**: Cleanest separation; independent versioning; easy to deploy scanner on NAS/Cloud while developers pull only the harness.
* **Cons**: Managing two Git repositories.

---

### Strategy C: Python Library / CLI Package (`ai-security-core`)
*Package the scanner as a PyPI-installable library.*

* **Usage**: `pip install ai-security-framework`
* **Commands**:
  - `ai-security serve` (starts FastAPI scanner)
  - `ai-security install-hooks` (copies hooks to `~/.claude/`)
  - `from ai_security import Scanner` (for standalone Python agents)

* **Pros**: Professional developer distribution model.
* **Cons**: Higher initial packaging complexity (`pyproject.toml`, build pipelines).

---

## 3. Implementation Status

The repository has been successfully reorganized according to **Strategy A (Monorepo with `harness/` and `scanner/` subdirectories)**. This provides architectural clarity while keeping maintenance simple. If the standalone scanner is adopted by other teams or projects later, execute **Strategy B** to extract `scanner/` into its own repository.

---

## 4. Decision Matrix

| Criteria | Strategy A (Monorepo Subdirs) | Strategy B (2 Separate Repos) | Strategy C (PyPI Package) |
| :--- | :--- | :--- | :--- |
| **Implementation Effort** | Low (30 mins) | Medium (1-2 hours) | High (1-2 days) |
| **Clarity of Separation** | High | Maximum | High |
| **Ease of Maintenance** | High | Medium | High |
| **NAS / Synology Compatibility**| Excellent | Excellent | Good |
