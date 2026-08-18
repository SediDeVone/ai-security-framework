# Claude Code Security Setup

Layered security for Claude Code covering hooks, skills, and MCP.
Adjusted architecture: **one persistent scanner service** (avoids LLM Guard's
multi-second model cold start per hook call) + **one thin hook dispatcher**.

## Architecture

```
prompt ──► UserPromptSubmit ─► guard.py ─► scanner service :8901 ─► NOVA + LLM Guard (block only)
tool in ─► PreToolUse ───────► guard.py ─► Presidio redact ─► updatedInput (rewrite)
tool out ► PostToolUse ──────► guard.py ─► NOVA on fetched content ─► block/flag
supply  ─► SessionStart ─────► agent-scan (mcp-scan) + sketchy (async, cached daily)
```

## Layers

| Layer | Tool | Hook / mechanism | Action |
|---|---|---|---|
| Prompt screening | NOVA rules + LLM Guard (Secrets, InvisibleText) | `UserPromptSubmit` | block (rewrite not possible here) |
| PII redaction | Presidio | `PreToolUse` → `updatedInput` | rewrite tool args (Write/Edit/Bash/MCP) |
| Secrets egress | gitleaks | `PreToolUse` on Bash + MCP sends | deny |
| Injection in fetched content | NOVA + LLM Guard | `PostToolUse` on WebFetch/MCP reads | block/flag via `updatedToolOutput` |
| MCP supply chain | Snyk agent-scan (ex mcp-scan, Invariant) | `SessionStart` + CI | tool poisoning, shadowing, rug pulls; also scans **skills** |
| Config tampering | sketchy (Adversis) | git post-checkout / CI | scans settings.json, CLAUDE.md, hook defs |
| Hard limits | Claude Code permissions | `permissions.deny` + managed settings | not bypassable by hooks |

## Install & Shortcuts

Using `make`:

```bash
make install-harness  # Installs hooks, commands, agents, & rules into ~/.claude/
make docker-up        # Starts containerized scanner service
make test             # Sanity & health check endpoints
make update-locks     # Computes and locks SHA256 hashes of instruction files
```

Manual install:

```bash
# 1. Scanner service (persistent — run via systemd/launchd or docker)
pip install -r scanner/requirements.txt
python scanner/scanner_service.py &          # listens on 127.0.0.1:8901

# 2. Supply-chain scanners
uvx mcp-scan@latest                          # or: npx snyk agent-scan
pipx install sketchy-scan                    # Adversis sketchy (check repo for exact name)
brew install gitleaks

# 3. Copy hooks + settings
cp -r harness/hooks ~/.claude/hooks
cp -r rules ~/.claude/nova-rules
cp harness/commands/strip-pii.md ~/.claude/commands/
cp harness/agents/untrusted-reader.md ~/.claude/agents/
# merge harness/settings.json into ~/.claude/settings.json
```

## Files

- `Makefile` — Shortcuts for installation, Docker management, & sanity testing
- `harness/settings.json` — hooks wiring + permission deny rules
- `harness/hooks/guard.py` — single dispatcher (prompt/tool-in/tool-out/Stop trace audit)
- `harness/hooks/sf_scan.sh` — Salesforce Code Analyzer, scoped to changed files
- `harness/hooks/redact_cli.py` — CLI behind the /strip-pii command
- `harness/commands/strip-pii.md` — copy to `~/.claude/commands/`
- `harness/agents/untrusted-reader.md` — copy to `~/.claude/agents/`
- `harness/hooks/skill_integrity_check.py` — SHA256 instruction & skill file integrity checker
- `scanner/adk_middleware.py` — Universal ADK/SDK security interceptor for custom Python agents (Google Gen AI ADK, LangChain, CrewAI)
- `scanner/budget_guard.py` — Token quota, step limit, & budget cap manager against Denial of Wallet
- `scanner/client.py` — Python SDK client for consuming the scanner in standalone agents
- `scanner/scanner_service.py` — FastAPI service: Presidio + NOVA + PromptGuard 2
- `scanner/scanner.service` — systemd unit template for persistent background execution on Linux
- `scanner/com.aisecurity.scanner.plist` — launchd configuration template for macOS autostart
- `scanner/Dockerfile` & `scanner/docker-compose.yml` — Docker container deployment
- `rules/` — Threat intelligence NOVA rules (.nov)
- `docs/ADK_HARNESS_SECURITY_GUIDE.md` — Dual security guide for CLI harnesses & custom ADK/SDK agents
- `docs/AI_SECURITY_PILLARS.md` — 6 Pillars of Secure AI Applications (Architecture, Injection, Data/PII, RAG, Agents, Monitoring)
- `docs/THREAT_MATRIX_MAPPING.md` — Comprehensive threat matrix & defense mapping guide
- `docs/` — Architecture assessments, split plans, & documentation

## Optional Security Tools & Configurations

| Tool | Purpose | Install / Run Command |
| :--- | :--- | :--- |
| **`promptfoo`** | Automated pre-deploy red-teaming & prompt injection probes | `npm install -g promptfoo` $\rightarrow$ `make redteam` |
| **`Pillow`** | EXIF & GPS metadata stripping from image uploads | `pip install Pillow` |
| **`slopsquatting_guard`** | PyPI API package existence verification hook | `cp harness/hooks/slopsquatting_guard.py ~/.claude/hooks/` |
| **`garak`** | NVIDIA LLM vulnerability & red-team scanner | `pip install -U garak` $\rightarrow$ `python -m garak --probes promptinject` |
| **`gitleaks`** | Git repository credential & secret scanner | `brew install gitleaks` |
| **`mcp-scan`** | MCP server supply chain & tool poisoning audit | `uvx mcp-scan@latest` |

## Deliberate choices

1. **PromptInjection classifier is advisory, not blocking** — too many false
   positives/negatives to be a gate. NOVA rules (explainable, tunable) gate;
   the classifier only annotates.
2. **Fail-open with logging** for scanner outages on `UserPromptSubmit`
   (a dead service shouldn't brick your session), **fail-closed on
   `PreToolUse`** for MCP sends (data egress is the higher risk).
3. **Redaction only at tool boundary.** `UserPromptSubmit` cannot rewrite the
   prompt — it blocks with a reason so you can resubmit clean.
4. **Permissions > hooks.** Hooks can be misconfigured or time out;
   `permissions.deny` and managed settings are enforced by Claude Code itself.
   Keep `curl|sh`, `.env` reads, and unpinned MCP installs in deny rules,
   not just hook logic.
5. **Dynamic Rule Reloading** — Rule updates in the rules directory are hot-loaded by the scanner service on the next request, eliminating manual restarts of the daemon.
6. **Regional PII Support** — Configured custom Presidio recognizers for Polish PESEL and NIP numbers, expanding out-of-the-box GDPR compliance.

## Not included, worth considering

- `allowManagedMcpServersOnly: true` + `allowedMcpServers` in managed settings
  (enterprise) — pins MCP servers centrally.
- `InstructionsLoaded` hook — audit log of every skill/CLAUDE.md load
  (observability only, can't block).
- Sandbox/devcontainer for `--dangerously-skip-permissions` runs.
