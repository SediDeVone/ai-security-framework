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

## Install

```bash
# 1. Scanner service (persistent — run via systemd/launchd or docker)
pip install -r scanner/requirements.txt
python scanner/scanner_service.py &          # listens on 127.0.0.1:8901

# 2. Supply-chain scanners
uvx mcp-scan@latest                          # or: npx snyk agent-scan
pipx install sketchy-scan                    # Adversis sketchy (check repo for exact name)
brew install gitleaks

# 3. Copy hooks + settings
cp -r hooks ~/.claude/hooks
cp -r rules ~/.claude/nova-rules
# merge settings.json into ~/.claude/settings.json
```

## Files

- `settings.json` — hooks wiring + permission deny rules
- `hooks/guard.py` — single dispatcher (prompt/tool-in/tool-out/Stop trace audit)
- `hooks/sf_scan.sh` — Salesforce Code Analyzer, scoped to the ONE changed
  file, PMD security rules only (SFGE stays in CI — see code-analyzer.yml)
- `hooks/redact_cli.py` — CLI behind the /strip-pii command
- `commands/strip-pii.md` — copy to `~/.claude/commands/`. Explicit local
  redaction: `/strip-pii <text or file path>`. The `!`-bash runs client-side
  BEFORE the prompt is sent, so only Presidio's output enters model context.
  Verify once on your version by checking the transcript for raw text.
- `agents/untrusted-reader.md` — copy to `~/.claude/agents/`. Read-only
  subagent for JIRA/Confluence/email/web content: injections that fire in it
  have no write/Bash/outbound tools to abuse. Adjust the MCP tool names in
  its frontmatter to match your connectors.
- `scanner/scanner_service.py` — FastAPI service: Presidio (with custom Polish PESEL/NIP recognizers) + NOVA (with dynamic hot-reloading) + PromptGuard 2 (injection scoring) + optional AlignmentCheck (trace audit)
- `scanner/requirements.txt`
- `rules/injection_basics.nov` — starter NOVA rule (extend via PromptIntel /
  `threatfeeds-to-nova`)
- `code-analyzer.yml` — Code Analyzer v5 config; per-file PMD in hooks,
  full SFGE data-flow scan in CI only (it cannot be scoped to changed files)
- `docs/security_assessment_and_plan.md` — Security assessment, validation notes, and standalone agent architecture plan.

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
