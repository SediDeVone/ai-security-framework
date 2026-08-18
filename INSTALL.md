# INSTALL — runbook for Claude Code

You are installing a security layer for Claude Code in a Salesforce project.
Follow these steps exactly. Do not improvise package names. If a step fails,
report it and continue with the remaining steps — do not silently skip.

## Step 0 — preconditions (ASK THE HUMAN, do not attempt yourself)

Confirm before starting:

1. Has the human accepted the Meta license for
   `meta-llama/Llama-Prompt-Guard-2-22M` on huggingface.co AND run
   `huggingface-cli login`? If not, PromptGuard 2 will silently disable —
   proceed, but say so in your final report.
2. Should STRICT_PII=1 be enabled (blocks any chat prompt containing PII)?
   Default: off.
3. The exact MCP tool names of their Atlassian/email connectors
   (`claude mcp list`), needed for Step 4.

## Step 1 — copy files (idempotent)

From this folder:

```bash
mkdir -p ~/.claude/hooks ~/.claude/nova-rules ~/.claude/commands ~/.claude/agents
cp harness/hooks/*.py harness/hooks/*.sh ~/.claude/hooks/ && chmod +x ~/.claude/hooks/*
cp rules/*.nov ~/.claude/nova-rules/
cp harness/commands/strip-pii.md ~/.claude/commands/
cp harness/agents/untrusted-reader.md ~/.claude/agents/
```

## Step 2 — MERGE settings.json (never overwrite)

Read `~/.claude/settings.json` if it exists. Deep-merge the `permissions.deny`
array (union, no duplicates) and each hooks event array (append our entries)
from this folder's `settings.json`. Write the result back. Show the human a
diff of what changed before writing.

## Step 3 — scanner service

```bash
python3 -m venv ~/.claude/scanner-venv
~/.claude/scanner-venv/bin/pip install -r scanner/requirements.txt
~/.claude/scanner-venv/bin/python -m spacy download en_core_web_lg
cp scanner/scanner_service.py ~/.claude/hooks/
```

### Autostart & Service Configuration (Recommended)
You can run the scanner service as a persistent background daemon:
- **macOS**: Edit and copy [com.aisecurity.scanner.plist](file:///Users/sebastianlasisz/workspace/repositories/ai_tools/ai-security-framework/scanner/com.aisecurity.scanner.plist) to `~/Library/LaunchAgents/` and load it:
  `launchctl load ~/Library/LaunchAgents/com.aisecurity.scanner.plist`
- **Linux**: Edit and copy [scanner.service](file:///Users/sebastianlasisz/workspace/repositories/ai_tools/ai-security-framework/scanner/scanner.service) to `/etc/systemd/system/` (or `~/.config/systemd/user/`) and enable it:
  `systemctl enable --now scanner.service`

### API Security (Recommended for Production)
To prevent unauthorized users on the network from accessing your sandbox or disabling your hooks, set the `SCANNER_API_KEY` environment variable in your service environment (e.g. plist or systemd file) and in your client shell. The scanner clients ([guard.py](file:///Users/sebastianlasisz/workspace/repositories/ai_tools/ai-security-framework/harness/hooks/guard.py) and [redact_cli.py](file:///Users/sebastianlasisz/workspace/repositories/ai_tools/ai-security-framework/harness/hooks/redact_cli.py)) will automatically pick it up and pass the key via `X-API-Key`.

Start manually and verify:

```bash
# Secure start example
export SCANNER_API_KEY="my-secret-key"
nohup ~/.claude/scanner-venv/bin/python ~/.claude/hooks/scanner_service.py \
  > /tmp/scanner.log 2>&1 &
sleep 20 && curl -s -X POST http://127.0.0.1:8901/redact \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: my-secret-key' \
  -d '{"text":"Contact John Smith at john@acme.com"}'
```

Expected: JSON with `<PERSON>` / `<EMAIL_ADDRESS>` placeholders. If torch or
model downloads fail, report it; the hooks fail open by design.

Ask the human whether to install a launchd/systemd unit for autostart —
do not create one unprompted.

## Step 4 — project adjustments

1. Edit `~/.claude/agents/untrusted-reader.md` frontmatter: replace the
   `mcp__atlassian__*` tool names with the human's actual connector tool
   names from Step 0.3.
2. Verify `sf` CLI + `@salesforce/plugin-code-analyzer` are installed:
   `sf code-analyzer --help`. If missing:
   `sf plugins install code-analyzer`.
3. jq is required by sf_scan.sh: verify `jq --version`.

## Step 5.5 — Optional Tools & Enhancements

### A. Pre-Deploy Red-Teaming (`promptfoo`)
Runs automated prompt injection & jailbreak probes.
```bash
npm install -g promptfoo          # Install CLI
make redteam                      # Run automated probes against redteam/promptfoo.yaml
```

### B. Image EXIF Metadata Cleaner (`Pillow`)
Removes GPS coordinates & camera info from image uploads before LLM processing.
```bash
~/.claude/scanner-venv/bin/pip install Pillow
```

### C. Slopsquatting Guard Hook
Prevents installing hallucinated PyPI packages (19.7% of AI code snippets).
```bash
cp harness/hooks/slopsquatting_guard.py ~/.claude/hooks/
chmod +x ~/.claude/hooks/slopsquatting_guard.py
```

### D. Red-Teaming Scanner (`garak`)
NVIDIA LLM security probing tool.
```bash
pip install -U garak
python -m garak --target_type openai --target_name gpt-4 --probes promptinject
```

## Step 6 — hand back to the human (YOU CANNOT DO THESE)

Report completion and tell the human to:

1. **Restart Claude Code** — hooks snapshot at session start; nothing is
   active until restart.
2. Run `/hooks` to confirm the entries appear.
3. Test `/strip-pii John Smith, john@acme.com, +48 601 234 567` and confirm
   the transcript shows only redacted text.
4. Note: Custom recognizers are pre-configured in the scanner service for Polish identifiers (PESEL/NIP).
5. Manually review every file you changed, especially settings.json —
   the human is the verification layer for this install, not you.
