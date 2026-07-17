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
cp hooks/*.py hooks/*.sh ~/.claude/hooks/ && chmod +x ~/.claude/hooks/*
cp rules/*.nov ~/.claude/nova-rules/
cp commands/strip-pii.md ~/.claude/commands/
cp agents/untrusted-reader.md ~/.claude/agents/
cp code-analyzer.yml <salesforce-project-root>/code-analyzer.yml  # skip if one exists
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

Start it and verify:

```bash
nohup ~/.claude/scanner-venv/bin/python ~/.claude/hooks/scanner_service.py \
  > /tmp/scanner.log 2>&1 &
sleep 20 && curl -s -X POST http://127.0.0.1:8901/redact \
  -H 'Content-Type: application/json' \
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

## Step 5 — smoke tests (run all, show results)

```bash
# hook wiring responds correctly
echo '{"hook_event_name":"UserPromptSubmit","prompt":"hello"}' \
  | python3 ~/.claude/hooks/guard.py; echo "exit=$?"          # expect exit=0, no output

# PII redaction path
echo '{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"x.txt","content":"Call John Smith at john.smith@acme.com about invoice 12345678"}}' \
  | python3 ~/.claude/hooks/guard.py                          # expect updatedInput with redactions

# sf scan ignores non-Salesforce files
echo '{"hook_event_name":"PostToolUse","tool_name":"Write","tool_input":{"file_path":"/tmp/readme.md"}}' \
  | bash ~/.claude/hooks/sf_scan.sh; echo "exit=$?"           # expect exit=0, no output
```

## Step 6 — hand back to the human (YOU CANNOT DO THESE)

Report completion and tell the human to:

1. **Restart Claude Code** — hooks snapshot at session start; nothing is
   active until restart.
2. Run `/hooks` to confirm the entries appear.
3. Test `/strip-pii John Smith, john@acme.com, +48 601 234 567` and confirm
   the transcript shows only redacted text.
4. Note: default Presidio misses Polish identifiers (PESEL/NIP) — custom
   recognizers needed if org data includes them.
5. Manually review every file you changed, especially settings.json —
   the human is the verification layer for this install, not you.
