---
description: Redact PII locally (Presidio) before the text reaches Claude
allowed-tools: Bash(python3 ~/.claude/hooks/redact_cli.py:*)
---

!`python3 ~/.claude/hooks/redact_cli.py "$ARGUMENTS"`

The text above was PII-redacted locally before you received it. Treat it as
my message and respond to it. Placeholders like <PERSON> or <EMAIL_ADDRESS>
stand for redacted values — never ask me to reveal them.
