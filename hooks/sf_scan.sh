#!/usr/bin/env bash
# PostToolUse hook: scoped Salesforce Code Analyzer scan.
# Scans ONLY the file Claude just wrote/edited, PMD security rules only.
# SFGE (whole-graph data flow) deliberately excluded — run that in CI.
set -u
INPUT=$(cat)

FILE=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty')
[ -z "$FILE" ] && exit 0

case "$FILE" in
  *.cls|*.trigger) SELECTOR="pmd:Security" ;;
  */lwc/*.js|*/aura/*.js) SELECTOR="eslint" ;;
  *) exit 0 ;;
esac

command -v sf >/dev/null || exit 0

OUT=$(mktemp /tmp/sfscan.XXXX.json)
sf code-analyzer run \
  --workspace "$FILE" \
  --rule-selector "$SELECTOR" \
  --output-file "$OUT" >/dev/null 2>&1

# Block on severity 1-2 (critical/high) so Claude fixes it in the same turn
VIOLATIONS=$(jq -r '[.violations[]? | select(.severity <= 2) |
  "\(.rule) (\(.primaryLocationIndex // "")): \(.message | .[0:160])"] |
  join("; ")' "$OUT" 2>/dev/null)
rm -f "$OUT"

if [ -n "$VIOLATIONS" ] && [ "$VIOLATIONS" != "null" ]; then
  jq -n --arg r "Code Analyzer security violations in $FILE — fix before proceeding: $VIOLATIONS" \
    '{"decision":"block","reason":$r}'
fi
exit 0
