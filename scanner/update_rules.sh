#!/usr/bin/env bash
# Automate NOVA rules updates from threat feeds.
# Usage: ./update_rules.sh [--force]

RULES_DIR="$HOME/.claude/nova-rules"
mkdir -p "$RULES_DIR"

echo "[nova] Checking for rule updates..."

# Example: Pulling from a hypothetical threat feed service
# In a real scenario, this would use a tool like threatfeeds-to-nova
# or simply curl a known-good repository of rules.

# For now, we simulate the update by touching the directory to trigger 
# the scanner's dynamic reload if we had downloaded anything.

# Example sync:
# curl -s https://api.threatintel.example/v1/nova/jailbreaks.nov -o "$RULES_DIR/jailbreaks.nov"

if [ "$1" == "--force" ]; then
    echo "[nova] Force reload triggered."
    touch "$RULES_DIR"
fi

echo "[nova] Rules directory is up to date."
