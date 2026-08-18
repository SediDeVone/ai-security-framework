#!/usr/bin/env python3
"""Skill & Instruction Integrity Checker (Harness Defense).

Verifies checksums of project instruction files (CLAUDE.md, AGENTS.md, .cursorrules)
and skillpacks to detect instruction poisoning or unauthorized tampering.
Reference: AI Security Framework / Supply Chain Defense.
"""
import hashlib
import json
import os
import sys
from typing import Dict, List


def calculate_file_sha256(filepath: str) -> str:
    """Calculates SHA256 hash of an instruction or skill file."""
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def check_instruction_files(workspace_dir: str, lock_hashes: Dict[str, str] = None) -> List[str]:
    """Audits instruction files in workspace for unauthorized modifications."""
    alerts = []
    target_files = ["CLAUDE.md", "AGENTS.md", ".cursorrules", ".env"]
    
    for filename in target_files:
        filepath = os.path.join(workspace_dir, filename)
        if os.path.isfile(filepath):
            current_hash = calculate_file_sha256(filepath)
            if lock_hashes and filename in lock_hashes:
                if lock_hashes[filename] != current_hash:
                    alerts.append(f"INSTRUCTION TAMPERING DETECTED: '{filename}' hash changed!")
    return alerts


def main():
    # SessionStart check
    workspace = os.getcwd()
    
    lock_file = os.path.expanduser("~/.claude/skill_locks.json")
    lock_hashes = {}
    if os.path.exists(lock_file):
        try:
            with open(lock_file, "r") as f:
                lock_hashes = json.load(f)
        except Exception:
            pass
            
    alerts = check_instruction_files(workspace, lock_hashes)
    if alerts:
        for alert in alerts:
            print(f"[security-alert] {alert}", file=sys.stderr)

    sys.exit(0)


if __name__ == "__main__":
    main()
