#!/usr/bin/env python3
"""Locks SHA256 hashes of instruction files in the workspace.

Computes the checksums of instruction and config files (CLAUDE.md, AGENTS.md,
.cursorrules, .env) and saves them to ~/.claude/skill_locks.json to detect
unauthorized tampering.
"""
import hashlib
import os
import json

def main():
    workspace = os.getcwd()
    lock_file = os.path.expanduser('~/.claude/skill_locks.json')
    lock_hashes = {}
    targets = ['CLAUDE.md', 'AGENTS.md', '.cursorrules', '.env']
    
    for t in targets:
        p = os.path.join(workspace, t)
        if os.path.isfile(p):
            h = hashlib.sha256()
            try:
                with open(p, 'rb') as f:
                    while chunk := f.read(8192):
                        h.update(chunk)
                lock_hashes[t] = h.hexdigest()
                print(f"Locked {t}: {lock_hashes[t]}")
            except Exception as e:
                print(f"Error locking {t}: {e}")
                
    os.makedirs(os.path.dirname(lock_file), exist_ok=True)
    with open(lock_file, 'w') as f:
        json.dump(lock_hashes, f, indent=2)
    print(f"Lockfile written to {lock_file}")

if __name__ == "__main__":
    main()
