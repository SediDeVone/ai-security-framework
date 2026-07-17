#!/usr/bin/env python3
"""CLI for the /strip-pii command.

Usage:
  redact_cli.py "<text>"      -> prints redacted text
  redact_cli.py <file-path>   -> writes <file>.redacted alongside, prints path

Uses the warm scanner service; falls back to direct Presidio import
(slow first call) if the service is down.
"""
import json
import os
import sys
import urllib.request

SCANNER = "http://127.0.0.1:8901/redact"


def redact(text: str) -> str:
    try:
        req = urllib.request.Request(
            SCANNER, data=json.dumps({"text": text}).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read())["text"]
    except Exception:
        from presidio_analyzer import AnalyzerEngine
        from presidio_anonymizer import AnonymizerEngine
        findings = AnalyzerEngine().analyze(text=text, language="en")
        if not findings:
            return text
        return AnonymizerEngine().anonymize(
            text=text, analyzer_results=findings).text


def main():
    arg = " ".join(sys.argv[1:]).strip()
    if not arg:
        print("(no text given to /strip-pii)")
        return
    if os.path.isfile(arg):
        with open(arg, encoding="utf-8", errors="replace") as f:
            red = redact(f.read())
        out_path = arg + ".redacted"
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(red)
        print(f"Redacted copy written to {out_path} — work with that file, "
              f"do not read the original.")
    else:
        print(redact(arg))


if __name__ == "__main__":
    main()
