"""Scan local plaintext files for likely secrets; never print raw values."""

import re
import json
import sys
from datetime import datetime
from pathlib import Path


# Visible detection rules: secret-shaped key=value pairs only.
PATTERNS = [
    (re.compile(r"(?i)password\s*=\s*\S+"), "Medium"),
    (re.compile(r"(?i)api[_-]?key\s*=\s*\S+"), "High"),
    (re.compile(r"(?i)token\s*=\s*\S+"), "High"),
]
PLAINTEXT_EXTENSIONS = (".env", ".txt", ".ini", ".cfg", ".config", ".yml", ".yaml")
FINDINGS_FILE = Path(__file__).with_name("findings.json")


def save_finding(summary, severity="Info"):
    """Append one masked result to a bounded local history for the viewer."""
    try:
        data = json.loads(FINDINGS_FILE.read_text(encoding="utf-8")) if FINDINGS_FILE.exists() else []
        if not isinstance(data, list):
            data = []
    except (OSError, json.JSONDecodeError):
        data = []
    data.append({"time": datetime.now().astimezone().strftime("%H:%M:%S"),
                 "summary": summary, "severity": severity})
    FINDINGS_FILE.write_text(json.dumps(data[-50:], indent=2), encoding="utf-8")


def mask(value):
    return value[:3] + "*" * max(0, len(value) - 6) + value[-3:] if len(value) > 6 else "****"


def is_plaintext_store(path):
    # This is a filename-based exposure proxy; it does not inspect encryption.
    return Path(path).suffix.lower() in PLAINTEXT_EXTENSIONS


def scan_file(path):
    findings = []
    exposed = is_plaintext_store(path)
    with open(path, encoding="utf-8", errors="ignore") as source:
        for lineno, line in enumerate(source, 1):
            for pattern, severity in PATTERNS:
                match = pattern.search(line)
                if match:
                    value = match.group().split("=", 1)[-1].strip()
                    findings.append((lineno, mask(value), severity, exposed))
                    break
    return findings


def main():
    if len(sys.argv) != 2:
        print("Usage: python scanner.py <file>", file=sys.stderr)
        return 2
    target = sys.argv[1]
    try:
        findings = scan_file(target)
    except OSError as error:
        print(f"Could not read {target}: {error}", file=sys.stderr)
        return 2
    for lineno, masked, severity, exposed in findings:
        flag = "EXPOSED/PLAINTEXT" if exposed else "not classified as plaintext config"
        summary = f"{Path(target).name}:{lineno}  {masked}  {flag}"
        print(f"{summary}  [{severity}]")
        save_finding(summary, severity)
    if not findings:
        print("No findings.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
