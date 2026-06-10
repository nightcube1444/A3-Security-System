"""
A3 Security System — Semgrep Integration
Static code analysis. Reads source code and finds security
vulnerabilities before the file ever runs.
Feeds findings into the A3 threat database.
"""

import subprocess
import sqlite3
import json
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH  = DATA_DIR / "a3_threats.db"

# Severity mapping — semgrep levels to A3 scores
SEVERITY_SCORES = {
    "ERROR":   60,
    "WARNING": 30,
    "INFO":    10,
}

def log(message, level="INFO"):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    colours = {
        "INFO":  "\033[97m", "OK":    "\033[92m",
        "WARN":  "\033[93m", "ALERT": "\033[91m", "ERROR": "\033[91m"
    }
    print(f"[{ts}] {colours.get(level,'')}[SEMGREP][{level}]\033[0m {message}")

def init_semgrep_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS semgrep_findings (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp    TEXT,
            file_path    TEXT,
            rule_id      TEXT,
            severity     TEXT,
            message      TEXT,
            line_start   INTEGER,
            line_end     INTEGER,
            code_snippet TEXT,
            score        INTEGER,
            category     TEXT
        )
    """)
    conn.commit()
    conn.close()

def is_semgrep_installed():
    try:
        result = subprocess.run(
            ["semgrep", "--version"],
            capture_output=True, text=True, timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False

def install_semgrep():
    log("Installing Semgrep...")
    try:
        result = subprocess.run(
            ["pip", "install", "semgrep"],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode == 0:
            log("Semgrep installed successfully", "OK")
            return True
        else:
            log(f"Install failed: {result.stderr}", "ERROR")
            return False
    except Exception as e:
        log(f"Install error: {e}", "ERROR")
        return False

def scan_file(file_path):
    """
    Scan a single file with Semgrep using security rulesets.
    Returns list of findings.
    """
    file_path = Path(file_path)
    if not file_path.exists():
        log(f"File not found: {file_path}", "ERROR")
        return []

    log(f"Scanning: {file_path.name}")

    # Use auto ruleset — Semgrep picks the right rules for the language
    cmd = [
        "semgrep",
        "--config", "auto",
        "--json",
        "--quiet",
        str(file_path)
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60
        )

        if result.returncode not in (0, 1):
            # 0 = no findings, 1 = findings found, anything else = error
            log(f"Semgrep error: {result.stderr[:200]}", "WARN")
            return []

        if not result.stdout.strip():
            log(f"No findings in {file_path.name}", "OK")
            return []

        data     = json.loads(result.stdout)
        findings = data.get("results", [])
        log(f"Found {len(findings)} issue(s) in {file_path.name}",
            "ALERT" if findings else "OK")
        return findings

    except subprocess.TimeoutExpired:
        log(f"Scan timed out for {file_path.name}", "WARN")
        return []
    except json.JSONDecodeError:
        log("Could not parse Semgrep output", "WARN")
        return []
    except Exception as e:
        log(f"Scan error: {e}", "ERROR")
        return []

def scan_directory(dir_path):
    """Scan an entire directory recursively."""
    dir_path = Path(dir_path)
    if not dir_path.exists():
        log(f"Directory not found: {dir_path}", "ERROR")
        return []

    log(f"Scanning directory: {dir_path}")

    cmd = [
        "semgrep",
        "--config", "auto",
        "--json",
        "--quiet",
        str(dir_path)
    ]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120
        )
        if not result.stdout.strip():
            return []
        data = json.loads(result.stdout)
        findings = data.get("results", [])
        log(f"Directory scan found {len(findings)} total issue(s)",
            "ALERT" if findings else "OK")
        return findings
    except Exception as e:
        log(f"Directory scan error: {e}", "ERROR")
        return []

def save_findings(findings, source_path):
    """Save Semgrep findings to the A3 database."""
    if not findings:
        return

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.now().isoformat()

    for f in findings:
        severity = f.get("extra", {}).get("severity", "INFO").upper()
        score    = SEVERITY_SCORES.get(severity, 10)
        message  = f.get("extra", {}).get("message", "")
        rule_id  = f.get("check_id", "unknown")
        path     = f.get("path", str(source_path))
        lines    = f.get("start", {})
        end      = f.get("end", {})
        snippet  = f.get("extra", {}).get("lines", "")

        # Extract category from rule ID
        # e.g. "python.lang.security.audit.exec-detected" → "security.audit"
        parts    = rule_id.split(".")
        category = ".".join(parts[2:4]) if len(parts) >= 4 else "general"

        c.execute("""
            INSERT INTO semgrep_findings
            (timestamp, file_path, rule_id, severity, message,
             line_start, line_end, code_snippet, score, category)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        """, (
            now, path, rule_id, severity, message,
            lines.get("line", 0), end.get("line", 0),
            snippet, score, category
        ))

    conn.commit()
    conn.close()
    log(f"Saved {len(findings)} finding(s) to database", "OK")

def print_findings(findings):
    """Print findings in a clear, readable format."""
    if not findings:
        print("\n  No security issues found.\n")
        return

    colours = {
        "ERROR":   "\033[91m",
        "WARNING": "\033[93m",
        "INFO":    "\033[94m",
    }
    reset = "\033[0m"

    print(f"\n{'═'*55}")
    print(f"  SEMGREP FINDINGS — {len(findings)} issue(s)")
    print(f"{'═'*55}")

    # Group by severity
    errors   = [f for f in findings if f.get("extra",{}).get("severity","").upper() == "ERROR"]
    warnings = [f for f in findings if f.get("extra",{}).get("severity","").upper() == "WARNING"]
    infos    = [f for f in findings if f.get("extra",{}).get("severity","").upper() == "INFO"]

    for group, label in [(errors,"ERROR"), (warnings,"WARNING"), (infos,"INFO")]:
        if not group:
            continue
        col = colours.get(label, "")
        print(f"\n  {col}[{label}] — {len(group)} finding(s){reset}")
        for f in group:
            path    = f.get("path", "unknown")
            line    = f.get("start", {}).get("line", "?")
            message = f.get("extra", {}).get("message", "")
            rule    = f.get("check_id", "")
            snippet = f.get("extra", {}).get("lines", "").strip()

            print(f"\n  {col}▸{reset} {Path(path).name}:{line}")
            print(f"    Rule    : {rule}")
            print(f"    Issue   : {message}")
            if snippet:
                print(f"    Code    : {snippet[:80]}")

    print(f"\n{'═'*55}\n")

def run(target):
    """
    Main entry point. Scan a file or directory.
    Returns total threat score from all findings.
    """
    init_semgrep_db()

    if not is_semgrep_installed():
        log("Semgrep not installed — installing now...")
        if not install_semgrep():
            log("Could not install Semgrep. Run: pip install semgrep", "ERROR")
            return 0

    target = Path(target)
    if target.is_dir():
        findings = scan_directory(target)
    else:
        findings = scan_file(target)

    print_findings(findings)
    save_findings(findings, target)

    total_score = sum(
        SEVERITY_SCORES.get(
            f.get("extra", {}).get("severity", "INFO").upper(), 10
        )
        for f in findings
    )
    return total_score

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 semgrep_scanner.py <file_or_directory>")
        print("Example: python3 semgrep_scanner.py ~/myapp/")
        print("Example: python3 semgrep_scanner.py suspicious_file.py")
        sys.exit(1)

    target = sys.argv[1]
    score  = run(target)
    print(f"Total threat score from static analysis: {score}")
