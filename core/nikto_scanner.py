"""
A3 Security System — Nikto Integration
Fast web server scanner. Checks for outdated software,
dangerous files, misconfigurations, and known vulnerabilities.
No Java needed — runs via command line.
"""

import subprocess
import sqlite3
import json
import re
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH  = DATA_DIR / "a3_threats.db"

# Severity scoring based on finding type
FINDING_SCORES = {
    "outdated":      20,
    "dangerous":     40,
    "misconfigured": 30,
    "default":       35,
    "vulnerability": 50,
    "info":          10,
}

def log(message, level="INFO"):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    colours = {
        "INFO":  "\033[97m", "OK":    "\033[92m",
        "WARN":  "\033[93m", "ALERT": "\033[91m",
        "ERROR": "\033[91m"
    }
    print(f"[{ts}] {colours.get(level,'')}[NIKTO][{level}]\033[0m {message}")

# ── Database ───────────────────────────────────────────────────────────────────

def init_nikto_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS nikto_findings (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT,
            target      TEXT,
            finding     TEXT,
            method      TEXT,
            url         TEXT,
            score       INTEGER,
            osvdb       TEXT,
            raw         TEXT
        )
    """)
    conn.commit()
    conn.close()

# ── Check Nikto installed ─────────────────────────────────────────────────────

def is_nikto_installed():
    try:
        result = subprocess.run(
            ["nikto", "-Version"],
            capture_output=True, text=True, timeout=10
        )
        return True
    except Exception:
        return False

# ── Parse Nikto output ────────────────────────────────────────────────────────

def score_finding(text):
    """Score a finding based on keywords in the description."""
    text_lower = text.lower()
    if any(w in text_lower for w in ["vulnerability", "cve-", "exploit"]):
        return FINDING_SCORES["vulnerability"]
    if any(w in text_lower for w in ["dangerous", "allows", "execute"]):
        return FINDING_SCORES["dangerous"]
    if any(w in text_lower for w in ["default", "password", "credential"]):
        return FINDING_SCORES["default"]
    if any(w in text_lower for w in ["outdated", "old version", "obsolete"]):
        return FINDING_SCORES["outdated"]
    if any(w in text_lower for w in ["misconfigur", "header missing", "not set"]):
        return FINDING_SCORES["misconfigured"]
    return FINDING_SCORES["info"]

def parse_nikto_output(output):
    """Parse Nikto text output into structured findings."""
    findings = []
    for line in output.splitlines():
        line = line.strip()
        # Nikto findings start with + prefix
        if not line.startswith("+"):
            continue
        # Skip header/summary lines
        if any(s in line for s in ["Target IP:", "Target Hostname:",
                                    "Target Port:", "Start Time:",
                                    "End Time:", "requests made",
                                    "host(s) tested", "Nikto"]):
            continue

        # Extract OSVDB reference if present
        osvdb = ""
        osvdb_match = re.search(r"OSVDB-(\d+)", line)
        if osvdb_match:
            osvdb = osvdb_match.group(0)

        # Extract URL if present
        url = ""
        url_match = re.search(r"(/[^\s:]+)", line)
        if url_match:
            url = url_match.group(1)

        # Extract HTTP method if present
        method = ""
        method_match = re.search(r"\b(GET|POST|HEAD|OPTIONS|PUT|DELETE)\b", line)
        if method_match:
            method = method_match.group(1)

        finding_text = line.lstrip("+ ").strip()
        score = score_finding(finding_text)

        findings.append({
            "finding": finding_text,
            "method":  method,
            "url":     url,
            "osvdb":   osvdb,
            "score":   score,
            "raw":     line
        })

    return findings

# ── Run Nikto scan ────────────────────────────────────────────────────────────

def scan(target, port=None, ssl=False, timeout_minutes=3):
    """
    Scan a target URL or IP with Nikto.
    target: URL or IP (e.g. '192.168.1.1' or 'http://mysite.com')
    port: optional port number
    ssl: set True for HTTPS targets
    """
    if not is_nikto_installed():
        log("Nikto not installed. Run: brew install nikto", "ERROR")
        return []

    # Clean up target
    target = target.replace("http://", "").replace("https://", "").rstrip("/")

    log(f"Starting Nikto scan: {target}")

    cmd = ["nikto", "-h", target, "-nointeractive", "-Format", "txt"]

    if port:
        cmd += ["-p", str(port)]
    if ssl:
        cmd += ["-ssl"]

    # Limit scan time
    cmd += ["-maxtime", f"{timeout_minutes}m"]

    try:
        log(f"Running scan (max {timeout_minutes} min)...")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_minutes * 60 + 30
        )
        output = result.stdout + result.stderr

        if not output.strip():
            log("No output from Nikto", "WARN")
            return []

        findings = parse_nikto_output(output)
        log(f"Scan complete — {len(findings)} finding(s)", 
            "ALERT" if findings else "OK")

        return findings, output

    except subprocess.TimeoutExpired:
        log("Scan timed out", "WARN")
        return [], ""
    except Exception as e:
        log(f"Scan error: {e}", "ERROR")
        return [], ""

# ── Save and display ──────────────────────────────────────────────────────────

def save_findings(findings, target, raw_output):
    if not findings:
        return
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.now().isoformat()
    for f in findings:
        c.execute("""
            INSERT INTO nikto_findings
            (timestamp, target, finding, method, url, score, osvdb, raw)
            VALUES (?,?,?,?,?,?,?,?)
        """, (now, target, f["finding"], f["method"],
              f["url"], f["score"], f["osvdb"], f["raw"]))
    conn.commit()
    conn.close()
    log(f"Saved {len(findings)} finding(s) to database", "OK")

def print_findings(findings, target):
    if not findings:
        print(f"\n  No findings for {target}\n")
        return

    high   = [f for f in findings if f["score"] >= 40]
    medium = [f for f in findings if 20 <= f["score"] < 40]
    low    = [f for f in findings if f["score"] < 20]

    print(f"\n{'═'*55}")
    print(f"  NIKTO RESULTS — {target}")
    print(f"  {len(findings)} finding(s): "
          f"{len(high)} high  {len(medium)} medium  {len(low)} low")
    print(f"{'═'*55}")

    for group, label, colour in [
        (high,   "HIGH",   "\033[91m"),
        (medium, "MEDIUM", "\033[93m"),
        (low,    "LOW",    "\033[94m")
    ]:
        if not group:
            continue
        print(f"\n  {colour}[{label}]{chr(0x1b)}[0m")
        for f in group:
            print(f"\n  ▸ {f['finding'][:120]}")
            if f["url"]:
                print(f"    URL    : {f['url']}")
            if f["method"]:
                print(f"    Method : {f['method']}")
            if f["osvdb"]:
                print(f"    Ref    : {f['osvdb']}")

    print(f"\n{'═'*55}\n")

# ── Quick scan common local targets ──────────────────────────────────────────

def scan_network_devices():
    """
    Scan all HTTP devices found by Layer 5 signal detector.
    Useful for scanning your router and other network devices.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            SELECT ip, open_ports FROM network_devices
            WHERE open_ports LIKE '%HTTP%'
               OR open_ports LIKE '%http%'
        """)
        devices = c.fetchall()
        conn.close()
    except Exception:
        devices = []

    if not devices:
        log("No HTTP devices found in network scan. Run signal_detector.py first.")
        return

    log(f"Found {len(devices)} HTTP device(s) to scan")
    for ip, ports_json in devices:
        log(f"Scanning {ip}...")
        result = scan(ip, timeout_minutes=2)
        if isinstance(result, tuple):
            findings, raw = result
        else:
            findings, raw = result, ""
        print_findings(findings, ip)
        save_findings(findings, ip, raw)

# ── Main ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    init_nikto_db()

    if not is_nikto_installed():
        log("Nikto not found. Install with: brew install nikto", "ERROR")
        sys.exit(1)

    if len(sys.argv) < 2:
        print("\nUsage:")
        print("  Scan a target   : python3 nikto_scanner.py <target>")
        print("  Scan your router: python3 nikto_scanner.py 192.168.1.1")
        print("  Scan network    : python3 nikto_scanner.py --network")
        print("\nExamples:")
        print("  python3 nikto_scanner.py 192.168.1.1")
        print("  python3 nikto_scanner.py http://localhost:8000")
        print("  python3 nikto_scanner.py --network")
        sys.exit(0)

    target = sys.argv[1]

    if target == "--network":
        scan_network_devices()
    else:
        result = scan(target)
        if isinstance(result, tuple):
            findings, raw = result
        else:
            findings, raw = result, ""
        print_findings(findings, target)
        save_findings(findings, target, raw)
        total = sum(f["score"] for f in findings)
        print(f"Total risk score: {total}")