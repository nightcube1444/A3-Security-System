"""
A3 Security System — Master Controller
The nervous system. Connects Layer 2, 3, and 4 together.
When the monitor flags a file → sandbox it → AI analyses it.
Everything automatic, everything logged.
"""

import time
import sqlite3
import json
import threading
import subprocess
import sys
import os
from datetime import datetime
from pathlib import Path

# Import our layers
sys.path.insert(0, str(Path(__file__).parent))
from sandbox import run_in_sandbox, init_sandbox_db, pull_sandbox_image
from ai_analyst import analyse_report, init_ai_db, ask_ollama
from swarm import start_swarm, publish_threat, check_swarm_intel

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).parent.parent
DATA_DIR    = BASE_DIR / "data"
DB_PATH     = DATA_DIR / "a3_threats.db"
VENV_PYTHON = BASE_DIR / "venv" / "bin" / "python3"   # always use venv Python

# ── State ─────────────────────────────────────────────────────────────────────
processed_file_ids    = set()
processed_sandbox_ids = set()

# ── Logging ───────────────────────────────────────────────────────────────────

COLOURS = {
    "INFO":  "\033[97m",
    "WARN":  "\033[93m",
    "ALERT": "\033[91m",
    "OK":    "\033[92m",
    "AI":    "\033[95m",
}
RESET = "\033[0m"

def log(message, level="INFO"):
    ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    col = COLOURS.get(level, "")
    print(f"[{ts}] {col}[A3 CTRL][{level}]{RESET} {message}")

# ── Pipeline: file → sandbox → AI ────────────────────────────────────────────

def run_full_pipeline(file_path, file_event_id):
    """
    Full pipeline for a single flagged file.
    Runs in its own thread so the monitor keeps watching.
    """
    file_path = Path(file_path)
    log(f"Pipeline started for: {file_path.name}", "ALERT")

    # ── Step 1: Sandbox ───────────────────────────────────────────────────────
    log(f"Sending to sandbox: {file_path.name}")
    report = run_in_sandbox(file_path)

    if not report:
        log(f"Sandbox failed for: {file_path.name}", "WARN")
        return

    log(f"Sandbox done — verdict:{report['verdict']} score:{report['score']}", "OK")

    # ── Step 2: AI Analysis ───────────────────────────────────────────────────
    log(f"Sending to Llama3...", "AI")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT id FROM sandbox_reports
        WHERE file_path = ?
        ORDER BY id DESC LIMIT 1
    """, (str(file_path),))
    row = c.fetchone()
    conn.close()
    sr_id = row[0] if row else None

    assessment = analyse_report(report, sandbox_report_id=sr_id)

    if assessment:
        action = assessment.get("recommended_action", "monitor").upper()
        ttype  = assessment.get("threat_type", "unknown").upper()
        log(f"AI verdict: {ttype} → Action: {action}", "AI")

        if action == "QUARANTINE":
            quarantine_file(file_path, report, assessment)
        elif action == "DELETE":
            log(f"DELETE recommended for {file_path.name} — logged only", "WARN")
        # Record on blockchain
        if report["verdict"] in ("MALICIOUS", "SUSPICIOUS"):
            try:
                record_threat(
                    str(file_path),
                    report.get("hash", ""),
                    report["verdict"],
                    ttype.lower(),
                    report.get("flags", []),
                    report.get("score", 0)
                )
                log(f"Threat recorded on blockchain ✓", "OK")
            except Exception as e:
                log(f"Blockchain record failed: {e}", "WARN")
    log(f"Pipeline complete for: {file_path.name}", "OK")

def quarantine_file(file_path, report, assessment):
    """Copy a confirmed threat to the quarantine folder."""
    quarantine_dir = BASE_DIR / "quarantine"
    quarantine_dir.mkdir(exist_ok=True)

    dest = quarantine_dir / f"{file_path.name}.quarantined"
    try:
        import shutil
        shutil.copy2(file_path, dest)
        log(f"QUARANTINED: {file_path.name} → quarantine/", "ALERT")

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS quarantine_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT,
                original    TEXT,
                quarantined TEXT,
                verdict     TEXT,
                threat_type TEXT,
                score       INTEGER
            )
        """)
        c.execute("""
            INSERT INTO quarantine_log
            (timestamp, original, quarantined, verdict, threat_type, score)
            VALUES (?,?,?,?,?,?)
        """, (
            datetime.now().isoformat(),
            str(file_path),
            str(dest),
            report.get("verdict", ""),
            assessment.get("threat_type", "unknown"),
            report.get("score", 0)
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        log(f"Quarantine failed: {e}", "WARN")

# ── Watchers ───────────────────────────────────────────────────────────────────

def watch_file_events():
    """Poll DB for new high-score file events from Layer 2."""
    log("File event watcher started")
    while True:
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("""
                SELECT id, path, score FROM file_events
                WHERE score >= 30
                ORDER BY id DESC LIMIT 10
            """)
            rows = c.fetchall()
            conn.close()

            for fid, fpath, score in rows:
                if fid not in processed_file_ids:
                    processed_file_ids.add(fid)
                    p = Path(fpath)
                    if p.exists():
                        log(f"Flagged file [score:{score}]: {p.name}", "ALERT")
                        t = threading.Thread(
                            target=run_full_pipeline,
                            args=(fpath, fid),
                            daemon=True
                        )
                        t.start()
                    else:
                        log(f"Flagged file gone: {fpath}", "WARN")

        except Exception as e:
            log(f"File watcher error: {e}", "WARN")

        time.sleep(5)

def watch_process_events():
    """Poll for high-score process events from Layer 2."""
    log("Process event watcher started")
    seen = set()
    while True:
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("""
                SELECT id, pid, name, score, flags FROM process_events
                WHERE score >= 50
                ORDER BY id DESC LIMIT 20
            """)
            rows = c.fetchall()
            conn.close()

            for rid, pid, name, score, flags_json in rows:
                if rid not in seen:
                    seen.add(rid)
                    flags = json.loads(flags_json) if flags_json else []
                    log(
                        f"HIGH-RISK PROCESS [score:{score}] "
                        f"PID:{pid} name:{name} flags:{flags}",
                        "ALERT"
                    )
        except Exception as e:
            log(f"Process watcher error: {e}", "WARN")

        time.sleep(8)

def print_status():
    """Print a system summary every 60 seconds."""
    while True:
        time.sleep(60)
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM file_events WHERE score >= 30")
            flagged = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM sandbox_reports")
            sandboxed = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM ai_assessments")
            analysed = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM sandbox_reports WHERE verdict='MALICIOUS'")
            malicious = c.fetchone()[0]
            try:
                c.execute("SELECT COUNT(*) FROM quarantine_log")
                quarantined = c.fetchone()[0]
            except Exception:
                quarantined = 0
            conn.close()

            print(f"\n{'═'*55}")
            print(f"  A3 STATUS — {datetime.now().strftime('%H:%M:%S')}")
            print(f"{'═'*55}")
            print(f"  Flagged files    : {flagged}")
            print(f"  Sandboxed        : {sandboxed}")
            print(f"  AI analysed      : {analysed}")
            print(f"  Malicious found  : {malicious}")
            print(f"  Quarantined      : {quarantined}")
            print(f"{'═'*55}\n")

        except Exception as e:
            log(f"Status error: {e}", "WARN")

# ── Layer 2 launcher ───────────────────────────────────────────────────────────

def start_monitor():
    """
    Launch Layer 2 monitor using the venv Python explicitly.
    This ensures psutil and watchdog are always found.
    """
    monitor_path = Path(__file__).parent / "monitor.py"

    # Use venv Python if it exists, otherwise fall back to current interpreter
    python_exe = str(VENV_PYTHON) if VENV_PYTHON.exists() else sys.executable

    log(f"Starting Layer 2 monitor (python: {Path(python_exe).name})...")

    # Pass the full environment including the venv paths
    env = os.environ.copy()
    if VENV_PYTHON.exists():
        venv_bin = str(VENV_PYTHON.parent)
        env["PATH"]        = venv_bin + os.pathsep + env.get("PATH", "")
        env["VIRTUAL_ENV"] = str(BASE_DIR / "venv")
        # Remove PYTHONHOME if set — it can interfere
        env.pop("PYTHONHOME", None)

    proc = subprocess.Popen(
        [python_exe, str(monitor_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        env=env
    )

    def stream_output():
        for line in proc.stdout:
            print(line, end="")

    t = threading.Thread(target=stream_output, daemon=True)
    t.start()
    return proc

# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    print(f"\n{'═'*55}")
    print(f"  A3 SECURITY SYSTEM — MASTER CONTROLLER")
    print(f"  All layers connected and active")
    print(f"{'═'*55}\n")

    init_sandbox_db()
    init_ai_db()
    init_chain_db()
    
    # Check Ollama
    log("Checking Ollama (Layer 4)...")
    test = ask_ollama("Reply with only the word: ready")
    if not test:
        log("Ollama not running — start with: ollama serve", "WARN")
        log("Layer 4 will be skipped until Ollama is available", "WARN")
    else:
        log("Ollama connected ✓", "OK")

    # Prepare sandbox
    log("Preparing Docker sandbox (Layer 3)...")
    pull_sandbox_image()
    log("Sandbox ready ✓", "OK")

    # Start swarm layer
    log("Starting swarm layer...")
    try:
        if start_swarm():
            log("Swarm layer active ✓", "OK")
        else:
            log("Swarm disabled — Redis not available", "WARN")
    except Exception as e:
        log(f"Swarm startup error: {e}", "WARN")

    # Start Layer 2 monitor
    monitor_proc = start_monitor()
    log("Layer 2 monitor running ✓", "OK")

    # Start background threads
    threads = [
        threading.Thread(target=watch_file_events,    daemon=True, name="file-watcher"),
        threading.Thread(target=watch_process_events, daemon=True, name="proc-watcher"),
        threading.Thread(target=print_status,         daemon=True, name="status"),
    ]
    for t in threads:
        t.start()

    log("All layers active. Watching your system...", "OK")
    log("Press Ctrl+C to stop\n", "INFO")

    try:
        while True:
            if monitor_proc.poll() is not None:
                log("Monitor stopped — restarting...", "WARN")
                monitor_proc = start_monitor()
            time.sleep(10)
    except KeyboardInterrupt:
        log("Shutting down A3...")
        monitor_proc.terminate()
        print("\nA3 stopped.\n")

if __name__ == "__main__":
    main()