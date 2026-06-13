"""
A3 Security System — Master Controller
Connects all layers. When a file is flagged → sandbox → AI → alert.
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

sys.path.insert(0, str(Path(__file__).parent))
from sandbox import run_in_sandbox, init_sandbox_db, pull_sandbox_image
from ai_analyst import analyse_report, init_ai_db, ask_ollama
from swarm import start_swarm, publish_threat, check_swarm_intel
from blockchain import init_chain_db, record_threat, validate_chain
from scheduler import start_scheduler
from telegram_bot import alert_malicious_file, alert_startup, alert_high_risk_process

BASE_DIR    = Path(__file__).parent.parent
DATA_DIR    = BASE_DIR / "data"
DB_PATH     = DATA_DIR / "a3_threats.db"
VENV_PYTHON = BASE_DIR / "venv" / "bin" / "python3"

processed_file_ids = set()

COLOURS = {
    "INFO": "\033[97m", "WARN": "\033[93m",
    "ALERT": "\033[91m", "OK": "\033[92m", "AI": "\033[95m",
}
RESET = "\033[0m"

def log(message, level="INFO"):
    ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    col = COLOURS.get(level, "")
    print(f"[{ts}] {col}[A3 CTRL][{level}]{RESET} {message}")

# ── Pipeline ───────────────────────────────────────────────────────────────────

def run_full_pipeline(file_path, file_event_id):
    file_path = Path(file_path)
    log(f"Pipeline started: {file_path.name}", "ALERT")

    # Step 0: Check swarm intel
    try:
        import hashlib
        file_hash = hashlib.sha256(file_path.read_bytes()).hexdigest()
        swarm_hit = check_swarm_intel(file_hash)
        if swarm_hit:
            log(f"SWARM HIT — {file_path.name} already known as {swarm_hit['verdict']}", "ALERT")
            return
    except Exception:
        pass

    # Step 1: Sandbox
    log(f"Sandboxing: {file_path.name}")
    report = run_in_sandbox(file_path)
    if not report:
        log(f"Sandbox failed: {file_path.name}", "WARN")
        return
    log(f"Sandbox done — verdict:{report['verdict']} score:{report['score']}", "OK")

    # Step 1b: Publish to swarm if threat
    if report["verdict"] in ("MALICIOUS", "SUSPICIOUS"):
        try:
            publish_threat(
                report.get("hash", ""), report["verdict"],
                "unknown", report.get("flags", []), report.get("score", 0)
            )
        except Exception:
            pass

    # Step 2: AI analysis
    log("Sending to Llama3...", "AI")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id FROM sandbox_reports WHERE file_path=? ORDER BY id DESC LIMIT 1",
              (str(file_path),))
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
                    str(file_path), report.get("hash", ""),
                    report["verdict"], ttype.lower(),
                    report.get("flags", []), report.get("score", 0)
                )
                log("Recorded on blockchain ✓", "OK")
            except Exception as e:
                log(f"Blockchain error: {e}", "WARN")

        # Telegram alert
        try:
            alert_malicious_file(
                file_path.name, report["verdict"], ttype.lower(),
                report.get("score", 0), report.get("flags", []), action
            )
        except Exception:
            pass

    log(f"Pipeline complete: {file_path.name}", "OK")

def quarantine_file(file_path, report, assessment):
    quarantine_dir = BASE_DIR / "quarantine"
    quarantine_dir.mkdir(exist_ok=True)
    dest = quarantine_dir / f"{file_path.name}.quarantined"
    try:
        import shutil
        shutil.copy2(file_path, dest)
        log(f"QUARANTINED: {file_path.name}", "ALERT")
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS quarantine_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT, original TEXT, quarantined TEXT,
                verdict TEXT, threat_type TEXT, score INTEGER
            )
        """)
        c.execute("""
            INSERT INTO quarantine_log
            (timestamp, original, quarantined, verdict, threat_type, score)
            VALUES (?,?,?,?,?,?)
        """, (datetime.now().isoformat(), str(file_path), str(dest),
              report.get("verdict", ""), assessment.get("threat_type", "unknown"),
              report.get("score", 0)))
        conn.commit()
        conn.close()
    except Exception as e:
        log(f"Quarantine failed: {e}", "WARN")

# ── Watchers ───────────────────────────────────────────────────────────────────

def watch_file_events():
    log("File event watcher started")
    while True:
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("SELECT id, path, score FROM file_events WHERE score >= 30 ORDER BY id DESC LIMIT 10")
            rows = c.fetchall()
            conn.close()
            for fid, fpath, score in rows:
                if fid not in processed_file_ids:
                    processed_file_ids.add(fid)
                    p = Path(fpath)
                    if p.exists():
                        log(f"Flagged file [score:{score}]: {p.name}", "ALERT")
                        threading.Thread(target=run_full_pipeline,
                                         args=(fpath, fid), daemon=True).start()
        except Exception as e:
            log(f"File watcher error: {e}", "WARN")
        time.sleep(5)

def watch_process_events():
    log("Process event watcher started")
    seen = set()
    while True:
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("SELECT id, pid, name, score, flags FROM process_events WHERE score >= 50 ORDER BY id DESC LIMIT 20")
            rows = c.fetchall()
            conn.close()
            for rid, pid, name, score, flags_json in rows:
                if rid not in seen:
                    seen.add(rid)
                    flags = json.loads(flags_json) if flags_json else []
                    log(f"HIGH-RISK PROCESS [score:{score}] PID:{pid} name:{name}", "ALERT")
                    try:
                        alert_high_risk_process(pid, name, score, flags)
                    except Exception:
                        pass
        except Exception as e:
            log(f"Process watcher error: {e}", "WARN")
        time.sleep(8)

def print_status():
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
            print(f"  Flagged files : {flagged}")
            print(f"  Sandboxed     : {sandboxed}")
            print(f"  AI analysed   : {analysed}")
            print(f"  Malicious     : {malicious}")
            print(f"  Quarantined   : {quarantined}")
            print(f"{'═'*55}\n")
        except Exception as e:
            log(f"Status error: {e}", "WARN")

# ── Monitor launcher ───────────────────────────────────────────────────────────

def start_monitor():
    monitor_path = Path(__file__).parent / "monitor.py"
    python_exe   = str(VENV_PYTHON) if VENV_PYTHON.exists() else sys.executable
    log(f"Starting Layer 2 monitor...")
    env = os.environ.copy()
    if VENV_PYTHON.exists():
        env["PATH"]        = str(VENV_PYTHON.parent) + os.pathsep + env.get("PATH", "")
        env["VIRTUAL_ENV"] = str(BASE_DIR / "venv")
        env.pop("PYTHONHOME", None)
    proc = subprocess.Popen(
        [python_exe, str(monitor_path)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1, env=env
    )
    threading.Thread(
        target=lambda: [print(line, end="") for line in proc.stdout],
        daemon=True
    ).start()
    return proc

# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    print(f"\n{'═'*55}")
    print(f"  A3 SECURITY SYSTEM — MASTER CONTROLLER")
    print(f"{'═'*55}\n")

    init_sandbox_db()
    init_ai_db()
    init_chain_db()

    log("Checking Ollama...")
    if not ask_ollama("Reply with only the word: ready"):
        log("Ollama not running — Layer 4 disabled", "WARN")
    else:
        log("Ollama connected ✓", "OK")

    log("Preparing Docker sandbox...")
    pull_sandbox_image()
    log("Sandbox ready ✓", "OK")

    log("Starting swarm layer...")
    try:
        start_swarm()
        log("Swarm active ✓", "OK")
    except Exception as e:
        log(f"Swarm error: {e}", "WARN")

    monitor_proc = start_monitor()
    log("Layer 2 monitor running ✓", "OK")

    for target, name in [
        (watch_file_events,    "file-watcher"),
        (watch_process_events, "proc-watcher"),
        (print_status,         "status"),
    ]:
        threading.Thread(target=target, daemon=True, name=name).start()

    start_scheduler()
    log("Autonomous scheduler active ✓", "OK")

    try:
        alert_startup()
    except Exception:
        pass

    log("All layers active. Watching your system...", "OK")
    log("Press Ctrl+C to stop\n")

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