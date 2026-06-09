"""
A3 Security System — Threat Viewer
See everything your monitor has detected.
Run this anytime to get a report from the database.
"""

import sqlite3
import json
from pathlib import Path
from datetime import datetime

DB_PATH = Path(__file__).parent.parent / "data" / "a3_threats.db"

def header(text):
    print("\n" + "=" * 60)
    print(f"  {text}")
    print("=" * 60)

def show_process_threats():
    header("Process Threats Detected")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT timestamp, pid, name, score, flags, status
        FROM process_events
        ORDER BY score DESC
        LIMIT 20
    """)
    rows = c.fetchall()
    conn.close()

    if not rows:
        print("  No process threats logged yet.")
        return

    for ts, pid, name, score, flags, status in rows:
        flag_list = json.loads(flags)
        colour = "\033[91m" if status == "FLAGGED" else "\033[93m"
        reset  = "\033[0m"
        print(f"\n  {colour}[{status}]{reset} Score: {score}")
        print(f"  Time   : {ts}")
        print(f"  PID    : {pid}  Name: {name}")
        print(f"  Flags  : {', '.join(flag_list)}")

def show_file_threats():
    header("File Events Detected")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT timestamp, event_type, path, score, flags
        FROM file_events
        ORDER BY score DESC
        LIMIT 20
    """)
    rows = c.fetchall()
    conn.close()

    if not rows:
        print("  No file events logged yet.")
        return

    for ts, etype, path, score, flags in rows:
        flag_list = json.loads(flags)
        colour = "\033[91m" if score >= 50 else "\033[93m"
        reset  = "\033[0m"
        print(f"\n  {colour}[{etype}]{reset} Score: {score}")
        print(f"  Time   : {ts}")
        print(f"  Path   : {path}")
        print(f"  Flags  : {', '.join(flag_list)}")

def show_summary():
    header("System Summary")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("SELECT COUNT(*) FROM process_events WHERE status='FLAGGED'")
    flagged = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM process_events")
    total_proc = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM file_events")
    total_file = c.fetchone()[0]

    c.execute("SELECT captured_at, process_count FROM system_baseline ORDER BY id DESC LIMIT 1")
    baseline = c.fetchone()
    conn.close()

    print(f"  Processes scanned   : {total_proc}")
    print(f"  Processes flagged   : {flagged}")
    print(f"  File events logged  : {total_file}")
    if baseline:
        print(f"  Baseline captured   : {baseline[0]}")
        print(f"  Baseline process ct : {baseline[1]}")

if __name__ == "__main__":
    if not DB_PATH.exists():
        print("No database found. Run monitor.py first.")
    else:
        show_summary()
        show_process_threats()
        show_file_threats()
        print("\n")
