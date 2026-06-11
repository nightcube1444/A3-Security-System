"""
A3 Security System — Autonomous Scheduler
Makes A3 fully self-running. No human input needed.
Runs all tasks automatically on a schedule:
  - Network scan        every 5 minutes
  - IP intelligence     every 10 minutes
  - ML retrain          every 24 hours
  - Chain validation    every 6 hours
  - Threat intel sync   every 1 hour
  - Weekly report       every 7 days
  - Swarm sync          every 30 minutes
"""

import time
import threading
import sqlite3
import json
from datetime import datetime, timedelta
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH  = DATA_DIR / "a3_threats.db"
LOG_PATH = BASE_DIR / "logs" / "scheduler.log"
LOG_PATH.parent.mkdir(exist_ok=True)

def log(message, level="INFO"):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    colours = {
        "INFO":  "\033[97m", "OK":    "\033[92m",
        "WARN":  "\033[93m", "ALERT": "\033[91m",
        "SCHED": "\033[96m"
    }
    line = f"[{ts}] {colours.get(level,'')}[SCHEDULER][{level}]\033[0m {message}"
    print(line)
    with open(LOG_PATH, "a") as f:
        f.write(f"[{ts}] [{level}] {message}\n")

# ── Task registry ─────────────────────────────────────────────────────────────

class Task:
    def __init__(self, name, fn, interval_seconds, run_on_start=True):
        self.name             = name
        self.fn               = fn
        self.interval         = interval_seconds
        self.run_on_start     = run_on_start
        self.last_run         = None
        self.run_count        = 0
        self.error_count      = 0
        self.last_error       = None

    def is_due(self):
        if self.last_run is None:
            return self.run_on_start
        return (datetime.now() - self.last_run).total_seconds() >= self.interval

    def run(self):
        log(f"Running task: {self.name}", "SCHED")
        try:
            self.fn()
            self.last_run  = datetime.now()
            self.run_count += 1
            log(f"Task complete: {self.name} (run #{self.run_count})", "OK")
        except Exception as e:
            self.error_count += 1
            self.last_error   = str(e)
            log(f"Task failed: {self.name} — {e}", "WARN")

# ── Task functions ────────────────────────────────────────────────────────────

def task_network_scan():
    """Scan network for new or changed devices."""
    try:
        import sys
        sys.path.insert(0, str(Path(__file__).parent))
        from signal_detector import run_full_scan, init_signal_db
        init_signal_db()
        run_full_scan()
    except Exception as e:
        log(f"Network scan error: {e}", "WARN")

def task_ip_intelligence():
    """Look up intel on any new network devices."""
    try:
        from ip_intel import lookup, print_intel, init_intel_db
        init_intel_db()

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        # Find devices not yet in ip_intelligence or older than 24h
        c.execute("""
            SELECT nd.ip FROM network_devices nd
            LEFT JOIN ip_intelligence ii ON nd.ip = ii.ip
            WHERE ii.ip IS NULL
               OR ii.timestamp < datetime('now', '-1 day')
            LIMIT 10
        """)
        ips = [row[0] for row in c.fetchall()]
        conn.close()

        for ip in ips:
            result = lookup(ip)
            if result.get("threat_score", 0) >= 30:
                log(f"High-risk IP detected: {ip} score:{result['threat_score']}", "ALERT")
    except Exception as e:
        log(f"IP intel error: {e}", "WARN")

def task_ml_retrain():
    """Retrain ML model on accumulated threat data."""
    try:
        from ml_trainer import train
        log("Retraining ML model with new data...")
        train()
    except Exception as e:
        log(f"ML retrain error: {e}", "WARN")

def task_chain_validation():
    """Validate blockchain integrity."""
    try:
        from blockchain import validate_chain, sync_existing_threats
        sync_existing_threats()
        valid, msg = validate_chain()
        if valid:
            log(f"Blockchain valid: {msg}", "OK")
        else:
            log(f"BLOCKCHAIN TAMPERED: {msg}", "ALERT")
    except Exception as e:
        log(f"Chain validation error: {e}", "WARN")

def task_swarm_sync():
    """Sync threat intelligence with swarm."""
    try:
        from swarm import sync_existing_threats
        sync_existing_threats()
    except Exception as e:
        log(f"Swarm sync error: {e}", "WARN")

def task_semgrep_scan():
    """Run static analysis on A3's own code to catch regressions."""
    try:
        from semgrep_scanner import run, init_semgrep_db
        init_semgrep_db()
        score = run(BASE_DIR / "core")
        if score > 100:
            log(f"Semgrep found issues in A3 code — score:{score}", "WARN")
        else:
            log(f"Semgrep scan clean — score:{score}", "OK")
    except Exception as e:
        log(f"Semgrep scan error: {e}", "WARN")

def task_weekly_report():
    """Generate a weekly security summary report."""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        week_ago = (datetime.now() - timedelta(days=7)).isoformat()

        c.execute("SELECT COUNT(*) FROM process_events WHERE timestamp > ?", (week_ago,))
        processes = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM sandbox_reports WHERE timestamp > ?", (week_ago,))
        sandboxed = c.fetchone()[0]

        c.execute("""
            SELECT COUNT(*) FROM sandbox_reports
            WHERE verdict='MALICIOUS' AND timestamp > ?
        """, (week_ago,))
        malicious = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM network_devices", )
        devices = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM blockchain")
        blocks = c.fetchone()[0]

        conn.close()

        report = {
            "generated":        datetime.now().isoformat(),
            "period":           "last 7 days",
            "processes_scanned": processes,
            "files_sandboxed":  sandboxed,
            "malicious_found":  malicious,
            "network_devices":  devices,
            "blockchain_blocks": blocks,
        }

        # Save report
        report_path = BASE_DIR / "data" / f"weekly_report_{datetime.now().strftime('%Y%m%d')}.json"
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)

        log(f"Weekly report generated: {report_path.name}", "OK")
        log(f"  Processes: {processes} | Sandboxed: {sandboxed} | "
            f"Malicious: {malicious} | Devices: {devices}", "SCHED")

    except Exception as e:
        log(f"Weekly report error: {e}", "WARN")

def task_cleanup():
    """Clean up old data to keep the database lean."""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        # Delete clean process events older than 7 days
        c.execute("""
            DELETE FROM process_events
            WHERE status='CLEAN'
            AND timestamp < datetime('now', '-7 days')
        """)
        deleted = c.rowcount

        # Delete old low-score file events
        c.execute("""
            DELETE FROM file_events
            WHERE score < 20
            AND timestamp < datetime('now', '-3 days')
        """)
        deleted += c.rowcount

        conn.commit()
        conn.close()

        if deleted:
            log(f"Cleanup: removed {deleted} old low-priority records", "OK")
    except Exception as e:
        log(f"Cleanup error: {e}", "WARN")

# ── Status display ────────────────────────────────────────────────────────────

def print_scheduler_status(tasks):
    print(f"\n{'═'*55}")
    print(f"  A3 SCHEDULER STATUS — {datetime.now().strftime('%H:%M:%S')}")
    print(f"{'═'*55}")
    for task in tasks:
        next_run = "NOW" if task.is_due() else \
            f"in {int(task.interval - (datetime.now() - task.last_run).total_seconds())}s" \
            if task.last_run else "on start"
        status = "✓" if task.error_count == 0 else f"⚠ {task.error_count} errors"
        print(f"  {task.name:<25} runs:{task.run_count:<4} next:{next_run:<12} {status}")
    print(f"{'═'*55}\n")

# ── Main scheduler loop ───────────────────────────────────────────────────────

def run_scheduler():
    log("A3 Autonomous Scheduler starting...", "SCHED")

    # Define all tasks with their schedules
    tasks = [
        Task("network_scan",      task_network_scan,      300,          True),   # 5 min
        Task("ip_intelligence",   task_ip_intelligence,   600,          False),  # 10 min
        Task("swarm_sync",        task_swarm_sync,        1800,         True),   # 30 min
        Task("chain_validation",  task_chain_validation,  21600,        True),   # 6 hours
        Task("ml_retrain",        task_ml_retrain,        86400,        False),  # 24 hours
        Task("semgrep_scan",      task_semgrep_scan,      86400,        False),  # 24 hours
        Task("weekly_report",     task_weekly_report,     604800,       False),  # 7 days
        Task("cleanup",           task_cleanup,           86400,        False),  # 24 hours
    ]

    log(f"Scheduled {len(tasks)} autonomous task(s)", "OK")
    for t in tasks:
        interval_str = (
            f"{t.interval}s" if t.interval < 3600 else
            f"{t.interval//3600}h" if t.interval < 86400 else
            f"{t.interval//86400}d"
        )
        log(f"  {t.name:<25} every {interval_str}", "SCHED")

    status_interval = 300   # print status every 5 minutes
    last_status     = time.time()

    log("Scheduler running — A3 is now fully autonomous", "OK")

    while True:
        # Check each task
        for task in tasks:
            if task.is_due():
                # Run in background thread so scheduler never blocks
                t = threading.Thread(
                    target=task.run,
                    daemon=True,
                    name=f"sched-{task.name}"
                )
                t.start()
                # Small gap between tasks to avoid overload
                time.sleep(2)

        # Print status periodically
        if time.time() - last_status >= status_interval:
            print_scheduler_status(tasks)
            last_status = time.time()

        time.sleep(30)  # check every 30 seconds

# ── Start as background thread ────────────────────────────────────────────────

def start_scheduler():
    """Start the scheduler in a background thread."""
    t = threading.Thread(
        target=run_scheduler,
        daemon=True,
        name="a3-scheduler"
    )
    t.start()
    log("Scheduler started in background", "OK")
    return t

if __name__ == "__main__":
    import sys
    if "--status" in sys.argv:
        log("Scheduler not running as standalone — use controller.py")
    else:
        # Run in foreground for testing
        run_scheduler()