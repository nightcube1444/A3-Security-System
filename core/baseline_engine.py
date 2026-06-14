"""
A3 Security System — Behavioral Baseline Engine
Watches your Mac for 7 days, learns what normal looks like.
After that, anything deviating from baseline gets flagged —
even with no known malware signature.
Catches zero-day malware, living-off-the-land attacks, insider threats.
"""

import sqlite3
import json
import time
import threading
import math
import psutil
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict

BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH  = DATA_DIR / "a3_threats.db"

# ── Config ─────────────────────────────────────────────────────────────────────
LEARNING_DAYS       = 7       # days to observe before flagging
SAMPLE_INTERVAL     = 30      # seconds between samples
ANOMALY_THRESHOLD   = 0.75    # 0-1 score above which we flag
MIN_SAMPLES         = 50      # minimum samples before we trust the baseline

def log(message, level="INFO"):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    colours = {
        "INFO":"\033[97m","OK":"\033[92m",
        "WARN":"\033[93m","ALERT":"\033[91m","BASE":"\033[96m"
    }
    print(f"[{ts}] {colours.get(level,'')}[BASELINE][{level}]\033[0m {message}")

# ── Database ───────────────────────────────────────────────────────────────────

def init_baseline_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Raw process observations during learning phase
    c.execute("""
        CREATE TABLE IF NOT EXISTS baseline_observations (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT,
            process     TEXT,
            cpu_pct     REAL,
            mem_mb      REAL,
            connections INTEGER,
            threads     INTEGER,
            hour_of_day INTEGER,
            day_of_week INTEGER
        )
    """)

    # Learned baseline per process
    c.execute("""
        CREATE TABLE IF NOT EXISTS baseline_profiles (
            process         TEXT PRIMARY KEY,
            sample_count    INTEGER DEFAULT 0,
            avg_cpu         REAL DEFAULT 0,
            std_cpu         REAL DEFAULT 0,
            max_cpu         REAL DEFAULT 0,
            avg_mem         REAL DEFAULT 0,
            std_mem         REAL DEFAULT 0,
            max_mem         REAL DEFAULT 0,
            avg_connections REAL DEFAULT 0,
            max_connections INTEGER DEFAULT 0,
            typical_hours   TEXT,
            first_seen      TEXT,
            last_seen       TEXT,
            trusted         INTEGER DEFAULT 0
        )
    """)

    # Anomaly events
    c.execute("""
        CREATE TABLE IF NOT EXISTS baseline_anomalies (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp     TEXT,
            process       TEXT,
            pid           INTEGER,
            anomaly_score REAL,
            anomaly_type  TEXT,
            observed_val  REAL,
            baseline_val  REAL,
            deviation     REAL,
            flags         TEXT
        )
    """)

    # Engine state
    c.execute("""
        CREATE TABLE IF NOT EXISTS baseline_state (
            key   TEXT PRIMARY KEY,
            value TEXT
        )
    """)

    conn.commit()
    conn.close()

# ── State management ──────────────────────────────────────────────────────────

def get_state(key, default=None):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT value FROM baseline_state WHERE key=?", (key,))
        row = c.fetchone()
        conn.close()
        return row[0] if row else default
    except Exception:
        return default

def set_state(key, value):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            INSERT OR REPLACE INTO baseline_state (key, value)
            VALUES (?,?)
        """, (key, str(value)))
        conn.commit()
        conn.close()
    except Exception:
        pass

def is_learning_phase():
    """True if still in the 7-day learning phase."""
    start = get_state("learning_start")
    if not start:
        set_state("learning_start", datetime.now().isoformat())
        log(f"Learning phase started — observing for {LEARNING_DAYS} days", "BASE")
        return True
    start_dt = datetime.fromisoformat(start)
    elapsed  = (datetime.now() - start_dt).total_seconds() / 86400
    return elapsed < LEARNING_DAYS

def learning_progress():
    """Returns (days_elapsed, days_total, pct)"""
    start = get_state("learning_start")
    if not start:
        return 0, LEARNING_DAYS, 0
    elapsed = (datetime.now() - datetime.fromisoformat(start)).total_seconds() / 86400
    elapsed = min(elapsed, LEARNING_DAYS)
    return round(elapsed, 1), LEARNING_DAYS, round(elapsed/LEARNING_DAYS*100, 1)

# ── Process observation ────────────────────────────────────────────────────────

def observe_processes():
    """Take a snapshot of all running processes."""
    observations = []
    now = datetime.now()

    for proc in psutil.process_iter():
        try:
            with proc.oneshot():
                name = proc.name().lower()
                if not name or name in ("idle", "kernel_task"):
                    continue

                cpu  = proc.cpu_percent(interval=0.1)
                mem  = proc.memory_info().rss / (1024 * 1024)  # MB
                try:
                    conns = len(proc.net_connections())
                except Exception:
                    conns = 0
                threads = proc.num_threads()

                observations.append({
                    "process":     name,
                    "pid":         proc.pid,
                    "cpu":         round(cpu, 2),
                    "mem":         round(mem, 2),
                    "connections": conns,
                    "threads":     threads,
                    "hour":        now.hour,
                    "dow":         now.weekday()
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return observations

# ── Save observations ─────────────────────────────────────────────────────────

def save_observations(observations):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.now().isoformat()
    for obs in observations:
        c.execute("""
            INSERT INTO baseline_observations
            (timestamp, process, cpu_pct, mem_mb, connections,
             threads, hour_of_day, day_of_week)
            VALUES (?,?,?,?,?,?,?,?)
        """, (now, obs["process"], obs["cpu"], obs["mem"],
              obs["connections"], obs["threads"],
              obs["hour"], obs["dow"]))
    conn.commit()
    conn.close()

# ── Build baseline profiles ───────────────────────────────────────────────────

def build_profiles():
    """
    Compute baseline statistics per process from all observations.
    Called after learning phase completes and periodically after.
    """
    log("Building baseline profiles from observations...", "BASE")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Get all unique processes
    c.execute("SELECT DISTINCT process FROM baseline_observations")
    processes = [row[0] for row in c.fetchall()]

    for proc in processes:
        c.execute("""
            SELECT cpu_pct, mem_mb, connections, hour_of_day
            FROM baseline_observations WHERE process=?
        """, (proc,))
        rows = c.fetchall()
        if len(rows) < 5:
            continue

        cpus  = [r[0] for r in rows]
        mems  = [r[1] for r in rows]
        conns = [r[2] for r in rows]
        hours = [r[3] for r in rows]

        def mean(vals):
            return sum(vals) / len(vals) if vals else 0

        def std(vals):
            m = mean(vals)
            variance = sum((v-m)**2 for v in vals) / len(vals)
            return math.sqrt(variance)

        # Count hours this process typically runs
        hour_counts = defaultdict(int)
        for h in hours:
            hour_counts[h] += 1
        typical_hours = [h for h, cnt in hour_counts.items()
                         if cnt >= len(rows) * 0.1]

        c.execute("""
            INSERT OR REPLACE INTO baseline_profiles
            (process, sample_count, avg_cpu, std_cpu, max_cpu,
             avg_mem, std_mem, max_mem, avg_connections, max_connections,
             typical_hours, first_seen, last_seen)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,
                    COALESCE((SELECT first_seen FROM baseline_profiles
                              WHERE process=?), ?),
                    ?)
        """, (
            proc, len(rows),
            round(mean(cpus), 2), round(std(cpus), 2), round(max(cpus), 2),
            round(mean(mems), 2), round(std(mems), 2), round(max(mems), 2),
            round(mean(conns), 2), max(conns),
            json.dumps(sorted(typical_hours)),
            proc, datetime.now().isoformat(),
            datetime.now().isoformat()
        ))

    conn.commit()
    conn.close()
    log(f"Baseline profiles built for {len(processes)} process(es)", "OK")

# ── Anomaly detection ─────────────────────────────────────────────────────────

def z_score(value, mean, std):
    """How many standard deviations away from normal."""
    if std < 0.01:
        return 0
    return abs(value - mean) / std

def detect_anomalies(observations):
    """
    Compare current observations against baseline profiles.
    Returns list of anomalies.
    """
    anomalies = []

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    for obs in observations:
        proc = obs["process"]

        c.execute("""
            SELECT sample_count, avg_cpu, std_cpu, max_cpu,
                   avg_mem, std_mem, max_mem,
                   avg_connections, max_connections, typical_hours
            FROM baseline_profiles WHERE process=?
        """, (proc,))
        profile = c.fetchone()

        if not profile:
            # New process never seen in baseline — mild flag
            if obs["cpu"] > 20 or obs["connections"] > 5:
                anomalies.append({
                    "process":      proc,
                    "pid":          obs["pid"],
                    "anomaly_score": 0.4,
                    "anomaly_type": "new_process",
                    "observed_val": obs["cpu"],
                    "baseline_val": 0,
                    "deviation":    0,
                    "flags":        ["never_seen_before"]
                })
            continue

        (sample_count, avg_cpu, std_cpu, max_cpu,
         avg_mem, std_mem, max_mem,
         avg_conn, max_conn, typical_hours_json) = profile

        if sample_count < MIN_SAMPLES:
            continue

        score = 0.0
        flags = []

        # CPU anomaly
        cpu_z = z_score(obs["cpu"], avg_cpu, std_cpu)
        if cpu_z > 3 and obs["cpu"] > avg_cpu * 3:
            score = max(score, min(cpu_z / 10, 1.0))
            flags.append(f"cpu_spike:{obs['cpu']:.0f}%_vs_avg_{avg_cpu:.0f}%")

        # Memory anomaly
        mem_z = z_score(obs["mem"], avg_mem, std_mem)
        if mem_z > 3 and obs["mem"] > avg_mem * 2:
            score = max(score, min(mem_z / 10, 1.0))
            flags.append(f"mem_spike:{obs['mem']:.0f}MB_vs_avg_{avg_mem:.0f}MB")

        # Network connection anomaly
        if obs["connections"] > 0 and avg_conn < 0.5:
            score = max(score, 0.6)
            flags.append(f"unexpected_connections:{obs['connections']}")
        elif obs["connections"] > max_conn * 2:
            score = max(score, 0.7)
            flags.append(f"excess_connections:{obs['connections']}_vs_max_{max_conn}")

        # Unusual hour
        try:
            typical = json.loads(typical_hours_json or "[]")
            if typical and obs["hour"] not in typical:
                score += 0.1
                flags.append(f"unusual_hour:{obs['hour']}:00")
        except Exception:
            pass

        if score >= ANOMALY_THRESHOLD and flags:
            anomalies.append({
                "process":       proc,
                "pid":           obs["pid"],
                "anomaly_score": round(score, 3),
                "anomaly_type":  flags[0].split(":")[0],
                "observed_val":  obs["cpu"],
                "baseline_val":  avg_cpu,
                "deviation":     round(cpu_z, 2),
                "flags":         flags
            })

    conn.close()
    return anomalies

# ── Save anomalies ────────────────────────────────────────────────────────────

def save_anomaly(anomaly):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT INTO baseline_anomalies
        (timestamp, process, pid, anomaly_score, anomaly_type,
         observed_val, baseline_val, deviation, flags)
        VALUES (?,?,?,?,?,?,?,?,?)
    """, (
        datetime.now().isoformat(),
        anomaly["process"], anomaly["pid"],
        anomaly["anomaly_score"], anomaly["anomaly_type"],
        anomaly["observed_val"], anomaly["baseline_val"],
        anomaly["deviation"], json.dumps(anomaly["flags"])
    ))
    conn.commit()
    conn.close()

# ── Main loop ─────────────────────────────────────────────────────────────────

def run(use_event_bus=True):
    """Main baseline engine loop."""
    init_baseline_db()

    # Import event bus
    event_bus = None
    if use_event_bus:
        try:
            from event_bus import bus, Events
            event_bus = bus
            if not bus._running:
                bus.start()
        except Exception as e:
            log(f"Event bus not available: {e}", "WARN")

    log("Baseline engine starting...", "BASE")
    elapsed, total, pct = learning_progress()
    log(f"Learning progress: {elapsed}/{total} days ({pct}%)", "BASE")

    profile_rebuild_interval = 3600  # rebuild profiles every hour
    last_profile_build       = 0
    sample_count             = 0

    while True:
        try:
            learning = is_learning_phase()
            obs = observe_processes()

            # Always save observations (learning or not)
            save_observations(obs)
            sample_count += 1

            # Periodically rebuild profiles
            if time.time() - last_profile_build > profile_rebuild_interval:
                build_profiles()
                last_profile_build = time.time()

                if event_bus:
                    event_bus.publish("baseline.updated", {
                        "profiles_built": True,
                        "learning": learning
                    }, source="baseline_engine")

            if not learning:
                # Detection mode — check for anomalies
                anomalies = detect_anomalies(obs)
                for anomaly in anomalies:
                    save_anomaly(anomaly)
                    log(
                        f"ANOMALY [{anomaly['anomaly_score']:.0%}] "
                        f"{anomaly['process']} — {anomaly['flags']}",
                        "ALERT"
                    )
                    # Publish to event bus
                    if event_bus:
                        event_bus.publish("baseline.anomaly", {
                            "process":       anomaly["process"],
                            "pid":           anomaly["pid"],
                            "anomaly_score": anomaly["anomaly_score"],
                            "flags":         anomaly["flags"]
                        }, source="baseline_engine")

                    # Telegram alert for high anomaly scores
                    if anomaly["anomaly_score"] >= 0.85:
                        try:
                            from telegram_bot import send
                            send(
                                f"🔍 <b>BEHAVIORAL ANOMALY</b>\n\n"
                                f"<b>Process</b>: <code>{anomaly['process']}</code>\n"
                                f"<b>PID</b>: {anomaly['pid']}\n"
                                f"<b>Score</b>: {anomaly['anomaly_score']:.0%}\n"
                                f"<b>Flags</b>: {', '.join(anomaly['flags'][:3])}\n\n"
                                f"<i>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>"
                            )
                        except Exception:
                            pass

            if sample_count % 20 == 0:
                elapsed, total, pct = learning_progress()
                mode = "LEARNING" if learning else "DETECTING"
                log(f"[{mode}] {elapsed}/{total}d — "
                    f"{sample_count} samples collected", "BASE")

        except Exception as e:
            log(f"Loop error: {e}", "WARN")

        time.sleep(SAMPLE_INTERVAL)

def start_baseline_engine():
    """Start baseline engine in background thread."""
    t = threading.Thread(
        target=run,
        daemon=True,
        name="baseline-engine"
    )
    t.start()
    log("Baseline engine started in background ✓", "OK")
    return t

# ── Stats ──────────────────────────────────────────────────────────────────────

def print_stats():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("SELECT COUNT(*) FROM baseline_observations")
    obs_count = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM baseline_profiles")
    prof_count = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM baseline_anomalies")
    anom_count = c.fetchone()[0]
    c.execute("""
        SELECT process, anomaly_score, flags, timestamp
        FROM baseline_anomalies
        ORDER BY anomaly_score DESC LIMIT 5
    """)
    top_anomalies = c.fetchall()
    conn.close()

    elapsed, total, pct = learning_progress()

    print(f"\n{'═'*55}")
    print(f"  BASELINE ENGINE STATUS")
    print(f"{'═'*55}")
    print(f"  Learning progress : {elapsed}/{total} days ({pct}%)")
    mode = "LEARNING" if is_learning_phase() else "DETECTING"
    print(f"  Mode              : {mode}")
    print(f"  Observations      : {obs_count:,}")
    print(f"  Process profiles  : {prof_count}")
    print(f"  Anomalies found   : {anom_count}")
    if top_anomalies:
        print(f"\n  Top anomalies:")
        for proc, score, flags_json, ts in top_anomalies:
            flags = json.loads(flags_json) if flags_json else []
            print(f"  {score:.0%}  {proc:<25} {flags[0] if flags else ''}")
    print(f"{'═'*55}\n")

# ── Main ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    if "--stats" in sys.argv:
        init_baseline_db()
        print_stats()
    elif "--build" in sys.argv:
        init_baseline_db()
        build_profiles()
        print_stats()
    else:
        run()