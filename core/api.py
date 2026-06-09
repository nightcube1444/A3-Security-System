"""
A3 Security System — Web API
FastAPI backend that serves all A3 data to the React dashboard.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import sqlite3
import json
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
DB_PATH  = BASE_DIR / "data" / "a3_threats.db"

app = FastAPI(title="A3 Security System", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/api/health")
def health():
    return {"status": "online", "timestamp": datetime.now().isoformat()}

# ── Summary stats ─────────────────────────────────────────────────────────────

@app.get("/api/summary")
def summary():
    conn = db()
    c = conn.cursor()
    def count(table, where="1=1"):
        try:
            c.execute(f"SELECT COUNT(*) FROM {table} WHERE {where}")
            return c.fetchone()[0]
        except Exception:
            return 0

    result = {
        "processes_scanned":  count("process_events"),
        "processes_flagged":  count("process_events", "status='FLAGGED'"),
        "files_flagged":      count("file_events", "score >= 30"),
        "sandboxed":          count("sandbox_reports"),
        "malicious":          count("sandbox_reports", "verdict='MALICIOUS'"),
        "suspicious":         count("sandbox_reports", "verdict='SUSPICIOUS'"),
        "ai_analysed":        count("ai_assessments"),
        "quarantined":        count("quarantine_log"),
        "network_devices":    count("network_devices"),
        "high_risk_devices":  count("network_devices", "threat_score >= 50"),
    }
    conn.close()
    return result

# ── Process events ─────────────────────────────────────────────────────────────

@app.get("/api/processes")
def processes(limit: int = 50):
    conn = db()
    c = conn.cursor()
    try:
        c.execute("""
            SELECT id, timestamp, pid, name, exe, score, flags, status
            FROM process_events
            ORDER BY id DESC LIMIT ?
        """, (limit,))
        rows = [dict(r) for r in c.fetchall()]
        for r in rows:
            r["flags"] = json.loads(r["flags"]) if r["flags"] else []
    except Exception:
        rows = []
    conn.close()
    return rows

# ── File events ───────────────────────────────────────────────────────────────

@app.get("/api/files")
def files(limit: int = 50):
    conn = db()
    c = conn.cursor()
    try:
        c.execute("""
            SELECT id, timestamp, event_type, path, score, flags
            FROM file_events
            WHERE score > 0
            ORDER BY id DESC LIMIT ?
        """, (limit,))
        rows = [dict(r) for r in c.fetchall()]
        for r in rows:
            r["flags"] = json.loads(r["flags"]) if r["flags"] else []
    except Exception:
        rows = []
    conn.close()
    return rows

# ── Sandbox reports ───────────────────────────────────────────────────────────

@app.get("/api/sandbox")
def sandbox(limit: int = 50):
    conn = db()
    c = conn.cursor()
    try:
        c.execute("""
            SELECT id, timestamp, file_path, verdict,
                   threat_score, behaviour_flags, exit_code, run_duration
            FROM sandbox_reports
            ORDER BY id DESC LIMIT ?
        """, (limit,))
        rows = [dict(r) for r in c.fetchall()]
        for r in rows:
            r["behaviour_flags"] = json.loads(r["behaviour_flags"]) if r["behaviour_flags"] else []
            r["file_name"] = Path(r["file_path"]).name if r["file_path"] else "unknown"
    except Exception:
        rows = []
    conn.close()
    return rows

# ── AI assessments ────────────────────────────────────────────────────────────

@app.get("/api/assessments")
def assessments(limit: int = 50):
    conn = db()
    c = conn.cursor()
    try:
        c.execute("""
            SELECT id, timestamp, file_path, verdict, threat_score,
                   threat_type, threat_family, confidence,
                   what_it_does, why_dangerous, recommended_action, indicators
            FROM ai_assessments
            ORDER BY id DESC LIMIT ?
        """, (limit,))
        rows = [dict(r) for r in c.fetchall()]
        for r in rows:
            r["indicators"] = json.loads(r["indicators"]) if r["indicators"] else []
            r["file_name"]  = Path(r["file_path"]).name if r["file_path"] else "unknown"
    except Exception:
        rows = []
    conn.close()
    return rows

# ── Network devices ───────────────────────────────────────────────────────────

@app.get("/api/network")
def network():
    conn = db()
    c = conn.cursor()
    try:
        c.execute("""
            SELECT id, first_seen, last_seen, ip, mac, hostname,
                   vendor, open_ports, is_trusted, threat_score, flags, scan_count
            FROM network_devices
            ORDER BY threat_score DESC
        """)
        rows = [dict(r) for r in c.fetchall()]
        for r in rows:
            r["open_ports"] = json.loads(r["open_ports"]) if r["open_ports"] else []
            r["flags"]      = json.loads(r["flags"])      if r["flags"]      else []
    except Exception:
        rows = []
    conn.close()
    return rows

# ── Recent alerts feed ────────────────────────────────────────────────────────

@app.get("/api/alerts")
def alerts(limit: int = 30):
    conn = db()
    c = conn.cursor()
    all_alerts = []

    # High score processes
    try:
        c.execute("""
            SELECT timestamp, 'process' as type, name as title,
                   score, status as severity, flags
            FROM process_events WHERE score >= 50
            ORDER BY id DESC LIMIT 10
        """)
        for r in c.fetchall():
            row = dict(r)
            row["flags"] = json.loads(row["flags"]) if row["flags"] else []
            all_alerts.append(row)
    except Exception:
        pass

    # Malicious sandbox results
    try:
        c.execute("""
            SELECT timestamp, 'sandbox' as type,
                   file_path as title, threat_score as score,
                   verdict as severity, behaviour_flags as flags
            FROM sandbox_reports
            WHERE verdict IN ('MALICIOUS','SUSPICIOUS')
            ORDER BY id DESC LIMIT 10
        """)
        for r in c.fetchall():
            row = dict(r)
            row["flags"] = json.loads(row["flags"]) if row["flags"] else []
            row["title"] = Path(row["title"]).name if row["title"] else "unknown"
            all_alerts.append(row)
    except Exception:
        pass

    # High risk network devices
    try:
        c.execute("""
            SELECT last_seen as timestamp, 'network' as type,
                   ip as title, threat_score as score,
                   'HIGH_RISK' as severity, flags
            FROM network_devices WHERE threat_score >= 50
            ORDER BY id DESC LIMIT 10
        """)
        for r in c.fetchall():
            row = dict(r)
            row["flags"] = json.loads(row["flags"]) if row["flags"] else []
            all_alerts.append(row)
    except Exception:
        pass

    # Sort by timestamp descending
    all_alerts.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    conn.close()
    return all_alerts[:limit]

# ── Threat trend (last 7 days) ────────────────────────────────────────────────

@app.get("/api/trend")
def trend():
    conn = db()
    c = conn.cursor()
    try:
        c.execute("""
            SELECT DATE(timestamp) as day, COUNT(*) as count, verdict
            FROM sandbox_reports
            GROUP BY day, verdict
            ORDER BY day DESC LIMIT 28
        """)
        rows = [dict(r) for r in c.fetchall()]
    except Exception:
        rows = []
    conn.close()
    return rows