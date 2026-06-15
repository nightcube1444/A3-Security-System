"""
A3 Security System — Incident Engine
The detective. Correlates events from all layers into incidents.
One suspicious process + one flagged file + one unknown device = an incident.
Groups related events into cases, assigns severity, triggers response.
"""

import sqlite3
import json
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH  = DATA_DIR / "a3_threats.db"

# ── Severity levels ───────────────────────────────────────────────────────────
SEVERITY = {
    "CRITICAL": 4,
    "HIGH":     3,
    "MEDIUM":   2,
    "LOW":      1,
    "INFO":     0
}

# How long to keep correlating events into the same incident (minutes)
CORRELATION_WINDOW = 15

def log(message, level="INFO"):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    colours = {
        "INFO":"\033[97m","OK":"\033[92m","WARN":"\033[93m",
        "ALERT":"\033[91m","INC":"\033[95m"
    }
    print(f"[{ts}] {colours.get(level,'')}[INCIDENT][{level}]\033[0m {message}")

# ── Database ───────────────────────────────────────────────────────────────────

def init_incident_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id   TEXT UNIQUE,
            title         TEXT,
            severity      TEXT,
            status        TEXT DEFAULT 'OPEN',
            event_count   INTEGER DEFAULT 0,
            first_event   TEXT,
            last_event    TEXT,
            events        TEXT,
            summary       TEXT,
            mitre_tactic  TEXT,
            recommended   TEXT
        )
    """)
    conn.commit()
    conn.close()

# ── Incident ID generator ─────────────────────────────────────────────────────

def make_incident_id():
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    import random, string
    suffix = "".join(random.choices(string.ascii_uppercase, k=4))
    return f"INC-{ts}-{suffix}"

# ── MITRE ATT&CK mapping ──────────────────────────────────────────────────────

def map_to_mitre(flags):
    """Map threat flags to MITRE ATT&CK tactics."""
    mappings = {
        "static_reverse_shell":      ("TA0011", "Command and Control"),
        "static_keylogger":          ("TA0009", "Collection"),
        "static_ransomware":         ("TA0040", "Impact"),
        "static_recursive_delete":   ("TA0040", "Impact"),
        "static_base64_decode":      ("TA0005", "Defense Evasion"),
        "static_imports_subprocess": ("TA0002", "Execution"),
        "static_system_command":     ("TA0002", "Execution"),
        "runtime_reads_sensitive":   ("TA0007", "Discovery"),
        "high_risk_port:RDP":        ("TA0008", "Lateral Movement"),
        "high_risk_port:SMB":        ("TA0008", "Lateral Movement"),
        "dga_pattern":               ("TA0011", "Command and Control"),
        "threat_feed":               ("TA0001", "Initial Access"),
        "cpu_spike":                 ("TA0040", "Impact"),
        "unexpected_connections":    ("TA0011", "Command and Control"),
    }
    for flag in flags:
        for key, (tactic_id, tactic_name) in mappings.items():
            if key in flag:
                return f"{tactic_id} — {tactic_name}"
    return "TA0000 — Unknown"

# ── Severity calculator ────────────────────────────────────────────────────────

def calculate_severity(events):
    """Calculate incident severity from constituent events."""
    score = 0
    for ev in events:
        ev_type = ev.get("type", "")
        data    = ev.get("data", {})

        if "malicious" in ev_type:
            score += 40
        elif "suspicious" in ev_type:
            score += 20
        elif "anomaly" in ev_type:
            score += 15
        elif "high_risk" in ev_type:
            score += 25
        elif "dns" in ev_type:
            score += 10

        score += data.get("score", 0) // 10
        score += data.get("anomaly_score", 0) * 20

    if score >= 80:
        return "CRITICAL"
    elif score >= 50:
        return "HIGH"
    elif score >= 25:
        return "MEDIUM"
    else:
        return "LOW"

# ── Incident correlator ────────────────────────────────────────────────────────

class IncidentCorrelator:
    def __init__(self):
        self._active_incidents = {}  # incident_id → incident dict
        self._lock = threading.Lock()

    def _find_related_incident(self, event):
        """
        Find an existing open incident this event belongs to.
        Events are related if they happen within CORRELATION_WINDOW minutes
        and share a common indicator (same process, IP, domain, or file).
        """
        now      = datetime.now()
        window   = timedelta(minutes=CORRELATION_WINDOW)
        ev_data  = event.get("data", {})

        # Extract indicators from event
        indicators = set()
        for field in ["process", "ip", "domain", "file", "file_path", "mac"]:
            val = ev_data.get(field, "")
            if val:
                indicators.add(str(val).lower())

        for inc_id, incident in self._active_incidents.items():
            # Check time window
            last = datetime.fromisoformat(incident["last_event"])
            if now - last > window:
                continue

            # Check shared indicators
            inc_indicators = set(incident.get("indicators", []))
            if indicators & inc_indicators:
                return inc_id

        return None

    def correlate(self, event):
        """Add an event to the incident system."""
        with self._lock:
            ev_type = event.get("type", "")
            ev_data = event.get("data", {})
            now_iso = datetime.now().isoformat()

            # Extract indicators
            indicators = set()
            for field in ["process", "ip", "domain", "file",
                           "file_path", "mac"]:
                val = ev_data.get(field, "")
                if val:
                    indicators.add(str(val).lower())

            # Find related incident or create new one
            inc_id = self._find_related_incident(event)

            if inc_id and inc_id in self._active_incidents:
                # Add to existing incident
                incident = self._active_incidents[inc_id]
                incident["events"].append(event)
                incident["last_event"] = now_iso
                incident["event_count"] += 1
                incident["indicators"].update(indicators)
                incident["severity"] = calculate_severity(incident["events"])
                self._save_incident(incident)
                log(f"Event added to {inc_id} "
                    f"(total: {incident['event_count']} events)", "INC")

            else:
                # Create new incident
                inc_id   = make_incident_id()
                title    = self._generate_title(ev_type, ev_data)
                severity = calculate_severity([event])
                mitre    = map_to_mitre(
                    ev_data.get("flags", []) +
                    [ev_type]
                )
                recommended = self._get_recommendation(ev_type, severity)

                incident = {
                    "incident_id":  inc_id,
                    "title":        title,
                    "severity":     severity,
                    "status":       "OPEN",
                    "event_count":  1,
                    "first_event":  now_iso,
                    "last_event":   now_iso,
                    "events":       [event],
                    "indicators":   indicators,
                    "mitre_tactic": mitre,
                    "recommended":  recommended,
                    "summary":      f"1 event detected — {title}"
                }
                self._active_incidents[inc_id] = incident
                self._save_incident(incident)

                col = ("\033[91m" if severity in ("CRITICAL","HIGH")
                       else "\033[93m")
                log(f"NEW INCIDENT [{col}{severity}\033[0m] "
                    f"{inc_id}: {title}", "ALERT")

                # Telegram alert for high/critical
                if severity in ("CRITICAL", "HIGH"):
                    try:
                        from telegram_bot import send
                        flags = ev_data.get("flags", [])
                        send(
                            f"🚨 <b>NEW INCIDENT — {severity}</b>\n\n"
                            f"<b>ID</b>: <code>{inc_id}</code>\n"
                            f"<b>Title</b>: {title}\n"
                            f"<b>MITRE</b>: {mitre}\n"
                            f"<b>Action</b>: {recommended}\n\n"
                            f"<i>{now_iso[:16]}</i>"
                        )
                    except Exception:
                        pass

            return inc_id

    def _generate_title(self, ev_type, data):
        """Generate a human-readable incident title."""
        titles = {
            "sandbox.malicious":   f"Malicious file: {Path(data.get('file','unknown')).name}",
            "sandbox.suspicious":  f"Suspicious file: {Path(data.get('file','unknown')).name}",
            "sandbox.feed_hit":    f"Known malware detected: {data.get('malware','unknown')}",
            "network.high_risk":   f"High-risk device: {data.get('ip','unknown')}",
            "network.new_device":  f"Unknown device: {data.get('ip','unknown')}",
            "dns.malicious":       f"Malicious DNS: {data.get('domain','unknown')}",
            "dns.suspicious":      f"Suspicious DNS: {data.get('domain','unknown')}",
            "baseline.anomaly":    f"Behavioral anomaly: {data.get('process','unknown')}",
            "process.flagged":     f"Suspicious process: {data.get('name','unknown')}",
            "feed.hit.hash":       f"Known malware hash matched",
            "feed.hit.ip":         f"Known malicious IP: {data.get('ip','unknown')}",
            "chain.tampered":      f"BLOCKCHAIN TAMPERED — evidence may be compromised",
        }
        return titles.get(ev_type, f"Security event: {ev_type}")

    def _get_recommendation(self, ev_type, severity):
        """Get recommended action for this type of incident."""
        recommendations = {
            "sandbox.malicious":  "Quarantine file immediately. Check for lateral movement.",
            "sandbox.suspicious": "Review file manually. Monitor related processes.",
            "network.high_risk":  "Isolate device from network. Investigate open ports.",
            "network.new_device": "Identify device owner. If unknown, block at router.",
            "dns.malicious":      "Block domain at DNS level. Check for data exfiltration.",
            "baseline.anomaly":   "Investigate process behaviour. Check for injection.",
            "process.flagged":    "Terminate process if confirmed malicious.",
            "chain.tampered":     "URGENT: Preserve evidence. Initiate incident response.",
        }
        return recommendations.get(
            ev_type,
            "Investigate and document. Escalate if severity remains."
        )

    def _save_incident(self, incident):
        """Save or update incident in database."""
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("""
                INSERT OR REPLACE INTO incidents
                (incident_id, title, severity, status, event_count,
                 first_event, last_event, events, summary,
                 mitre_tactic, recommended)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """, (
                incident["incident_id"],
                incident["title"],
                incident["severity"],
                incident["status"],
                incident["event_count"],
                incident["first_event"],
                incident["last_event"],
                json.dumps(incident["events"]),
                f"{incident['event_count']} event(s) — {incident['title']}",
                incident["mitre_tactic"],
                incident["recommended"]
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            log(f"Save incident error: {e}", "WARN")

    def cleanup_old(self, hours=24):
        """Move old open incidents to MONITORING status."""
        cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
        with self._lock:
            for inc_id, incident in list(self._active_incidents.items()):
                if incident["last_event"] < cutoff:
                    incident["status"] = "MONITORING"
                    self._save_incident(incident)
                    del self._active_incidents[inc_id]

# ── Global correlator ─────────────────────────────────────────────────────────
correlator = IncidentCorrelator()

# ── Event bus integration ─────────────────────────────────────────────────────

def setup_event_bus_handlers():
    """Subscribe to all relevant events from the event bus."""
    try:
        from event_bus import bus, Events
        if not bus._running:
            bus.start()

        # Events that should trigger incident correlation
        incident_events = [
            Events.SANDBOX_MALICIOUS,
            Events.SANDBOX_SUSPICIOUS,
            Events.SANDBOX_FEED_HIT,
            Events.NETWORK_HIGH_RISK,
            Events.NETWORK_NEW_DEVICE,
            Events.DNS_MALICIOUS,
            Events.DNS_SUSPICIOUS,
            Events.BASELINE_ANOMALY,
            Events.PROCESS_FLAGGED,
            Events.FEED_HIT_HASH,
            Events.FEED_HIT_IP,
            Events.CHAIN_TAMPERED,
        ]

        def handle_event(event):
            correlator.correlate({
                "type":      event.type,
                "data":      event.data,
                "source":    event.source,
                "timestamp": event.timestamp
            })

        for ev_type in incident_events:
            bus.subscribe(ev_type, handle_event)

        log(f"Subscribed to {len(incident_events)} event type(s)", "OK")
        return True
    except Exception as e:
        log(f"Event bus setup failed: {e}", "WARN")
        return False

# ── Print incidents ────────────────────────────────────────────────────────────

def print_incidents(limit=10):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT incident_id, title, severity, status,
               event_count, first_event, mitre_tactic
        FROM incidents
        ORDER BY
            CASE severity
                WHEN 'CRITICAL' THEN 4
                WHEN 'HIGH'     THEN 3
                WHEN 'MEDIUM'   THEN 2
                WHEN 'LOW'      THEN 1
                ELSE 0
            END DESC,
            last_event DESC
        LIMIT ?
    """, (limit,))
    rows = c.fetchall()
    conn.close()

    print(f"\n{'═'*60}")
    print(f"  INCIDENTS ({len(rows)} shown)")
    print(f"{'═'*60}")

    cols = {
        "CRITICAL": "\033[91m", "HIGH": "\033[91m",
        "MEDIUM":   "\033[93m", "LOW":  "\033[94m"
    }
    reset = "\033[0m"

    for inc_id, title, severity, status, count, first, mitre in rows:
        col = cols.get(severity, "")
        print(f"\n  {col}[{severity}]{reset} {inc_id}")
        print(f"  Title  : {title}")
        print(f"  Status : {status}  Events: {count}  Since: {first[:16]}")
        print(f"  MITRE  : {mitre}")

    print(f"\n{'═'*60}\n")

def start_incident_engine():
    """Start the incident engine."""
    init_incident_db()
    setup_event_bus_handlers()

    # Background cleanup thread
    def cleanup_loop():
        while True:
            time.sleep(3600)
            correlator.cleanup_old(hours=24)

    t = threading.Thread(target=cleanup_loop, daemon=True,
                          name="incident-cleanup")
    t.start()
    log("Incident engine started ✓", "OK")

# ── Main ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    init_incident_db()

    if "--list" in sys.argv:
        print_incidents()

    elif "--test" in sys.argv:
        # Simulate a multi-event incident
        log("Running incident correlation test...")

        from event_bus import bus, Events
        bus.start()
        setup_event_bus_handlers()

        # Simulate attack sequence
        time.sleep(0.5)
        bus.publish(Events.SANDBOX_MALICIOUS, {
            "file": "/tmp/payload.py",
            "score": 110,
            "verdict": "MALICIOUS",
            "flags": ["static_imports_subprocess", "static_base64_decode"]
        }, source="sandbox")

        time.sleep(0.5)
        bus.publish(Events.PROCESS_FLAGGED, {
            "name": "python3",
            "pid": 9999,
            "score": 80,
            "flags": ["unexpected_connections"]
        }, source="monitor")

        time.sleep(0.5)
        bus.publish(Events.DNS_SUSPICIOUS, {
            "domain": "xk92jdla.xyz",
            "score": 65,
            "flags": ["dga_pattern", "suspicious_tld"]
        }, source="dns_monitor")

        time.sleep(1)
        bus.wait_until_empty()
        print_incidents(limit=5)

    else:
        start_incident_engine()
        log("Incident engine running. Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(60)
        except KeyboardInterrupt:
            pass