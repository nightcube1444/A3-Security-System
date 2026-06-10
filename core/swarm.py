"""
A3 Security System — Swarm Layer
Many agents, one shared brain.
Each A3 instance publishes threat signatures to Redis.
All other agents subscribe and update their detection rules instantly.
One machine learns → all machines protected.
"""

import redis
import json
import sqlite3
import hashlib
import threading
import time
import socket
import uuid
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH  = DATA_DIR / "a3_threats.db"

# ── Config ────────────────────────────────────────────────────────────────────
REDIS_HOST    = "localhost"
REDIS_PORT    = 6379
REDIS_DB      = 0

CHANNEL_THREATS   = "a3:threats"       # new threat signatures
CHANNEL_HEARTBEAT = "a3:heartbeat"     # agent alive pings
CHANNEL_INTEL     = "a3:intel"         # shared threat intelligence

# This agent's unique identity
AGENT_ID      = str(uuid.uuid4())[:8]
AGENT_HOST    = socket.gethostname()

def log(message, level="INFO"):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    colours = {
        "INFO":  "\033[97m", "OK":    "\033[92m",
        "WARN":  "\033[93m", "ALERT": "\033[91m",
        "SWARM": "\033[95m"
    }
    print(f"[{ts}] {colours.get(level,'')}[SWARM/{AGENT_ID}][{level}]\033[0m {message}")

# ── Database ───────────────────────────────────────────────────────────────────

def init_swarm_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Shared threat signatures received from other agents
    c.execute("""
        CREATE TABLE IF NOT EXISTS swarm_signatures (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            received_at  TEXT,
            source_agent TEXT,
            source_host  TEXT,
            file_hash    TEXT UNIQUE,
            verdict      TEXT,
            threat_type  TEXT,
            flags        TEXT,
            score        INTEGER,
            shared_at    TEXT
        )
    """)

    # Agent registry — who is on the swarm
    c.execute("""
        CREATE TABLE IF NOT EXISTS swarm_agents (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id     TEXT UNIQUE,
            hostname     TEXT,
            first_seen   TEXT,
            last_seen    TEXT,
            threats_shared INTEGER DEFAULT 0
        )
    """)

    conn.commit()
    conn.close()

# ── Redis connection ──────────────────────────────────────────────────────────

def get_redis():
    try:
        r = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            db=REDIS_DB,
            decode_responses=True,
            socket_timeout=5
        )
        r.ping()
        return r
    except Exception as e:
        log(f"Redis connection failed: {e}", "WARN")
        return None

# ── Publish a threat to the swarm ─────────────────────────────────────────────

def publish_threat(file_hash, verdict, threat_type, flags, score):
    """
    Share a confirmed threat signature with all other agents.
    Called automatically when A3 finds a MALICIOUS or SUSPICIOUS file.
    """
    r = get_redis()
    if not r:
        return False

    message = {
        "type":         "threat",
        "agent_id":     AGENT_ID,
        "agent_host":   AGENT_HOST,
        "timestamp":    datetime.now().isoformat(),
        "file_hash":    file_hash,
        "verdict":      verdict,
        "threat_type":  threat_type,
        "flags":        flags,
        "score":        score,
    }

    try:
        r.publish(CHANNEL_THREATS, json.dumps(message))
        log(f"Published threat to swarm: {verdict} hash:{file_hash[:12]}...", "SWARM")

        # Also store in Redis as persistent intel (expires after 7 days)
        key = f"a3:sig:{file_hash}"
        r.setex(key, 604800, json.dumps(message))
        return True
    except Exception as e:
        log(f"Publish failed: {e}", "WARN")
        return False

# ── Check if hash is known threat ─────────────────────────────────────────────

def check_swarm_intel(file_hash):
    """
    Before sandboxing a file, check if any other agent already
    identified it as a threat. Returns threat info or None.
    """
    # Check local swarm signatures first
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            SELECT verdict, threat_type, flags, score, source_host
            FROM swarm_signatures
            WHERE file_hash = ?
        """, (file_hash,))
        row = c.fetchone()
        conn.close()
        if row:
            verdict, threat_type, flags_json, score, source = row
            return {
                "verdict":     verdict,
                "threat_type": threat_type,
                "flags":       json.loads(flags_json) if flags_json else [],
                "score":       score,
                "source":      source,
                "from_swarm":  True
            }
    except Exception:
        pass

    # Check Redis for real-time intel from other agents
    r = get_redis()
    if r:
        try:
            key  = f"a3:sig:{file_hash}"
            data = r.get(key)
            if data:
                info = json.loads(data)
                if info.get("agent_id") != AGENT_ID:
                    log(f"Swarm intel hit: {info['verdict']} from {info['agent_host']}", "SWARM")
                    return {
                        "verdict":     info["verdict"],
                        "threat_type": info.get("threat_type", "unknown"),
                        "flags":       info.get("flags", []),
                        "score":       info.get("score", 0),
                        "source":      info["agent_host"],
                        "from_swarm":  True
                    }
        except Exception:
            pass

    return None

# ── Save received threat signature ────────────────────────────────────────────

def save_signature(msg):
    """Save a threat signature received from another swarm agent."""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        # Update agent registry
        c.execute("""
            INSERT INTO swarm_agents (agent_id, hostname, first_seen, last_seen, threats_shared)
            VALUES (?, ?, ?, ?, 1)
            ON CONFLICT(agent_id) DO UPDATE SET
                last_seen = excluded.last_seen,
                threats_shared = threats_shared + 1
        """, (
            msg["agent_id"],
            msg["agent_host"],
            msg["timestamp"],
            msg["timestamp"]
        ))

        # Save signature (ignore if we already have it)
        c.execute("""
            INSERT OR IGNORE INTO swarm_signatures
            (received_at, source_agent, source_host, file_hash,
             verdict, threat_type, flags, score, shared_at)
            VALUES (?,?,?,?,?,?,?,?,?)
        """, (
            datetime.now().isoformat(),
            msg["agent_id"],
            msg["agent_host"],
            msg["file_hash"],
            msg["verdict"],
            msg.get("threat_type", "unknown"),
            json.dumps(msg.get("flags", [])),
            msg.get("score", 0),
            msg["timestamp"]
        ))

        conn.commit()
        conn.close()
    except Exception as e:
        log(f"Save signature error: {e}", "WARN")

# ── Subscriber thread ─────────────────────────────────────────────────────────

def start_subscriber():
    """
    Listen for threat intelligence from other agents.
    Runs in a background thread forever.
    """
    def _listen():
        log("Subscriber started — listening for swarm intel", "SWARM")
        while True:
            try:
                r = get_redis()
                if not r:
                    log("Waiting for Redis...", "WARN")
                    time.sleep(10)
                    continue

                pubsub = r.pubsub()
                pubsub.subscribe(CHANNEL_THREATS, CHANNEL_HEARTBEAT)
                log(f"Subscribed to channels: {CHANNEL_THREATS}, {CHANNEL_HEARTBEAT}", "OK")

                for message in pubsub.listen():
                    if message["type"] != "message":
                        continue

                    try:
                        data = json.loads(message["data"])
                    except Exception:
                        continue

                    # Skip our own messages
                    if data.get("agent_id") == AGENT_ID:
                        continue

                    channel = message["channel"]

                    if channel == CHANNEL_THREATS:
                        verdict = data.get("verdict", "?")
                        host    = data.get("agent_host", "?")
                        fhash   = data.get("file_hash", "")[:12]
                        log(
                            f"Received threat from {host}: "
                            f"{verdict} hash:{fhash}...",
                            "ALERT" if verdict == "MALICIOUS" else "WARN"
                        )
                        save_signature(data)

                    elif channel == CHANNEL_HEARTBEAT:
                        host = data.get("agent_host", "?")
                        aid  = data.get("agent_id", "?")
                        log(f"Agent online: {host} [{aid}]", "SWARM")
                        # Update agent registry
                        try:
                            conn = sqlite3.connect(DB_PATH)
                            c = conn.cursor()
                            c.execute("""
                                INSERT INTO swarm_agents
                                (agent_id, hostname, first_seen, last_seen)
                                VALUES (?,?,?,?)
                                ON CONFLICT(agent_id) DO UPDATE SET
                                    last_seen = excluded.last_seen
                            """, (aid, host,
                                  datetime.now().isoformat(),
                                  datetime.now().isoformat()))
                            conn.commit()
                            conn.close()
                        except Exception:
                            pass

            except Exception as e:
                log(f"Subscriber error: {e} — reconnecting in 5s", "WARN")
                time.sleep(5)

    t = threading.Thread(target=_listen, daemon=True, name="swarm-subscriber")
    t.start()
    return t

# ── Heartbeat thread ──────────────────────────────────────────────────────────

def start_heartbeat():
    """Announce this agent to the swarm every 30 seconds."""
    def _beat():
        while True:
            r = get_redis()
            if r:
                try:
                    msg = {
                        "type":       "heartbeat",
                        "agent_id":   AGENT_ID,
                        "agent_host": AGENT_HOST,
                        "timestamp":  datetime.now().isoformat()
                    }
                    r.publish(CHANNEL_HEARTBEAT, json.dumps(msg))
                except Exception:
                    pass
            time.sleep(30)

    t = threading.Thread(target=_beat, daemon=True, name="swarm-heartbeat")
    t.start()
    return t

# ── Sync existing threats to swarm ────────────────────────────────────────────

def sync_existing_threats():
    """
    On startup, share all confirmed MALICIOUS threats this agent
    has found with the rest of the swarm.
    """
    r = get_redis()
    if not r:
        return

    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            SELECT sr.file_hash, sr.verdict, sr.behaviour_flags, sr.threat_score,
                   aa.threat_type
            FROM sandbox_reports sr
            LEFT JOIN ai_assessments aa ON sr.id = aa.sandbox_report_id
            WHERE sr.verdict IN ('MALICIOUS', 'SUSPICIOUS')
            AND sr.file_hash != 'unavailable'
        """)
        threats = c.fetchall()
        conn.close()

        synced = 0
        for fhash, verdict, flags_json, score, threat_type in threats:
            flags = json.loads(flags_json) if flags_json else []
            key   = f"a3:sig:{fhash}"
            if not r.exists(key):
                publish_threat(fhash, verdict, threat_type or "unknown", flags, score)
                synced += 1

        if synced:
            log(f"Synced {synced} existing threat(s) to swarm", "SWARM")
    except Exception as e:
        log(f"Sync error: {e}", "WARN")

# ── Swarm status ──────────────────────────────────────────────────────────────

def get_swarm_status():
    """Get current swarm status — agents online, signatures shared."""
    status = {
        "agent_id":          AGENT_ID,
        "agent_host":        AGENT_HOST,
        "agents_seen":       0,
        "signatures_received": 0,
        "redis_connected":   False
    }

    r = get_redis()
    if r:
        status["redis_connected"] = True
        try:
            # Count signatures in Redis
            keys = r.keys("a3:sig:*")
            status["signatures_in_redis"] = len(keys)
        except Exception:
            pass

    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM swarm_agents")
        status["agents_seen"] = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM swarm_signatures")
        status["signatures_received"] = c.fetchone()[0]
        conn.close()
    except Exception:
        pass

    return status

# ── Start swarm ───────────────────────────────────────────────────────────────

def start_swarm():
    """Start all swarm components. Call this from the controller."""
    init_swarm_db()

    r = get_redis()
    if not r:
        log("Redis not available — swarm disabled", "WARN")
        return False

    log(f"Starting swarm agent [{AGENT_ID}] on {AGENT_HOST}", "SWARM")

    start_subscriber()
    start_heartbeat()
    sync_existing_threats()

    status = get_swarm_status()
    log(f"Swarm active — {status['agents_seen']} agent(s) known, "
        f"{status['signatures_received']} signature(s) received", "OK")
    return True

# ── Main ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"\n{'═'*55}")
    print(f"  A3 SWARM AGENT [{AGENT_ID}]")
    print(f"  Host: {AGENT_HOST}")
    print(f"{'═'*55}\n")

    if start_swarm():
        log("Swarm running. Press Ctrl+C to stop.")
        log("Open another terminal and run this on a second machine")
        log("to see agents discover each other automatically.")

        # Keep running and print status every 30 seconds
        try:
            while True:
                time.sleep(30)
                status = get_swarm_status()
                print(f"\n  Agents seen     : {status['agents_seen']}")
                print(f"  Sigs received   : {status['signatures_received']}")
                print(f"  Redis connected : {status['redis_connected']}\n")
        except KeyboardInterrupt:
            log("Swarm agent stopped.")
    else:
        log("Could not start swarm — is Redis running?", "WARN")
        log("Start Redis with: brew services start redis")