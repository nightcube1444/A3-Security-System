"""
A3 Security System — Event Bus
The central nervous system. All layers publish events here.
All layers subscribe to what they care about.
No tight coupling between components anymore.

Usage:
    from event_bus import bus

    # Publish an event
    bus.publish("threat.detected", {"file": "bad.py", "score": 110})

    # Subscribe to events
    bus.subscribe("threat.detected", my_handler_function)

    # Wildcard subscribe
    bus.subscribe("threat.*", handle_all_threats)
    bus.subscribe("*", handle_everything)
"""

import threading
import queue
import time
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from collections import defaultdict

BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH  = DATA_DIR / "a3_threats.db"

def log(message, level="INFO"):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    colours = {
        "INFO":"\033[97m","OK":"\033[92m",
        "WARN":"\033[93m","BUS":"\033[96m"
    }
    print(f"[{ts}] {colours.get(level,'')}[EVENT BUS][{level}]\033[0m {message}")

# ── Event types ───────────────────────────────────────────────────────────────
# All event types used across A3 — organised by category

class Events:
    # Layer 2 — process and file monitor
    PROCESS_FLAGGED     = "process.flagged"
    PROCESS_CLEAN       = "process.clean"
    FILE_FLAGGED        = "file.flagged"
    FILE_CREATED        = "file.created"
    FILE_MODIFIED       = "file.modified"

    # Layer 3 — sandbox
    SANDBOX_STARTED     = "sandbox.started"
    SANDBOX_COMPLETE    = "sandbox.complete"
    SANDBOX_MALICIOUS   = "sandbox.malicious"
    SANDBOX_SUSPICIOUS  = "sandbox.suspicious"
    SANDBOX_CLEAN       = "sandbox.clean"
    SANDBOX_FEED_HIT    = "sandbox.feed_hit"

    # Layer 4 — AI analysis
    AI_ASSESSMENT       = "ai.assessment"
    AI_QUARANTINE       = "ai.quarantine"

    # Layer 5 — network
    NETWORK_NEW_DEVICE  = "network.new_device"
    NETWORK_HIGH_RISK   = "network.high_risk"
    NETWORK_SCAN_DONE   = "network.scan_done"

    # DNS
    DNS_SUSPICIOUS      = "dns.suspicious"
    DNS_MALICIOUS       = "dns.malicious"
    DNS_FEED_HIT        = "dns.feed_hit"

    # Threat intelligence
    FEED_HIT_HASH       = "feed.hit.hash"
    FEED_HIT_IP         = "feed.hit.ip"
    FEED_HIT_DOMAIN     = "feed.hit.domain"
    FEED_UPDATED        = "feed.updated"

    # Baseline
    BASELINE_ANOMALY    = "baseline.anomaly"
    BASELINE_UPDATED    = "baseline.updated"

    # Incidents
    INCIDENT_CREATED    = "incident.created"
    INCIDENT_UPDATED    = "incident.updated"
    INCIDENT_RESOLVED   = "incident.resolved"

    # Swarm
    SWARM_THREAT_RECEIVED = "swarm.threat_received"
    SWARM_AGENT_JOINED    = "swarm.agent_joined"

    # Blockchain
    CHAIN_BLOCK_ADDED   = "chain.block_added"
    CHAIN_TAMPERED      = "chain.tampered"

    # System
    SYSTEM_STARTUP      = "system.startup"
    SYSTEM_SHUTDOWN     = "system.shutdown"
    SYSTEM_ERROR        = "system.error"

# ── Event object ──────────────────────────────────────────────────────────────

class Event:
    def __init__(self, event_type, data=None, source=None):
        self.id         = f"{int(time.time()*1000)}"
        self.type       = event_type
        self.data       = data or {}
        self.source     = source or "unknown"
        self.timestamp  = datetime.now().isoformat()

    def to_dict(self):
        return {
            "id":        self.id,
            "type":      self.type,
            "data":      self.data,
            "source":    self.source,
            "timestamp": self.timestamp
        }

    def __repr__(self):
        return f"Event({self.type}, source={self.source})"

# ── Event Bus ─────────────────────────────────────────────────────────────────

class EventBus:
    def __init__(self, persist=True, max_queue=1000):
        self._subscribers   = defaultdict(list)  # event_type → [handlers]
        self._wildcard_subs = []                  # handlers subscribed to "*"
        self._queue         = queue.Queue(maxsize=max_queue)
        self._lock          = threading.Lock()
        self._running       = False
        self._persist       = persist
        self._event_count   = 0
        self._worker        = None

    def subscribe(self, event_type, handler, description=""):
        """
        Subscribe a handler to an event type.
        Supports wildcards:
          - "*"         : all events
          - "threat.*"  : all threat events
          - "sandbox.*" : all sandbox events
        """
        with self._lock:
            if event_type == "*":
                self._wildcard_subs.append(handler)
                log(f"Wildcard subscriber added: {handler.__name__}", "BUS")
            else:
                self._subscribers[event_type].append(handler)
                log(f"Subscriber added: {handler.__name__} → {event_type}", "BUS")

    def unsubscribe(self, event_type, handler):
        with self._lock:
            if event_type == "*":
                self._wildcard_subs = [h for h in self._wildcard_subs
                                        if h != handler]
            elif event_type in self._subscribers:
                self._subscribers[event_type] = [
                    h for h in self._subscribers[event_type] if h != handler
                ]

    def publish(self, event_type, data=None, source=None):
        """
        Publish an event. Non-blocking — event is queued and
        processed asynchronously by the worker thread.
        """
        event = Event(event_type, data, source)
        try:
            self._queue.put_nowait(event)
            return event
        except queue.Full:
            log(f"Event queue full — dropping: {event_type}", "WARN")
            return None

    def publish_sync(self, event_type, data=None, source=None):
        """Publish and process synchronously — use sparingly."""
        event = Event(event_type, data, source)
        self._dispatch(event)
        return event

    def _dispatch(self, event):
        """Dispatch event to all matching subscribers."""
        handlers = []

        with self._lock:
            # Exact match
            handlers.extend(self._subscribers.get(event.type, []))

            # Prefix wildcard — e.g. "sandbox.*" matches "sandbox.complete"
            prefix = event.type.split(".")[0]
            handlers.extend(self._subscribers.get(f"{prefix}.*", []))

            # Global wildcard
            handlers.extend(self._wildcard_subs)

        # Deduplicate
        seen = set()
        unique_handlers = []
        for h in handlers:
            if id(h) not in seen:
                seen.add(id(h))
                unique_handlers.append(h)

        # Call each handler in its own thread so one slow handler
        # doesn't block others
        for handler in unique_handlers:
            t = threading.Thread(
                target=self._safe_call,
                args=(handler, event),
                daemon=True
            )
            t.start()

        self._event_count += 1

        # Persist high-value events to database
        if self._persist:
            self._maybe_persist(event)

    def _safe_call(self, handler, event):
        """Call a handler safely — catch and log exceptions."""
        try:
            handler(event)
        except Exception as e:
            log(f"Handler {handler.__name__} failed for {event.type}: {e}", "WARN")

    def _maybe_persist(self, event):
        """Save important events to database for history."""
        # Only persist meaningful security events
        persist_types = {
            Events.PROCESS_FLAGGED, Events.FILE_FLAGGED,
            Events.SANDBOX_MALICIOUS, Events.SANDBOX_SUSPICIOUS,
            Events.AI_QUARANTINE, Events.NETWORK_NEW_DEVICE,
            Events.NETWORK_HIGH_RISK, Events.DNS_MALICIOUS,
            Events.DNS_SUSPICIOUS, Events.BASELINE_ANOMALY,
            Events.INCIDENT_CREATED, Events.CHAIN_TAMPERED,
            Events.FEED_HIT_HASH, Events.FEED_HIT_IP,
        }
        if event.type not in persist_types:
            return
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("""
                CREATE TABLE IF NOT EXISTS event_log (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id   TEXT,
                    event_type TEXT,
                    source     TEXT,
                    data       TEXT,
                    timestamp  TEXT
                )
            """)
            c.execute("""
                INSERT INTO event_log
                (event_id, event_type, source, data, timestamp)
                VALUES (?,?,?,?,?)
            """, (
                event.id, event.type, event.source,
                json.dumps(event.data), event.timestamp
            ))
            conn.commit()
            conn.close()
        except Exception:
            pass

    def _worker_loop(self):
        """Background thread that processes the event queue."""
        log("Event bus worker started", "BUS")
        while self._running:
            try:
                event = self._queue.get(timeout=1)
                self._dispatch(event)
                self._queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                log(f"Worker error: {e}", "WARN")

    def start(self):
        """Start the event bus worker thread."""
        self._running = True
        self._worker  = threading.Thread(
            target=self._worker_loop,
            daemon=True,
            name="event-bus-worker"
        )
        self._worker.start()
        log("Event bus started ✓", "OK")

    def stop(self):
        self._running = False
        log(f"Event bus stopped — {self._event_count} events processed", "BUS")

    def stats(self):
        return {
            "event_count":    self._event_count,
            "queue_size":     self._queue.qsize(),
            "subscriber_types": len(self._subscribers),
            "wildcard_subs":  len(self._wildcard_subs),
            "running":        self._running
        }

    def wait_until_empty(self, timeout=10):
        """Wait for the queue to drain — useful for testing."""
        try:
            self._queue.join()
        except Exception:
            time.sleep(timeout)

# ── Global singleton ──────────────────────────────────────────────────────────
# Import this from anywhere: from event_bus import bus, Events
bus = EventBus(persist=True)

# ── Main — demo and test ──────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"\n{'═'*55}")
    print(f"  A3 EVENT BUS — demo")
    print(f"{'═'*55}\n")

    bus.start()

    # Example handlers
    def on_threat(event):
        print(f"  🚨 THREAT HANDLER: {event.data.get('file','?')} "
              f"score:{event.data.get('score',0)}")

    def on_any_sandbox(event):
        print(f"  📦 SANDBOX HANDLER: {event.type} — "
              f"{event.data.get('verdict','?')}")

    def on_network(event):
        print(f"  🌐 NETWORK HANDLER: {event.data.get('ip','?')}")

    def log_everything(event):
        print(f"  📝 LOG: [{event.type}] from {event.source}")

    # Subscribe
    bus.subscribe(Events.SANDBOX_MALICIOUS,  on_threat)
    bus.subscribe(Events.SANDBOX_SUSPICIOUS, on_threat)
    bus.subscribe("sandbox.*",               on_any_sandbox)
    bus.subscribe(Events.NETWORK_NEW_DEVICE, on_network)
    bus.subscribe("*",                       log_everything)

    print("Publishing test events...\n")

    # Publish test events
    bus.publish(Events.SANDBOX_MALICIOUS,
                {"file": "evil.py", "score": 110, "verdict": "MALICIOUS"},
                source="sandbox")

    bus.publish(Events.SANDBOX_CLEAN,
                {"file": "good.py", "score": 0, "verdict": "CLEAN"},
                source="sandbox")

    bus.publish(Events.NETWORK_NEW_DEVICE,
                {"ip": "192.168.1.99", "vendor": "Unknown"},
                source="signal_detector")

    bus.publish(Events.BASELINE_ANOMALY,
                {"process": "python3", "anomaly_score": 0.87},
                source="baseline_engine")

    # Wait for events to process
    time.sleep(1)
    bus.wait_until_empty()

    print(f"\n  Stats: {bus.stats()}\n")
    bus.stop()