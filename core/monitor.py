"""
A3 Security System — Layer 2: Process & File Monitor
The immune system's white blood cells.
Watches every process and file change on the system,
scores suspicious behaviour, and logs threats to the database.
"""

import psutil
import time
import hashlib
import sqlite3
import json
import os
import platform
from datetime import datetime
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR   = Path(__file__).parent.parent
DATA_DIR   = BASE_DIR / "data"
LOG_DIR    = BASE_DIR / "logs"
DB_PATH    = DATA_DIR / "a3_threats.db"
LOG_PATH   = LOG_DIR  / "monitor.log"

DATA_DIR.mkdir(exist_ok=True)
LOG_DIR.mkdir(exist_ok=True)

# ── Suspicious indicators (scoring system) ───────────────────────────────────
# Each flag adds points. Score >= THREAT_THRESHOLD → flagged as threat.
THREAT_THRESHOLD = 50

# Exact name matches only — the full process name must equal one of these
SUSPICIOUS_NAMES_EXACT = [
    "nc", "ncat", "netcat", "nmap", "masscan",
    "msfconsole", "metasploit", "cobaltstrike",
    "mimikatz", "lazagne", "keylogger",
    "backdoor", "reverse_shell", "payload"
]

# Substring matches — process name must CONTAIN this as a whole word
SUSPICIOUS_NAMES_KEYWORD = [
    "keylogger", "backdoor", "payload", "exploit",
    "shellcode", "rootkit", "ransomware"
]

# Known safe Apple system processes — never flag these
APPLE_WHITELIST = {
    "loginwindow", "launchd", "kernel_task", "syslogd", "configd",
    "notificationcenter", "usernotiﬁcationcenter", "usernotificationcenter",
    "safaribookmarksyncagent", "safarilaunchagent", "colorsync",
    "syncdefaultsd", "transparencyd", "cmfsyncagent", "imdpersistenceagent",
    "imklaunchagent", "mapssyncd", "appplaceholdersyncd", "avconferenced",
    "swtransparencyd", "siriinferenced", "protectedcloudkeysyncing",
    "postersyncd", "financed", "callhistorysynchelper", "intelligencecontextd",
    "intelligenceplatformcomputeservice", "colorsync.useragent",
    "com.apple.colorsyncxpcagent", "saextensionorchestrator",
    "qlpreviewgenerationextension", "intelligenceplatformd",
    "generativeexperiencesd", "windowserver", "coreaudiod", "bluetoothd",
    "locationd", "trustd", "securityd", "opendirectoryd", "diskarbitrationd",
    "mds", "mdworker", "spotlight", "systempolicyd", "symptomsd",
    "airportd", "wifid", "powerd", "thermalmonitord", "apsd",
}

SUSPICIOUS_PATHS = [
    "/tmp/", "/var/tmp/", "/dev/shm/",
    str(Path.home() / "Downloads"),
]

SUSPICIOUS_EXTENSIONS = [
    ".sh", ".py", ".rb", ".pl", ".exe",
    ".dmg", ".pkg", ".app", ".deb"
]

WATCH_DIRS = [
    str(Path.home() / "Downloads"),
    str(Path.home() / "Desktop"),
    "/tmp",
    "/var/tmp",
]

# ── Database setup ────────────────────────────────────────────────────────────

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS process_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT,
            pid         INTEGER,
            name        TEXT,
            exe         TEXT,
            cmdline     TEXT,
            username    TEXT,
            score       INTEGER,
            flags       TEXT,
            status      TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS file_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT,
            event_type  TEXT,
            path        TEXT,
            file_hash   TEXT,
            score       INTEGER,
            flags       TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS system_baseline (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            captured_at TEXT,
            process_count INTEGER,
            known_pids  TEXT
        )
    """)
    conn.commit()
    conn.close()
    log("Database initialised at " + str(DB_PATH))

# ── Logging ───────────────────────────────────────────────────────────────────

def log(message, level="INFO"):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] [{level}] {message}"
    print(line)
    with open(LOG_PATH, "a") as f:
        f.write(line + "\n")

# ── Process scoring ───────────────────────────────────────────────────────────

def score_process(proc_info):
    score = 0
    flags = []

    name = proc_info.get("name", "").lower()
    exe  = proc_info.get("exe",  "") or ""
    cmd  = " ".join(proc_info.get("cmdline", []) or []).lower()
    user = proc_info.get("username", "") or ""

    # Skip known safe Apple system processes entirely
    if name in APPLE_WHITELIST:
        return 0, []

    # Exact name match against known hacking tools
    if name in SUSPICIOUS_NAMES_EXACT:
        score += 60
        flags.append(f"exact_tool_match:{name}")

    # Keyword substring match (whole-word only)
    for keyword in SUSPICIOUS_NAMES_KEYWORD:
        if keyword in name:
            score += 40
            flags.append(f"keyword_match:{keyword}")

    # Running from a temp or download directory
    for p in SUSPICIOUS_PATHS:
        if exe.startswith(p):
            score += 30
            flags.append(f"suspicious_path:{p}")

    # Running as root — only flag non-Apple processes
    if user == "root" and not exe.startswith("/usr/") and not exe.startswith("/System/"):
        score += 20
        flags.append("unexpected_root")

    # Network connection with no known executable path
    if proc_info.get("connections") and not exe:
        score += 25
        flags.append("network_no_exe")

    # Command line contains base64 or eval (obfuscated payloads)
    if "base64" in cmd or " eval " in cmd:
        score += 35
        flags.append("obfuscated_command")

    # Hidden process name (starts with dot)
    if name.startswith("."):
        score += 40
        flags.append("hidden_process_name")

    return score, flags

def get_process_info(proc):
    try:
        with proc.oneshot():
            return {
                "pid":         proc.pid,
                "name":        proc.name(),
                "exe":         proc.exe() if proc.exe() else "",
                "cmdline":     proc.cmdline(),
                "username":    proc.username(),
                "connections": proc.net_connections(),
                "status":      proc.status(),
            }
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None

def save_process_event(info, score, flags):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT INTO process_events
        (timestamp, pid, name, exe, cmdline, username, score, flags, status)
        VALUES (?,?,?,?,?,?,?,?,?)
    """, (
        datetime.now().isoformat(),
        info["pid"],
        info["name"],
        info["exe"],
        " ".join(info["cmdline"] or []),
        info["username"],
        score,
        json.dumps(flags),
        "FLAGGED" if score >= THREAT_THRESHOLD else "CLEAN"
    ))
    conn.commit()
    conn.close()

# ── File event handler ────────────────────────────────────────────────────────

def file_hash(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return "unavailable"

def score_file(path):
    score = 0
    flags = []
    ext = Path(path).suffix.lower()

    if ext in SUSPICIOUS_EXTENSIONS:
        score += 30
        flags.append(f"suspicious_extension:{ext}")

    for p in SUSPICIOUS_PATHS:
        if path.startswith(p):
            score += 25
            flags.append(f"suspicious_location:{p}")

    # Executable bit set
    try:
        if os.access(path, os.X_OK):
            score += 20
            flags.append("executable_bit_set")
    except Exception:
        pass

    return score, flags

class A3FileHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            self._handle(event.src_path, "CREATED")

    def on_modified(self, event):
        if not event.is_directory:
            self._handle(event.src_path, "MODIFIED")

    def _handle(self, path, event_type):
        score, flags = score_file(path)
        fhash = file_hash(path) if score > 0 else "skipped"

        if score >= THREAT_THRESHOLD:
            log(f"FILE THREAT [{score}] {event_type}: {path} | flags: {flags}", "ALERT")
        elif score > 0:
            log(f"File event [{score}] {event_type}: {path} | flags: {flags}", "WARN")

        if score > 0:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("""
                INSERT INTO file_events
                (timestamp, event_type, path, file_hash, score, flags)
                VALUES (?,?,?,?,?,?)
            """, (
                datetime.now().isoformat(),
                event_type,
                path,
                fhash,
                score,
                json.dumps(flags)
            ))
            conn.commit()
            conn.close()

# ── Baseline snapshot ─────────────────────────────────────────────────────────

def capture_baseline():
    pids = [p.pid for p in psutil.process_iter()]
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT INTO system_baseline (captured_at, process_count, known_pids)
        VALUES (?,?,?)
    """, (datetime.now().isoformat(), len(pids), json.dumps(pids)))
    conn.commit()
    conn.close()
    log(f"Baseline captured — {len(pids)} processes running")

# ── Main monitor loop ─────────────────────────────────────────────────────────

def run_process_monitor(interval=10):
    seen_pids = set()
    log("Process monitor started")

    while True:
        current_pids = set()
        for proc in psutil.process_iter():
            try:
                current_pids.add(proc.pid)
                # Only analyse new processes we haven't seen before
                if proc.pid not in seen_pids:
                    info = get_process_info(proc)
                    if info:
                        score, flags = score_process(info)
                        if score >= THREAT_THRESHOLD:
                            log(
                                f"PROCESS THREAT [{score}] PID:{info['pid']} "
                                f"name:{info['name']} flags:{flags}",
                                "ALERT"
                            )
                            save_process_event(info, score, flags)
                        elif score > 0:
                            log(
                                f"Suspicious process [{score}] PID:{info['pid']} "
                                f"name:{info['name']} flags:{flags}",
                                "WARN"
                            )
                            save_process_event(info, score, flags)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        seen_pids = current_pids
        time.sleep(interval)

def run():
    log("=" * 60)
    log("A3 Security System — Layer 2 starting")
    log(f"Platform : {platform.system()} {platform.mac_ver()[0]}")
    log(f"Database : {DB_PATH}")
    log("=" * 60)

    init_db()
    capture_baseline()

    # Start file watcher
    handler  = A3FileHandler()
    observer = Observer()
    for d in WATCH_DIRS:
        if os.path.exists(d):
            observer.schedule(handler, d, recursive=True)
            log(f"Watching directory: {d}")
    observer.start()

    try:
        run_process_monitor(interval=10)
    except KeyboardInterrupt:
        log("Shutting down A3 monitor...")
        observer.stop()
    observer.join()

if __name__ == "__main__":
    run()