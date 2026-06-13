"""
A3 Security System — Threat Intelligence Feeds
Pulls known malicious IPs, domains, and file hashes from
free public threat intelligence sources automatically.
No API keys needed for basic feeds.

Sources:
  - MalwareBazaar  : known malware file hashes (abuse.ch)
  - Feodo Tracker  : botnet C2 IPs (abuse.ch)
  - URLhaus        : malicious URLs and domains (abuse.ch)
  - Emerging Threats: known bad IPs (open ruleset)
"""

import urllib.request
import urllib.error
import sqlite3
import json
import csv
import io
import time
import hashlib
from datetime import datetime, timedelta
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH  = DATA_DIR / "a3_threats.db"

# How often to refresh each feed (seconds)
FEED_INTERVALS = {
    "malwarebazaar": 3600,    # 1 hour
    "feodo":         3600,    # 1 hour
    "urlhaus":       3600,    # 1 hour
    "emerging":      86400,   # 24 hours
}

def log(message, level="INFO"):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    colours = {
        "INFO":  "\033[97m", "OK":    "\033[92m",
        "WARN":  "\033[93m", "ALERT": "\033[91m",
        "FEED":  "\033[96m"
    }
    print(f"[{ts}] {colours.get(level,'')}[FEEDS][{level}]\033[0m {message}")

# ── Database ───────────────────────────────────────────────────────────────────

def init_feeds_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Known malicious file hashes
    c.execute("""
        CREATE TABLE IF NOT EXISTS threat_hashes (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            hash       TEXT UNIQUE,
            hash_type  TEXT,
            malware    TEXT,
            source     TEXT,
            added_at   TEXT,
            tags       TEXT
        )
    """)

    # Known malicious IPs
    c.execute("""
        CREATE TABLE IF NOT EXISTS threat_ips (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ip         TEXT UNIQUE,
            port       TEXT,
            malware    TEXT,
            source     TEXT,
            added_at   TEXT,
            last_seen  TEXT
        )
    """)

    # Known malicious domains and URLs
    c.execute("""
        CREATE TABLE IF NOT EXISTS threat_domains (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            domain     TEXT UNIQUE,
            url        TEXT,
            threat     TEXT,
            source     TEXT,
            added_at   TEXT
        )
    """)

    # Feed metadata — when each feed was last updated
    c.execute("""
        CREATE TABLE IF NOT EXISTS feed_metadata (
            feed_name  TEXT PRIMARY KEY,
            last_updated TEXT,
            record_count INTEGER
        )
    """)

    conn.commit()
    conn.close()

# ── HTTP helper ───────────────────────────────────────────────────────────────

def _fetch(url, timeout=30):
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "A3-Security-System/1.0 (threat-intel)",
                "Accept":     "text/plain, application/json, text/csv"
            }
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="ignore")
    except Exception as e:
        log(f"Fetch error {url[:60]}: {e}", "WARN")
        return None

def _is_feed_fresh(feed_name):
    """Check if a feed was recently updated — avoid hammering APIs."""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            SELECT last_updated FROM feed_metadata WHERE feed_name = ?
        """, (feed_name,))
        row = c.fetchone()
        conn.close()
        if not row:
            return False
        last = datetime.fromisoformat(row[0])
        interval = FEED_INTERVALS.get(feed_name, 3600)
        return (datetime.now() - last).total_seconds() < interval
    except Exception:
        return False

def _update_feed_meta(feed_name, count):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT OR REPLACE INTO feed_metadata (feed_name, last_updated, record_count)
        VALUES (?,?,?)
    """, (feed_name, datetime.now().isoformat(), count))
    conn.commit()
    conn.close()

# ── MalwareBazaar — file hashes ───────────────────────────────────────────────

def update_malwarebazaar():
    """
    Pull recent malware hashes from MalwareBazaar (abuse.ch).
    Free, no API key needed. Updated every hour.
    """
    if _is_feed_fresh("malwarebazaar"):
        log("MalwareBazaar feed is fresh — skipping", "INFO")
        return 0

    log("Updating MalwareBazaar feed...", "FEED")

    # Get recent samples (last 1000)
    data = _fetch("https://mb-api.abuse.ch/api/v1/", timeout=30)

    # Use the export endpoint for bulk hashes
    raw = _fetch(
        "https://bazaar.abuse.ch/export/txt/sha256/recent/",
        timeout=60
    )

    if not raw:
        return 0

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    count = 0

    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # SHA256 hashes are 64 chars
        if len(line) == 64:
            try:
                c.execute("""
                    INSERT OR IGNORE INTO threat_hashes
                    (hash, hash_type, malware, source, added_at)
                    VALUES (?,?,?,?,?)
                """, (line.lower(), "sha256", "malware",
                      "malwarebazaar", datetime.now().isoformat()))
                count += c.rowcount
            except Exception:
                pass

    conn.commit()
    conn.close()
    _update_feed_meta("malwarebazaar", count)
    log(f"MalwareBazaar: added {count} new hash(es)", "OK")
    return count

# ── Feodo Tracker — botnet C2 IPs ─────────────────────────────────────────────

def update_feodo():
    """
    Pull known botnet command-and-control IPs from Feodo Tracker.
    These are IPs that malware phones home to.
    """
    if _is_feed_fresh("feodo"):
        log("Feodo feed is fresh — skipping", "INFO")
        return 0

    log("Updating Feodo Tracker feed...", "FEED")
    raw = _fetch(
        "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        timeout=30
    )

    if not raw:
        return 0

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    count = 0

    reader = csv.reader(io.StringIO(raw))
    for row in reader:
        if not row or row[0].startswith("#"):
            continue
        if len(row) >= 4:
            try:
                # Format: first_seen, dst_ip, dst_port, malware
                ip      = row[1].strip()
                port    = row[2].strip()
                malware = row[3].strip() if len(row) > 3 else "botnet"
                c.execute("""
                    INSERT OR REPLACE INTO threat_ips
                    (ip, port, malware, source, added_at, last_seen)
                    VALUES (?,?,?,?,?,?)
                """, (ip, port, malware, "feodo",
                      datetime.now().isoformat(),
                      datetime.now().isoformat()))
                count += 1
            except Exception:
                pass

    conn.commit()
    conn.close()
    _update_feed_meta("feodo", count)
    log(f"Feodo Tracker: loaded {count} botnet IP(s)", "OK")
    return count

# ── URLhaus — malicious URLs ──────────────────────────────────────────────────

def update_urlhaus():
    """
    Pull malicious URLs and domains from URLhaus (abuse.ch).
    Great for detecting malware download sites.
    """
    if _is_feed_fresh("urlhaus"):
        log("URLhaus feed is fresh — skipping", "INFO")
        return 0

    log("Updating URLhaus feed...", "FEED")
    raw = _fetch(
        "https://urlhaus.abuse.ch/downloads/csv_recent/",
        timeout=60
    )

    if not raw:
        return 0

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    count = 0

    reader = csv.reader(io.StringIO(raw))
    for row in reader:
        if not row or row[0].startswith("#"):
            continue
        if len(row) >= 5:
            try:
                url    = row[2].strip().strip('"')
                threat = row[4].strip().strip('"')
                if not url.startswith("http"):
                    continue
                # Extract domain from URL
                domain = url.split("/")[2] if "/" in url else url
                c.execute("""
                    INSERT OR IGNORE INTO threat_domains
                    (domain, url, threat, source, added_at)
                    VALUES (?,?,?,?,?)
                """, (domain.lower(), url, threat,
                      "urlhaus", datetime.now().isoformat()))
                count += c.rowcount
            except Exception:
                pass

    conn.commit()
    conn.close()
    _update_feed_meta("urlhaus", count)
    log(f"URLhaus: added {count} malicious domain(s)", "OK")
    return count

# ── Emerging Threats — known bad IPs ─────────────────────────────────────────

def update_emerging_threats():
    """
    Pull Emerging Threats open IP blocklist.
    Known scanners, attackers, and malicious hosts.
    """
    if _is_feed_fresh("emerging"):
        log("Emerging Threats feed is fresh — skipping", "INFO")
        return 0

    log("Updating Emerging Threats feed...", "FEED")
    raw = _fetch(
        "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        timeout=30
    )

    if not raw:
        return 0

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    count = 0

    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Simple IP validation
        parts = line.split(".")
        if len(parts) == 4:
            try:
                c.execute("""
                    INSERT OR IGNORE INTO threat_ips
                    (ip, port, malware, source, added_at, last_seen)
                    VALUES (?,?,?,?,?,?)
                """, (line, "", "compromised",
                      "emerging_threats",
                      datetime.now().isoformat(),
                      datetime.now().isoformat()))
                count += c.rowcount
            except Exception:
                pass

    conn.commit()
    conn.close()
    _update_feed_meta("emerging", count)
    log(f"Emerging Threats: added {count} IP(s)", "OK")
    return count

# ── Lookup functions ──────────────────────────────────────────────────────────

def check_hash(file_hash):
    """
    Check if a file hash is in the threat intelligence database.
    Returns threat info or None.
    Call this BEFORE sandboxing — instant verdict on known threats.
    """
    file_hash = file_hash.lower().strip()
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            SELECT malware, source, added_at, tags
            FROM threat_hashes WHERE hash = ?
        """, (file_hash,))
        row = c.fetchone()
        conn.close()
        if row:
            return {
                "matched":  True,
                "hash":     file_hash,
                "malware":  row[0],
                "source":   row[1],
                "added_at": row[2],
                "tags":     row[3]
            }
    except Exception as e:
        log(f"Hash lookup error: {e}", "WARN")
    return None

def check_ip(ip):
    """
    Check if an IP is in the threat intelligence database.
    Returns threat info or None.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            SELECT malware, source, port, last_seen
            FROM threat_ips WHERE ip = ?
        """, (ip,))
        row = c.fetchone()
        conn.close()
        if row:
            return {
                "matched": True,
                "ip":      ip,
                "malware": row[0],
                "source":  row[1],
                "port":    row[2],
                "last_seen": row[3]
            }
    except Exception as e:
        log(f"IP lookup error: {e}", "WARN")
    return None

def check_domain(domain):
    """
    Check if a domain is in the threat intelligence database.
    """
    domain = domain.lower().strip()
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            SELECT threat, source, url
            FROM threat_domains WHERE domain = ?
        """, (domain,))
        row = c.fetchone()
        conn.close()
        if row:
            return {
                "matched": True,
                "domain":  domain,
                "threat":  row[0],
                "source":  row[1],
                "url":     row[2]
            }
    except Exception as e:
        log(f"Domain lookup error: {e}", "WARN")
    return None

# ── Feed statistics ────────────────────────────────────────────────────────────

def get_stats():
    """Get current threat intelligence database statistics."""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM threat_hashes")
        hashes = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM threat_ips")
        ips = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM threat_domains")
        domains = c.fetchone()[0]
        c.execute("SELECT feed_name, last_updated, record_count FROM feed_metadata")
        feeds = c.fetchall()
        conn.close()
        return {
            "total_hashes":  hashes,
            "total_ips":     ips,
            "total_domains": domains,
            "feeds":         feeds
        }
    except Exception:
        return {}

def print_stats():
    stats = get_stats()
    print(f"\n{'═'*55}")
    print(f"  THREAT INTELLIGENCE DATABASE")
    print(f"{'═'*55}")
    print(f"  Known malware hashes : {stats.get('total_hashes', 0):,}")
    print(f"  Known malicious IPs  : {stats.get('total_ips', 0):,}")
    print(f"  Known bad domains    : {stats.get('total_domains', 0):,}")
    print(f"\n  Feed status:")
    for name, updated, count in stats.get("feeds", []):
        print(f"  {name:<20} {count:>6} records  updated:{updated[:16]}")
    print(f"{'═'*55}\n")

# ── Update all feeds ──────────────────────────────────────────────────────────

def update_all():
    """Pull all threat intelligence feeds. Safe to call frequently."""
    log("Updating all threat intelligence feeds...", "FEED")
    total = 0
    total += update_feodo()
    time.sleep(1)
    total += update_urlhaus()
    time.sleep(1)
    total += update_emerging_threats()
    time.sleep(1)
    total += update_malwarebazaar()
    log(f"Feed update complete — {total} new record(s) added", "OK")
    print_stats()
    return total

# ── Main ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    init_feeds_db()

    if "--stats" in sys.argv:
        print_stats()

    elif "--check-hash" in sys.argv:
        idx = sys.argv.index("--check-hash")
        if len(sys.argv) > idx + 1:
            h = sys.argv[idx + 1]
            result = check_hash(h)
            if result:
                print(f"\n  MATCH FOUND")
                print(f"  Hash   : {h}")
                print(f"  Malware: {result['malware']}")
                print(f"  Source : {result['source']}\n")
            else:
                print(f"\n  No match for {h}\n")

    elif "--check-ip" in sys.argv:
        idx = sys.argv.index("--check-ip")
        if len(sys.argv) > idx + 1:
            ip = sys.argv[idx + 1]
            result = check_ip(ip)
            if result:
                print(f"\n  MALICIOUS IP FOUND")
                print(f"  IP     : {ip}")
                print(f"  Malware: {result['malware']}")
                print(f"  Source : {result['source']}\n")
            else:
                print(f"\n  IP {ip} not in threat database\n")

    else:
        update_all()