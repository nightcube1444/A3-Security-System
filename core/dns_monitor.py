"""
A3 Security System — DNS Monitoring Layer
Watches every DNS query your Mac makes.
Flags lookups for known malicious domains,
unusual TLDs, DGA patterns, and suspicious behaviour.
Malware always phones home — DNS is how it does it.
"""

import subprocess
import sqlite3
import json
import re
import threading
import time
import hashlib
from datetime import datetime
from pathlib import Path
from collections import Counter

BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH  = DATA_DIR / "a3_threats.db"

# ── Suspicious TLDs — commonly used in malware/phishing ──────────────────────
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",  # free TLDs abused heavily
    ".xyz", ".top", ".club", ".work",
    ".date", ".download", ".stream",
    ".bid", ".win", ".loan", ".review",
    ".accountant", ".science", ".faith"
}

# ── Known DGA patterns — domain generation algorithm signatures ───────────────
DGA_PATTERNS = [
    r"^[a-z]{12,20}\.(com|net|org|info)$",      # long random lowercase
    r"^[a-z0-9]{15,30}\.(com|net)$",             # alphanumeric garbage
    r"^[bcdfghjklmnpqrstvwxz]{8,}\.",             # no vowels (consonant-heavy)
]

# ── Legit high-volume domains to whitelist ────────────────────────────────────
WHITELIST = {
    "apple.com", "icloud.com", "apple-dns.net",
    "google.com", "googleapis.com", "gstatic.com",
    "microsoft.com", "windows.com", "office.com",
    "cloudflare.com", "fastly.com", "akamai.net",
    "amazonaws.com", "cloudfront.net",
    "anthropic.com", "openai.com",
    "localhost", "local"
}

def log(message, level="INFO"):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    colours = {
        "INFO":  "\033[97m", "OK":    "\033[92m",
        "WARN":  "\033[93m", "ALERT": "\033[91m",
        "DNS":   "\033[96m"
    }
    print(f"[{ts}] {colours.get(level,'')}[DNS][{level}]\033[0m {message}")

# ── Database ───────────────────────────────────────────────────────────────────

def init_dns_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS dns_queries (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT,
            domain      TEXT,
            query_type  TEXT,
            source_pid  TEXT,
            source_proc TEXT,
            threat_score INTEGER DEFAULT 0,
            flags       TEXT,
            blocked     INTEGER DEFAULT 0
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS dns_stats (
            domain      TEXT PRIMARY KEY,
            query_count INTEGER DEFAULT 0,
            first_seen  TEXT,
            last_seen   TEXT,
            max_score   INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()

# ── Domain analysis ────────────────────────────────────────────────────────────

def extract_root_domain(domain):
    """Extract root domain from subdomain. e.g. sub.evil.com → evil.com"""
    parts = domain.rstrip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain

def is_whitelisted(domain):
    root = extract_root_domain(domain)
    return (domain in WHITELIST or root in WHITELIST or
            any(domain.endswith("." + w) for w in WHITELIST))

def calculate_entropy(domain):
    """
    Shannon entropy of a domain name.
    High entropy = random-looking = possible DGA.
    Legitimate domains tend to have lower entropy.
    """
    name = domain.split(".")[0]
    if not name:
        return 0
    freq = Counter(name)
    length = len(name)
    entropy = -sum((count/length) * __import__("math").log2(count/length)
                   for count in freq.values())
    return round(entropy, 2)

def score_domain(domain):
    """Score a domain for threat indicators."""
    score = 0
    flags = []
    domain = domain.lower().strip().rstrip(".")

    if not domain or is_whitelisted(domain):
        return 0, []

    # Check threat intelligence feeds
    try:
        from threat_feeds import check_domain
        hit = check_domain(extract_root_domain(domain))
        if hit:
            score += 80
            flags.append(f"threat_feed:{hit['source']}")
            flags.append(f"threat_type:{hit['threat']}")
    except Exception:
        pass

    # Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 25
            flags.append(f"suspicious_tld:{tld}")
            break

    # DGA pattern matching
    for pattern in DGA_PATTERNS:
        if re.match(pattern, domain):
            score += 40
            flags.append("dga_pattern")
            break

    # High entropy (random-looking domain)
    entropy = calculate_entropy(domain)
    if entropy > 3.8:
        score += 20
        flags.append(f"high_entropy:{entropy}")

    # Very long domain name
    if len(domain) > 50:
        score += 15
        flags.append(f"long_domain:{len(domain)}")

    # Many subdomains (DNS tunneling indicator)
    parts = domain.split(".")
    if len(parts) > 5:
        score += 20
        flags.append(f"many_subdomains:{len(parts)}")

    # Contains IP address pattern
    if re.search(r"\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}", domain):
        score += 30
        flags.append("ip_in_domain")

    # Homograph attack patterns (numbers replacing letters)
    if re.search(r"(paypa1|g00gle|micosoft|arnazon|faceb00k)", domain):
        score += 70
        flags.append("homograph_attack")

    # Newly observed patterns (common in malware)
    suspicious_keywords = [
        "update", "secure", "login", "account", "verify",
        "banking", "password", "credential", "invoice",
        "download", "install", "payload", "gate", "bot"
    ]
    for kw in suspicious_keywords:
        if kw in domain:
            score += 10
            flags.append(f"suspicious_keyword:{kw}")
            break

    return score, flags

# ── DNS capture using system tools ────────────────────────────────────────────

def get_dns_cache():
    """
    Read macOS DNS cache to get recently resolved domains.
    Uses mDNSResponder statistics.
    """
    domains = set()
    try:
        result = subprocess.run(
            ["sudo", "-n", "dscacheutil", "-cachedump", "-entries", "Host"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            if "name:" in line.lower():
                parts = line.split(":")
                if len(parts) >= 2:
                    domain = parts[1].strip().rstrip(".")
                    if domain:
                        domains.add(domain.lower())
    except Exception:
        pass
    return domains

def get_active_connections_domains():
    """
    Get domains from active network connections using lsof.
    More reliable than DNS cache on Mac.
    """
    domains = {}
    try:
        result = subprocess.run(
            ["lsof", "-i", "-n", "-P"],
            capture_output=True, text=True, timeout=10
        )
        # Parse domains from established connections
        pattern = re.compile(
            r"(\S+)\s+(\d+)\s+\S+\s+\S+\s+IPv[46]\s+\S+\s+\S+\s+TCP\s+"
            r"[\d.]+:\d+->(\S+):\d+"
        )
        for match in pattern.finditer(result.stdout):
            proc_name, pid, remote = match.groups()
            # Try reverse DNS on IP
            if not re.match(r"^\d+\.\d+\.\d+\.\d+$", remote):
                domains[remote.lower()] = {"proc": proc_name, "pid": pid}
    except Exception:
        pass

    # Also try netstat for DNS queries (port 53)
    try:
        result = subprocess.run(
            ["netstat", "-an"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            if ".53 " in line or ":53 " in line:
                parts = line.split()
                if len(parts) >= 5:
                    addr = parts[4]
                    ip = addr.rsplit(".", 1)[0] if "." in addr else addr
                    if ip:
                        domains[ip] = {"proc": "dns_query", "pid": "0"}
    except Exception:
        pass

    return domains

def monitor_dns_log():
    """
    Monitor /var/log/system.log or use log stream for DNS activity.
    Most reliable method on modern macOS.
    """
    domains = {}
    try:
        # Use macOS log stream to capture DNS queries
        result = subprocess.run(
            ["log", "show", "--predicate",
             "subsystem == 'com.apple.mDNSResponder'",
             "--last", "1m", "--style", "compact"],
            capture_output=True, text=True, timeout=15
        )
        # Extract domain names from mDNSResponder logs
        domain_pattern = re.compile(
            r"([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\."
            r"[a-zA-Z]{2,}\.?)"
        )
        for line in result.stdout.splitlines():
            for match in domain_pattern.finditer(line):
                domain = match.group(1).lower().rstrip(".")
                if "." in domain and len(domain) > 4:
                    domains[domain] = {"proc": "mDNSResponder", "pid": "0"}
    except Exception:
        pass
    return domains

# ── Save and alert ────────────────────────────────────────────────────────────

def save_query(domain, score, flags, proc="unknown", pid="0"):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.now().isoformat()
    c.execute("""
        INSERT INTO dns_queries
        (timestamp, domain, query_type, source_pid, source_proc,
         threat_score, flags, blocked)
        VALUES (?,?,?,?,?,?,?,?)
    """, (now, domain, "A", str(pid), proc,
          score, json.dumps(flags), 0))

    # Update stats
    c.execute("""
        INSERT INTO dns_stats (domain, query_count, first_seen, last_seen, max_score)
        VALUES (?, 1, ?, ?, ?)
        ON CONFLICT(domain) DO UPDATE SET
            query_count = query_count + 1,
            last_seen   = excluded.last_seen,
            max_score   = MAX(max_score, excluded.max_score)
    """, (domain, now, now, score))

    conn.commit()
    conn.close()

# ── Main monitor loop ─────────────────────────────────────────────────────────

def run_monitor(interval=30):
    """
    Continuously monitor DNS activity.
    Checks every `interval` seconds.
    """
    log("DNS monitor started — watching all network queries", "DNS")
    seen_domains = set()
    alert_count  = 0

    while True:
        # Gather domains from multiple sources
        all_domains = {}
        all_domains.update(monitor_dns_log())
        all_domains.update(get_active_connections_domains())

        new_this_round = 0
        for domain, meta in all_domains.items():
            if domain in seen_domains:
                continue
            if len(domain) < 4 or "." not in domain:
                continue

            seen_domains.add(domain)
            score, flags = score_domain(domain)

            if score > 0:
                new_this_round += 1
                save_query(domain, score, flags,
                           meta.get("proc", "unknown"),
                           meta.get("pid", "0"))

                if score >= 60:
                    log(f"HIGH RISK DNS [{score}]: {domain} — {flags}", "ALERT")
                    alert_count += 1
                    # Telegram alert for high-risk domains
                    try:
                        from telegram_bot import send
                        send(
                            f"🌐 <b>SUSPICIOUS DNS QUERY</b>\n\n"
                            f"<b>Domain</b>: <code>{domain}</code>\n"
                            f"<b>Score</b>: {score}\n"
                            f"<b>Flags</b>: {', '.join(flags[:3])}\n\n"
                            f"<i>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>"
                        )
                    except Exception:
                        pass
                elif score >= 30:
                    log(f"Suspicious DNS [{score}]: {domain}", "WARN")

        if new_this_round:
            log(f"Analysed {new_this_round} new domain(s) — "
                f"{alert_count} total alerts", "DNS")

        time.sleep(interval)

# ── Stats ──────────────────────────────────────────────────────────────────────

def print_stats(limit=20):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT domain, query_count, max_score, last_seen
        FROM dns_stats
        WHERE max_score > 0
        ORDER BY max_score DESC
        LIMIT ?
    """, (limit,))
    rows = c.fetchall()

    c.execute("SELECT COUNT(*) FROM dns_queries")
    total = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM dns_queries WHERE threat_score >= 60")
    high_risk = c.fetchone()[0]
    conn.close()

    print(f"\n{'═'*55}")
    print(f"  DNS MONITORING STATS")
    print(f"{'═'*55}")
    print(f"  Total queries logged : {total}")
    print(f"  High risk domains    : {high_risk}")
    print(f"\n  Top suspicious domains:")
    for domain, count, score, last in rows:
        col = "\033[91m" if score >= 60 else "\033[93m"
        print(f"  {col}{score:3d}{chr(27)}[0m  {domain:<45} queries:{count}")
    print(f"{'═'*55}\n")

def start_dns_monitor():
    """Start DNS monitor as background thread."""
    t = threading.Thread(target=run_monitor, daemon=True, name="dns-monitor")
    t.start()
    log("DNS monitor running in background ✓", "OK")
    return t

# ── Main ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    init_dns_db()

    if "--stats" in sys.argv:
        print_stats()
    elif "--once" in sys.argv:
        # Single scan
        log("Running single DNS scan...")
        domains = monitor_dns_log()
        domains.update(get_active_connections_domains())
        log(f"Found {len(domains)} domain(s)")
        for domain, meta in sorted(domains.items())[:50]:
            score, flags = score_domain(domain)
            if score > 0:
                col = "\033[91m" if score >= 60 else "\033[93m"
                print(f"  {col}[{score:3d}]{chr(27)}[0m {domain}")
                if flags:
                    print(f"         {', '.join(flags)}")
    else:
        run_monitor(interval=30)