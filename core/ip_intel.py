"""
A3 Security System — IP Intelligence Module
When Layer 5 detects an unknown device or suspicious connection,
this module automatically looks up the IP using free public APIs:
  - ipinfo.io    : owner, ISP, location, org
  - AbuseIPDB    : abuse reports and confidence score
  - ip-api.com   : geolocation and ISP details
No API keys needed for basic lookups.
"""

import urllib.request
import urllib.error
import json
import sqlite3
import time
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH  = DATA_DIR / "a3_threats.db"

# Rate limiting — be respectful to free APIs
RATE_LIMIT_SECONDS = 1.5
_last_request = 0

def log(message, level="INFO"):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    colours = {
        "INFO":  "\033[97m", "OK":    "\033[92m",
        "WARN":  "\033[93m", "ALERT": "\033[91m",
        "INTEL": "\033[96m"
    }
    print(f"[{ts}] {colours.get(level,'')}[IP INTEL][{level}]\033[0m {message}")

def init_intel_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS ip_intelligence (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp    TEXT,
            ip           TEXT UNIQUE,
            hostname     TEXT,
            org          TEXT,
            isp          TEXT,
            country      TEXT,
            city         TEXT,
            region       TEXT,
            latitude     REAL,
            longitude    REAL,
            is_vpn       INTEGER DEFAULT 0,
            is_proxy     INTEGER DEFAULT 0,
            is_tor       INTEGER DEFAULT 0,
            abuse_score  INTEGER DEFAULT 0,
            abuse_reports INTEGER DEFAULT 0,
            threat_score INTEGER DEFAULT 0,
            raw_data     TEXT
        )
    """)
    conn.commit()
    conn.close()

# ── Rate limiter ──────────────────────────────────────────────────────────────

def _rate_limit():
    global _last_request
    elapsed = time.time() - _last_request
    if elapsed < RATE_LIMIT_SECONDS:
        time.sleep(RATE_LIMIT_SECONDS - elapsed)
    _last_request = time.time()

# ── HTTP helper ───────────────────────────────────────────────────────────────

def _get(url, timeout=10):
    try:
        _rate_limit()
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "A3-Security-System/1.0"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        log(f"Request failed {url}: {e}", "WARN")
        return None

# ── Is private IP ─────────────────────────────────────────────────────────────

def is_private_ip(ip):
    """Check if IP is a private/local address — skip lookup for these."""
    private_ranges = [
        "10.", "192.168.", "172.16.", "172.17.", "172.18.",
        "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
        "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
        "172.29.", "172.30.", "172.31.", "127.", "169.254.",
        "::1", "fc00:", "fe80:"
    ]
    return any(ip.startswith(r) for r in private_ranges)

# ── ipinfo.io lookup ──────────────────────────────────────────────────────────

def lookup_ipinfo(ip):
    """
    Free tier: 50,000 requests/month.
    Returns: org, hostname, city, region, country, location.
    """
    data = _get(f"https://ipinfo.io/{ip}/json")
    if not data:
        return {}
    return {
        "hostname": data.get("hostname", ""),
        "org":      data.get("org", ""),
        "city":     data.get("city", ""),
        "region":   data.get("region", ""),
        "country":  data.get("country", ""),
        "loc":      data.get("loc", ""),
        "timezone": data.get("timezone", ""),
    }

# ── ip-api.com lookup ─────────────────────────────────────────────────────────

def lookup_ipapi(ip):
    """
    Free tier: 45 requests/minute, no key needed.
    Returns: ISP, org, proxy/VPN detection, geolocation.
    """
    data = _get(
        f"http://ip-api.com/json/{ip}"
        f"?fields=status,message,country,regionName,city,lat,lon,"
        f"isp,org,as,proxy,hosting,query"
    )
    if not data or data.get("status") != "success":
        return {}
    return {
        "isp":      data.get("isp", ""),
        "org":      data.get("org", ""),
        "country":  data.get("country", ""),
        "city":     data.get("city", ""),
        "region":   data.get("regionName", ""),
        "lat":      data.get("lat", 0),
        "lon":      data.get("lon", 0),
        "is_proxy": data.get("proxy", False),
        "is_hosting": data.get("hosting", False),
        "asn":      data.get("as", ""),
    }

# ── Threat scoring ────────────────────────────────────────────────────────────

def score_ip_intel(ipinfo, ipapi):
    """Score an IP based on intelligence gathered."""
    score = 0
    flags = []

    # VPN/Proxy/Hosting detected
    if ipapi.get("is_proxy"):
        score += 30
        flags.append("proxy_detected")
    if ipapi.get("is_hosting"):
        score += 20
        flags.append("hosting_provider")

    # Known malicious ASNs (simplified list of commonly abused)
    asn = ipapi.get("asn", "").lower()
    suspicious_asns = ["as209", "as4134", "as4837", "as9009"]
    for s_asn in suspicious_asns:
        if s_asn in asn:
            score += 15
            flags.append(f"suspicious_asn:{asn[:20]}")
            break

    # No hostname — common for scanners/bots
    if not ipinfo.get("hostname"):
        score += 5
        flags.append("no_hostname")

    # Cloud/VPS providers often used for attacks
    org = (ipapi.get("org", "") + ipinfo.get("org", "")).lower()
    cloud_providers = ["digitalocean", "linode", "vultr", "ovh",
                       "hetzner", "choopa", "frantech"]
    for provider in cloud_providers:
        if provider in org:
            score += 15
            flags.append(f"cloud_vps:{provider}")
            break

    return score, flags

# ── Main lookup ───────────────────────────────────────────────────────────────

def lookup(ip):
    """
    Full IP intelligence lookup.
    Returns a dict with all available information and a threat score.
    """
    if is_private_ip(ip):
        log(f"Skipping private IP: {ip}", "INFO")
        return {"ip": ip, "private": True, "threat_score": 0}

    # Check cache first
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            SELECT * FROM ip_intelligence WHERE ip = ?
            AND timestamp > datetime('now', '-1 day')
        """, (ip,))
        cached = c.fetchone()
        conn.close()
        if cached:
            log(f"Cache hit for {ip}", "INFO")
            return {"ip": ip, "cached": True,
                    "org": cached[3], "isp": cached[4],
                    "country": cached[5], "city": cached[6],
                    "threat_score": cached[12]}
    except Exception:
        pass

    log(f"Looking up: {ip}", "INTEL")

    # Gather intel from multiple sources
    ipinfo = lookup_ipinfo(ip)
    ipapi  = lookup_ipapi(ip)

    # Score the IP
    threat_score, flags = score_ip_intel(ipinfo, ipapi)

    # Parse location
    lat, lon = 0.0, 0.0
    if ipinfo.get("loc"):
        try:
            lat, lon = map(float, ipinfo["loc"].split(","))
        except Exception:
            pass

    result = {
        "ip":           ip,
        "hostname":     ipinfo.get("hostname", ""),
        "org":          ipapi.get("org") or ipinfo.get("org", ""),
        "isp":          ipapi.get("isp", ""),
        "country":      ipapi.get("country") or ipinfo.get("country", ""),
        "city":         ipapi.get("city") or ipinfo.get("city", ""),
        "region":       ipapi.get("region") or ipinfo.get("region", ""),
        "latitude":     ipapi.get("lat") or lat,
        "longitude":    ipapi.get("lon") or lon,
        "is_proxy":     int(ipapi.get("is_proxy", False)),
        "is_hosting":   int(ipapi.get("is_hosting", False)),
        "asn":          ipapi.get("asn", ""),
        "threat_score": threat_score,
        "flags":        flags,
        "timezone":     ipinfo.get("timezone", ""),
    }

    # Save to database
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            INSERT OR REPLACE INTO ip_intelligence
            (timestamp, ip, hostname, org, isp, country, city, region,
             latitude, longitude, is_vpn, is_proxy, is_tor,
             abuse_score, abuse_reports, threat_score, raw_data)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            datetime.now().isoformat(),
            ip,
            result["hostname"],
            result["org"],
            result["isp"],
            result["country"],
            result["city"],
            result["region"],
            result["latitude"],
            result["longitude"],
            0,
            result["is_proxy"],
            0,
            0, 0,
            threat_score,
            json.dumps(result)
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        log(f"DB save error: {e}", "WARN")

    return result

# ── Display ───────────────────────────────────────────────────────────────────

def print_intel(result):
    ip    = result.get("ip", "")
    score = result.get("threat_score", 0)

    if score >= 40:
        col = "\033[91m"
    elif score >= 20:
        col = "\033[93m"
    else:
        col = "\033[92m"
    reset = "\033[0m"

    print(f"\n{'─'*55}")
    print(f"  {col}IP INTELLIGENCE — {ip}{reset}")
    print(f"{'─'*55}")

    if result.get("private"):
        print(f"  Private/local IP — no lookup needed\n")
        return

    fields = [
        ("Hostname",  result.get("hostname") or "—"),
        ("Org",       result.get("org")      or "—"),
        ("ISP",       result.get("isp")      or "—"),
        ("Location",  f"{result.get('city','')}, {result.get('country','')}"),
        ("ASN",       result.get("asn")      or "—"),
        ("Proxy/VPN", "YES" if result.get("is_proxy") else "No"),
        ("Hosting",   "YES" if result.get("is_hosting") else "No"),
        ("Score",     f"{col}{score}{reset}"),
    ]
    for label, value in fields:
        print(f"  {label:<12}: {value}")

    flags = result.get("flags", [])
    if flags:
        print(f"  Flags       : {', '.join(flags)}")

    print(f"{'─'*55}\n")

# ── Scan all network devices ──────────────────────────────────────────────────

def scan_all_network_devices():
    """Look up intel on every device Layer 5 found."""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT ip FROM network_devices ORDER BY threat_score DESC")
        devices = [row[0] for row in c.fetchall()]
        conn.close()
    except Exception:
        devices = []

    if not devices:
        log("No network devices found. Run signal_detector.py first.", "WARN")
        return

    log(f"Looking up {len(devices)} device(s)...", "INTEL")
    for ip in devices:
        result = lookup(ip)
        print_intel(result)

# ── Main ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    init_intel_db()

    if len(sys.argv) < 2:
        print("\nUsage:")
        print("  Lookup one IP    : python3 ip_intel.py 8.8.8.8")
        print("  Your public IP   : python3 ip_intel.py $(curl -s ifconfig.me)")
        print("  All network devs : python3 ip_intel.py --network")
        print()
        sys.exit(0)

    target = sys.argv[1]

    if target == "--network":
        scan_all_network_devices()
    else:
        result = lookup(target)
        print_intel(result)