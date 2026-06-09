"""
A3 Security System — Layer 5: Signal Detector
The nervous system's sensors. Discovers all devices on your network,
maps them, detects unknown or rogue devices, and flags anomalies.

On Mac we use:
  - ARP scan      : maps every IP + MAC on the network
  - mDNS/Bonjour  : discovers named services (printers, TVs, phones)
  - Bluetooth     : detects nearby BT devices
  - Port scan     : checks what services each device is running
"""

import subprocess
import sqlite3
import json
import socket
import struct
import time
import threading
import re
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH  = DATA_DIR / "a3_threats.db"

# ── Known device registry ─────────────────────────────────────────────────────
# Add your own trusted devices here (MAC address → friendly name)
# Find your device MACs by running this once: arp -a
TRUSTED_DEVICES = {
    "26:23:f0:eb:17:bc": "My MacBook",
    "bc:62:d2:54:03:60": "Router",
    "94:54:c5:f2:8e:b8": "Solar Inverter — Modbus OK"
}

# Ports to check on each device
INTERESTING_PORTS = [
    (22,   "SSH"),
    (23,   "Telnet"),        # old/insecure — always flag
    (80,   "HTTP"),
    (443,  "HTTPS"),
    (445,  "SMB"),           # Windows file sharing
    (3389, "RDP"),           # Remote desktop
    (8080, "HTTP-alt"),
    (8443, "HTTPS-alt"),
    (5900, "VNC"),           # Remote desktop
    (1883, "MQTT"),          # IoT protocol
    (502,  "Modbus"),        # Industrial/IoT
    (9100, "Printer"),
]

HIGH_RISK_PORTS = {23, 445, 3389, 5900, 502}  # these alone raise the score

def log(message, level="INFO"):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    colours = {"INFO":"\033[97m","WARN":"\033[93m","ALERT":"\033[91m","OK":"\033[92m"}
    reset = "\033[0m"
    col = colours.get(level, "")
    print(f"[{ts}] {col}[SIGNAL][{level}]{reset} {message}")

# ── Database ───────────────────────────────────────────────────────────────────

def init_signal_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS network_devices (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            first_seen   TEXT,
            last_seen    TEXT,
            ip           TEXT,
            mac          TEXT,
            hostname     TEXT,
            vendor       TEXT,
            open_ports   TEXT,
            is_trusted   INTEGER DEFAULT 0,
            threat_score INTEGER DEFAULT 0,
            flags        TEXT,
            scan_count   INTEGER DEFAULT 1
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS signal_events (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp  TEXT,
            event_type TEXT,
            ip         TEXT,
            mac        TEXT,
            details    TEXT,
            score      INTEGER
        )
    """)
    conn.commit()
    conn.close()

# ── Network helpers ────────────────────────────────────────────────────────────

def get_local_ip():
    """Get this machine's local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def get_network_prefix(ip):
    """Turn 192.168.1.5 into 192.168.1"""
    parts = ip.split(".")
    return ".".join(parts[:3])

def mac_vendor_guess(mac):
    """
    Guess device vendor from MAC OUI prefix.
    Very simplified — just the most common ones.
    """
    if not mac or mac == "unknown":
        return "unknown"
    prefix = mac.upper().replace("-", ":")[0:8]
    vendors = {
        "A4:83:E7": "Apple",    "F0:18:98": "Apple",
        "3C:22:FB": "Apple",    "8C:85:90": "Apple",
        "DC:A6:32": "Raspberry Pi", "B8:27:EB": "Raspberry Pi",
        "00:50:56": "VMware",   "00:0C:29": "VMware",
        "08:00:27": "VirtualBox",
        "00:16:3E": "Xen",
        "00:1A:11": "Google",   "54:60:09": "Google",
        "B0:BE:76": "Samsung",  "8C:77:12": "Samsung",
        "AC:BC:32": "Xiaomi",   "00:9E:C8": "Xiaomi",
        "18:65:90": "OnePlus",
        "74:DA:38": "Edimax",   "00:E0:4C": "Realtek",
        "00:1B:44": "SanDisk",
    }
    for oui, name in vendors.items():
        if prefix.startswith(oui):
            return name
    return "unknown"

# ── ARP scan ───────────────────────────────────────────────────────────────────

def arp_scan(network_prefix):
    """
    Use the system arp table + ping sweep to find all devices.
    No root needed on Mac for reading arp cache.
    """
    devices = {}
    log(f"ARP scanning {network_prefix}.0/24 ...")

    # First ping sweep to populate ARP cache (runs fast in parallel)
    threads = []
    def ping(ip):
        subprocess.run(
            ["ping", "-c", "1", "-W", "500", "-t", "1", ip],
            capture_output=True, timeout=2
        )

    for i in range(1, 255):
        ip = f"{network_prefix}.{i}"
        t = threading.Thread(target=ping, args=(ip,), daemon=True)
        threads.append(t)
        t.start()
        if len(threads) % 50 == 0:
            time.sleep(0.1)  # small throttle

    # Wait for pings to finish (max 4 seconds)
    for t in threads:
        t.join(timeout=4)

    # Now read the ARP cache
    try:
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True, text=True, timeout=10
        )
        # Parse: hostname (ip) at mac on interface
        pattern = re.compile(
            r"(\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]+)",
            re.IGNORECASE
        )
        for match in pattern.finditer(result.stdout):
            hostname, ip, mac = match.groups()
            if mac in ("(incomplete)", "ff:ff:ff:ff:ff:ff"):
                continue
            if not ip.startswith(network_prefix):
                continue
            devices[ip] = {
                "ip":       ip,
                "mac":      mac.lower(),
                "hostname": hostname if hostname != "?" else "unknown",
                "vendor":   mac_vendor_guess(mac),
            }
    except Exception as e:
        log(f"ARP scan error: {e}", "WARN")

    log(f"ARP scan found {len(devices)} device(s)")
    return devices

# ── Port scanner ───────────────────────────────────────────────────────────────

def scan_ports(ip, timeout=0.5):
    """Quick port scan — check interesting ports only."""
    open_ports = []
    for port, service in INTERESTING_PORTS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append({"port": port, "service": service})
            s.close()
        except Exception:
            pass
    return open_ports

# ── mDNS/Bonjour discovery ─────────────────────────────────────────────────────

def mdns_scan():
    """Use dns-sd (built into Mac) to discover Bonjour services."""
    services = []
    log("mDNS/Bonjour scan starting (5 seconds)...")
    try:
        # Browse for common service types
        for svc_type in ["_http._tcp", "_ssh._tcp", "_smb._tcp", "_ipp._tcp"]:
            result = subprocess.run(
                ["dns-sd", "-B", svc_type, "local."],
                capture_output=True, text=True, timeout=3
            )
            for line in result.stdout.splitlines():
                if "Add" in line or "Found" in line:
                    parts = line.split()
                    if len(parts) >= 7:
                        services.append({
                            "type":    svc_type,
                            "name":    parts[-1],
                            "domain":  "local"
                        })
    except Exception as e:
        log(f"mDNS scan note: {e}", "INFO")
    log(f"mDNS found {len(services)} service(s)")
    return services

# ── Bluetooth scan ─────────────────────────────────────────────────────────────

def bluetooth_scan():
    """Use system_profiler to list nearby Bluetooth devices (Mac built-in)."""
    devices = []
    log("Bluetooth scan starting...")
    try:
        result = subprocess.run(
            ["system_profiler", "SPBluetoothDataType", "-json"],
            capture_output=True, text=True, timeout=15
        )
        data = json.loads(result.stdout)
        bt_data = data.get("SPBluetoothDataType", [{}])[0]

        # Connected devices
        for section in ["device_connected", "device_not_connected",
                         "devices_list", "other_devices"]:
            section_data = bt_data.get(section, [])
            if isinstance(section_data, list):
                for item in section_data:
                    if isinstance(item, dict):
                        for name, info in item.items():
                            devices.append({
                                "name":    name,
                                "address": info.get("device_address", "unknown"),
                                "type":    info.get("device_minorType", "unknown"),
                                "connected": section == "device_connected"
                            })
    except Exception as e:
        log(f"Bluetooth scan note: {e}", "INFO")
    log(f"Bluetooth found {len(devices)} device(s)")
    return devices

# ── Threat scoring ─────────────────────────────────────────────────────────────

def score_device(device, open_ports):
    score = 0
    flags = []

    mac = device.get("mac", "")
    hostname = device.get("hostname", "").lower()
    vendor = device.get("vendor", "unknown")

    # Unknown device (not in trusted list)
    if mac and mac not in TRUSTED_DEVICES:
        score += 15
        flags.append("unknown_device")

    # Unknown vendor
    if vendor == "unknown":
        score += 10
        flags.append("unknown_vendor")

    # High risk ports open
    for p in open_ports:
        if p["port"] in HIGH_RISK_PORTS:
            score += 30
            flags.append(f"high_risk_port:{p['service']}")
        else:
            score += 5
            flags.append(f"open_port:{p['service']}")

    # Suspicious hostname patterns
    for pattern in ["hack", "pwn", "evil", "rogue", "kali", "parrot"]:
        if pattern in hostname:
            score += 50
            flags.append(f"suspicious_hostname:{pattern}")

    return score, flags

# ── Save + display ─────────────────────────────────────────────────────────────

def save_device(device, open_ports, score, flags):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.now().isoformat()

    # Check if device already known
    c.execute("SELECT id, scan_count FROM network_devices WHERE mac = ?",
              (device["mac"],))
    existing = c.fetchone()

    ports_json = json.dumps(open_ports)
    flags_json = json.dumps(flags)
    trusted    = 1 if device["mac"] in TRUSTED_DEVICES else 0

    if existing:
        c.execute("""
            UPDATE network_devices
            SET last_seen=?, ip=?, hostname=?, open_ports=?,
                threat_score=?, flags=?, scan_count=scan_count+1
            WHERE mac=?
        """, (now, device["ip"], device["hostname"],
              ports_json, score, flags_json, device["mac"]))
    else:
        c.execute("""
            INSERT INTO network_devices
            (first_seen, last_seen, ip, mac, hostname, vendor,
             open_ports, is_trusted, threat_score, flags)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        """, (now, now, device["ip"], device["mac"],
              device["hostname"], device["vendor"],
              ports_json, trusted, score, flags_json))
        # Log as new device event
        c.execute("""
            INSERT INTO signal_events
            (timestamp, event_type, ip, mac, details, score)
            VALUES (?,?,?,?,?,?)
        """, (now, "NEW_DEVICE", device["ip"], device["mac"],
              json.dumps(device), score))

    conn.commit()
    conn.close()

def print_device(device, open_ports, score, flags):
    trusted = device["mac"] in TRUSTED_DEVICES
    if score >= 50:
        col = "\033[91m"   # red
    elif score >= 20:
        col = "\033[93m"   # yellow
    else:
        col = "\033[92m"   # green
    reset = "\033[0m"
    trust_label = " [TRUSTED]" if trusted else " [UNKNOWN]"

    print(f"\n  {col}{'─'*50}{reset}")
    print(f"  {col}Device{reset}{trust_label}  score:{score}")
    print(f"  IP       : {device['ip']}")
    print(f"  MAC      : {device['mac']}")
    print(f"  Hostname : {device['hostname']}")
    print(f"  Vendor   : {device['vendor']}")
    if open_ports:
        port_str = ", ".join(f"{p['service']}({p['port']})" for p in open_ports)
        print(f"  Ports    : {port_str}")
    if flags:
        print(f"  Flags    : {', '.join(flags)}")

# ── Full scan ─────────────────────────────────────────────────────────────────

def run_full_scan():
    log("="*50)
    log("Layer 5 — Full network scan starting")
    log("="*50)

    local_ip = get_local_ip()
    prefix   = get_network_prefix(local_ip)
    log(f"Your IP: {local_ip} | Scanning: {prefix}.0/24")

    # ARP scan — find all devices
    devices = arp_scan(prefix)

    if not devices:
        log("No devices found. Are you on a network?", "WARN")
        return

    # Port scan each device in parallel
    log(f"Port scanning {len(devices)} device(s)...")
    results = []

    def scan_device(device):
        open_ports = scan_ports(device["ip"])
        score, flags = score_device(device, open_ports)
        save_device(device, open_ports, score, flags)
        results.append((device, open_ports, score, flags))

    threads = []
    for device in devices.values():
        t = threading.Thread(target=scan_device, args=(device,), daemon=True)
        threads.append(t)
        t.start()

    for t in threads:
        t.join(timeout=10)

    # Sort by score descending — highest risk first
    results.sort(key=lambda x: x[2], reverse=True)

    # Display results
    print(f"\n{'═'*55}")
    print(f"  NETWORK SCAN RESULTS — {len(results)} devices found")
    print(f"{'═'*55}")

    high_risk  = [r for r in results if r[2] >= 50]
    medium     = [r for r in results if 20 <= r[2] < 50]
    low        = [r for r in results if r[2] < 20]

    if high_risk:
        print(f"\n  \033[91m⚠ HIGH RISK ({len(high_risk)} device(s))\033[0m")
        for device, ports, score, flags in high_risk:
            print_device(device, ports, score, flags)

    if medium:
        print(f"\n  \033[93m⚡ MEDIUM RISK ({len(medium)} device(s))\033[0m")
        for device, ports, score, flags in medium:
            print_device(device, ports, score, flags)

    if low:
        print(f"\n  \033[92m✓ LOW RISK ({len(low)} device(s))\033[0m")
        for device, ports, score, flags in low[:5]:  # show max 5 clean
            print_device(device, ports, score, flags)
        if len(low) > 5:
            print(f"\n  ... and {len(low)-5} more clean devices")

    # Bluetooth
    bt_devices = bluetooth_scan()
    if bt_devices:
        print(f"\n{'─'*55}")
        print(f"  BLUETOOTH — {len(bt_devices)} device(s) detected")
        print(f"{'─'*55}")
        for bt in bt_devices:
            status = "CONNECTED" if bt.get("connected") else "nearby"
            print(f"  {bt['name']} | {bt['address']} | {bt['type']} | {status}")

    # mDNS services
    mdns = mdns_scan()
    if mdns:
        print(f"\n{'─'*55}")
        print(f"  mDNS SERVICES — {len(mdns)} found")
        print(f"{'─'*55}")
        for svc in mdns:
            print(f"  {svc['name']} | {svc['type']}")

    print(f"\n{'═'*55}")
    print(f"  Scan complete. Results saved to database.")
    log(f"Scan complete — {len(high_risk)} high risk, "
        f"{len(medium)} medium, {len(low)} low")

    return results

# ── Continuous monitoring ─────────────────────────────────────────────────────

def run_continuous(interval_minutes=5):
    """Run a full scan every N minutes. Alerts on new devices."""
    log(f"Continuous mode — scanning every {interval_minutes} minutes")
    log("Press Ctrl+C to stop")

    known_macs = set()

    # Load already-known devices
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT mac FROM network_devices")
        known_macs = {row[0] for row in c.fetchall()}
        conn.close()
    except Exception:
        pass

    while True:
        results = run_full_scan()
        if results:
            for device, ports, score, flags in results:
                mac = device["mac"]
                if mac not in known_macs:
                    log(f"NEW DEVICE on network: {device['ip']} "
                        f"({device['vendor']}) score:{score}", "ALERT")
                    known_macs.add(mac)

        log(f"Next scan in {interval_minutes} minutes...")
        time.sleep(interval_minutes * 60)

# ── Main ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    init_signal_db()

    if "--continuous" in sys.argv:
        run_continuous(interval_minutes=5)
    else:
        run_full_scan()