"""
A3 Security System — Telegram Alert Bot
Sends instant alerts to your phone when A3 detects threats.
No internet required for A3 itself — only the alert goes out.

Alerts sent for:
  - MALICIOUS file detected
  - New unknown device on network
  - High risk network device
  - Blockchain tampered
  - System startup/shutdown
"""

import urllib.request
import urllib.parse
import json
import os
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent

# ── Load credentials from .env ────────────────────────────────────────────────

def load_env():
    env_path = BASE_DIR / ".env"
    config = {}
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                key, val = line.split("=", 1)
                config[key.strip()] = val.strip()
    # Also check environment variables
    config["TELEGRAM_TOKEN"]   = config.get("TELEGRAM_TOKEN")   or os.environ.get("TELEGRAM_TOKEN", "")
    config["TELEGRAM_CHAT_ID"] = config.get("TELEGRAM_CHAT_ID") or os.environ.get("TELEGRAM_CHAT_ID", "")
    return config

CONFIG = load_env()

def log(message, level="INFO"):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    colours = {"INFO":"\033[97m","OK":"\033[92m","WARN":"\033[93m","ERROR":"\033[91m"}
    print(f"[{ts}] {colours.get(level,'')}[TELEGRAM][{level}]\033[0m {message}")

# ── Send message ──────────────────────────────────────────────────────────────

def send(message, parse_mode="HTML"):
    """Send a message to your Telegram chat."""
    token   = CONFIG.get("TELEGRAM_TOKEN", "")
    chat_id = CONFIG.get("TELEGRAM_CHAT_ID", "")

    if not token or not chat_id:
        log("Telegram not configured — check .env file", "WARN")
        return False

    url  = f"https://api.telegram.org/bot{token}/sendMessage"
    data = json.dumps({
        "chat_id":    chat_id,
        "text":       message,
        "parse_mode": parse_mode
    }).encode("utf-8")

    try:
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode())
            if result.get("ok"):
                log("Alert sent ✓", "OK")
                return True
            else:
                log(f"Send failed: {result}", "WARN")
                return False
    except Exception as e:
        log(f"Send error: {e}", "WARN")
        return False

# ── Alert templates ───────────────────────────────────────────────────────────

def alert_malicious_file(file_name, verdict, threat_type,
                          score, flags, action):
    """Alert when a malicious file is detected."""
    flag_str = "\n".join(f"  • {f}" for f in flags[:5]) if flags else "  • none"
    emoji = "🚨" if verdict == "MALICIOUS" else "⚠️"

    msg = (
        f"{emoji} <b>A3 THREAT DETECTED</b>\n\n"
        f"<b>File</b>: <code>{file_name}</code>\n"
        f"<b>Verdict</b>: {verdict}\n"
        f"<b>Type</b>: {threat_type.upper()}\n"
        f"<b>Score</b>: {score}/200\n"
        f"<b>Action</b>: {action.upper()}\n\n"
        f"<b>Flags</b>:\n{flag_str}\n\n"
        f"<i>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>"
    )
    return send(msg)

def alert_new_device(ip, mac, vendor, score, flags):
    """Alert when an unknown device joins the network."""
    flag_str = ", ".join(flags[:3]) if flags else "none"
    emoji = "🔴" if score >= 50 else "🟡"

    msg = (
        f"{emoji} <b>NEW NETWORK DEVICE</b>\n\n"
        f"<b>IP</b>: <code>{ip}</code>\n"
        f"<b>MAC</b>: <code>{mac}</code>\n"
        f"<b>Vendor</b>: {vendor}\n"
        f"<b>Risk Score</b>: {score}\n"
        f"<b>Flags</b>: {flag_str}\n\n"
        f"<i>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>"
    )
    return send(msg)

def alert_blockchain_tamper(block_index, error):
    """Alert when blockchain tampering is detected."""
    msg = (
        f"🔐 <b>BLOCKCHAIN TAMPERED</b>\n\n"
        f"<b>Block</b>: #{block_index}\n"
        f"<b>Error</b>: {error}\n\n"
        f"⚠️ Evidence may have been altered.\n"
        f"Check A3 immediately.\n\n"
        f"<i>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>"
    )
    return send(msg)

def alert_threat_feed_hit(file_name, malware, source):
    """Alert when a file matches a known threat feed entry."""
    msg = (
        f"🚨 <b>KNOWN MALWARE DETECTED</b>\n\n"
        f"<b>File</b>: <code>{file_name}</code>\n"
        f"<b>Malware</b>: {malware}\n"
        f"<b>Source</b>: {source}\n\n"
        f"File hash matched threat intelligence database.\n"
        f"Sandbox skipped — instant verdict.\n\n"
        f"<i>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>"
    )
    return send(msg)

def alert_high_risk_process(pid, name, score, flags):
    """Alert when a high-risk process is detected."""
    flag_str = ", ".join(flags[:3]) if flags else "none"
    msg = (
        f"⚠️ <b>SUSPICIOUS PROCESS</b>\n\n"
        f"<b>Name</b>: <code>{name}</code>\n"
        f"<b>PID</b>: {pid}\n"
        f"<b>Score</b>: {score}\n"
        f"<b>Flags</b>: {flag_str}\n\n"
        f"<i>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>"
    )
    return send(msg)

def alert_startup():
    """Alert when A3 starts up."""
    import socket
    hostname = socket.gethostname()
    msg = (
        f"✅ <b>A3 SECURITY SYSTEM ONLINE</b>\n\n"
        f"<b>Host</b>: {hostname}\n"
        f"<b>Time</b>: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        f"All layers active. Watching your system."
    )
    return send(msg)

def alert_weekly_report(processes, sandboxed, malicious, devices):
    """Send weekly summary report."""
    msg = (
        f"📊 <b>A3 WEEKLY REPORT</b>\n\n"
        f"<b>Processes scanned</b>: {processes}\n"
        f"<b>Files sandboxed</b>: {sandboxed}\n"
        f"<b>Malicious found</b>: {malicious}\n"
        f"<b>Network devices</b>: {devices}\n\n"
        f"<i>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>"
    )
    return send(msg)

# ── Test ──────────────────────────────────────────────────────────────────────

def test():
    """Send a test message to verify the bot is working."""
    log("Sending test message...")
    return send(
        "🤖 <b>A3 Security System</b>\n\n"
        "Test message — bot is configured correctly.\n\n"
        f"<i>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>"
    )

# ── Main ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    if "--test" in sys.argv:
        success = test()
        if not success:
            print("\nCheck your .env file has correct TELEGRAM_TOKEN and TELEGRAM_CHAT_ID\n")
    else:
        test()