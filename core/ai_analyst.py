"""
A3 Security System — Layer 4: AI Analysis Engine
The brain. Takes sandbox reports from Layer 3, sends them to
local Llama3 via Ollama, gets a detailed threat assessment,
and stores everything in the database.
"""

import json
import sqlite3
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).parent.parent
DATA_DIR    = BASE_DIR / "data"
SANDBOX_DIR = BASE_DIR / "sandbox"
DB_PATH     = DATA_DIR / "a3_threats.db"

# ── Ollama config ─────────────────────────────────────────────────────────────
OLLAMA_URL   = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3"

# ── Database ───────────────────────────────────────────────────────────────────

def init_ai_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS ai_assessments (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp         TEXT,
            sandbox_report_id INTEGER,
            file_path         TEXT,
            file_hash         TEXT,
            verdict           TEXT,
            threat_score      INTEGER,
            threat_type       TEXT,
            threat_family     TEXT,
            confidence        TEXT,
            what_it_does      TEXT,
            why_dangerous     TEXT,
            recommended_action TEXT,
            indicators        TEXT,
            raw_response      TEXT
        )
    """)
    conn.commit()
    conn.close()

def log(message, level="INFO"):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] [AI] [{level}] {message}")

# ── Ollama call ────────────────────────────────────────────────────────────────

def ask_ollama(prompt):
    """Send a prompt to local Ollama and return the response text."""
    payload = json.dumps({
        "model":  OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.1,   # low temp = consistent, factual responses
            "num_predict": 800,
        }
    }).encode("utf-8")

    req = urllib.request.Request(
        OLLAMA_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("response", "").strip()
    except urllib.error.URLError as e:
        log(f"Cannot reach Ollama — is it running? ({e})", "ERROR")
        return None
    except Exception as e:
        log(f"Ollama error: {e}", "ERROR")
        return None

# ── Prompt builder ─────────────────────────────────────────────────────────────

def build_prompt(report):
    """
    Build a structured prompt from a sandbox report.
    We tell the AI exactly what format to respond in so we can parse it.
    """
    flags     = report.get("flags", [])
    verdict   = report.get("verdict", "UNKNOWN")
    score     = report.get("score", 0)
    stdout    = report.get("stdout", "")[:500]
    stderr    = report.get("stderr", "")[:300]
    file_name = Path(report.get("file", "unknown")).name

    prompt = f"""You are a cybersecurity analyst AI inside an endpoint detection system called A3.
You have just received a sandbox analysis report for a suspicious file.
Analyse it and respond ONLY with a JSON object — no extra text, no markdown, no explanation outside the JSON.

SANDBOX REPORT:
- File: {file_name}
- Verdict: {verdict}
- Threat Score: {score}/200
- Behaviour Flags: {', '.join(flags) if flags else 'none'}
- Runtime Output: {stdout if stdout else 'none'}
- Runtime Errors: {stderr if stderr else 'none'}

Respond with ONLY this JSON structure:
{{
  "threat_type": "one of: ransomware / spyware / trojan / backdoor / dropper / coinminer / worm / adware / benign / unknown",
  "threat_family": "specific malware family name if known, or 'unknown'",
  "confidence": "one of: high / medium / low",
  "what_it_does": "one sentence describing what this file does",
  "why_dangerous": "one sentence explaining why this is dangerous, or 'not dangerous' if benign",
  "recommended_action": "one of: quarantine / delete / monitor / allow",
  "indicators": ["list", "of", "key", "suspicious", "indicators", "found"]
}}"""

    return prompt

# ── Response parser ────────────────────────────────────────────────────────────

def parse_response(raw):
    """Extract the JSON from the AI response."""
    if not raw:
        return None
    try:
        # Find the first { and last } to extract JSON cleanly
        start = raw.find("{")
        end   = raw.rfind("}") + 1
        if start == -1 or end == 0:
            return None
        json_str = raw[start:end]
        return json.loads(json_str)
    except json.JSONDecodeError as e:
        log(f"Could not parse AI response as JSON: {e}", "WARN")
        return None

# ── Core analysis function ─────────────────────────────────────────────────────

def analyse_report(report, sandbox_report_id=None):
    """
    Run AI analysis on a sandbox report dict.
    Returns the parsed assessment or None on failure.
    """
    file_name = Path(report.get("file", "unknown")).name
    log(f"Analysing: {file_name} (score:{report.get('score',0)} verdict:{report.get('verdict','?')})")

    prompt   = build_prompt(report)
    log("Sending to Llama3...")
    raw      = ask_ollama(prompt)

    if not raw:
        log("No response from Ollama", "ERROR")
        return None

    parsed = parse_response(raw)

    if not parsed:
        log("Could not parse AI response — saving raw text", "WARN")
        parsed = {
            "threat_type":         "unknown",
            "threat_family":       "unknown",
            "confidence":          "low",
            "what_it_does":        "Analysis failed — see raw response",
            "why_dangerous":       "unknown",
            "recommended_action":  "monitor",
            "indicators":          []
        }

    # Print the assessment clearly
    action_colours = {
        "quarantine": "\033[91m",  # red
        "delete":     "\033[91m",  # red
        "monitor":    "\033[93m",  # yellow
        "allow":      "\033[92m",  # green
    }
    reset = "\033[0m"
    col   = action_colours.get(parsed.get("recommended_action", ""), "")

    print(f"\n{'─'*55}")
    print(f"  AI ASSESSMENT — {file_name}")
    print(f"{'─'*55}")
    print(f"  Type       : {parsed.get('threat_type', '?').upper()}")
    print(f"  Family     : {parsed.get('threat_family', '?')}")
    print(f"  Confidence : {parsed.get('confidence', '?').upper()}")
    print(f"  Does       : {parsed.get('what_it_does', '?')}")
    print(f"  Danger     : {parsed.get('why_dangerous', '?')}")
    print(f"  Action     : {col}{parsed.get('recommended_action', '?').upper()}{reset}")
    indicators = parsed.get("indicators", [])
    if indicators:
        print(f"  Indicators : {', '.join(indicators)}")
    print(f"{'─'*55}\n")

    # Save to database
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT INTO ai_assessments
        (timestamp, sandbox_report_id, file_path, file_hash,
         verdict, threat_score, threat_type, threat_family,
         confidence, what_it_does, why_dangerous, recommended_action,
         indicators, raw_response)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        datetime.now().isoformat(),
        sandbox_report_id,
        report.get("file", ""),
        report.get("hash", ""),
        report.get("verdict", ""),
        report.get("score", 0),
        parsed.get("threat_type", "unknown"),
        parsed.get("threat_family", "unknown"),
        parsed.get("confidence", "low"),
        parsed.get("what_it_does", ""),
        parsed.get("why_dangerous", ""),
        parsed.get("recommended_action", "monitor"),
        json.dumps(parsed.get("indicators", [])),
        raw
    ))
    conn.commit()
    conn.close()
    log(f"Assessment saved to database")

    return parsed

# ── Analyse all unanalysed sandbox reports ─────────────────────────────────────

def analyse_pending():
    """
    Find all sandbox reports that haven't been AI-analysed yet and analyse them.
    This lets you run Layer 4 after Layer 3 and catch up on any queued reports.
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Get sandbox reports not yet in ai_assessments
    c.execute("""
        SELECT sr.id, sr.file_path, sr.file_hash, sr.verdict,
               sr.threat_score, sr.behaviour_flags, sr.stdout, sr.stderr
        FROM sandbox_reports sr
        LEFT JOIN ai_assessments aa ON sr.id = aa.sandbox_report_id
        WHERE aa.id IS NULL
        ORDER BY sr.id DESC
    """)
    pending = c.fetchall()
    conn.close()

    if not pending:
        log("No pending sandbox reports to analyse")
        return

    log(f"Found {len(pending)} unanalysed sandbox report(s)")

    for row in pending:
        sr_id, file_path, file_hash, verdict, score, flags_json, stdout, stderr = row
        flags = json.loads(flags_json) if flags_json else []

        report = {
            "file":    file_path,
            "hash":    file_hash,
            "verdict": verdict,
            "score":   score,
            "flags":   flags,
            "stdout":  stdout or "",
            "stderr":  stderr or "",
        }
        analyse_report(report, sandbox_report_id=sr_id)

# ── Analyse a report JSON file directly ───────────────────────────────────────

def analyse_json_file(json_path):
    """Analyse a sandbox report JSON file from sandbox/reports/"""
    try:
        with open(json_path) as f:
            report = json.load(f)
        analyse_report(report)
    except Exception as e:
        log(f"Could not read report file: {e}", "ERROR")

# ── Main ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    init_ai_db()

    # Check Ollama is reachable
    log("Checking Ollama connection...")
    test = ask_ollama("Reply with only the word: ready")
    if not test:
        log("Ollama is not running. Start it with: ollama serve", "ERROR")
        sys.exit(1)
    log(f"Ollama connected — model: {OLLAMA_MODEL}")

    if len(sys.argv) > 1:
        # Analyse a specific JSON report file
        analyse_json_file(sys.argv[1])
    else:
        # Analyse all pending sandbox reports from the database
        analyse_pending()