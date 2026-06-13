"""
A3 Security System — Layer 3: Sandbox Engine
Two-layer analysis: static (source code scan) + dynamic (runtime output).
"""

import subprocess, sqlite3, json, os, shutil, hashlib, time
from datetime import datetime
from pathlib import Path

BASE_DIR    = Path(__file__).parent.parent
DATA_DIR    = BASE_DIR / "data"
SANDBOX_DIR = BASE_DIR / "sandbox"
DB_PATH     = DATA_DIR / "a3_threats.db"

SANDBOX_DIR.mkdir(exist_ok=True)
(SANDBOX_DIR / "samples").mkdir(exist_ok=True)
(SANDBOX_DIR / "reports").mkdir(exist_ok=True)

SANDBOX_IMAGE   = "python:3.11-slim"
MAX_RUN_SECONDS = 15
MEMORY_LIMIT    = "64m"
CPU_LIMIT       = "0.5"

def init_sandbox_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS sandbox_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT, file_path TEXT, file_hash TEXT,
            container_id TEXT, run_duration REAL,
            stdout TEXT, stderr TEXT, exit_code INTEGER,
            verdict TEXT, threat_score INTEGER, behaviour_flags TEXT
        )
    """)
    conn.commit(); conn.close()

def log(message, level="INFO"):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] [SANDBOX] [{level}] {message}")

def hash_file(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""): h.update(chunk)
        return h.hexdigest()
    except Exception:
        return "unavailable"

def analyse_behaviour(stdout, stderr, exit_code, source_code=""):
    score = 0
    flags = []

    # ── Layer A: Static analysis — scan the source code itself ───────────────
    if source_code:
        src = source_code.lower()
        static = [
            ("import socket",       20, "static_imports_socket"),
            ("import subprocess",   30, "static_imports_subprocess"),
            ("os.system(",          35, "static_system_command"),
            ("subprocess.call(",    35, "static_subprocess_call"),
            ("subprocess.run(",     30, "static_subprocess_run"),
            ("subprocess.popen(",   40, "static_subprocess_popen"),
            ("exec(",               35, "static_code_exec"),
            ("eval(",               35, "static_dynamic_eval"),
            ("import base64",       20, "static_base64_import"),
            ("base64.b64decode",    25, "static_base64_decode"),
            ("/etc/passwd",         50, "static_sensitive_file"),
            ("/etc/shadow",         50, "static_sensitive_file"),
            ("rm -rf",              50, "static_destructive_cmd"),
            ("chmod(",              20, "static_permission_change"),
            ("keylog",              60, "static_keylogger"),
            ("ransom",              60, "static_ransomware"),
            ("reverse_shell",       70, "static_reverse_shell"),
            ("pty.spawn",           70, "static_shell_spawn"),
            (".connect((",          30, "static_socket_connect"),
            ("urllib.request",      20, "static_http_request"),
            ("requests.get(",       20, "static_http_get"),
            ("requests.post(",      25, "static_http_post"),
            ("shutil.rmtree",       40, "static_recursive_delete"),
            ("open('/etc",          45, "static_reads_etc"),
        ]
        for keyword, points, flag in static:
            if keyword in src:
                score += points
                flags.append(flag)

    # ── Layer B: Dynamic analysis — scan what the program printed ─────────────
    runtime = (stdout + stderr).lower()
    dynamic = [
        ("socket",      20, "runtime_socket_usage"),
        ("/etc/passwd", 50, "runtime_reads_sensitive"),
        ("rm -rf",      50, "runtime_destructive_cmd"),
        ("keylog",      60, "runtime_keylogger"),
        ("ransom",      60, "runtime_ransomware"),
    ]
    for keyword, points, flag in dynamic:
        if keyword in runtime:
            score += points
            flags.append(flag)

    if exit_code not in (0, 1):
        score += 10
        flags.append(f"unusual_exit_code:{exit_code}")

    return score, flags

def get_verdict(score):
    if score >= 60:   return "MALICIOUS"
    elif score >= 30: return "SUSPICIOUS"
    elif score > 0:   return "LOW_RISK"
    else:             return "CLEAN"

def pull_sandbox_image():
    log(f"Pulling sandbox image: {SANDBOX_IMAGE}")
    result = subprocess.run(["docker", "pull", SANDBOX_IMAGE], capture_output=True, text=True)
    if result.returncode == 0: log("Sandbox image ready")
    else: log(f"Failed to pull image: {result.stderr}", "ERROR")

def run_in_sandbox(file_path):
    file_path = Path(file_path)
    if not file_path.exists():
        log(f"File not found: {file_path}", "ERROR"); return None

    file_hash    = hash_file(file_path)
    container_id = f"a3_sandbox_{int(time.time())}"
    start_time   = time.time()

    # Read source code for static analysis
    try:
        source_code = file_path.read_text(errors="ignore")
    except Exception:
        source_code = ""

    log(f"Sandboxing: {file_path.name}")
    log(f"SHA256: {file_hash}")
    log(f"Container: {container_id}")
    
    # Check threat intelligence feeds before sandboxing
    try:
        from threat_feeds import check_hash, init_feeds_db
        init_feeds_db()
        feed_hit = check_hash(file_hash)
        if feed_hit:
            log(f"THREAT FEED HIT — known {feed_hit['malware']} ({feed_hit['source']})", "ALERT")
            return {
                "timestamp": datetime.now().isoformat(),
                "file": str(file_path), "hash": file_hash,
                "container": "feed_hit", "duration": 0,
                "exit_code": 0, "stdout": "", "stderr": "",
                "score": 200,
                "flags": [f"threat_feed:{feed_hit['source']}", f"malware:{feed_hit['malware']}"],
                "verdict": "MALICIOUS",
                "ml_verdict": "MALICIOUS", "ml_confidence": 1.0,
            }
    except Exception as e:
        log(f"Feed check skipped: {e}", "INFO")
        
    # Copy file to sandbox samples dir (skip if already there)
    sample_path = SANDBOX_DIR / "samples" / file_path.name
    if file_path.resolve() != sample_path.resolve():
        shutil.copy2(file_path, sample_path)

    cmd = [
        "docker", "run", "--rm",
        "--name", container_id,
        "--network", "none",
        f"--memory={MEMORY_LIMIT}",
        f"--cpus={CPU_LIMIT}",
        "--read-only",
        "--tmpfs", "/tmp:size=32m",
        "-v", f"{sample_path}:/sample/{file_path.name}:ro",
        SANDBOX_IMAGE,
        "python3", f"/sample/{file_path.name}"
    ]

    try:
        result    = subprocess.run(cmd, capture_output=True, text=True, timeout=MAX_RUN_SECONDS)
        duration  = time.time() - start_time
        stdout    = result.stdout[:5000]
        stderr    = result.stderr[:5000]
        exit_code = result.returncode
    except subprocess.TimeoutExpired:
        duration  = MAX_RUN_SECONDS
        stdout    = ""
        stderr    = f"[A3] Container killed after {MAX_RUN_SECONDS}s timeout"
        exit_code = -1
        log("Container timed out — killed", "WARN")
        subprocess.run(["docker", "rm", "-f", container_id], capture_output=True)
    except Exception as e:
        log(f"Sandbox error: {e}", "ERROR"); return None

    score, flags = analyse_behaviour(stdout, stderr, exit_code, source_code)
    verdict      = get_verdict(score)

    log(f"Run complete in {duration:.1f}s | exit:{exit_code} | score:{score} | verdict:{verdict}")

    # ML prediction — instant, no AI API needed
    ml_verdict, ml_confidence, ml_probs = None, 0, {}
    try:
        from ml_trainer import predict as ml_predict
        ml_verdict, ml_confidence, ml_probs = ml_predict(flags, score)
        if ml_verdict:
            log(f"ML prediction: {ml_verdict} ({ml_confidence:.0%} confidence)")
        severity = {"CLEAN": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}
        if ml_verdict and severity.get(ml_verdict, 0) > severity.get(verdict, 0):
            log(f"ML upgraded verdict: {verdict} → {ml_verdict}", "WARN")
            verdict = ml_verdict
    except Exception as e:
        log(f"ML prediction skipped: {e}", "INFO")

    report = {
        "timestamp": datetime.now().isoformat(), "file": str(file_path),
        "hash": file_hash, "container": container_id,
        "duration": round(duration, 2), "exit_code": exit_code,
        "stdout": stdout, "stderr": stderr,
        "score": score, "flags": flags, "verdict": verdict,
        "ml_verdict": ml_verdict, "ml_confidence": round(ml_confidence, 3),
    }

    report_path = SANDBOX_DIR / "reports" / f"{container_id}.json"
    with open(report_path, "w") as f: json.dump(report, f, indent=2)
    log(f"Report saved: {report_path}")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT INTO sandbox_reports
        (timestamp, file_path, file_hash, container_id, run_duration,
         stdout, stderr, exit_code, verdict, threat_score, behaviour_flags)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
    """, (report["timestamp"], str(file_path), file_hash, container_id,
          report["duration"], stdout, stderr, exit_code, verdict,
          score, json.dumps(flags)))
    conn.commit(); conn.close()

    colours = {"MALICIOUS":"\033[91m","SUSPICIOUS":"\033[93m","LOW_RISK":"\033[94m","CLEAN":"\033[92m"}
    reset = "\033[0m"
    col   = colours.get(verdict, "")
    print(f"\n{'='*55}")
    print(f"  {col}VERDICT: {verdict}{reset}  (score: {score})")
    print(f"  File   : {file_path.name}")
    print(f"  Hash   : {file_hash[:20]}...")
    if flags: print(f"  Flags  : {', '.join(flags)}")
    print(f"{'='*55}\n")
    return report

def create_test_samples():
    samples_dir = SANDBOX_DIR / "samples"

    clean = samples_dir / "test_clean.py"
    clean.write_text('print("Hello, I am a clean program.")\nprint(2 + 2)\n')

    suspicious = samples_dir / "test_suspicious.py"
    suspicious.write_text('import socket\nimport subprocess\nprint("testing")\n')

    risky = samples_dir / "test_risky.py"
    risky.write_text(
        'import base64\nimport subprocess\nimport os\n'
        'cmd = base64.b64decode("ZWNobyBoYWNrZWQ=").decode()\n'
        'print(f"Running: {cmd}")\nos.system(cmd)\n'
    )
    log("Test samples created in sandbox/samples/")
    return clean, suspicious, risky

if __name__ == "__main__":
    import sys
    init_sandbox_db()
    pull_sandbox_image()

    if len(sys.argv) > 1:
        run_in_sandbox(sys.argv[1])
    else:
        log("No file specified — running test samples")
        clean, suspicious, risky = create_test_samples()
        print("\n--- Test 1: Clean file ---")
        run_in_sandbox(clean)
        print("\n--- Test 2: Suspicious file ---")
        run_in_sandbox(suspicious)
        print("\n--- Test 3: High-risk file ---")
        run_in_sandbox(risky)