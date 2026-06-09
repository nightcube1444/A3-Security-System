"""
A3 Security System — ML Layer
Trains a threat classifier on sandbox behaviour data.
Uses synthetic training data + real collected samples.
Gets smarter every time new threats are sandboxed.
"""

import sqlite3
import json
import pickle
import numpy as np
from datetime import datetime
from pathlib import Path

BASE_DIR   = Path(__file__).parent.parent
DATA_DIR   = BASE_DIR / "data"
DB_PATH    = DATA_DIR / "a3_threats.db"
MODEL_PATH = DATA_DIR / "a3_classifier.pkl"
SCALER_PATH= DATA_DIR / "a3_scaler.pkl"

# ── All possible behaviour flags (feature vocabulary) ─────────────────────────
ALL_FLAGS = [
    # Static analysis flags
    "static_imports_socket", "static_imports_subprocess", "static_system_command",
    "static_subprocess_call", "static_subprocess_run", "static_subprocess_popen",
    "static_code_exec", "static_dynamic_eval", "static_base64_import",
    "static_base64_decode", "static_sensitive_file", "static_destructive_cmd",
    "static_permission_change", "static_keylogger", "static_ransomware",
    "static_reverse_shell", "static_shell_spawn", "static_socket_connect",
    "static_http_request", "static_http_get", "static_http_post",
    "static_recursive_delete", "static_reads_etc",
    # Runtime analysis flags
    "runtime_socket_usage", "runtime_network_connect", "runtime_http_library",
    "runtime_reads_sensitive", "runtime_destructive_cmd",
    "runtime_keylogger", "runtime_ransomware",
    # Exit code flags
    "unusual_exit_code:-1",
]

VERDICT_MAP = {"CLEAN": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}
VERDICT_NAMES = {0: "CLEAN", 1: "SUSPICIOUS", 2: "MALICIOUS"}

def log(msg, level="INFO"):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    colours = {"INFO":"\033[97m","OK":"\033[92m","WARN":"\033[93m","ERROR":"\033[91m"}
    print(f"[{ts}] {colours.get(level,'')}[ML][{level}]\033[0m {msg}")

# ── Feature extraction ────────────────────────────────────────────────────────

def flags_to_vector(flags, score):
    """Convert a list of behaviour flags + score into a feature vector."""
    vec = []
    # One-hot encode each known flag
    for f in ALL_FLAGS:
        vec.append(1 if f in flags else 0)
    # Add numeric features
    vec.append(min(score, 200) / 200.0)          # normalised score
    vec.append(len(flags))                         # total flag count
    vec.append(sum(1 for f in flags if "static" in f))   # static flag count
    vec.append(sum(1 for f in flags if "runtime" in f))  # runtime flag count
    vec.append(sum(1 for f in flags if "keylogger" in f or
                   "ransomware" in f or "reverse_shell" in f))  # critical flags
    return vec

# ── Synthetic training data ───────────────────────────────────────────────────

def generate_synthetic_data():
    """
    Generate realistic synthetic training samples.
    Based on real malware behaviour patterns.
    """
    samples = []  # (flags, score, verdict)

    # ── CLEAN samples ─────────────────────────────────────────────────────────
    clean_patterns = [
        ([], 0),
        ([], 0),
        ([], 0),
        (["static_http_get"], 20),
        (["static_imports_socket"], 20),
        (["static_http_request"], 20),
        (["static_imports_subprocess"], 30),
        (["static_imports_socket", "static_http_get"], 35),
        ([], 0),
        ([], 0),
        ([], 0),
        (["static_imports_subprocess"], 30),
        ([], 0),
        (["static_http_request", "static_http_get"], 35),
        ([], 0),
    ]
    for flags, score in clean_patterns:
        samples.append((flags, score, "CLEAN"))

    # ── SUSPICIOUS samples ────────────────────────────────────────────────────
    suspicious_patterns = [
        (["static_imports_socket", "static_imports_subprocess"], 50),
        (["static_imports_subprocess", "static_system_command"], 65),
        (["static_base64_import", "static_imports_subprocess"], 50),
        (["static_imports_socket", "static_socket_connect"], 50),
        (["static_subprocess_run", "static_system_command"], 65),
        (["static_base64_decode", "static_imports_subprocess"], 55),
        (["static_imports_socket", "static_http_post"], 40),
        (["static_subprocess_popen", "static_imports_socket"], 70),
        (["static_dynamic_eval", "static_base64_decode"], 60),
        (["static_code_exec", "static_imports_subprocess"], 65),
        (["runtime_socket_usage", "static_imports_socket"], 40),
        (["static_imports_subprocess", "static_http_post"], 45),
        (["static_base64_import", "static_socket_connect"], 50),
        (["static_subprocess_call", "static_imports_socket"], 65),
        (["static_dynamic_eval", "static_imports_subprocess"], 65),
    ]
    for flags, score in suspicious_patterns:
        samples.append((flags, score, "SUSPICIOUS"))

    # ── MALICIOUS samples ─────────────────────────────────────────────────────
    malicious_patterns = [
        # Ransomware
        (["static_ransomware", "static_recursive_delete", "static_imports_subprocess"], 170),
        (["static_ransomware", "static_base64_decode", "static_system_command"], 155),
        (["static_ransomware", "runtime_ransomware", "static_recursive_delete"], 180),
        (["static_ransomware", "static_permission_change", "static_imports_subprocess"], 150),
        # Keylogger
        (["static_keylogger", "static_imports_socket", "static_socket_connect"], 140),
        (["static_keylogger", "static_http_post", "runtime_keylogger"], 160),
        (["static_keylogger", "static_base64_encode", "static_imports_subprocess"], 130),
        # Reverse shell
        (["static_reverse_shell", "static_shell_spawn", "static_imports_socket"], 170),
        (["static_reverse_shell", "static_subprocess_popen", "static_socket_connect"], 165),
        (["static_shell_spawn", "static_imports_socket", "static_system_command"], 140),
        # Trojan/dropper
        (["static_imports_subprocess", "static_system_command",
          "static_base64_decode", "static_destructive_cmd"], 120),
        (["static_code_exec", "static_dynamic_eval",
          "static_base64_decode", "static_system_command"], 130),
        (["static_reads_etc", "static_sensitive_file",
          "runtime_reads_sensitive", "static_imports_subprocess"], 125),
        # Worm/propagation
        (["static_imports_socket", "static_socket_connect",
          "static_subprocess_run", "static_http_post"], 110),
        (["static_imports_socket", "static_http_post",
          "static_imports_subprocess", "static_system_command"], 105),
        # Destructive
        (["static_recursive_delete", "static_destructive_cmd",
          "static_permission_change"], 120),
        (["static_destructive_cmd", "static_system_command",
          "unusual_exit_code:-1", "static_imports_subprocess"], 115),
        # Data exfiltration
        (["static_reads_etc", "static_sensitive_file",
          "static_http_post", "static_imports_socket"], 120),
        (["static_reads_etc", "runtime_reads_sensitive",
          "static_http_post", "static_socket_connect"], 125),
        # Combined high-risk
        (["static_imports_subprocess", "static_system_command",
          "static_base64_import", "static_base64_decode",
          "static_dynamic_eval"], 130),
    ]
    for flags, score in malicious_patterns:
        samples.append((flags, score, "MALICIOUS"))

    log(f"Generated {len(samples)} synthetic samples "
        f"({sum(1 for s in samples if s[2]=='CLEAN')} clean, "
        f"{sum(1 for s in samples if s[2]=='SUSPICIOUS')} suspicious, "
        f"{sum(1 for s in samples if s[2]=='MALICIOUS')} malicious)")
    return samples

# ── Load real data from DB ─────────────────────────────────────────────────────

def load_real_data():
    """Load real sandbox reports from the database."""
    samples = []
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            SELECT behaviour_flags, threat_score, verdict
            FROM sandbox_reports
            WHERE verdict IN ('CLEAN','SUSPICIOUS','MALICIOUS')
        """)
        for flags_json, score, verdict in c.fetchall():
            flags = json.loads(flags_json) if flags_json else []
            samples.append((flags, score, verdict))
        conn.close()
        log(f"Loaded {len(samples)} real samples from database")
    except Exception as e:
        log(f"Could not load real data: {e}", "WARN")
    return samples

# ── Train model ───────────────────────────────────────────────────────────────

def train():
    try:
        from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
        from sklearn.preprocessing import StandardScaler
        from sklearn.model_selection import cross_val_score
        from sklearn.metrics import classification_report
    except ImportError:
        log("scikit-learn not installed. Run: pip install scikit-learn", "ERROR")
        return False

    log("Starting ML training...")

    # Combine synthetic + real data
    synthetic = generate_synthetic_data()
    real      = load_real_data()
    all_data  = synthetic + real
    log(f"Total training samples: {len(all_data)}")

    # Build feature matrix
    X, y = [], []
    for flags, score, verdict in all_data:
        if verdict not in VERDICT_MAP:
            continue
        X.append(flags_to_vector(flags, score))
        y.append(VERDICT_MAP[verdict])

    X = np.array(X)
    y = np.array(y)

    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Train Random Forest
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        class_weight="balanced"
    )
    model.fit(X_scaled, y)

    # Cross-validation score
    scores = cross_val_score(model, X_scaled, y, cv=3, scoring="accuracy")
    log(f"Cross-validation accuracy: {scores.mean():.1%} (+/- {scores.std():.1%})", "OK")

    # Save model and scaler
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)
    with open(SCALER_PATH, "wb") as f:
        pickle.dump(scaler, f)

    log(f"Model saved to {MODEL_PATH}", "OK")
    log(f"Scaler saved to {SCALER_PATH}", "OK")

    # Feature importance
    feature_names = ALL_FLAGS + ["norm_score","flag_count",
                                  "static_count","runtime_count","critical_count"]
    importances = model.feature_importances_
    top = sorted(zip(feature_names, importances), key=lambda x: x[1], reverse=True)[:8]
    log("Top 8 most important features:")
    for name, imp in top:
        bar = "█" * int(imp * 40)
        print(f"    {name:<40} {bar} {imp:.3f}")

    return True

# ── Predict ───────────────────────────────────────────────────────────────────

def predict(flags, score):
    """
    Predict threat verdict for a file given its behaviour flags and score.
    Returns (verdict, confidence, probabilities)
    """
    if not MODEL_PATH.exists():
        return None, 0, {}

    try:
        with open(MODEL_PATH, "rb") as f:
            model = pickle.load(f)
        with open(SCALER_PATH, "rb") as f:
            scaler = pickle.load(f)

        vec     = np.array([flags_to_vector(flags, score)])
        vec_s   = scaler.transform(vec)
        pred    = model.predict(vec_s)[0]
        proba   = model.predict_proba(vec_s)[0]
        verdict = VERDICT_NAMES[pred]
        confidence = float(proba[pred])

        probs = {VERDICT_NAMES[i]: float(p) for i, p in enumerate(proba)}
        return verdict, confidence, probs

    except Exception as e:
        log(f"Prediction error: {e}", "WARN")
        return None, 0, {}

# ── Retrain on new data ───────────────────────────────────────────────────────

def retrain_if_new_data(min_new_samples=5):
    """
    Check if enough new sandbox data has been collected since last training.
    If yes, retrain automatically.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM sandbox_reports")
        total = c.fetchone()[0]
        conn.close()

        # Retrain if we have new data
        if MODEL_PATH.exists():
            model_age = datetime.now().timestamp() - MODEL_PATH.stat().st_mtime
            if model_age < 3600 and total < min_new_samples:
                log("Model is recent and no significant new data — skipping retrain")
                return False

        log(f"Retraining with {total} total sandbox reports...")
        return train()

    except Exception as e:
        log(f"Retrain check error: {e}", "WARN")
        return False

# ── Test the model ────────────────────────────────────────────────────────────

def test_model():
    """Run a few test predictions to verify the model works."""
    print(f"\n{'─'*55}")
    print("  ML MODEL TEST PREDICTIONS")
    print(f"{'─'*55}")

    tests = [
        ([], 0, "Expected: CLEAN"),
        (["static_imports_socket", "static_imports_subprocess"], 50,
         "Expected: SUSPICIOUS"),
        (["static_imports_subprocess", "static_system_command",
          "static_base64_decode", "static_dynamic_eval"], 130,
         "Expected: MALICIOUS"),
        (["static_ransomware", "static_recursive_delete"], 170,
         "Expected: MALICIOUS"),
        (["static_keylogger", "static_imports_socket"], 140,
         "Expected: MALICIOUS"),
    ]

    for flags, score, expected in tests:
        verdict, confidence, probs = predict(flags, score)
        col = "\033[92m" if "CLEAN" in verdict else \
              "\033[93m" if "SUSPICIOUS" in verdict else "\033[91m"
        print(f"\n  {col}{verdict}\033[0m ({confidence:.0%} confidence)")
        print(f"  Flags : {flags[:3]}")
        print(f"  Score : {score}")
        print(f"  Note  : {expected}")
        print(f"  Probs : clean={probs.get('CLEAN',0):.0%} "
              f"suspicious={probs.get('SUSPICIOUS',0):.0%} "
              f"malicious={probs.get('MALICIOUS',0):.0%}")

    print(f"\n{'─'*55}\n")

# ── Main ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    if "--retrain" in sys.argv:
        retrain_if_new_data()
    else:
        success = train()
        if success:
            test_model()