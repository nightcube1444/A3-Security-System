from pathlib import Path
import sqlite3
import importlib.util

BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "a3_threats.db"

REQUIRED_FILES = [
    "core/api.py",
    "core/monitor.py",
    "core/risk_engine.py",
    "core/baseline_engine.py",
    "core/incident_engine.py",
    "core/communication_agent.py",
    "dashboard/src/App.jsx",
    "requirements.txt",
]

REQUIRED_TABLES = [
    "process_events",
    "file_events",
    "sandbox_reports",
    "ai_assessments",
    "incidents",
    "baseline_anomalies",
    "baseline_observations",
    "baseline_profiles",
]


def check_file(path):
    full_path = BASE_DIR / path
    return full_path.exists()


def check_python_import(path):
    try:
        full_path = BASE_DIR / path
        module_name = path.replace("/", ".").replace(".py", "")
        spec = importlib.util.spec_from_file_location(module_name, full_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return True, "OK"
    except Exception as e:
        return False, str(e)


def check_database():
    result = {
        "exists": DB_PATH.exists(),
        "tables": {},
    }

    if not DB_PATH.exists():
        return result

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    for table in REQUIRED_TABLES:
        try:
            cur.execute(f"SELECT COUNT(*) FROM {table}")
            count = cur.fetchone()[0]
            result["tables"][table] = {
                "exists": True,
                "count": count,
            }
        except Exception as e:
            result["tables"][table] = {
                "exists": False,
                "error": str(e),
            }

    conn.close()
    return result


def run_health_check():
    print("\n==============================")
    print(" A3 SYSTEM HEALTH CHECK")
    print("==============================\n")

    print("[1] Required files")
    for file in REQUIRED_FILES:
        status = "OK" if check_file(file) else "MISSING"
        print(f" {status:8} {file}")

    print("\n[2] Python module imports")
    for file in REQUIRED_FILES:
        if file.endswith(".py"):
            ok, msg = check_python_import(file)
            status = "OK" if ok else "ERROR"
            print(f" {status:8} {file} -> {msg}")

    print("\n[3] Database")
    db = check_database()
    print(f" DB exists: {db['exists']}")

    if db["exists"]:
        for table, info in db["tables"].items():
            if info["exists"]:
                print(f" OK       {table} ({info['count']} rows)")
            else:
                print(f" MISSING  {table} -> {info['error']}")

    print("\nHealth check complete.\n")


if __name__ == "__main__":
    run_health_check()