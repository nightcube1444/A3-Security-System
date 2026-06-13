"""
A3 Security System — Communication Agent

Reads A3 system outputs and generates a clear briefing:
- experiment lab status
- latest threat ledger entries
- database summary
- recommendations

This makes A3 "talk back" to you.
"""

import json
import sqlite3
from pathlib import Path
from datetime import datetime


BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"

DB_PATH = DATA_DIR / "a3_threats.db"
CHAIN_PATH = DATA_DIR / "a3_chain.json"
EXPERIMENT_DIR = DATA_DIR / "experiment_reports"


def load_latest_experiment_report():
    if not EXPERIMENT_DIR.exists():
        return None

    reports = list(EXPERIMENT_DIR.glob("experiment_report_*.json"))

    if not reports:
        return None

    latest = max(reports, key=lambda p: p.stat().st_mtime)

    try:
        with open(latest, "r") as f:
            data = json.load(f)
        data["_file"] = str(latest)
        return data
    except Exception:
        return None


def load_threat_chain(limit=5):
    if not CHAIN_PATH.exists():
        return []

    try:
        with open(CHAIN_PATH, "r") as f:
            chain = json.load(f)

        threat_blocks = [
            block for block in chain
            if block.get("data", {}).get("type") == "threat"
        ]

        return threat_blocks[-limit:]

    except Exception:
        return []


def get_db_summary():
    summary = {
        "database_exists": DB_PATH.exists(),
        "process_events": 0,
        "file_events": 0,
        "sandbox_events": 0,
        "errors": []
    }

    if not DB_PATH.exists():
        return summary

    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()

        for table in ["process_events", "file_events", "sandbox_events"]:
            try:
                cur.execute(f"SELECT COUNT(*) FROM {table}")
                summary[table] = cur.fetchone()[0]
            except Exception as e:
                summary["errors"].append(f"{table}: {e}")

        conn.close()

    except Exception as e:
        summary["errors"].append(str(e))

    return summary


def generate_recommendations(experiment, chain, db_summary):
    recs = []

    if experiment:
        accuracy = experiment.get("accuracy", 0)
        failed = experiment.get("failed", 0)

        if accuracy < 80:
            recs.append("Experiment accuracy is below 80%. Improve detection rules.")
        elif failed > 0:
            recs.append("Some experiment samples failed. Review weak detections.")
        else:
            recs.append("Experiment Lab is passing. Add harder safe test samples.")

    else:
        recs.append("No experiment report found. Run: python3 core/experiment_lab.py")

    if not chain:
        recs.append("No threat ledger entries found. Run sandbox tests to generate evidence.")
    else:
        high_scores = []

        for block in chain:
            data = block.get("data", {})
            if data.get("score", 0) >= 80:
                high_scores.append(data)

        if high_scores:
            recs.append("High-risk threat entries exist. Review the latest malicious detections.")

    if not db_summary.get("database_exists"):
        recs.append("Threat database not found. Start monitor or initialize database.")

    if db_summary.get("errors"):
        recs.append("Database has missing tables or schema issues. Review database.py.")

    return recs


def print_briefing():
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    experiment = load_latest_experiment_report()
    chain = load_threat_chain(limit=5)
    db_summary = get_db_summary()
    recommendations = generate_recommendations(experiment, chain, db_summary)

    print("\n" + "=" * 60)
    print(" A3 SECURITY BRIEFING")
    print("=" * 60)
    print(f" Time: {now}")

    print("\n[1] System Data")
    print(f" Database Exists : {db_summary['database_exists']}")
    print(f" Process Events  : {db_summary['process_events']}")
    print(f" File Events     : {db_summary['file_events']}")
    print(f" Sandbox Events  : {db_summary['sandbox_events']}")

    if db_summary["errors"]:
        print(" DB Warnings:")
        for error in db_summary["errors"]:
            print(f"  - {error}")

    print("\n[2] Latest Experiment Lab Report")

    if experiment:
        print(f" Report File : {experiment.get('_file')}")
        print(f" Total Tests : {experiment.get('total_tests')}")
        print(f" Passed      : {experiment.get('passed')}")
        print(f" Failed      : {experiment.get('failed')}")
        print(f" Accuracy    : {experiment.get('accuracy')}%")

        failed_tests = [
            r for r in experiment.get("results", [])
            if not r.get("passed")
        ]

        if failed_tests:
            print(" Failed Tests:")
            for test in failed_tests:
                print(
                    f"  - {test.get('sample')} "
                    f"expected {test.get('expected')} "
                    f"but got {test.get('predicted')}"
                )
    else:
        print(" No experiment report found.")

    print("\n[3] Latest Threat Ledger Entries")

    if chain:
        for block in chain:
            data = block.get("data", {})
            print(
                f" - {data.get('verdict')} | "
                f"Score {data.get('score')} | "
                f"{data.get('threat_type')} | "
                f"{Path(data.get('file_path', 'unknown')).name}"
            )
    else:
        print(" No threat entries found.")

    print("\n[4] Recommendations")

    for rec in recommendations:
        print(f" - {rec}")

    print("\n" + "=" * 60)
    print(" End of briefing")
    print("=" * 60 + "\n")


def get_briefing_data():
    experiment = load_latest_experiment_report()
    chain = load_threat_chain(limit=5)
    db_summary = get_db_summary()
    recommendations = generate_recommendations(experiment, chain, db_summary)

    return {
        "timestamp": datetime.now().isoformat(),
        "database": db_summary,
        "latest_experiment": experiment,
        "latest_threats": chain,
        "recommendations": recommendations
    }


if __name__ == "__main__":
    print_briefing()