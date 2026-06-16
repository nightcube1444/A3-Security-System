"""
A3 Security System — Self Reflection Engine

Reads A3 learning memory and experiment reports,
then produces a self-assessment:

- What A3 learned
- What improved
- What is weak
- What should be built next

This is operational self-reflection, not consciousness.
"""

import json
from pathlib import Path
from datetime import datetime


BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"

MEMORY_PATH = DATA_DIR / "learning_memory.json"
EXPERIMENT_DIR = DATA_DIR / "experiment_reports"
REFLECTION_PATH = DATA_DIR / "self_reflection.json"


def load_json(path, default):
    if not path.exists():
        return default

    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return default


def latest_experiment_report():
    if not EXPERIMENT_DIR.exists():
        return None

    reports = list(EXPERIMENT_DIR.glob("experiment_report_*.json"))

    if not reports:
        return None

    latest = max(reports, key=lambda p: p.stat().st_mtime)

    data = load_json(latest, None)

    if data:
        data["_file"] = str(latest)

    return data


def analyze_memory(memories):
    summary = {
        "total_lessons": len(memories),
        "fixed_lessons": 0,
        "pending_lessons": 0,
        "failed_lessons": 0,
        "categories": {},
        "top_tags": {},
    }

    for lesson in memories:
        result = str(lesson.get("result", "")).upper()
        category = lesson.get("category", "unknown")

        summary["categories"][category] = summary["categories"].get(category, 0) + 1

        if result in ["FIXED", "SUCCESS", "IMPROVED"]:
            summary["fixed_lessons"] += 1
        elif result == "PENDING":
            summary["pending_lessons"] += 1
        elif result in ["FAILED", "REGRESSION"]:
            summary["failed_lessons"] += 1

        for tag in lesson.get("tags", []):
            summary["top_tags"][tag] = summary["top_tags"].get(tag, 0) + 1

    return summary


def generate_reflection():
    memories = load_json(MEMORY_PATH, [])
    experiment = latest_experiment_report()
    memory_summary = analyze_memory(memories)

    strengths = []
    weaknesses = []
    next_actions = []

    if experiment:
        accuracy = experiment.get("accuracy", 0)
        failed = experiment.get("failed", 0)

        if accuracy >= 90:
            strengths.append(
                f"Experiment Lab is strong. Latest accuracy is {accuracy}%."
            )
        else:
            weaknesses.append(
                f"Experiment Lab accuracy is {accuracy}%. Detection rules need improvement."
            )

        if failed == 0:
            strengths.append("No failed experiment samples in the latest run.")
        else:
            weaknesses.append(f"{failed} experiment samples failed.")
            next_actions.append("Review failed experiment samples and update detection rules.")
    else:
        weaknesses.append("No experiment report found.")
        next_actions.append("Run python3 core/experiment_lab.py.")

    if memory_summary["fixed_lessons"] > 0:
        strengths.append(
            f"A3 has fixed {memory_summary['fixed_lessons']} learned issue(s)."
        )

    if memory_summary["pending_lessons"] > 0:
        weaknesses.append(
            f"A3 has {memory_summary['pending_lessons']} pending lesson(s)."
        )
        next_actions.append("Review learning_memory.json and resolve pending lessons.")

    if memory_summary["total_lessons"] == 0:
        weaknesses.append("A3 has no learning memory yet.")
        next_actions.append("Run experiments and store lessons from failures.")

    if not next_actions:
        next_actions.append("Add harder safe experiment samples to challenge A3.")

    reflection = {
        "timestamp": datetime.now().isoformat(),
        "system_state": "IMPROVING",
        "memory_summary": memory_summary,
        "latest_experiment": {
            "file": experiment.get("_file") if experiment else None,
            "accuracy": experiment.get("accuracy") if experiment else None,
            "passed": experiment.get("passed") if experiment else None,
            "failed": experiment.get("failed") if experiment else None,
        },
        "strengths": strengths,
        "weaknesses": weaknesses,
        "next_actions": next_actions,
    }

    with open(REFLECTION_PATH, "w") as f:
        json.dump(reflection, f, indent=2)

    return reflection


def print_reflection(reflection):
    print("\n" + "=" * 60)
    print(" A3 SELF REFLECTION")
    print("=" * 60)

    print(f"\nTime: {reflection['timestamp']}")
    print(f"System State: {reflection['system_state']}")

    print("\n[Memory]")
    ms = reflection["memory_summary"]
    print(f"Total Lessons : {ms['total_lessons']}")
    print(f"Fixed Lessons : {ms['fixed_lessons']}")
    print(f"Pending       : {ms['pending_lessons']}")

    print("\n[Latest Experiment]")
    exp = reflection["latest_experiment"]
    print(f"Accuracy : {exp['accuracy']}%")
    print(f"Passed   : {exp['passed']}")
    print(f"Failed   : {exp['failed']}")

    print("\n[Strengths]")
    for item in reflection["strengths"]:
        print(f" - {item}")

    print("\n[Weaknesses]")
    if reflection["weaknesses"]:
        for item in reflection["weaknesses"]:
            print(f" - {item}")
    else:
        print(" - No major weaknesses detected from current memory.")

    print("\n[Next Actions]")
    for item in reflection["next_actions"]:
        print(f" - {item}")

    print("\n" + "=" * 60 + "\n")


if __name__ == "__main__":
    reflection = generate_reflection()
    print_reflection(reflection)