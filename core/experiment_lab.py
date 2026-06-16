"""
A3 Security System — Experiment Lab

Safe detection testing lab.
Generates harmless test samples, runs A3-style static checks,
compares expected vs predicted verdict, saves a report,
and stores failed experiments in Learning Memory.

This does NOT create real malware.
"""

import json
import hashlib
from pathlib import Path
from datetime import datetime

try:
    from core.learning_memory import LearningMemory
except Exception:
    from learning_memory import LearningMemory


BASE_DIR = Path(__file__).parent.parent
LAB_DIR = BASE_DIR / "sandbox" / "experiment_samples"
REPORT_DIR = BASE_DIR / "data" / "experiment_reports"

LAB_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)


SAMPLES = [
    {
        "name": "clean_hello.py",
        "expected": "CLEAN",
        "content": """
print("Hello from clean sample")
x = 2 + 2
print(x)
"""
    },
    {
        "name": "suspicious_socket.py",
        "expected": "SUSPICIOUS",
        "content": """
import socket

print("Simulated socket usage only")
# No real connection is made
"""
    },
    {
        "name": "suspicious_subprocess.py",
        "expected": "SUSPICIOUS",
        "content": """
import subprocess

print("Simulated subprocess usage only")
# No command is executed
"""
    },
    {
        "name": "malicious_pattern_base64.py",
        "expected": "MALICIOUS",
        "content": """
import base64
import subprocess

encoded = "ZWNobyBoZWxsbw=="
decoded = base64.b64decode(encoded)
print("Decoded payload simulation:", decoded)
# No execution happens
"""
    },
    {
        "name": "malicious_pattern_ransomware.py",
        "expected": "MALICIOUS",
        "content": """
# Simulated ransomware-like pattern
# This does NOT encrypt, delete, or modify files

keywords = ["encrypt", "decrypt", "ransom", "payment", "bitcoin"]
for word in keywords:
    print("Simulation keyword:", word)
"""
    },
    {
        "name": "malicious_pattern_keylogger.py",
        "expected": "MALICIOUS",
        "content": """
# Simulated keylogger-like pattern
# This does NOT record keys

keywords = ["keyboard", "keystroke", "listener", "keylogger"]
for word in keywords:
    print("Simulation keyword:", word)
"""
    },
        {
        "name": "suspicious_dns_beacon.py",
        "expected": "SUSPICIOUS",
        "content": """
# Simulated DNS beacon-like pattern
# This does NOT make any network connection

domains = [
    "a1b2c3d4-test.example",
    "x9y8z7-check.example",
    "beacon-status.example"
]

for domain in domains:
    print("Simulated DNS lookup:", domain)
"""
    },
    {
        "name": "suspicious_persistence.py",
        "expected": "SUSPICIOUS",
        "content": """
# Simulated persistence-related keywords
# This does NOT modify startup items

keywords = [
    "launchagent",
    "launchdaemon",
    "login item",
    "startup",
    "persistence"
]

for word in keywords:
    print("Persistence simulation:", word)
"""
    },
    {
        "name": "malicious_file_burst.py",
        "expected": "MALICIOUS",
        "content": """
# Simulated destructive file activity pattern
# This does NOT delete or modify files

keywords = [
    "delete many files",
    "overwrite documents",
    "recursive file modification",
    "mass file rename",
    "file destruction"
]

for word in keywords:
    print("File burst simulation:", word)
"""
    },
    {
        "name": "malicious_encoded_network.py",
        "expected": "MALICIOUS",
        "content": """
# Simulated encoded network payload pattern
# This does NOT connect to the internet

import base64
import socket

encoded = "Y29tbWFuZF9hbmRfY29udHJvbA=="
decoded = base64.b64decode(encoded)

print("Encoded network simulation:", decoded)
"""
    },
]


def sha256_file(path):
    h = hashlib.sha256()

    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)

    return h.hexdigest()


def generate_samples():
    created = []

    for sample in SAMPLES:
        path = LAB_DIR / sample["name"]

        with open(path, "w") as f:
            f.write(sample["content"].strip() + "\n")

        created.append({
            "name": sample["name"],
            "path": str(path),
            "expected": sample["expected"],
            "hash": sha256_file(path)
        })

    return created


def static_analyze_file(path):
    """
    Safe static pattern analysis.
    Does not execute the sample.
    """

    with open(path, "r", errors="ignore") as f:
        content = f.read().lower()

    score = 0
    flags = []

    rules = [
        ("import subprocess", 30, "static_imports_subprocess"),
        ("os.system", 50, "static_system_command"),
        ("subprocess.run", 50, "static_subprocess_run"),
        ("subprocess.call", 50, "static_subprocess_call"),
        ("import socket", 30, "static_imports_socket"),
        ("base64", 30, "static_base64_usage"),
        ("b64decode", 40, "static_base64_decode"),
        ("encrypt", 45, "static_ransomware_keyword_encrypt"),
        ("ransom", 60, "static_ransomware_keyword_ransom"),
        ("bitcoin", 35, "static_ransomware_keyword_payment"),
        ("keyboard", 35, "static_keylogger_keyword_keyboard"),
        ("keystroke", 45, "static_keylogger_keyword_keystroke"),
        ("keylogger", 60, "static_keylogger_keyword"),
        ("beacon", 35, "static_dns_beacon_keyword"),
        ("dns lookup", 35, "static_dns_lookup_pattern"),
        ("launchagent", 15, "static_persistence_launchagent"),
        ("launchdaemon", 15, "static_persistence_launchdaemon"),
        ("login item", 15, "static_persistence_login_item"),
        ("startup", 15, "static_persistence_startup"),
        ("persistence", 15, "static_persistence_keyword"),
        ("delete many files", 60, "static_mass_delete_keyword"),
        ("overwrite documents", 60, "static_overwrite_documents"),
        ("recursive file modification", 60, "static_recursive_file_modification"),
        ("mass file rename", 50, "static_mass_file_rename"),
        ("file destruction", 60, "static_file_destruction_keyword"),
        ("command_and_control", 60, "static_c2_keyword"),
    ]

    for pattern, points, flag in rules:
        if pattern in content:
            score += points
            flags.append(flag)

    if score >= 80:
        verdict = "MALICIOUS"
    elif score >= 30:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return {
        "score": score,
        "flags": flags,
        "verdict": verdict
    }


def generate_recommendations(results):
    recommendations = []

    for r in results:
        if not r["passed"]:
            recommendations.append(
                f"Improve rules for {r['sample']}: "
                f"expected {r['expected']} but got {r['predicted']}."
            )

    if not recommendations:
        recommendations.append(
            "All tests passed. Add more realistic safe samples next."
        )

    return recommendations


def save_failed_tests_to_memory(results):
    memory = LearningMemory()
    saved = []

    for r in results:
        if not r.get("passed"):
            lesson = memory.add_lesson(
                title=f"Failed detection: {r.get('sample')}",
                category="experiment_failure",
                problem=(
                    f"{r.get('sample')} was expected to be "
                    f"{r.get('expected')} but A3 predicted "
                    f"{r.get('predicted')}."
                ),
                cause=(
                    "Detection rule score, threshold, or feature coverage "
                    "may be insufficient."
                ),
                fix=(
                    "Review flags and scoring rules for this sample. "
                    "Add or adjust detection rules, then rerun experiment lab."
                ),
                result="PENDING",
                confidence=0.7,
                tags=[
                    "experiment",
                    "failed_test",
                    str(r.get("expected")).lower(),
                    str(r.get("predicted")).lower(),
                ],
            )

            saved.append(lesson)

    return saved


def run_experiments():
    print("\nA3 Experiment Lab Starting...")
    print("-" * 50)

    samples = generate_samples()
    results = []

    passed = 0
    failed = 0

    for sample in samples:
        analysis = static_analyze_file(sample["path"])

        is_pass = analysis["verdict"] == sample["expected"]

        if is_pass:
            passed += 1
        else:
            failed += 1

        result = {
            "sample": sample["name"],
            "path": sample["path"],
            "hash": sample["hash"],
            "expected": sample["expected"],
            "predicted": analysis["verdict"],
            "score": analysis["score"],
            "flags": analysis["flags"],
            "passed": is_pass
        }

        results.append(result)

        status = "PASS" if is_pass else "FAIL"

        print(f"[{status}] {sample['name']}")
        print(f"  Expected : {sample['expected']}")
        print(f"  Predicted: {analysis['verdict']}")
        print(f"  Score    : {analysis['score']}")
        print(f"  Flags    : {analysis['flags']}")
        print()

    total = len(results)
    accuracy = round((passed / total) * 100, 2) if total else 0

    memory_lessons = save_failed_tests_to_memory(results)

    report = {
        "timestamp": datetime.now().isoformat(),
        "total_tests": total,
        "passed": passed,
        "failed": failed,
        "accuracy": accuracy,
        "results": results,
        "recommendations": generate_recommendations(results),
        "memory_lessons_saved": len(memory_lessons)
    }

    report_path = REPORT_DIR / f"experiment_report_{int(datetime.now().timestamp())}.json"

    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    print("-" * 50)
    print("Experiment Lab Complete")
    print(f"Total Tests          : {total}")
    print(f"Passed               : {passed}")
    print(f"Failed               : {failed}")
    print(f"Accuracy             : {accuracy}%")
    print(f"Memory lessons saved : {len(memory_lessons)}")
    print(f"Report saved         : {report_path}")

    return report


if __name__ == "__main__":
    run_experiments()