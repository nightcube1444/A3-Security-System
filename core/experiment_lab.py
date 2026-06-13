"""
A3 Security System — Experiment Lab

Safe detection testing lab.
Generates harmless test samples, runs A3-style static checks,
compares expected vs predicted verdict, and saves a report.

This does NOT create real malware.
"""

import os
import json
import hashlib
from pathlib import Path
from datetime import datetime


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
    }
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

    report = {
        "timestamp": datetime.now().isoformat(),
        "total_tests": total,
        "passed": passed,
        "failed": failed,
        "accuracy": accuracy,
        "results": results,
        "recommendations": generate_recommendations(results)
    }

    report_path = REPORT_DIR / f"experiment_report_{int(datetime.now().timestamp())}.json"

    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    print("-" * 50)
    print("Experiment Lab Complete")
    print(f"Total Tests : {total}")
    print(f"Passed      : {passed}")
    print(f"Failed      : {failed}")
    print(f"Accuracy    : {accuracy}%")
    print(f"Report saved: {report_path}")

    return report


def generate_recommendations(results):
    recommendations = []

    for r in results:
        if not r["passed"]:
            recommendations.append(
                f"Improve rules for {r['sample']}: expected {r['expected']} but got {r['predicted']}."
            )

    if not recommendations:
        recommendations.append("All tests passed. Add more realistic safe samples next.")

    return recommendations


if __name__ == "__main__":
    run_experiments()