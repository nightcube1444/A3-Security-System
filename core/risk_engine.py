"""
A3 Security System
Risk Scoring Engine
"""

import os

class RiskEngine:

    @staticmethod
    def calculate_process_risk(process_name, process_path=""):

        score = 0
        reasons = []

        process_name = process_name.lower()

        # Suspicious names
        suspicious_names = [
            "nc",
            "netcat",
            "bash",
            "python",
            "perl",
            "ruby",
            "sh"
        ]

        if process_name in suspicious_names:
            score += 25
            reasons.append("Potential scripting tool")

        # Running from temp locations
        if "/tmp" in process_path:
            score += 40
            reasons.append("Running from temp directory")

        if "/var/tmp" in process_path:
            score += 40
            reasons.append("Running from var/tmp")

        # Hidden file
        filename = os.path.basename(process_path)

        if filename.startswith("."):
            score += 15
            reasons.append("Hidden executable")

        # Cap score
        score = min(score, 100)

        severity = RiskEngine.get_severity(score)

        return {
            "score": score,
            "severity": severity,
            "reasons": reasons
        }

    @staticmethod
    def get_severity(score):

        if score >= 80:
            return "CRITICAL"

        elif score >= 60:
            return "HIGH"

        elif score >= 30:
            return "MEDIUM"

        else:
            return "LOW"