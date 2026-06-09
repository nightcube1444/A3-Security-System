from core.risk_engine import RiskEngine

result = RiskEngine.calculate_process_risk(
    "python",
    "/tmp/malware.py"
)

print(result)