from core.osint_engine import OSINTEngine

print("\n=== IP LOOKUP ===")
print(OSINTEngine.lookup_ip("8.8.8.8"))

print("\n=== PHONE LOOKUP ===")
print(OSINTEngine.lookup_phone("+442083661177"))

print("\n=== USERNAME LOOKUP ===")
print(OSINTEngine.lookup_username("github"))