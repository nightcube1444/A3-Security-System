import base64
import subprocess

encoded = "ZWNobyBoZWxsbw=="
decoded = base64.b64decode(encoded)
print("Decoded payload simulation:", decoded)
# No execution happens
