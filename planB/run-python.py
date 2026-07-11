#!/usr/bin/env python3
import pathlib
import re
import subprocess
import sys

root = pathlib.Path(__file__).resolve().parent
cmd = [str(root / "run-java.sh"), *sys.argv[1:]]
proc = subprocess.run(cmd, cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
print(proc.stdout, end="")
if proc.returncode != 0:
    sys.exit(proc.returncode)

def last_value(name: str):
    values = []
    for line in proc.stdout.splitlines():
        if line.startswith(name + "="):
            values.append(line.split("=", 1)[1].strip())
    return values[-1] if values else None

native_hex = last_value("NATIVE_SIGNATURE_HEX")
signer_v4_b64 = last_value("SIGNER_V4_SIGNATURE_BASE64")
signer_v5_authorization = last_value("SIGNER_V5_AUTHORIZATION")
if not native_hex and not signer_v4_b64 and not signer_v5_authorization:
    hex_lines = [line.strip() for line in proc.stdout.splitlines() if re.fullmatch(r"[0-9a-f]{32,}", line.strip())]
    native_hex = hex_lines[-1] if hex_lines else None
if native_hex:
    print("PYTHON_NATIVE_SIGNATURE_HEX=" + native_hex)
if signer_v4_b64:
    print("PYTHON_SIGNER_V4_SIGNATURE_BASE64=" + signer_v4_b64)
if signer_v5_authorization:
    print("PYTHON_SIGNER_V5_AUTHORIZATION=" + signer_v5_authorization)
if not native_hex and not signer_v4_b64 and not signer_v5_authorization:
    print("signature output not found", file=sys.stderr)
    sys.exit(1)
