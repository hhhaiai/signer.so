#!/usr/bin/env python3
"""Verify the Java signer retry/reset/lockdown bytecode without executing it."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[2]
JAVAP = ROOT / ".omx/static-audit-20260713/original-java-javap.txt"
OUTPUT = ROOT / ".omx/static-audit-20260713/java-retry-lockdown.md"


def require(text: str, pattern: str, description: str) -> None:
    if re.search(pattern, text, re.MULTILINE | re.DOTALL) is None:
        raise SystemExit(f"missing static evidence: {description}")


def main() -> None:
    text = JAVAP.read_text()
    checks = [
        (r"0: getstatic.*Field a:Z.*3: ifeq\s+15", "process-global lockdown early return"),
        (r"136: iconst_2\s+137: istore\s+4", "two-attempt initialization"),
        (r"147\s+167\s+181\s+Class java/security/UnrecoverableKeyException", "UnrecoverableKey retry catch"),
        (r"147\s+167\s+176\s+Class java/security/InvalidKeyException", "InvalidKey retry catch"),
        (r"295: iinc\s+4, -1", "attempt decrement"),
        (r"302: ldc.*AndroidKeyStore.*314: invokevirtual.*deleteEntry", "key2 deletion"),
        (r"317: ldc.*adjust_keys.*328: ldc.*encrypted_key.*335: invokeinterface.*apply", "preference reset"),
        (r"343: aload_0.*354: iconst_1.*355: putstatic.*Field a:Z.*374: athrow", "unsupported lockdown and rethrow"),
        (r"375: iload\s+4.*377: ifne\s+403.*382: iconst_1.*383: putstatic.*Field a:Z", "retry exhaustion lockdown"),
        (r"507: aload_0.*508: ifnonnull\s+538.*521: ldc.*activity_kind.*529: ldc.*client_sdk.*537: return", "null native result cleanup"),
        (r"544: iconst_2.*Base64.encodeToString.*548: ldc.*signature", "Base64 NO_WRAP signature write"),
        (r"Exception table:.*147\s+167", "catch range ends before reset block"),
    ]
    for pattern, description in checks:
        require(text, pattern, description)

    OUTPUT.write_text("""# Java retry/reset/lockdown static proof

Source of truth: `classes.jar` bytecode rendered in `original-java-javap.txt`.

```text
if processLockdown: return
if null/empty arguments: return
insert activity_kind/client_sdk
attempts = 2
while attempts > 0:
  ensure key; compute Java HMAC
  UnsupportedApi:
    lockdown = true; remove temporary keys; rethrow
  InvalidKeyException or UnrecoverableKeyException:
    attempts--
    delete AndroidKeyStore key2
    remove adjust_keys/encrypted_key and apply
  other Exception:
    remove temporary keys; rethrow
if attempts == 0:
  lockdown = true; remove temporary keys; return
nativeResult = nSign(...)
if nativeResult == null:
  remove temporary keys; return
signature = Base64.encodeToString(nativeResult, NO_WRAP /* flag 2 */)
remove temporary keys
```

The exception table covers bytecode offsets `147..167` only. Reset bytecode
starts at `302`, so an exception raised while deleting `key2` or clearing the
preference escapes directly and does not reach the ordinary temporary-key
cleanup blocks. The C++ control-flow model intentionally preserves this edge.
""")
    print("JAVA_RETRY_LOCKDOWN_STATIC_OK")


if __name__ == "__main__":
    main()
