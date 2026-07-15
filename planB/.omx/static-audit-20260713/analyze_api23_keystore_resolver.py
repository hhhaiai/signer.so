#!/usr/bin/env python3
"""Close the ARM64 API >=23 AndroidKeyStore resolver, including null-key semantics."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[2]
SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
DISASSEMBLY = ROOT / ".omx/libsigner-arm64-objdump.txt"
OUTPUT = ROOT / ".omx/static-audit-20260713/arm64-api23-keystore-resolver.md"


def require(text: str, pattern: str, description: str) -> None:
    if re.search(pattern, text, re.MULTILINE | re.DOTALL) is None:
        raise SystemExit(f"missing static evidence: {description}")


def decoded(blob: bytes, vma: int, key: int, size: int) -> bytes:
    raw = blob[vma - 0x8000:vma - 0x8000 + size]
    return bytes(value ^ key for value in raw)


def main() -> None:
    text = DISASSEMBLY.read_text()
    blob = SO.read_bytes()
    checks = [
        (r"a4c90:.*adr\s+x\d+, 0x144e40", "KeyStore class"),
        (r"a4ba0:.*adr\s+x\d+, 0x1449a8", "getInstance method"),
        (r"a4ba8:.*adr\s+x\d+, 0x144e60", "getInstance signature"),
        (r"a5768:.*adr\s+x\d+, 0x144e90", "load method"),
        (r"a5410:.*adr\s+x\d+, 0x144ea0", "load signature"),
        (r"a723c:.*adr\s+x\d+, 0x144f40", "getKey method"),
        (r"a7244:.*adr\s+x\d+, 0x144f50", "getKey signature"),
        (r"c95e8:.*adr\s+x2, 0x145760", "AndroidKeyStore argument"),
        (r"c9600:.*bl\s+0xa4450", "getInstance call"),
        (r"c9858:.*bl\s+0xa5308", "load null call"),
        (r"c975c:.*adr\s+x3, 0x145770", "key2 argument"),
        (r"c9760:.*mov\s+x4, xzr", "null password argument"),
        (r"c977c:.*bl\s+0xa6c9c", "getKey call"),
        (r"c97b8:.*cmp\s+w8, #0x0.*c97c8:.*csel\s+x9, x25, x15, eq", "getKey status gate"),
        (r"c9818:.*ldur\s+x8, \[x29, #-0x30\].*c9824:.*ldr\s+x8, \[x8\].*c9828:.*stur\s+w9, \[x29, #-0x14\].*c9838:.*str\s+x8, \[x10\]", "unconditional key output transfer and success flag"),
        (r"c9718:.*ldur\s+x8, \[x29, #-0x20\].*c9720:.*stur\s+x8, \[x29, #-0x38\].*c9724:.*cmp\s+x8, #0x0", "KeyStore local-ref null guard"),
        (r"c98bc:.*ldur\s+x0, \[x29, #-0x10\].*c98c0:.*ldur\s+x1, \[x29, #-0x38\].*c98c8:.*ldr\s+x8, \[x8, #0xb8\].*c98cc:.*blr\s+x8", "DeleteLocalRef KeyStore cleanup"),
        (r"c995c:.*ldur\s+w8, \[x29, #-0x44\].*c9960:.*and\s+w0, w8, #0x1", "boolean return"),
    ]
    for pattern, description in checks:
        require(text, pattern, description)

    strings = {
        "KeyStoreClass": decoded(blob, 0x144E40, 0x13, 23),
        "getInstance": decoded(blob, 0x1449A8, 0x1E, 12),
        "getInstanceSignature": decoded(blob, 0x144E60, 0x53, 45),
        "load": decoded(blob, 0x144E90, 0xB0, 5),
        "loadSignature": decoded(blob, 0x144EA0, 0xBB, 47),
        "getKey": decoded(blob, 0x144F40, 0x72, 7),
        "getKeySignature": decoded(blob, 0x144F50, 0x1C, 42),
        "AndroidKeyStore": decoded(blob, 0x145760, 0xEC, 16),
        "key2": decoded(blob, 0x145770, 0x81, 5),
    }
    expected = {
        "KeyStoreClass": b"java/security/KeyStore\0",
        "getInstance": b"getInstance\0",
        "getInstanceSignature": b"(Ljava/lang/String;)Ljava/security/KeyStore;\0",
        "load": b"load\0",
        "loadSignature": b"(Ljava/security/KeyStore$LoadStoreParameter;)V\0",
        "getKey": b"getKey\0",
        "getKeySignature": b"(Ljava/lang/String;[C)Ljava/security/Key;\0",
        "AndroidKeyStore": b"AndroidKeyStore\0",
        "key2": b"key2\0",
    }
    for name, value in expected.items():
        if strings[name] != value:
            raise SystemExit(f"decoded string mismatch {name}: {strings[name]!r}")

    OUTPUT.write_text("""# ARM64 API >=23 AndroidKeyStore resolver

## Recovered call-level behavior

```text
keyStore = KeyStore.getInstance("AndroidKeyStore")
if JNI helper failed: return false

keyStore.load(null)
if JNI helper failed: DeleteLocalRef(keyStore); return false

key = keyStore.getKey("key2", null)
if JNI helper failed: DeleteLocalRef(keyStore); return false

*output = key        // copied without a null-key rejection
success = true
DeleteLocalRef(keyStore)
return success
```

## Important null distinction

At `0xc9818..0xc9838`, the object stored by the `getKey` helper is copied to the
caller output and the local success flag is set to one. There is no `cbz`, null
comparison or null-to-failure conversion on that key object. Therefore:

```text
getKey JNI call succeeded + returned null => resolver returns true with null key
getKey JNI helper/pending-exception failure => resolver returns false
```

The caller must preserve this distinction. A null key reaches the later
`Mac.init(Key)` path, where Java/JNI behavior determines the eventual failure.

## Local-reference ownership

The temporary KeyStore object is guarded and released through the JNI vtable
entry at offset `0xb8` (`DeleteLocalRef`) on success and post-creation failures.
The returned Key reference is transferred to the caller and is not deleted by
`0xc9250`.

## Helper addresses

| Address | Role |
|---|---|
| `0xa4450` | `KeyStore.getInstance(String)` |
| `0xa5308` | `KeyStore.load(LoadStoreParameter)` |
| `0xa6c9c` | `KeyStore.getKey(String,char[])` |
| `0xc9250` | API >=23 resolver and ownership/error orchestration |
""")
    print("API23_KEYSTORE_RESOLVER_STATIC_OK")


if __name__ == "__main__":
    main()
