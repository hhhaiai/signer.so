#!/usr/bin/env python3
"""Statically close the native expected Java-HMAC producer on ARM64."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[2]
SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
DISASSEMBLY = ROOT / ".omx/libsigner-arm64-objdump.txt"
OUTPUT = ROOT / ".omx/static-audit-20260713/arm64-expected-java-hmac.md"


def require(text: str, pattern: str, description: str) -> None:
    if re.search(pattern, text, re.MULTILINE) is None:
        raise SystemExit(f"missing static evidence: {description}")


def decoded(blob: bytes, vma: int, key: int, size: int) -> bytes:
    # The relevant writable data segment has VMA-file-offset delta 0x8000.
    raw = blob[vma - 0x8000:vma - 0x8000 + size]
    return bytes(value ^ key for value in raw)


def main() -> None:
    text = DISASSEMBLY.read_text()
    blob = SO.read_bytes()

    checks = [
        (r"9bcf4:.*adr\s+x2, 0x144ad8", "toString method name"),
        (r"9bcfc:.*adr\s+x3, 0x144af0", "toString signature"),
        (r"9bd14:.*ldr\s+x8, \[x8, #0x108\]", "JNI GetMethodID for toString"),
        (r"9bf44:.*ldr\s+x8, \[x8, #0x110\]", "JNI CallObjectMethod for toString"),
        (r"9c44c:.*adr\s+x2, 0x144b08", "getBytes method name"),
        (r"9c454:.*adr\s+x3, 0x144954", "getBytes signature"),
        (r"c8ee0:.*ldr\s+w26, \[x2, #0xc\]", "Android API read"),
        (r"c8f40:.*cmp\s+w26, #0x16", "API 22 split"),
        (r"c912c:.*bl\s+0xc9250", "API >=23 key route"),
        (r"c9178:.*bl\s+0xc9988", "API 18..22 key route"),
        (r"c91c4:.*cmp\s+w27, #0x11", "API 17 unsupported boundary"),
        (r"c95e8:.*adr\s+x2, 0x145760", "AndroidKeyStore string"),
        (r"c975c:.*adr\s+x3, 0x145770", "key2 alias"),
        (r"ca050:.*adr\s+x3, 0x145798", "adjust_keys preference"),
        (r"c9f90:.*adr\s+x3, 0x1457a8", "encrypted_key preference"),
        (r"ca218:.*adr\s+x3, 0x1457b8", "AES SecretKeySpec algorithm"),
        (r"ca958:.*adr\s+x2, 0x145748", "HmacSHA256 algorithm"),
        (r"ca964:.*bl\s+0xa9d44", "Mac.getInstance helper"),
        (r"ca9c0:.*bl\s+0xab130", "Mac.init helper"),
        (r"caba0:.*bl\s+0xab870", "Mac.update helper"),
        (r"caa50:.*bl\s+0xac1d8", "Mac.doFinal helper"),
        (r"caa98:.*bl\s+0x94bc0", "expected byte array native copy"),
        (r"eef8:.*ldur\s+x8, \[x29, #-0x78\]", "supplied cursor"),
        (r"eefc:.*ldr\s+x9, \[sp, #0x80\]", "expected cursor"),
        (r"ef08:.*cmp\s+w8, w9", "byte comparison"),
        (r"eccc:.*bl\s+0x13548c", "correction 0x07 writer"),
    ]
    for pattern, description in checks:
        require(text, pattern, description)

    strings = {
        "toString": decoded(blob, 0x144AD8, 0x6A, 9),
        "toStringSignature": decoded(blob, 0x144AF0, 0x47, 21),
        "getBytes": decoded(blob, 0x144B08, 0xD2, 9),
        "byteArraySignature": decoded(blob, 0x144954, 0xB6, 5),
        "AndroidKeyStore": decoded(blob, 0x145760, 0xEC, 16),
        "key2": decoded(blob, 0x145770, 0x81, 5),
        "adjust_keys": decoded(blob, 0x145798, 0xDC, 12),
        "encrypted_key": decoded(blob, 0x1457A8, 0xCD, 14),
        "AES": decoded(blob, 0x1457B8, 0xB6, 4),
        "HmacSHA256": decoded(blob, 0x145748, 0x9F, 11),
        "MacClass": decoded(blob, 0x144FE0, 0x29, 17),
        "getInstance": decoded(blob, 0x1449A8, 0x1E, 12),
        "getInstanceSignature": decoded(blob, 0x145000, 0xC4, 39),
        "init": decoded(blob, 0x1449EC, 0x3B, 5),
        "initSignature": decoded(blob, 0x145030, 0xAD, 23),
        "update": decoded(blob, 0x145048, 0xA5, 7),
        "updateSignature": decoded(blob, 0x145050, 0x7B, 6),
        "doFinal": decoded(blob, 0x144A18, 0xA6, 8),
        "doFinalSignature": decoded(blob, 0x144954, 0xB6, 5),
    }
    expected = {
        "toString": b"toString\0",
        "toStringSignature": b"()Ljava/lang/String;\0",
        "getBytes": b"getBytes\0",
        "byteArraySignature": b"()[B\0",
        "AndroidKeyStore": b"AndroidKeyStore\0",
        "key2": b"key2\0",
        "adjust_keys": b"adjust_keys\0",
        "encrypted_key": b"encrypted_key\0",
        "AES": b"AES\0",
        "HmacSHA256": b"HmacSHA256\0",
        "MacClass": b"javax/crypto/Mac\0",
        "getInstance": b"getInstance\0",
        "getInstanceSignature": b"(Ljava/lang/String;)Ljavax/crypto/Mac;\0",
        "init": b"init\0",
        "initSignature": b"(Ljava/security/Key;)V\0",
        "update": b"update\0",
        "updateSignature": b"([B)V\0",
        "doFinal": b"doFinal\0",
        "doFinalSignature": b"()[B\0",
    }
    for name, value in expected.items():
        if strings[name] != value:
            raise SystemExit(f"decoded string mismatch {name}: {strings[name]!r}")

    OUTPUT.write_text("""# ARM64 expected Java-HMAC producer

## Closed flow

```text
Map/Object at context+0x10
  -> 0x9b684: Object.toString()Ljava/lang/String;
  -> 0x9c030: String.getBytes()[B
  -> 0xc8ec0: select key route using context+0x0c Android API
       API >= 23: 0xc9250, AndroidKeyStore.getKey("key2", null)
       API 18..22: 0xc9988, adjust_keys/encrypted_key legacy unwrap route
       API < 18: unsupported status 18
  -> 0xca648:
       Mac.getInstance("HmacSHA256")
       Mac.init(java.security.Key)
       Mac.update(mapToStringBytes)
       Mac.doFinal() -> byte[]
  -> 0x94bc0: copy expected byte[] into native memory
  -> 0xef00..0xef08: compare supplied and expected bytes
  -> mismatch: correction 0x07 via 0x13548c
```

## API selection evidence

- `0xc8ee0`: reads `context+0x0c` Android API.
- `0xc8f40`: compares API against `0x16` (22); the greater branch is API >=23.
- `0xc912c`: calls `0xc9250`, the AndroidKeyStore route.
- `0xc9178`: calls `0xc9988`, the legacy preference/RSA route.
- `0xc91c4`: compares against `0x11` (17), closing API <18 as unsupported.

## Decoded constants

| VMA | XOR | value |
|---|---:|---|
| `0x144ad8` | `0x6a` | `toString` |
| `0x144af0` | `0x47` | `()Ljava/lang/String;` |
| `0x144b08` | `0xd2` | `getBytes` |
| `0x144954` | `0xb6` | `()[B` |
| `0x145760` | `0xec` | `AndroidKeyStore` |
| `0x145770` | `0x81` | `key2` |
| `0x145798` | `0xdc` | `adjust_keys` |
| `0x1457a8` | `0xcd` | `encrypted_key` |
| `0x1457b8` | `0xb6` | `AES` |
| `0x145748` | `0x9f` | `HmacSHA256` |
| `0x144fe0` | `0x29` | `javax/crypto/Mac` |
| `0x1449a8` | `0x1e` | `getInstance` |
| `0x145000` | `0xc4` | `(Ljava/lang/String;)Ljavax/crypto/Mac;` |
| `0x1449ec` | `0x3b` | `init` |
| `0x145030` | `0xad` | `(Ljava/security/Key;)V` |
| `0x145048` | `0xa5` | `update` |
| `0x145050` | `0x7b` | `([B)V` |
| `0x144a18` | `0xa6` | `doFinal` |

## Compatibility consequence

The C++ cryptographic equivalent is HMAC-SHA256 over the bytes produced by
Android's no-argument `String.getBytes()`, using the key selected by the API
route. A complete platform adapter must preserve Java default-charset behavior,
KeyStore exceptions, legacy unwrap failures, null results and pending JNI
exceptions; accepting arbitrary raw key bytes is only an engine-level adapter,
not the complete Android behavior.
""")
    print("EXPECTED_JAVA_HMAC_STATIC_OK")


if __name__ == "__main__":
    main()
