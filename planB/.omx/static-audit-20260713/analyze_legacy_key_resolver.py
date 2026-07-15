#!/usr/bin/env python3
"""Statically close the ARM64 API 18..22 wrapped-key resolver success path."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[2]
SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
DISASSEMBLY = ROOT / ".omx/libsigner-arm64-objdump.txt"
OUTPUT = ROOT / ".omx/static-audit-20260713/arm64-legacy-key-resolver.md"


def require(text: str, pattern: str, description: str) -> None:
    if re.search(pattern, text, re.MULTILINE) is None:
        raise SystemExit(f"missing static evidence: {description}")


def decoded(blob: bytes, vma: int, key: int, size: int) -> bytes:
    raw = blob[vma - 0x8000:vma - 0x8000 + size]
    return bytes(value ^ key for value in raw)


def main() -> None:
    text = DISASSEMBLY.read_text()
    blob = SO.read_bytes()

    checks = [
        (r"b4f54:.*adr\s+x26, 0x145190", "getSharedPreferences name"),
        (r"b50fc:.*adr\s+x3, 0x1451b0", "getSharedPreferences signature"),
        (r"c1b1c:.*adr\s+x24, 0x145548", "getString name"),
        (r"c1e30:.*adr\s+x3, 0x145560", "getString signature"),
        (r"935c8:.*adr\s+x12, 0x144910", "Base64 class"),
        (r"93af4:.*adr\s+x2, 0x144924", "Base64.decode name"),
        (r"93afc:.*adr\s+x3, 0x144930", "Base64.decode signature"),
        (r"be128:.*adr\s+x1, 0x1454d0", "SecretKeySpec class"),
        (r"be894:.*adr\s+x2, 0x144a44", "SecretKeySpec constructor"),
        (r"be89c:.*adr\s+x3, 0x1454f0", "SecretKeySpec constructor signature"),
        (r"cb5d4:.*adr\s+x2, 0x145760", "AndroidKeyStore"),
        (r"cb8a8:.*adr\s+x13, 0x145770", "key2 alias"),
        (r"cb93c:.*adr\s+x2, 0x145780", "RSA transformation"),
        (r"ca078:.*bl\s+0xb479c", "getSharedPreferences call"),
        (r"c9fb0:.*bl\s+0xc0d84", "getString call"),
        (r"ca3e0:.*bl\s+0x93014", "Base64.decode call"),
        (r"ca148:.*bl\s+0xcac40", "RSA unwrap call"),
        (r"ca22c:.*bl\s+0xbd6a8", "SecretKeySpec call"),
    ]
    for pattern, description in checks:
        require(text, pattern, description)

    strings = {
        "getSharedPreferences": decoded(blob, 0x145190, 0xF7, 21),
        "getSharedPreferencesSignature": decoded(blob, 0x1451B0, 0x9F, 57),
        "getString": decoded(blob, 0x145548, 0xB6, 10),
        "getStringSignature": decoded(blob, 0x145560, 0x03, 57),
        "Base64Class": decoded(blob, 0x144910, 0xDD, 20),
        "decode": decoded(blob, 0x144924, 0x0A, 7),
        "decodeSignature": decoded(blob, 0x144930, 0x2B, 24),
        "SecretKeySpecClass": decoded(blob, 0x1454D0, 0xDC, 32),
        "constructor": decoded(blob, 0x144A44, 0x21, 7),
        "constructorSignature": decoded(blob, 0x1454F0, 0xE3, 24),
        "AndroidKeyStore": decoded(blob, 0x145760, 0xEC, 16),
        "key2": decoded(blob, 0x145770, 0x81, 5),
        "rsaTransformation": decoded(blob, 0x145780, 0x3C, 21),
        "adjustKeys": decoded(blob, 0x145798, 0xDC, 12),
        "encryptedKey": decoded(blob, 0x1457A8, 0xCD, 14),
        "aes": decoded(blob, 0x1457B8, 0xB6, 4),
    }
    expected = {
        "getSharedPreferences": b"getSharedPreferences\0",
        "getSharedPreferencesSignature": b"(Ljava/lang/String;I)Landroid/content/SharedPreferences;\0",
        "getString": b"getString\0",
        "getStringSignature": b"(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;\0",
        "Base64Class": b"android/util/Base64\0",
        "decode": b"decode\0",
        "decodeSignature": b"(Ljava/lang/String;I)[B\0",
        "SecretKeySpecClass": b"javax/crypto/spec/SecretKeySpec\0",
        "constructor": b"<init>\0",
        "constructorSignature": b"([BLjava/lang/String;)V\0",
        "AndroidKeyStore": b"AndroidKeyStore\0",
        "key2": b"key2\0",
        "rsaTransformation": b"RSA/ECB/PKCS1Padding\0",
        "adjustKeys": b"adjust_keys\0",
        "encryptedKey": b"encrypted_key\0",
        "aes": b"AES\0",
    }
    for name, value in expected.items():
        if strings[name] != value:
            raise SystemExit(f"decoded string mismatch {name}: {strings[name]!r}")

    OUTPUT.write_text("""# ARM64 API 18..22 legacy wrapped-key resolver

## Closed success path

```text
Context
  -> 0xb479c: getSharedPreferences("adjust_keys", MODE_PRIVATE)
  -> 0xc0d84: getString("encrypted_key", null)
  -> 0x93014: android.util.Base64.decode(value, DEFAULT)
  -> 0xcac40:
       KeyStore.getInstance("AndroidKeyStore") / load(null)
       getEntry("key2", null) -> PrivateKeyEntry
       Cipher.getInstance("RSA/ECB/PKCS1Padding")
       init(DECRYPT_MODE, privateKey)
       doFinal(encryptedBytes) -> raw 16-byte legacy HMAC key
  -> 0xbd6a8: new SecretKeySpec(rawKey, "AES")
  -> 0xca648: Mac.init(Key), update(data), doFinal()
```

The flattened block order in `0xc9988` is not source order; the helper identities,
arguments and recovered Java source close the observable success order above.

## Helper evidence

| Address | Recovered role |
|---|---|
| `0xb479c` | `Context.getSharedPreferences(String,int)` |
| `0xc0d84` | `SharedPreferences.getString(String,String)` |
| `0x93014` | `Base64.decode(String,int)` |
| `0xcac40` | AndroidKeyStore `key2` RSA/PKCS1 private-key unwrap |
| `0xbd6a8` | `SecretKeySpec(byte[],String)` constructor |

## Full orchestrator closure

The companion `analyze_legacy_key_resolver_c9988_full.py` interprets the complete
flattened FDE and proves preexisting-status behavior, null forwarding, Base64
status 26 normalization, RSA boolean gating, final output publication and the
exact four-reference cleanup order. Direct C++ is
`runRecoveredLegacyWrappedKeyResolverC9988(...)`.
""")
    print("LEGACY_KEY_RESOLVER_STATIC_OK")


if __name__ == "__main__":
    main()
