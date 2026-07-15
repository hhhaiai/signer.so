# JNI `Cipher.init(int, Key)` helper `0x96ea8`

## Scope and role

```text
ARM64  0x96ea8..0x975f0
x86_64 0x997a5..0x99de0
```

The sole direct caller uses:

```text
ARM64  0xcb1e0 -> 0x96ea8  in FDE 0xcac40..0xcba84
x86_64 0xba429 -> 0x997a5 in FDE 0xba02d..0xbac93
```

Both callers pass operation mode `2`, the Java `Cipher.DECRYPT_MODE` value.
The remaining arguments are the shared status pointer, `JNIEnv`, cipher object
and `java.security.Key` object.

## Decoded constants

| ABI | VMA | file offset | XOR key | plaintext |
|---|---:|---:|---:|---|
| ARM64 | `0x1449ec` | `0x13c9ec` | `0x3b` | `init\0` |
| ARM64 | `0x144a00` | `0x13ca00` | `0x30` | `(ILjava/security/Key;)V\0` |
| x86_64 | `0x13d48c` | `0x13548c` | `0x6b` | `init\0` |
| x86_64 | `0x13d4a0` | `0x1354a0` | `0x14` | `(ILjava/security/Key;)V\0` |

Each string is protected by a distinct acquire/release once-lock in both
ABIs.

## JNI and status flow

| operation | ARM64 | x86_64 | table offset |
|---|---:|---:|---:|
| `GetObjectClass(cipher)` | `0x972c4` | `0x99aa1` | `+0xf8` |
| exception consume | `0x972d0` | `0x99abd` | helper |
| `GetMethodID(init, signature)` | `0x97428` | `0x99bd0` | `+0x108` |
| exception consume | `0x97438` | `0x99be6` | helper |
| `CallVoidMethod(cipher, method, mode, key)` | `0x975a4` | `0x99d64` | `+0x1e8` |
| exception consume | `0x975ac` | `0x99d78` | helper |
| `DeleteLocalRef(cipherClass)` | `0x97564` | `0x99cf3` | `+0xb8` |

Terminal behavior:

```text
cipher == null or key == null       status 3, no JNI
class null or class exception       status 18
method null or method exception     status 18
CallVoidMethod exception            status 41 (0x29)
success                             preserve incoming status
```

The cipher-class local reference is deleted whenever class acquisition
returned a non-null reference. There is no returned object or output slot.

## C++ recovery

```text
RecoveredJniIntKeyInitOperations96ea8
runRecoveredJniIntKeyInit96ea8
recoveredJniIntKeyInit96ea8Regression
```

The regression covers success, signed operation-mode forwarding, incoming
nonzero status, null cipher, null key, class-null, class-exception, method-null,
method-exception, call-exception, exact strings, event order and class cleanup.

## Verification

```bash
python3 .omx/static-audit-20260713/analyze_jni_cipher_init_96ea8.py
```

The verifier checks both callee and caller FDEs, exact caller mode/argument
forwarding, four decoded constants, both once-lock protocols, JNI table
offsets, all three exception consumers, status values, C++ regression tokens
and recovered JNI-reachable coverage.

## Observation-only original-SO corroboration

The isolated API 18 Unidbg test below installs a caller-supplied RSA key pair
and wrapped secret, then observes the natural legacy decrypt path without
changing registers, branches, return values, JNI objects or target bytes:

```text
unidbg-adjust-runner/src/test/java/local/JniCipherInitNativeIntegrationTest.java
```

Observed hook points:

```text
0x96ea8 entry
0x97428 GetMethodID call
0x975a4 CallVoidMethod call
0x975b0 exception result
0x97564 DeleteLocalRef
0xcb1e4 caller status observation
```

The current offline run produced:

```text
entries=1
status=0 -> 0
method=init
signature=(ILjava/security/Key;)V
entry/call mode=2/2
cipher forwarded=true
key forwarded=true
call exception=0
class DeleteLocalRef count=1
Tests run: 1, Failures: 0, Errors: 0, Skipped: 0
```

The Maven log is:

```text
.omx/static-audit-20260713/jni-cipher-init-96ea8-unidbg.log
```
