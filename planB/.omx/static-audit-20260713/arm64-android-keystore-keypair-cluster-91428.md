# ARM64 AndroidKeyStore key-pair cluster

## Closed FDEs

| ABI | Range | Recovered role |
|---|---|---|
| ARM64 | `0xa0640..0xa1230` | JNI `KeyPairGenerator.generateKeyPair()` helper |
| x86_64 | `0x9fc58..0xa0319` | equivalent JNI helper |
| ARM64 | `0x91428..0x917a8` | AndroidKeyStore/load/generate orchestrator |
| x86_64 | `0x958b5..0x95bf1` | equivalent orchestrator |

Neither ARM64 FDE is statically reachable from the two exported JNI entries in
the current direct-call graph. They remain part of the 388-FDE full-file
recovery objective.

## `0xa0640` source-level signature

```cpp
void generateKeyPair(
    std::uint32_t* status,
    JNIEnv* env,
    jobject keyPairGenerator,
    jobject* outputKeyPair);
```

Recovered flow:

```text
if keyPairGenerator == null:
    *status = 3
    *outputKeyPair = null
    return

generatorClass = GetObjectClass(keyPairGenerator)       // vtable +0xf8
classException = consumeException(env)                  // ARM64 0x92a20
if generatorClass == null || classException:
    *status = 18
    if generatorClass != null: DeleteLocalRef(generatorClass)
    *outputKeyPair = null
    return

method = GetMethodID(                                  // vtable +0x108
    generatorClass,
    "generateKeyPair",
    "()Ljava/security/KeyPair;")
methodException = consumeException(env)
if method == null || methodException:
    *status = 18
    DeleteLocalRef(generatorClass)
    *outputKeyPair = null
    return

*outputKeyPair = CallObjectMethod(keyPairGenerator, method) // +0x110
callException = consumeException(env)
if callException || *outputKeyPair == null:
    *status = 28

DeleteLocalRef(generatorClass)                          // +0xb8
if *status != 0:
    *outputKeyPair = null
```

An incoming nonzero status does not skip JNI. If all JNI operations otherwise
succeed, the final status remains unchanged and the returned KeyPair reference
is cleared. On status zero, the returned local reference is transferred to the
caller and is not deleted by this FDE.

## `0x91428` source-level signature

```cpp
void createAndroidKeyStoreAndGenerate(
    std::uint32_t* status,
    JNIEnv* env,
    jobject keyPairGenerator,
    jobject* outputKeyStore,
    jobject* outputKeyPair);
```

Recovered order:

```text
provider = acquireXorOnce("AndroidKeyStore")

KeyStore.getInstance(provider, outputKeyStore)  // ARM64 0xa4450
if *status != 0: goto failure

KeyStore.load(*outputKeyStore, null)             // ARM64 0xa5308
if *status != 0: goto failure

KeyPairGenerator.generateKeyPair(                // ARM64 0xa0640
    keyPairGenerator, outputKeyPair)
if *status != 0: goto failure

return

failure:
    *outputKeyStore = null
    *outputKeyPair = null
    return
```

There is no outer null check for the KeyStore result. A successful
`getInstance` helper call returning null is forwarded into the `load` helper,
whose own null-object rule writes status `3`.

The failure block does not call `DeleteLocalRef`. Consequently, a KeyStore
local reference published before a later load/generate failure is overwritten
with null without being released by this FDE. The compatibility-accurate C++
preserves that caller-visible ownership edge; a hardened wrapper can release
such references separately.

On complete success, both KeyStore and KeyPair references remain published and
are transferred to the caller.

## XOR-once provider constant

ARM64:

```text
VMA:        0x144880
file offset:0x13c880
ciphertext: 95 ba b0 a6 bb bd b0 9f b1 ad 87 a0 bb a6 b1 d4
key:        0xd4
plaintext:  AndroidKeyStore\0
lock:       0x146850
initialized:0x14685c
```

x86_64:

```text
VMA:        0x13d320
file offset:0x135320
key:        0x6e
plaintext:  AndroidKeyStore\0
lock:       0x13ef92
initialized:0x13ef93
```

Both ABIs use a byte compare-exchange loop, decode only when the initialized
byte is zero, publish initialized `1`, and release the lock before invoking
`KeyStore.getInstance`.

## Cross-ABI method constants

| ABI | VMA | Key | Plaintext |
|---|---:|---:|---|
| ARM64 | `0x144d00` | `0x22` | `generateKeyPair\0` |
| ARM64 | `0x144d10` | `0x7c` | `()Ljava/security/KeyPair;\0` |
| x86_64 | `0x13d7a0` | `0x82` | `generateKeyPair\0` |
| x86_64 | `0x13d7b0` | `0xdb` | `()Ljava/security/KeyPair;\0` |

## Caller-input boundary

The fixed provider, method name and JNI signature are recovered protocol
constants. Runtime values are not synthesized:

- `status` storage is caller supplied;
- `JNIEnv*` is caller supplied;
- the `KeyPairGenerator` object is caller supplied;
- both output slots are caller supplied;
- helper success/failure and returned Java references come from caller-provided
  operations in portable C++.

The C++ does not construct a substitute generator, KeyStore, KeyPair, Android
profile or JNI environment.

## Evidence and regression

```text
.omx/static-audit-20260713/analyze_android_keystore_keypair_cluster_91428.py
native-reimplementation/recovered_primitives.cpp:
  runRecoveredJniGenerateKeyPairA0640
  recoveredJniGenerateKeyPairA0640Regression
  acquireRecoveredAndroidKeyStoreString91428
  runRecoveredAndroidKeyStoreKeyPair91428WithState
  recoveredAndroidKeyStoreKeyPair91428Regression
```

The regressions cover null generator, class/method/call failures, three pending
exception positions, null returned KeyPair, incoming nonzero status, provider
decode-once behavior, helper forwarding, all three outer failure stages, exact
short-circuiting, success reference transfer and two-output failure clearing.
