# Caller-supplied runtime input boundary

Date: 2026-07-15

## Decision

Runtime/device facts are caller-owned inputs.  The recovered C++ path may keep
only constants proven to belong to the original protocol or algorithm, such as
property names, JNI names/signatures, descriptor tags, bit masks, offsets,
correction identifiers and XOR-once strings.  It must not silently replace an
omitted runtime value with Pixel, Google, host-machine or fabricated data.

## C++ input surfaces

| Runtime fact | Caller-supplied surface | Missing versus zero |
| --- | --- | --- |
| 13 Android property values | `RecoveredDetectorInputProfile8746c::propertyValues` plus `propertyProvided` | Empty string is valid when its presence bit is true; missing rejects unless the caller explicitly selects `UseEmptyString` |
| Display width/height | `displayWidth`, `displayHeight`, `displayMetricsProvided` | Numeric zero remains distinct from an omitted display record |
| Sensor name/vendor list | `sensorNameVendorPairs`, `sensorListProvided` | An explicitly supplied empty list is distinct from a missing list |
| HWCAP/HWCAP2 and auxiliary descriptor | `RecoveredCpuFeatureDecoderInput1398cc` value fields plus `*Provided` flags | All-zero snapshots are valid values and do not mean missing |
| `ID_AA64PFR0/1`, `ZFR0`, `ISAR0/1` | `RecoveredCpuFeatureDecoderInput1398cc` value fields plus `*Provided` flags | Conditional requirements follow the recovered HWCAP/SVE branches |
| JNIEnv, PackageInfo, SigningInfo, Cipher, Key and returned Java objects | Function arguments and caller-supplied JNI operation tables | The recovery forwards actual handles and never creates substitute Java objects |
| Signer time, correction list, field 2, certificate SHA-1, plaintext and state | `NativeInputs`; standalone CLI uses `NativeInputPresence` | `0`, `false`, empty correction list and empty plaintext are valid explicit inputs; omitted fields fail |

## Standalone CLI boundary

Normal CLI use starts from `NativeInputs{}` and requires all six materialized
signer fields:

```text
--time-seconds
--correction-codes
--urandom-hex
--certificate-sha1
--native-plaintext-hex or --param-hex
--state
```

`--use-regression-fixture` is the only path that loads the frozen Pixel oracle
values.  It is intended for regression replay and is explicit at the call
site.  `--signer-code-trampoline-detected` is restricted to that fixture mode;
strict callers provide the complete correction list instead of inheriting the
fixture's correction vector.

The three optional Java HMAC values also have independent presence bits, so an
explicitly supplied empty byte sequence is not mistaken for an omitted CLI
argument.  If one is supplied, all three must be supplied.

## Java adapter boundary

`RecoveredNativeBackend` now requires `runtime.timeSeconds` and at least four
bytes of `runtime.urandomHex`, then forwards both to the recovered C++ process.
It no longer substitutes the host wall clock and no longer relies on the C++
regression fixture for field 2.  The frozen example job contains its urandom
bytes explicitly.

## Validation

- C++17 `-Wall -Wextra -Werror -fsyntax-only`: PASS.
- Strict partial CLI input: rejected with an explicit missing-field list.
- Strict all-zero/false/empty CLI input: accepted and produced
  `SIGNATURE_HEX`, proving value and presence are separate.
- Existing original-SO C++ oracle matrix: PASS.
- ASan+UBSan base, partial-input and explicit-zero paths: PASS with leak
  detection disabled for compatibility fixtures.
- Frozen recovered Java-to-C++ backend: exact reference match PASS.
- Offline `RecoveredNativeBackendIntegrationTest`: 21 tests, 0 failures,
  0 errors, 0 skipped.
- Missing Java `runtime.timeSeconds` and `runtime.urandomHex`: both rejected at
  the adapter boundary with specific diagnostics.

