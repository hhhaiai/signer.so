# Three Signer Implementations Directory Design

## 1. Objective

Create three clearly separated entry directories for the signer work already present in this
workspace:

1. the source-recovered C++ implementation in `recovered_primitives.cpp`;
2. the JNI/ABI compatibility bridge that delegates to a caller-supplied official `libsigner.so`;
3. the Unidbg ARM64 emulation runner.

The reorganization must be non-destructive. Existing canonical source files remain in their current
locations, and the new directories provide stable build, validation, invocation, configuration, and
documentation entry points. No algorithm source is duplicated and no existing build path is moved.

## 2. Selected Approach

Create a new top-level directory:

```text
signer-implementations/
├── README.md
├── ARCHITECTURE.md
├── verify-all.sh
├── 01-recovered-cpp/
├── 02-vendor-jni-bridge/
└── 03-unidbg-runner/
```

The directories are numbered to make their distinction and intended comparison order explicit.
They are entry-point packages rather than copied source trees.

## 3. Canonical Source Ownership

### 3.1 Recovered C++

Canonical source:

```text
native-reimplementation/recovered_primitives.cpp
```

The new directory must not copy this file. Its scripts compile or inspect the canonical file by an
absolute path derived from the script location.

### 3.2 Vendor JNI bridge

Canonical sources:

```text
native-reimplementation/signer_jni_bridge.cpp
native-reimplementation/signer_jni_bridge.h
native-reimplementation/signer_backend.cpp
native-reimplementation/signer_backend.h
native-reimplementation/fake_signer_backend.cpp
native-reimplementation/fake_signer_backend.h
native-reimplementation/CMakeLists.txt
```

The production shared library is `libsigner_compat.so` or the platform-equivalent dynamic library.
It does not link `recovered_primitives.cpp`. Production configuration does not link the fake backend.

### 3.3 Unidbg runner

Canonical project:

```text
unidbg-adjust-runner/
```

The new directory wraps the Maven project and its Java entry points without copying Java sources or
the Maven project.

## 4. Required Directory Contents

### 4.1 `01-recovered-cpp`

```text
01-recovered-cpp/
├── README.md
├── build.sh
├── check.sh
├── run-example.sh
├── config/
│   └── input.env.example
└── docs/
    ├── INPUT_CONTRACT.md
    ├── COVERAGE.md
    └── SECURITY_BOUNDARY.md
```

Responsibilities:

- compile the canonical source into a local build directory;
- provide a compile-only strict check;
- document the `NativeInputs` contract and presence semantics;
- document the current FDE/JNI-reachable coverage rather than claiming full SO parity;
- keep execution explicit and opt-in;
- classify the implementation as audit-only and production-ineligible;
- never link it into `libsigner_compat.so`.

The example runner must not invent omitted runtime fields. It reads caller-supplied values from an
environment file or process environment and fails when a required field is absent. The checked-in
configuration file contains format examples, not production credentials or secret materials.

### 4.2 `02-vendor-jni-bridge`

```text
02-vendor-jni-bridge/
├── README.md
├── build-host.sh
├── build-android.sh
├── check.sh
├── config/
│   └── vendor.env.example
├── examples/
│   ├── native_install_example.cpp
│   └── java_call_example.java
└── docs/
    ├── JNI_ABI.md
    ├── LIFECYCLE.md
    └── ERROR_MODEL.md
```

Responsibilities:

- build the existing compatibility library without recovered signing code;
- document `libsigner_compat_install_vendor`, close, backend-kind, and last-error APIs;
- document the two JNI exports and the exact `nSign` Java descriptor;
- demonstrate that the caller supplies an absolute path to the official local library;
- document self-reference protection, exception mapping, backend lifecycle, and retained DSO handle
  behavior;
- keep the test-only fake backend out of production builds.

The example code documents integration and must not embed a machine-specific official library path.
The path comes from the caller or a local configuration environment variable.

### 4.3 `03-unidbg-runner`

```text
03-unidbg-runner/
├── README.md
├── build.sh
├── check.sh
├── run-one-click.sh
├── run-direct.sh
├── config/
│   ├── device-profile.example.json
│   └── request.example.json
└── docs/
    ├── EMULATION_MODEL.md
    ├── INPUT_CONTRACT.md
    └── TROUBLESHOOTING.md
```

Responsibilities:

- build the canonical `unidbg-adjust-runner` Maven project in offline mode by default;
- document `SignerOneClick`, `SignerDirectRunner`, `SignerEngine`, `AdjustSignatureRunner`,
  `DeviceProfile`, and `ConfigurableAndroidARM64Emulator` roles;
- provide JSON-driven invocation examples using only local workspace artifacts;
- document virtual Android fields, files, properties, certificates, sensors, sockets, API level, and
  request parameters;
- distinguish execution of the original ARM64 SO from the source-recovered C++ path;
- avoid Internet access and external hosts.

Example configuration uses synthetic test values and identifies them as examples. It does not
contain extracted credentials, device secrets, certificates with private material, or authentication
state.

## 5. Top-Level Documentation

`signer-implementations/README.md` must contain a selection matrix:

| Implementation | Reimplements native algorithm | Loads official SO | Emulates ARM64 | Primary role |
|---|---:|---:|---:|---|
| Recovered C++ | Yes, with documented remaining unknown functions | No | No | Static recovery and regression |
| Vendor JNI bridge | No | Yes | No | JNI/ABI-compatible local delegation |
| Unidbg runner | No; executes ARM64 code | Yes | Yes | Isolated behavioral observation and parity |

`ARCHITECTURE.md` must show each call chain and explicitly state that the three implementations are
alternatives with different trust and runtime models, not layers that must be chained together.

## 6. Invocation Model

### 6.1 Recovered C++

```text
caller fields -> CLI parser -> NativeInputs -> sign() -> byte vector
```

Build and compile-only checks are safe defaults. Signature execution is an explicit separate command.

### 6.2 Vendor JNI bridge

```text
Java NativeLibHelper -> libsigner_compat JNI export -> SignerCompatibilityLayer
-> VendorSignerBackend -> dlopen/dlsym -> official local libsigner.so JNI export
```

The official path is supplied by the caller and must be absolute. The compatibility library and
official library must have distinct filenames/SONAMEs.

### 6.3 Unidbg

```text
JSON device/request configuration -> Java runner -> Unidbg Android ARM64 emulator
-> locally loaded ARM64 libsigner.so -> emulated JNI -> structured result
```

Unidbg execution is local emulation, not a native Android process and not a C++ algorithm rewrite.

## 7. Error Handling

- Shell scripts use `set -euo pipefail`, validate required tools and inputs, and emit actionable
  errors to stderr.
- Recovered C++ invocation preserves the canonical program's argument validation and refuses missing
  strict inputs.
- Vendor bridge documentation maps `SignerError` values to C API status and Java exception classes.
- Unidbg wrappers validate that the Maven project, input JSON, and local library/artifact paths exist
  before invoking Java.
- No wrapper silently selects a production library, device profile, certificate, key, or backend.

## 8. Verification

Top-level `verify-all.sh` performs non-sensitive checks only:

1. validates all required directory files;
2. runs strict compile-only validation for `recovered_primitives.cpp`;
3. builds and tests the JNI compatibility layer;
4. runs its non-sensitive boundary audit;
5. compiles/tests the Unidbg Maven project offline where dependencies are already present;
6. validates example JSON syntax;
7. does not execute recovered signature generation;
8. does not invoke the official SO through Unidbg;
9. does not access the Internet or external hosts.

## 9. Non-Goals

- Do not move existing canonical source files.
- Do not duplicate recovered algorithm source.
- Do not combine recovered signing code with the production compatibility library.
- Do not make Unidbg a production signing backend.
- Do not add credential extraction, authentication bypass, privilege escalation, persistence, or
  external network functionality.
- Do not claim all 388 ARM64 FDE functions are recovered while unknown functions remain.
- Do not repair unrelated stale documentation outside the new three-directory documentation set.

## 10. Acceptance Criteria

- All three numbered directories exist with the documented files.
- Each directory independently answers: what it is, what it depends on, how to build it, how to call
  it, what it returns, how it fails, and whether it is production-eligible.
- All wrapper paths are derived from their location and do not require the current working directory
  to be the repository root.
- The recovered check passes under C++17 with `-Wall -Wextra -Werror -fsyntax-only`.
- The compatibility layer's existing host tests pass and its production artifact contains no
  recovered implementation markers.
- Unidbg wrapper checks run offline and validate examples without loading a target SO during the
  top-level safe verification.
- No existing canonical source is moved or duplicated.
