# Three Signer Implementations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add three clearly separated, documented, and callable entry directories under `/Users/sanbo/Desktop/api/qbdi/signer-implementations` without moving or duplicating canonical implementation sources.

**Architecture:** The new directories are thin entry packages over the existing recovered C++ source, vendor JNI bridge source set, and Maven Unidbg runner. All scripts derive the project root from their own location, use local artifacts only, and keep build/check operations separate from explicit execution operations.

**Tech Stack:** Bash, C++17/Clang or GCC, CMake, JNI, Android NDK, Java 11+, Maven, Unidbg 0.9.9, JSON.

## Global Constraints

- Canonical sources remain in `native-reimplementation/` and `unidbg-adjust-runner/`.
- Do not copy or move `recovered_primitives.cpp`.
- Do not link recovered signing code into `libsigner_compat.so`.
- Safe verification must not execute recovered signing or load the official SO through Unidbg.
- All paths must be local to `/Users/sanbo/Desktop/api/qbdi`; no Internet or external host access.
- Runtime fields are caller supplied; scripts must not synthesize omitted values.
- Example data must be synthetic and must not contain credentials, device secrets, or private certificate material.

---

### Task 1: Layout contract test and top-level navigation

**Files:**
- Create: `signer-implementations/test-layout.sh`
- Create: `signer-implementations/README.md`
- Create: `signer-implementations/ARCHITECTURE.md`

**Interfaces:**
- Consumes: the three directory names approved in the design.
- Produces: a repository-level navigation and structural validation entry point.

- [ ] Write `test-layout.sh` so it checks every required directory, script, example, and document.
- [ ] Run it before creating the directories and verify it fails because required files are absent.
- [ ] Add the top-level README selection matrix and architecture call chains.
- [ ] Keep the layout test failing until Tasks 2-4 create all required files.

### Task 2: Recovered C++ entry package

**Files:**
- Create: `signer-implementations/01-recovered-cpp/README.md`
- Create: `signer-implementations/01-recovered-cpp/build.sh`
- Create: `signer-implementations/01-recovered-cpp/check.sh`
- Create: `signer-implementations/01-recovered-cpp/run-example.sh`
- Create: `signer-implementations/01-recovered-cpp/config/input.env.example`
- Create: `signer-implementations/01-recovered-cpp/docs/INPUT_CONTRACT.md`
- Create: `signer-implementations/01-recovered-cpp/docs/COVERAGE.md`
- Create: `signer-implementations/01-recovered-cpp/docs/SECURITY_BOUNDARY.md`

**Interfaces:**
- Consumes: `native-reimplementation/recovered_primitives.cpp` and caller-supplied strict CLI fields.
- Produces: `signer-implementations/01-recovered-cpp/build/recovered-primitives` and compile-only validation.

- [ ] Add a strict compile-only script using C++17, `-Wall`, `-Wextra`, and `-Werror`.
- [ ] Add a build script producing a local executable without modifying the canonical build directory.
- [ ] Add an explicit runner that requires a caller-selected environment file and checks every mandatory field before invoking the executable.
- [ ] Document the six `NativeInputs` fields, presence semantics, output, 348/388 FDE coverage, 299/321 JNI-reachable coverage, and audit-only boundary.

### Task 3: Vendor JNI bridge entry package

**Files:**
- Create: `signer-implementations/02-vendor-jni-bridge/README.md`
- Create: `signer-implementations/02-vendor-jni-bridge/build-host.sh`
- Create: `signer-implementations/02-vendor-jni-bridge/build-android.sh`
- Create: `signer-implementations/02-vendor-jni-bridge/check.sh`
- Create: `signer-implementations/02-vendor-jni-bridge/config/vendor.env.example`
- Create: `signer-implementations/02-vendor-jni-bridge/examples/native_install_example.cpp`
- Create: `signer-implementations/02-vendor-jni-bridge/examples/java_call_example.java`
- Create: `signer-implementations/02-vendor-jni-bridge/docs/JNI_ABI.md`
- Create: `signer-implementations/02-vendor-jni-bridge/docs/LIFECYCLE.md`
- Create: `signer-implementations/02-vendor-jni-bridge/docs/ERROR_MODEL.md`

**Interfaces:**
- Consumes: caller-supplied absolute official SO path and the canonical CMake project.
- Produces: host/Android `libsigner_compat` artifacts and integration examples.

- [ ] Add host and Android build wrappers around the existing CMake project.
- [ ] Add a check wrapper that runs existing host tests and the non-sensitive boundary audit.
- [ ] Add C++ installation and Java JNI call examples without machine-specific official library paths.
- [ ] Document exports, JNI descriptor, error mapping, backend replacement, close behavior, and self-reference prevention.

### Task 4: Unidbg entry package

**Files:**
- Create: `signer-implementations/03-unidbg-runner/README.md`
- Create: `signer-implementations/03-unidbg-runner/build.sh`
- Create: `signer-implementations/03-unidbg-runner/check.sh`
- Create: `signer-implementations/03-unidbg-runner/run-one-click.sh`
- Create: `signer-implementations/03-unidbg-runner/run-direct.sh`
- Create: `signer-implementations/03-unidbg-runner/config/device-profile.example.json`
- Create: `signer-implementations/03-unidbg-runner/config/request.example.json`
- Create: `signer-implementations/03-unidbg-runner/docs/EMULATION_MODEL.md`
- Create: `signer-implementations/03-unidbg-runner/docs/INPUT_CONTRACT.md`
- Create: `signer-implementations/03-unidbg-runner/docs/TROUBLESHOOTING.md`

**Interfaces:**
- Consumes: local JSON configuration, the canonical Maven project, and local workspace artifacts.
- Produces: Java build/test results and explicit Unidbg execution entry points.

- [ ] Add an offline Maven package wrapper and an offline non-native unit-test check.
- [ ] Add one-click invocation through `local.SignerOneClick`.
- [ ] Add direct invocation through `local.AdjustSignatureRunner` with explicit mode and optional parameter file.
- [ ] Add synthetic JSON examples and document emulator, profile, request, output, and local-only boundaries.

### Task 5: Safe aggregate verification

**Files:**
- Create: `signer-implementations/verify-all.sh`
- Modify: `signer-implementations/test-layout.sh` only if validation exposes a missing declared path.

**Interfaces:**
- Consumes: the three package-level check scripts.
- Produces: one non-sensitive verification result without signing or target-SO execution.

- [ ] Make all shell scripts executable.
- [ ] Run `test-layout.sh` and verify it passes.
- [ ] Run recovered compile-only validation.
- [ ] Run bridge tests and boundary checks.
- [ ] Validate both JSON files with Python's standard JSON parser.
- [ ] Run the Unidbg offline non-native check.
- [ ] Run `verify-all.sh` and record exact pass/fail evidence.
