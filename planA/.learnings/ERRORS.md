# Errors

## [ERR-20260710-001] python-json-tool-import-shadowing

**Logged**: 2026-07-10T16:20:00+08:00
**Priority**: medium
**Status**: resolved
**Area**: infra

### Summary
`python3 -m json.tool` failed because the active Python standard-library `argparse.py` unexpectedly imports unavailable `requests`.

### Error

```text
ModuleNotFoundError: No module named 'requests'
```

### Context

- Occurred while formatting Maven Central/GitHub API JSON.
- Active executable was `/opt/local/bin/python3`, while modules were loaded from `/Library/Frameworks/Python.framework/Versions/3.11/lib/python3.11`.

### Suggested Fix

Use installed `jq` for JSON inspection in this workspace rather than repeating the broken `python3 -m json.tool` path.

### Metadata

- Reproducible: yes
- Related Files: `task_plan.md`

### Resolution

- **Resolved**: 2026-07-10T16:21:00+08:00
- **Notes**: Switched JSON parsing to `/usr/local/bin/jq`; Maven response parsed successfully.

---

## [ERR-20260710-010] missing-message-digest-update

**Logged**: 2026-07-10T17:13:00+08:00
**Priority**: medium
**Status**: resolved
**Area**: tests

### Summary
The live certificate digest path uses incremental `MessageDigest.update(byte[])` followed by `digest()` rather than only `digest(byte[])`.

### Error

```text
UnsupportedOperationException: java/security/MessageDigest->update([B)V
```

### Context

- This refines the JNI call sequence for certificate hashing.

### Suggested Fix

Bridge V/non-V `update([B)V`, `digest()[B`, and `digest([B)[B` to the same host MessageDigest instance.

### Metadata

- Reproducible: yes
- Related Files: `runtime/unidbg/src/main/java/com/adjust/research/AndroidRuntimeJni.java`

### Resolution

- **Resolved**: 2026-07-10T17:14:00+08:00
- **Notes**: Added incremental digest bridge methods.

---

## [ERR-20260710-009] missing-message-digest-factory

**Logged**: 2026-07-10T17:10:00+08:00
**Priority**: medium
**Status**: resolved
**Area**: tests

### Summary
After certificate bridging, native execution reached Java certificate hashing and required `MessageDigest.getInstance(String)`.

### Error

```text
UnsupportedOperationException: java/security/MessageDigest->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;
```

### Context

- The failure occurs after `PackageInfo.signatures` and `Signature.toByteArray()`, confirming certificate digesting is on the live path.

### Suggested Fix

Bridge the static factory to host JCA and retain unidbg's existing `MessageDigest.digest([B)` support.

### Metadata

- Reproducible: yes
- Related Files: `runtime/unidbg/src/main/java/com/adjust/research/AndroidRuntimeJni.java`

### Resolution

- **Resolved**: 2026-07-10T17:11:00+08:00
- **Notes**: Added static V/non-V MessageDigest factory bridging.

---

## [ERR-20260710-008] unidbg-missing-package-signatures-and-debugger-hang

**Logged**: 2026-07-10T17:06:00+08:00
**Priority**: high
**Status**: resolved
**Area**: tests

### Summary
The first real native smoke run reached certificate inspection but lacked `PackageInfo.signatures`; with no SLF4J provider, unidbg entered its interactive debugger and left the Surefire child running.

### Error

```text
UnsupportedOperationException: android/content/pm/PackageInfo->signatures:[Landroid/content/pm/Signature;
```

### Context

- This is the first genuine JNI boundary after `Context.getPackageName()` was fixed.
- The stuck Surefire child PIDs were inspected and terminated explicitly.

### Suggested Fix

Provide deterministic certificate bytes through `PackageInfo.signatures` and `Signature.toByteArray()`. Install an SLF4J provider at WARN/INFO so unidbg reports exceptions instead of opening an interactive debugger in CI.

### Metadata

- Reproducible: yes
- Related Files: `runtime/unidbg/src/main/java/com/adjust/research/AndroidRuntimeJni.java`, `runtime/unidbg/pom.xml`

### Resolution

- **Resolved**: 2026-07-10T17:08:00+08:00
- **Notes**: Added configurable certificate bytes and `slf4j-simple`; subsequent failures remain non-interactive and diagnostic.

---

## [ERR-20260710-007] dvm-class-name-format

**Logged**: 2026-07-10T17:00:00+08:00
**Priority**: low
**Status**: resolved
**Area**: tests

### Summary
The test expected an internal JVM slash name from `DvmClass.getName()`, but unidbg returns the dotted Java name.

### Error

```text
expected: <java/util/Map> but was: <java.util.Map>
```

### Context

- JNI signatures still use slash names; `DvmClass.getName()` is a presentation/API detail and returns dotted names.

### Suggested Fix

Assert the actual public API representation and keep JNI descriptor assertions separate.

### Metadata

- Reproducible: yes
- Related Files: `runtime/unidbg/src/test/java/com/adjust/research/AndroidRuntimeJniTest.java`

### Resolution

- **Resolved**: 2026-07-10T17:01:00+08:00
- **Notes**: Updated the class-name assertion to `java.util.Map`.

---

## [ERR-20260710-006] unidbg-vm-interface-vs-basevm

**Logged**: 2026-07-10T16:57:00+08:00
**Priority**: low
**Status**: resolved
**Area**: tests

### Summary
The JNI unit test passed the public `VM` interface to an `AbstractJni` method whose compile-time parameter is `BaseVM`.

### Error

```text
VM cannot be converted to BaseVM
```

### Context

- `emulator.createDalvikVM()` returns the `VM` interface even though the runtime implementation derives from `BaseVM`.

### Suggested Fix

Cast to `BaseVM` only in direct JNI-dispatch tests; keep production APIs typed to `VM` where possible.

### Metadata

- Reproducible: yes
- Related Files: `runtime/unidbg/src/test/java/com/adjust/research/AndroidRuntimeJniTest.java`

### Resolution

- **Resolved**: 2026-07-10T16:58:00+08:00
- **Notes**: Added the explicit test-only cast.

---

## [ERR-20260710-005] maven-default-source-5

**Logged**: 2026-07-10T16:52:00+08:00
**Priority**: medium
**Status**: resolved
**Area**: tests

### Summary
The first Maven RED run failed before reaching the intended missing implementation because Maven's default compiler plugin 3.1 selected obsolete source/target 5.

### Error

```text
不再支持源选项 5。请使用 7 或更高版本。
不再支持目标选项 5。请使用 7 或更高版本。
```

### Context

- The POM set `maven.compiler.release=11` but did not pin a compiler plugin that understands the `release` property.

### Suggested Fix

Pin `maven-compiler-plugin` 3.11.0 and configure `<release>11</release>` explicitly.

### Metadata

- Reproducible: yes
- Related Files: `runtime/unidbg/pom.xml`

### Resolution

- **Resolved**: 2026-07-10T16:53:00+08:00
- **Notes**: Added compiler plugin 3.11.0; the next RED run can now reach `HmacInputBuilder` compilation.

---

## [ERR-20260710-004] resource-copy-relative-path

**Logged**: 2026-07-10T16:48:00+08:00
**Priority**: low
**Status**: resolved
**Area**: tests

### Summary
The first Task 1 test command used a workspace-root-relative sample path while its working directory was already `runtime/unidbg`.

### Error

```text
missing file/path while copying jni/arm64-v8a/libsigner.so
```

### Context

- Command workdir: `/Users/sanbo/Desktop/p/runtime/unidbg`
- Incorrect source: `jni/arm64-v8a/libsigner.so`
- Correct source: `../../jni/arm64-v8a/libsigner.so`

### Suggested Fix

Verify `pwd` and source paths before grouped build commands; use a workdir-relative path or absolute workspace path consistently.

### Metadata

- Reproducible: yes
- Related Files: `runtime/unidbg/src/main/resources/arm64-v8a/libsigner.so`

### Resolution

- **Resolved**: 2026-07-10T16:49:00+08:00
- **Notes**: Corrected the source to `../../jni/arm64-v8a/libsigner.so` before rerunning the RED test.

---

## [ERR-20260710-003] unavailable-maven-version

**Logged**: 2026-07-10T16:34:00+08:00
**Priority**: low
**Status**: resolved
**Area**: infra

### Summary
Bulk AAR download stopped on metadata-listed version `3.35.1`, whose AAR URL returns 404.

### Error

```text
curl: (22) The requested URL returned error: 404
```

### Context

- Initial loop used `set -e`, so one unavailable historical artifact aborted the version comparison.

### Suggested Fix

Handle each historical version independently, remove partial files, and continue the matrix when one version is unavailable.

### Metadata

- Reproducible: yes
- Related Files: `analysis/upstream/adjust-signature/version-matrix.tsv`

### Resolution

- **Resolved**: 2026-07-10T16:35:00+08:00
- **Notes**: Re-ran with per-version error handling; all available versions were compared and 3.62.0 matched exactly.

---

## [ERR-20260710-002] grep-app-vercel-challenge

**Logged**: 2026-07-10T16:28:00+08:00
**Priority**: low
**Status**: resolved
**Area**: infra

### Summary
`grep.app` API returned HTTP 429 with a Vercel challenge instead of code-search JSON.

### Error

```text
HTTP/2 429
x-vercel-mitigated: challenge
```

### Context

- Queries targeted the public class name `NativeLibHelper` and the recovered JNI descriptor.

### Suggested Fix

Do not retry the challenged endpoint repeatedly. Use Maven Central metadata, upstream repositories, or downloaded AAR inspection instead.

### Metadata

- Reproducible: yes
- Related Files: `findings.md`

### Resolution

- **Resolved**: 2026-07-10T16:30:00+08:00
- **Notes**: Maven Central search found the official `com.adjust.signature:adjust-android-signature` artifact.

---
## [ERR-20260710-INIT] skill-creator-init-permission

**Logged**: 2026-07-10T16:00:00+08:00
**Priority**: low
**Status**: resolved
**Area**: tooling

### Summary
`skill-creator/scripts/init_skill.py` is readable but not executable, so direct invocation fails.

### Error
```text
command/setup failure: permission denied
```

### Context
- Attempted direct execution of `/Users/sanbo/.codex/skills/.system/skill-creator/scripts/init_skill.py --help`.
- File mode is `-rw-r--r--` and the shebang is `#!/usr/bin/env python3`.

### Suggested Fix
Invoke it explicitly with `python3` rather than changing the installed system skill's permissions.

### Metadata
- Reproducible: yes
- Related Files: `/Users/sanbo/.codex/skills/.system/skill-creator/scripts/init_skill.py`

---
## [ERR-20260710-FWD] skill-forward-test-environment

**Logged**: 2026-07-10T17:35:00+08:00
**Priority**: medium
**Status**: partially resolved
**Area**: tooling

### Summary
The first isolated Codex skill forward-test exposed a broken default `python3`; a Claude Code forward-test could not start because the local CLI is not authenticated.

### Error
```text
default /opt/local/bin/python3: argparse imports a non-stdlib requests module and aborts
Claude Code: Not logged in; Please run /login
```

### Context
- The installed skill utilities themselves passed under `/usr/local/bin/python3`.
- The skill now exposes direct shell wrappers that probe a healthy Python interpreter.
- A fresh native Codex subagent forward-test was started after the wrapper fix.

### Suggested Fix
Keep command wrappers interpreter-selecting; authenticate Claude Code before repeating its model-level forward-test.

### Metadata
- Reproducible: yes
- Related Files: `~/.codex/skills/android-so-reversing/scripts/python_runner.sh`

---

## [ERR-20260710-TRACE] unidbg-hook-detach-crash

**Logged**: 2026-07-10T17:35:00+08:00
**Priority**: high
**Status**: resolved
**Area**: tests

### Summary
Calling `UnHook.unhook()` from inside a Unicorn2 `CodeHook` callback terminated the forked JVM with exit 134.

### Error
```text
Surefire forked VM terminated; Process Exit Code: 134
```

### Context
- The initial TraceRecorder detached immediately after reaching its event cap.
- The crash disappeared after keeping the hook attached until `close()`, limiting the hook range to the real nSign body, and ignoring events after the cap.

### Suggested Fix
Never detach a Unicorn2 hook from its own callback; defer unhooking until emulation returns.

### Metadata
- Reproducible: yes
- Related Files: `runtime/unidbg/src/main/java/com/adjust/research/TraceRecorder.java`

---
