# ARM64 module runtime scaffolding and CPU-feature constructor

## Scope

This batch closes six non-JNI-reachable ARM64 FDEs:

```text
0x8070..0x8080   module DSO finalizer wrapper
0x8080..0x8088   no-op callback
0x8088..0x8090   no-op callback tail alias
0x8090..0x80a4   nullable exit-callback dispatcher
0x80a4..0x80c0   __cxa_atexit registration wrapper
0x139d04..0x139d9c AArch64 CPU-feature constructor wrapper
```

These are compiler/runtime initialization functions rather than signer data
transformations, but they are part of the target ELF's authoritative 388-FDE
inventory and therefore part of the all-function recovery objective.

## `0x8070..0x80c0`

### DSO finalization

`0x8070` computes the image-local handle at `0x13e170` and tail-calls:

```c
__cxa_finalize(dsoHandle);
```

The C++ model injects both the relocated DSO handle and finalizer callback so
it does not invent a fixed host address.

### No-op and alias

`0x8080` is exactly `BTI c; RET`. `0x8088` is `BTI c` followed by a tail branch
to `0x8080`. They have the same source-level no-op behavior but remain distinct
coverage rows.

### Nullable callback dispatcher

`0x8090` implements:

```cpp
if (callback != nullptr) callback();
```

The non-null path uses `BR x16`, so it is a tail invocation. The null path
returns directly.

### Atexit registration

`0x80a4` registers `0x8090` as the destructor callback, the incoming function
pointer as its argument, and the same image-local DSO handle:

```c
return __cxa_atexit(dispatcher8090, incomingCallback, dsoHandle);
```

The registration return value is preserved.

## `0x139d04` CPU-feature constructor wrapper

The wrapper first reads the process-global feature word at `0x146bb8`. A
nonzero value returns immediately without property or aux-vector reads.

On the cold path:

```text
__system_property_get("ro.arch", buffer)
if returned length >= 1 and strncmp(buffer,"exynos9810",10) == 0:
    return
hwcap  = getauxval(AT_HWCAP=16)
hwcap2 = getauxval(AT_HWCAP2=26)
descriptor = {24, hwcap, hwcap2}
0x1398cc(hwcap | 0x4000000000000000, descriptor)
```

The ten-byte comparison is a prefix check, so `exynos9810-extra` also skips
initialization. A missing property does not skip it.

The `0x4000000000000000` bit tags the supplied descriptor. The wrapper stores
`24`, HWCAP and HWCAP2 consecutively at stack bytes `+0x08/+0x10/+0x18`, then
passes `sp+0x08` to `0x1398cc`.

`0x1398cc..0x139d04` remains a separate FDE and is now independently recovered
in `.omx/static-audit-20260713/arm64-cpu-feature-decoder-1398cc.md`.  The wrapper
evidence here still does not stand in for the decoder evidence.

## C++ symbols

```text
RecoveredModuleRuntimeOperations8070
runRecoveredModuleFinalize8070
runRecoveredModuleNoOp8080
runRecoveredModuleNoOpAlias8088
runRecoveredModuleExitDispatcher8090
runRecoveredModuleAtExitRegistration80a4
recoveredModuleRuntimeScaffolding8070Regression

RecoveredCpuFeatureConstructorOperations139d04
runRecoveredCpuFeatureConstructor139d04
recoveredCpuFeatureConstructor139d04Regression

RecoveredCpuFeatureDecoderInput1398cc
RecoveredCpuFeatureDecoderOutput1398cc
runRecoveredCpuFeatureDecoder1398cc
recoveredCpuFeatureDecoder1398ccRegression
```

## Verifiers

```bash
python3 .omx/static-audit-20260713/analyze_module_runtime_scaffolding_8070.py
python3 .omx/static-audit-20260713/analyze_cpu_feature_constructor_139d04.py
python3 .omx/static-audit-20260713/analyze_cpu_feature_decoder_1398cc.py
```

The first verifier locks all instructions from `0x8070` through `0x80bc` and
checks the callback-driven C++ model and coverage rows. The second verifies the
raw `ro.arch`/`exynos9810` bytes, global gate, ten-byte prefix comparison,
ordered aux-vector reads, descriptor construction, tagged call argument,
regression guard and the separately recovered status of `0x1398cc`.  The third
verifier locks the decoder's descriptor selection, five `ID_AA64*` reads,
intermediate global stores, caller-presence gates and final bit-58 publication.

## Coverage effect

Together with the preceding context-flag/no-op batch, the authoritative matrix
is now:

```text
319 recovered / 0 partial / 69 unknown
JNI-reachable: 276 recovered / 0 partial / 45 unknown
```
