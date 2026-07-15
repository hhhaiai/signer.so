# ARM64 native signing-context orchestrator

This report reads existing ARM64/x86_64 objdump text only. It does not load or
execute `libsigner.so`.

## `0xcc47c` realtime helper

ARM64 `0xcc47c..0xcc600` and x86_64 `0xbb5b8..0xbb6a6` are equivalent:

```text
clock_gettime(CLOCK_REALTIME, &timespec)
success -> seconds * 1000.0 + nanoseconds / 1000000.0
failure + non-null status -> *status = 14, return 0.0
failure + null status     -> return 0.0 without a write
```

There is no `-ENOSYS`/`gettimeofday` fallback here. That fallback belongs to
the separate `0xd184` helper.

## `0xcbe98` loaded-input contract

The outer 0x28-byte descriptor is assumed accessible. Native code
unconditionally dereferences its four pointer slots before checking their
pointee values:

| descriptor offset | loaded value |
|---:|---|
| `+0x00` | `JNIEnv*` |
| `+0x08` | pointer to Java Context reference |
| `+0x10` | pointer to Java Map reference |
| `+0x18` | pointer to supplied Java-HMAC byte-array reference |
| `+0x20` | pointer to Android API integer |

The post-dereference gate accepts only:

```text
androidApi >= 1
JNIEnv != null
Context != null
Map != null
supplied Java HMAC != null
```

An invalid loaded value returns null. It is not safe to pass a null outer
descriptor or null pointer slot, because those are dereferenced before the
gate.

## Valid-path order

```text
0xcc47c CLOCK_REALTIME helper
memset(context+0x08, 0, 0x120)
store timing at +0x00, API at +0x0c, Map at +0x10
0x134a1c descriptor/correction initialization
zero 20-byte context+0xf0 region
0xd466c
0x1e578 certificate/digest stage
  nonzero status -> reset status to zero and continue
0xcba90 native context init stage 1
0xcbbd4 native context init stage 2
0x143e8 environment dispatcher
0xd6888 post-environment stage
0xf224 timing correction gate
0x11da64 final consumer
```

The final consumer's boolean result only selects the flattened cleanup entry;
both values converge to the same ownership cleanup. `0xcbe98` returns the
reference stored at context `+0x18`.

## Cleanup order

```text
if context+0x108 != null: free and clear it
if context+0x110 != null: free and clear it
free(context+0x120) unconditionally
return context+0x18
```

The C++ model is `modelRecoveredSigningContextOrchestrator()`, and the exact
clock helper is `recoveredSigningContextClockMilliseconds()`.
