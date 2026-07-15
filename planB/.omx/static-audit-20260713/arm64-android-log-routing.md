# Android log routing

## Ranges

| Role | ARM64 | x86_64 |
|---|---|---|
| varargs adapter | `0x12fa24..0x12fab4` | `0x12a08e..0x12a130` |
| formatter/router | `0x12fab4..0x130098` | `0x12a130..0x12a4f8` |
| snprintf adapter | `0x130098..0x130128` | `0x12a4f8..0x12a59e` |
| no-op post hook | `0x130128..0x13012c` | `0x12a59e..0x12a59f` |
| Android log sink | `0x13012c..0x13063c` | `0x12a59f..0x12a8ff` |

## Source-level signature and flow

```cpp
void logf(const char* source,
          int sourceLine,
          int priorityIndex,
          const char* format,
          ...);
```

```text
message[0x400] = {0}
prefix[0x400] = {0}
vsnprintf(message, 0x400, format, args)

if source != null:
    snprintf(prefix, 0x400, "== %s@%d", source, sourceLine)
else:
    selectedPrefix = null

priority = {2, 3, 5, 6}[priorityIndex]
tag = "signer"

if selectedPrefix == null:
    __android_log_print(priority, tag, "%s", message)
else:
    __android_log_print(priority, tag, "%s: %s", prefix, message)
```

The table maps valid indices `0..3` to Android `VERBOSE`, `DEBUG`, `WARN`,
and `ERROR`. The native caller contract assumes an in-range index; the sink
does not expose a safe public bounds check.

The timestamp front end is the only direct `0x12fa24` caller. It passes
`source=null`, `sourceLine=0`, and `priorityIndex=0`, so both nSign timestamp
lines are emitted as:

```cpp
__android_log_print(ANDROID_LOG_VERBOSE, "signer", "%s", timestampLine);
```

Both `vsnprintf` return values and the `__android_log_print` return value are
ignored. This chain neither reads nor writes signer status and cannot clear or
replace the `jbyteArray` returned by the signing context.

## C++

- `recoveredBoundedSnprintf()`
- `modelRecoveredAndroidLogRoute()`
- `runRecovered12fa24Log()`
- `runRecoveredTimestampLog()` now continues through the recovered sink
