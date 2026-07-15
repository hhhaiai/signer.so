# TracerPid periodic callback and consumer

## Ranges

- ARM64 callback: `0xd4e0c..0xd6888`
- x86_64 callback: `0xc2115..0xc3126`
- ARM64 consumer: `0xd6888..0xd6994`
- x86_64 consumer: `0xc3126..0xc31ce`

## Static strings

| ABI | address | transform | plaintext |
|---|---:|---:|---|
| ARM64 | `0x145898` | XOR `0xf6` | `TracerPid:` |
| ARM64 | `0x1458b0` | XOR `0x78` | `/proc/%d/status` |
| x86_64 | `0x13e328` | XOR `0x74` | `TracerPid:` |
| x86_64 | `0x13e340` | XOR `0x24` | `/proc/%d/status` |

The strings are decoded once under byte-sized atomic/CAS guards. These guards
are initialization locks, not alternate cipher selectors.

## Callback behavior

The callback keeps a process-global sticky verdict. When it is not already
set, it obtains the PID, formats `/proc/<pid>/status`, checks readability,
opens with `openat(AT_FDCWD, path, O_RDONLY, 0)`, reads at most `0x800` bytes,
and closes the descriptor even when `read` fails. It searches for
`TracerPid:` using ASCII case-insensitive byte comparison and parses the
suffix with the SO's whitespace/sign/decimal `atoi` behavior. A nonzero value
sets the sticky verdict to one; ordinary path/open/read/marker failures leave
the previous verdict unchanged.

ARM64 direct syscall numbers are `56` for `openat` and `172` for `getpid`;
x86_64 uses `257` and `39` respectively.

## Context consumer

`0xd6888` reads the sticky verdict after the environment dispatcher:

```text
if tracerDetected:
    write correction 0x26
    context.flags |= 1
context.flags |= 0x0000004000000000  // bit 38
```

Thus correction `0x26` is the native `/proc/<pid>/status` TracerPid verdict,
not a cryptographic algorithm-selection signal.

## C++

- `modelRecoveredTracerPidProbe()`
- `runRecoveredTracerPidPeriodicCallback()`
- `applyRecoveredTracerPidPostStage()`

The model accepts injected syscall outcomes/status bytes and never reads the
host `/proc` filesystem during regression.
