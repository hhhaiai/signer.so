# ARM64 `/proc/self/cmdline` owned-string producer (`0x1709c`)

## Scope

- ARM64 FDE: `0x1709c..0x179f8`
- x86_64 peer: `0x18909..0x18fe3`
- Sole caller:
  - ARM64 `0xcde4..0xd184`, call `0xce4c`
  - x86_64 `0x111bc..0x11519`, call `0x1121f`
- ABI:

```text
ARM64:  x0 = uint32_t* status, x1 = char** output
x86_64: rdi = uint32_t* status, rsi = char** output
```

Read-only verifier:

```text
.omx/static-audit-20260713/analyze_proc_self_cmdline_owned_string_1709c.py
```

Formal closure state after generator regeneration:

```text
all FDEs:      347 recovered / 0 partial / 41 unknown
JNI reachable: 298 recovered / 0 partial / 23 unknown
```

## XOR-once path

| ABI | encoded VMA | length | XOR | decoded |
|---|---:|---:|---:|---|
| ARM64 | `0x1430d0` | 19 | `0xb7` | `/proc/self/cmdline\0` |
| x86_64 | `0x13baa0` | 19 | `0xc5` | `/proc/self/cmdline\0` |

ARM64 state is `lock=0x146440`, `initialized=0x146441`; x86_64 is
`lock=0x13ed28`, `initialized=0x13ed29`.  Both ABIs acquire/release the same
decode-once state twice on the full success path: once before `access`, then
again before `openat`.  The bytes are XOR-decoded only when `initialized==0`.

## Exact recovered flow

```cpp
void produceCmdline(uint32_t* status, char** output) {
    const char* path = acquireDecodedCmdlinePath();
    uint8_t stackBuffer[4096];

    if (access(path, R_OK /* 4 */) != 0) {
        *status = 8;
        return;                         // output untouched
    }

    path = acquireDecodedCmdlinePath();
    int fd = openat(AT_FDCWD /* -100 */, path,
                    O_RDONLY /* 0 */, 0);
    if (fd == -1) {
        *status = 12;
        return;                         // output untouched
    }

    int64_t count = read(fd, stackBuffer, 0x0fff);
    close(fd);                           // unconditional; return ignored

    if (count == 0) {
        *status = 8;
        return;                         // output untouched
    }

    uint64_t nativeCount = (uint64_t)count;
    char* owned = (char*)malloc(nativeCount + 1); // wrapping add
    if (owned == nullptr) {
        *output = nullptr;
        *status = 2;
        return;
    }

    owned[nativeCount] = '\0';          // before the copy loop
    for (uint64_t i = 0; i < nativeCount; ++i) {
        owned[i] = stackBuffer[i];
    }
    *output = owned;                     // published only after full copy
}
```

System-call evidence:

- ARM64: `openat=56`, `read=63`, `close=57` via `syscall@plt`;
- x86_64: `openat=257`, `read=0`, `close=3` via `syscall@plt`;
- read capacity is exactly `4095`, leaving one unused stack byte;
- `close(fd)` always follows `read`, including zero or negative reads;
- the close return value is ignored.

## Status and output behavior

| Condition | status | output mutation |
|---|---:|---|
| `access(path,R_OK) != 0` | `8` | untouched |
| `openat(...) == -1` | `12` | untouched |
| `read(...) == 0` | `8` | untouched |
| `malloc(count+1) == null` | `2` | explicitly set null |
| positive read + allocation success | incoming status preserved | overwritten with owned copy |

The helper does **not** pre-clear either output or status, and it does not read
or gate on incoming status.  Therefore:

1. success preserves an incoming nonzero status while still publishing a new
   allocation;
2. access/open/empty-read failures leave any incoming output pointer unchanged;
3. malloc failure clears the output pointer without freeing an incoming value;
4. success overwrites an incoming output pointer without freeing it.

The sole natural caller prevents stale-pointer behavior by explicitly setting
`status=0` and `output=null` before the call.  It later calls `free(output)`
unconditionally, so a successfully published allocation remains caller-owned
even if status was nonzero on entry.

## Final conclusion for negative reads

Both ABIs test the read result only for equality with zero:

```text
ARM64  0x177b0: cmp x19, #0
x86_64 0x18e46: test r13, r13
```

There is no signed `<0` rejection.  A negative read therefore proceeds to the
unsigned allocation/copy path.

- `read == -1`: `uint64_t(-1)+1` wraps to allocation size `0`.
- If `malloc(0)` returns null, native status becomes `2` and output is cleared.
- If `malloc(0)` returns non-null, the next write is `owned[UINT64_MAX]=0`
  (effectively one byte before the allocation), followed by a practically
  unbounded copy loop.  This is a reachable memory-corruption boundary if the
  read syscall fails after `access` and `openat` succeeded.
- Other negative values request enormous allocations; ordinary allocation
  failure yields status `2`, but an unexpectedly successful allocation would
  still drive an out-of-bounds source read/copy.

Severity: **High** memory-safety finding in the original low-level behavior.
Recommended repair for a hardened implementation is an explicit
`if (count <= 0)` branch before unsigned conversion.  Mapping negative reads
to status `8` preserves the parent-level correction `0x34`, but this is a
deliberate safety fix rather than byte-for-byte parity with the original SO.

## User-supplied data boundary and implemented C++ API

The path `/proc/self/cmdline` is fixed by the original program and represents
an OS interface, not fabricated device data.  The **contents and I/O results**
must remain caller/profile supplied.  The existing profile filesystem map
already supports custom bytes or a missing entry for this path.

Implemented low-level interface in
`native-reimplementation/recovered_primitives.cpp`:

```cpp
struct RecoveredProcSelfCmdlineOperations1709c {
    void* context;
    int (*accessPath)(void* context, const char* path, int mode);
    int64_t (*openAt)(void* context, int32_t directoryFd,
                      const char* path, int32_t flags, int32_t mode);
    int64_t (*readFile)(void* context, int32_t fd,
                        void* buffer, uint64_t capacity);
    int64_t (*closeFile)(void* context, int32_t fd);
    void* (*allocate)(void* context, uint64_t size);
    void (*storeTerminator)(void* context, void* allocation,
                            uint64_t offset);
    void (*copyBytes)(void* context, void* destination,
                      const void* source, uint64_t length);
};

void runRecoveredProcSelfCmdlineOwnedString1709c(
        uint32_t* status,
        uint64_t* output,
        const RecoveredProcSelfCmdlineOperations1709c& operations);
```

The profile-backed callback can return user-provided cmdline bytes without
accessing a host file. Direct regression now covers positive bytes, embedded
NUL, max `4095`, access failure, low-32-bit open `-1`, read `0`, read `-1`
with allocator forced null and with `malloc(0)` modeled non-null, ordinary
allocation failure, ignored close error, incoming nonzero status, sentinel
output preservation on pre-allocation failures, two path uses and exact call
order. Unsafe memory effects are recorded by callbacks instead of executed.

## Existing dynamic support

Natural original-SO traces already show:

```text
open /proc/self/cmdline (O_RDONLY)
read 99 bytes
close /proc/self/cmdline
```

in
`.omx/static-audit-20260713/current-337-51-b8830-legacy-api18-jni-trace-attempt-1.log`.
This confirms the positive I/O path.  Forcing a negative read would alter the
syscall result and is therefore not observation-only; the negative-read finding
is intentionally based on matching ARM64/x86_64 static control flow.
