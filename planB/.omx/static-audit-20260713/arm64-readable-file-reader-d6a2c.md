# ARM64 `0xd6a2c..0xd6cb8` readable-file syscall helper

Target:

```text
/Users/sanbo/Desktop/api/qbdi/adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so
```

Recovered source:

```text
/Users/sanbo/Desktop/api/qbdi/native-reimplementation/recovered_primitives.cpp
```

## Recovered ABI

```cpp
bool helper(const char* path, uint64_t size, void* output);
```

The source-level implementation is callback-driven so syscall ordering and the
native invalid-address edge can be regression-tested without performing host
I/O or a real out-of-bounds store.

## Control and data flow

1. `0xd6a4c..0xd6a58` rejects null `output` or null `path`.
2. `0xd6bb4..0xd6be4` calls `access(path, R_OK)` and returns false on failure.
3. `0xd6c30..0xd6c60` invokes syscall 56 as
   `openat(AT_FDCWD=-100, path, O_RDONLY=0, mode=0)`. The comparison at
   `0xd6c54` tests the low 32-bit fd value against `-1`.
4. `0xd6c68..0xd6c8c` invokes syscall 63 as `read(fd, output, size)`. Only a
   64-bit return exactly equal to `-1` is failure.
5. For every other read result, `0xd6bec..0xd6c04` writes a NUL byte at
   `output[readResult - 1]` and reports success. There is no positive-length
   guard: a zero-byte read attempts `output[-1]`; another negative result such
   as `-2` would attempt `output[-3]`. The C++ model exposes that signed offset
   through `storeTerminator` instead of causing undefined behavior in tests.
6. `0xd6c0c..0xd6c2c` closes every successfully opened fd through syscall 57,
   regardless of read success; the close return is ignored.
7. `0xd6c94` returns the one-bit success flag.

## Regression coverage

- null path and null output;
- failed readability check;
- open result `-1`;
- read result `-1` with mandatory close;
- normal and partial positive reads, including overwrite of the final byte read;
- zero-byte read modeled as terminator offset `-1`;
- non-`-1` negative read modeled as success with a negative terminator offset;
- exact `AT_FDCWD`, flags, mode, fd, size, write, and close ordering;
- ignored close result.

Static proof:

```bash
python3 .omx/static-audit-20260713/analyze_readable_file_reader_d6a2c.py
```
