# ARM64 path-existence counter `0x1f95c..0x1fae4`

Recovered ABI:

```cpp
void helper(
    const char* const* paths,
    uint64_t count,
    uint16_t* existing_count);
```

Evidence:

- `0x1fa00/0x1fa04` preserves the output counter, path array and count.
- `0x1fab4..0x1fabc` compares the current zero-based index with `count`.
- `0x1fa88` loads `paths[index]` with an eight-byte stride.
- `0x1fa8c` calls recovered `0xd7890`, the exact `access(path, F_OK)` Boolean
  helper.
- Only a true result reaches `0x1fa64..0x1fa7c`, which performs
  `ldrh`, `add 1`, `strh`. The caller's initial counter is preserved and the
  increment wraps modulo `2^16`.
- A zero count exits without dereferencing the array or counter.

Owned C++:

- `runRecoveredPathExistenceCounter1f95c`
- `recoveredPathExistenceCounter1f95cRegression`

The regression verifies order, exact call count, match-only increments,
16-bit wraparound and zero-count no-op behavior.
