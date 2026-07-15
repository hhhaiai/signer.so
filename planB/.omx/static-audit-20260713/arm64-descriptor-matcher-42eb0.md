# ARM64 `0x42eb0..0x430f4` paired descriptor any-match wrapper

The function is an orchestration wrapper around the independently inventoried
predicate `0x23730`.

```cpp
bool anyMatch(
    uint64_t argument0,
    const uint64_t* descriptors,
    const uint32_t* descriptorKinds,
    uint64_t count);
```

It explicitly rejects only a null descriptor pointer array. For each index it
loads `descriptors[index]` with an eight-byte stride and
`descriptorKinds[index]` with a four-byte stride, then calls:

```text
0x23730(argument0, descriptors[index], descriptorKinds[index])
```

The first true low-bit result short-circuits to true. Otherwise the index is
incremented and traversal continues; zero count or full exhaustion returns
false. The kind array and child predicate pointer are intentionally not given
extra source-level guards because the native path does not guard them when the
count is nonzero.

Direct C++ is `runRecoveredAnyDescriptorMatcher42eb0`; regression verifies
null/zero-count behavior, exact argument forwarding, early stop, and complete
miss traversal.

Repeatable evidence check:

```bash
python3 .omx/static-audit-20260713/analyze_descriptor_matcher_42eb0.py
```
