# ARM64 owned pointer-array destructor `0xc8c44..0xc8eb8`

Recovered ABI:

```cpp
void helper(void** values, uint64_t count);
```

Recovered behavior:

1. A null array is a no-op.
2. Walk exactly `count` eight-byte pointer slots in ascending order.
3. Skip null elements.
4. Free every non-null element, then write zero to that same slot.
5. Free the array allocation last. A non-null array is therefore freed even
   when `count == 0`.

Evidence addresses:

- `0xc8da0..0xc8dac`: index/count test.
- `0xc8e68..0xc8e74`: slot address and element load/null gate.
- `0xc8db4..0xc8db8`: element free.
- `0xc8dfc`: slot clear after the free.
- `0xc8e84`: index increment.
- `0xc8e1c..0xc8e20`: final array free.

Owned C++:

- `runRecoveredOwnedPointerArrayDestroyC8c44`
- `recoveredOwnedPointerArrayDestroyC8c44Regression`
