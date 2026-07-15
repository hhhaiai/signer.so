# ARM64 system-property metadata initializer `0xd3ff0..0xd4220`

## Recovered ABI

```cpp
void* helper(uint32_t* status);
```

The helper owns a temporary source object produced by `0xd352c` and returns a
new `0x30`-byte metadata object only when every stage leaves `status == 0`.

## Exact order and data flow

1. Call `0xd352c(status)` unconditionally, including when the caller supplied a
   nonzero status, and retain its returned temporary source.
2. Read `*status`.  A nonzero value skips allocation and population.
3. For zero status, call `calloc(1, 0x30)`.
4. Allocation failure stores status `2` and does not call the population
   helper.
5. On allocation success, load the source byte pointer at `source+0x08`, load
   the zero-extended 32-bit offset at `source+0x2c`, and publish
   `cursor = bytes + offset` in a caller-local pointer slot.
6. Call `0xd28d0(status, source, &cursor, metadata)`.
7. A nonzero post-population status frees the metadata object and makes the
   return value null.
8. Call destructor `0xd3d90(source)` on every ordinary return path, after any
   metadata failure cleanup.
9. Return the metadata pointer only on success.

## Evidence addresses

```text
0xd4024        temporary source creation
0xd4028        post-create status read
0xd4144..14c   calloc(1, 0x30)
0xd4174..17c   allocation failure status 2
0xd4184        source+0x08 byte pointer
0xd418c        source+0x2c uint32 offset
0xd419c..1a0   cursor derivation and publication
0xd4190..1a4   four-argument 0xd28d0 population call
0xd41a8        post-population status read
0xd41bc..1c0   failed metadata free
0xd41f0..1f4   unconditional source destructor
0xd41f8        final pointer return
```

## Owned C++ and regression

- `RecoveredSystemPropertyMetadataSourceD3ff0`
- `runRecoveredSystemPropertyMetadataInitD3ff0`
- `recoveredSystemPropertyMetadataInitD3ff0Regression`

The regression covers preexisting status, allocation failure, successful
cursor forwarding, failed-population cleanup, return publication and exact
cleanup order.
