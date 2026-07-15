# ARM64 descriptor-record batch matcher `0x24444..0x24860`

## Record layout

The outer array uses a fixed `0x100` stride (`0x247a0`):

| Offset | Type | Meaning |
|---:|---|---|
| `0x00` | `uint64_t` | system-property name passed to `0xd4678` |
| `0x08` | `uint64_t[20]` | descriptor pointers |
| `0xa8` | `uint32_t[20]` | descriptor kinds |
| `0xf8` | `uint64_t` | active descriptor count |

The parallel arrays follow directly from the `index << 3` and `index << 2`
addressing at `0x24660/0x24664`, followed by loads at `0x24668/0x2466c`.

## Execution order

For every outer record:

1. Zero exactly `0x5c` bytes of local property-value storage
   (`0x246f4`, `0x24748..0x24768`).
2. Call the Android system-property compatibility reader
   `0xd4678(property_name, local_value)` at `0x247ac`.
3. Walk `descriptor_count` entries in order.
4. Call recovered dispatcher `0x23730(local_value, descriptor, kind)` at
   `0x24670`.
5. For every true result, increment the caller's existing `uint16_t` counter
   through `ldrh/add/strh` at `0x24644..0x2464c`; overflow wraps naturally.

Owned C++:

- `RecoveredDescriptorBatchRecord24444` with offset and size assertions.
- `runRecoveredDescriptorBatch24444`.
- `recoveredDescriptorBatch24444Regression`.

The regression verifies property-read order, a fresh all-zero 92-byte buffer,
mixed predicate kinds, match-only increments, 16-bit wraparound and zero-count
no-op behavior.
