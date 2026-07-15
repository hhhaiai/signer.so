# arm64 protected crypto/work engine: `0xf1ec8..0x11ba78`

## Exact function boundary

The target ELF `.eh_frame` contains one FDE covering:

```text
start 0x0f1ec8
end   0x11ba78
size  0x29bb0 bytes
```

Therefore addresses previously discussed as AES, SHA, IV and output-word states are not separate
native functions; they are states inside one very large flattened function.

## Static shape

```text
instructions:       42,732
conditional/direct branches: 645
direct call sites:   7,223
unique direct targets: 17
indirect calls (blr): 0
rand call sites:     2 (0x11a62c, 0x11a64c)
```

Top direct-call targets:

| target | calls | current role |
|---:|---:|---|
| `0x138a70` | 2846 | logical node/value construction |
| `0x138b74` | 2500 | logical node/value query |
| `0x138744` | 451 | logical word reader |
| `0x138c8c` | 299 | bounded logical operation |
| `0x138318` | 293 | logical word writer |
| `0x138e60` | 240 | logical operation with immediate/index |
| `0x138e58` | 224 | tail wrapper into logical operation family |
| `0x138560` | 108 | logical object operation |
| `0x138660` | 68 | logical object operation |
| `0x137a78` | 58 | allocation/graph helper family |
| `0x137980` | 58 | allocation/graph helper family |
| `0x138728` | 43 | terminal/index-derived word calculation |
| `0x137898` | 27 | tail wrapper to `0x138a70` |
| `0x13789c` | 3 | tail wrapper |
| `0x1378a0` | 2 | tail wrapper |
| `rand@plt` | 2 | IV `rand() XOR rand()` |
| `__stack_chk_fail@plt` | 1 | stack guard |

## Input initialization

The only known call at final consumer `0x11e7f0` passes:

```text
w2 = 9
nine byte descriptors in x3..x7 and four stack slots
```

The entry loop converts every descriptor to big-endian 32-bit logical words and writes them to
`workObject+0x20+i*8`. There is no algorithm identifier argument and no indirect function call.

## Algorithm-switch assessment

The engine contains several cryptographic stages recovered elsewhere:

```text
custom-state SHA-256
AES-256 block/CBC operations
HMAC-SHA256
Bionic-rand IV generation
```

The static form is a fixed generated logical circuit/work graph: thousands of calls to a small
17-target helper vocabulary, fixed nine-input initialization, two fixed rand sites, and no `blr`
dispatcher. This supports the interpretation that SHA/AES/HMAC are sequential layers of one adj8
pipeline, not multiple final algorithms selected through a function pointer.

This is not yet a proof that every one of the 645 branches is input-independent. Completion requires
lifting the helper vocabulary and classifying each branch predicate. The next static step is to turn
the 7,223-call schedule into a compact IR and locate any branch whose predicate depends on an
external parameter rather than status/allocation/loop state.
