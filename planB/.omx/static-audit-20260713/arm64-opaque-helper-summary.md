# Arm64 protected helper static summary

This report parses the existing objdump text. It does not load or execute libsigner.so.

## Function boundaries and direct calls

### metadata preparation 0xa334

- Strict range: `0xa334..0xaf38`
- Instructions: **770**
- Direct calls: **7**, unique targets: **2**

| count | target |
|---:|---|
| 4 | `0x139800 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6d1fc>` |
| 3 | `0x9aa5c <.text+0x929ec>` |

### metadata builder/orchestrator 0xaf3c

- Strict range: `0xaf3c..0xcde0`
- Instructions: **1962**
- Direct calls: **15**, unique targets: **5**

| count | target |
|---:|---|
| 8 | `0x139800 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6d1fc>` |
| 4 | `0x9954c <.text+0x914dc>` |
| 1 | `0x9548c <.text+0x8d41c>` |
| 1 | `0x95680 <.text+0x8d610>` |
| 1 | `0xa334 <.text+0x22c4>` |

### protected crypto/data engine 0xf1ec8

- Strict range: `0xf1ec8..0x11ba74`
- Instructions: **42732**
- Direct calls: **7223**, unique targets: **17**

| count | target |
|---:|---|
| 2846 | `0x138a70 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6c46c>` |
| 2500 | `0x138b74 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6c570>` |
| 451 | `0x138744 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6c140>` |
| 299 | `0x138c8c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6c688>` |
| 293 | `0x138318 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6bd14>` |
| 240 | `0x138e60 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6c85c>` |
| 224 | `0x138e58 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6c854>` |
| 108 | `0x138560 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6bf5c>` |
| 68 | `0x138660 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6c05c>` |
| 58 | `0x137a78 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6b474>` |
| 58 | `0x137980 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6b37c>` |
| 43 | `0x138728 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6c124>` |
| 27 | `0x137898 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6b294>` |
| 3 | `0x13789c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6b298>` |
| 2 | `0x1378a0 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6b29c>` |
| 2 | `0x13a020 <rand@plt>` |
| 1 | `0x139df0 <__stack_chk_fail@plt>` |

### generic range/byte adapter 0x11ba78

- Strict range: `0x11ba78..0x11d408`
- Instructions: **1637**
- Direct calls: **8**, unique targets: **7**

| count | target |
|---:|---|
| 2 | `0x139800 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6d1fc>` |
| 1 | `0x8af4 <.text+0xa84>` |
| 1 | `0xacd90 <.text+0xa4d20>` |
| 1 | `0x139e20 <malloc@plt>` |
| 1 | `0xadbf4 <.text+0xa5b84>` |
| 1 | `0x139de0 <free@plt>` |
| 1 | `0x139df0 <__stack_chk_fail@plt>` |

### result concatenation wrapper 0x11d798

- Strict range: `0x11d798..0x11da60`
- Instructions: **179**
- Direct calls: **4**, unique targets: **3**

| count | target |
|---:|---|
| 2 | `0x11ba78 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x4f474>` |
| 1 | `0x139e50 <calloc@plt>` |
| 1 | `0x139df0 <__stack_chk_fail@plt>` |

## Static classification

- `0xaf3c` calls metadata builder `0x9954c` exactly four times and also calls `0xa334`; these ranges belong to parameter/metadata construction, not a second final cipher.
- `0x11d798` calls `0x11ba78` twice with callback addresses `0x11d528` and `0x11d40c`, allocates `combined_length + 1`, and returns the concatenated buffer through output pointers.
- Callback `0x11d528` contains the explicit `memcpy` append path; callback `0x11d40c` accumulates/advances a destination pointer. These are generic output adapters.
- `0xf1ec8..0x11ba74` is the only remaining large protected crypto/data engine. It contains the recovered AES, SHA-256, HMAC, correction and IV regions.
- The engine has exactly two direct `rand@plt` call sites (`0x11a62c`, `0x11a64c`); the state machine loops over those sites to produce the four IV words. No second random/nonce call family is present in this engine.

## Recovered protected-engine container vocabulary

### Counter chain and word-stack aliases: `0x137894..0x137d0c`

`0x137894..0x1378a8` consists of five four-byte tail aliases for stack allocate,
push, empty, pop and destroy. The adjacent counter chain reuses the 16-byte
word-node layout but its 8-byte owner contains only a head pointer:

| range | recovered operation | exact edge behavior |
|---|---|---|
| `0x1378a8..0x137980` | allocate counter-chain owner | `calloc(1,8)`; failure status `2` |
| `0x137980..0x137a78` | push counter node | `calloc(1,16)`; failure status `2`; no separate count field |
| `0x137a78..0x137b64` | decrement head counter | assumes non-null head; unsigned decrement; a new value of zero unlinks/frees the head; returns the new value |
| `0x137b64..0x137c38` | destroy counter node chain | recursive next-first free |
| `0x137c38..0x137d0c` | destroy counter-chain owner | destroys head chain, then frees the 8-byte owner |

### Framed word arena: `0x138318..0x138818`

The high-frequency helpers operate on this exact arm64 layout:

```cpp
struct ProtectedWordArena {
    uint32_t capacityWords; // +0x00
    uint32_t reserved04;    // +0x04
    uint32_t* words;        // +0x08
    uint32_t lengthWords;   // +0x10
    uint32_t frameDepth;    // +0x14
    uint32_t* frameBases;   // +0x18
};
```

| range | recovered operation | exact edge behavior |
|---|---|---|
| `0x137d0c..0x137fa8` | allocate arena | requested capacity rounds to 128 words; allocates object, words and one zero frame base; any allocation failure sets status `2` and frees completed allocations |
| `0x137fa8..0x138318` | export big-endian words | zero length is a no-op; non-4-byte length sets status `6`; native capacity guard uses `sourceOffset+byteLength` before copying `byteLength/4` words |
| `0x138318..0x138560` | write `words[frameBases[depth-1]+offset]` | capacity grows by exactly 128 words; direct `realloc` result assignment; failure status `2`; length becomes `max(length,index+1)` |
| `0x138560..0x138660` | push frame | reallocates `frameBases` by one word, appends current length; failure status `2` |
| `0x138660..0x138728` | pop frame | restores length from the last frame base; depth zero sets status `7` |
| `0x138728..0x138744` | current frame length | `lengthWords-frameBases[depth-1]` |
| `0x138744..0x138818` | read frame-relative word | checks against allocated capacity, not logical length; out-of-capacity returns zero without changing status |
| `0x138818..0x138988` | destroy arena | frees word buffer when non-null, frame-base buffer, then owner object; null is accepted |
| `0x139270..0x13927c` | read export byte length | reads frame-relative word zero from the arena pointer at protected object offset `+0x28` |
| `0x13927c..0x1392c4` | export wrapper | exports from the data arena at object offset `+0x20`, starting at zero, into the caller buffer |

### Linked word stack: `0x138a70..0x138fd4`

```cpp
struct ProtectedWordNode {
    uint32_t value;          // +0x00
    uint32_t reserved04;     // +0x04
    ProtectedWordNode* next; // +0x08
};
struct ProtectedWordStack {
    uint32_t count;          // +0x00
    uint32_t reserved04;     // +0x04
    ProtectedWordNode* head; // +0x08
};
```

| range | recovered operation | exact edge behavior |
|---|---|---|
| `0x138988..0x138a60` | allocate zeroed stack | `calloc(1,16)`; failure status `2` |
| `0x138a60..0x138a70` | empty test | returns `count == 0` |
| `0x138a70..0x138b74` | push one 32-bit word | `calloc(1,16)`; failure status `2` |
| `0x138b74..0x138c8c` | pop head word | empty stack status `3`, return zero; otherwise unlink/free head |
| `0x138c8c..0x138e58` | duplicate one zero-based indexed node value at the head | requires `count > index`, otherwise status `4`; the single push allocation failure leaves status `2` |
| `0x138e58..0x138e60` | validate nonempty stack | tail-calls the previous helper with `N=0` |
| `0x138e60..0x138fd4` | swap head value with zero-based item N | requires `count > N`, otherwise status `4` |
| `0x138fd4..0x1390a8` | destroy node chain | recursively destroys `next`, then frees the current node; null is accepted |
| `0x1390a8..0x13917c` | destroy stack | destroys the head chain, then frees the owner object; null is accepted |

These functions are data-structure primitives used to evaluate the fixed protected circuit. They are not independent cipher implementations or an algorithm dispatcher. Source-level equivalents now live in `native-reimplementation/recovered_primitives.cpp`.

### Compiler atomic support: `0x139800..0x1398cc`

- `0x139800` is an acquire byte compare-exchange. It chooses arm64 LSE `casab`
  or an `ldaxrb`/`stxrb` loop through a process-global capability byte, returns
  the observed old value, and writes the desired byte only on equality.
- `0x139834` initializes that capability byte from `getauxval(AT_HWCAP)` bit 8.
  Even when the bit is present it disables LSE for `ro.arch=exynos9810`; a
  missing/empty property leaves the advertised feature enabled.

These are compiler/platform runtime helpers, not signer algorithm selectors.

## Protected work object: `0x1392c4..0x1397fc`

The object is exactly `0xa0` bytes and contains **sixteen** arena lanes. The
previous nine-slot description confused this internal evaluator object with
the final consumer's nine input descriptors.

```cpp
struct ProtectedWorkObject {
    ProtectedWordStack* evaluationStack;       // +0x00
    ProtectedWordArena* sharedArena;           // +0x08
    ProtectedCounterChain* counterChain;       // +0x10
    ProtectedWordStack* auxiliaryStack;        // +0x18
    ProtectedWordArena* lanes[16];             // +0x20..+0x98
};
```

`0x1393cc` allocates the zeroed owner, then creates members in this order:

1. stack at `+0x00`;
2. arena with requested capacity `0x100` at `+0x08`;
3. counter-chain owner at `+0x10`;
4. stack at `+0x18`;
5. sixteen arenas, each requested capacity `0x100`, at `+0x20..+0x98`.

After the owner allocation, every child failure is detected through the shared
status word and transfers to `0x1392c4`, which destroys the partially populated
object. The destructor order is the four fixed members above, the sixteen lanes
in ascending index order, then the owner object. All child destructors accept
null, so zero-filled unallocated slots are safe during partial cleanup.

## Recovered 32-bit materialization runs

### Final HMAC key at 0xf9014..0xf9298

```text
caab8344 4a214639 2abb96b6 42306155
29a770c6 3c163c1c 7528673e 0671728f
```

### Field-4 SHA source words at 0xf97c8..0xf9a3c

```text
018a6c12 190ae32c ce07f549 3186d96f
cb061855 af48c173 9da54cdc 06cf339e
```

Each word XOR `0xcccccccc` gives the recovered custom SHA-256 initial state.

A scan of immediate 32-bit writes through engine writer `0x138a70` finds exactly three runs of at least eight consecutive non-small words: the HMAC key at `0xf9014`, the field-4 SHA source state at `0xf97c8`, and the run beginning `a6c52aab 77ab6249 ...` at `0xfb7b8`.

The `0xfb7b8` run is later reused with logical indices `0x41..0x48` in the correction/environment construction region, so it is not a second final HMAC/AES key. This scan only rules out a second directly materialized eight-word key run; a key derived algebraically inside opaque states still requires data-flow proof.

## GCM-looking string fragment correction

The bytes rendered by strings as `=gcm` or `=gcmj` are the low bytes of the opaque 64-bit control-state constant:

```text
0x9224eb6a6d63673d
```

Cross-ABI evidence:

- arm64 `0x6dcd8..0x6dce8`: materializes the constant and compares it as a state value.
- x86_64 `0x5e946`: `movabs 0x9224eb6a6d63673d`, followed by a state comparison.
- x86 `0x5938d` and `0x5df6d`: compares/XORs the two 32-bit halves `0x6d63673d` and `0x9224eb6a`.
- armv7 string hits contain the same two words in mixed ARM/Thumb code/data alignment.

Therefore these string hits are not evidence of an AES-GCM algorithm name or metadata value.

## Current second-envelope verdict

No second final-envelope key materialization, nonce generator, tag-length branch, metadata builder value or output-concatenation layout was found in these bounded helpers. The remaining uncertainty is reachability and full semantic naming inside the 42,732-instruction protected engine at `0xf1ec8..0x11ba74`.
