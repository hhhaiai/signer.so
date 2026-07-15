# ARM64 native context dynamic pair closure

## Result

On the analyzed ARM64 `libsigner.so`, final descriptors 8/9 are a reserved
zero-length pair on the statically reachable native signing pipeline:

```text
context+0x118 length = 0
context+0x120 data   = nullptr
slot 8 bytes         = 00 00 00 00
slot 9 bytes         = empty
```

## Initialization evidence

- `0xcbec0`: native context base is `sp+0x88`.
- `0xcbf5c`: `x9 = context+0x08`; it is saved at `sp+0x10` by `0xcbf84`.
- `0xcc3e8..0xcc3f4`: `memset(context+0x08, 0, 0x120)`.
- The zero range is `[context+0x08, context+0x128)`, so it covers both
  `context+0x118` and `context+0x120` completely.

## Producer search

The checker performs conservative fixed-point register may-alias propagation
through direct branches and recursively follows direct calls whenever x0..x7
may contain the context or a fixed context-relative pointer. Analyzed entries
and reachable context-bearing helpers:

- `0x80c0` `correction 0x2b and flag-bit-0 helper`
- `0x80f4` `correction 0x39 and flag-bit-0 helper`
- `0x8128` `sub_8128`
- `0xcde4` `context+0x108 string-consistency stage`
- `0xd184` `realtime threshold comparison`
- `0xd428` `cmdline missing/empty wrapper`
- `0xd45c` `context flag-mask 0x0010000000000200`
- `0xd474` `public-source linked-list check`
- `0xd980` `correction 0x37 and flag-bit-0 helper`
- `0xd9b4` `context flag-mask 0x0080020000000000`
- `0xd9cc` `SHA-1 candidate digest comparator`
- `0xddc4` `public-source digest validation stage`
- `0xe674` `correction 0x38 and flag-bit-0 helper`
- `0xe6a8` `context flag-mask 0x0100040000000000`
- `0xe6c0` `supplied/expected Java-HMAC comparator`
- `0xf1fc` `context flag-mask helper`
- `0xf224` `timing correction gate`
- `0xf328` `environment stage dispatcher`
- `0xfce0` `environment stage-1 emulator/automation initializer`
- `0x12a30` `13-predicate post-detector aggregator`
- `0x13000` `context fallback mask stage`
- `0x13044` `nested context mask stage`
- `0x13088` `sub_13088`
- `0x13dc8` `packed-transition filtered record stage`
- `0x14078` `fixed-loopback filtered record stage`
- `0x14380` `correction 0x32 and flag-bit-0 helper A`
- `0x143b4` `correction 0x32 and flag-bit-0 helper B`
- `0x143e8` `environment dispatcher`
- `0x14ef8` `ART/linker stat post-stage`
- `0x150b8` `correction 0x3b and flag-bit-0 helper`
- `0x15104` `sub_15104`
- `0x4d9bc` `GreatFruit/Google sensor-pair predicate`
- `0x59658` `microvirt dynamic-pair substring predicate`
- `0x5a8e0` `Tiantian sensor-pair predicate`
- `0x5c6d8` `seven physical sensor-pair predicate`
- `0x5f900` `Goldfish three-sensor predicate`
- `0x615d8` `MPU/Orientaion two-sensor predicate`
- `0x6a4e0` `Goldfish two-sensor subset predicate`
- `0x6c590` `Genymotion sensor-pair predicate`
- `0x6dbbc` `leapdroid substring predicate`
- `0x6f758` `open-source two-sensor predicate`
- `0x76f2c` `haima substring predicate`
- `0x77f7c` `vmos substring predicate`
- `0x78f68` `paired device/build substring predicate`
- `0x7bb98` `context flag-mask 0x3dffe800`
- `0x7bbb0` `eight fixed-string detector marker matcher`
- `0x868b4` `ASCII case-insensitive detector marker matcher`
- `0x9279c` `context +0xe0 bit setter`
- `0xc8c44` `owned pointer-array destructor`
- `0xcba90` `native context init stage 1`
- `0xcbbd4` `native context init stage 2`
- `0xd6888` `TracerPid correction/context consumer`
- `0x11da64` `final consumer`
- `0x13063c` `signer-code trampoline detector`
- `0x134dd8` `correction replacement-slot finder`
- `0x13548c` `correction find-and-write wrapper`
- `0x1354bc` `ordered correction-array writer`
- `0x13917c` `byte descriptor allocator`
- `0x139800` `acquire byte compare-exchange`

Observed fixed context-relative write offsets: `0x0, 0x8, 0xe0`.
No write targets `context+0x118` or `context+0x120`.

| address | write | function | instruction |
|---|---|---|---|
| `0xd05c` | `context+0xe0` | `context+0x108 string-consistency stage` | `d05c: f9007268     	str	x8, [x19, #0xe0]` |
| `0xd140` | `context+0xe0` | `context+0x108 string-consistency stage` | `d140: f9007268     	str	x8, [x19, #0xe0]` |
| `0xd310` | `context+0x0` | `realtime threshold comparison` | `d310: fd00026b     	str	d11, [x19]` |
| `0xd32c` | `context+0x8` | `realtime threshold comparison` | `d32c: 39002268     	strb	w8, [x19, #0x8]` |
| `0xd44c` | `context+0xe0` | `cmdline missing/empty wrapper` | `d44c: f9007268     	str	x8, [x19, #0xe0]` |
| `0xd46c` | `context+0xe0` | `context flag-mask 0x0010000000000200` | `d46c: f9007008     	str	x8, [x0, #0xe0]` |
| `0xd9a4` | `context+0xe0` | `correction 0x37 and flag-bit-0 helper` | `d9a4: f9007268     	str	x8, [x19, #0xe0]` |
| `0xd9c4` | `context+0xe0` | `context flag-mask 0x0080020000000000` | `d9c4: f9007008     	str	x8, [x0, #0xe0]` |
| `0xe698` | `context+0xe0` | `correction 0x38 and flag-bit-0 helper` | `e698: f9007268     	str	x8, [x19, #0xe0]` |
| `0xe6b8` | `context+0xe0` | `context flag-mask 0x0100040000000000` | `e6b8: f9007008     	str	x8, [x0, #0xe0]` |
| `0xf20c` | `context+0xe0` | `context flag-mask helper` | `f20c: f9007008     	str	x8, [x0, #0xe0]` |
| `0xf314` | `context+0xe0` | `timing correction gate` | `f314: f9007268     	str	x8, [x19, #0xe0]` |
| `0xf900` | `context+0xe0` | `environment stage dispatcher` | `f900: f9007268     	str	x8, [x19, #0xe0]` |
| `0xf92c` | `context+0xe0` | `environment stage dispatcher` | `f92c: f9007268     	str	x8, [x19, #0xe0]` |
| `0xf9a4` | `context+0xe0` | `environment stage dispatcher` | `f9a4: f9007268     	str	x8, [x19, #0xe0]` |
| `0xf9d0` | `context+0xe0` | `environment stage dispatcher` | `f9d0: f9007268     	str	x8, [x19, #0xe0]` |
| `0xf9fc` | `context+0xe0` | `environment stage dispatcher` | `f9fc: f9007268     	str	x8, [x19, #0xe0]` |
| `0xfa70` | `context+0xe0` | `environment stage dispatcher` | `fa70: f9007268     	str	x8, [x19, #0xe0]` |
| `0xfa9c` | `context+0xe0` | `environment stage dispatcher` | `fa9c: f9007268     	str	x8, [x19, #0xe0]` |
| `0xfc2c` | `context+0xe0` | `environment stage dispatcher` | `fc2c: f9007268     	str	x8, [x19, #0xe0]` |
| `0xfc58` | `context+0xe0` | `environment stage dispatcher` | `fc58: f9007268     	str	x8, [x19, #0xe0]` |
| `0xfc84` | `context+0xe0` | `environment stage dispatcher` | `fc84: f9007268     	str	x8, [x19, #0xe0]` |
| `0x13024` | `context+0xe0` | `context fallback mask stage` | `13024: f9007008     	str	x8, [x0, #0xe0]` |
| `0x13034` | `context+0xe0` | `context fallback mask stage` | `13034: f9007268     	str	x8, [x19, #0xe0]` |
| `0x13068` | `context+0xe0` | `nested context mask stage` | `13068: f9007268     	str	x8, [x19, #0xe0]` |
| `0x134c4` | `context+0xe0` | `sub_13088` | `134c4: f9007369     	str	x9, [x27, #0xe0]` |
| `0x134f8` | `context+0xe0` | `sub_13088` | `134f8: f9007369     	str	x9, [x27, #0xe0]` |
| `0x13538` | `context+0xe0` | `sub_13088` | `13538: f9007369     	str	x9, [x27, #0xe0]` |
| `0x1400c` | `context+0xe0` | `packed-transition filtered record stage` | `1400c: f9007268     	str	x8, [x19, #0xe0]` |
| `0x14028` | `context+0xe0` | `packed-transition filtered record stage` | `14028: f9007268     	str	x8, [x19, #0xe0]` |
| `0x14250` | `context+0xe0` | `fixed-loopback filtered record stage` | `14250: f9007268     	str	x8, [x19, #0xe0]` |
| `0x142e8` | `context+0xe0` | `fixed-loopback filtered record stage` | `142e8: f9007268     	str	x8, [x19, #0xe0]` |
| `0x143a4` | `context+0xe0` | `correction 0x32 and flag-bit-0 helper A` | `143a4: f9007268     	str	x8, [x19, #0xe0]` |
| `0x143d8` | `context+0xe0` | `correction 0x32 and flag-bit-0 helper B` | `143d8: f9007268     	str	x8, [x19, #0xe0]` |
| `0x1503c` | `context+0xe0` | `ART/linker stat post-stage` | `1503c: f9007269     	str	x9, [x19, #0xe0]` |
| `0x15080` | `context+0xe0` | `ART/linker stat post-stage` | `15080: f9007268     	str	x8, [x19, #0xe0]` |
| `0x150dc` | `context+0xe0` | `correction 0x3b and flag-bit-0 helper` | `150dc: f9007268     	str	x8, [x19, #0xe0]` |
| `0x7bba8` | `context+0xe0` | `context flag-mask 0x3dffe800` | `7bba8: f9007008     	str	x8, [x0, #0xe0]` |
| `0x927a4` | `context+0xe0` | `context +0xe0 bit setter` | `927a4: f9007048     	str	x8, [x2, #0xe0]` |
| `0xd6980` | `context+0xe0` | `TracerPid correction/context consumer` | `d6980: f9007268     	str	x8, [x19, #0xe0]` |

The correction encoder's indexed halfword stores are intentionally not
misreported as fixed-offset writes; their base is `context+0x20` and the
separate `0x13531c..0x135484` analysis bounds them to the correction region.

## Consumer and cleanup evidence

- `0x11e658`: reads `context+0x118`, reverses the 32-bit zero and creates the
  four-byte length descriptor used as slot 8.
- `0x11e760/0x11e764`: reads length/pointer for slot 9.
- `0xcc1c0/0xcc1c4`: cleanup loads `context+0x120` and calls `free`; null is
  therefore the normal no-data cleanup value.

## Compatibility consequence

The Java-supplied HMAC is not slot 8/9, and neither is `adj_signing_id` on this
ARM64 path. Any `adj_signing_id` contribution to the protected engine must be
recovered from the fixed context descriptors or an earlier protected
transformation, not from the reserved dynamic pair.
