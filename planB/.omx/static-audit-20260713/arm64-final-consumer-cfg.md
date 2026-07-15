# arm64 final consumer bounded CFG

## Scope

- Included: `0x11da64..0x11ea74`.
- `0x11ea70` is the normal `ret`; `0x11ea74` is the stack-check failure call.
- Excluded: the next function beginning at `0x11ea78`.
- Parsed instructions: **1029**; basic blocks: **84**; CFG edges: **117**.

## Direct calls

| call site | target |
|---:|---|
| `0x11daa8` | `0x13a030 <time@plt>` |
| `0x11daac` | `0x13a040 <srand@plt>` |
| `0x11dac4` | `0x13917c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6cb78>` |
| `0x11e01c` | `0xa334 <.text+0x22c4>` |
| `0x11e078` | `0x139270 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6cc6c>` |
| `0x11e088` | `0x139e50 <calloc@plt>` |
| `0x11e0e0` | `0x13917c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6cb78>` |
| `0x11e178` | `0xaf3c <.text+0x2ecc>` |
| `0x11e2c0` | `0x13917c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6cb78>` |
| `0x11e418` | `0x13917c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6cb78>` |
| `0x11e5fc` | `0x13917c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6cb78>` |
| `0x11e664` | `0x13917c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6cb78>` |
| `0x11e6bc` | `0x13917c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6cb78>` |
| `0x11e70c` | `0x1393cc <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6cdc8>` |
| `0x11e768` | `0x13917c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6cb78>` |
| `0x11e7f0` | `0xf1ec8 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x258c4>` |
| `0x11e848` | `0x13917c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6cb78>` |
| `0x11e924` | `0x11d798 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x51194>` |
| `0x11e980` | `0x13927c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6cc78>` |
| `0x11e9d4` | `0x1392c4 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6ccc0>` |
| `0x11e9dc` | `0x13926c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6cc68>` |
| `0x11e9e4` | `0x13926c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6cc68>` |
| `0x11e9ec` | `0x13926c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6cc68>` |
| `0x11e9f4` | `0x13926c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6cc68>` |
| `0x11e9fc` | `0x13926c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6cc68>` |
| `0x11ea04` | `0x13926c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6cc68>` |
| `0x11ea0c` | `0x13926c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6cc68>` |
| `0x11ea14` | `0x13926c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6cc68>` |
| `0x11ea1c` | `0x13926c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6cc68>` |
| `0x11ea24` | `0x139de0 <free@plt>` |
| `0x11ea2c` | `0x139de0 <free@plt>` |
| `0x11ea74` | `0x139df0 <__stack_chk_fail@plt>` |

## Original-context offsets referenced

The prologue keeps the original context in x19 and saves it at sp+0x70 before opaque register rotation.

`+0x20`, `+0x30`, `+0x50`, `+0xe0`, `+0xf0`, `+0x118` (length), `+0x120` (data pointer)

## Basic blocks

Each row records the terminal instruction and statically visible successors.

| block | instruction range | terminal | successors | direct calls |
|---:|---:|---|---|---|
| `0x11da64` | `0x11da64..0x11db20` | `str x8, [sp, #0xd0]` | 0x11db24 (fallthrough) | 0x11daa8->0x13a030 <time@plt>, 0x11daac->0x13a040 <srand@plt>, 0x11dac4->0x13917c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6cb78> |
| `0x11db24` | `0x11db24..0x11db6c` | `b.eq 0x11e974 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x52370>` | 0x11e974 (b.eq), 0x11db70 (fallthrough) | - |
| `0x11db70` | `0x11db70..0x11db88` | `b.eq 0x11e4b0 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x51eac>` | 0x11e4b0 (b.eq), 0x11db8c (fallthrough) | - |
| `0x11db8c` | `0x11db8c..0x11dba0` | `b.eq 0x11e5f0 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x51fec>` | 0x11e5f0 (b.eq), 0x11dba4 (fallthrough) | - |
| `0x11dba4` | `0x11dba4..0x11dbb8` | `b.eq 0x11e4f8 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x51ef4>` | 0x11e4f8 (b.eq), 0x11dbbc (fallthrough) | - |
| `0x11dbbc` | `0x11dbbc..0x11dbd0` | `b.eq 0x11e8b8 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x522b4>` | 0x11e8b8 (b.eq), 0x11dbd4 (fallthrough) | - |
| `0x11dbd4` | `0x11dbd4..0x11dbe8` | `b.eq 0x11e83c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x52238>` | 0x11e83c (b.eq), 0x11dbec (fallthrough) | - |
| `0x11dbec` | `0x11dbec..0x11dc00` | `b.eq 0x11e360 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x51d5c>` | 0x11e360 (b.eq), 0x11dc04 (fallthrough) | - |
| `0x11dc04` | `0x11dc04..0x11dc18` | `b.eq 0x11e758 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x52154>` | 0x11e758 (b.eq), 0x11dc1c (fallthrough) | - |
| `0x11dc1c` | `0x11dc1c..0x11dc30` | `b.eq 0x11e55c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x51f58>` | 0x11e55c (b.eq), 0x11dc34 (fallthrough) | - |
| `0x11dc34` | `0x11dc34..0x11dc48` | `b.eq 0x11e074 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x51a70>` | 0x11e074 (b.eq), 0x11dc4c (fallthrough) | - |
| `0x11dc4c` | `0x11dc4c..0x11dc60` | `b.eq 0x11e2b4 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x51cb0>` | 0x11e2b4 (b.eq), 0x11dc64 (fallthrough) | - |
| `0x11dc64` | `0x11dc64..0x11dc78` | `b.eq 0x11dfc0 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x519bc>` | 0x11dfc0 (b.eq), 0x11dc7c (fallthrough) | - |
| `0x11dc7c` | `0x11dc7c..0x11dc90` | `b.eq 0x11e7b8 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x521b4>` | 0x11e7b8 (b.eq), 0x11dc94 (fallthrough) | - |
| `0x11dc94` | `0x11dc94..0x11dca8` | `b.eq 0x11e164 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x51b60>` | 0x11e164 (b.eq), 0x11dcac (fallthrough) | - |
| `0x11dcac` | `0x11dcac..0x11dd04` | `b.eq 0x11db24 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x51520>` | 0x11db24 (b.eq), 0x11dd08 (fallthrough) | - |
| `0x11dd08` | `0x11dd08..0x11dd1c` | `b.eq 0x11e010 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x51a0c>` | 0x11e010 (b.eq), 0x11dd20 (fallthrough) | - |
| `0x11dd20` | `0x11dd20..0x11dd34` | `b.eq 0x11e464 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x51e60>` | 0x11e464 (b.eq), 0x11dd38 (fallthrough) | - |
| `0x11dd38` | `0x11dd38..0x11dd4c` | `b.eq 0x11e6b0 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x520ac>` | 0x11e6b0 (b.eq), 0x11dd50 (fallthrough) | - |
| `0x11dd50` | `0x11dd50..0x11dd64` | `b.eq 0x11dfb4 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x519b0>` | 0x11dfb4 (b.eq), 0x11dd68 (fallthrough) | - |
| `0x11dd68` | `0x11dd68..0x11dd7c` | `b.eq 0x11e648 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x52044>` | 0x11e648 (b.eq), 0x11dd80 (fallthrough) | - |
| `0x11dd80` | `0x11dd80..0x11dd94` | `b.eq 0x11e90c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x52308>` | 0x11e90c (b.eq), 0x11dd98 (fallthrough) | - |
| `0x11dd98` | `0x11dd98..0x11de00` | `b.eq 0x11db24 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x51520>` | 0x11db24 (b.eq), 0x11de04 (fallthrough) | - |
| `0x11de04` | `0x11de04..0x11de18` | `b.eq 0x11dfb4 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x519b0>` | 0x11dfb4 (b.eq), 0x11de1c (fallthrough) | - |
| `0x11de1c` | `0x11de1c..0x11de30` | `b.eq 0x11e708 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x52104>` | 0x11e708 (b.eq), 0x11de34 (fallthrough) | - |
| `0x11de34` | `0x11de34..0x11de90` | `b.eq 0x11db24 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x51520>` | 0x11db24 (b.eq), 0x11de94 (fallthrough) | - |
| `0x11de94` | `0x11de94..0x11dea8` | `b.eq 0x11e220 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x51c1c>` | 0x11e220 (b.eq), 0x11deac (fallthrough) | - |
| `0x11deac` | `0x11deac..0x11dec0` | `b.eq 0x11e0d4 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x51ad0>` | 0x11e0d4 (b.eq), 0x11dec4 (fallthrough) | - |
| `0x11dec4` | `0x11dec4..0x11ded8` | `b.eq 0x11e1c4 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x51bc0>` | 0x11e1c4 (b.eq), 0x11dedc (fallthrough) | - |
| `0x11dedc` | `0x11dedc..0x11def0` | `b.eq 0x11e12c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x51b28>` | 0x11e12c (b.eq), 0x11def4 (fallthrough) | - |
| `0x11def4` | `0x11def4..0x11df08` | `b.eq 0x11e268 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x51c64>` | 0x11e268 (b.eq), 0x11df0c (fallthrough) | - |
| `0x11df0c` | `0x11df0c..0x11df20` | `b.eq 0x11e30c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x51d08>` | 0x11e30c (b.eq), 0x11df24 (fallthrough) | - |
| `0x11df24` | `0x11df24..0x11df38` | `b.eq 0x11e3fc <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x51df8>` | 0x11e3fc (b.eq), 0x11df3c (fallthrough) | - |
| `0x11df3c` | `0x11df3c..0x11df50` | `b.eq 0x11e5a0 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x51f9c>` | 0x11e5a0 (b.eq), 0x11df54 (fallthrough) | - |
| `0x11df54` | `0x11df54..0x11dfac` | `b.ne 0x11db24 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x51520>` | 0x11db24 (b.ne), 0x11dfb0 (fallthrough) | - |
| `0x11dfb0` | `0x11dfb0..0x11dfb0` | `b 0x11e9d0 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x523cc>` | 0x11e9d0 (branch) | - |
| `0x11dfb4` | `0x11dfb4..0x11dfbc` | `b 0x11e368 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x51d64>` | 0x11e368 (branch) | - |
| `0x11dfc0` | `0x11dfc0..0x11e00c` | `b 0x11e3d8 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x51dd4>` | 0x11e3d8 (branch) | - |
| `0x11e010` | `0x11e010..0x11e070` | `b 0x11db24 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x51520>` | 0x11db24 (branch) | 0x11e01c->0xa334 <.text+0x22c4> |
| `0x11e074` | `0x11e074..0x11e0d0` | `b 0x11e894 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x52290>` | 0x11e894 (branch) | 0x11e078->0x139270 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6cc6c>, 0x11e088->0x139e50 <calloc@plt> |
| `0x11e0d4` | `0x11e0d4..0x11e128` | `b 0x11e890 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x5228c>` | 0x11e890 (branch) | 0x11e0e0->0x13917c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6cb78> |
| `0x11e12c` | `0x11e12c..0x11e160` | `b 0x11e390 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x51d8c>` | 0x11e390 (branch) | - |
| `0x11e164` | `0x11e164..0x11e1c0` | `b 0x11e9c8 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x523c4>` | 0x11e9c8 (branch) | 0x11e178->0xaf3c <.text+0x2ecc> |
| `0x11e1c4` | `0x11e1c4..0x11e21c` | `b 0x11db24 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x51520>` | 0x11db24 (branch) | - |
| `0x11e220` | `0x11e220..0x11e264` | `b 0x11e3b8 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x51db4>` | 0x11e3b8 (branch) | - |
| `0x11e268` | `0x11e268..0x11e2b0` | `b 0x11e3c0 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x51dbc>` | 0x11e3c0 (branch) | - |
| `0x11e2b4` | `0x11e2b4..0x11e308` | `b 0x11e7b0 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x521ac>` | 0x11e7b0 (branch) | 0x11e2c0->0x13917c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6cb78> |
| `0x11e30c` | `0x11e30c..0x11e35c` | `b 0x11db24 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x51520>` | 0x11db24 (branch) | - |
| `0x11e360` | `0x11e360..0x11e364` | `mov w8, #0x2` | 0x11e368 (fallthrough) | - |
| `0x11e368` | `0x11e368..0x11e38c` | `mov x5, x22` | 0x11e390 (fallthrough) | - |
| `0x11e390` | `0x11e390..0x11e3a4` | `str x17, [sp, #0xb8]` | 0x11e3a8 (fallthrough) | - |
| `0x11e3a8` | `0x11e3a8..0x11e3ac` | `str x17, [sp, #0xb0]` | 0x11e3b0 (fallthrough) | - |
| `0x11e3b0` | `0x11e3b0..0x11e3b4` | `str x17, [sp, #0xa8]` | 0x11e3b8 (fallthrough) | - |
| `0x11e3b8` | `0x11e3b8..0x11e3bc` | `str x17, [sp, #0xa0]` | 0x11e3c0 (fallthrough) | - |
| `0x11e3c0` | `0x11e3c0..0x11e3c4` | `str x17, [sp, #0x98]` | 0x11e3c8 (fallthrough) | - |
| `0x11e3c8` | `0x11e3c8..0x11e3cc` | `str x17, [sp, #0x90]` | 0x11e3d0 (fallthrough) | - |
| `0x11e3d0` | `0x11e3d0..0x11e3d4` | `str x17, [sp, #0x88]` | 0x11e3d8 (fallthrough) | - |
| `0x11e3d8` | `0x11e3d8..0x11e3dc` | `str x17, [sp, #0x80]` | 0x11e3e0 (fallthrough) | - |
| `0x11e3e0` | `0x11e3e0..0x11e3f8` | `b 0x11db24 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x51520>` | 0x11db24 (branch) | - |
| `0x11e3fc` | `0x11e3fc..0x11e460` | `b 0x11e890 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x5228c>` | 0x11e890 (branch) | 0x11e418->0x13917c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6cb78> |
| `0x11e464` | `0x11e464..0x11e4ac` | `b 0x11e3c8 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x51dc4>` | 0x11e3c8 (branch) | - |
| `0x11e4b0` | `0x11e4b0..0x11e4f4` | `b 0x11e3b0 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x51dac>` | 0x11e3b0 (branch) | - |
| `0x11e4f8` | `0x11e4f8..0x11e558` | `b 0x11db24 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x51520>` | 0x11db24 (branch) | - |
| `0x11e55c` | `0x11e55c..0x11e59c` | `b 0x11e3a8 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x51da4>` | 0x11e3a8 (branch) | - |
| `0x11e5a0` | `0x11e5a0..0x11e5ec` | `b 0x11e3d0 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x51dcc>` | 0x11e3d0 (branch) | - |
| `0x11e5f0` | `0x11e5f0..0x11e644` | `b 0x11e7b0 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x521ac>` | 0x11e7b0 (branch) | 0x11e5fc->0x13917c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6cb78> |
| `0x11e648` | `0x11e648..0x11e6ac` | `b 0x11e7b0 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x521ac>` | 0x11e7b0 (branch) | 0x11e664->0x13917c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6cb78> |
| `0x11e6b0` | `0x11e6b0..0x11e704` | `b 0x11e7b0 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x521ac>` | 0x11e7b0 (branch) | 0x11e6bc->0x13917c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6cb78> |
| `0x11e708` | `0x11e708..0x11e754` | `b 0x11e890 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x5228c>` | 0x11e890 (branch) | 0x11e70c->0x1393cc <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6cdc8> |
| `0x11e758` | `0x11e758..0x11e7ac` | `movk x9, #0x59e8, lsl #48` | 0x11e7b0 (fallthrough) | 0x11e768->0x13917c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6cb78> |
| `0x11e7b0` | `0x11e7b0..0x11e7b4` | `b 0x11e894 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x52290>` | 0x11e894 (branch) | - |
| `0x11e7b8` | `0x11e7b8..0x11e838` | `b 0x11e96c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x52368>` | 0x11e96c (branch) | 0x11e7f0->0xf1ec8 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x258c4> |
| `0x11e83c` | `0x11e83c..0x11e88c` | `movk x9, #0xee97, lsl #48` | 0x11e890 (fallthrough) | 0x11e848->0x13917c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6cb78> |
| `0x11e890` | `0x11e890..0x11e890` | `csel x2, x8, x9, eq` | 0x11e894 (fallthrough) | - |
| `0x11e894` | `0x11e894..0x11e894` | `ldur x6, [x29, #-0x50]` | 0x11e898 (fallthrough) | - |
| `0x11e898` | `0x11e898..0x11e8b4` | `b 0x11db24 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x51520>` | 0x11db24 (branch) | - |
| `0x11e8b8` | `0x11e8b8..0x11e908` | `b 0x11e3e0 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x51ddc>` | 0x11e3e0 (branch) | - |
| `0x11e90c` | `0x11e90c..0x11e968` | `movk x9, #0x6353, lsl #48` | 0x11e96c (fallthrough) | 0x11e924->0x11d798 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x51194> |
| `0x11e96c` | `0x11e96c..0x11e970` | `b 0x11e898 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x52294>` | 0x11e898 (branch) | - |
| `0x11e974` | `0x11e974..0x11e9c4` | `movk x9, #0xc50, lsl #48` | 0x11e9c8 (fallthrough) | 0x11e980->0x13927c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6cc78> |
| `0x11e9c8` | `0x11e9c8..0x11e9cc` | `b 0x11e898 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x52294>` | 0x11e898 (branch) | - |
| `0x11e9d0` | `0x11e9d0..0x11ea50` | `b.ne 0x11ea74 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x52470>` | 0x11ea74 (b.ne), 0x11ea54 (fallthrough) | 0x11e9d4->0x1392c4 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6ccc0>, 0x11e9dc->0x13926c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6cc68>, 0x11e9e4->0x13926c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6cc68>, 0x11e9ec->0x13926c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6cc68>, 0x11e9f4->0x13926c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6cc68>, 0x11e9fc->0x13926c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6cc68>, 0x11ea04->0x13926c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6cc68>, 0x11ea0c->0x13926c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6cc68>, 0x11ea14->0x13926c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6cc68>, 0x11ea1c->0x13926c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6cc68>, 0x11ea24->0x139de0 <free@plt>, 0x11ea2c->0x139de0 <free@plt> |
| `0x11ea54` | `0x11ea54..0x11ea70` | `ret ` | - | - |
| `0x11ea74` | `0x11ea74..0x11ea74` | `bl 0x139df0 <__stack_chk_fail@plt>` | - | 0x11ea74->0x139df0 <__stack_chk_fail@plt> |
