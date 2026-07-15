# protected engine final-algorithm selection audit

This is a static-only cross-ABI audit. No target library or recovered program
was executed.

## Scope

The final protected engine is the single ARM64 FDE:

```text
0xf1ec8..0x11ba78
```

It receives a fixed count of nine descriptors from the final consumer. There
is no separate algorithm identifier argument and no indirect `blr` call in the
engine.

## Complete direct-call vocabulary

The engine contains 7,223 direct call sites and only 17 unique targets:

```text
0x138a70  protected word-stack push
0x138b74  protected word-stack pop
0x138744  framed word-arena read
0x138c8c  duplicate one zero-based indexed stack word
0x138318  framed word-arena write
0x138e60  top/index swap
0x138e58  nonempty wrapper
0x138560  frame push
0x138660  frame pop
0x137a78  counter decrement
0x137980  counter push
0x138728  current frame length
0x137898  stack-push tail alias
0x13789c  stack-empty tail alias
0x1378a0  stack-pop tail alias
rand@plt
__stack_chk_fail@plt
```

There are zero indirect calls. In particular, there is no function-pointer
dispatcher that selects AES-CBC, AES-GCM, ChaCha20, or another final cipher.

## Conditional-branch accounting

Counting `b.cond`, `cbz/cbnz`, and `tbz/tbnz` gives 7,114 conditional branches.
Of those, 6,499 target the single common early-return block `0xf214c`.

At least 6,493 of those 6,499 are immediately preceded by:

```asm
ldr  w8, [x19]          // protected-engine status
cbnz w8, 0xf214c        // abort on nonzero status
```

The remaining six retain `w8` across a register-restore instruction before the
same branch. Thus the overwhelming majority of apparent engine branching is
error/status propagation after calls to the recovered stack/arena helpers,
not algorithm selection.

Other repeated branch families are structurally accounted for:

- 108 branches to `0xf23c8` are generated operation-dispatch loop edges;
- 66 branches to `0x11ba64` converge on `status = 8` bounds failure;
- 22 branches to `0x119b10` terminate bounded word-copy loops.

This does not yet rename every branch predicate, but it materially narrows the
unclassified surface from thousands of apparent choices to the generated
circuit's loop/operation schedule.

## Alternate-suite signature scan

All four shipped ABIs were scanned for:

```text
expand 32-byte k
expand 16-byte k
ChaCha20
Poly1305
AES/GCM
GCM/NoPadding
```

There are no hits in arm64-v8a, armeabi-v7a, x86, or x86_64.

The two ARM64 engine immediates equal to `0x87` occur at `0x10c80c` and
`0x10e2ac` inside long alternating index/value table-construction schedules.
They are table bytes in the fixed AES logical circuit, not a GHASH mode
selection branch. No ChaCha sigma word sequence or Poly1305 clamp/mask family
was found.

The prior strings-rendered `=gcm`/`=gcmj` fragments remain disproved as names:
cross-ABI disassembly shows that they are bytes inside the opaque control-state
constant `0x9224eb6a6d63673d`, used in state comparisons.

## What actually switches dynamically

There is a real Android-API-dependent cryptographic routing layer outside the
final protected engine:

```text
API <18   -> unsupported Java-HMAC key route
API 18-22 -> preference/Base64 + RSA/ECB/PKCS1Padding unwrap
API >=23  -> AndroidKeyStore key2 lookup
all successful routes -> Java Mac HmacSHA256
```

This switches how the Java-HMAC key is obtained. It does not switch the final
native signature envelope. The recovered final path remains the sequential
adj8 pipeline:

```text
custom-state SHA-256
-> AES-256-CBC with PKCS#7
-> HMAC-SHA256 over ciphertext
-> IV || ciphertext || 32-byte tag
```

## Current verdict

There is currently no positive static evidence for multiple final signature
algorithms selected by request parameters. The user's remembered "multiple
crypto paths" most likely corresponds to the API-dependent KeyStore/RSA key
provisioning routes plus the sequential SHA/AES/HMAC layers.

This is not used to mark the huge protected engine recovered: complete parity
still requires lifting its generated operation schedule and closing every
remaining status/output state. The reproducible counter/scan script is
`analyze_protected_engine_algorithm_selection.py`.
