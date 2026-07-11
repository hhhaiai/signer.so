# `libsigner.so` 3.67.0 reverse-engineering status

This document is deliberately an evidence log, not a claim that the native
library has been fully recovered.  The desktop runner executes the original
ARM64 `libsigner.so` through Unidbg; it does not substitute a reconstructed
signature implementation.

## Artifact

| Item | Value |
| --- | --- |
| File | `adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so` |
| Format | ELF64 AArch64, stripped |
| GNU build-id | `e3effad6e520baa84e5f29946b780b268258cc43` |
| JNI exports | `Java_com_adjust_sdk_sig_NativeLibHelper_nOnResume`, `Java_com_adjust_sdk_sig_NativeLibHelper_nSign` |

## Recovered and independently verified behavior

1. The public Java bridge keeps the original `Signer` descriptors.  The native
   descriptor used by the runner is
   `nSign(Landroid/content/Context;Ljava/lang/Object;[BI)[B`.
2. `nSign` receives the same 32-byte HMAC on the Pixel 8 reference run and on
   the desktop run.
3. The native plaintext allocation is 155 bytes and consists of the ordered
   request/device fields.  Its captured bytes are equal on the reference run
   and the desktop run.
4. The fixed runtime values are equal: PID `4242`, `time()` `1760000000`,
   `gettimeofday()` `1760000000.123000`, and `clock_gettime()`
   `1760000000.123000000`.
5. The first eight Bionic `rand()` values after `srand(1760000000)` are equal:
   `708751583, 286884797, 1500726753, 2029542795, 1992164192, 89733111,
   1363640712, 620674713`.
6. The SO asks Java for `SHA1` and computes the SHA-1 certificate fingerprint.
   The desktop result is `164a86faf30e412b59223a36ccbe0f6e46e40958`, equal to
   `reference-certificate.der`.
7. The 176-byte result starts with an equal 16-byte prefix on the true-device
   and desktop runs:
   `3b273362218b186a73e7349775b93f11`.
8. The protected source-vector operation for the first 16-byte body block is
   standard AES-256. The observed sequence is initial AddRoundKey, 13 rounds
   of SubBytes/MixColumns/AddRoundKey, and a final SubBytes/AddRoundKey without
   MixColumns.
9. The recovered 32-byte AES key is
   `ffb5e5f9c862b637d13351c292633e39965a3c2d037ed64dfff5388e11d80db3`.
   All 15 dynamically extracted round keys match the standard AES-256 key
   expansion.
10. Standard JCE `AES/ECB/NoPadding` independently reproduces the traced
    desktop block exactly:
    `3a273bb6bc3ecb04958bbb36efd3d8b6 ->
    ddd8309a1bb05b2a137aa23a545411eb`.

## Native investigation map

| Module-relative address | Observation |
| --- | --- |
| `0xcba8c` | `Java_com_adjust_sdk_sig_NativeLibHelper_nOnResume` |
| `0xcc604` | `Java_com_adjust_sdk_sig_NativeLibHelper_nSign` |
| `0x95680` | JNI `SetByteArrayRegion` output path |
| `0x11d9e0` | Native plaintext allocation return path |
| `0x11daa8` / `0x11daac` | `time()` then `srand()` path |
| `0x913a0` | `SHA-256` string reference in obfuscated JNI-related path |
| `0x1441d8`, `0x1442f0`, `0x144390` | Runtime-XOR/anti-emulation string state differs between device and Unidbg |
| `0x1463c5`, `0x146693`, `0x1466ad` | Device/Unidbg environment state flags differ before `srand()` |

## Recovered result-marshalling chain

The final byte-array handoff is no longer an opaque endpoint.  Static
disassembly and a non-intrusive Unidbg memory-write trace establish this chain:

```text
libsigner + 0x11e178
  -> libsigner + 0x0af3c  (allocates a JNI byte array)
  -> libsigner + 0x095680 (JNI SetByteArrayRegion wrapper)
```

At `0x0af3c`, the original fourth argument is the result byte length and the
fifth is the native byte buffer.  `0x095680` calls the JNI table entry at
offset `0x680` with `(jbyteArray, start=0, length, buffer)`.  The output
allocation is made by the preceding `0x11e074 -> 0x139270 -> calloc` path.

The opt-in host-only diagnostic
`ADJUST_OUTPUT_WRITE_TRACE_ADDRESS=<hex-address>` uses Unidbg's memory-write
trace, rather than a debugger breakpoint or allocator wrapper.  On the fixed
reference run it identified final-body word `0xddd8309a` flowing through the
generic word-vector writer at `0x138318`, called from `0x10ee98`.  This is a
serialization/marshalling stage, not yet the key-derivation implementation.

The caller at `0x10ee98` has now been disassembled and observed at runtime:

```text
0x10ee7c  ldr x0, [x26]
0x10ee80  ldr x23, [x21]
0x10ee84  bl  0x138744       # obtain source word for index w22
0x10ee88  mov w3, w0
0x10ee8c  mov x0, x19
0x10ee90  mov x1, x23
0x10ee94  mov w2, w22
0x10ee98  bl  0x138318       # write word to destination vector
```

`ADJUST_SOURCE_WORD_TRACE=1` is an opt-in code trace around the reader call,
not the writer call: it captures the source object and index immediately
before `0x10ee84`, then captures the returned word at `0x10ee88`.  This is
important because `0x10ee98` has already overwritten `x0` with the writer
context (`x19`); an earlier diagnostic that treated that register as the
reader's source was invalid and has been removed.  The final desktop body
still begins with returned word `0xddd8309a`, but the source-object evidence
must now be collected at `0x10ee84` before making any claim about its layout
or the earliest divergence.

That corrected desktop trace establishes the actual source layout for the
first body word: the reader's source object is at `0x123183a0`, has a
`0x480`-word data area at `0x12511000`, and has a two-entry offset table at
`0x123170d0`.  The second table entry is `0x1d4`, so reader index `0` selects
the raw word at data index `468`; it is already `0xddd8309a` before the final
copy.  The corresponding native sequence is:

```text
0x10ecb8 -> 0x138b74  # obtain the first body word
0x10ecd4 -> 0x138318  # append it to the protected source vector
0x10ee84 -> 0x138744  # read it back by logical output index
0x10ee98 -> 0x138318  # copy it to the JNI output vector
```

Therefore the first desktop/true-device difference is before `0x10ecb8`, not
in either vector reader or final marshalling.  An attempted narrow Frida
`Interceptor` on physical `libsigner.so+0x10ee84` caused the protected
`nSign` call not to complete, matching the earlier Stalker limitation.  It is
not retained in the reference harness; further physical evidence must avoid
an in-process hook at that address.

Static disassembly of `0x138b74` shows that it is a protected word accessor:
it reads a count and node pointer from its second argument, reads the node's
word and next pointer, invokes `0x139de0`, then returns the word.  The fixed
desktop run supplies `0xddd8309a` at `0x10ecb8`; the true reference supplies
`0x51da6894` at the corresponding final output position.  The still-unknown
producer is the protected code that populates this operand before the
accessor, not `0x138b74`'s reader mechanics.

### Verified protected-VM materialization of the first divergent word

The prior conclusion is now narrowed to a concrete write and a concrete
stack operation.  These observations use only default-off Unidbg backend
code hooks; normal signing has none of them installed.

1. `ADJUST_WATCH_MEMORY_CHECKPOINTS` samples selected module-relative PCs
   without broad instruction logging.  With the watch address
   `0x12511750`, the word remains `0x010008d4` through `0x10ecbc` and becomes
   `0xddd8309a` only after the call at `0x10ecd4` returns.
2. The target call's static body is the generic protected vector writer at
   `0x138318`.  With a caller filter of `0x10ecd8`, its dynamic registers
   prove the exact store:

   ```text
   libsigner + 0x1384d8: x23 = 0x12511000, w25 = 0x1d4,
                            watched = 0x010008d4
   libsigner + 0x1384dc: w8 = 0xddd8309a
                            str w8, [x23, w25, uxtw #2]
   libsigner + 0x1384e0: watched = 0xddd8309a
   ```

   Thus the physical address is exactly
   `0x12511000 + 0x1d4 * 4 = 0x12511750`.  This is a materialization store,
   not the origin of the value in `w8`.
3. The value comes from the protected linked-node stack.  At `0x10ec44` and
   `0x10ec5c`, `0x138b74` pops respectively `0x00d8309a` and
   `0xdd000000`.  The caller performs `orr w2, w0, w21` and calls
   `0x138a70` at `0x10ec74`.  Static disassembly of `0x138a70` shows that it
   allocates a 16-byte node, stores `w2` as its word, and links it to the
   operand stack.  The resulting node word is `0xddd8309a`; it is then popped
   at `0x10ecb8` and materialized by the writer above.
4. The node address seen in the final stage (`0x1231f170`) is a transient heap
   allocation, not a stable input address.  Sampling it before the final VM
   stage observes unrelated heap reuse.  It must therefore not be treated as
   a durable device parameter or patched as if it were an environmental
   source.

The former strict-reference discrepancy was consequently **not** caused by
`0x138b74`, `0x138a70`, the generic writer, or final byte-array marshalling.
Those routines implement a stack-machine evaluation and serialization.  The
later codeword/dispatcher investigation documented below closed the producer
gap.  These observations now serve as evidence for the independently compiled
primitive slice under `native-reimplementation/`; they still do not by
themselves constitute a complete SO replacement.

For low-overhead repeatable host evidence, the runner now supports these
default-off diagnostics:

```text
ADJUST_ACCESSOR_TRANSITION_TRACE=1
ADJUST_WATCH_MEMORY_ADDRESS=<guest address>
ADJUST_WATCH_MEMORY_CHECKPOINTS=<comma-separated libsigner relative PCs>
ADJUST_WATCH_MEMORY_CHECKPOINT_LR=<optional relative caller return PC>
ADJUST_WATCH_MEMORY_CHECKPOINT_REGISTERS=1
ADJUST_CRYPTO_WORD_TRACE=1
ADJUST_VECTOR_STORE_WATCH_RAW_RANGE=<start:end raw indices>
ADJUST_VM_NODE_WATCH_ADDRESS=<guest address>
ADJUST_VM_STACK_SNAPSHOT_PC=<libsigner relative PC>
ADJUST_VM_STACK_SNAPSHOT_TOP_VALUE=<optional top word>
```

`ADJUST_CRYPTO_WORD_TRACE` and the vector-writer watch path use backend
`CodeHook` rather than `traceCode`, so their own diagnostics do not emit a
full instruction trace.  A full-module block hook was tested once and was too
slow for the protected path; it is deliberately not retained.

## Recovered AES-256 block primitive

The earlier “unknown protected producer” has now been narrowed substantially.
`ADJUST_VECTOR_STORE_WATCH_RAW_RANGE=0x3d6:0x3e5` observes raw source slots
`982..997` at the real vector store. For caller `libsigner.so+0x104fb4`, the
hook records both the byte before and after XOR. Their XOR is the round-key
byte. One fixed desktop run produced exactly `15 * 16 = 240` AddRoundKey
events and these round keys:

```text
00 ffb5e5f9c862b637d13351c292633e39
01 965a3c2d037ed64dfff5388e11d80db3
02 9f62887b57003e4c86336f8e145051b7
03 6c09ed846f773bc990820347815a0ef4
04 23c9377774c9093bf2fa66b5e6aa3702
05 e2a577f38dd24c3a1d504f7d9c0a4189
06 404a90a934839992c679ff2720d3c825
07 55c39fccd811d3f6c5419c8b594bdd02
08 fb8be762cf087ef0097181d729a249f2
09 f0f9a44528e877b3eda9eb38b4e2363a
10 738e67efbc86191fb5f798c89c55d13a
11 2e059ac506eded76eb44064e5fa63074
12 778af520cb0cec3f7efb74f7e2aea5cd
13 b6e19c78b00c710e5b48774004ee4734
14 1f2aedd2d42601edaadd751a4873d0d7
```

The first two rows form the 256-bit key. A canonical AES-256 key expansion
reproduces rows `00..14` exactly. Dynamic caller semantics independently
agree with AES: `0x10337c` performs SubBytes (for example input `0xa8`
becomes AES S-box value `0xc2`), the `0xfe130` family performs MixColumns,
and `0x104fb4` performs AddRoundKey.

Decrypting the archived Pixel 8 first body ciphertext with the same fixed key
shows that the desktop and Pixel 8 AES inputs differ in only four bytes:

```text
desktop input  3a273bb6bc3ecb04958bbb36efd3d8b6
Pixel 8 input  3a273bb6bc3ecba0bf89d236efd3d8b6
XOR delta      00000000000000a42a02690000000000

raw slot 989   desktop 04 -> Pixel a0
raw slot 990   desktop 95 -> Pixel bf
raw slot 991   desktop 8b -> Pixel 89
raw slot 992   desktop bb -> Pixel d2
```

This proves that the first-block discrepancy is not the AES algorithm and is
not an AES-key mismatch. It is upstream in the producer of pre-AES source
slots `989..992`. It does **not** yet prove the 160-byte body's block mode,
padding/layout, or that every later block uses the same wrapper.

## Current boundary

### 2026-07-11 strict-reference closure

The former four-byte pre-AES discrepancy is closed.  The producer chain is:

```text
0x143e8 protected environment dispatcher
  -> 0x13063c signer-code trampoline detector
  -> code 0x25 correction through 0x13548c
  -> 0xcacc inserted before fixed code 0x05 / 0x6ee6
  -> context + 0x54 becomes 0x6ee6cacc
  -> vector serialization, prefix XOR and AES-256
```

The downstream byte permutation turns this codeword material into the
previously observed `...cacd6ee6...` serialized source bytes; `0xcacd` is not
the pre-permutation correction codeword itself.

`0x13063c` scans tables of `libsigner.so` function entry addresses.  It copies
up to the first eight bytes of each entry and recognizes an ARM64
`LDR literal -> BR` trampoline pattern.  Its result controls the dispatcher
branch that calls correction code `0x25`.

The frozen Pixel 8 result was captured while `fixed-runtime.js` had Frida
Interceptor hooks installed on the exported `nOnResume` / `nSign` entries.
Those hooks are therefore part of the captured native environment, even
though they are not an intrinsic Pixel hardware property.  The desktop job
models the observation explicitly:

```json
{
  "device": {
    "runtime": {
      "signerCodeTrampolineDetected": true
    }
  }
}
```

No Frida runtime is used on the computer.  `DeviceProfile`, `SignerOneClick`
and `AdjustSignatureRunner.Config` carry this value to a narrow Unidbg model
of the detector result.  With the value enabled, the original SO produces the
archived Pixel bytes without modifying `reference-result.json`:

```text
./test-device-reference.sh
exit 0
Pixel 8 device reference exact structured JSON match OK
raw signature length = 176 bytes
```

`SignerOneClick.firstMismatch` recursively requires the same JSON key sets,
list sizes and scalar values.  The shell test deliberately does not compare
serialized JSON text because `/` and `\/` are equivalent JSON strings; the
embedded `expectedResultFile` comparison is the authoritative strict gate.

The remaining reverse-engineering boundary is now the requested complete
independent C/C++/Go replacement.  The Java/Unidbg signer and the frozen Pixel
reference are equivalent, but normal execution still loads the original ARM64
`libsigner.so`.  `native-reimplementation/` independently compiles and tests
AES-256 plus the complete 16-halfword correction encoder recovered from
`0x13531c`; the complete 176-byte native pipeline has not yet been reproduced
by that source.

## Instrumentation constraints observed

Two broad tracing techniques were tested and deliberately not retained in the
runner/reference harness:

- Frida `Stalker` call-event tracing on the true-device `nSign` path prevents
  the protected call from completing.
- A narrow Frida `Interceptor` at `libsigner.so+0x10ee84` likewise prevents
  the protected true-device `nSign` call from completing.
- HookZz wrapping of libc allocator entry points (`malloc`/`calloc`/`realloc`)
  causes an unmapped read in Unidbg's libc dispatcher.
- `ADJUST_TRACE=1` is useful only for short JNI/property surveys: a complete
  fixed-reference run produced a host-JVM `SIGBUS` in macOS `libverify.dylib`
  after the native result returned.  Do not use it as a regression verifier;
  leave it disabled for normal runs and use the narrow opt-in traces instead.

Both techniques change execution enough to be unusable as equivalence
evidence.  Future probes must use selective, low-overhead observations at
known native addresses or externally visible buffers, then prove that the
unmodified desktop signer still passes its ordinary regression suite.

## Negative environment experiments

The true-device trace reports successful `access()` calls for a subset of
`/dev/__properties__` nodes.  Adding the observed successful nodes
(`property_info`, `build_odm_prop`, `build_prop`, and `exported_config_prop`)
to the desktop `filesystem.files` profile did not change any byte of the
desktop 176-byte result.  Those property-node existence checks are therefore
not the remaining direct derivation input for the captured reference case.
