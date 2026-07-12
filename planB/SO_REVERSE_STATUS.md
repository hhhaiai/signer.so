# `libsigner.so` 3.67.0 reverse-engineering status

This document is deliberately an evidence log. The default Java desktop backend
still executes the original ARM64 `libsigner.so` through Unidbg. The optional
Java `recovered` backend now invokes the independently source-built C++17 core,
does not load the original SO, and exactly matches the frozen Pixel result. The
remaining boundary is Android probe-to-correction mapping, not Java integration
or the AES/HMAC/result-layout algorithm.

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
| `0x9279c` | `nOnResume` helper: sets context `+0xe0` bit `0x1000000000000`; not the metadata/algorithm dispatcher |
| `0x9954c` | Protected metadata item builder, called once for each of the four fixed key/value pairs |
| `0x99f10` / `0x99de8` | JNI `NewStringUTF` calls for metadata key/value respectively |
| `0x9a4dc` | JNI `Map.put` call for a completed metadata item |
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

The Java/Unidbg signer and the frozen Pixel reference are equivalent. The
independent C++ implementation reproduces the complete 176-byte pipeline, and
`runtime.backend=recovered` now exposes it behind the same Java `Signer` API and
fixed `onResume -> sign` lifecycle. What remains before calling it a general SO
replacement is the complete mapping from every Android/native probe to its
correction event.

## 2026-07-12 complete source-built result pipeline

### Final format and fixed cryptographic material

The independently compiled C++ now proves the complete layout:

```text
176 bytes = 16-byte IV + 128-byte AES-256-CBC ciphertext + 32-byte HMAC-SHA256
```

Recovered AES-256 key:

```text
ffb5e5f9c862b637d13351c292633e39
965a3c2d037ed64dfff5388e11d80db3
```

Recovered HMAC-SHA256 key:

```text
caab83444a2146392abb96b642306155
29a770c63c163c1c7528673e0671728f
```

The HMAC message is the 128-byte ciphertext only; it does not include the IV.

### IV derivation

`0x11a62c/0x11a64c` call Bionic `rand()` twice per output word. Four words are:

```text
IV_word[i] = rand() XOR rand()
```

The seed is native `timeSeconds`. For `1760000000` the result is
`3b273362218b186a73e7349775b93f11`. Changing only the seed to `1760000001`
produces a C++ signature exactly equal to the original SO's complete 176 bytes.

### 113-byte payload

```text
01
00 08 + 8 environment halfwords
02 + 4-byte field2 serialized in reverse order
03 + 20-byte certificate SHA1
04 + 32-byte custom-state SHA-256 field
05 + SHA256(empty)
06 + one-byte state
```

Field 4 hashes a different serialization of the same inputs: certificate SHA1,
`00 08` plus the halfwords, field2 in forward order, `SHA256(empty)`, state,
and the native plaintext.

### Field-4 custom SHA-256 initial state

The source constants are emitted at `0xf8xxx..0xf9a4c`, copied through
`0x111020`, then XORed with `0xcccccccc` by `0x115ca0..0x115ce8`. The resulting
initial state is:

```text
cd46a0de d5c62fe0 02cb3985 fd4a15a3
07cad499 63840dbf 51698010 ca03ff52
```

Using this state with otherwise standard SHA-256 padding/compression over the
Pixel 229-byte material gives these exact block states:

```text
1 9c5245c90d73ee79a98ab1650b7d7fd74ba327d58460a7b4389832e193d3b2ad
2 b87423995a0954c8c6454b4a60fc23d6f2a35e8e75acef675af49f911f931a02
3 e283c5c66393e853d87b0712ab34170cf0bab471e6f6c02c6da1da731b55d080
4 fef6ae81ab7a34b0c938952ba406bbee57d47d7b82a99fde1a6b84e42e105380
```

This closes the earlier reason why ordinary `SHA256(229-byte material)` did not
match field 4.

### Field-0 correction model

The field starts with eight halfwords `encodeCorrection(0x40..0x47)`.
Environment correction events overwrite the first N slots in event order. The
original SO rounds capacity up in blocks of eight halfwords and repeats the
eight-value base pattern before applying overrides: `8 -> 16 -> 24 -> 32 ...`.

```text
trampoline=false: [2b,36,05]    -> d49d b5d3 6ee6 6c8f a19a 6ae7 a7f2 cc92
trampoline=true : [2b,36,25,05] -> d49d b5d3 cacc 6ee6 a19a 6ae7 a7f2 cc92
```

Decrypting both original-SO outputs and rebuilding them in C++ proves the rule;
both complete 176-byte results match exactly.

A combined nine-event profile proves the expansion rule end-to-end:

```text
corrections = 2b,09,37,2a,3c,35,36,25,05
field 0     = 16 halfwords
payload     = 129 bytes
ciphertext  = 144 bytes
result      = 16-byte IV + 144-byte ciphertext + 32-byte tag = 192 bytes
```

The independently built C++ result and the Java recovered-backend result both
match the original SO's complete 192 bytes.

The default-off `ADJUST_NATIVE_APPEND_CORRECTIONS` diagnostic redirects the
original SO at the native context consumer, invokes the real correction helper
at `0x13548c`, and restores the complete Unicorn CPU context before normal
execution resumes. Injecting 13 events after the four-event Pixel sequence
produces this additional original-SO oracle:

```text
corrections = 2b,36,25,05,01,02,03,04,05,06,07,08,09,0a,0b,0c,0d
field 0     = 24 halfwords
payload     = 145 bytes
ciphertext  = 160 bytes
result      = 16-byte IV + 160-byte ciphertext + 32-byte tag = 208 bytes
```

Decrypting the result confirms field-0 count byte `0x18`. The recovered C++
backend, after changing growth from an unsupported doubling assumption to
eight-halfword chunking, reproduces all 208 bytes exactly.

#### Narrowed correction conditions

Static AArch64 disassembly now closes two wrapper-level conditions without
assigning unsupported Android marketing names:

- `0x80c0` always calls `0x13548c(context+0x20, 0x2b)`, then ORs bit 0 into
  `context+0xe0`. Its observed call site is `0x8998` inside the protected
  initialization state machine. Entry/return probes across package, path,
  certificate, maps, timing, API 23/35/36 and trampoline variants show exactly
  one `0x2b` event on every successful `nOnResume`. It is therefore the fixed
  first successful native-context initialization event, not a variable Android
  environment anomaly.
- `0xf224` loads `context[+0x8]`. If that byte is nonzero, the state machine
  reaches `0xf2d8` and calls `0x13548c(context+0x20, 0x05)`; if it is zero,
  the correction is skipped and the function only updates `context+0xe0`.
  The producer is now identified: `0xd184` calls AArch64 syscalls `169`
  (`gettimeofday`) and `113` (`clock_gettime`), converts both results to a
  common time scale, compares their elapsed/delta value with a caller-supplied
  threshold, and writes byte `1` at `0xd32c` when the protected timing state
  selects the anomaly branch. Narrow dynamic evidence on the Pixel profile is:

  ```text
  timing-check-entry value=0x0
  timing-check-write before=0x0 write=0x1
  correction-0x05-gate value=0x1
  ```

  `nOnResume` calls the correction gate at `0xcc26c`. The configurable host
  observation is `runtime.correction05Enabled`; setting it false immediately
  before `0xf224` removes only correction `0x05`.
- Decrypting that original-SO output proves the `context+0x8` timing flag is
  not payload field 6: with correction `0x05` disabled, field 0 becomes
  `[2b,36,25]`, while the payload still ends in `06 01`. The recovered backend
  therefore keeps payload state `true` and independently controls correction
  `0x05`; conflating the two would produce a different signature.
- `0x14e44` is a simple unconditional wrapper for correction `0x36`; its
  dispatcher call site is `0x14a04`. The containing dispatcher at `0x14d9c`
  calls helper `0xd78b8`, which accesses `/proc/self/maps` and writes an integer
  result through an output pointer. Narrow original-SO probes establish:

  ```text
  maps contains a line with current packageName and /base.apk:
      helper return=0, result=0, corrections=2b,36,25,05
  maps exists but has no such package/base.apk line:
      helper return=0, result=0, corrections=2b,37,36,25,05
  maps path missing:
      result=8, corrections=2b,37,35,36,25,05
  ```

  A line-level binary search of the 3268-line frozen maps snapshot reduced the
  success condition to line 3189, the mapped package `.../base.apk` entry.
  Follow-up path-shape experiments prove the decision is not exact sourceDir
  containment: a line must contain the current runtime package name and
  `/base.apk`. A package-name-only shared-library line still produces `0x37`;
  a package/base.apk line suppresses it. Changing the runtime package while
  leaving the old maps path produces `0x37`; changing the maps package with it
  suppresses `0x37`. Address, permission bits, inode/device fields and spacing
  do not decide the branch.

  Separate one-line inputs containing `frida-server`, `gum-js-loop`,
  `libfrida-gadget.so`, `XposedBridge.jar`, or `/data/local/tmp/clean.so` all
  produced the same missing-package-baseApk sequence `[2b,37,36,25,05]`. Therefore
  this branch is an application APK mapping-presence check, not evidence of a
  Frida/Xposed keyword blacklist.

  Thus `0x37` is the maps-present-but-current-package-base.apk-not-found event,
  `0x35` is the maps path missing/access-failure event, and `0x36` is a baseline
  maps probe/scan completion event present in all observed cases. It is
  incorrect to name `0x36` itself as "maps missing". The Java recovered backend
  now implements this package/base.apk line rule. If such a line exists but its
  extracted first APK path differs from `applicationInfo.publicSourceDir`, the
  separate correction `0x29` is emitted.

### Multi-configuration oracle evidence

`native-reimplementation/build-and-test.sh` requires exact complete-signature
matches for:

1. frozen Pixel reference;
2. `timeSeconds=1760000001`;
3. `signerCodeTrampolineDetected=false`;
4. `correction05Enabled=false`, producing corrections `[2b,36,25]` while
   retaining payload field 6 as `01`;
5. empty `/proc/self/maps`, producing `[2b,37,36,25,05]`;
6. missing `/proc/self/maps`, producing `[2b,37,35,36,25,05]`;
7. changed `device_name`, which changes the native plaintext and field 4;
8. omitted `android_id`, `country`, and `device_name`; the original SO allocation
   length and complete output prove missing fields contribute empty bytes;
9. APK signer certificate versus PackageManager certificate mismatch, producing
   correction `0x2a` immediately after the earlier package/maps/path events;
10. a combined nine-correction profile, proving 8-to-16 field-0 expansion and a
    complete 192-byte result.

### Correction `0x2a`: APK/package certificate mismatch

Controlled original-SO experiments kept every Pixel input fixed while changing
the certificate returned through the emulated PackageManager and/or resigning
the same APK payload:

```text
reference APK + reference certificate:       2b,36,25,05
alternate APK + matching alternate cert:     2b,36,25,05
alternate APK + reference certificate:       2b,2a,36,25,05
reference APK + alternate certificate:       2b,2a,36,25,05
v2-only alternate APK + matching cert:       2b,36,25,05
v3-only APK + matching cert:                  2b,36,25,05
v3-only APK + alternate cert:                 2b,2a,36,25,05
```

Changing the PackageManager certificate by one byte, truncating/appending it,
using zero bytes, arbitrary text, or a different valid X.509 certificate while
keeping the reference APK all produced `0x2a`. A separately signed APK with its
own matching certificate removed `0x2a`, proving that this is not a hardcoded
reference fingerprint check. It is the mismatch event between the certificate
reported for the package and the actual signer certificate parsed from
`applicationInfo.sourceDir`/`baseApk`.

`RecoveredNativeBackend` parses v1 and v2 APK signer certificates through the
project-local Maven dependency. The project-owned pure Java
`ApkSigningBlockCertificates` additionally parses APK Signature Scheme v3
(`0xf05368c0`) and v3.1 (`0x1b93ad61`) signing blocks directly from EOCD,
central-directory offset, APK Signing Block pairs and length-prefixed signer
records. It does not invoke Android SDK tools at runtime. A valid v3-only APK
with the matching reference certificate exactly reproduces the original-SO
no-`0x2a` 176-byte result; replacing only the PackageManager certificate emits
the original-SO `0x2a` result. Both complete outputs match the recovered C++
backend byte-for-byte. Unreadable/unsigned APKs remain an explicit
`runtime.correctionCodes` calibration case rather than being guessed.

### Corrections `0x09`, `0x34`, `0x29`, `0x38`, and `0x3c`

Controlled single-variable original-SO experiments close four additional
environment events:

- `0x09`: `/proc/self/cmdline` is non-empty, but its first NUL-terminated process
  name differs from the runtime package name. A matching cmdline suppresses it;
  whitespace or another non-empty process name emits it. Earlier package-only
  experiments also left the frozen cmdline unchanged and therefore did not
  isolate the APK manifest. A corrected experiment changes runtime package and
  cmdline together while leaving the APK manifest unchanged; `0x09` disappears,
  proving binary AXML manifest package mismatch is not this event.
- `0x34`: `/proc/self/cmdline` is missing or its first process-name field is
  empty. The unique wrapper is `0xd428`, with observed call sites `0xcbd7c` and
  `0xd068`; the missing/empty experiment reaches the latter and emits exactly
  `0x34`. `0x09` and `0x34` are mutually exclusive for the observed cmdline
  states.
- `0x29`: `/proc/self/maps` contains a current-package `/base.apk` mapping, but
  the path extracted from the first such line differs from
  `applicationInfo.publicSourceDir`. If no package/base.apk line exists,
  `0x37` is emitted and this comparison is not reached.
- `0x38`: `applicationInfo.publicSourceDir` cannot be opened/is absent. The
  basename and path shape do not decide it: preparing the same path through
  `sourceDir` or `filesystem.files` removes only `0x38`. The Unidbg IO resolver
  now treats an unprovided publicSourceDir distinct from sourceDir as ENOENT, so
  stale rootfs files from previous runs cannot alter the observation.
- `0x3c`: the event is present exactly when
  `androidApi != 36`. It is independent of `targetSdk`. Original-SO probes emit
  it for API 18/21/22, API 23 through 35, and again for 37/40, but not for 36.
  The API 18-22 path is now executable on the desktop through SharedPreferences,
  Android Base64, AndroidKeyStore RSA private-key entry, Cipher and SecretKeySpec
  JNI emulation; APIs 18, 21 and 22 all produce the same exact original-SO
  176-byte result for equal downstream observations.

The observed combined ordering is:

```text
2b, 34-or-09, 37-or-29, 38, 2a, 3c, 35, 36, 25, 05
```

`0x34`/`0x09` and `0x37`/`0x29` are mutually exclusive pairs in the recovered model. Other entries
appear only when their corresponding observation is true. The nine-event
original-SO vector `2b,09,37,2a,3c,35,36,25,05` is reproduced byte-for-byte by
both the C++ CLI and the unchanged Java `Signer` API through
`runtime.backend=recovered`.

### API-selected cryptographic layers

JNI traces confirm that the signer has API-selected key acquisition and MAC
paths in addition to the independently recovered native result envelope:

```text
API 23+:
  AndroidKeyStore.getKey("key2")
  -> HmacSHA256

API 18-22:
  SharedPreferences["adjust_keys"]["encrypted_key"]
  -> Base64.decode
  -> AndroidKeyStore PrivateKeyEntry.getPrivateKey
  -> RSA/ECB/PKCS1Padding decrypt
  -> SecretKeySpec(..., "AES")
  -> HmacSHA256

Observed native result envelope:
  custom-state SHA-256
  -> AES-256-CBC + PKCS#7
  -> HMAC-SHA256(ciphertext)
  -> IV || ciphertext || tag
```

The desktop profile can now reproduce the API 18-22 persistent state instead
of only generating a fresh pair. `device.legacyKeyStore` imports a PKCS#8 RSA
private key plus X.509 SubjectPublicKeyInfo public key, while
`device.sharedPreferences.adjust_keys.encrypted_key` supplies the paired
Base64 RSA/PKCS1-wrapped secret. A controlled API 18 original-SO test succeeds
only with the imported pair and reproduces the complete established 176-byte
oracle.

For equal correction sequences and payload inputs, API 18/21/22 and API 35
produce the same complete `adj8` result, even though their Android key retrieval
paths differ. This proves a dynamic crypto/key-management switch, but does not
yet prove a second final envelope algorithm. Unreached protected dispatcher
branches remain under investigation and are not collapsed into the recovered
`adj8` path without an original-SO oracle.

Changing only the Java-side signing key/HMAC input did not change any native
signature byte on the Pixel profile. This agrees with field 5 being
`SHA256(empty)` on the recovered path; the source implementation does not claim
that Java HMAC bytes are a field-4 input.

### `algorithm=adj8` selection evidence

The initial trace label for `0x9279c` was incorrect. Static disassembly proves
that the function is only the `onResume` state-bit setter:

```text
ldr x8, [x2, #0xe0]
orr x8, x8, #0x1000000000000
str x8, [x2, #0xe0]
ret
```

The protected metadata item builder starts at `0x9954c`. Four original-SO call
sites invoke it with four static encoded key/value buffers. The opt-in
`ADJUST_NATIVE_METADATA_TRACE=1` probe maps them as follows (addresses are
module-relative):

```text
key 0x142ea8 + value 0x142eb4 -> headers_id     = 9
key 0x142ed0 + value 0x142ea0 -> adj_signing_id = 1400000
key 0x142eb8 + value 0x142ec8 -> native_version = 3.67.0
key 0x142ee0 + value 0x142eec -> algorithm      = adj8
```

API 22, API 36 and the combined nine-correction profile reach the same four
builder calls with the same static key/value addresses and values. A separate
27-case host matrix varied API 18/22/23/28/35/36/40, environment, activity
kind, client SDK, public request version, minimal parameters and 64 extra
parameters. Every valid case returned the same `adj8`, `1400000`, `9`, and
`3.67.0` metadata. Evidence is stored under:

```text
.omx/algorithm-matrix/results.json
.omx/metadata-direct.stderr
.omx/metadata-api22.stderr
.omx/metadata-api36.stderr
.omx/metadata-combined.stderr
```

The current evidence therefore supports this narrower conclusion for
`libsigner.so` 3.67.0: multiple cryptographic primitives and an API-selected
key-management path exist, but `algorithm=adj8` is a fixed static metadata
value on every reachable valid path tested so far. It does not prove that all
other library versions use only `adj8`, and it does not yet prove that no
unreached/tamper/failure branch in this binary can select a different final
envelope.

### Targeted native crypto-switch matrix

A direct original-SO matrix now separates the Java HMAC argument from the
native API/environment inputs. The probe fixes PID, `time`, `gettimeofday`,
`clock_gettime` and `/dev/urandom`, then calls the unchanged native descriptor:

```text
nOnResume()
-> nSign(Context, Object, byte[], int)
```

For API 36, changing the third argument across 0, 16, 31, 32, 33 and 64 bytes,
and changing its byte value from `0x11` to `0x22`, produces the exact same
192-byte result SHA-256 every time:

```text
118637a615c3bf42ca3d7abbe8a0d2777ff7cd733c71a9601d0c34a6f8629b7b
```

Thus the reached native `adj8` path does not select a final cipher from the
length or content of the Java-produced HMAC byte array. API is observable,
but the newly isolated API 23/24 boundary changes the environment correction
vector rather than the final envelope:

```text
API 23 corrections: 2b,07,34,37,38,2f,36,05
API 24 corrections: 2b,07,34,37,38,2f,3c,36,05

API 23 -> 176 bytes, algorithm=adj8
API 24 -> 192 bytes, algorithm=adj8
```

The added `0x3c` makes field 0 cross the 8-halfword capacity boundary, so the
plaintext/ciphertext grows by one AES block. This is dynamic input selection
inside the same recovered `custom SHA-256 -> AES-256-CBC -> HMAC-SHA256`
envelope, not evidence of AES-GCM, RSA or another final signer algorithm.

Reproducible evidence:

```text
.omx/ProbeNativeCryptoSwitch.java
.omx/native-crypto-input-matrix-deterministic.log
.omx/native-api-switch-matrix-deterministic.log
.omx/native-api23-corrections.stderr
.omx/native-api24-corrections.stderr
```

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
