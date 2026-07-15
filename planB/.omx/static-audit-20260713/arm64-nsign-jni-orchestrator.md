# ARM64 nSign JNI orchestrator

## Scope and status

- export/FDE: `0xcc604..0xcd934`
- status: **recovered**
- the flattened FDE has been interpreted end-to-end with stubbed callees;
  descriptor values, exact environment comparison, conditional timestamp
  logging, independent clock-status decisions and JNI return are closed

## JNI arguments

| register | Java/native meaning | prologue evidence |
|---|---|---|
| `x0` | `JNIEnv*` | `0xcc63c`, stack `-0x90` |
| `x1` | helper object/class, not forwarded | unused by descriptor |
| `x2` | Android `Context` | `0xcc63c`, stack `-0x88` |
| `x3` | Java Map/Object | `0xcc634`, stack `-0x80` |
| `x4` | supplied Java-HMAC `byte[]` | `0xcc634`, stack `-0x78` |
| `w5` | Android API | `0xcc62c`, stack `-0x6c` |

## Dynamic wrappers and descriptor

`0xccd3c..0xccd9c` carves five 16-byte value wrappers, a 0x30-byte
descriptor, and a separate output wrapper from the stack.  The descriptor
passed to `0xcbe98` is:

| descriptor offset | value |
|---:|---|
| `+0x00` | `JNIEnv*` value |
| `+0x08` | pointer to Context wrapper |
| `+0x10` | pointer to Map wrapper |
| `+0x18` | pointer to supplied-HMAC wrapper |
| `+0x20` | pointer to API wrapper |

This matches `0xcbe98`'s pre-validation unconditional pointer-slot
dereferences.

## Observable order

1. `0xccdc0`: run one-shot periodic timer helper `0xd4908`.
2. Decode Map key `environment` (`0x1457c0`, XOR `0x28`) and reference value
   `sandbox` (`0x1457d0`, XOR `0x1a`), then `0xcce40` reads the Map value
   through `0xaebf8` and the byte loop at `0xcccb8` compares it with
   `sandbox`.
3. Set the environment auxiliary bit unless Map copy succeeded with a non-null
   C string exactly equal to `sandbox` (case-sensitive, NUL-terminated).
4. `0xcd4b8`: first `CLOCK_REALTIME` sample. Log `Signing all the parameters
   begin` only when both the environment bit and current status are zero.
5. `0xcd774`: call `0xcbe98` with the descriptor and save returned
   `jbyteArray` at stack `-0x98`.
6. Clear the outer status, then `0xcd788` takes the second realtime sample.
7. Log `Signing all the parameters end  ` only when the environment bit and
   second-clock status are both zero. The first-clock failure is deliberately
   not carried into this decision.
8. `0xcd904` returns the saved `jbyteArray` on every branch.

Therefore neither outer clock failure clears or replaces the result produced
by `0xcbe98`.  The inner clock in `0xcbe98` remains different: its failure
returns null before context processing.

## C++

`runRecoveredNsignOrchestratorCC604()` is the callback-driven execution form.
`recoveredNsignOrchestratorCC604Regression()` covers exact sandbox, mismatch,
Map failure, first/second clock failure, null environment and null result.
`analyze_nsign_jni_orchestrator_full.py` interprets the complete ARM64 FDE and
proves the same matrix without loading the shared object.
