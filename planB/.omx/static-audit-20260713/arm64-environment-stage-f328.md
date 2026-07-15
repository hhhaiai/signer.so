# ARM64 `0xf328..0xfce0` environment stage dispatcher

## ABI and ownership

The only caller at `0xcbb40..0xcbb50` supplies:

```text
x0 = JNI environment
x1 = caller uint32 status pointer
x2 = Java Context
x3 = native context
```

The function zeroes a `0x878`-byte stack object, initializes it through
`0x8746c(env, javaContext, scratch)`, and copies the returned status to the
caller's status pointer. Every exit calls `0x13000(context)` and
`0x8fb44(scratch)`. Therefore local-object cleanup and the fallback context
mask are unconditional, including initialization failure and final-stage
failure.

## Reachable flattened-state chain

Starting from the sole entry state, static constant propagation removes the
decoy states and leaves this runtime order:

| order | probe/callee | condition | correction |
|---:|---|---|---:|
| 1 | `0x1f058(&u16)` | `u16 != 0` | `0x01` |
| 2 | timing `0xd184(15000ms)`; `0x1fae4(&u16)` | `u16 > 2` | `0x02` |
| 3 | timing; `0x25068(&u16)` | `u16 != 0` | `0x03` |
| 4 | timing; `0x26de0(env,&u16)` | `u16 > 5` | `0x08` |
| 5 | timing; `0x2c618(env)` | boolean true | `0x28` |
| 6 | timing; `0x2cc9c(env)` | boolean true | `0x2c` |
| 7 | timing; `0x21c34(&u16)` | `u16 != 0` | `0x1f` |
| 8 | timing; `0xfce0(status,scratch,context)` | boolean false | return false |

If `0xfce0` returns true, `0x12a30(scratch,context)` runs, the local result is
set to one, and the function returns true after unconditional cleanup. If the
initial `0x8746c` status is nonzero, all probes are skipped and the function
returns false after the same cleanup.

Relevant correction blocks are:

```text
0xfc08 -> 0x01
0xfc60 -> 0x02
0xf8dc -> 0x03
0xf908 -> 0x08
0xf980 -> 0x28
0xf9d8 -> 0x2c
0xfa78 -> 0x1f
```

Each block calls `0x13548c(context+0x20, code)` before ORing context flag bit
zero. ARM64 `0xfc8c..0xfcb4` and x86_64 `0x138de..0x13907` independently
confirm unconditional fallback/cleanup and the one-bit return.

## C++ parity surface

`runRecoveredEnvironmentStageDispatcherF328()` now implements the reachable
orchestration directly. The individual probe bodies and the still-partial
`0xfce0` stage remain address-named callbacks so this FDE can be closed without
inventing semantics for its callees.

`recoveredEnvironmentF328Regression()` validates:

- zero-initialized `0x878` scratch ownership;
- exact call/timing order and seven `15000ms` probes;
- threshold boundaries `2` and `5`;
- ordered corrections `01,02,03,08,28,2c,1f` and flag bit zero;
- initialization failure, final-stage failure, and success return/status paths;
- success-only `0x12a30`;
- unconditional fallback mask and destructor.

Repeatable check:

```bash
python3 .omx/static-audit-20260713/analyze_environment_stage_f328.py
./native-reimplementation/build-and-test.sh
```
