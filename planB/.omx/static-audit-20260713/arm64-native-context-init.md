# ARM64 native context initialization stages

## Scope

This closes the source-level orchestration at:

```text
0xcba90..0xcbbd4  stage 1
0xcbbd4..0xcbe94  stage 2
0xcbe94..0xcbe98  tail alias to 0x143e8
```

Repeatable static checker:

```text
.omx/static-audit-20260713/analyze_native_context_init.py
```

The corresponding C++ entries are:

```text
runRecoveredNativeContextInitStage1()
runRecoveredNativeContextInitStage2()
runRecoveredEnvironmentDispatcherTail()
```

The still-opaque large callees retain address-based callback names until each
is independently lifted.  The small correction/flag leaves, the complete
`0x16b7c` owned-string producer, the `0xcde4` string-consistency stage, and the
`0x179f8` `publicSourceDir` producer are now direct owned C++ functions.  The
wrappers preserve argument positions, branching, status resets, context
pointer slots, and call order.

## Stage 1: `0xcba90`

ABI:

```text
x0 = JNIEnv-like environment
x1 = Java Context object
x2 = native context
```

Source-equivalent order:

```cpp
uint32_t status = 0;
sub_13088(context);
if (!sub_f328(env, &status, javaContext, context)) {
    sub_13000(context);
    status = 0;
}
sub_9279c(&status, env, context);
```

Evidence:

- `0xcbadc`: unconditional `0x13088(context)`.
- `0xcbb40..0xcbb50`: `0xf328(env,&status,javaContext,context)`.
- `0xcbb54..0xcbb5c`: bit-zero result selects success/failure state.
- `0xcbb74..0xcbb90`: false-only `0x13000(context)` followed by status zero.
- `0xcbb94..0xcbba0`: final `0x9279c(&status,env,context)` on both paths.

x86_64 `0xbaca8..0xbad82` has the same state constants and calls:

```text
0x15ebe  0x13088 equivalent
0x130fb  0xf328 equivalent
0x15e7d  0x13000 equivalent
0x9685c  0x9279c equivalent
```

## Stage 2: `0xcbbd4`

ABI:

```text
x0 = JNIEnv-like environment
x1 = Java Context object
x2 = supplied Java HMAC byte[]
x3 = native context
```

Initial sequence:

```cpp
uint32_t status = 0;
sub_8128(env, context);
if (!sub_e6c0(&status, env, context, javaContext, suppliedJavaHmac)) {
    sub_f1fc(context);
    status = 0;
}
```

The `0xe6c0` false branch is therefore fail-open.  It does not return from
stage 2.  Both branches continue with the first owned-pointer producer:

```cpp
sub_16b7c(&status, env, javaContext, &context->ownedPointer108);
```

### First producer succeeds (`status == 0`)

```cpp
sub_cde4(context);
sub_179f8(&status, env, javaContext,
          context->ownedPointer108, &context->ownedPointer110);
```

If the second producer succeeds:

```cpp
sub_d474(context);
sub_ddc4(context);
```

If the second producer fails:

```cpp
sub_d980(context);
sub_e674(context);
sub_d9b4(context);
sub_e6a8(context);
status = 0;
```

### First producer fails (`status != 0`)

```cpp
sub_d428(context);
sub_d980(context);
sub_e674(context);
sub_d45c(context);
sub_d9b4(context);
sub_e6a8(context);
status = 0;
```

All three paths then execute:

```cpp
sub_14ef8(context);
sub_15104(env, context);
```

The stage has no source-level return value.  ARM64 returns the residual value
left by `0x15104`; x86_64 likewise returns the residual `rax` from `0x175d5`.
The only upper caller at `0xcc254` consumes neither register and immediately
calls `0x143e8` at `0xcc25c`.

Cross-ABI direct-call mapping:

| ARM64 | x86_64 | role in this wrapper |
|---:|---:|---|
| `0x8128` | `0xe80a` | pre-stage |
| `0xe6c0` | `0x12544` | supplied/expected Java-HMAC stage |
| `0xf1fc` | `0x1303a` | false-only context mask |
| `0x16b7c` | `0x18473` | producer for `context+0x108` |
| `0xcde4` | `0x111bc` | second-producer pre-stage |
| `0x179f8` | `0x18fe3` | producer for `context+0x110` |
| `0xd428` | `0x11770` | first-producer failure-only stage |
| `0xd45c` | `0x11789` | first-producer failure-only stage |
| `0xd474` | `0x1179b` | both-producers-success stage |
| `0xd980` | `0x11bf5` | failure cleanup/probe stage |
| `0xd9b4` | `0x11c0e` | common failure tail stage |
| `0xddc4` | `0x11f34` | both-producers-success stage |
| `0xe674` | `0x12519` | failure cleanup/probe stage |
| `0xe6a8` | `0x12532` | common failure tail stage |
| `0x14ef8` | `0x17453` | unconditional finalizer |
| `0x15104` | `0x175d5` | unconditional finalizer |

## JNI references and memory ownership

Neither wrapper contains a direct JNI vtable call, `DeleteLocalRef`, `free`,
`calloc`, or `realloc`.  Those effects belong to the address-named callees and
must be preserved when those callees are replaced.  Stage 2 itself passes the
two native output slots by address and deliberately does not pre-clear them:

```text
context+0x108 -> first producer output
context+0x110 -> second producer output
```

The enclosing `0xcbe98` orchestration zeroes `context+0x08..+0x127` before
calling these stages, so both pointers begin null on the normal JNI path.

## Tail alias `0xcbe94`

`0xcbe94` is exactly:

```asm
b 0x143e8
```

It is a source-level tail entry to the environment dispatcher, not another
dispatcher and not a cryptographic algorithm selector.
