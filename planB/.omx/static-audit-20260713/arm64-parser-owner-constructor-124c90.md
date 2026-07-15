# ARM64 parser-owner constructor `0x124c90..0x125074`

## Scope

This note statically closes the only JNI-reachable caller-facing constructor
immediately before the already recovered `0x125074` destructor.

| ABI | range |
|---|---|
| ARM64 | `0x124c90..0x125074` |
| x86_64 | `0x11cb9c..0x11cf06` |

Both boundaries are `.eh_frame` FDE boundaries.  ARM64 has one direct caller,
`0xddc4`, which passes `context+0x110` as the path and always forwards the
returned pointer to `0x127194` and finally `0x125074`.

## Recovered behavior

```cpp
ParserOwner* create(uint32_t* status, const char* path) {
    if (access(path, R_OK) != 0) {
        *status = 2;
        return nullptr;
    }

    FILE* stream = fopen(path, "rb");
    if (stream == nullptr) {
        *status = 2;
        return nullptr;
    }

    ParserOwner* owner = calloc(1, 0x48);
    if (owner == nullptr) {
        *status = 1;
        return nullptr; // native code does not fclose(stream)
    }

    owner->stream = stream;
    initialize(owner + 0x18); // 0x122fdc
    initialize(owner + 0x28); // 0x124a18
    initialize(owner + 0x38); // 0x124a18
    return owner;
}
```

The function does not clear or inspect a preexisting status on the success
path.  It only writes status `2` for the access/fopen failures and status `1`
for the owner-allocation failure.

## File mode

The mode is stored in ABI-private XOR form and decoded once:

| ABI | data | XOR | plaintext |
|---|---|---:|---|
| ARM64 `0x145f84` | `8c 9c fe` | `fe` | `72 62 00` = `rb\0` |
| x86_64 `0x13ea23` | `2f 3f 5d` | `5d` | `72 62 00` = `rb\0` |

ARM64 uses the byte compare-exchange helper at `0x139800`; x86_64 uses an
inline `lock cmpxchgb`.  The flattened state constants are shared across both
ABIs, including the access success/failure, fopen failure and calloc
success/failure states.

## Object layout and initialization

```text
+0x00 FILE* stream
+0x08 16 zero bytes retained from calloc
+0x18 first container owner  {head=null, tailSlot=&head}
+0x28 second large owner     {head=null, tailSlot=&head}
+0x38 third large owner      {head=null, tailSlot=&head}
sizeof = 0x48
```

ARM64 success block:

```text
0x124ea0 store FILE* at +0x00 and advance temporary pointer to +0x38
0x124ea4 call 0x122fdc for +0x18
0x124eac call 0x124a18 for +0x28
0x124eb4 call 0x124a18 for +0x38
```

x86_64 mirrors the same stores/calls at `0x11cd03..0x11cd1c`, using
initializer entries `0x11b433` and `0x11c96e`.

## Allocation-failure resource leak

Both ABI functions open the stream before `calloc(1, 0x48)`.  The allocation
failure blocks write status `1`, set the returned owner to null and return
without any `fclose` call.  This is preserved for behavioral parity in the
direct C++ reconstruction, but it is a low-severity file-descriptor leak under
memory pressure and should be fixed in maintained product code.

## C++ and static regression

Implementation:

```text
native-reimplementation/recovered_primitives.cpp
RecoveredParserOwnerCreateOperations124c90
runRecoveredParserOwnerCreate124c90
recoveredParserOwnerCreate124c90Regression
```

The callback-driven regression covers:

1. access failure -> status `2`, no later operation;
2. fopen failure -> status `2`, no allocation;
3. allocation failure -> status `1`, no initializer and no implicit close;
4. success -> preserved incoming status, exact `rb` mode, `calloc(1,0x48)`,
   FILE publication and ordered owner initialization.

Static verifier:

```text
.omx/static-audit-20260713/analyze_parser_owner_constructor_124c90.py
```
