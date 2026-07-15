# ARM64 public-source linked-list check

## Scope

```text
0xd474..0xd980
```

C++:

```text
runRecoveredPublicSourceListCheck()
```

Repeatable checker:

```text
.omx/static-audit-20260713/analyze_public_source_list_check.py
```

## Recovered flow

The wrapper initializes:

```cpp
uint32_t status = 0;
RecoveredOwnedStringList list = {0, &list.head};
```

Then:

```cpp
timingComparison(context, 15000.0);
sub_18540(&status, context->ownedPointer108, &list);

if (status != 0) {
    correction(0x37);
    flags |= 1;
} else {
    timingComparison(context, 15000.0);
    if (list.head == 0) {
        correction(0x37);
        flags |= 1;
    } else {
        bool found = false;
        for (Node* node = list.head; node != nullptr; node = node->next) {
            if (strcmp(node->string, (char*)context->ownedPointer110) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            correction(0x29);
            flags |= 1;
        }
    }
}

flags |= 0x0080020000000000;
destroyOwnedStringList(&list);
```

The second timing call occurs for every status-zero producer result, including
a null list head.  It is skipped only when `sub_18540` leaves nonzero status.

## Linked-list layout and comparison

The producer output is a 16-byte intrusive owner:

```text
+0x00  head node
+0x08  tail pointer-slot address
```

Its empty invariant is `{head=null, tailSlot=&head}`.  Each list node is read
as two consecutive 64-bit fields:

```text
+0x00  C-string pointer
+0x08  next-node pointer
```

The native byte loop has no null guard for either the node string or
`context+0x110`.  It stops on the first unequal byte or equal NUL terminators.
An unequal result advances to `node->next`; exhausting the list emits
correction `0x29`.

## Failure and cleanup

- Nonzero producer status emits correction `0x37`.
- A successful producer that returns a null list also emits `0x37`.
- An empty/nonmatching list emits `0x29` only after complete traversal.
- A matching node emits neither `0x29` nor `0x37`.
- The fixed flag mask is applied on every path.
- `sub_1dbd8(&list)` is unconditional and occurs after the flag write.
- The destructor repeatedly saves `node->next` into owner head, frees
  `node->string`, then frees the node.  It finally restores
  `{head=null, tailSlot=&head}` and does not free the stack owner itself.

## Cross-ABI confirmation

x86_64 `0x1179b..0x11bf5` confirms:

| ARM64 | x86_64 | role |
|---:|---:|---|
| `0xd184` | `0x11519` | 15000 ms timing helper, called twice |
| `0x18540` | `0x19bdf` | linked-list producer |
| `0xd980` | `0x11bf5` | correction `0x37` wrapper |
| `0x13548c(0x29)` | `0x12f5ad(0x29)` | no-list-match correction |
| `0x1dbd8` | `0x22b54` | 16-byte intrusive-owner cleanup |

This function validates an environment/package-source result.  It has no
request-parameter-dependent cipher selection and is not a crypto dispatcher.
