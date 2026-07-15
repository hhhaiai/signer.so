# Composite parser-owner destructor `0x125074..0x125210`

## Cross-ABI ranges

| ABI | Range |
|---|---|
| ARM64 | `0x125074..0x125210` |
| x86_64 | `0x11cf06..0x11d040` |

Both functions implement the same opaque-state dispatch with the same seven
64-bit state constants. The observable source-level behavior is:

```text
if owner == null:
    return

if owner->stream != null:
    fclose(owner->stream)
    owner->stream = null

destroy(owner + 0x18) through the 0x122fe4 list-destructor alias
destroy(owner + 0x28) through the 0x124a20 large-list alias
destroy(owner + 0x38) through the 0x124a20 large-list alias
free(owner)
```

The x86_64 aliases are `0x11b43c -> 0x11b0d8` and
`0x11c977 -> 0x11c5fe`. The callback-driven C++ representation keeps the
native order while allowing the regression to observe it without closing a
real stream or freeing a real outer allocation.

## Evidence anchors

```text
ARM64  0x125094/+0x18, 0x125098/+0x28, 0x1250b0/+0x38
ARM64  0x12518c/0x122fe4, 0x125194/0x124a20,
       0x12519c/0x124a20, 0x1251a4/free
ARM64  0x1251c0/fclose, 0x1251c8/stream clear

x86_64 0x11cf28/+0x18, 0x11cf31/+0x28, 0x11cf3a/+0x38
x86_64 0x11cfda/0x11b43c, 0x11cfe4/0x11c977,
       0x11cfee/0x11c977, 0x11cff8/free
x86_64 0x11d011/fclose, 0x11d025/stream clear
```

Machine-checkable evidence:

```text
.omx/static-audit-20260713/analyze_parser_owner_destructor_125074.py
```
