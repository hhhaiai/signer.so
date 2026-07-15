# ARM64 public-source list producer recovery (`0x18540..0x1dbd8`)

This function is now identified as a `/proc/self/maps`-based public-source path
producer, not a cipher selector.

## Confirmed inputs and output

ABI input is `(uint32_t* status, const char* packageName,
RecoveredOwnedStringList* output)`.  The output owner remains the 16-byte
`{head, tailSlot}` object consumed by `0x1dbd8`.  The append tail at
`0x1db2c..0x1db94` stores the new node through `*tailSlot` first and then
updates `tailSlot` from the node's `+0x08` next-slot address.

Each node is allocated with `calloc(1, 16)` at `0x1b0c8..0x1b0d4`.  Its value
is produced by `strdup` at `0x1ab70..0x1ab74`; allocation failure writes status
`2`.  This preserves partial-list ownership for the caller's destructor.

## Decoded process-map strings

The function uses process-global CAS locks and XOR-once writable strings:

```text
VMA 0x143100, XOR 0x7d -> /proc/self/maps\0
VMA 0x143110, XOR 0x39 -> r\0
VMA 0x143120, XOR 0x43 -> %*llx-%*llx %*s %*s %*s %*s %s\0
VMA 0x143140, XOR 0x9e -> apk\0
```

The function checks `access("/proc/self/maps", R_OK)` at `0x1c21c`; it does
not directly reference or probe the adjacent qemud/qemu-pipe globals.  The maps
file is opened by `fopen` at `0x1c17c`.  Lines are read with
`fgets(buffer, 0x1080, file)` at `0x1bbf0..0x1bc08`, and the final path token is
extracted by `sscanf` at `0x1bf20..0x1bf44`.

## Last-dot suffix helper

`0xd6cb8..0xd6ed8`, called once by the producer, scans its input string for its
last dot.  It returns the byte after the last dot unless the dot is absent or
is the first byte; those two cases return the shared empty literal at VMA
`0x3068`.  In this producer the returned suffix is compared case-insensitively
with the decoded `"apk"` literal, so the helper is not package-name-specific.
It is implemented directly as `recoveredSuffixAfterLastDot()`.

The following comparison loop folds only ASCII `A..Z` by OR-ing `0x20` and
leaves every other byte unchanged before comparing.  The direct C++ helpers
are `recoveredAsciiLower()`, `recoveredAsciiCaseInsensitiveEquals()` and
`recoveredPathHasApkSuffix()`.

## Package-name path matcher

The producer reserves a `0x800`-byte table (`256 * sizeof(uint64_t)`) and uses
exact, case-sensitive byte-window comparisons between the package-name input
and the parsed path.  This is an inlined Boyer-Moore/Horspool-style substring
search; its observable result is reproduced without the skip-table
optimization by `recoveredPathContainsPackageName()`.  Empty package names
match at the start, as in the native search setup.  The combined predicate is
`recoveredPublicSourcePathCandidateMatches()`:

```text
ASCII-case-insensitive final suffix == "apk"
AND
parsed path contains packageName as an exact byte substring
```

This agrees with the existing one-line maps artifact: changing mapping
addresses, inode, permissions or spacing does not affect the result, while
changing one byte inside the package-name portion removes the candidate.

## Confirmed failure states

The x86_64 cross-architecture state machine closes these error paths:

```text
access("/proc/self/maps", R_OK) != 0 -> state 0x96EEB6C1AF4D042A
                                        -> *status = 8 at 0x1e0c9
fopen(...) == nullptr                  -> state 0xD8E551C8D36C3F01
                                        -> state 0x96EEB6C1AF4D042A
                                        -> *status = 8
calloc/strdup failure                  -> *status = 2 at 0x1e3cc..0x1e3d3
```

Normal `fgets()` EOF enters the close/return chain and does not by itself write
an error status.  Malformed lines (`sscanf != 1`) are skipped back into the
read loop rather than being treated as producer failure.

## Node ownership and completion

For every qualifying path, the exact mutation order is:

```text
calloc(1, 16)
append node through *tailSlot
advance tailSlot to &node->next
strdup(parsedPath)
store result into node->value
```

This ordering is visible in x86_64 at `0x22a8d..0x22aaf`, followed through
state `0xCF84E40FB2E2365C` to `strdup` at `0x1de21..0x1de34`.  Consequently a
`strdup` failure leaves an already-linked node whose value is null; status `2`
is written, the file is closed, and the caller's unconditional list destructor
performs `free(nullptr)` followed by `free(node)`.  A successful copy returns
to the next `fgets`, so duplicate qualifying maps lines are retained as
separate nodes.  `fclose()` is unconditional after every path on which
`fopen()` succeeded, including EOF and either allocation failure.

The complete direct implementation is
`runRecoveredPublicSourceListProducer()`.  `stage18540` has been removed from
`RecoveredNativeContextInitOperations`, and the public-source list checker now
calls the recovered producer directly.
