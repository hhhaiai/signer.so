# ARM64 container parser cluster `0x12243c..0x123288`

The functions in this cluster use flattened control flow.  Their call order,
arguments, uint32 arithmetic, status short circuits and boundary branches were
executed with the existing text-only ARM64 interpreter in
`analyze_container_parser_cluster_12243c_123288.py`.

## `0x12243c..0x122bb8`: one `0x58` container node

The function first appends a node through `0x1222a8`, even before reading any
body bytes.  A nonzero post-append status returns with the partial node owned by
the outer list.

Wire order:

```text
uint32 firstSize
first[firstSize]   -> 0x121adc, node+0x00

uint32 secondSize
second[secondSize] -> 0x12183c, node+0x30

uint32 thirdSize
third[thirdSize]   -> 0x122090, node+0x40
```

After each length prefix, cumulative size is advanced with native uint32
wraparound.  Unsigned overshoot writes status `8` before the corresponding
nested parser.  After the owned buffer is read successfully, cumulative size
must exactly equal the caller total; otherwise status `8` is written while the
fully populated node remains owned by the list.

## `0x122d24..0x122fdc`: bounded node sequence

Wire:

```text
repeat:
    uint32 recordSize
    recordBody[recordSize] -> 0x12243c
```

Total zero is a no-op.  For every nonzero sequence, the nested parser runs
before `offset += recordSize + 4`.  Reaching or passing the bound requires exact
equality; overshoot writes status `8`.

## `0x122fe8..0x123254`: single-section wrapper

Wire:

```text
uint32 sectionSize
section[sectionSize] -> 0x122d24
```

`sectionSize + 4` uses uint32 arithmetic.  Unsigned overshoot is rejected before
the nested sequence.  A successful nested sequence is followed by exact-total
validation.  Unlike `0x122d24`, total zero still attempts the four-byte prefix
read and then reports status `8` when that read succeeds with a zero size.

## `0x123288..0x1238ec`: three lists and two fixed fields

Aggregate layout:

```cpp
struct Aggregate {
    FileListOwner first;    // +0x00
    FileListOwner second;   // +0x10
    uint32_t firstValue;    // +0x20
    uint32_t secondValue;   // +0x24
    FileListOwner third;    // +0x28
}; // 0x38
```

Wire order:

```text
uint32 firstSize
first[firstSize]   -> 0x12014c, aggregate+0x00

uint32 secondSize
second[secondSize] -> 0x120858, aggregate+0x10

uint32 firstValue  -> aggregate+0x20
uint32 secondValue -> aggregate+0x24

uint32 thirdSize
third[thirdSize]   -> 0x120ffc, aggregate+0x28
```

The fixed overhead is 20 bytes: three size prefixes plus two fixed values.
All bounds use uint32 cumulative arithmetic, nested nonzero status stops the
state machine, and the final cumulative size must be exact.

## Owned implementation and regression

- `runRecoveredContainerNodeParser12243c`;
- `runRecoveredContainerNodeSequence122d24`;
- `runRecoveredContainerNodeSequenceWrapper122fe8`;
- `runRecoveredThreeListTwoFieldParser123288`;
- `recoveredContainerParserCluster12243c123288Regression`.

The native regression covers valid nested bodies, exact stream positions,
outer ownership, fixed-field publication, final-size mismatch after a fully
read node and destructor cleanup.
