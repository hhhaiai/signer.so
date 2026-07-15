# ARM64 repeated file-parser cluster `0x120858..0x121aac`

This region contains three repeated list-owner families.  All use the same
24-byte node layout:

```text
+0x00 uint32 tag_or_length
+0x04 uint32 payload_length_or_zero
+0x08 owned payload pointer
+0x10 next node
```

## Family B: raw sized payloads

- `0x120858`: bounded sequence of `uint32 payloadLength` followed by payload;
  cumulative offset is uint32 `previous + payloadLength + 4`, with exact-total
  status `8`.
- `0x120afc`: payload-before-node destructor alias.
- `0x120c68`: zeroed 24-byte append alias.

## Family C: tagged payloads

- `0x120de8`: caller record size includes the four-byte tag;
  `payloadLength = uint32(recordSize - 4)`, then tag read, length publication at
  `+0x04`, `calloc(1,payloadLength)` at `+0x08`, exact payload read.
- `0x120ffc`: bounded size-prefixed sequence around `0x120de8`, using the same
  uint32 `size+4` progression and exact-total status `8`.
- `0x121260`: destructor alias.
- `0x1213cc`: append alias.

## Family D: framed tag plus explicit payload length

- `0x12154c`: behaviorally identical to `0x11fe4c`: read tag and explicit
  payload length, require zero-extended `payloadLength+8 == recordSize`, then
  allocate/read payload.
- `0x12183c`: bounded size-prefixed sequence around `0x12154c`, with uint32
  `size+4` progression and exact-total status `8`.

## Aggregate destructor

`0x121aac` owns three consecutive 16-byte list owners and destroys them in the
exact order:

```text
owner+0x20 -> 0x120afc
owner+0x10 -> 0x1203e4
owner+0x00 -> tail-call 0x11fb60
```

## Owned C++ and regression

- `runRecoveredFileListSizedPayloadSequence120858`
- `runRecoveredFileListDestroy120afc`
- `runRecoveredFileListAppend120c68`
- `runRecoveredFileListTaggedPayloadRead120de8`
- `runRecoveredFileListTaggedPayloadSequence120ffc`
- `runRecoveredFileListDestroy121260`
- `runRecoveredFileListAppend1213cc`
- `runRecoveredFileListRecordRead12154c`
- `runRecoveredFileListRecordSequence12183c`
- `runRecoveredThreeFileListDestroy121aac`
- `recoveredFileListRepeatedParserCluster120858121aacRegression`

The regression exercises all three wire formats, field offsets, payload bytes,
list/tail invariants, nested aliases and aggregate cleanup.
