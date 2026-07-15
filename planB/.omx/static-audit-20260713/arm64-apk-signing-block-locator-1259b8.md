# ARM64 APK Signing Block locator `0x1259b8..0x127194`

## Scope

This note statically closes the flattened function immediately between the
recovered ZIP EOCD scanner and the still-unrecovered Signing Block entry
consumer.

| ABI | FDE range |
|---|---|
| ARM64 | `0x1259b8..0x127194` |
| x86_64 | `0x11d585..0x11e1d8` |

The direct caller is ARM64 `0x127194`, which passes the same status pointer and
the `0x48`-byte parser owner created by `0x124c90`.

## Recovered interface and owner fields

```cpp
void locateApkSigningBlock(uint32_t* status, ParserOwner* owner);

struct ParserOwner {
    FILE* stream;                    // +0x00
    long signingBlockFooterOffset;   // +0x08
    uint64_t signingBlockSize;       // +0x10
    ...                              // +0x18..+0x47
};
```

`+0x08` is written by checked `ftell` immediately after seeking `-24` from the
central-directory start.  It therefore records the file offset of the footer
size word at the beginning of the final 24-byte Signing Block footer.

`+0x10` receives that footer's uint64 size.  The function later reads the
duplicate uint64 size at the Signing Block header and requires exact equality.

## Semantic operation order

The EOCD scanner leaves the stream immediately after the four-byte EOCD
signature.  Ignoring opaque dispatcher states, the reachable operation order
is:

```text
0x125770 scan backward for EOCD
if caller status != 0: return

fseek(+12, SEEK_CUR)
fread(uint32 centralDirectoryOffset)
fseek(centralDirectoryOffset, SEEK_SET)
fread(4-byte central-directory signature)
require signature == 50 4b 01 02, else status 3

fseek(-20, SEEK_CUR)
fread(16-byte footer magic)
require magic == "APK Sig Block 42", else status 5

fseek(-24, SEEK_CUR)
ftell(owner+0x08)
fread(uint64 footerSize -> owner+0x10)
fseek(uint64(8 - footerSize), SEEK_CUR)
fread(uint64 headerSize)
require headerSize == footerSize, else status 6
return with stream immediately after headerSize
```

All checked seek/read/tell failures use the already recovered wrappers and
therefore write status `2`.  The function does not clear a preexisting status:
after the initial EOCD scan, any nonzero status immediately exits.

## Position arithmetic

Let `C` be the absolute start of the ZIP Central Directory.  After reading and
validating `PK 01 02`, the stream is at `C + 4`.

```text
C + 4  --seek -20-->  C - 16  (magic start)
C - 16 --read 16-->   C       (central-directory start)
C      --seek -24-->  C - 24  (footer size word)
C - 24 --read 8-->    C - 16
```

For a native footer size `S`, the Signing Block starts at `C - S - 8`:

```text
(C - 16) + (8 - S) = C - S - 8
```

ARM64 performs `sub x2, x9, x8` with `x9=8` and `x8=S`, so the subtraction is
modulo 64 bits before the result is interpreted by `fseek` as a signed `long`.
The C++ reconstruction preserves those exact bits with `memcpy` into `long`.

## Cross-ABI encoded constants

### ZIP Central Directory File Header signature

| ABI | address | encoded | XOR | plaintext |
|---|---:|---|---:|---|
| ARM64 | `0x145f90` | `f7 ec a6 a5` | `a7` | `50 4b 01 02` |
| x86_64 | `0x13ea2c` | `e6 fd b7 b4` | `b6` | `50 4b 01 02` |

### APK Signing Block footer magic

| ABI | address | encoded | XOR | plaintext |
|---|---:|---|---:|---|
| ARM64 | `0x145fa0` | `7d 6c 77 1c 6f 55 5b 1c 7e 50 53 5f 57 1c 08 0e` | `3c` | `APK Sig Block 42` |
| x86_64 | `0x13ea30` | `57 46 5d 36 45 7f 71 36 54 7a 79 75 7d 36 22 24` | `16` | `APK Sig Block 42` |

The native images decode each writable marker once under a byte
compare-exchange lock.  The source reconstruction uses immutable plaintext
arrays because the observable comparison values are identical and the
process-global decode race is not part of the parser API.

## Error mapping

| Condition | status | stream position at detection |
|---|---:|---|
| checked seek/read/tell failure | `2` | wrapper-dependent partial position |
| central-directory signature mismatch | `3` | `C + 4` |
| APK Signing Block magic mismatch | `5` | `C` |
| header/footer uint64 size mismatch | `6` | first entry position after header size |

On success the incoming status is zero and remains zero.  The stream is left
immediately after the initial Signing Block uint64 size, at the first ID-value
entry consumed by `0x127194`.

## Input-validation observation

The native function verifies only:

1. central-directory signature;
2. footer magic;
3. equality of the two uint64 sizes.

It does not explicitly require `size >= 24`, prove that `C - size - 8` is
inside the file, or impose an upper bound before the modulo-64-bit subtraction.
Checked `fseek`/`fread` reject many malformed values, but seek-past-EOF may
succeed and a crafted small size can point the header read into footer bytes.
The downstream impact remains dependent on `0x127194`; this is currently a
low-severity parser-hardening finding rather than a proven memory-safety bug.

## C++ and static evidence

Implementation:

```text
native-reimplementation/recovered_primitives.cpp
RecoveredApkSigningBlockLocatorOperations1259b8
runRecoveredApkSigningBlockLocator1259b8
recoveredApkSigningBlockLocator1259b8Regression
```

The callback-driven regression represents:

1. preexisting-status early exit after the EOCD scan;
2. the exact successful seek/read/tell sequence and owner publications;
3. statuses `3`, `5` and `6` for the three semantic mismatches;
4. scanner status failure;
5. each of the eleven checked I/O failure positions.

Static verifier:

```text
.omx/static-audit-20260713/analyze_apk_signing_block_locator_1259b8.py
```

It re-disassembles both ABIs, decodes both marker sets, verifies the operation
and status blocks, checks the owner layout and C++ token order, and requires
the recovered coverage entry.
