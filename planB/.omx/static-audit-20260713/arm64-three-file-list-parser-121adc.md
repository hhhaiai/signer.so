# ARM64 three-section file-list parser `0x121adc..0x122090`

## Recovered ABI

```cpp
void helper(
    uint32_t* status,
    ThreeFileListOwner* owner,
    uint32_t totalSize,
    FILE* stream);
```

`ThreeFileListOwner` contains list owners at offsets `0x00`, `0x10` and
`0x20`.

## Wire order and routing

```text
uint32 firstSize
firstSection[firstSize]    -> 0x12014c, owner+0x00

uint32 secondSize
secondSection[secondSize]  -> 0x120858, owner+0x10

uint32 thirdSize
thirdSection[thirdSize]    -> 0x120ffc, owner+0x20

optional trailing bytes
```

The helper maintains a uint32 cumulative count including all three four-byte
size prefixes:

```text
after first  = firstSize + 4
after second = firstSize + secondSize + 8
after third  = firstSize + secondSize + thirdSize + 12
```

Each addition uses native 32-bit wraparound.  Immediately after each size is
read, the current cumulative value must be unsigned `<= totalSize`; otherwise
status `8` is written before the corresponding nested parser runs.  Every
nested parser is followed by a nonzero-status short circuit.

After the third parser:

- cumulative equal to `totalSize`: return without seeking;
- cumulative less than `totalSize`: call recovered checked fseek with
  `offset = totalSize - cumulative` and `whence = SEEK_CUR (1)`.

## Evidence addresses

```text
0x121dec / 0x121e1c  first size read / first parser
0x121f48 / 0x122034  second size read / second parser
0x121f24 / 0x121ea0  third size read / third parser
0x121f74..78          first cumulative bound
0x121fec..ff8         second cumulative bound
0x121fa0..fb4         third cumulative bound
0x121db8..dc8         status 8 publication
0x121e30..e78         trailing SEEK_CUR skip
```

## Owned C++ and regression

- `runRecoveredThreeFileListParser121adc`
- `recoveredThreeFileListParser121adcRegression`

The regression builds all three real nested wire formats, verifies list field
contents and final stream position including trailing bytes, then exercises the
first upper-bound failure and confirms no list publication.
