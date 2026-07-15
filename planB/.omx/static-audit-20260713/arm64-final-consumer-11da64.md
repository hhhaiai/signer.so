# ARM64 final consumer `0x11da64..0x11ea78`

The complete static state-machine interpretation recovers this transaction:

1. `time` seeds `srand`.
2. Create descriptors for context ranges `+0x50/128`, `+0xf0/20`.
3. Materialize selected Map plaintext through `0x11d798`.
4. Create descriptors for `+0xe0/16`, `+0x30/32`, `+0x20/4`, the
   big-endian plaintext length, plaintext bytes, the big-endian reserved
   dynamic length, and the reserved dynamic bytes.
5. Create the protected work object, run `0xf1ec8` with exactly nine
   descriptors, read its output length, allocate a zeroed output buffer, and
   export the work result.
6. Build the JNI result through `0xaf3c`.

Descriptor/work/export failures are normalized to outer status `4`.
`0x11d798` and `0xaf3c` statuses are preserved. A null output allocation sets
status `2`. Any failure invokes metadata rollback `0xa334` with a separate
cleanup status that cannot replace the outer failure.

Every path then destroys the work object, releases descriptor indices in
order `2,1,6,5,0,3,4,8,7`, frees output, frees plaintext, and returns whether
the final outer status is zero. The static interpreter verifies the complete
success call sequence and every descriptor/materializer/work/engine/allocation/
export/result failure boundary.
