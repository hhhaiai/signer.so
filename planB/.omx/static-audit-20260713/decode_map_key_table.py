#!/usr/bin/env python3
"""Decode the arm64 Map-key table without loading or executing the ELF."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
OUTPUT = Path(__file__).resolve().parent / "arm64-map-key-table.txt"

DATA_FILE_OFFSET = 0x13AE10
DATA_VIRTUAL_ADDRESS = 0x142E10
TABLE_VIRTUAL_ADDRESS = 0x145A30
TABLE_SIZE = 1363
XOR_BYTE = 0x52


def main() -> None:
    file_offset = DATA_FILE_OFFSET + TABLE_VIRTUAL_ADDRESS - DATA_VIRTUAL_ADDRESS
    encoded = SO.read_bytes()[file_offset:file_offset + TABLE_SIZE]
    decoded = bytes(value ^ XOR_BYTE for value in encoded)
    if len(decoded) != TABLE_SIZE or decoded[-1] != 0:
        raise SystemExit("decoded table does not end at the expected NUL byte")
    keys = decoded[:-1].decode("ascii").split(",")
    if len(keys) != 100:
        raise SystemExit(f"expected 100 keys, got {len(keys)}")
    OUTPUT.write_text(
        f"vaddr=0x{TABLE_VIRTUAL_ADDRESS:x}\n"
        f"file_offset=0x{file_offset:x}\n"
        f"encoded_size={TABLE_SIZE}\n"
        f"xor=0x{XOR_BYTE:02x}\n"
        f"decoded_text_size={len(decoded) - 1}\n"
        f"key_count={len(keys)}\n"
        + "\n".join(f"{index:03d} {key}" for index, key in enumerate(keys))
        + "\n"
    )


if __name__ == "__main__":
    main()
