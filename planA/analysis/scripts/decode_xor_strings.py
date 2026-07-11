#!/usr/bin/python3
"""Recover the declared one-byte-XOR strings from libsigner.so samples."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
from typing import Iterable


ARTIFACT = "com.adjust.signature:adjust-android-signature:3.62.0"

# These plaintexts were independently recovered from nSign/JNI/anti-debug call sites.
# The script verifies every observation against the actual bytes instead of expanding
# the catalog with printable-looking guesses.
DECLARED_STRINGS = (
    ("environment_key", "environment", "verified"),
    ("sandbox_value", "sandbox", "verified"),
    ("sign_begin_log", "Signing all the parameters begin", "verified"),
    ("sign_end_log", "Signing all the parameters end  ", "verified"),
    ("map_get_descriptor", "(Ljava/lang/Object;)Ljava/lang/Object;", "corroborated"),
    ("tracer_pid_label", "TracerPid:", "corroborated"),
    ("proc_status_format", "/proc/%d/status", "corroborated"),
    ("map_get_name", "get", "corroborated"),
    ("timestamp_format", "%Y-%m-%dT%H:%M:%S", "corroborated"),
    ("timezone_format", "%z", "corroborated"),
    ("timestamp_log_format", "%s: %s.%03dZ%s", "corroborated"),
)

# Short plaintexts have unrelated uniform-XOR matches elsewhere in the protected
# image. These offsets select the instances independently tied to the JNI Map.get
# and timestamp-formatting call sites across all four exact 3.62.0 samples.
PREFERRED_FILE_OFFSETS = {
    "map_get_name": {
        "arm64-v8a": 0x115F2C,
        "armeabi-v7a": 0x103F36,
        "x86": 0x11076C,
        "x86_64": 0x1077DC,
    },
    "timezone_format": {
        "arm64-v8a": 0x116F44,
        "armeabi-v7a": 0x104E22,
        "x86": 0x1116E2,
        "x86_64": 0x1087D2,
    },
}

RECORD_METADATA = {
    "environment_key": {
        "arm64_guard": {
            "atomic_word_rva": "0x11fa58",
            "initialized_byte_rva": "0x11fa65",
            "once_gate_function_rva": "0x212730",
            "evidence": "decompiler-data-flow",
        }
    }
}


class ElfFormatError(ValueError):
    pass


def xor_bytes(data: bytes, key: int) -> bytes:
    if not 0 <= key <= 0xFF:
        raise ValueError("xor key must fit in one byte")
    return bytes(value ^ key for value in data)


class ElfImage:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        self._segments = self._parse_load_segments()

    def _parse_load_segments(self) -> list[tuple[int, int, int, int]]:
        data = self.data
        if len(data) < 16 or data[:4] != b"\x7fELF":
            raise ElfFormatError(f"not an ELF file: {self.path}")
        elf_class, byte_order = data[4], data[5]
        if elf_class not in (1, 2) or byte_order not in (1, 2):
            raise ElfFormatError(f"unsupported ELF encoding: {self.path}")
        endian = "<" if byte_order == 1 else ">"
        if elf_class == 1:
            header = struct.unpack_from(endian + "HHIIIIIHHHHHH", data, 16)
            phoff, phentsize, phnum = header[4], header[8], header[9]
            phfmt = endian + "IIIIIIII"
        else:
            header = struct.unpack_from(endian + "HHIQQQIHHHHHH", data, 16)
            phoff, phentsize, phnum = header[4], header[8], header[9]
            phfmt = endian + "IIQQQQQQ"
        expected_size = struct.calcsize(phfmt)
        if phnum and phentsize < expected_size:
            raise ElfFormatError("program header entry is truncated")

        segments: list[tuple[int, int, int, int]] = []
        for index in range(phnum):
            offset = phoff + index * phentsize
            if offset + expected_size > len(data):
                raise ElfFormatError("program header table is truncated")
            fields = struct.unpack_from(phfmt, data, offset)
            if elf_class == 1:
                p_type, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, _flags, _align = fields
            else:
                p_type, _flags, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, _align = fields
            if p_type == 1:
                segments.append((p_offset, p_filesz, p_vaddr, p_memsz))
        if not segments:
            raise ElfFormatError("ELF has no PT_LOAD segments")
        return segments

    def rva_to_offset(self, rva: int) -> int:
        for file_offset, file_size, virtual_address, memory_size in self._segments:
            if virtual_address <= rva < virtual_address + memory_size:
                delta = rva - virtual_address
                if delta >= file_size:
                    raise ElfFormatError(f"RVA {rva:#x} is in zero-filled memory")
                return file_offset + delta
        raise ElfFormatError(f"RVA {rva:#x} is outside PT_LOAD segments")

    def offset_to_rva(self, offset: int) -> int:
        for file_offset, file_size, virtual_address, _memory_size in self._segments:
            if file_offset <= offset < file_offset + file_size:
                return virtual_address + offset - file_offset
        raise ElfFormatError(f"file offset {offset:#x} is outside PT_LOAD segments")

    def read_rva(self, rva: int, size: int) -> bytes:
        offset = self.rva_to_offset(rva)
        end = offset + size
        if end > len(self.data):
            raise ElfFormatError("read exceeds ELF file")
        return self.data[offset:end]


def _find_uniform_xor(data: bytes, plaintext: bytes) -> list[tuple[int, int, bytes]]:
    expected = plaintext + b"\0"
    matches: list[tuple[int, int, bytes]] = []
    for key in range(1, 256):
        ciphertext = xor_bytes(expected, key)
        start = 0
        while True:
            offset = data.find(ciphertext, start)
            if offset < 0:
                break
            matches.append((offset, key, ciphertext))
            start = offset + 1
    return matches


def _abi_images(sample_root: Path) -> Iterable[tuple[str, ElfImage]]:
    for library in sorted(Path(sample_root).glob("*/libsigner.so")):
        yield library.parent.name, ElfImage(library)


def build_catalog(sample_root: Path) -> dict[str, object]:
    images = list(_abi_images(sample_root))
    if not images:
        raise FileNotFoundError(f"no ABI libsigner.so files under {sample_root}")

    records: list[dict[str, object]] = []
    for record_id, plaintext, evidence in DECLARED_STRINGS:
        observations: list[dict[str, object]] = []
        decoded = (plaintext + "\0").encode("utf-8")
        for abi, image in images:
            matches = _find_uniform_xor(image.data, plaintext.encode("utf-8"))
            preferred = PREFERRED_FILE_OFFSETS.get(record_id, {}).get(abi)
            if preferred is not None:
                matches = [match for match in matches if match[0] == preferred]
            if len(matches) != 1:
                raise ValueError(
                    f"{record_id}: expected one verified XOR match for {abi}, got {len(matches)}"
                )
            file_offset, key, ciphertext = matches[0]
            rva = image.offset_to_rva(file_offset)
            observations.append(
                {
                    "abi": abi,
                    "sample_sha256": hashlib.sha256(image.data).hexdigest(),
                    "rva": hex(rva),
                    "file_offset": hex(file_offset),
                    "xor_key": hex(key),
                    "ciphertext_hex": ciphertext.hex(),
                    "decoded_hex": xor_bytes(ciphertext, key).hex(),
                    "verified_against_sample": xor_bytes(ciphertext, key) == decoded,
                }
            )
        record = {
            "id": record_id,
            "plaintext": plaintext,
            "encoding": "utf-8+nul",
            "transform": "uniform-byte-xor",
            "evidence": evidence,
            "observations": observations,
        }
        record.update(RECORD_METADATA.get(record_id, {}))
        records.append(record)

    return {
        "schema": "libsigner.xor-strings/v1",
        "sample": {"artifact": ARTIFACT, "abi_count": len(images)},
        "records": records,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        catalog = build_catalog(args.sample_root)
        serialized = json.dumps(catalog, indent=2, sort_keys=True) + "\n"
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized, encoding="utf-8")
    except (OSError, ValueError, ElfFormatError) as exc:
        print(f"decode_xor_strings: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
