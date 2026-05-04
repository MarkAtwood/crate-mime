#!/usr/bin/env python3
"""
Oracle fixture generator for yencoding crate tests.

This script generates yEnc-encoded test fixtures using pure Python arithmetic.
It is the ground-truth oracle -- fixtures must NOT be re-derived from the Rust crate.

Run from the fixtures directory:
    python3 gen_fixtures.py

All CRC32 values are computed over the *decoded* payload using Python's
binascii.crc32(), which matches RFC 5536 / yEnc spec expectations.
"""

import binascii
import os
import struct

# ---------------------------------------------------------------------------
# Core yEnc encoding (Python arithmetic only -- no yEnc library)
# ---------------------------------------------------------------------------

def yenc_encode_raw(data: bytes) -> bytes:
    """Encode bytes using the yEnc offset+escape algorithm."""
    out = bytearray()
    for b in data:
        v = (b + 42) % 256
        if v in (0, 10, 13, 61):   # NUL, LF, CR, = must be escaped
            out.append(0x3D)        # '='
            v = (v + 64) % 256
        out.append(v)
    return bytes(out)


def yenc_line_wrap(encoded: bytes, line_len: int = 128) -> bytes:
    """
    Split encoded byte stream into lines of at most line_len bytes.
    Lines are separated by CRLF.  A dot at the start of a line is escaped
    per NNTP dot-stuffing (prepend an extra dot).
    """
    lines = []
    i = 0
    while i < len(encoded):
        line = encoded[i:i + line_len]
        # NNTP dot-stuffing: escape leading dot
        if line and line[0:1] == b'.':
            line = b'.' + line
        lines.append(line)
        i += line_len
    return b'\r\n'.join(lines)


def crc32_hex(data: bytes) -> str:
    """Return lowercase 8-char hex CRC32 of data."""
    return format(binascii.crc32(data) & 0xFFFFFFFF, '08x')


# ---------------------------------------------------------------------------
# Article builders
# ---------------------------------------------------------------------------

def single_part_article(
    payload: bytes,
    filename: str = 'test.bin',
    line_len: int = 128,
    override_crc: str | None = None,
    omit_yend: bool = False,
    preamble_lines: list[str] | None = None,
) -> bytes:
    """
    Build a complete single-part yEnc article.

    =ybegin line: size=, name=
    optional preamble lines (inserted *before* =ybegin per the spec)
    encoded data lines
    =yend line: size=, crc32=
    """
    encoded = yenc_encode_raw(payload)
    data_lines = yenc_line_wrap(encoded, line_len)
    crc = override_crc if override_crc is not None else crc32_hex(payload)

    parts: list[bytes] = []

    if preamble_lines:
        for line in preamble_lines:
            parts.append(line.encode('ascii') + b'\r\n')

    parts.append(
        f'=ybegin line={line_len} size={len(payload)} name={filename}\r\n'.encode('ascii')
    )
    parts.append(data_lines)
    parts.append(b'\r\n')

    if not omit_yend:
        parts.append(
            f'=yend size={len(payload)} crc32={crc}\r\n'.encode('ascii')
        )

    return b''.join(parts)


def multipart_article(
    payload: bytes,
    part_number: int,
    total_parts: int,
    part_begin: int,   # 1-based byte offset of first byte in this part
    part_end: int,     # 1-based byte offset of last byte in this part
    filename: str = 'test.bin',
    line_len: int = 128,
) -> bytes:
    """
    Build one part of a multi-part yEnc article.

    =ybegin: line=, part=, total=, size= (total payload size), name=
    =ypart:  begin=, end=
    encoded part data
    =yend:   size= (part size), part=, pcrc32=, crc32= (whole file)
    """
    part_payload = payload[part_begin - 1:part_end]
    encoded = yenc_encode_raw(part_payload)
    data_lines = yenc_line_wrap(encoded, line_len)
    pcrc = crc32_hex(part_payload)
    total_crc = crc32_hex(payload)

    parts: list[bytes] = []
    parts.append(
        (
            f'=ybegin part={part_number} total={total_parts}'
            f' line={line_len} size={len(payload)} name={filename}\r\n'
        ).encode('ascii')
    )
    parts.append(
        f'=ypart begin={part_begin} end={part_end}\r\n'.encode('ascii')
    )
    parts.append(data_lines)
    parts.append(b'\r\n')
    parts.append(
        (
            f'=yend size={len(part_payload)} part={part_number}'
            f' pcrc32={pcrc} crc32={total_crc}\r\n'
        ).encode('ascii')
    )
    return b''.join(parts)


# ---------------------------------------------------------------------------
# Fixture generation
# ---------------------------------------------------------------------------

HERE = os.path.dirname(os.path.abspath(__file__))


def write_fixture(name: str, data: bytes) -> None:
    path = os.path.join(HERE, name)
    with open(path, 'wb') as f:
        f.write(data)
    print(f'  wrote {name}: {len(data)} bytes')


def main() -> None:
    print('Generating yEnc test fixtures...')

    # ------------------------------------------------------------------
    # 1. single_part.yenc  — bytes(range(64))
    # ------------------------------------------------------------------
    payload_64 = bytes(range(64))
    crc_64 = crc32_hex(payload_64)
    single = single_part_article(payload_64, filename='test.bin')
    write_fixture('single_part.yenc', single)

    # ------------------------------------------------------------------
    # 2. multi_part_1.yenc and multi_part_2.yenc — bytes(range(128))
    #    Split evenly: part1 = bytes 0..63, part2 = bytes 64..127
    # ------------------------------------------------------------------
    payload_128 = bytes(range(128))
    crc_128 = crc32_hex(payload_128)
    half = len(payload_128) // 2  # 64

    mp1 = multipart_article(
        payload_128,
        part_number=1, total_parts=2,
        part_begin=1, part_end=half,
        filename='test.bin',
    )
    write_fixture('multi_part_1.yenc', mp1)

    mp2 = multipart_article(
        payload_128,
        part_number=2, total_parts=2,
        part_begin=half + 1, part_end=len(payload_128),
        filename='test.bin',
    )
    write_fixture('multi_part_2.yenc', mp2)

    # ------------------------------------------------------------------
    # 3. prose_preamble.yenc — single-part with 3 preamble text lines
    # ------------------------------------------------------------------
    preamble = [
        'This is a usenet post.',
        'Subject: [01/01] test.bin yenc',
        'Newsgroups: alt.binaries.test',
    ]
    prose = single_part_article(payload_64, filename='test.bin', preamble_lines=preamble)
    write_fixture('prose_preamble.yenc', prose)

    # ------------------------------------------------------------------
    # 4. crc_mismatch.yenc — correct encoding, crc32 forced to 00000000
    # ------------------------------------------------------------------
    crc_bad = single_part_article(payload_64, filename='test.bin', override_crc='00000000')
    write_fixture('crc_mismatch.yenc', crc_bad)

    # ------------------------------------------------------------------
    # 5. truncated.yenc — =yend line omitted
    # ------------------------------------------------------------------
    trunc = single_part_article(payload_64, filename='test.bin', omit_yend=True)
    write_fixture('truncated.yenc', trunc)

    # ------------------------------------------------------------------
    # Summary for manifest generation
    # ------------------------------------------------------------------
    print()
    print('CRC32 values (decoded payloads):')
    print(f'  bytes(range( 64)) crc32 = {crc_64}')
    print(f'  bytes(range(128)) crc32 = {crc_128}')
    print(f'  part1 crc32            = {crc32_hex(payload_128[:half])}')
    print(f'  part2 crc32            = {crc32_hex(payload_128[half:])}')
    print()
    print('Done.')


if __name__ == '__main__':
    main()
