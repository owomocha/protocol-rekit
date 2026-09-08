"""Recover string constants an arm64 function points at -- without a disassembler.

On Apple silicon a function that references a string does it in two steps:

    adrp x1, <page>          ; x1 = page-aligned address, +-4GB of here
    add  x1, x1, #<offset>   ; x1 = exact address of the bytes

So if you want to know which literal a routine uses, you don't need Hopper or
a full capstone dependency -- you need to decode two instruction words and add
them up. That's a few bit shifts. This module does exactly that: decode the
handful of instructions involved, follow the adrp/add pair to a virtual
address, map that back to a file offset via the Mach-O segments, and read the
C string sitting there.

It's deliberately small. The point isn't to reimplement a disassembler; it's
that for this one very common idiom you don't have to.
"""
from __future__ import annotations

import struct
import sys


def decode_movz(word: int) -> tuple[int, int, int] | None:
    """MOVZ Wd/Xd, #imm16, LSL #(shift). Returns (rd, imm16, shift) or None.

    The sf bit (W vs X register) is masked out, so both widths decode the same.
    """
    if (word & 0x7F800000) != 0x52800000:
        return None
    rd = word & 0x1F
    imm16 = (word >> 5) & 0xFFFF
    shift = ((word >> 21) & 0x3) * 16
    return rd, imm16, shift


def decode_adrp(pc: int, word: int) -> tuple[int, int] | None:
    """ADRP Xd, <label>. Returns (rd, target_page_address) or None."""
    if (word & 0x9F000000) != 0x90000000:
        return None
    rd = word & 0x1F
    immlo = (word >> 29) & 0x3
    immhi = (word >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):          # sign-extend the 21-bit immediate
        imm -= 1 << 21
    target = (pc & ~0xFFF) + (imm << 12)
    return rd, target & 0xFFFFFFFFFFFF


def decode_add_imm(word: int) -> tuple[int, int, int] | None:
    """ADD (immediate). Returns (rd, rn, imm) or None. Handles the LSL #12 form."""
    if (word & 0x7F800000) != 0x11000000:   # sf masked out: W and X both match
        return None
    rd = word & 0x1F
    rn = (word >> 5) & 0x1F
    imm = (word >> 10) & 0xFFF
    if (word >> 22) & 0x1:       # sh bit: immediate is shifted left 12
        imm <<= 12
    return rd, rn, imm


def read_cstr(data: bytes, offset: int, limit: int = 256) -> str:
    end = data.find(b"\x00", offset, offset + limit)
    if end < 0:
        end = min(offset + limit, len(data))
    return data[offset:end].decode("ascii", "replace")


def follow_adrp_add(code: bytes, base_va: int, window: int = 16):
    """Scan `code` for adrp/add pairs and yield (site_va, reg, target_va).

    `base_va` is the virtual address of code[0]. For each ADRP we look a short
    `window` of instructions ahead for the matching ADD on the same register --
    that's the pair that materializes a pointer.
    """
    n = len(code) // 4
    for i in range(n):
        word = struct.unpack_from("<I", code, i * 4)[0]
        adrp = decode_adrp(base_va + i * 4, word)
        if adrp is None:
            continue
        reg, page = adrp
        for j in range(i + 1, min(i + 1 + window, n)):
            add = decode_add_imm(struct.unpack_from("<I", code, j * 4)[0])
            if add and add[0] == reg and add[1] == reg:
                yield base_va + i * 4, reg, page + add[2]
                break


# --- tying it to a real Mach-O (used from the CLI, not needed for the tests) --

FAT_MAGIC, FAT_MAGIC_64 = 0xCAFEBABE, 0xCAFEBABF
CPU_TYPE_ARM64 = 0x0100000C  # covers arm64 and arm64e (same cputype)


def thin_macho(data: bytes, cpu_type: int = CPU_TYPE_ARM64) -> bytes:
    """Return the arm64 slice of a universal binary, or `data` if already thin.

    Fat headers are big-endian; the arm64 and arm64e subtypes share one cputype,
    so this picks up either.
    """
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic not in (FAT_MAGIC, FAT_MAGIC_64):
        return data
    wide = magic == FAT_MAGIC_64
    nfat = struct.unpack_from(">I", data, 4)[0]
    pos = 8
    for _ in range(nfat):
        if wide:
            ct, _cs, off, size = struct.unpack_from(">IIQQ", data, pos)
            pos += 32
        else:
            ct, _cs, off, size = struct.unpack_from(">IIII", data, pos)
            pos += 20
        if ct == cpu_type:
            return data[off:off + size]
    raise ValueError("no arm64 slice in this universal binary")


LC_SEGMENT_64 = 0x19


def _load_commands(data: bytes):
    """Yield (cmd, offset) for each load command of a 64-bit Mach-O."""
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic not in (0xFEEDFACF, 0xCFFAEDFE):
        raise ValueError("not a 64-bit Mach-O")
    ncmds = struct.unpack_from("<I", data, 16)[0]
    pos = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, pos)
        yield cmd, pos
        pos += cmdsize


def macho_segments(data: bytes) -> list[tuple[int, int, int]]:
    """Return (vmaddr, fileoff, size) for each LC_SEGMENT_64."""
    segs = []
    for cmd, pos in _load_commands(data):
        if cmd == LC_SEGMENT_64:
            vmaddr, _vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, pos + 24)
            segs.append((vmaddr, fileoff, filesize))
    return segs


def macho_text_section(data: bytes) -> tuple[int, int, int] | None:
    """(addr, fileoff, size) of __TEXT,__text -- the code alone.

    The __TEXT segment also carries __cstring, __const and the unwind tables,
    and decoding those as instructions turns up adrp/add "pairs" that point
    nowhere useful. None when there is no such section (a shared-cache slice).
    """
    for cmd, pos in _load_commands(data):
        if cmd != LC_SEGMENT_64:
            continue
        nsects = struct.unpack_from("<I", data, pos + 64)[0]
        for k in range(nsects):
            sect = pos + 72 + k * 80
            sectname, segname = struct.unpack_from("<16s16s", data, sect)
            if segname.rstrip(b"\0") == b"__TEXT" and sectname.rstrip(b"\0") == b"__text":
                addr, size, offset = struct.unpack_from("<QQI", data, sect + 32)
                return addr, offset, size
    return None


def va_to_offset(segs: list[tuple[int, int, int]], va: int) -> int | None:
    for vmaddr, fileoff, size in segs:
        if vmaddr <= va < vmaddr + size:
            return fileoff + (va - vmaddr)
    return None


def strings_in_macho(path: str, limit: int = 400) -> list[tuple[int, str]]:
    """Best-effort: every string an adrp/add pair points at in the __text section."""
    with open(path, "rb") as fh:
        data = thin_macho(fh.read())
    segs = macho_segments(data)
    text = macho_text_section(data) or next((s for s in segs if s[0] and s[2]), None)
    if text is None:
        return []
    vmaddr, fileoff, size = text
    code = data[fileoff:fileoff + size]
    seen, out = set(), []
    for _site, _reg, target in follow_adrp_add(code, vmaddr):
        off = va_to_offset(segs, target)
        if off is None or off in seen:
            continue
        seen.add(off)
        s = read_cstr(data, off)
        if s.isprintable() and len(s) >= 3:
            out.append((target, s))
            if len(out) >= limit:
                break
    return out


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        raise SystemExit(1)
    for va, s in strings_in_macho(sys.argv[1]):
        print(f"0x{va:012x}  {s!r}")


if __name__ == "__main__":
    main()
