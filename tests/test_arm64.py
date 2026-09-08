import struct

from rekit.arm64 import (
    decode_add_imm,
    decode_adrp,
    decode_movz,
    follow_adrp_add,
    read_cstr,
)


def test_decode_movz():
    # MOVZ w0, #0x1234
    assert decode_movz(0x52800000 | (0x1234 << 5)) == (0, 0x1234, 0)
    # MOVZ x2, #0xABCD  (sf set) decodes the same fields
    assert decode_movz(0xD2800000 | (0xABCD << 5) | 2) == (2, 0xABCD, 0)
    assert decode_movz(0xD503201F) is None  # NOP


def test_decode_adrp_and_add():
    rd, page = decode_adrp(0x1000, 0x90000001)
    assert rd == 1 and page == 0x1000
    assert decode_add_imm(0x91000021 | (0x40 << 10)) == (1, 1, 0x40)
    # the LSL #12 form multiplies the immediate
    assert decode_add_imm(0x91400021 | (0x2 << 10)) == (1, 1, 0x2000)


def test_follow_pair_to_target():
    base = 0x100000000
    code = struct.pack("<II",
                       0x90000001,                  # adrp x1, <this page>
                       0x91000021 | (0x40 << 10))   # add  x1, x1, #0x40
    pairs = list(follow_adrp_add(code, base))
    assert pairs == [(base, 1, base + 0x40)]


def test_read_cstr():
    blob = b"..\x00HELLO\x00tail"
    assert read_cstr(blob, 3) == "HELLO"
    assert read_cstr(blob, 0) == ".."


def _tiny_macho(cstr: bytes, base: int = 0x100000000) -> bytes:
    """Header + one __TEXT segment with __text (an adrp/add pair) and __cstring."""
    seg_size = 72 + 2 * 80
    text_off = 32 + seg_size
    cstr_off = text_off + 8
    code = struct.pack("<II",
                       0x90000001,                       # adrp x1, <this page>
                       0x91000021 | (cstr_off << 10))    # add  x1, x1, #cstr_off
    size = cstr_off + len(cstr)
    header = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, seg_size, 0, 0)
    seg = struct.pack("<II16sQQQQIIII", 0x19, seg_size, b"__TEXT", base, size, 0, size, 5, 5, 2, 0)
    text = struct.pack("<16s16sQQIIIIIIII", b"__text", b"__TEXT",
                       base + text_off, len(code), text_off, 2, 0, 0, 0x80000400, 0, 0, 0)
    cstring = struct.pack("<16s16sQQIIIIIIII", b"__cstring", b"__TEXT",
                          base + cstr_off, len(cstr), cstr_off, 0, 0, 0, 2, 0, 0, 0)
    return header + seg + text + cstring + code + cstr


def test_text_section_is_found_and_followed(tmp_path):
    from rekit.arm64 import macho_text_section, strings_in_macho
    blob = _tiny_macho(b"hello from __cstring\x00")
    assert macho_text_section(blob) == (0x100000000 + 32 + 232, 32 + 232, 8)
    path = tmp_path / "tiny"
    path.write_bytes(blob)
    assert strings_in_macho(str(path)) == [(0x100000000 + 32 + 232 + 8, "hello from __cstring")]
