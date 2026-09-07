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
