from rekit.findcrypt import scan, summary


def test_finds_aes_and_sha_constants():
    aes_sbox = bytes.fromhex("637c777bf26b6fc53001672bfed7ab76")
    sha256_h = bytes.fromhex("6a09e667bb67ae85")
    te0_le = bytes.fromhex("a56363c6")
    blob = b"\x00" * 16 + aes_sbox + b"\xff" * 8 + sha256_h + b"\x11" * 4 + te0_le

    counts = summary(scan(blob))
    assert counts.get("AES", 0) >= 2      # S-box and the Te0 word
    assert counts.get("SHA-256", 0) == 1


def test_clean_buffer_has_no_hits():
    assert scan(b"\x00" * 1024 + b"just some ascii text here") == []
