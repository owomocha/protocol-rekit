from rekit.findcrypt import SIGNATURES, scan, summary


def _crc32_table():
    table = []
    for n in range(256):
        c = n
        for _ in range(8):
            c = (0xEDB88320 ^ (c >> 1)) if c & 1 else c >> 1
        table.append(c)
    return table


def test_finds_aes_and_sha_constants():
    aes_sbox = bytes.fromhex("637c777bf26b6fc53001672bfed7ab76")
    sha256_be = bytes.fromhex("6a09e667bb67ae853c6ef372a54ff53a")
    te0_le = bytes.fromhex("a56363c6847c7cf8")
    blob = b"\x00" * 16 + aes_sbox + b"\xff" * 8 + sha256_be + b"\x11" * 4 + te0_le

    counts = summary(scan(blob))
    assert counts.get("AES", 0) >= 2      # S-box and the Te0 words
    assert counts.get("SHA-256", 0) == 1


def test_word_constants_hit_in_either_byte_order():
    words = (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A)
    le = b"".join(w.to_bytes(4, "little") for w in words)
    be = b"".join(w.to_bytes(4, "big") for w in words)
    notes = {h.note for h in scan(le + b"\x00" * 8 + be) if h.name == "SHA-256"}
    assert notes == {"initial hash words, little-endian words",
                     "initial hash words, big-endian words"}


def test_crc32_signature_matches_the_generated_table():
    # regenerate from the polynomial instead of trusting a typed-in constant;
    # the signature once had a wrong byte and could never match anything
    table = b"".join(w.to_bytes(4, "little") for w in _crc32_table())
    assert summary(scan(b"\x00" * 32 + table)).get("CRC-32") == 1


def test_chacha20_and_sha512():
    blob = (b"expand 32-byte k"
            + (0x6A09E667F3BCC908).to_bytes(8, "little")
            + (0xBB67AE8584CAA73B).to_bytes(8, "little"))
    counts = summary(scan(blob))
    assert counts.get("ChaCha20") == 1
    assert counts.get("SHA-512") == 1


def test_every_signature_is_at_least_eight_bytes():
    # four-byte patterns turn up by accident in any large binary
    assert all(len(s.pattern) >= 8 for s in SIGNATURES)


def test_clean_buffer_has_no_hits():
    assert scan(b"\x00" * 1024 + b"just some ascii text here") == []
