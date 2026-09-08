"""Guess which crypto a binary uses by looking for its telltale constants.

Cryptographic primitives are full of magic numbers that have to be there: AES
has its S-box and round constants, SHA has its initial hash words, CRC32 has
its lookup table. Those byte patterns are public knowledge and they survive
compilation unchanged, so scanning for them tells you what a binary rolled in
long before you disassemble a single function -- and, handily, *which* flavour
(a byte-oriented S-box implementation reads differently from a T-table one).

This is the well-trodden findcrypt/signsrch idea, kept to a tight, honest set
of signatures. It identifies primitives; it does not break anything.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class Signature:
    name: str
    note: str
    pattern: bytes


def _words(name: str, note: str, words: tuple[int, ...], width: int = 4) -> list[Signature]:
    """A constant that lives in a word array, in both byte orders.

    The same table compiles to different bytes on little- and big-endian
    targets, and some code stores it big-endian on purpose, so match both and
    say which one hit -- that alone hints at how the code was built.
    """
    le = b"".join(w.to_bytes(width, "little") for w in words)
    be = b"".join(w.to_bytes(width, "big") for w in words)
    return [Signature(name, f"{note}, little-endian words", le),
            Signature(name, f"{note}, big-endian words", be)]


# Every pattern below is a published constant, verifiable in the relevant spec
# or reference implementation. The CRC-32 one is also checked in the tests
# against a table regenerated from the polynomial: an earlier version had one
# wrong byte in it and, of course, never matched anything.
SIGNATURES: list[Signature] = [
    Signature("AES", "S-box (byte-oriented)",
              bytes.fromhex("637c777bf26b6fc53001672bfed7ab76")),
    Signature("AES", "round constants (Rcon)",
              bytes.fromhex("01020408102040801b36")),
    *_words("AES", "Te0 table (table-driven)", (0xC66363A5, 0xF87C7C84)),
    *_words("SHA-256", "initial hash words", (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A)),
    *_words("SHA-512", "initial hash words", (0x6A09E667F3BCC908, 0xBB67AE8584CAA73B), width=8),
    *_words("SHA-1", "initial hash words", (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)),
    *_words("MD5", "K[0..1] sine constants", (0xD76AA478, 0xE8C7B756)),
    *_words("CRC-32", "IEEE table, first entries", (0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA)),
    Signature("ChaCha20", "sigma constant", b"expand 32-byte k"),
]


@dataclass(frozen=True)
class Hit:
    name: str
    note: str
    offset: int


def scan(data: bytes, signatures: list[Signature] = SIGNATURES,
         max_per_sig: int = 4) -> list[Hit]:
    """Find known crypto constants in `data`, sorted by file offset."""
    hits: list[Hit] = []
    for sig in signatures:
        start, found = 0, 0
        while found < max_per_sig:
            idx = data.find(sig.pattern, start)
            if idx < 0:
                break
            hits.append(Hit(sig.name, sig.note, idx))
            start = idx + 1
            found += 1
    hits.sort(key=lambda h: h.offset)
    return hits


def summary(hits: list[Hit]) -> dict[str, int]:
    """Which primitives were seen, and how many times each."""
    counts: dict[str, int] = {}
    for h in hits:
        counts[h.name] = counts.get(h.name, 0) + 1
    return counts


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        raise SystemExit(1)
    with open(sys.argv[1], "rb") as fh:
        data = fh.read()
    hits = scan(data)
    if not hits:
        print("no known crypto constants found")
        return
    for h in hits:
        print(f"0x{h.offset:08x}  {h.name:<8} {h.note}")
    print("\nfound: " + ", ".join(f"{k} x{v}" for k, v in sorted(summary(hits).items())))


if __name__ == "__main__":
    main()
