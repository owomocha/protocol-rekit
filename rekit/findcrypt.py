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


# Every pattern below is a published constant, verifiable in the relevant spec
# or reference implementation.
SIGNATURES: list[Signature] = [
    Signature("AES", "S-box (byte-oriented)",
              bytes.fromhex("637c777bf26b6fc53001672bfed7ab76")),
    Signature("AES", "Te0 table, little-endian (table-driven)",
              bytes.fromhex("a56363c6")),
    Signature("AES", "Te0 table, big-endian",
              bytes.fromhex("c66363a5")),
    Signature("AES", "round constants (Rcon)",
              bytes.fromhex("01020408102040801b36")),
    Signature("SHA-256", "initial hash words",
              bytes.fromhex("6a09e667bb67ae85")),
    Signature("SHA-1", "initial hash words",
              bytes.fromhex("67452301efcdab8998badcfe")),
    Signature("MD5", "K[0] sine constant",
              bytes.fromhex("78a46ad7")),
    Signature("CRC-32", "IEEE polynomial table",
              bytes.fromhex("000000009630077728610eee")),
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
