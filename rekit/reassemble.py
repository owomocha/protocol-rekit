"""Reassemble a large reply that was split into chunks and compressed.

Servers that stream small updates in cleartext often switch strategy for a big
one-shot answer: compress it and cut it across several frames. If you don't put
the pieces back together first, the bytes look like garbage and it's easy to
conclude (wrongly) that "the big responses are encrypted". They usually aren't
-- they're just chunked zlib.

A chunk here looks like `C <marker> <total>|<compressed bytes>`, where the
marker's second letter is F/M/L for first/middle/last and the digits before it
group chunks that belong to the same reply. Strip the header off each chunk,
concatenate in order, inflate. That's the whole trick.

Real protocols vary the header, so the splitter takes either a separator byte
(default) or a fixed header length -- whichever the wire actually uses.
"""
from __future__ import annotations

import argparse
import re
import zlib
from collections import defaultdict

from .framing import Frame, frames_from_pcap

# C <two-letter marker><group id> <total length>
_HEADER = re.compile(rb"^C ([A-Z])([FML])(\d+) (\d+)")
_PART_ORDER = {"F": 0, "M": 1, "L": 2}


def _chunk_payload(body: bytes, sep: int | None, header_len: int | None) -> bytes | None:
    if header_len is not None:
        return body[header_len:] if len(body) > header_len else None
    i = body.find(sep)
    return body[i + 1:] if i >= 0 else None


def group_chunks(frames: list[Frame], sep: bytes = b"|",
                 header_len: int | None = None) -> dict[str, list[tuple]]:
    """Bucket compressed chunks by group id, ordered first->middle->last."""
    sep_byte = sep[0] if sep else None
    groups: dict[str, list[tuple]] = defaultdict(list)
    for f in frames:
        if not f.body.startswith(b"C "):
            continue
        m = _HEADER.match(f.body)
        if not m:
            continue
        _kind, part, gid, total = m.group(1), m.group(2).decode(), m.group(3).decode(), int(m.group(4))
        payload = _chunk_payload(f.body, sep_byte, header_len)
        if payload is None:
            continue
        groups[gid].append((_PART_ORDER.get(part, 1), f.ts, total, payload))
    for gid in groups:
        groups[gid].sort(key=lambda t: (t[0], t[1]))
    return groups


def reassemble(frames: list[Frame], sep: bytes = b"|",
               header_len: int | None = None) -> dict[str, dict]:
    """Return {group_id: {"data", "declared_total", "chunks", "ratio"}}."""
    out: dict[str, dict] = {}
    for gid, chunks in group_chunks(frames, sep, header_len).items():
        compressed = b"".join(c[3] for c in chunks)
        declared = chunks[0][2] if chunks else 0
        entry = {
            "chunks": len(chunks),
            "compressed_bytes": len(compressed),
            "declared_total": declared,
        }
        try:
            data = zlib.decompress(compressed)
            entry["data"] = data
            entry["ratio"] = len(compressed) / len(data) if data else 0.0
        except zlib.error as exc:
            entry["error"] = str(exc)
        out[gid] = entry
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="reassemble chunked+zlib replies")
    ap.add_argument("pcap")
    ap.add_argument("--server")
    ap.add_argument("--dump", type=int, default=0, help="print first N bytes of each reply")
    args = ap.parse_args()

    _, recv = frames_from_pcap(args.pcap, args.server)
    replies = reassemble(recv)
    print(f"reassembled {len(replies)} reply group(s)")
    for gid, r in sorted(replies.items()):
        if "data" in r:
            print(f"\ngroup {gid}: {r['chunks']} chunks, "
                  f"{r['compressed_bytes']}B compressed (declared {r['declared_total']}B) "
                  f"-> {len(r['data'])}B inflated, ratio {r['ratio']*100:.0f}%")
            if args.dump:
                print("  " + r["data"][:args.dump].decode("latin1").replace("\n", "\n  "))
        else:
            print(f"\ngroup {gid}: inflate failed: {r.get('error')}")


if __name__ == "__main__":
    main()
