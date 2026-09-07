"""Recover fixed-width field boundaries from delimiter-less ASCII records.

The nastiest kind of text protocol has no separators at all: every field is a
fixed number of columns, numbers are space-padded, and if you miscount by one
byte every value downstream is quietly wrong. Counting by hand does not scale
and it does not survive a layout you guessed wrong.

The trick that does scale: collect many records of the same kind and look for
columns that are blank in *every* one of them. Those are almost certainly the
padding between fields, and the runs in between are the fields. It's only a
hypothesis -- a column can be blank across your sample by luck -- so the output
is a starting point you confirm by eyeballing the values (does this run parse
as a date? does that one add up?), never the final word.
"""
from __future__ import annotations

import argparse

from .framing import Frame, frames_from_pcap


def boundaries(records: list[str]) -> list[tuple[int, int]]:
    """Return (start, width) for each run of columns that isn't always blank."""
    if not records:
        return []
    width = min(len(r) for r in records)
    always_blank = [all(r[i] == " " for r in records) for i in range(width)]
    fields: list[tuple[int, int]] = []
    start = None
    for i, blank in enumerate(always_blank):
        if not blank and start is None:
            start = i
        elif blank and start is not None:
            fields.append((start, i - start))
            start = None
    if start is not None:
        fields.append((start, width - start))
    return fields


def infer(records: list[str], samples: int = 3) -> dict:
    """Boundaries plus a few example values per field, for a human to sanity check."""
    fields = boundaries(records)
    lengths = sorted({len(r) for r in records})
    idx = (0, len(records) // 2, -1)[:samples]
    rows = [
        {
            "start": o,
            "width": w,
            "samples": [records[k][o:o + w].strip() for k in idx],
        }
        for o, w in fields
    ]
    return {
        "count": len(records),
        "lengths": lengths,
        "variable": len(lengths) > 1,
        "fields": rows,
    }


def _records_by_tag(frames: list[Frame]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for f in frames:
        out.setdefault(f.tag(), []).append(f.text)
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="infer fixed-width field layout")
    ap.add_argument("pcap")
    ap.add_argument("--server")
    ap.add_argument("--tag", help="only this message tag")
    ap.add_argument("--min", type=int, default=3, help="skip tags with fewer records")
    args = ap.parse_args()

    _, recv = frames_from_pcap(args.pcap, args.server)
    groups = _records_by_tag(recv)
    for tag, records in sorted(groups.items(), key=lambda x: -len(x[1])):
        if args.tag and tag != args.tag:
            continue
        if len(records) < args.min:
            continue
        info = infer(records)
        note = "  (variable length; only the common prefix is meaningful)" if info["variable"] else ""
        print(f"\n== {tag}  {info['count']} records  lengths={info['lengths']}{note} ==")
        print(f"   inferred {len(info['fields'])} fields")
        print(f"   {'#':>3} {'start':>5} {'width':>5}  examples")
        for i, fld in enumerate(info["fields"]):
            print(f"   {i:>3} {fld['start']:>5} {fld['width']:>5}  {fld['samples']}")


if __name__ == "__main__":
    main()
