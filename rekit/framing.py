"""Cut a reassembled TCP stream into application frames, then make sense of them.

Two framing styles cover a surprising number of in-house protocols:

    framed   : STX + <ASCII length> + body + ETX      (what a server pushes)
    unframed : <ASCII length> + body                  (what a client sends)

Once you have frames, three questions usually matter:

  - what *kinds* of message are there?  -> classify() groups by a leading tag
  - which are pushed vs pulled?         -> streaming shows up as many small
                                          frames of one tag; a request/response
                                          reply as a few large ones
  - is the feed actually real-time?     -> measure_latency() compares an in-band
                                          HHMMSS clock against the time the
                                          bytes arrived. This is the only honest
                                          way to tell a live feed from a cached
                                          one, and it's why rekit.pcap bothers
                                          to remember arrival times.
"""
from __future__ import annotations

import argparse
import datetime
import re
from collections import Counter, defaultdict

from .pcap import Stream, load_streams

STX, ETX = 0x02, 0x03


class Frame:
    __slots__ = ("offset", "ts", "body")

    def __init__(self, offset: int, ts: float, body: bytes):
        self.offset = offset
        self.ts = ts
        self.body = body

    @property
    def text(self) -> str:
        return "".join(chr(b) if 32 <= b < 127 else "." for b in self.body)

    def tag(self, pattern: re.Pattern = re.compile(rb"[A-Z][A-Z0-9]{1,7}")) -> str:
        """A short leading identifier for the message kind.

        Bodies often start with a few pad bytes, so strip whitespace first and
        match the first uppercase-ish token. What counts as a tag is protocol
        specific -- pass your own compiled pattern when the default is wrong.
        """
        m = pattern.match(self.body.lstrip())
        return m.group(0).decode("latin1") if m else "?"


def split_frames(stream: Stream, framed: bool = True, len_width: int = 8,
                 stx: int = STX, etx: int = ETX) -> list[Frame]:
    """Split a stream into frames, keeping each frame's arrival time.

    `framed=True`  -> stx + <len_width ASCII digits> + body + etx
    `framed=False` -> <len_width ASCII digits> + body
    """
    b = stream.data
    n = len(b)
    out: list[Frame] = []
    i = 0
    while i < n:
        if framed:
            j = b.find(stx, i)
            if j < 0 or j + 1 + len_width > n:
                break
            lenf = b[j + 1:j + 1 + len_width]
            if not lenf.isdigit():
                i = j + 1
                continue
            length = int(lenf)
            start = j + 1 + len_width
            end = start + length
            if end < n and b[end] == etx:
                out.append(Frame(j, stream.time_at(j), bytes(b[start:end])))
                i = end + 1
            else:  # truncated or misframed: fall back to the next ETX
                k = b.find(etx, start)
                if k < 0:
                    break
                out.append(Frame(j, stream.time_at(j), bytes(b[start:k])))
                i = k + 1
        else:
            if i + len_width > n:
                break
            lenf = b[i:i + len_width]
            if not lenf.isdigit():
                i += 1
                continue
            length = int(lenf)
            if length <= 0 or i + len_width + length > n:
                break
            start = i + len_width
            out.append(Frame(i, stream.time_at(i), bytes(b[start:start + length])))
            i = start + length
    return out


def classify(frames: list[Frame]) -> dict[str, dict]:
    """Group frames by tag with count / average length / a sample."""
    by_tag: dict[str, list[Frame]] = defaultdict(list)
    for f in frames:
        by_tag[f.tag()].append(f)
    out = {}
    for tag, fs in by_tag.items():
        out[tag] = {
            "count": len(fs),
            "avg_len": sum(len(f.body) for f in fs) // len(fs),
            "sample": fs[0].text[:96],
        }
    return out


def _clock_in_tail(text: str, tail: int, upper: float | None) -> int | None:
    """Find an HHMMSS somewhere in the last `tail` chars; return seconds.

    Fixed-width tails jam several 6-digit numbers together with no separator,
    so slide a 6-digit window and keep the largest plausible time (the newest
    event). `upper` (arrival second-of-day) rejects a price/id that merely
    looks like a future time.
    """
    s = text[-tail:]
    best = None
    for i in range(len(s) - 5):
        w = s[i:i + 6]
        if not w.isdigit():
            continue
        h, mi, sec = int(w[:2]), int(w[2:4]), int(w[4:6])
        if mi > 59 or sec > 59 or not (0 <= h <= 23):
            continue
        secs = h * 3600 + mi * 60 + sec
        if upper is not None and secs > upper + 5:
            continue
        if best is None or secs > best:
            best = secs
    return best


def measure_latency(frames: list[Frame], tail: int = 48) -> dict[str, dict]:
    """Delay between an in-band HHMMSS clock and the packet's arrival time.

    Returns per-tag stats plus a granularity flag: if the seconds digit is
    almost always 00 the clock is minute-precision, and the "delay" you'd
    compute from it is just up to 59s of quantization -- not a real delay.
    Reporting that distinction is the whole point; without it you'd claim a
    minute-stamped feed is seconds slow when it isn't.
    """
    per_tag: dict[str, list[float]] = defaultdict(list)
    sec_digit: dict[str, Counter] = defaultdict(Counter)
    last_seen: dict[tuple[str, str], int] = {}
    for f in frames:
        dt = datetime.datetime.fromtimestamp(f.ts)
        wall = dt.hour * 3600 + dt.minute * 60 + dt.second + dt.microsecond / 1e6
        secs = _clock_in_tail(f.text, tail, wall)
        if secs is None:
            continue
        delay = wall - secs
        if not (-5 <= delay <= 600):
            continue
        tag = f.tag()
        sec_digit[tag][secs % 60] += 1
        # only count a frame whose clock advanced past the last one we saw for
        # this tag -- otherwise repeated snapshots of the same event inflate n
        key = (tag, f.text[:16])
        if last_seen.get(key, -1) < secs:
            if key in last_seen:
                per_tag[tag].append(delay)
            last_seen[key] = secs

    out = {}
    for tag, ds in per_tag.items():
        if not ds:
            continue
        s = sorted(ds)
        hist = sec_digit[tag]
        n = sum(hist.values()) or 1
        out[tag] = {
            "n": len(s),
            "min": s[0],
            "median": s[len(s) // 2],
            "max": s[-1],
            "precision": "minute" if hist[0] / n >= 0.9 else "second",
        }
    return out


def frames_from_pcap(path: str, server: str | None = None):
    """Convenience: (client->server frames, server->client frames)."""
    c2s, s2c, _ = load_streams(path, server)
    return split_frames(c2s, framed=False), split_frames(s2c, framed=True)


def main() -> None:
    ap = argparse.ArgumentParser(description="frame + classify a captured stream")
    ap.add_argument("pcap")
    ap.add_argument("--server")
    ap.add_argument("--latency", action="store_true")
    args = ap.parse_args()

    send, recv = frames_from_pcap(args.pcap, args.server)
    print(f"frames: sent {len(send)}  received {len(recv)}")

    if args.latency:
        print("\n=== feed latency (in-band clock vs arrival) ===")
        print(f"{'tag':<8}{'prec':<8}{'n':>6}{'min':>8}{'median':>9}{'max':>8}")
        for tag, st in sorted(measure_latency(recv).items()):
            print(f"{tag:<8}{st['precision']:<8}{st['n']:>6}"
                  f"{st['min']:>7.2f}s{st['median']:>8.2f}s{st['max']:>7.2f}s")
        print("note: 'minute' precision rows are quantization, not real delay")
        return

    print("\n=== received (server -> client) by tag ===")
    print(f"{'tag':<8}{'count':>7}{'avg_len':>9}  sample")
    for tag, st in sorted(classify(recv).items(), key=lambda x: -x[1]["count"]):
        print(f"{tag:<8}{st['count']:>7}{st['avg_len']:>9}  {st['sample'][:60]}")
    print("\n=== sent (client -> server) by tag ===")
    for tag, st in sorted(classify(send).items(), key=lambda x: -x[1]["count"]):
        print(f"{tag:<8}{st['count']:>7}{st['avg_len']:>9}  {st['sample'][:60]}")


if __name__ == "__main__":
    main()
