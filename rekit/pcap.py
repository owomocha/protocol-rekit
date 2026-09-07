"""Read a pcap/pcapng file with nothing but the standard library.

No tshark, no scapy, no libpcap. It parses the capture file format itself,
strips the link/IP/TCP layers, and rebuilds each direction of a TCP
connection into one contiguous byte stream — which is what you actually want
when the app-layer protocol runs in cleartext and you need to look at it.

The one non-obvious feature: every reconstructed stream keeps an index of
*when each byte arrived*. That's what lets you line up an in-band timestamp
inside a message with the wall-clock time the packet landed, and measure how
stale a feed really is (see rekit.framing.measure_latency). Drop the arrival
times and you can't tell "real-time" from "cached and replayed".

CLI:
    python -m rekit.pcap capture.pcap                 # summary of flows
    python -m rekit.pcap capture.pcap 10.0.0.5:443    # pin one peer
"""
from __future__ import annotations

import socket
import struct
import sys

# pcap link-layer types we care about (see tcpdump's LINKTYPE_ list).
LINKTYPE_EN10MB = 1     # Ethernet
LINKTYPE_NULL = 0       # BSD loopback
LINKTYPE_LOOP = 108     # OpenBSD loopback
LINKTYPE_RAW = 101      # raw IP, no link header


class Stream:
    """One direction of a TCP conversation, plus an arrival-time index.

    `data` is the reassembled byte stream. `segments` is a sorted list of
    (offset_into_data, arrival_epoch) so `time_at()` can answer "when did the
    byte at offset N show up?" in log(n).
    """

    __slots__ = ("label", "data", "segments", "_seen")

    def __init__(self, label: str):
        self.label = label
        self.data = bytearray()
        self.segments: list[tuple[int, float]] = []
        self._seen: set[int] = set()

    def append(self, seq: int, payload: bytes, ts: float) -> None:
        if not payload:
            return
        # Retransmits repeat a sequence number; take the first copy and keep
        # tcpdump's arrival order. This is deliberately not a full TCP
        # reassembler — captures off a quiet client link almost never reorder,
        # and pretending otherwise hides real gaps.
        if seq in self._seen:
            return
        self._seen.add(seq)
        self.segments.append((len(self.data), ts))
        self.data += payload

    def time_at(self, offset: int) -> float:
        """Arrival time (epoch seconds) of the byte at `offset`."""
        segs = self.segments
        if not segs:
            return 0.0
        lo, hi, best = 0, len(segs) - 1, segs[0][1]
        while lo <= hi:
            mid = (lo + hi) // 2
            if segs[mid][0] <= offset:
                best = segs[mid][1]
                lo = mid + 1
            else:
                hi = mid - 1
        return best


def iter_packets(path: str):
    """Yield (epoch_ts, linktype, frame_bytes) for pcap or pcapng input."""
    with open(path, "rb") as fh:
        blob = fh.read()
    if len(blob) < 24:
        raise ValueError("file too short to be a capture")
    magic = blob[:4]
    if magic in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1",
                 b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1"):
        yield from _iter_classic(blob, magic)
    elif magic == b"\x0a\x0d\x0d\x0a":
        yield from _iter_pcapng(blob)
    else:
        raise ValueError(f"unknown capture magic: {magic.hex()}")


def _iter_classic(blob: bytes, magic: bytes):
    little = magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1")
    nano = magic in (b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1")
    end = "<" if little else ">"
    linktype = struct.unpack_from(end + "I", blob, 20)[0]
    pos, n = 24, len(blob)
    while pos + 16 <= n:
        ts_sec, ts_frac, incl, _orig = struct.unpack_from(end + "IIII", blob, pos)
        pos += 16
        if pos + incl > n:
            break
        ts = ts_sec + ts_frac / (1e9 if nano else 1e6)
        yield ts, linktype, blob[pos:pos + incl]
        pos += incl


def _iter_pcapng(blob: bytes):
    pos, n, end = 0, len(blob), "<"
    linktypes: list[int] = []
    tsresol: list[int] = []
    while pos + 12 <= n:
        btype, blen = struct.unpack_from(end + "II", blob, pos)
        if btype == 0x0A0D0D0A:  # Section Header Block sets byte order
            bom = struct.unpack_from("<I", blob, pos + 8)[0]
            end = "<" if bom == 0x1A2B3C4D else ">"
            btype, blen = struct.unpack_from(end + "II", blob, pos)
            linktypes, tsresol = [], []
        if blen < 12 or pos + blen > n:
            break
        body = blob[pos + 8:pos + blen - 4]
        if btype == 0x00000001:  # Interface Description Block
            linktypes.append(struct.unpack_from(end + "H", body, 0)[0])
            tsresol.append(_ng_tsresol(body[8:], end))
        elif btype == 0x00000006:  # Enhanced Packet Block
            iface, th, tl, incl, _orig = struct.unpack_from(end + "IIIII", body, 0)
            div = tsresol[iface] if iface < len(tsresol) else 1_000_000
            ts = ((th << 32) | tl) / div
            lt = linktypes[iface] if iface < len(linktypes) else LINKTYPE_EN10MB
            yield ts, lt, body[20:20 + incl]
        pos += blen


def _ng_tsresol(opts: bytes, end: str) -> int:
    """Read the if_tsresol(9) option from an IDB; default is microseconds."""
    pos = 0
    while pos + 4 <= len(opts):
        code, olen = struct.unpack_from(end + "HH", opts, pos)
        val = opts[pos + 4:pos + 4 + olen]
        pos += 4 + ((olen + 3) // 4) * 4
        if code == 0:
            break
        if code == 9 and val:
            r = val[0]
            return (1 << (r & 0x7F)) if (r & 0x80) else (10 ** r)
    return 1_000_000


def _l3_payload(linktype: int, frame: bytes) -> bytes | None:
    """Strip the link layer and return the IPv4 packet (or None)."""
    if linktype == LINKTYPE_EN10MB:
        if len(frame) < 14:
            return None
        etype = struct.unpack_from(">H", frame, 12)[0]
        off = 14
        while etype in (0x8100, 0x88A8):  # skip VLAN tags
            if len(frame) < off + 4:
                return None
            etype = struct.unpack_from(">H", frame, off + 2)[0]
            off += 4
        return frame[off:] if etype == 0x0800 else None
    if linktype in (LINKTYPE_NULL, LINKTYPE_LOOP):
        if len(frame) < 4:
            return None
        fam = struct.unpack_from("<I", frame, 0)[0]
        if fam not in (2, 0x02000000):
            fam = struct.unpack_from(">I", frame, 0)[0]
        return frame[4:] if fam == 2 else None
    if linktype == LINKTYPE_RAW:
        return frame
    return None


def _tcp_segments(path: str, since: float | None, until: float | None):
    """Yield (src_ep, dst_ep, seq, payload, ts) for every TCP segment.

    Endpoints are "ip:port" strings. Packets outside [since, until] are
    dropped early so a multi-hundred-MB capture never has to live in memory
    all at once.
    """
    for ts, linktype, frame in iter_packets(path):
        if (since is not None and ts < since) or (until is not None and ts > until):
            continue
        ip = _l3_payload(linktype, frame)
        if ip is None or len(ip) < 20 or (ip[0] >> 4) != 4:
            continue
        ihl = (ip[0] & 0x0F) * 4
        if ip[9] != 6 or len(ip) < ihl + 20:  # protocol 6 == TCP
            continue
        total_len = struct.unpack_from(">H", ip, 2)[0]
        tcp = ip[ihl:total_len] if 0 < total_len <= len(ip) else ip[ihl:]
        if len(tcp) < 20:
            continue
        sport, dport = struct.unpack_from(">HH", tcp, 0)
        seq = struct.unpack_from(">I", tcp, 4)[0]
        doff = (tcp[12] >> 4) * 4
        payload = tcp[doff:]
        if not payload:
            continue
        src = f"{socket.inet_ntoa(ip[12:16])}:{sport}"
        dst = f"{socket.inet_ntoa(ip[16:20])}:{dport}"
        yield src, dst, seq, payload, ts


def _pick_server(byte_counts: dict[tuple[str, str], int]) -> str | None:
    """Choose the busiest bidirectional flow and guess which end is the server.

    Heuristic: the endpoint with the lower port number is the listener. If the
    ports tie, the side that sent more bytes wins (a feed pushes far more than
    the client asks for).
    """
    pair_bytes: dict[frozenset, int] = {}
    for (src, dst), nbytes in byte_counts.items():
        pair_bytes[frozenset((src, dst))] = pair_bytes.get(frozenset((src, dst)), 0) + nbytes
    if not pair_bytes:
        return None
    a, b = sorted(max(pair_bytes, key=pair_bytes.get))
    pa = int(a.rsplit(":", 1)[1])
    pb = int(b.rsplit(":", 1)[1])
    if pa != pb:
        return a if pa < pb else b
    return a if byte_counts.get((a, b), 0) >= byte_counts.get((b, a), 0) else b


def load_streams(path: str, server: str | None = None,
                 since: float | None = None,
                 until: float | None = None):
    """Reassemble one TCP conversation into (client->server, server->client, stats).

    `server` pins the server endpoint as "ip" or "ip:port". If omitted, the
    busiest flow in the capture is used and the server side is guessed.
    """
    counts: dict[tuple[str, str], int] = {}
    segs = list(_tcp_segments(path, since, until))
    for src, dst, _seq, payload, _ts in segs:
        counts[(src, dst)] = counts.get((src, dst), 0) + len(payload)

    if server is None:
        server = _pick_server(counts)
    server_has_port = server is not None and ":" in server

    def is_server(ep: str) -> bool:
        return ep == server if server_has_port else ep.rsplit(":", 1)[0] == server

    c2s = Stream("client->server")
    s2c = Stream("server->client")
    for src, dst, seq, payload, ts in segs:
        if server is None:
            continue
        if is_server(src):
            s2c.append(seq, payload, ts)
        elif is_server(dst):
            c2s.append(seq, payload, ts)

    stats = {
        "server": server,
        "flows": counts,
        "c2s_bytes": len(c2s.data),
        "s2c_bytes": len(s2c.data),
        "span": (s2c.segments[-1][1] - s2c.segments[0][1]) if s2c.segments else 0.0,
    }
    return c2s, s2c, stats


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        raise SystemExit(1)
    path = sys.argv[1]
    server = sys.argv[2] if len(sys.argv) > 2 else None
    c2s, s2c, st = load_streams(path, server)
    print(f"=== {path} ===")
    print(f"server (picked): {st['server']}")
    print(f"client->server  {st['c2s_bytes']}B ({len(c2s.segments)} segments)")
    print(f"server->client  {st['s2c_bytes']}B ({len(s2c.segments)} segments)")
    print(f"span of received data: {st['span']:.1f}s")
    print("\ntop flows by payload bytes:")
    for (src, dst), nbytes in sorted(st["flows"].items(), key=lambda x: -x[1])[:10]:
        print(f"  {src:>22} -> {dst:<22} {nbytes:>10}B")


if __name__ == "__main__":
    main()
