"""Generate a synthetic capture so the tools have something real to chew on.

There is no real-world data anywhere in this repo. Instead this module makes
up a small, deliberately awkward binary protocol -- fixed-width ASCII fields
with no delimiters, a streaming path and a request/response path, a chunked
zlib reply -- and writes it out as an honest .pcap (Ethernet/IPv4/TCP, real
checksums). Every tool in the kit is exercised against this file in the tests
and in examples/walkthrough.md.

The made-up protocol ("TLM"):

  server -> client, streaming (pushed continuously):
      STX + <8-digit ASCII body length> + body + ETX
      body = "  " + TAG(4) + fixed-width columns, no separators
        TAG "TELE": sensor telemetry, ends in an HHMMSS event clock
        TAG "STAT": a status line with a different column layout

  client -> server, request:
      <8-digit ASCII body length> + "REQ " + name

  server -> client, response to a request (large -> chunked + compressed):
      each chunk is a normal frame whose body is
      "C " + PART + GID(4) + " " + <8-digit total> + "|" + <zlib chunk>
      PART in {AF, AM, AL} = first / middle / last

Run it directly to drop a capture on disk:
    python -m rekit.demo /tmp/tlm.pcap
"""
from __future__ import annotations

import struct
import sys
import zlib

STX, ETX = 0x02, 0x03
CLIENT_IP, SERVER_IP = "10.0.0.20", "10.0.0.9"
CLIENT_PORT, SERVER_PORT = 51000, 9443


# --- the made-up wire format -------------------------------------------------

def _col(value, width: int) -> str:
    """Right-justify into a fixed field so the leading columns stay blank.

    That blank margin is exactly what makes the fields *look* delimited to a
    column detector even though the wire has no separators at all.
    """
    s = str(value)
    return s.rjust(width)[:width]


def tele_body(sensor: str, seq: int, r1: int, r2: int, r3: int,
              flag: str, hhmmss: str) -> bytes:
    # Note the flag sits flush against the clock with no gap -- a realistic bit
    # of nastiness that the column detector can't split on its own, so it makes
    # a nice example of "the tool gives you a hypothesis, you confirm it".
    body = ("  TELE" + _col(sensor, 6) + _col(seq, 8) + _col(r1, 10)
            + _col(r2, 10) + _col(r3, 10) + " " + flag + hhmmss)
    return body.encode("ascii")


def stat_body(node: str, code: int, hhmmss: str) -> bytes:
    body = "  STAT" + _col(node, 8) + _col(code, 6) + "   " + hhmmss
    return body.encode("ascii")


def framed(body: bytes) -> bytes:
    """server->client framing: STX + 8-digit length + body + ETX."""
    return bytes([STX]) + f"{len(body):08d}".encode() + body + bytes([ETX])


def unframed(body: bytes) -> bytes:
    """client->server framing: 8-digit length + body (no STX/ETX)."""
    return f"{len(body):08d}".encode() + body


def chunked_response(gid: int, payload: bytes, parts: int = 3) -> list[bytes]:
    """Compress `payload` and cut it into `parts` framed chunks."""
    comp = zlib.compress(payload, 9)
    total = len(comp)
    step = (total + parts - 1) // parts
    frames = []
    for k in range(parts):
        piece = comp[k * step:(k + 1) * step]
        if not piece:
            continue
        tag = "AF" if k == 0 else ("AL" if (k + 1) * step >= total else "AM")
        hdr = f"C {tag}{gid:04d} {total:08d}|".encode()
        frames.append(framed(hdr + piece))
    return frames


# --- a minimal, correct pcap writer -----------------------------------------

def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f">{len(data)//2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def _tcp_ip_frame(src_ip, sport, dst_ip, dport, seq, ack, payload) -> bytes:
    src = bytes(int(x) for x in src_ip.split("."))
    dst = bytes(int(x) for x in dst_ip.split("."))
    tcp = struct.pack(">HHIIBBHHH", sport, dport, seq, ack,
                      (5 << 4), 0x18, 65535, 0, 0)  # data-offset 5, PSH|ACK
    pseudo = src + dst + struct.pack(">BBH", 0, 6, len(tcp) + len(payload))
    csum = _checksum(pseudo + tcp + payload)
    tcp = tcp[:16] + struct.pack(">H", csum) + tcp[18:]
    total = 20 + len(tcp) + len(payload)
    ip = struct.pack(">BBHHHBBH", 0x45, 0, total, 0, 0x4000, 64, 6, 0) + src + dst
    ip = ip[:10] + struct.pack(">H", _checksum(ip)) + ip[12:]
    eth = b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02\x08\x00"
    return eth + ip + tcp + payload


def write_pcap(path: str, packets: list) -> None:
    """packets: list of (ts, direction, payload) with direction in {"c2s","s2c"}."""
    seqs = {"c2s": 1, "s2c": 1}
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, direction, payload in packets:
            if direction == "c2s":
                frame = _tcp_ip_frame(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT,
                                      seqs["c2s"], seqs["s2c"], payload)
            else:
                frame = _tcp_ip_frame(SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT,
                                      seqs["s2c"], seqs["c2s"], payload)
            seqs[direction] += len(payload)
            sec = int(ts)
            usec = int(round((ts - sec) * 1_000_000))
            fh.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            fh.write(frame)


# --- put it all together -----------------------------------------------------

def generate(path: str, base_epoch: float | None = None) -> dict:
    """Write a capture that exercises every tool. Returns some ground truth.

    Arrival times are pinned to 09:30 local so the packets' wall clock lines up
    with the in-band HHMMSS field -- that alignment is what makes the latency
    measurement meaningful (a live feed is captured while the market clock and
    your clock agree).
    """
    import datetime
    if base_epoch is None:
        day = datetime.date(2024, 6, 3)  # an arbitrary weekday
        base_epoch = datetime.datetime.combine(day, datetime.time(9, 30, 0)).timestamp()
    packets: list = []
    base_secs = 9 * 3600 + 30 * 60  # 09:30:00 as second-of-day

    # 1) a burst of streaming telemetry, one event per ~0.2s, with a small,
    #    fixed feed delay of 0.13s between the event clock and the packet.
    for i in range(120):
        ev = base_secs + i // 5            # event clock advances every 5 frames
        hhmmss = f"{ev // 3600:02d}{(ev % 3600) // 60:02d}{ev % 60:02d}"
        sensor = f"A{(i % 7) + 10:03d}"
        body = tele_body(sensor, 1000 + i, 100 + i * 3, 2000 - i, i * i % 997,
                         "N", hhmmss)
        arrival = base_epoch + (ev - base_secs) + 0.13   # 130 ms feed delay
        packets.append((arrival, "s2c", framed(body)))
        if i % 10 == 0:
            packets.append((arrival + 0.01, "s2c", framed(
                stat_body(f"NODE{i:02d}", 200 + i, hhmmss))))

    # 2) a client request, then a chunked+compressed reply.
    req_t = base_epoch + 30.0
    packets.append((req_t, "c2s", unframed(b"REQ CONFIG.TABLE")))
    payload = ("".join(f"{k:04d} param_{k % 13:02d} value={k*7 % 1000:04d} "
                       f"unit=ms scope=global note=synthetic\n" for k in range(400))
               ).encode("ascii")
    for j, chunk in enumerate(chunked_response(1, payload, parts=4)):
        packets.append((req_t + 0.05 + j * 0.01, "s2c", chunk))

    packets.sort(key=lambda p: p[0])
    write_pcap(path, packets)
    return {
        "path": path,
        "feed_delay_s": 0.13,
        "tele_frames": 120,
        "response_gid": 1,
        "response_plain_bytes": len(payload),
    }


def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else "tlm.pcap"
    truth = generate(path)
    print(f"wrote {path}")
    for k, v in truth.items():
        print(f"  {k}: {v}")


if __name__ == "__main__":
    main()
