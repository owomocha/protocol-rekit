# wire-re

[日本語](README.ja.md) · [![ci](https://github.com/owomocha/wire-re/actions/workflows/ci.yml/badge.svg)](https://github.com/owomocha/wire-re/actions)

Tools for reading how a closed-source desktop app talks to its server, when the traffic is cleartext. Standard library only — a pcap is a length-prefixed record stream once you've read the header, and I'd rather not put scapy or tshark on every machine I work from.

Where this came from, and what's deliberately missing: it's the reusable half of a project reverse-engineering a commercial app I use. The target isn't in the repo — no name, hosts, message catalogue, and nothing about its auth or key derivation. That last omission is a decision, not a gap; publishing a live third party's key schedule helps no one worth helping. Everything here runs on a synthetic protocol instead, so the examples reproduce on `/tmp/tlm.pcap` (`python -m rekit.demo`) and touch no one's server.

## is the feed live, or replayed?

Reassembling the stream and splitting frames is rote. The real question is whether a feed is live or a server replaying a snapshot, and only timing answers it. `rekit.pcap` keeps a `(stream_offset, arrival_time)` index per direction and binary-searches it, so for any byte in the reassembled stream you can recover when it actually arrived in O(log n). Set that against a timestamp carried inside the message and you get true lag:

```
$ python -m rekit.framing /tmp/tlm.pcap --latency
tag     prec         n     min   median     max
TELE    second     113   0.13s    0.13s   0.13s
```

Whether that number means anything comes down to two things. Precision: if a message stamps only HH:MM, the "delay" is just how far into the current minute you are — up to 59 s of quantization — so each tag is classified minute- or second-precision by the *ratio* of zero-second samples (a count would let one stray frame flip it), and the two are never pooled. And freshness vs. latency: a feed re-sends the last value between updates, so only frames whose clock advanced past the previous one for that key count as new events; the rest measure how stale the held value is, which is a different question with a different answer.

## fixed-width fields with no separators

Delimiter-free fixed-width ASCII is common here: space-padded numbers, nothing between them, and a one-byte miscount corrupts every field below it. So `rekit.columns` doesn't count — across a few hundred records of one type, any column blank in *all* of them is padding, and the runs between are fields. O(width × records), and it returns a hypothesis rather than truth (a column can be blank by luck), which is why it prints sample values to check against.

```
$ python -m rekit.columns /tmp/tlm.pcap --tag TELE
== TELE  120 records  lengths=[58] ==
   inferred 7 fields
     # start width  examples
     0     2     4  ['TELE', 'TELE', 'TELE']
     1     8     4  ['A010', 'A014', 'A010']
     ...
     6    51     7  ['N093000', 'N093012', 'N093023']
```

The ceiling is honest: field 6 is a status flag butted straight against a clock with no blank column between them, so voting can't split it — that last cut is done by eye. A structural method takes you to the edge of the ambiguity and stops there.

## the binary side, without a disassembler

I don't pull in capstone for two idioms that fit in a page of bit-twiddling.

Which strings a function references — on arm64 a literal is an `adrp`/`add` pair. `adrp` carries a 21-bit immediate split across two fields (`immlo` at bits 30:29, `immhi` at 23:5), sign-extended and shifted to a 4 KB page; `add` supplies the low 12 bits. Rebuild the address, map it through the Mach-O `LC_SEGMENT_64` table to a file offset, read the C string. It masks off the `sf` bit so the W- and X-register encodings decode as one, and it lifts the arm64 slice out of a fat binary first:

```
$ python -m rekit.arm64 /bin/ls | head -4
0x0001000048ee  'bin/ls'
0x0001000048f5  'Unix2003'
0x0001000048fe  'COLUMNS'
0x000100004906  'LS_SAMESORT'
```

Which crypto is linked in, before reading any of it — primitives can't omit their constants (AES's S-box and Rcon, SHA's IV words, the CRC-32 table), and those come through compilation verbatim. Matching them even tells a byte-oriented AES S-box from a T-table build; different implementations, different on-disk signatures:

```
$ python -m rekit.findcrypt "$(brew --prefix openssl)/lib/libcrypto.dylib"
0x00239800  AES      Te0 table, little-endian (table-driven)
found: AES x1
```

Same family as findcrypt/signsrch, cut to signatures I trust. It identifies primitives; it doesn't touch them. (Recent macOS keeps system crypto in the dyld shared cache, so scan something that statically embeds it — the Homebrew OpenSSL above does.)

## the rest

`rekit.reassemble` regroups chunked, zlib-compressed replies by sequence id and inflates — the big "encrypted" response is usually just deflate once the chunks are in order. And `rekit.pcap` bounds each TCP payload by the IP total-length field rather than the captured length, so Ethernet padding on short frames never leaks into the stream; it dedupes retransmits by sequence number and keeps arrival order instead of pretending to be a full reassembler, so a lossy midpoint capture shows gaps rather than silently wrong bytes.

Each module runs as `python -m rekit.<name>`; `examples/walkthrough.md` is the full run. Capture with `tcpdump -i any -w app.pcap 'tcp and host <server>'` (pcap and pcapng both read). Cleartext only; for TLS, decrypt first.

MIT.
