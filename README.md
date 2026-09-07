# wire-re

[日本語](README.ja.md) · [![ci](https://github.com/owomocha/wire-re/actions/workflows/ci.yml/badge.svg)](https://github.com/owomocha/wire-re/actions)

Tools for reading how a closed-source desktop app talks to its server, when the traffic is cleartext. Standard library only.

They came out of reverse-engineering a commercial app I use. The app isn't here — no name, hosts, message list, or auth. Just the reusable parts, with a synthetic protocol to run them against, so every example below works on `/tmp/tlm.pcap` (`python -m rekit.demo` writes it).

## is the feed live, or replayed?

`rekit.pcap` records when each byte arrived, so a message carrying its own timestamp gives you the real lag:

```
$ python -m rekit.framing /tmp/tlm.pcap --latency
tag     prec         n     min   median     max
TELE    second     113   0.13s    0.13s   0.13s
```

The `prec` column matters: a minute-only clock produces fake latency — really just position within the minute — so those rows are flagged and never mixed with second-precision ones.

## fields with no separators

Fixed-width ASCII, space-padded, no delimiters — miscount one byte and everything below shifts. So don't count. Take a few hundred records and find the columns blank in all of them; those are the padding.

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

Field 6 is a flag flush against a clock, nothing blank between them, so the tool leaves that last split to you. It returns a hypothesis, not the answer.

## the binary side

Against the app's Mach-O — the strings a function references, from its `adrp`/`add` pair, without a disassembler:

```
$ python -m rekit.arm64 /bin/ls | head -4
0x0001000048ee  'bin/ls'
0x0001000048f5  'Unix2003'
0x0001000048fe  'COLUMNS'
0x000100004906  'LS_SAMESORT'
```

And the crypto linked in, from constants it can't omit — byte-oriented vs. table-driven AES included:

```
$ python -m rekit.findcrypt "$(brew --prefix openssl)/lib/libcrypto.dylib"
0x00239800  AES      Te0 table, little-endian (table-driven)
found: AES x1
```

## the rest

`rekit.reassemble` rebuilds chunked, zlib-compressed replies — the "encrypted" big response is usually just deflate. `rekit.pcap` alone summarises a capture and infers the server. Each module runs as `python -m rekit.<name>`; `examples/walkthrough.md` is the full run.

Capture with `tcpdump -i any -w app.pcap 'tcp and host <server>'` (pcap and pcapng both read). Cleartext only — for TLS, decrypt first. The binary side is Apple-silicon Mach-O, `adrp`/`add` only.

MIT.
