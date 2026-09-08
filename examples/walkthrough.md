# walkthrough

The tools in order, on the bundled synthetic capture. The fake protocol ("TLM")
is described at the top of `rekit/demo.py`.

```
$ python -m rekit.demo /tmp/tlm.pcap
wrote /tmp/tlm.pcap
  feed_delay_s: 0.13
  tele_frames: 120
  response_plain_bytes: 24400
```

Who's talking — a 460:1 imbalance says feed, not conversation:

```
$ python -m rekit.pcap /tmp/tlm.pcap
server (picked): 10.0.0.9:9443
client->server  24B (1 segments)
server->client  11191B (136 segments)
```

Message types — two streaming tags, plus four `C ` frames that are one
compressed reply split into chunks:

```
$ python -m rekit.framing /tmp/tlm.pcap
tag       count  avg_len  sample
TELE        120       58    TELE  A010    1000       100      2000 ...
STAT         12       29    STAT  NODE00   200   093000
?             4      630  C AF0001 00002451|x...
```

Is it live — second precision, 130 ms behind:

```
$ python -m rekit.framing /tmp/tlm.pcap --latency
tag     prec         n     min   median     max
TELE    second     113   0.13s    0.13s   0.13s
```

Field layout of TELE:

```
$ python -m rekit.columns /tmp/tlm.pcap --tag TELE
     # start width  examples
     0     2     4  ['TELE', 'TELE', 'TELE']
     1     8     4  ['A010', 'A014', 'A010']
     ...
     6    51     7  ['N093000', 'N093012', 'N093023']
```

The chunked reply — four chunks, inflated back to 24,400 bytes:

```
$ python -m rekit.reassemble /tmp/tlm.pcap --dump 60
group 0001: 4 chunks, 2451B compressed -> 24400B inflated, ratio 10%
  0000 param_00 value=0000 unit=ms scope=global note=synthetic
```

Binary side, on any Mach-O you have:

```
$ python -m rekit.arm64 /bin/ls | head -3
0x0001000048ee  'bin/ls'
0x0001000048f5  'Unix2003'
0x0001000048fe  'COLUMNS'

$ python -m rekit.findcrypt "$(brew --prefix openssl)/lib/libcrypto.dylib"
0x00004e10  SHA-256  initial hash words, little-endian words
0x00226800  AES      Te0 table (table-driven), little-endian words
0x002339a0  ChaCha20 sigma constant
0x002339c0  ChaCha20 sigma constant
0x002f9340  SHA-256  initial hash words, little-endian words
0x002f9720  SHA-512  initial hash words, little-endian words
0x002ff340  SHA-512  initial hash words, little-endian words
0x002ff388  SHA-256  initial hash words, little-endian words

found: AES x1, ChaCha20 x2, SHA-256 x3, SHA-512 x2
```
