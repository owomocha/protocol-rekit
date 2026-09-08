# Changelog

## 0.1.0 — 2026-09-09

First tagged release. Compared with the untagged initial push:

- `pcap`: the capture is mmapped and walked packet by packet. Picking the server costs a counting pass over the file instead of a copy of every segment, so a multi-hundred-MB capture no longer has to fit in memory.
- `arm64`: string recovery decodes `__TEXT,__text` only. The rest of the segment (`__cstring`, `__const`, unwind tables) used to go through the decoder too and produced adrp/add "pairs" that pointed nowhere.
- `findcrypt`: word constants are matched in both byte orders and the note says which hit. The CRC-32 table signature had one wrong byte and could never match; it is now checked in the tests against a table regenerated from the polynomial. Added the ChaCha20 sigma constant and the SHA-512 IV.
- `framing`: `--utc-offset` for a feed whose in-band clock is written in a zone the capture machine wasn't in.
