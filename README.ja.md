# wire-re

[English](README.md) · [![ci](https://github.com/owomocha/wire-re/actions/workflows/ci.yml/badge.svg)](https://github.com/owomocha/wire-re/actions)

クローズドソースのデスクトップアプリが平文でサーバと喋っているとき、その中身を読むための道具。標準ライブラリだけ。

元は自分が使っている商用アプリの解析から出たもので、アプリ自体は入れていない——名前もホストもメッセージ一覧も認証も無し。汎用の部分だけを抜き出し、試すための架空プロトコルを同梱した。下の例は全部 `/tmp/tlm.pcap`（`python -m rekit.demo` で生成）で動く。

## ライブか、再生か

`rekit.pcap` は各バイトの到着時刻を記録するので、メッセージが自分の時刻を持てば実際のラグが測れる:

```
$ python -m rekit.framing /tmp/tlm.pcap --latency
tag     prec         n     min   median     max
TELE    second     113   0.13s    0.13s   0.13s
```

`prec` の列が効く。分単位の時刻は偽の遅延——実際は分内の位置——を生むので、その行は印を付けて秒精度と混ぜない。

## 区切りのないフィールド

固定幅 ASCII・空白詰め・区切りなし。1バイト違えると以降が全部ずれる。だから数えない。レコードを数百件集め、全件で空白の列を探す。それが詰め物。

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

フィールド6はフラグと時刻が密着していて間に空白がない。そこだけ手法では割れないので、最後の一刀は自分で入れる。返るのは仮説であって答えではない。

## バイナリ側

アプリの Mach-O に対して。関数が参照する文字列を、`adrp`/`add` のペアから逆アセンブラなしで:

```
$ python -m rekit.arm64 /bin/ls | head -4
0x0001000048ee  'bin/ls'
0x0001000048f5  'Unix2003'
0x0001000048fe  'COLUMNS'
0x000100004906  'LS_SAMESORT'
```

リンクされた暗号を、省けない定数から——バイト指向と table 駆動の AES も見分ける:

```
$ python -m rekit.findcrypt "$(brew --prefix openssl)/lib/libcrypto.dylib"
0x00239800  AES      Te0 table, little-endian (table-driven)
found: AES x1
```

## 残り

`rekit.reassemble` はチャンク＋zlib の応答を組み直す——「暗号化」に見える大応答はたいてい deflate。`rekit.pcap` 単体でもキャプチャを要約しサーバを推定する。各モジュールは `python -m rekit.<名前>`。全体の流れは `examples/walkthrough.md`。

キャプチャは `tcpdump -i any -w app.pcap 'tcp and host <サーバ>'`（pcap も pcapng も読む）。平文専用、TLS は先に復号。バイナリ側は Apple シリコンの Mach-O・`adrp`/`add` のみ。

MIT.
