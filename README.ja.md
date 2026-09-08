# wire-re

[English](README.md) · [![ci](https://github.com/owomocha/wire-re/actions/workflows/ci.yml/badge.svg)](https://github.com/owomocha/wire-re/actions)

クローズドソースのデスクトップアプリが平文でサーバと喋っているとき、その中身を読むための道具。標準ライブラリだけ——pcap はヘッダさえ読めば長さ前置きのレコード列でしかないし、作業マシンごとに scapy や tshark を入れたくない。

出所と、意図的に欠けているもの: これは自分が使う商用アプリを解析したプロジェクトの、再利用できる半分。対象はリポジトリに無い——名前もホストもメッセージ一覧も、認証も鍵導出も。最後のは欠落ではなく判断で、稼働中の第三者の鍵スケジュールを公開して得をする相手はいない。ここにあるものは合成プロトコルで動くので、例は `/tmp/tlm.pcap`（`python -m rekit.demo`）で再現でき、誰のサーバにも触らない。

## ライブか、再生か

ストリームの再構成もフレーム分割も定型作業。本題はフィードがライブか、サーバがスナップショットを再生しているかで、答えるのは時刻だけ。`rekit.pcap` は方向ごとに `(ストリーム内オフセット, 到着時刻)` の索引を持ち二分探索するので、再構成後の任意のバイトが実際に届いた時刻を O(log n) で引ける。メッセージ内の時刻と突き合わせれば真のラグが出る:

```
$ python -m rekit.framing /tmp/tlm.pcap --latency
tag     prec         n     min   median     max
TELE    second     113   0.13s    0.13s   0.13s
```

この数字が意味を持つかは二点で決まる。精度: メッセージが HH:MM しか刻まないなら「遅延」は分内の位置（最大59秒の量子化）でしかないので、秒桁が0の標本の*比率*で分/秒精度を判定し（件数だと外れ1件で反転する）、両者は決して混ぜない。鮮度と遅延: フィードは更新の合間に前値を再送するので、同一キーで時刻が前進したフレームだけを新イベントとして数える。残りが測るのは保持値の古さで、別の問い・別の答え。

## 区切りのない固定幅フィールド

区切りなしの固定幅 ASCII はここでは定番——空白詰めの数値・間に区切り無し・1バイトの数え違いが以降のフィールドを全部壊す。だから `rekit.columns` は数えない。ある種類のレコード数百件で、全件空白の列が詰め物、その間がフィールド。O(幅 × 件数) で、返すのは真実でなく仮説（偶然の空白もある）だから、確認用に実値を並べる。

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

天井は正直だ: フィールド6はステータスフラグが時刻に密着して間に空白列が無く、多数決では割れない——最後の一刀は目で入れる。構造的手法は曖昧さの縁までで止まる。

## 逆アセンブラなしのバイナリ側

1ページのビット演算で済む二つのイディオムに capstone は持ち込まない。

関数が参照する文字列——arm64 のリテラルは `adrp`/`add` のペア。`adrp` は21ビット即値を二フィールド（`immlo` が bit30:29・`immhi` が bit23:5）に分割して持ち、符号拡張して 4KB ページへシフト、`add` が下位12ビットを足す。アドレスを復元し、Mach-O の `LC_SEGMENT_64` 表でファイルオフセットに写して C 文字列を読む。`sf` ビットを落として W/X レジスタ形を同一に扱い、fat バイナリからは先に arm64 スライスを抜く:

```
$ python -m rekit.arm64 /bin/ls | head -4
0x0001000048ee  'bin/ls'
0x0001000048f5  'Unix2003'
0x0001000048fe  'COLUMNS'
0x000100004906  'LS_SAMESORT'
```

リンクされた暗号を、読む前に——プリミティブは定数を省けない（AES の S-box と Rcon・SHA の IV・CRC-32 表）し、それらはコンパイルを素通りで残る。照合はバイト指向の AES S-box と T-table 版まで見分ける。実装が違えばディスク上の署名も違う:

```
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

ワード表は両方のバイト順で照合し、どちらで当たったかを注記に出す。findcrypt/signsrch と同系統を、信頼できる署名に絞ったもの。同定するだけで触らない。（最近の macOS はシステム暗号を dyld 共有キャッシュに置くので、静的に埋め込んだもの——上の Homebrew OpenSSL——を走査する。）

## 残り

`rekit.reassemble` はチャンク＋zlib 応答を連番でまとめて展開する——大きい「暗号化」応答は順に繋いだ瞬間たいてい deflate。`rekit.pcap` は各 TCP ペイロードをキャプチャ長でなく IP total-length で切るので、短いフレームの Ethernet パディングがストリームに漏れない。再送はシーケンス番号で重複排除し到着順を保つ——完全な再構成器を装わないので、取りこぼしのある中継点では黙って壊れず素直に隙間を見せる。

各モジュールは `python -m rekit.<名前>`。全体は `examples/walkthrough.md`。キャプチャは `tcpdump -i any -w app.pcap 'tcp and host <サーバ>'`（pcap も pcapng も読む）。平文専用、TLS は先に復号。

MIT.
