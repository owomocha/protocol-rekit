from rekit.framing import frames_from_pcap
from rekit.reassemble import reassemble


def test_chunked_reply_inflates_to_the_original(capture):
    _send, recv = frames_from_pcap(capture["path"])
    replies = reassemble(recv)
    gid = f"{capture['response_gid']:04d}"
    assert gid in replies
    r = replies[gid]
    assert "error" not in r
    assert r["chunks"] == 4
    assert r["compressed_bytes"] == r["declared_total"]
    assert len(r["data"]) == capture["response_plain_bytes"]
    assert r["data"].startswith(b"0000 param_00 value=0000")
    assert r["data"].endswith(b"note=synthetic\n")
