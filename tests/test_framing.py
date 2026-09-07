from rekit.framing import classify, frames_from_pcap, measure_latency


def test_frame_counts_and_tags(capture):
    send, recv = frames_from_pcap(capture["path"])
    kinds = classify(recv)
    assert kinds["TELE"]["count"] == capture["tele_frames"]
    assert "STAT" in kinds
    # the client made exactly one request
    assert classify(send)["REQ"]["count"] == 1


def test_latency_recovers_the_injected_feed_delay(capture):
    _send, recv = frames_from_pcap(capture["path"])
    lat = measure_latency(recv)
    tele = lat["TELE"]
    assert tele["precision"] == "second"
    # the demo injects a flat 130 ms delay; allow a hair of rounding
    assert abs(tele["median"] - capture["feed_delay_s"]) < 0.02
