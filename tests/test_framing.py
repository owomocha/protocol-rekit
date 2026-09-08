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


def test_utc_offset_replaces_the_machine_zone(capture):
    import datetime
    _send, recv = frames_from_pcap(capture["path"])
    here = datetime.datetime.fromtimestamp(recv[0].ts).astimezone().utcoffset()
    hours = here.total_seconds() / 3600
    same = measure_latency(recv, utc_offset=hours)["TELE"]["median"]
    assert abs(same - measure_latency(recv)["TELE"]["median"]) < 1e-6
    # one hour off puts every frame outside the plausible window
    assert "TELE" not in measure_latency(recv, utc_offset=hours + 1)
