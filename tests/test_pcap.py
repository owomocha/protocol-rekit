from rekit.pcap import iter_packets, load_streams


def test_picks_server_and_splits_directions(capture):
    c2s, s2c, stats = load_streams(capture["path"])
    # the feed pushes far more than the client asks for
    assert stats["s2c_bytes"] > stats["c2s_bytes"] * 10
    # server was auto-detected as the low port (9443 < 51000)
    assert stats["server"].endswith(":9443")
    assert len(c2s.data) > 0 and len(s2c.data) > 0


def test_arrival_times_are_monotonic_and_indexed(capture):
    _c2s, s2c, _ = load_streams(capture["path"])
    ts = [t for _off, t in s2c.segments]
    assert ts == sorted(ts)
    # time_at at the start and end brackets the whole capture span
    assert s2c.time_at(0) <= s2c.time_at(len(s2c.data) - 1)


def test_explicit_server_matches_autopick(capture):
    auto = load_streams(capture["path"])[2]
    pinned = load_streams(capture["path"], server="10.0.0.9:9443")[2]
    assert pinned["s2c_bytes"] == auto["s2c_bytes"]


def test_pinned_server_tallies_the_same_flows(capture):
    auto = load_streams(capture["path"])[2]
    pinned = load_streams(capture["path"], server="10.0.0.9:9443")[2]
    # pinning skips the counting pass, so the flow table must be built on the way
    assert pinned["flows"] == auto["flows"]


def test_short_or_unknown_files_are_rejected(tmp_path):
    import pytest
    short = tmp_path / "short.pcap"
    short.write_bytes(b"\x00" * 10)
    with pytest.raises(ValueError, match="too short"):
        list(iter_packets(str(short)))
    junk = tmp_path / "junk.pcap"
    junk.write_bytes(b"\x00" * 64)
    with pytest.raises(ValueError, match="unknown capture magic"):
        list(iter_packets(str(junk)))
