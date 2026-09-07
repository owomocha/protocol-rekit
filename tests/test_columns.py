from rekit.columns import boundaries, infer
from rekit.framing import frames_from_pcap


def test_boundaries_on_hand_made_records():
    # three fixed-width records: two fields with a blank column (index 3) between
    records = [
        "AB  12 ",
        "CD  345",
        "EF  9  ",
    ]
    fields = boundaries(records)
    # column 2 and 3 are always blank -> a field at 0..1 and one starting at 4
    assert (0, 2) in fields
    assert any(start == 4 for start, _w in fields)


def test_infer_finds_the_telemetry_layout(capture):
    _send, recv = frames_from_pcap(capture["path"])
    tele = [f.text for f in recv if f.tag() == "TELE"]
    info = infer(tele)
    assert not info["variable"]           # every TELE record is the same length
    # tag, sensor, seq, three readings, and the glued flag+clock tail
    assert 6 <= len(info["fields"]) <= 8
    assert info["fields"][0]["samples"][0] == "TELE"
