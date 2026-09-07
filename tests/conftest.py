import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from rekit import demo  # noqa: E402


@pytest.fixture(scope="session")
def capture(tmp_path_factory):
    """A synthetic capture plus the ground truth used to make it."""
    path = tmp_path_factory.mktemp("cap") / "tlm.pcap"
    truth = demo.generate(str(path))
    return truth
