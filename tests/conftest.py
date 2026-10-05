import pytest

TOKEN = "AKIAFUSE7Q2X9EXAMPLE"


@pytest.fixture(autouse=True)
def fuse_home(tmp_path, monkeypatch):
    """Every test gets its own state dir; nothing touches the real ~/.bastionfuse."""
    home = tmp_path / "fusehome"
    monkeypatch.setenv("BASTIONFUSE_HOME", str(home))
    monkeypatch.delenv("BASTIONFUSE_HONEYTOKENS", raising=False)
    monkeypatch.delenv("BASTIONFUSE_KILL", raising=False)
    return home


def pol(**fuse):
    return {"policy_version": 2, "fuse": fuse}
