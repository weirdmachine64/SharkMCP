"""Unit tests for sharkd.py — Session and SessionPool."""

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

import sharkmcp.sharkd as sharkd_module
from sharkmcp.sharkd import Session, SessionPool, SharkdError

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _bypass_selector(monkeypatch):
    """Replace _readline_with_timeout with a direct readline() call.

    The real implementation uses selectors, which requires a real file
    descriptor. MagicMock stdout objects don't have one.
    """
    monkeypatch.setattr(
        sharkd_module,
        "_readline_with_timeout",
        lambda stream, timeout: stream.readline(),
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_proc(responses: list[dict]) -> MagicMock:
    # Trailing "" signals EOF if readline() is called past the last response.
    lines = [json.dumps(r) + "\n" for r in responses] + [""]
    proc = MagicMock(spec=subprocess.Popen)
    proc.poll.return_value = None
    proc.returncode = 0
    proc.stdin = MagicMock()
    proc.stdout = MagicMock()
    proc.stdout.readline.side_effect = lines
    return proc


def _make_session(responses: list[dict], alias: str = "test") -> Session:
    return Session(alias=alias, path="/tmp/fake.pcap", proc=_make_proc(responses))


def _loaded_pool(tmp_path, alias: str = "s", extra_responses: list[dict] | None = None):
    pcap = tmp_path / f"{alias}.pcap"
    pcap.write_bytes(b"\x00")
    pool = SessionPool()
    responses = [{"jsonrpc": "2.0", "id": 1, "result": {"status": "OK"}}]
    if extra_responses:
        responses += extra_responses
    proc = _make_proc(responses)
    with patch("subprocess.Popen", return_value=proc):
        pool.load(str(pcap), alias=alias)
    return pool


# ---------------------------------------------------------------------------
# Session.call
# ---------------------------------------------------------------------------


def test_call_success_returns_result():
    sess = _make_session([{"jsonrpc": "2.0", "id": 1, "result": {"status": "OK"}}])
    assert sess.call("status") == {"status": "OK"}


def test_call_increments_id():
    sess = _make_session(
        [
            {"jsonrpc": "2.0", "id": 1, "result": "a"},
            {"jsonrpc": "2.0", "id": 2, "result": "b"},
        ]
    )
    sess.call("foo")
    sess.call("bar")
    calls = sess.proc.stdin.write.call_args_list
    assert json.loads(calls[0][0][0].strip())["id"] == 1
    assert json.loads(calls[1][0][0].strip())["id"] == 2


def test_call_raises_sharkerror_on_rpc_error():
    sess = _make_session(
        [{"jsonrpc": "2.0", "id": 1, "error": {"code": -32600, "message": "invalid"}}]
    )
    with pytest.raises(SharkdError) as exc_info:
        sess.call("status")
    assert exc_info.value.code == -32600


def test_call_raises_on_dead_process():
    sess = _make_session([])
    sess.proc.poll.return_value = 1
    with pytest.raises(SharkdError):
        sess.call("status")


def test_call_raises_on_empty_stdout():
    sess = _make_session([])
    with pytest.raises(SharkdError, match="closed"):
        sess.call("status")


def test_call_sends_params_when_provided():
    sess = _make_session([{"jsonrpc": "2.0", "id": 1, "result": {}}])
    sess.call("load", {"file": "/tmp/a.pcap"})
    payload = json.loads(sess.proc.stdin.write.call_args[0][0].strip())
    assert payload["params"] == {"file": "/tmp/a.pcap"}


def test_call_omits_params_key_when_none():
    sess = _make_session([{"jsonrpc": "2.0", "id": 1, "result": {}}])
    sess.call("status")
    payload = json.loads(sess.proc.stdin.write.call_args[0][0].strip())
    assert "params" not in payload


# ---------------------------------------------------------------------------
# Session.close
# ---------------------------------------------------------------------------


def test_close_sends_bye():
    sess = _make_session([{"jsonrpc": "2.0", "id": 1, "result": {}}])
    sess.close()
    written = sess.proc.stdin.write.call_args_list[0][0][0]
    assert json.loads(written.strip())["method"] == "bye"


def test_close_tolerates_bye_failure():
    sess = _make_session([])
    sess.proc.poll.return_value = 1
    sess.close()  # should not raise


# ---------------------------------------------------------------------------
# SessionPool
# ---------------------------------------------------------------------------


def test_pool_load_stores_session(tmp_path):
    pool = _loaded_pool(tmp_path, alias="s1")
    assert "s1" in pool.aliases()


def test_pool_load_raises_if_alias_exists(tmp_path):
    pcap = tmp_path / "dup.pcap"
    pcap.write_bytes(b"\x00")
    pool = SessionPool()
    procs = [
        _make_proc([{"jsonrpc": "2.0", "id": 1, "result": {"status": "OK"}}]),
        _make_proc([{"jsonrpc": "2.0", "id": 1, "result": {"status": "OK"}}]),
    ]
    with patch("subprocess.Popen", side_effect=procs):
        pool.load(str(pcap), alias="dup")
        with pytest.raises(ValueError, match="already loaded"):
            pool.load(str(pcap), alias="dup")


def test_pool_load_raises_file_not_found():
    pool = SessionPool()
    with pytest.raises(FileNotFoundError):
        pool.load("/nonexistent/path.pcap")


def test_pool_load_raises_on_non_ok_result(tmp_path):
    pcap = tmp_path / "bad.pcap"
    pcap.write_bytes(b"\x00")
    pool = SessionPool()
    proc = _make_proc([{"jsonrpc": "2.0", "id": 1, "result": {"status": "ERR"}}])
    with patch("subprocess.Popen", return_value=proc):
        with pytest.raises(SharkdError):
            pool.load(str(pcap))


def test_pool_get_raises_on_unknown_alias():
    pool = SessionPool()
    with pytest.raises(KeyError, match="unknown alias"):
        pool.get("nope")


def test_pool_unload_removes_session(tmp_path):
    pool = _loaded_pool(
        tmp_path, alias="x", extra_responses=[{"jsonrpc": "2.0", "id": 2, "result": {}}]
    )
    pool.unload("x")
    assert "x" not in pool.aliases()


def test_pool_unload_raises_on_unknown_alias():
    pool = SessionPool()
    with pytest.raises(KeyError, match="unknown alias"):
        pool.unload("ghost")


def test_pool_aliases_returns_all_loaded(tmp_path):
    pool = SessionPool()
    for name in ("a", "b", "c"):
        p = tmp_path / f"{name}.pcap"
        p.write_bytes(b"\x00")
        proc = _make_proc([{"jsonrpc": "2.0", "id": 1, "result": {"status": "OK"}}])
        with patch("subprocess.Popen", return_value=proc):
            pool.load(str(p), alias=name)
    assert set(pool.aliases()) == {"a", "b", "c"}


def test_pool_close_all_empties_pool(tmp_path):
    pool = SessionPool()
    for name in ("p", "q"):
        p = tmp_path / f"{name}.pcap"
        p.write_bytes(b"\x00")
        proc = _make_proc(
            [
                {"jsonrpc": "2.0", "id": 1, "result": {"status": "OK"}},
                {"jsonrpc": "2.0", "id": 2, "result": {}},
            ]
        )
        with patch("subprocess.Popen", return_value=proc):
            pool.load(str(p), alias=name)
    pool.close_all()
    assert pool.aliases() == []


def test_pool_default_alias_is_filename(tmp_path):
    pcap = tmp_path / "myfile.pcap"
    pcap.write_bytes(b"\x00")
    pool = SessionPool()
    proc = _make_proc([{"jsonrpc": "2.0", "id": 1, "result": {"status": "OK"}}])
    with patch("subprocess.Popen", return_value=proc):
        sess = pool.load(str(pcap))
    assert sess.alias == "myfile.pcap"
