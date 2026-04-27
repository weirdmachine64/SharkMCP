"""Unit tests for server.py — caching, pagination, alias maps, tool logic."""

from unittest.mock import MagicMock

import pytest

import sharkmcp.server as srv

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_session(responses: dict) -> MagicMock:
    """Return a session whose .call(method, ...) returns responses[method]."""
    sess = MagicMock()
    sess.call.side_effect = lambda method, *args, **kwargs: responses.get(method, {})
    return sess


def _wire_pool(alias: str, responses: dict):
    """Patch pool.get so alias resolves to a mock session."""
    sess = _mock_session(responses)
    srv.pool.get = MagicMock(return_value=sess)
    return sess


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------


def _clear_cache():
    with srv._cache_lock:
        srv._cache.clear()


def test_cache_get_returns_none_for_missing_key():
    _clear_cache()
    assert srv._cache_get(("missing",)) is None


def test_cache_set_and_get_roundtrip():
    _clear_cache()
    key = ("tap", "alias1", "conv:TCP", "")
    srv._cache_set(key, [{"a": 1}])
    assert srv._cache_get(key) == [{"a": 1}]


def test_invalidate_alias_removes_matching_keys():
    _clear_cache()
    srv._cache_set(("tap", "victim", "conv:TCP", ""), [1])
    srv._cache_set(("tap", "victim", "endpt:TCP", ""), [2])
    srv._cache_set(("tap", "other", "conv:TCP", ""), [3])
    srv._invalidate_alias("victim")
    assert srv._cache_get(("tap", "victim", "conv:TCP", "")) is None
    assert srv._cache_get(("tap", "victim", "endpt:TCP", "")) is None
    assert srv._cache_get(("tap", "other", "conv:TCP", "")) == [3]


# ---------------------------------------------------------------------------
# _paginate
# ---------------------------------------------------------------------------


def _items(n: int) -> list[dict]:
    return [{"txf": i, "rxf": i, "txb": i * 10, "rxb": i * 10} for i in range(n)]


def test_paginate_by_bytes_sorts_descending():
    items = _items(5)
    result = srv._paginate(items, "convs", "bytes", 0, 5)
    totals = [e["txb"] + e["rxb"] for e in result["convs"]]
    assert totals == sorted(totals, reverse=True)


def test_paginate_by_frames_sorts_descending():
    items = _items(5)
    result = srv._paginate(items, "convs", "frames", 0, 5)
    totals = [e["txf"] + e["rxf"] for e in result["convs"]]
    assert totals == sorted(totals, reverse=True)


def test_paginate_skip_and_limit():
    items = _items(10)
    result = srv._paginate(items, "convs", "bytes", skip=2, limit=3)
    assert len(result["convs"]) == 3
    assert result["skip"] == 2
    assert result["limit"] == 3
    assert result["total"] == 10


def test_paginate_truncated_flag():
    items = _items(10)
    result = srv._paginate(items, "convs", "bytes", skip=0, limit=5)
    assert result["truncated"] is True


def test_paginate_not_truncated_when_all_returned():
    items = _items(3)
    result = srv._paginate(items, "convs", "bytes", skip=0, limit=10)
    assert result["truncated"] is False


def test_paginate_limit_zero_returns_all():
    items = _items(7)
    result = srv._paginate(items, "convs", "bytes", skip=0, limit=0)
    assert len(result["convs"]) == 7


# ---------------------------------------------------------------------------
# _validate_graph_type
# ---------------------------------------------------------------------------


def test_validate_graph_type_accepts_basic():
    for t in ("packets", "bytes", "bits"):
        srv._validate_graph_type(t)  # no exception


def test_validate_graph_type_accepts_aggregators():
    for t in (
        "sum:tcp.len",
        "avg:udp.length",
        "min:frame.len",
        "max:ip.ttl",
        "load:tcp.len",
        "frames:tcp.len",
    ):
        srv._validate_graph_type(t)


def test_validate_graph_type_rejects_unknown():
    with pytest.raises(ValueError, match="invalid graph type"):
        srv._validate_graph_type("garbage")


# ---------------------------------------------------------------------------
# Layer alias map
# ---------------------------------------------------------------------------


def test_layer_alias_tcp():
    assert srv._LAYER_ALIASES["tcp"] == "TCP"


def test_layer_alias_ipv4_variants():
    assert srv._LAYER_ALIASES["ip"] == "IPv4"
    assert srv._LAYER_ALIASES["ipv4"] == "IPv4"


def test_follow_alias_tls():
    assert srv._FOLLOW_ALIASES["tls"] == "TLS"


# ---------------------------------------------------------------------------
# load_pcap / list_pcaps / unload_pcap
# ---------------------------------------------------------------------------


def test_load_pcap_invalidates_cache_and_returns_alias():
    _clear_cache()
    srv._cache_set(("tap", "demo", "conv:TCP", ""), [1, 2])

    fake_sess = MagicMock()
    fake_sess.alias = "demo"
    fake_sess.path = "/tmp/demo.pcap"
    fake_sess.call.return_value = {"frames": 100}
    srv.pool.load = MagicMock(return_value=fake_sess)

    result = srv.load_pcap("/tmp/demo.pcap", alias="demo")
    assert result["alias"] == "demo"
    assert srv._cache_get(("tap", "demo", "conv:TCP", "")) is None


def test_list_pcaps_aggregates_status():
    fake_sess = MagicMock()
    fake_sess.path = "/tmp/x.pcap"
    fake_sess.call.return_value = {"frames": 5}
    srv.pool.aliases = MagicMock(return_value=["x"])
    srv.pool.get = MagicMock(return_value=fake_sess)

    result = srv.list_pcaps()
    assert len(result) == 1
    assert result[0]["alias"] == "x"


def test_unload_pcap_invalidates_cache():
    _clear_cache()
    srv._cache_set(("tap", "bye", "conv:TCP", ""), [99])
    srv.pool.unload = MagicMock()

    result = srv.unload_pcap("bye")
    assert result == {"alias": "bye", "unloaded": True}
    assert srv._cache_get(("tap", "bye", "conv:TCP", "")) is None


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------


def test_validate_raises_if_neither_filter_nor_field():
    with pytest.raises(ValueError, match="at least one"):
        srv.validate("alias")


def test_validate_returns_ok_on_success():
    _wire_pool("alias", {"check": {"status": "OK"}})
    result = srv.validate("alias", filter="tcp.port == 80")
    assert result["status"] == "OK"


def test_validate_returns_error_on_sharkerror():
    from sharkmcp.sharkd import SharkdError

    sess = MagicMock()
    sess.call.side_effect = SharkdError(-1, "bad filter")
    srv.pool.get = MagicMock(return_value=sess)
    result = srv.validate("alias", filter="!!!bad!!!")
    assert result["status"] == "error"


# ---------------------------------------------------------------------------
# complete
# ---------------------------------------------------------------------------


def test_complete_raises_if_neither_field_nor_pref():
    with pytest.raises(ValueError, match="at least one"):
        srv.complete("alias")


def test_complete_truncates_at_limit():
    _wire_pool("alias", {"complete": {"field": [f"tcp.f{i}" for i in range(300)]}})
    result = srv.complete("alias", field="tcp.", limit=10)
    assert result["field"]["truncated"] is True
    assert len(result["field"]["items"]) == 10


def test_complete_no_truncation_when_under_limit():
    _wire_pool("alias", {"complete": {"field": ["tcp.port", "tcp.len"]}})
    result = srv.complete("alias", field="tcp.", limit=200)
    assert result["field"]["truncated"] is False


# ---------------------------------------------------------------------------
# tap — raw escape hatch
# ---------------------------------------------------------------------------


def test_tap_raises_on_empty_specs():
    with pytest.raises(ValueError, match="non-empty"):
        srv.tap("alias", [])


def test_tap_raises_on_too_many_specs():
    with pytest.raises(ValueError, match="16"):
        srv.tap("alias", [f"spec{i}" for i in range(17)])


def test_tap_caches_result():
    _clear_cache()
    tap_data = [{"type": "conv", "convs": [{"a": 1}]}]
    _wire_pool("alias", {"tap": {"taps": tap_data}})

    srv.tap("alias", ["conv:TCP"])
    # second call should NOT hit pool.get again (served from cache)
    srv.pool.get.reset_mock()
    srv.tap("alias", ["conv:TCP"])
    srv.pool.get.assert_not_called()


# ---------------------------------------------------------------------------
# protocol_stats / service_response_time / response_time_delay
# ---------------------------------------------------------------------------


def test_protocol_stats_raises_on_unknown():
    with pytest.raises(ValueError, match="unknown protocol"):
        srv.protocol_stats("alias", "fakeproto")


def test_service_response_time_raises_on_unknown():
    with pytest.raises(ValueError, match="unknown protocol"):
        srv.service_response_time("alias", "notreal")


def test_response_time_delay_raises_on_unknown():
    with pytest.raises(ValueError, match="unknown protocol"):
        srv.response_time_delay("alias", "notreal")


# ---------------------------------------------------------------------------
# iograph
# ---------------------------------------------------------------------------


def test_iograph_raises_on_too_many_graphs():
    with pytest.raises(ValueError, match="8"):
        srv.iograph("alias", graphs=["packets"] * 9)


def test_iograph_raises_on_invalid_graph_type():
    with pytest.raises(ValueError, match="invalid graph type"):
        srv.iograph("alias", graphs=["bad_type"])
