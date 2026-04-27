"""SharkMCP — MCP server exposing the full sharkd JSON-RPC API."""

import atexit
import threading
from typing import Any, Literal

from mcp.server.fastmcp import FastMCP

from sharkmcp.sharkd import SessionPool, SharkdError

mcp = FastMCP("sharkmcp")
pool = SessionPool()
atexit.register(pool.close_all)

# ---------------------------------------------------------------------------
# Result cache
# ---------------------------------------------------------------------------
_cache: dict[tuple, list[Any]] = {}
_cache_lock = threading.Lock()


def _cache_get(key: tuple) -> list[Any] | None:
    with _cache_lock:
        return _cache.get(key)


def _cache_set(key: tuple, value: list[Any]) -> None:
    with _cache_lock:
        _cache[key] = value


def _invalidate_alias(alias: str) -> None:
    with _cache_lock:
        stale = [k for k in _cache if k[1] == alias]
        for k in stale:
            del _cache[k]


# ---------------------------------------------------------------------------
# Name mappings
# ---------------------------------------------------------------------------

_LAYER_ALIASES: dict[str, str] = {
    # Common
    "tcp": "TCP",
    "udp": "UDP",
    "ip": "IPv4",
    "ipv4": "IPv4",
    "ipv6": "IPv6",
    "eth": "Ethernet",
    "ethernet": "Ethernet",
    # Transport
    "sctp": "SCTP",
    "dccp": "DCCP",
    "mptcp": "MPTCP",
    # Wireless
    "wifi": "IEEE 802.11",
    "ieee80211": "IEEE 802.11",
    "wpan": "IEEE 802.15.4",
    "ieee802154": "IEEE 802.15.4",
    "bluetooth": "Bluetooth",
    "zigbee": "ZigBee",
    # Legacy / specialty
    "fc": "FC",
    "fddi": "FDDI",
    "tokenring": "Token-Ring",
    "sll": "SLL",
    "usb": "USB",
    "ipx": "IPX",
    "ncp": "NCP",
    "jxta": "JXTA",
    "ltp": "LTP",
    "bpv7": "BPv7",
    "rsvp": "RSVP",
    "opensafety": "openSAFETY",
}

# sharkd uses mixed-case for some follow targets
_FOLLOW_ALIASES: dict[str, str] = {
    "tcp": "TCP",
    "udp": "UDP",
    "tls": "TLS",
    "http": "HTTP",
    "http2": "HTTP2",
    "quic": "QUIC",
    "sip": "SIP",
    "dccp": "DCCP",
    "websocket": "WebSocket",
}

_PROTOCOL_STATS_MAP: dict[str, str] = {
    "dns": "stat:dns",
    "http": "stat:http",
    "http_requests": "stat:http_req",
    "http_server": "stat:http_srv",
    "http_seq": "stat:http_seq",
    "http2": "stat:http2",
    "rtsp": "stat:rtsp",
    "sip": "nstat:sip,stat",
    "dhcp": "nstat:dhcp,stat",
    "h225": "nstat:h225,counter",
}

_SRT_MAP: dict[str, str] = {
    "afp": "srt:afp",
    "camel": "srt:camel",
    "dcerpc": "srt:dcerpc",
    "diameter": "srt:diameter",
    "fc": "srt:fc",
    "gtp": "srt:gtp",
    "gtpv2": "srt:gtpv2",
    "ldap": "srt:ldap",
    "ncp": "srt:ncp",
    "rpc": "srt:rpc",
    "scsi": "srt:scsi",
    "smb": "srt:smb",
    "smb2": "srt:smb2",
    "snmp": "srt:snmp",
}

_RTD_MAP: dict[str, str] = {
    "h225_ras": "rtd:h225_ras",
    "megaco": "rtd:megaco",
    "mgcp": "rtd:mgcp",
    "radius": "rtd:radius",
}

_SEQA_MAP: dict[str, str] = {
    "any": "seqa:any",
    "tcp": "seqa:tcp",
    "icmp": "seqa:icmp",
    "icmpv6": "seqa:icmpv6",
}


# ---------------------------------------------------------------------------
# Tap helpers
# ---------------------------------------------------------------------------


def _tap(alias: str, spec: str, display_filter: str | None) -> Any:
    sess = pool.get(alias)
    params: dict[str, Any] = {"tap0": spec}
    if display_filter:
        params["filter"] = display_filter
    return sess.call("tap", params)


def _tap_cached(
    alias: str, spec: str, display_filter: str | None, list_key: str
) -> list[Any]:
    """Return the raw item list for a tap, using the cache when available.

    The sharkd call (and PCAP rescan) only happens on the first request for
    a given (alias, spec, filter) combination. All subsequent calls —
    including paginated pages — are served from memory.
    """
    key = ("tap", alias, spec, display_filter or "")
    cached = _cache_get(key)
    if cached is not None:
        return cached
    result = _tap(alias, spec, display_filter)
    taps = result.get("taps", []) if isinstance(result, dict) else []
    items: list[Any] = []
    for tap in taps:
        if list_key in tap:
            items = tap[list_key]
            break
    _cache_set(key, items)
    return items


def _paginate(
    items: list[Any], list_key: str, sort_by: str, skip: int, limit: int
) -> dict:
    if sort_by == "bytes":
        items = sorted(
            items, key=lambda x: x.get("txb", 0) + x.get("rxb", 0), reverse=True
        )
    else:
        items = sorted(
            items, key=lambda x: x.get("txf", 0) + x.get("rxf", 0), reverse=True
        )
    total = len(items)
    page = items[skip : skip + limit] if limit else items[skip:]
    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "truncated": (skip + len(page)) < total,
        list_key: page,
    }


# Flat list keys that can be paginated.
# "protos" (phs nested tree) is intentionally excluded.
_FLAT_LIST_KEYS = (
    "convs",
    "hosts",
    "objects",
    "details",
    "streams",
    "calls",
    "clips",
    "nodes",
    "packets",
    "flows",
)


def _detect_list_key(tap_entry: dict) -> str | None:
    for key in _FLAT_LIST_KEYS:
        if key in tap_entry and isinstance(tap_entry[key], list):
            return key
    return None


# ---------------------------------------------------------------------------
# Graph type validation
# ---------------------------------------------------------------------------

_BASIC_GRAPH_TYPES = {"packets", "bytes", "bits"}
_ADVANCED_PREFIXES = ("sum:", "frames:", "max:", "min:", "avg:", "load:")


def _validate_graph_type(g: str) -> None:
    if g in _BASIC_GRAPH_TYPES or any(g.startswith(p) for p in _ADVANCED_PREFIXES):
        return
    raise ValueError(
        f"invalid graph type {g!r}; use 'packets', 'bytes', 'bits', "
        "or a field aggregator: sum:<f>, frames:<f>, max:<f>, "
        "min:<f>, avg:<f>, load:<f>"
    )


# ---------------------------------------------------------------------------
# Shared layer-type Literal (used by both conversations and endpoints)
# ---------------------------------------------------------------------------

_LayerType = Literal[
    # Common
    "tcp",
    "udp",
    "ip",
    "ipv4",
    "ipv6",
    "eth",
    "ethernet",
    # Transport
    "sctp",
    "dccp",
    "mptcp",
    # Wireless
    "wifi",
    "ieee80211",
    "wpan",
    "ieee802154",
    "bluetooth",
    "zigbee",
    # Legacy / specialty
    "fc",
    "fddi",
    "tokenring",
    "sll",
    "usb",
    "ipx",
    "ncp",
    "jxta",
    "ltp",
    "bpv7",
    "rsvp",
    "opensafety",
]


# ===========================================================================
# SESSION MANAGEMENT
# ===========================================================================


@mcp.tool()
def load_pcap(path: str, alias: str | None = None) -> dict:
    """Load a PCAP/PCAPNG file into a fresh sharkd session.

    `alias` defaults to the basename. Each loaded PCAP keeps a dedicated
    sharkd subprocess warm so subsequent queries are interactive.
    Returns the alias and basic status (frame count, duration, file size).
    """
    sess = pool.load(path, alias)
    _invalidate_alias(sess.alias)
    return {"alias": sess.alias, "path": sess.path, "status": sess.call("status")}


@mcp.tool()
def list_pcaps() -> list[dict]:
    """List every loaded PCAP with its current sharkd status."""
    out = []
    for alias in pool.aliases():
        sess = pool.get(alias)
        try:
            status: Any = sess.call("status")
        except SharkdError as e:
            status = {"error": str(e)}
        out.append({"alias": alias, "path": sess.path, "status": status})
    return out


@mcp.tool()
def unload_pcap(alias: str) -> dict:
    """Terminate the sharkd session for `alias` and free its memory."""
    pool.unload(alias)
    _invalidate_alias(alias)
    return {"alias": alias, "unloaded": True}


# ===========================================================================
# FILE OVERVIEW
# ===========================================================================


@mcp.tool()
def pcap_summary(alias: str) -> dict:
    """Combined `status` + `analyse`: filename, size, frame count, duration,
    protocols seen, first/last timestamps."""
    sess = pool.get(alias)
    return {
        "alias": alias,
        "status": sess.call("status"),
        "analyse": sess.call("analyse"),
    }


@mcp.tool()
def server_info(alias: str) -> dict:
    """List all types available in this sharkd session: tap identifiers,
    follow protocols, column fields, and stats tree entries.

    Useful for discovering valid values before calling conversations,
    endpoints, follow_stream, or protocol_hierarchy.
    """
    sess = pool.get(alias)
    return sess.call("info")


# ===========================================================================
# PACKET INSPECTION
# ===========================================================================


@mcp.tool()
def list_packets(
    alias: str,
    display_filter: str | None = None,
    skip: int = 0,
    limit: int = 100,
    columns: list[str] | None = None,
    refs: list[int] | None = None,
) -> dict:
    """Page through packets via sharkd `frames`.

    `display_filter` accepts Wireshark display-filter syntax.
    `columns` overrides the default column set with arbitrary field names
      (e.g. `["frame.number", "ip.src", "tcp.dstport"]`).
    `refs` is a list of reference frame numbers for delta-time calculations.
    """
    sess = pool.get(alias)
    params: dict[str, Any] = {"limit": limit}
    if skip > 0:
        params["skip"] = skip
    if display_filter:
        params["filter"] = display_filter
    if columns:
        for i, col in enumerate(columns):
            params[f"column{i}"] = col if ":" in col else f"{col}:0"
    if refs:
        params["refs"] = ",".join(str(r) for r in refs)
    frames = sess.call("frames", params)
    return {
        "alias": alias,
        "skip": skip,
        "limit": limit,
        "filter": display_filter,
        "columns": columns,
        "frames": frames,
    }


@mcp.tool()
def packet_detail(
    alias: str,
    frame_number: int,
    include_bytes: bool = False,
    include_hidden: bool = False,
    ref_frame: int | None = None,
    prev_frame: int | None = None,
) -> Any:
    """Full protocol tree for one frame.

    `include_bytes`  — add raw bytes (base64) per layer.
    `include_hidden` — include hidden protocol tree fields.
    `ref_frame`      — reference frame number for delta-time display.
    `prev_frame`     — previous frame number for delta-time display.
    """
    sess = pool.get(alias)
    params: dict[str, Any] = {
        "frame": frame_number,
        "proto": True,
        "columns": True,
        "color": True,
    }
    if include_bytes:
        params["bytes"] = True
    if include_hidden:
        params["hidden"] = True
    if ref_frame is not None:
        params["ref_frame"] = ref_frame
    if prev_frame is not None:
        params["prev_frame"] = prev_frame
    return sess.call("frame", params)


@mcp.tool()
def extract_fields(
    alias: str,
    fields: list[str],
    display_filter: str | None = None,
    skip: int = 0,
    limit: int = 100,
) -> dict:
    """Extract arbitrary fields per packet, e.g.
    `["ip.src", "tcp.dstport", "http.host"]`. Returns rows of dicts keyed
    by field name."""
    if not fields:
        raise ValueError("fields must be non-empty")
    sess = pool.get(alias)
    params: dict[str, Any] = {"limit": limit}
    if skip > 0:
        params["skip"] = skip
    if display_filter:
        params["filter"] = display_filter
    for i, f in enumerate(fields):
        params[f"column{i}"] = f if ":" in f else f"{f}:0"
    raw = sess.call("frames", params) or []
    rows = []
    for entry in raw:
        cols = entry.get("c") or entry.get("columns") or []
        row: dict[str, Any] = dict(zip(fields, cols))
        if "num" in entry:
            row["_frame"] = entry["num"]
        rows.append(row)
    return {
        "alias": alias,
        "fields": fields,
        "skip": skip,
        "limit": limit,
        "filter": display_filter,
        "rows": rows,
    }


# ===========================================================================
# UTILITIES
# ===========================================================================


@mcp.tool()
def validate(
    alias: str,
    filter: str | None = None,
    field: str | None = None,
) -> dict:
    """Validate a display-filter expression and/or a field name.

    `filter` — Wireshark display filter (e.g. `tcp.port == 443`).
    `field`  — fully qualified field name (e.g. `http.request.method`).

    Returns `{"status":"OK"}` on success or an error object.
    At least one of filter or field must be provided.
    """
    if filter is None and field is None:
        raise ValueError("provide at least one of filter or field")
    sess = pool.get(alias)
    params: dict[str, Any] = {}
    if filter is not None:
        params["filter"] = filter
    if field is not None:
        params["field"] = field
    try:
        result = sess.call("check", params)
        if isinstance(result, dict):
            return result
        return {"status": "OK", "result": result}
    except SharkdError as e:
        return {"status": "error", "code": e.code, "message": str(e)}


@mcp.tool()
def complete(
    alias: str,
    field: str | None = None,
    pref: str | None = None,
    limit: int = 200,
) -> dict:
    """Autocomplete field names or preference names by prefix.

    `field` — field prefix, e.g. `"tcp."` → all tcp.* dissector fields.
    `pref`  — preference prefix, e.g. `"tcp."` → all tcp.* preferences.

    At least one of field or pref must be provided.
    Dense protocols (e.g. `"opcua."`) can return thousands of entries;
    `limit` caps the list (0 = no cap).
    """
    if field is None and pref is None:
        raise ValueError("provide at least one of field or pref")
    sess = pool.get(alias)
    params: dict[str, Any] = {}
    if field is not None:
        params["field"] = field
    if pref is not None:
        params["pref"] = pref
    raw = sess.call("complete", params)
    result: dict[str, Any] = {}
    if field is not None:
        items = raw.get("field", []) if isinstance(raw, dict) else []
        total = len(items)
        truncated = bool(limit) and total > limit
        result["field"] = {
            "prefix": field,
            "total": total,
            "truncated": truncated,
            "items": items[:limit] if truncated else items,
        }
    if pref is not None:
        items = raw.get("pref", []) if isinstance(raw, dict) else []
        total = len(items)
        truncated = bool(limit) and total > limit
        result["pref"] = {
            "prefix": pref,
            "total": total,
            "truncated": truncated,
            "items": items[:limit] if truncated else items,
        }
    return result


@mcp.tool()
def get_preference(alias: str, preference: str | None = None) -> dict:
    """Read one or all sharkd dissector preferences.

    Pass a dotted preference name (e.g. `"tcp.check_checksum"`) to read a
    single value, or omit to dump all preferences. Useful for checking
    whether a dissector is enabled or what port a protocol is bound to.
    """
    sess = pool.get(alias)
    params: dict[str, Any] = {}
    if preference:
        params["pref"] = preference
    return sess.call("dumpconf", params)


@mcp.tool()
def set_preference(alias: str, name: str, value: str) -> dict:
    """Set a sharkd dissector preference for this session.

    Changes are session-scoped and do not persist after the server restarts.
    Common uses: forcing a non-standard port to decode as a specific protocol
    (e.g. `name="http.tcp.port", value="8080"`), or enabling/disabling a
    dissector option.
    """
    sess = pool.get(alias)
    return sess.call("setconf", {"name": name, "value": value})


@mcp.tool()
def set_frame_comment(alias: str, frame_number: int, comment: str = "") -> dict:
    """Set a comment on a frame for the duration of this session (non-persistent).

    Pass an empty string to clear an existing comment.
    Useful for annotating frames during forensic analysis.
    """
    sess = pool.get(alias)
    return sess.call("setcomment", {"frame": frame_number, "comment": comment})


# ===========================================================================
# TRAFFIC STRUCTURE
# ===========================================================================


@mcp.tool()
def protocol_hierarchy(alias: str, display_filter: str | None = None) -> Any:
    """Protocol hierarchy stats — nested tree of frame/byte counts per protocol."""
    return _tap(alias, "phs", display_filter)


@mcp.tool()
def io_stats(
    alias: str,
    interval_ms: int = 1000,
    display_filter: str | None = None,
    skip: int = 0,
    limit: int = 300,
) -> Any:
    """Per-interval frame and byte counts. `interval_ms` is the bucket size.

    Results are in chronological order and paged with `skip`/`limit`.
    The PCAP is scanned only on the first call for a given (interval, filter)
    combination; subsequent pages are served from cache.
    Default limit is 300 intervals (~5 min at 1 s buckets). Set `limit=0` for all.
    """
    key = ("ivl", alias, interval_ms, display_filter or "")
    intervals = _cache_get(key)
    if intervals is None:
        sess = pool.get(alias)
        params: dict[str, Any] = {"interval": interval_ms}
        if display_filter:
            params["filter"] = display_filter
        result = sess.call("intervals", params)
        intervals = result.get("intervals", []) if isinstance(result, dict) else []
        _cache_set(key, intervals)
    total = len(intervals)
    page = intervals[skip : skip + limit] if limit else intervals[skip:]
    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "truncated": (skip + len(page)) < total,
        "intervals": page,
    }


@mcp.tool()
def iograph(
    alias: str,
    graphs: list[str],
    interval_ms: int = 1000,
    filters: list[str] | None = None,
    skip: int = 0,
    limit: int = 300,
) -> dict:
    """Per-interval traffic graph for up to 8 simultaneous lines.

    Each entry in `graphs` must be one of:
      "packets" | "bytes" | "bits"          — basic counters
      "sum:<field>" | "avg:<field>"         — aggregate a numeric field per interval
      "min:<field>" | "max:<field>"         — min/max of a numeric field per interval
      "load:<field>" | "frames:<field>"     — bit-rate or frame count for a field

    `filters` — optional per-graph display filters (parallel list to graphs);
                enables multi-line graphs of different protocol streams.

    Results are paged with `skip`/`limit` (default 300 buckets ≈ 5 min at 1 s).
    """
    for g in graphs:
        _validate_graph_type(g)
    if not graphs:
        graphs = ["packets"]
    if len(graphs) > 8:
        raise ValueError("sharkd supports at most 8 simultaneous graphs")

    sess = pool.get(alias)
    params: dict[str, Any] = {"interval": interval_ms}
    for i, g in enumerate(graphs):
        params[f"graph{i}"] = g
    if filters:
        for i, f in enumerate(filters[: len(graphs)]):
            if f:
                params[f"filter{i}"] = f

    result = sess.call("iograph", params)
    if isinstance(result, dict):
        raw = result.get("iograph", [])
        out_graphs = []
        for i, entry in enumerate(raw):
            items = entry.get("items", [])
            total = len(items)
            page = items[skip : skip + limit] if limit else items[skip:]
            out_graphs.append(
                {
                    "type": graphs[i] if i < len(graphs) else f"graph{i}",
                    "total_intervals": total,
                    "skip": skip,
                    "limit": limit,
                    "truncated": (skip + len(page)) < total,
                    "items": page,
                }
            )
        return {"interval_ms": interval_ms, "graphs": out_graphs}
    return result


@mcp.tool()
def follow_stream(
    alias: str,
    protocol: Literal[
        "tcp", "udp", "tls", "http", "http2", "quic", "sip", "dccp", "websocket"
    ],
    display_filter: str,
    max_payloads: int = 200,
) -> Any:
    """Reassemble a stream. `display_filter` selects it (e.g. `tcp.stream eq 3`).
    Returns client/server addrs and base64 payload chunks with direction.

    Long-lived streams can produce huge payload lists; `max_payloads` caps
    how many chunks are returned. Set to 0 for no cap.
    """
    proto = _FOLLOW_ALIASES.get(protocol.lower(), protocol.upper())
    sess = pool.get(alias)
    result = sess.call("follow", {"follow": proto, "filter": display_filter})
    if max_payloads and isinstance(result, dict):
        payloads = result.get("payloads")
        if isinstance(payloads, list) and len(payloads) > max_payloads:
            result["total_payloads"] = len(payloads)
            result["truncated"] = True
            result["payloads"] = payloads[:max_payloads]
    return result


# ===========================================================================
# CONVERSATIONS & TOPOLOGY
# ===========================================================================


@mcp.tool()
def conversations(
    alias: str,
    type: _LayerType = "tcp",
    display_filter: str | None = None,
    sort_by: Literal["bytes", "frames"] = "bytes",
    skip: int = 0,
    limit: int = 20,
) -> Any:
    """Conversation table for a given layer. Sums frames/bytes per peer pair.

    Results are sorted by `sort_by` (descending) and paged with `skip`/`limit`.
    The PCAP is scanned only on the first call for a given filter; all
    subsequent pages are served from an in-memory cache. Set `limit=0` for all.
    """
    proto = _LAYER_ALIASES.get(type.lower(), type)
    spec = f"conv:{proto}"
    items = _tap_cached(alias, spec, display_filter, "convs")
    return _paginate(items, "convs", sort_by, skip, limit)


@mcp.tool()
def endpoints(
    alias: str,
    type: _LayerType = "tcp",
    display_filter: str | None = None,
    sort_by: Literal["bytes", "frames"] = "bytes",
    skip: int = 0,
    limit: int = 20,
) -> Any:
    """Endpoint table for a given layer. Sums tx/rx frames and bytes per host.

    Results are sorted by `sort_by` (descending) and paged with `skip`/`limit`.
    The PCAP is scanned only on the first call for a given filter; all
    subsequent pages are served from an in-memory cache. Set `limit=0` for all.
    """
    proto = _LAYER_ALIASES.get(type.lower(), type)
    spec = f"endpt:{proto}"
    items = _tap_cached(alias, spec, display_filter, "hosts")
    return _paginate(items, "hosts", sort_by, skip, limit)


# ===========================================================================
# PROTOCOL STATISTICS
# ===========================================================================


@mcp.tool()
def expert_info(
    alias: str,
    display_filter: str | None = None,
    skip: int = 0,
    limit: int = 100,
) -> dict:
    """Per-frame expert diagnostics — errors, warnings, notes, and chats.

    Returns Wireshark's built-in anomaly detection results: TCP retransmissions,
    malformed packets, unusual sequences, and protocol violations.
    Each entry contains frame number (`f`), severity (`s`), protocol (`p`),
    and message (`m`). Results are cached after the first scan.
    """
    items = _tap_cached(alias, "expert", display_filter, "details")
    total = len(items)
    page = items[skip : skip + limit] if limit else items[skip:]
    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "truncated": (skip + len(page)) < total,
        "details": page,
    }


@mcp.tool()
def protocol_stats(
    alias: str,
    protocol: Literal[
        "dns",
        "http",
        "http_requests",
        "http_server",
        "http_seq",
        "http2",
        "rtsp",
        "sip",
        "dhcp",
        "h225",
    ],
    display_filter: str | None = None,
) -> Any:
    """Protocol-level aggregate statistics.

    protocol options:
      dns           — query/response counts by type and return code
      http          — HTTP request/response packet counters
      http_requests — requests grouped by URI
      http_server   — load distribution across servers
      http_seq      — HTTP request sequences
      http2         — HTTP/2 stream statistics
      rtsp          — RTSP packet counters
      sip           — SIP response code counters
      dhcp          — DHCP message type distribution
      h225          — H.225 message and response status
    """
    spec = _PROTOCOL_STATS_MAP.get(protocol)
    if spec is None:
        raise ValueError(f"unknown protocol {protocol!r}")
    return _tap(alias, spec, display_filter)


@mcp.tool()
def service_response_time(
    alias: str,
    protocol: Literal[
        "smb",
        "smb2",
        "snmp",
        "ldap",
        "diameter",
        "ncp",
        "rpc",
        "afp",
        "gtp",
        "gtpv2",
        "scsi",
        "dcerpc",
        "fc",
        "camel",
    ],
    display_filter: str | None = None,
) -> Any:
    """Service response time statistics — min/max/avg latency per request type.

    Measures the elapsed time between a protocol request and its response.
    Useful for detecting slow servers, network congestion, or anomalous
    response-time patterns in application protocols.
    """
    spec = _SRT_MAP.get(protocol)
    if spec is None:
        raise ValueError(f"unknown protocol {protocol!r}")
    return _tap(alias, spec, display_filter)


@mcp.tool()
def response_time_delay(
    alias: str,
    protocol: Literal["h225_ras", "megaco", "mgcp", "radius"],
    display_filter: str | None = None,
) -> Any:
    """Response time delay statistics for signalling protocols.

    Measures per-transaction round-trip delay:
      h225_ras — H.225 RAS registration/admission delays
      megaco   — MEGACO/H.248 gateway control delays
      mgcp     — MGCP gateway control delays
      radius   — RADIUS authentication/accounting delays
    """
    spec = _RTD_MAP.get(protocol)
    if spec is None:
        raise ValueError(f"unknown protocol {protocol!r}")
    return _tap(alias, spec, display_filter)


@mcp.tool()
def sequence_diagram(
    alias: str,
    type: Literal["any", "tcp", "icmp", "icmpv6"] = "tcp",
    display_filter: str | None = None,
) -> Any:
    """Flow sequence diagram data for visualising packet exchanges.

    Returns time-ordered node and flow entries suitable for rendering
    a sequence diagram (equivalent to Wireshark's Flow Graph window).
      any     — all flows
      tcp     — TCP flows (handshakes, data, teardowns)
      icmp    — ICMP echo request/reply flows
      icmpv6  — ICMPv6 flows
    """
    spec = _SEQA_MAP.get(type)
    if spec is None:
        raise ValueError(f"unknown type {type!r}")
    return _tap(alias, spec, display_filter)


# ===========================================================================
# MEDIA & VOIP
# ===========================================================================


@mcp.tool()
def voip_calls(
    alias: str,
    display_filter: str | None = None,
) -> Any:
    """VoIP call list with state, duration, and participant addresses.

    Detects SIP, H.323, MGCP, and SKINNY calls in the capture and
    reconstructs the call flow from signalling messages.
    """
    return _tap(alias, "voip-calls", display_filter)


@mcp.tool()
def rtp_streams(
    alias: str,
    stream_spec: str | None = None,
    display_filter: str | None = None,
) -> Any:
    """RTP stream inventory and per-stream quality analysis.

    Without `stream_spec` — returns all RTP streams with SSRC, codec,
    packet count, and timing.

    With `stream_spec` — returns jitter, packet loss, and sequence error
    statistics for one stream. Format:
      `<src_ip>_<src_port>_<dst_ip>_<dst_port>_<ssrc>`
    e.g. `200.57.7.195_9762_200.57.7.196_26946_0xd2bd4e3e`
    """
    if stream_spec:
        return _tap(alias, f"rtp-analyse:{stream_spec}", display_filter)
    return _tap(alias, "rtp-streams", display_filter)


@mcp.tool()
def multicast_streams(
    alias: str,
    display_filter: str | None = None,
) -> Any:
    """UDP multicast stream statistics.

    Returns per-stream packet counts, byte rates, and burst statistics
    for all UDP multicast flows in the capture.
    """
    return _tap(alias, "multicast", display_filter)


# ===========================================================================
# EXPORT & OBJECTS
# ===========================================================================

_EO_TYPES = Literal["http", "dicom", "smb", "tftp", "imf", "ftp-data"]


@mcp.tool()
def export_objects(
    alias: str,
    type: _EO_TYPES = "http",
    skip: int = 0,
    limit: int = 50,
) -> dict:
    """List exportable objects of the given type found in the capture.

    Each returned object includes a `_download` token that can be passed to
    `download_object` to retrieve the raw content. Supported types:
    http, dicom, smb, tftp, imf, ftp-data.

    The PCAP is scanned only on the first call for a given type; subsequent
    pages are served from cache.
    """
    spec = f"eo:{type}"
    items = _tap_cached(alias, spec, None, "objects")
    total = len(items)
    page = items[skip : skip + limit] if limit else items[skip:]
    return {
        "type": type,
        "total": total,
        "skip": skip,
        "limit": limit,
        "truncated": (skip + len(page)) < total,
        "objects": page,
    }


@mcp.tool()
def download_object(alias: str, token: str) -> dict:
    """Download the raw content of an exportable object, TLS secrets, or RTP audio.

    Tokens come from:
      `export_objects`  → `"eo:http_0"`, `"eo:imf_0"`, etc.
      TLS session keys  → `"ssl-secrets"` (NSS Key Log format, if embedded)
      RTP audio stream  → `"rtp:<src_ip>_<src_port>_<dst_ip>_<dst_port>_<ssrc>"`

    Content is returned base64-encoded under the `data` key along with
    the MIME type and original filename where available.
    """
    sess = pool.get(alias)
    return sess.call("download", {"token": token})


# ===========================================================================
# ESCAPE HATCH
# ===========================================================================


@mcp.tool()
def tap(
    alias: str,
    specs: list[str],
    filter: str | None = None,
    skip: int = 0,
    limit: int = 100,
) -> dict:
    """Run one or more sharkd statistics taps in a single PCAP scan.

    `specs`   — tap identifiers from server_info, e.g.
                ["expert", "conv:TCP", "stat:dns", "srt:smb"]
    `filter`  — global display filter applied to all taps (sharkd supports
                only one filter per tap call; per-tap filters are iograph-only)
    `skip` / `limit` — pagination applied to each tap's flat list result

    Up to 16 specs per call (sharkd limit). Results are cached after the
    first scan; paginated follow-up calls are served from memory.
    Use `server_info` to discover all valid tap identifiers.
    """
    if not specs:
        raise ValueError("specs must be non-empty")
    if len(specs) > 16:
        raise ValueError("sharkd supports at most 16 simultaneous taps")

    key = ("raw_tap", alias, tuple(specs), filter or "")
    cached = _cache_get(key)

    if cached is None:
        params: dict[str, Any] = {}
        for i, spec in enumerate(specs):
            params[f"tap{i}"] = spec
        if filter:
            params["filter"] = filter
        sess = pool.get(alias)
        result = sess.call("tap", params)
        cached = result.get("taps", []) if isinstance(result, dict) else []
        _cache_set(key, cached)

    out: list[dict] = []
    for tap_entry in cached:
        # shallow copy — never mutate the cache
        entry = dict(tap_entry)
        list_key = _detect_list_key(entry)
        if list_key:
            items: list = entry[list_key]
            total = len(items)
            page = items[skip : skip + limit] if limit else items[skip:]
            entry[list_key] = page
            entry["total"] = total
            entry["skip"] = skip
            entry["limit"] = limit
            entry["truncated"] = (skip + len(page)) < total
        out.append(entry)

    return {"taps": out}


def main() -> int:
    mcp.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
