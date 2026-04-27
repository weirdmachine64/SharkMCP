# SharkMCP

An [MCP](https://modelcontextprotocol.io) server that exposes [sharkd](https://wiki.wireshark.org/Development/sharkd) — Wireshark's programmatic interface — as a set of tools for AI assistants. Load PCAP/PCAPNG files and analyse them with natural language.

## Requirements

- Python 3.10+
- Wireshark (provides `sharkd`)

## Installation

```bash
git clone https://github.com/weirdmachine64/sharkmcp.git
cd sharkmcp
pip install -e .
```

Or run directly from the repo without installing:

```bash
uvx --from git+https://github.com/weirdmachine64/sharkmcp sharkmcp
```

## Configuration

Add to your `.mcp.json`:

```json
{
  "mcpServers": {
    "sharkmcp": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/weirdmachine64/sharkmcp", "sharkmcp"],
      "env": {
        "SHARKMCP_TIMEOUT": "300"
      }
    }
  }
}
```

| Env var | Default | Description |
|---------|---------|-------------|
| `SHARKMCP_SHARKD_BIN` | `sharkd` | Path to sharkd binary |
| `SHARKMCP_TIMEOUT` | `300` | Per-request timeout in seconds |

## Tools

Each loaded PCAP gets a dedicated sharkd subprocess. Results from expensive scans (conversations, expert info, export objects) are cached in memory so paginated follow-up calls are served without re-scanning.

### Session
| Tool | Description |
|------|-------------|
| `load_pcap(path, alias?)` | Load a PCAP/PCAPNG file |
| `list_pcaps()` | List all loaded PCAPs |
| `unload_pcap(alias)` | Terminate session and free memory |

### Overview
| Tool | Description |
|------|-------------|
| `pcap_summary(alias)` | Frame count, duration, file size, protocols seen |
| `server_info(alias)` | All available tap types, follow protocols, field types |

### Packet Inspection
| Tool | Description |
|------|-------------|
| `list_packets(alias, filter?, columns?, refs?)` | Paginated frame list with display filter |
| `packet_detail(alias, frame, include_bytes?, include_hidden?)` | Full protocol tree for one frame |
| `extract_fields(alias, fields, filter?)` | Extract arbitrary fields per packet as a table |

### Utilities
| Tool | Description |
|------|-------------|
| `validate(alias, filter?, field?)` | Validate a display filter and/or field name |
| `complete(alias, field?, pref?)` | Autocomplete field or preference names by prefix |
| `get_preference(alias, preference?)` | Read dissector preferences |
| `set_preference(alias, name, value)` | Set a dissector preference for this session |
| `set_frame_comment(alias, frame, comment)` | Annotate a frame (session-scoped) |

### Traffic Structure
| Tool | Description |
|------|-------------|
| `protocol_hierarchy(alias, filter?)` | Nested protocol tree with frame/byte counts |
| `io_stats(alias, interval_ms?, filter?)` | Per-interval frame and byte counts |
| `iograph(alias, graphs, interval_ms?, filters?)` | Multi-line traffic graph; supports `packets`, `bytes`, `bits`, `sum:<field>`, `avg:<field>`, `min:<field>`, `max:<field>`, `load:<field>`, `frames:<field>` |
| `follow_stream(alias, protocol, filter)` | Reassemble a stream (`tcp`, `udp`, `tls`, `http`, `http2`, `quic`, `sip`, `dccp`, `websocket`) |

### Conversations & Topology
| Tool | Description |
|------|-------------|
| `conversations(alias, type?, sort_by?)` | Conversation table — bytes/frames per peer pair |
| `endpoints(alias, type?, sort_by?)` | Endpoint table — tx/rx per host |

Supported layer types for both: `tcp`, `udp`, `ip`, `ipv6`, `eth`, `sctp`, `dccp`, `mptcp`, `wifi`, `bluetooth`, `zigbee`, `fc`, `fddi`, `usb`, and more.

### Protocol Statistics
| Tool | Description |
|------|-------------|
| `expert_info(alias, filter?)` | Per-frame anomaly detection — errors, warnings, notes, chats |
| `protocol_stats(alias, protocol)` | Aggregate stats for `dns`, `http`, `http_requests`, `http_server`, `sip`, `dhcp`, `h225`, `http2`, `rtsp` |
| `service_response_time(alias, protocol)` | Request/response latency for `smb`, `smb2`, `snmp`, `ldap`, `diameter`, `rpc`, `gtp`, and more |
| `response_time_delay(alias, protocol)` | Round-trip delay for `radius`, `h225_ras`, `megaco`, `mgcp` |
| `sequence_diagram(alias, type?)` | Flow diagram data for `tcp`, `icmp`, `icmpv6`, `any` |

### Media & VoIP
| Tool | Description |
|------|-------------|
| `voip_calls(alias, filter?)` | SIP/H.323 call list with state and participants |
| `rtp_streams(alias, stream_spec?)` | RTP stream inventory; pass `stream_spec` for per-stream jitter/loss |
| `multicast_streams(alias, filter?)` | UDP multicast stream statistics |

### Export & Objects
| Tool | Description |
|------|-------------|
| `export_objects(alias, type?)` | List extractable objects (`http`, `imf`, `smb`, `tftp`, `dicom`, `ftp-data`) |
| `download_object(alias, token)` | Download an object, TLS session keys (`ssl-secrets`), or RTP audio (`rtp:<spec>`) as base64 |

### Escape Hatch
| Tool | Description |
|------|-------------|
| `tap(alias, specs, filter?, skip?, limit?)` | Run any sharkd tap directly — up to 16 specs in one PCAP scan. Use `server_info` to discover valid identifiers. |

## Example

```
> load_pcap("/captures/traffic.pcap", alias="traffic")
> protocol_hierarchy("traffic")
> expert_info("traffic", limit=20)
> conversations("traffic", type="tcp", sort_by="bytes")
> extract_fields("traffic", ["dns.qry.name", "dns.a"], filter="dns")
> follow_stream("traffic", "http", "tcp.stream eq 0")
> export_objects("traffic", type="http")
> download_object("traffic", "eo:http_0")
```

## Architecture

```
AI assistant
     │  MCP (stdio)
     ▼
 SharkMCP server
     │  JSON-RPC 2.0 (stdin/stdout)
     ├─ sharkd [pcap-1]
     ├─ sharkd [pcap-2]
     └─ sharkd [pcap-N]
```

One `sharkd` subprocess per loaded PCAP. Sessions are isolated — concurrent queries on different aliases never block each other.
