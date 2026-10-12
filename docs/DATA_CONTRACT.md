# Telemetry Contract & Adapters

## Canonical `FlowEvent`

| Field | Type | Meaning |
| :--- | :--- | :--- |
| `timestamp` | ISO 8601 timezone-aware | Event timestamp, stored in UTC |
| `source` | `zeek`, `suricata`, `canonical`, `simulator` | Source adapter |
| `uid` | string or null | Sensor-reported record ID |
| `src_ip`, `dst_ip` | IPv4 or IPv6 | Connection endpoints |
| `src_port`, `dst_port` | integer 0–65535 | Transport ports; zero for protocols without ports |
| `proto` | tcp, udp, icmp, other | Normalized protocol |
| `duration` | float seconds | Elapsed connection time |
| `orig_bytes`, `resp_bytes` | nonnegative integer | Directional bytes |
| `orig_pkts`, `resp_pkts` | nonnegative integer | Directional packet counts |
| `conn_state` | short string | Sensor connection state (lowercased) |
| `label` | `benign`, `anomaly`, or null | Optional offline evaluation label only; never a detection feature |

> For the canonical API, do not send extra fields. API payload validates a 1–250 event batch. File adapters preserve strict bounds and reject malformed data with a source filename/line number.

## Zeek mapping (`conn.log`, JSON output)

| Zeek field | Canonical |
| :--- | :--- |
| `ts` (epoch seconds) | timestamp |
| `id.orig_h`, `id.resp_h` | source, destination IP |
| `id.orig_p`, `id.resp_p` | source, destination port |
| `orig_bytes`, `resp_bytes` | directional bytes |
| `orig_pkts`, `resp_pkts` | directional packet counts |
| `duration`, `proto`, `conn_state`, `uid` | equivalent canonical fields |

This adapter is for **JSON Zeek connection logs**, not Zeek's default tab-separated/ASCII `conn.log` format. Missing numeric counters and `-` are interpreted as zero, which is an approximation and should be interpreted with that context.

## Suricata mapping (EVE JSON)

Only `event_type: "flow"` records are processed. All other EVE event types are ignored. `src_ip`/`dest_ip`, ports, `flow_id` and `proto` are taken from the EVE envelope. `flow.bytes_toserver`, `flow.bytes_toclient`, `pkts_toserver`, `pkts_toclient`, `flow.age` and `flow.state` are mapped to the canonical schema.

**Important:** The meaning and direction of counters depend on sensor configuration. Validate both adapters against a known capture before combining sources to train a model. Never silently treat unrelated Zeek and Suricata states as identical.

## Feature definitions

The v1 model includes logs of duration, directional bytes, directional packets, bytes/second and bytes/packet; response fraction; numeric destination port and a well-known-port indicator; one-hot protocol and connection state. It deliberately excludes timestamp, IP address, source ID and provided labels to reduce trivial identifier and label leakage.

## Data privacy and provenance

- **Public sample files are fabricated** and contain documentation-safe addresses.
- Own-network logs may identify endpoints or users; apply access control and retention limits.
- Do not upload internal IP inventories, PCAPs, credentials or user traffic without authorization.
- Real-world training requires explicit provenance, representative benign calibration and independent validation periods.
