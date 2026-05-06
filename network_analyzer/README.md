# 🛡️ NetAnalyzer Pro — Network Protocol Analyzer

A **production-grade, Wireshark-inspired** network protocol analyzer built in Python.  
Real-time packet capture → deep protocol parsing → statistical analysis → live Streamlit dashboard.

---

## 📐 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    CAPTURE LAYER                            │
│  [Network Interface]  ──→  [PacketSniffer Thread]           │
│                               │  raw_queue (Queue)          │
└───────────────────────────────┼─────────────────────────────┘
                                ▼
┌─────────────────────────────────────────────────────────────┐
│                   PROCESSING LAYER                          │
│  [PacketParser Thread]  Chain-of-Responsibility dispatch    │
│  DNS → HTTP → ICMP → TCP → UDP → Fallback                  │
│                               │  parsed_queue (Queue)       │
└───────────────────────────────┼─────────────────────────────┘
                                ▼
         ┌──────────────────────┼───────────────────────┐
         ▼                      ▼                       ▼
┌─────────────────┐  ┌──────────────────┐  ┌───────────────────┐
│ StatisticsEngine│  │ AnomalyDetector  │  │  SessionTracker   │
│ (sliding window)│  │ spike/scan/hits  │  │  5-tuple flows    │
└────────┬────────┘  └────────┬─────────┘  └────────┬──────────┘
         │                    │                      │
         └──────────────┬─────┘──────────────────────┘
                        ▼
         ┌──────────────────────────────┐
         │   PacketBuffer (circular)    │
         │   DataStore  (SQLite opt.)   │
         └──────────────┬───────────────┘
                        ▼
         ┌──────────────────────────────┐
         │     Streamlit UI (1s poll)   │
         │  KPIs │ Table │ Charts │ Alerts│
         └──────────────────────────────┘
```

All inter-module communication uses `queue.Queue` or `threading.RLock`-protected state.  
No shared mutable state without locks. All background threads run as `daemon=True`.

---

## 📁 Project Structure

```
network_analyzer/
├── capture/
│   ├── sniffer.py          # Scapy-based threaded capture engine
│   └── interface.py        # Interface discovery (scapy → psutil → socket)
├── processing/
│   ├── models.py           # PacketRecord frozen dataclass
│   ├── parser.py           # Chain-of-Responsibility dispatcher
│   └── protocols/
│       ├── tcp.py          # TCP + HTTP-on-80 detection
│       ├── udp.py          # UDP parser
│       ├── icmp.py         # ICMP type/code decoding
│       ├── dns.py          # DNS query/response parser
│       └── http.py         # Payload-based HTTP parser
├── analysis/
│   ├── stats.py            # Sliding-window throughput + top-talkers
│   ├── anomaly.py          # Spike / repeated-hit / port-scan detection
│   └── sessions.py         # Bidirectional flow session tracking
├── data/
│   ├── buffer.py           # Thread-safe circular buffer (deque)
│   └── store.py            # Batched SQLite + CSV/JSON export
├── ui/
│   ├── dashboard.py        # Streamlit app entry point
│   ├── filters.py          # Centralized filter state (AND logic)
│   └── components/
│       ├── packet_table.py # Color-coded protocol table
│       ├── charts.py       # Plotly pie + dual-axis time-series
│       └── alerts_panel.py # Severity-coded alert feed
├── utils/
│   ├── config.py           # All thresholds/limits (no magic numbers)
│   └── logger.py           # Rotating file + stream handler factory
├── main.py                 # Entrypoint: UI mode or --cli headless mode
├── requirements.txt
└── README.md
```

---

## ✅ Prerequisites

| Requirement | Detail |
|---|---|
| **OS** | Windows 10/11, Linux, macOS |
| **Python** | 3.10 or higher |
| **Privileges** | **Administrator** (Windows) or **root/sudo** (Linux/macOS) — required for raw socket access |
| **Npcap** (Windows) | Install from [npcap.com](https://npcap.com/) — required by scapy on Windows |

> ⚠️ **Windows users**: Install [Npcap](https://npcap.com/) before running. During installation, check **"Install Npcap in WinPcap API-compatible mode"**.

---

## 🚀 Installation

```bash
# 1. Clone the repository
git clone https://github.com/your-username/network-analyzer.git
cd network-analyzer/network_analyzer

# 2. Create and activate a virtual environment
python -m venv venv

# Windows
venv\Scripts\activate

# Linux / macOS
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

---

## ▶️ How to Run

### UI Mode (default — launches Streamlit dashboard)

```bash
# Windows — run as Administrator
python main.py

# With a specific interface and BPF filter
python main.py --interface "Wi-Fi" --filter "tcp"

# Direct streamlit launch (alternative)
streamlit run ui/dashboard.py
```

Open your browser at **http://localhost:8501**

### CLI / Headless Mode

```bash
# 60-second headless capture on eth0
python main.py --cli --interface eth0 --duration 60

# With SQLite persistence
python main.py --cli --interface eth0 --sqlite --db-path capture.db

# All options
python main.py --help
```

---

## 🌟 Feature List

### Live Capture
- Scapy-backed `AsyncSniffer` in a daemon thread — never blocks the UI
- BPF filter input (e.g. `tcp port 443`, `udp`, `icmp`)
- Interface auto-detection with dropdown selector
- Start / Stop / Clear controls

### Deep Protocol Parsing
| Protocol | What's extracted |
|---|---|
| **TCP** | Flags (SYN/ACK/FIN…), ports, payload preview |
| **UDP** | Ports, payload preview |
| **ICMP** | Type name (Echo Request/Reply, TTL Exceeded…) |
| **DNS** | Query name, response records (A/AAAA/CNAME…) |
| **HTTP** | First request/response line, method detection |

### Statistical Analysis
- **Sliding 60-second window** for packets/sec and bytes/sec
- All-time total counters and per-protocol breakdown
- Top-5 talkers by packet count

### Anomaly Detection
| Type | Default Threshold | Alert Level |
|---|---|---|
| Traffic spike | > 500 pkt/sec | 🚨 CRITICAL |
| Repeated hits | > 100 hits / 10s from one IP | ⚠️ WARN |
| Port scan | > 20 distinct ports / 5s | 🚨 CRITICAL |

Thresholds are adjustable from the sidebar in real time.

### Session Tracking
- Bidirectional flows grouped by canonical 5-tuple
- Tracks: start time, last seen, packet count, byte count, state (ACTIVE / IDLE)
- Automatic cleanup of stale sessions

### Dashboard
- **4 tabs**: Packets · Charts · Alerts · Sessions
- **KPI cards**: total packets, pps, KB/s, active sessions, alert count
- **Protocol pie chart** (Plotly donut)
- **Dual-axis time-series** (pps + KB/s)
- **Color-coded packet table** (per-protocol row colors)
- **1-second auto-refresh** (configurable 0.5–5s)
- Full **dark mode** (custom CSS + Streamlit theme)

### Filtering (AND logic)
- Protocol multiselect
- Source IP / Destination IP substring match
- Port number (src OR dst)
- Free-text payload search

### Export
- **CSV export** — one row per packet, headers auto-generated
- **JSON export** — array of packet objects
- Both respect active filters

---

## 🔧 Configuration

All tunable values live in `utils/config.py` — **no magic numbers** elsewhere:

```python
# Example overrides
from utils.config import DEFAULT_CONFIG

DEFAULT_CONFIG.buffer.max_capacity = 20_000      # bigger buffer
DEFAULT_CONFIG.anomaly.packets_per_sec_spike = 1000  # raise spike threshold
DEFAULT_CONFIG.store.enabled = True               # turn on SQLite
```

---

## 🔌 How to Add a New Protocol Parser

1. Create `processing/protocols/myprotocol.py`:

```python
from processing.models import PacketRecord

class MyProtocolParser:
    def can_handle(self, packet) -> bool:
        from scapy.layers.xxx import MyLayer
        return packet.haslayer(MyLayer)

    def parse(self, packet) -> PacketRecord:
        layer = packet[MyLayer]
        return PacketRecord(
            timestamp=PacketRecord.make_timestamp(),
            src_ip=..., dst_ip=...,
            src_port=0, dst_port=0,
            protocol="MYPROTO",
            size=len(packet),
            ttl=0, flags="",
            payload_summary="...",
            raw_summary=packet.summary(),
        )
```

2. Register it in `processing/parser.py` — add an instance to `_PARSER_CHAIN` **before** the fallback:

```python
from processing.protocols.myprotocol import MyProtocolParser

class PacketParser:
    _PARSER_CHAIN = [
        DNSParser(),
        HTTPParser(),
        ICMPParser(),
        MyProtocolParser(),   # ← add here
        TCPParser(),
        UDPParser(),
        _FallbackParser(),
    ]
```

3. Optionally add a color to `ui/components/packet_table.py` → `_PROTO_COLORS`.

That's it — no other files need touching.

---

## ⚠️ Known Limitations

| Limitation | Detail |
|---|---|
| **Root required** | Raw socket access mandates admin/root. There is no workaround. |
| **Windows + Npcap** | Scapy requires Npcap on Windows; WinPcap is end-of-life and unsupported. |
| **No TLS decryption** | HTTPS payload shows as encrypted bytes. TLS 1.3 session keys would be needed. |
| **IPv6 partial** | IPv6 headers are captured but not deeply parsed (shown as OTHER). |
| **No packet injection** | This is a read-only analyzer. No packet crafting or replay. |
| **Streamlit threading** | `st.session_state` is per-browser-tab; multiple tabs = separate capture sessions. |
| **High-speed links** | At > ~50k pkt/sec the Python GIL may cause parser lag; use BPF filters to reduce load. |

---

## 📄 License

MIT — free to use, modify, and distribute.

---

*Built as a portfolio project demonstrating: threaded Python systems, real-time data pipelines, protocol parsing, and modern Streamlit UI design.*
