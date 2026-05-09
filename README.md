🛡️ NetAnalyzer Pro — Network Protocol Analyzer
A production-grade, Wireshark-inspired network protocol analyzer built in Python.
Real-time packet capture → deep protocol parsing → statistical analysis → live Streamlit dashboard.

🌐 **Live Demo**: [netanalyzer-pro.streamlit.app](https://netanalyzer-pro-9k8pzj7r6l33ch6qtdkhth.streamlit.app/)
*(Note: Use **Simulation Mode (Demo)** in the sidebar when viewing the hosted version)*

📐 Architecture
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
All inter-module communication uses queue.Queue or threading.RLock-protected state.
No shared mutable state without locks. All background threads run as daemon=True.

📁 Project Structure
network_analyzer/
├── capture/
│   ├── sniffer.py          # Scapy-based threaded capture engine
│   ├── simulator.py        # Traffic simulation for hosted/non-root environments
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

✅ Prerequisites
| Requirement | Detail |
| :--- | :--- |
| OS | Windows 10/11, Linux, macOS |
| Python | 3.10 or higher |
| Privileges | Administrator (Windows) or root/sudo (Linux/macOS) — required for raw socket access |
| Npcap (Windows)| Install from npcap.com — required by scapy on Windows |

⚠️ **Windows users**: Install Npcap before running. During installation, check "Install Npcap in WinPcap API-compatible mode".

🚀 Installation
1. Clone the repository
```bash
git clone https://github.com/phanishree2005/NetAnalyzer-Pro.git
cd NetAnalyzer-Pro
```

2. Create and activate a virtual environment
```bash
python -m venv venv
# Windows
venv\Scripts\activate
# Linux / macOS
source venv/bin/activate
```

3. Install dependencies
```bash
pip install -r requirements.txt
```

▶️ How to Run
UI Mode (default — launches Streamlit dashboard)
```bash
# Windows — run as Administrator
python main.py

# With a specific interface and BPF filter
python main.py --interface "Wi-Fi" --filter "tcp"
```
Open your browser at `http://localhost:8501`

CLI / Headless Mode
```bash
# 60-second headless capture on eth0
python main.py --cli --interface eth0 --duration 60
```

🌟 Feature List
- **Live Capture**: Scapy-backed AsyncSniffer in a daemon thread.
- **Simulation Mode**: Integrated traffic generator for portfolio demos and restricted environments.
- **Deep Protocol Parsing**: Extracts detailed metadata from TCP, UDP, ICMP, DNS, and HTTP.
- **Statistical Analysis**: Sliding 60-second window for throughput and top-talkers.
- **Anomaly Detection**: Real-time alerts for traffic spikes, repeated hits, and port scans.
- **Session Tracking**: Bidirectional flow grouping by canonical 5-tuple.
- **Interactive Dashboard**: Modern, SaaS-inspired UI with Plotly charts and color-coded streams.

🔧 Configuration
All tunable values live in `utils/config.py` — no magic numbers elsewhere.

📄 License
MIT — free to use, modify, and distribute.

Built as a portfolio project demonstrating: threaded Python systems, real-time data pipelines, protocol parsing, and modern Streamlit UI design.
