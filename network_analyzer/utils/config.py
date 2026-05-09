"""
utils/config.py — Centralized configuration for the Network Protocol Analyzer.

All tunable constants live here. No magic numbers elsewhere in the codebase.
"""

from dataclasses import dataclass, field
from typing import List


@dataclass
class CaptureConfig:
    """Configuration for the packet capture layer."""
    default_interface: str = ""
    default_bpf_filter: str = ""
    raw_queue_maxsize: int = 50_000      # max raw packets queued before drop
    snap_length: int = 65_535            # bytes captured per packet
    simulation_mode: bool = False        # if True, generate fake traffic


@dataclass
class BufferConfig:
    """Configuration for the in-memory packet buffer."""
    max_capacity: int = 10_000           # circular buffer max packets


@dataclass
class StatsConfig:
    """Configuration for the statistics engine."""
    sliding_window_seconds: int = 60     # width of throughput sliding window
    snapshot_interval_seconds: float = 1.0


@dataclass
class AnomalyConfig:
    """Thresholds for the anomaly detection engine."""
    packets_per_sec_spike: int = 500     # alert if pps exceeds this
    repeated_hit_count: int = 100        # alert if src_ip hits > N in window
    repeated_hit_window_seconds: int = 10
    port_scan_port_count: int = 20       # N distinct ports from one IP → scan
    port_scan_window_seconds: int = 5


@dataclass
class StoreConfig:
    """Configuration for the SQLite persistence layer."""
    enabled: bool = False
    db_path: str = "packets.db"
    batch_size: int = 200                # write every N records
    batch_interval_seconds: float = 5.0  # or every T seconds


@dataclass
class UIConfig:
    """Configuration for the Streamlit dashboard."""
    refresh_interval_seconds: float = 1.0
    max_table_rows: int = 200
    dark_mode: bool = True
    default_protocols: List[str] = field(
        default_factory=lambda: ["TCP", "UDP", "ICMP", "DNS", "HTTP", "HTTPS", "ARP", "OTHER"]
    )


@dataclass
class AppConfig:
    """Root application configuration — inject this everywhere."""
    capture: CaptureConfig = field(default_factory=CaptureConfig)
    buffer: BufferConfig = field(default_factory=BufferConfig)
    stats: StatsConfig = field(default_factory=StatsConfig)
    anomaly: AnomalyConfig = field(default_factory=AnomalyConfig)
    store: StoreConfig = field(default_factory=StoreConfig)
    ui: UIConfig = field(default_factory=UIConfig)


# Module-level singleton — import this where needed.
DEFAULT_CONFIG = AppConfig()
