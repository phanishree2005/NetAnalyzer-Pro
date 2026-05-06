"""
analysis/stats.py — StatisticsEngine: real-time throughput and protocol metrics.

Uses a sliding time window to compute packets/sec and bytes/sec. All public
methods are thread-safe via a single reentrant lock.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, Deque, Tuple

from utils.config import StatsConfig, DEFAULT_CONFIG
from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class StatsSnapshot:
    """Immutable snapshot of statistics at a point in time.

    Attributes:
        timestamp:         When the snapshot was taken (Unix epoch).
        total_packets:     All-time packet count.
        total_bytes:       All-time byte count.
        packets_per_sec:   Packets/sec averaged over the sliding window.
        bytes_per_sec:     Bytes/sec averaged over the sliding window.
        protocol_counts:   Per-protocol all-time packet counts.
        top_talkers:       Top 5 source IPs by packet count.
    """

    timestamp: float
    total_packets: int
    total_bytes: int
    packets_per_sec: float
    bytes_per_sec: float
    protocol_counts: Dict[str, int] = field(default_factory=dict)
    top_talkers: Dict[str, int] = field(default_factory=dict)


class StatisticsEngine:
    """Accumulates packet metrics and provides thread-safe snapshots.

    Feed packet records via :meth:`record_packet`; retrieve current
    statistics via :meth:`get_snapshot`.

    Example::

        engine = StatisticsEngine()
        engine.record_packet(record)
        snap = engine.get_snapshot()
        print(snap.packets_per_sec)
    """

    def __init__(self, config: StatsConfig | None = None) -> None:
        """Initialise the statistics engine.

        Args:
            config: :class:`StatsConfig`; defaults to global config.
        """
        self._cfg = config or DEFAULT_CONFIG.stats
        self._lock = threading.RLock()

        # All-time counters
        self._total_packets: int = 0
        self._total_bytes: int = 0
        self._protocol_counts: Dict[str, int] = defaultdict(int)
        self._src_ip_counts: Dict[str, int] = defaultdict(int)

        # Sliding window — (timestamp, bytes) tuples
        self._window: Deque[Tuple[float, int]] = deque()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record_packet(self, record: object) -> None:
        """Ingest a parsed packet record.

        Args:
            record: A :class:`~processing.models.PacketRecord` instance.
        """
        with self._lock:
            self._total_packets += 1
            self._total_bytes += record.size  # type: ignore[attr-defined]
            self._protocol_counts[record.protocol] += 1  # type: ignore[attr-defined]
            if record.src_ip:  # type: ignore[attr-defined]
                self._src_ip_counts[record.src_ip] += 1  # type: ignore[attr-defined]

            now = time.time()
            self._window.append((now, record.size))  # type: ignore[attr-defined]
            self._evict_old(now)

    def get_snapshot(self) -> StatsSnapshot:
        """Return a thread-safe snapshot of current statistics.

        Returns:
            A :class:`StatsSnapshot` instance.
        """
        with self._lock:
            now = time.time()
            self._evict_old(now)

            window_duration = self._cfg.sliding_window_seconds
            pkt_count = len(self._window)
            byte_sum = sum(b for _, b in self._window)

            pps = pkt_count / window_duration if window_duration > 0 else 0.0
            bps = byte_sum / window_duration if window_duration > 0 else 0.0

            # Top 5 talkers
            sorted_talkers = sorted(
                self._src_ip_counts.items(), key=lambda x: x[1], reverse=True
            )[:5]

            return StatsSnapshot(
                timestamp=now,
                total_packets=self._total_packets,
                total_bytes=self._total_bytes,
                packets_per_sec=round(pps, 2),
                bytes_per_sec=round(bps, 2),
                protocol_counts=dict(self._protocol_counts),
                top_talkers=dict(sorted_talkers),
            )

    def reset(self) -> None:
        """Reset all counters and the sliding window."""
        with self._lock:
            self._total_packets = 0
            self._total_bytes = 0
            self._protocol_counts.clear()
            self._src_ip_counts.clear()
            self._window.clear()
        logger.info("StatisticsEngine reset.")

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _evict_old(self, now: float) -> None:
        """Remove entries outside the sliding window.

        Args:
            now: Current time in Unix epoch seconds.
        """
        cutoff = now - self._cfg.sliding_window_seconds
        while self._window and self._window[0][0] < cutoff:
            self._window.popleft()
