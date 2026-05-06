"""
analysis/anomaly.py — AnomalyDetector: spike, repeated-hit, and port-scan detection.

Emits Alert objects consumed by the UI alerts panel and (optionally) the logger.
All state is protected by a reentrant lock.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Deque, Dict, List, Tuple

from utils.config import AnomalyConfig, DEFAULT_CONFIG
from utils.logger import get_logger

logger = get_logger(__name__)


class AlertLevel(str, Enum):
    """Severity levels for anomaly alerts."""
    INFO = "INFO"
    WARN = "WARN"
    CRITICAL = "CRITICAL"


@dataclass
class Alert:
    """Represents a single anomaly detection event.

    Attributes:
        level:     Severity of the alert.
        message:   Human-readable description.
        timestamp: Unix epoch when the alert was raised.
        src_ip:    Source IP that triggered the alert (may be empty).
    """
    level: AlertLevel
    message: str
    timestamp: float
    src_ip: str = ""

    def to_dict(self) -> dict:
        """Serialise to plain dict for UI rendering."""
        return {
            "level": self.level.value,
            "message": self.message,
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
        }


class AnomalyDetector:
    """Detects traffic anomalies and emits Alert objects.

    Three detection strategies:
    1. **Spike detection** — pps exceeds a configurable threshold.
    2. **Repeated-hit detection** — single src_ip sends > N packets in T sec.
    3. **Port-scan detection** — single src_ip hits > N distinct dst_ports in T sec.

    Example::

        detector = AnomalyDetector()
        detector.analyze(record)
        alerts = detector.get_alerts(clear=True)
    """

    def __init__(self, config: AnomalyConfig | None = None) -> None:
        """Initialise the detector.

        Args:
            config: :class:`AnomalyConfig`; defaults to global config.
        """
        self._cfg = config or DEFAULT_CONFIG.anomaly
        self._lock = threading.RLock()

        # Sliding window for PPS spike detection: list of timestamps
        self._pkt_timestamps: Deque[float] = deque()

        # Per-IP hit tracking: ip → deque of timestamps
        self._ip_hits: Dict[str, Deque[float]] = defaultdict(deque)

        # Per-IP port tracking: ip → deque of (timestamp, dst_port)
        self._ip_ports: Dict[str, Deque[Tuple[float, int]]] = defaultdict(deque)

        # Alert buffer
        self._alerts: List[Alert] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, record: object) -> None:
        """Analyse one parsed packet and raise alerts as needed.

        Args:
            record: A :class:`~processing.models.PacketRecord`.
        """
        with self._lock:
            now = time.time()
            src_ip: str = record.src_ip  # type: ignore[attr-defined]
            dst_port: int = record.dst_port  # type: ignore[attr-defined]

            self._check_spike(now)
            if src_ip:
                self._check_repeated_hits(src_ip, now)
                if dst_port:
                    self._check_port_scan(src_ip, dst_port, now)

    def get_alerts(self, clear: bool = False) -> List[Alert]:
        """Return current alert list.

        Args:
            clear: If ``True``, clear the internal alert buffer after reading.

        Returns:
            List of :class:`Alert` objects, newest last.
        """
        with self._lock:
            result = list(self._alerts)
            if clear:
                self._alerts.clear()
            return result

    def clear_alerts(self) -> None:
        """Discard all buffered alerts."""
        with self._lock:
            self._alerts.clear()

    # ------------------------------------------------------------------
    # Detection strategies
    # ------------------------------------------------------------------

    def _check_spike(self, now: float) -> None:
        """Emit CRITICAL alert if current pps exceeds threshold."""
        cutoff = now - 1.0  # 1-second window for pps
        self._pkt_timestamps.append(now)
        while self._pkt_timestamps and self._pkt_timestamps[0] < cutoff:
            self._pkt_timestamps.popleft()

        pps = len(self._pkt_timestamps)
        if pps >= self._cfg.packets_per_sec_spike:
            self._emit(Alert(
                level=AlertLevel.CRITICAL,
                message=f"Traffic spike: {pps} packets/sec (threshold={self._cfg.packets_per_sec_spike})",
                timestamp=now,
            ))

    def _check_repeated_hits(self, src_ip: str, now: float) -> None:
        """Emit WARN alert if one src_ip exceeds N hits in T seconds."""
        window = self._cfg.repeated_hit_window_seconds
        cutoff = now - window
        dq = self._ip_hits[src_ip]
        dq.append(now)
        while dq and dq[0] < cutoff:
            dq.popleft()

        if len(dq) >= self._cfg.repeated_hit_count:
            self._emit(Alert(
                level=AlertLevel.WARN,
                message=(
                    f"Repeated hits from {src_ip}: "
                    f"{len(dq)} requests in {window}s "
                    f"(threshold={self._cfg.repeated_hit_count})"
                ),
                timestamp=now,
                src_ip=src_ip,
            ))

    def _check_port_scan(self, src_ip: str, dst_port: int, now: float) -> None:
        """Emit CRITICAL alert if one src_ip probes many distinct ports."""
        window = self._cfg.port_scan_window_seconds
        cutoff = now - window
        dq = self._ip_ports[src_ip]
        dq.append((now, dst_port))
        while dq and dq[0][0] < cutoff:
            dq.popleft()

        distinct_ports = {p for _, p in dq}
        if len(distinct_ports) >= self._cfg.port_scan_port_count:
            self._emit(Alert(
                level=AlertLevel.CRITICAL,
                message=(
                    f"Possible port scan from {src_ip}: "
                    f"{len(distinct_ports)} distinct ports in {window}s"
                ),
                timestamp=now,
                src_ip=src_ip,
            ))

    def _emit(self, alert: Alert) -> None:
        """Add alert to buffer; deduplicate within 2s to avoid spam."""
        if self._alerts:
            last = self._alerts[-1]
            if (
                last.level == alert.level
                and last.src_ip == alert.src_ip
                and last.message == alert.message
                and alert.timestamp - last.timestamp < 2.0
            ):
                return  # suppress duplicate

        self._alerts.append(alert)
        # Keep buffer bounded
        if len(self._alerts) > 1000:
            self._alerts = self._alerts[-500:]

        logger.warning("[ALERT %s] %s", alert.level.value, alert.message)
