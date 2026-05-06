"""
analysis/sessions.py — SessionTracker: groups packets into bidirectional flows.

A session (flow) is identified by the canonical 5-tuple:
    sorted((src_ip, dst_ip)), sorted((src_port, dst_port)), protocol

This ensures that both directions of a TCP connection share one session entry.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Tuple

from utils.logger import get_logger

logger = get_logger(__name__)

SessionKey = Tuple[tuple, tuple, str]  # (ip_pair, port_pair, protocol)


@dataclass
class Session:
    """Represents an active network flow (bidirectional).

    Attributes:
        key:          Canonical 5-tuple key.
        src_ip:       IP that initiated the first seen packet.
        dst_ip:       Destination IP.
        src_port:     Source port.
        dst_port:     Destination port.
        protocol:     Layer-4/7 protocol string.
        start_time:   Unix epoch of first packet.
        last_seen:    Unix epoch of most recent packet.
        packet_count: Total packets in this flow.
        byte_count:   Total bytes in this flow.
        state:        Textual state ("ACTIVE", "CLOSED", "IDLE").
    """

    key: SessionKey
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: float
    last_seen: float
    packet_count: int = 0
    byte_count: int = 0
    state: str = "ACTIVE"

    @property
    def duration_seconds(self) -> float:
        """Elapsed time since session start."""
        return self.last_seen - self.start_time

    def to_dict(self) -> dict:
        """Serialise session to a plain dict for UI rendering."""
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "packets": self.packet_count,
            "bytes": self.byte_count,
            "duration_s": round(self.duration_seconds, 2),
            "state": self.state,
            "start_time": self.start_time,
            "last_seen": self.last_seen,
        }


class SessionTracker:
    """Groups parsed packets into bidirectional flow sessions.

    Sessions are considered IDLE after ``idle_timeout_seconds`` without
    a new packet. Idle sessions are cleaned up periodically.

    Example::

        tracker = SessionTracker()
        tracker.update(record)
        sessions = tracker.get_sessions()
    """

    _IDLE_TIMEOUT = 120.0    # seconds of inactivity before marking IDLE
    _CLEANUP_INTERVAL = 30.0  # how often to sweep idle sessions

    def __init__(self) -> None:
        """Initialise the session tracker."""
        self._lock = threading.RLock()
        self._sessions: Dict[SessionKey, Session] = {}
        self._last_cleanup: float = time.time()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def update(self, record: object) -> None:
        """Update or create a session for the given packet record.

        Args:
            record: A :class:`~processing.models.PacketRecord`.
        """
        key: SessionKey = record.session_key()  # type: ignore[attr-defined]
        now = time.time()

        with self._lock:
            if key in self._sessions:
                sess = self._sessions[key]
                sess.packet_count += 1
                sess.byte_count += record.size  # type: ignore[attr-defined]
                sess.last_seen = now
                sess.state = "ACTIVE"
            else:
                self._sessions[key] = Session(
                    key=key,
                    src_ip=record.src_ip,  # type: ignore[attr-defined]
                    dst_ip=record.dst_ip,  # type: ignore[attr-defined]
                    src_port=record.src_port,  # type: ignore[attr-defined]
                    dst_port=record.dst_port,  # type: ignore[attr-defined]
                    protocol=record.protocol,  # type: ignore[attr-defined]
                    start_time=now,
                    last_seen=now,
                    packet_count=1,
                    byte_count=record.size,  # type: ignore[attr-defined]
                )

            # Periodic cleanup of idle sessions
            if now - self._last_cleanup > self._CLEANUP_INTERVAL:
                self._cleanup(now)
                self._last_cleanup = now

    def get_sessions(self) -> Dict[SessionKey, Session]:
        """Return a shallow copy of the current session map.

        Returns:
            Dict mapping session keys to :class:`Session` objects.
        """
        with self._lock:
            return dict(self._sessions)

    def get_active_count(self) -> int:
        """Return the number of currently active sessions.

        Returns:
            Integer count.
        """
        with self._lock:
            return sum(1 for s in self._sessions.values() if s.state == "ACTIVE")

    def reset(self) -> None:
        """Clear all tracked sessions."""
        with self._lock:
            self._sessions.clear()
        logger.info("SessionTracker reset.")

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _cleanup(self, now: float) -> None:
        """Mark stale sessions as IDLE and remove very old ones."""
        to_delete = []
        for key, sess in self._sessions.items():
            idle_for = now - sess.last_seen
            if idle_for > self._IDLE_TIMEOUT * 2:
                to_delete.append(key)
            elif idle_for > self._IDLE_TIMEOUT:
                sess.state = "IDLE"

        for key in to_delete:
            del self._sessions[key]

        if to_delete:
            logger.debug("Session cleanup removed %d stale sessions.", len(to_delete))
