"""
processing/models.py — Core data model for a parsed network packet.

PacketRecord is the single source of truth that flows through all
downstream layers: analysis engine, buffer, data store, and UI.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass(frozen=True)
class PacketRecord:
    """Immutable, hashable record representing one captured & parsed packet.

    All layers downstream of the parser work exclusively with this type.
    Being frozen means we can safely put it in sets, use it as dict keys,
    and share it across threads without locks.

    Attributes:
        timestamp:       Unix epoch (float) when the packet was captured.
        src_ip:          Source IP address string, or empty for non-IP frames.
        dst_ip:          Destination IP address string.
        src_port:        Source port (TCP/UDP), or 0 for non-port protocols.
        dst_port:        Destination port, or 0.
        protocol:        Human-readable protocol name ("TCP", "UDP", …).
        size:            Total captured packet size in bytes.
        ttl:             IP Time-To-Live value, or 0 if not applicable.
        flags:           TCP flags string (e.g. "S", "SA", "PA") or "".
        payload_summary: Short human-readable payload excerpt.
        raw_summary:     One-line scapy summary string for the full frame.
        extra:           Protocol-specific key-value pairs (DNS name, etc.).
    """

    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    size: int
    ttl: int
    flags: str
    payload_summary: str
    raw_summary: str
    extra: Dict[str, str] = field(default_factory=dict, hash=False, compare=False)

    @staticmethod
    def make_timestamp() -> float:
        """Return the current UTC Unix timestamp."""
        return time.time()

    def session_key(self) -> tuple:
        """Return the canonical 5-tuple used for session grouping.

        Bidirectional flows are normalised so that (A→B) and (B→A) share
        the same key.

        Returns:
            Sorted tuple of (ip_pair, port_pair, protocol).
        """
        ip_pair = tuple(sorted([self.src_ip, self.dst_ip]))
        port_pair = tuple(sorted([self.src_port, self.dst_port]))
        return (ip_pair, port_pair, self.protocol)

    def to_dict(self) -> Dict[str, object]:
        """Serialise to a plain dict (for CSV/JSON export).

        Returns:
            Dictionary with all fields serialised as primitives.
        """
        return {
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "size": self.size,
            "ttl": self.ttl,
            "flags": self.flags,
            "payload_summary": self.payload_summary,
            "raw_summary": self.raw_summary,
            **{f"extra_{k}": v for k, v in self.extra.items()},
        }
