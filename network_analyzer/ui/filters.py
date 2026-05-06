"""
ui/filters.py — Centralized filter state shared between UI components.

FilterState is a plain dataclass that the sidebar writes to and all
table/chart components read from. It is kept in st.session_state so it
persists across Streamlit reruns.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class FilterState:
    """Holds all active filter parameters from the sidebar.

    Attributes:
        selected_protocols: Protocols to include (empty = all).
        src_ip:             Filter by source IP substring (case-insensitive).
        dst_ip:             Filter by destination IP substring.
        port:               Filter by source OR destination port (0 = any).
        search_text:        Free-text search across payload_summary / raw_summary.
    """

    selected_protocols: List[str] = field(
        default_factory=lambda: ["TCP", "UDP", "ICMP", "DNS", "HTTP", "OTHER"]
    )
    src_ip: str = ""
    dst_ip: str = ""
    port: int = 0
    search_text: str = ""

    def matches(self, record: object) -> bool:
        """Return True if *record* passes all active filters.

        Filters are combined with AND logic.

        Args:
            record: A :class:`~processing.models.PacketRecord` instance.

        Returns:
            bool — True means the packet should be shown.
        """
        proto: str = getattr(record, "protocol", "")
        src: str = getattr(record, "src_ip", "")
        dst: str = getattr(record, "dst_ip", "")
        sport: int = getattr(record, "src_port", 0)
        dport: int = getattr(record, "dst_port", 0)
        summary: str = getattr(record, "payload_summary", "")
        raw: str = getattr(record, "raw_summary", "")

        if self.selected_protocols and proto not in self.selected_protocols:
            return False

        if self.src_ip and self.src_ip.lower() not in src.lower():
            return False

        if self.dst_ip and self.dst_ip.lower() not in dst.lower():
            return False

        if self.port and self.port not in (sport, dport):
            return False

        if self.search_text:
            needle = self.search_text.lower()
            if needle not in summary.lower() and needle not in raw.lower():
                return False

        return True
