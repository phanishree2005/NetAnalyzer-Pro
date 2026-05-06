"""processing/protocols/http.py — Standalone HTTP parser (port-agnostic).

This parser handles HTTP traffic that isn't already caught by the TCP
parser's port-based heuristic — e.g., non-standard ports carrying HTTP.
"""

from __future__ import annotations

from processing.models import PacketRecord
from utils.logger import get_logger

logger = get_logger(__name__)

_HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ")
_HTTP_RESPONSE = b"HTTP/"


class HTTPParser:
    """Parse HTTP traffic from a TCP payload into a PacketRecord."""

    def can_handle(self, packet: object) -> bool:
        """Return True if *packet* looks like HTTP traffic."""
        try:
            from scapy.layers.inet import TCP  # type: ignore
            if not packet.haslayer(TCP):  # type: ignore[attr-defined]
                return False
            payload = bytes(packet[TCP].payload)  # type: ignore[index]
            return any(payload.startswith(m) for m in _HTTP_METHODS + (_HTTP_RESPONSE,))
        except Exception:
            return False

    def parse(self, packet: object) -> PacketRecord:
        """Extract HTTP request/response line and return a PacketRecord."""
        from scapy.layers.inet import IP, TCP  # type: ignore

        ip_layer = packet[IP] if packet.haslayer(IP) else None  # type: ignore[attr-defined]
        tcp_layer = packet[TCP]  # type: ignore[index]
        payload = bytes(tcp_layer.payload)

        src_ip = ip_layer.src if ip_layer else ""
        dst_ip = ip_layer.dst if ip_layer else ""
        ttl = ip_layer.ttl if ip_layer else 0

        first_line = payload.split(b"\r\n")[0].decode("utf-8", errors="replace")[:120]

        flag_map = {0x01: "F", 0x02: "S", 0x04: "R", 0x08: "P", 0x10: "A", 0x20: "U"}
        raw_flags = int(tcp_layer.flags)
        flags_str = "".join(v for k, v in flag_map.items() if raw_flags & k) or "0"

        return PacketRecord(
            timestamp=PacketRecord.make_timestamp(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=int(tcp_layer.sport),
            dst_port=int(tcp_layer.dport),
            protocol="HTTP",
            size=len(packet),  # type: ignore[arg-type]
            ttl=ttl,
            flags=flags_str,
            payload_summary=first_line,
            raw_summary=packet.summary(),  # type: ignore[attr-defined]
            extra={"http_line": first_line},
        )
