"""processing/protocols/tcp.py — TCP packet parser."""

from __future__ import annotations

from typing import TYPE_CHECKING

from processing.models import PacketRecord
from utils.logger import get_logger

if TYPE_CHECKING:
    pass  # scapy types only available at runtime

logger = get_logger(__name__)


class TCPParser:
    """Parse TCP segments from a scapy Packet into a PacketRecord.

    Implements the BaseParser interface used by PacketParser dispatcher.
    """

    def can_handle(self, packet: object) -> bool:  # noqa: ANN001
        """Return True if *packet* contains a TCP layer.

        Args:
            packet: Raw scapy Packet object.

        Returns:
            bool indicating whether this parser handles the packet.
        """
        try:
            from scapy.layers.inet import TCP  # type: ignore
            return packet.haslayer(TCP)  # type: ignore[attr-defined]
        except Exception:
            return False

    def parse(self, packet: object) -> PacketRecord:  # noqa: ANN001
        """Extract TCP fields and return a PacketRecord.

        Args:
            packet: Raw scapy Packet with a TCP layer.

        Returns:
            A populated :class:`PacketRecord`.
        """
        from scapy.layers.inet import IP, TCP  # type: ignore

        ip_layer = packet[IP] if packet.haslayer(IP) else None  # type: ignore[attr-defined]
        tcp_layer = packet[TCP]

        src_ip = ip_layer.src if ip_layer else ""
        dst_ip = ip_layer.dst if ip_layer else ""
        ttl = ip_layer.ttl if ip_layer else 0

        # Decode TCP flags to human-readable string
        flag_map = {
            0x01: "F", 0x02: "S", 0x04: "R",
            0x08: "P", 0x10: "A", 0x20: "U",
        }
        raw_flags = int(tcp_layer.flags)
        flags_str = "".join(v for k, v in flag_map.items() if raw_flags & k) or "0"

        # Payload summary
        payload = bytes(tcp_layer.payload)
        payload_summary = _safe_decode(payload[:80])

        # Detect HTTP/HTTPS inside TCP
        is_http_port = tcp_layer.dport in (80, 8080) or tcp_layer.sport in (80, 8080)
        is_https_port = tcp_layer.dport in (443, 8443) or tcp_layer.sport in (443, 8443)
        # TLS ClientHello / ServerHello detection via content-type byte 0x16
        is_tls_handshake = len(payload) > 0 and payload[0] == 0x16

        if is_http_port and any(payload.startswith(m.encode()) for m in
                                ["GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "HTTP/"]):
            protocol = "HTTP"
        elif is_https_port or is_tls_handshake:
            protocol = "HTTPS"
        else:
            protocol = "TCP"

        extra = {}
        if protocol == "HTTP" and payload:
            lines = payload_summary.split("\n")
            if lines:
                extra["http_line"] = lines[0][:120]

        return PacketRecord(
            timestamp=PacketRecord.make_timestamp(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=int(tcp_layer.sport),
            dst_port=int(tcp_layer.dport),
            protocol=protocol,
            size=len(packet),  # type: ignore[arg-type]
            ttl=ttl,
            flags=flags_str,
            payload_summary=payload_summary[:120],
            raw_summary=packet.summary(),  # type: ignore[attr-defined]
            extra=extra,
        )


def _safe_decode(data: bytes, encoding: str = "utf-8") -> str:
    """Decode bytes to a string, replacing undecodable bytes."""
    return data.decode(encoding, errors="replace").replace("\r", "").strip()
