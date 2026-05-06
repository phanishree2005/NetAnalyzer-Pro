"""processing/protocols/udp.py — UDP datagram parser."""

from __future__ import annotations

from processing.models import PacketRecord
from utils.logger import get_logger

logger = get_logger(__name__)


class UDPParser:
    """Parse UDP datagrams from a scapy Packet into a PacketRecord."""

    def can_handle(self, packet: object) -> bool:
        """Return True if *packet* contains a UDP layer."""
        try:
            from scapy.layers.inet import UDP  # type: ignore
            return packet.haslayer(UDP)  # type: ignore[attr-defined]
        except Exception:
            return False

    def parse(self, packet: object) -> PacketRecord:
        """Extract UDP fields and return a PacketRecord."""
        from scapy.layers.inet import IP, UDP  # type: ignore

        ip_layer = packet[IP] if packet.haslayer(IP) else None  # type: ignore[attr-defined]
        udp_layer = packet[UDP]

        src_ip = ip_layer.src if ip_layer else ""
        dst_ip = ip_layer.dst if ip_layer else ""
        ttl = ip_layer.ttl if ip_layer else 0

        payload = bytes(udp_layer.payload)
        payload_summary = payload[:80].decode("utf-8", errors="replace").strip()

        return PacketRecord(
            timestamp=PacketRecord.make_timestamp(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=int(udp_layer.sport),
            dst_port=int(udp_layer.dport),
            protocol="UDP",
            size=len(packet),  # type: ignore[arg-type]
            ttl=ttl,
            flags="",
            payload_summary=payload_summary[:120],
            raw_summary=packet.summary(),  # type: ignore[attr-defined]
        )
