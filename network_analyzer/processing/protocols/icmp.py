"""processing/protocols/icmp.py — ICMP packet parser."""

from __future__ import annotations

from processing.models import PacketRecord
from utils.logger import get_logger

logger = get_logger(__name__)

_ICMP_TYPES = {
    0: "Echo Reply",
    3: "Dest Unreachable",
    5: "Redirect",
    8: "Echo Request",
    11: "Time Exceeded",
    12: "Parameter Problem",
}


class ICMPParser:
    """Parse ICMP packets from a scapy Packet into a PacketRecord."""

    def can_handle(self, packet: object) -> bool:
        """Return True if *packet* contains an ICMP layer."""
        try:
            from scapy.layers.inet import ICMP  # type: ignore
            return packet.haslayer(ICMP)  # type: ignore[attr-defined]
        except Exception:
            return False

    def parse(self, packet: object) -> PacketRecord:
        """Extract ICMP fields and return a PacketRecord."""
        from scapy.layers.inet import IP, ICMP  # type: ignore

        ip_layer = packet[IP] if packet.haslayer(IP) else None  # type: ignore[attr-defined]
        icmp_layer = packet[ICMP]

        src_ip = ip_layer.src if ip_layer else ""
        dst_ip = ip_layer.dst if ip_layer else ""
        ttl = ip_layer.ttl if ip_layer else 0
        icmp_type = int(icmp_layer.type)
        type_name = _ICMP_TYPES.get(icmp_type, f"Type-{icmp_type}")

        return PacketRecord(
            timestamp=PacketRecord.make_timestamp(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=0,
            dst_port=0,
            protocol="ICMP",
            size=len(packet),  # type: ignore[arg-type]
            ttl=ttl,
            flags="",
            payload_summary=type_name,
            raw_summary=packet.summary(),  # type: ignore[attr-defined]
            extra={"icmp_type": str(icmp_type), "icmp_type_name": type_name},
        )
