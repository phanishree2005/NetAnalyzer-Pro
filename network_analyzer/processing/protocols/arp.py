"""processing/protocols/arp.py — ARP (Address Resolution Protocol) packet parser.

Handles both ARP requests and replies, providing MAC-to-IP mapping info
useful for network topology and ARP-spoofing detection.
"""

from __future__ import annotations

from processing.models import PacketRecord
from utils.logger import get_logger

logger = get_logger(__name__)

_ARP_OP_NAMES = {
    1: "Request",
    2: "Reply",
    3: "Request Reverse",
    4: "Reply Reverse",
}


class ARPParser:
    """Parse ARP packets from a scapy Packet into a PacketRecord.

    Implements the BaseParser interface used by PacketParser dispatcher.
    ARP packets are placed early in the chain since they have no IP layer.
    """

    def can_handle(self, packet: object) -> bool:
        """Return True if *packet* contains an ARP layer.

        Args:
            packet: Raw scapy Packet object.

        Returns:
            bool indicating whether this parser handles the packet.
        """
        try:
            from scapy.layers.l2 import ARP  # type: ignore
            return packet.haslayer(ARP)  # type: ignore[attr-defined]
        except Exception:
            return False

    def parse(self, packet: object) -> PacketRecord:
        """Extract ARP fields and return a PacketRecord.

        Args:
            packet: Raw scapy Packet with an ARP layer.

        Returns:
            A populated :class:`PacketRecord`.
        """
        from scapy.layers.l2 import ARP  # type: ignore

        arp = packet[ARP]  # type: ignore[index]
        op_code = int(arp.op)
        op_name = _ARP_OP_NAMES.get(op_code, f"Op-{op_code}")

        src_ip = str(arp.psrc) if arp.psrc else ""
        dst_ip = str(arp.pdst) if arp.pdst else ""
        src_mac = str(arp.hwsrc) if arp.hwsrc else ""
        dst_mac = str(arp.hwdst) if arp.hwdst else ""

        summary = f"ARP {op_name}: {src_ip} ({src_mac}) → {dst_ip} ({dst_mac})"

        return PacketRecord(
            timestamp=PacketRecord.make_timestamp(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=0,
            dst_port=0,
            protocol="ARP",
            size=len(packet),  # type: ignore[arg-type]
            ttl=0,
            flags="",
            payload_summary=summary[:120],
            raw_summary=packet.summary(),  # type: ignore[attr-defined]
            extra={
                "arp_op": op_name,
                "src_mac": src_mac,
                "dst_mac": dst_mac,
            },
        )
