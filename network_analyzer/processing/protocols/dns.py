"""processing/protocols/dns.py — DNS packet parser."""

from __future__ import annotations

from processing.models import PacketRecord
from utils.logger import get_logger

logger = get_logger(__name__)


class DNSParser:
    """Parse DNS queries/responses from a scapy Packet into a PacketRecord."""

    def can_handle(self, packet: object) -> bool:
        """Return True if *packet* contains a DNS layer."""
        try:
            from scapy.layers.dns import DNS  # type: ignore
            return packet.haslayer(DNS)  # type: ignore[attr-defined]
        except Exception:
            return False

    def parse(self, packet: object) -> PacketRecord:
        """Extract DNS fields and return a PacketRecord."""
        from scapy.layers.inet import IP, UDP  # type: ignore
        from scapy.layers.dns import DNS, DNSQR, DNSRR  # type: ignore

        ip_layer = packet[IP] if packet.haslayer(IP) else None  # type: ignore[attr-defined]
        udp_layer = packet[UDP] if packet.haslayer(UDP) else None
        dns_layer = packet[DNS]

        src_ip = ip_layer.src if ip_layer else ""
        dst_ip = ip_layer.dst if ip_layer else ""
        ttl = ip_layer.ttl if ip_layer else 0
        src_port = int(udp_layer.sport) if udp_layer else 53
        dst_port = int(udp_layer.dport) if udp_layer else 53

        # Extract query name
        qname = ""
        try:
            if dns_layer.qd:
                qname = dns_layer.qd.qname.decode("utf-8", errors="replace").rstrip(".")
        except Exception:
            pass

        # Extract answer if present
        answers = []
        try:
            rr = dns_layer.an
            while rr:
                if hasattr(rr, "rdata"):
                    answers.append(str(rr.rdata))
                rr = rr.payload if hasattr(rr, "payload") else None
                if not hasattr(rr, "rdata"):
                    break
        except Exception:
            pass

        qr_flag = "Response" if dns_layer.qr else "Query"
        summary = f"DNS {qr_flag}: {qname}" + (f" → {', '.join(answers[:3])}" if answers else "")

        extra = {"dns_qname": qname, "dns_type": qr_flag}
        if answers:
            extra["dns_answers"] = ", ".join(answers[:3])

        return PacketRecord(
            timestamp=PacketRecord.make_timestamp(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol="DNS",
            size=len(packet),  # type: ignore[arg-type]
            ttl=ttl,
            flags="",
            payload_summary=summary[:120],
            raw_summary=packet.summary(),  # type: ignore[attr-defined]
            extra=extra,
        )
