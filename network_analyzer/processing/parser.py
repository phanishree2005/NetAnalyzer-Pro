"""
processing/parser.py — PacketParser: dispatcher that reads raw packets from
the capture queue and routes them to the correct protocol-specific parser.

Architecture: Chain-of-Responsibility — parsers are tried in priority order.
Parsed PacketRecord objects are placed onto a second queue consumed by the
analysis engine and data buffer.
"""

from __future__ import annotations

import queue
import threading
import time
from typing import List, Optional

from processing.models import PacketRecord
from processing.protocols.arp import ARPParser
from processing.protocols.dns import DNSParser
from processing.protocols.http import HTTPParser
from processing.protocols.icmp import ICMPParser
from processing.protocols.tcp import TCPParser
from processing.protocols.udp import UDPParser
from utils.logger import get_logger

logger = get_logger(__name__)


class _FallbackParser:
    """Catch-all parser for packets that no specific parser handles."""

    def can_handle(self, packet: object) -> bool:
        """Always returns True — this is the last in the chain."""
        return True

    def parse(self, packet: object) -> PacketRecord:
        """Produce a minimal PacketRecord for unrecognised frames."""
        try:
            size = len(packet)  # type: ignore[arg-type]
            summary = packet.summary()  # type: ignore[attr-defined]
        except Exception:
            size = 0
            summary = "Unknown"

        # Try to extract IP src/dst even for non-TCP/UDP
        src_ip, dst_ip, ttl = "", "", 0
        try:
            from scapy.layers.inet import IP  # type: ignore
            if packet.haslayer(IP):  # type: ignore[attr-defined]
                ip = packet[IP]  # type: ignore[index]
                src_ip, dst_ip, ttl = ip.src, ip.dst, ip.ttl
        except Exception:
            pass

        return PacketRecord(
            timestamp=PacketRecord.make_timestamp(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=0,
            dst_port=0,
            protocol="OTHER",
            size=size,
            ttl=ttl,
            flags="",
            payload_summary=summary[:120],
            raw_summary=summary,
        )


class PacketParser:
    """Reads raw packets from the capture queue and dispatches to parsers.

    Runs in a dedicated daemon thread. Emits :class:`PacketRecord` objects
    onto ``parsed_queue``, which is consumed by the analysis engine and
    the in-memory buffer.

    The parser chain follows a Chain-of-Responsibility pattern:
    DNS → HTTP → ICMP → TCP → UDP → Fallback.
    (DNS before TCP so DNS-over-port-53-UDP is correctly labelled.)

    Example::

        parser = PacketParser(raw_queue=sniffer.get_queue())
        parser.start()
        parsed_q = parser.get_queue()
    """

    # Parser priority order (most specific first)
    # ARP first — has no IP layer so must be before generic parsers
    # DNS before TCP so DNS-over-port-53-UDP is correctly labelled
    _PARSER_CHAIN = [
        ARPParser(),
        DNSParser(),
        HTTPParser(),
        ICMPParser(),
        TCPParser(),
        UDPParser(),
        _FallbackParser(),
    ]

    def __init__(
        self,
        raw_queue: queue.Queue,
        parsed_queue_maxsize: int = 50_000,
    ) -> None:
        """Initialise the parser.

        Args:
            raw_queue:             Queue of raw scapy Packet objects from the
                                   sniffer.
            parsed_queue_maxsize:  Maximum depth of the parsed packet queue.
        """
        self._raw_queue = raw_queue
        self._parsed_queue: queue.Queue = queue.Queue(maxsize=parsed_queue_maxsize)
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._is_running = False
        self._parsed_count = 0
        self._error_count = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the parser thread.

        Raises:
            RuntimeError: If already running.
        """
        if self._is_running:
            raise RuntimeError("PacketParser is already running.")
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._parse_loop,
            name="PacketParserThread",
            daemon=True,
        )
        self._thread.start()
        self._is_running = True
        logger.info("PacketParser started.")

    def stop(self) -> None:
        """Stop the parser thread gracefully."""
        if not self._is_running:
            return
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        self._is_running = False
        logger.info(
            "PacketParser stopped. parsed=%d errors=%d",
            self._parsed_count,
            self._error_count,
        )

    def get_queue(self) -> queue.Queue:
        """Return the parsed-packet output queue.

        Returns:
            Queue of :class:`PacketRecord` objects.
        """
        return self._parsed_queue

    @property
    def is_running(self) -> bool:
        """``True`` if the parser thread is active."""
        return self._is_running

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _parse_loop(self) -> None:
        """Main parser loop — runs in the parser thread."""
        while not self._stop_event.is_set():
            try:
                raw_packet = self._raw_queue.get(timeout=0.1)
            except queue.Empty:
                continue

            record = self._dispatch(raw_packet)
            if record is None:
                continue

            try:
                self._parsed_queue.put_nowait(record)
                self._parsed_count += 1
            except queue.Full:
                logger.debug("Parsed queue full — dropping parsed record.")

    def _dispatch(self, packet: object) -> Optional[PacketRecord]:
        """Try each parser in chain order; return first successful result.

        Args:
            packet: Raw scapy Packet object.

        Returns:
            A :class:`PacketRecord` or ``None`` on failure.
        """
        for parser in self._PARSER_CHAIN:
            try:
                if parser.can_handle(packet):
                    return parser.parse(packet)
            except Exception as exc:
                self._error_count += 1
                logger.debug(
                    "Parser %s failed: %s", type(parser).__name__, exc
                )
        return None
