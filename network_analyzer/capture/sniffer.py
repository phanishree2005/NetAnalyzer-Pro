"""
capture/sniffer.py — Scapy-based packet capture engine.

Runs in a dedicated daemon thread so it never blocks the UI or parser.
Puts raw scapy Packet objects onto a thread-safe Queue consumed by
the processing layer.
"""

from __future__ import annotations

import queue
import threading
from typing import Callable, Optional

from utils.logger import get_logger
from utils.config import CaptureConfig, DEFAULT_CONFIG

logger = get_logger(__name__)


class PacketSniffer:
    """Threaded packet capture engine backed by scapy's AsyncSniffer.

    Example usage::

        sniffer = PacketSniffer(config=DEFAULT_CONFIG.capture)
        sniffer.start(interface="eth0", bpf_filter="tcp")
        raw_q = sniffer.get_queue()
        # …later…
        sniffer.stop()

    The queue contains raw scapy ``Packet`` objects.  Downstream consumers
    (``PacketParser``) drain this queue independently.
    """

    def __init__(self, config: Optional[CaptureConfig] = None) -> None:
        """Initialise the sniffer with capture configuration.

        Args:
            config: :class:`CaptureConfig` instance; defaults to the global
                ``DEFAULT_CONFIG.capture`` if not provided.
        """
        self._config: CaptureConfig = config or DEFAULT_CONFIG.capture
        self._raw_queue: queue.Queue = queue.Queue(
            maxsize=self._config.raw_queue_maxsize
        )
        self._sniffer_thread: Optional[threading.Thread] = None
        self._stop_event: threading.Event = threading.Event()
        self._is_running: bool = False
        self._packet_count: int = 0
        self._dropped_count: int = 0
        self._interface: str = ""
        self._bpf_filter: str = ""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self, interface: str = "", bpf_filter: str = "") -> None:
        """Begin sniffing packets in a background daemon thread.

        Args:
            interface:  Network interface name (e.g. ``"eth0"``).  Uses
                        scapy's default when empty.
            bpf_filter: Berkeley Packet Filter expression (e.g. ``"tcp"``).

        Raises:
            RuntimeError: If the sniffer is already running.
        """
        if self._is_running:
            raise RuntimeError("Sniffer is already running. Call stop() first.")

        self._interface = interface or self._config.default_interface
        self._bpf_filter = bpf_filter or self._config.default_bpf_filter
        self._stop_event.clear()
        self._packet_count = 0
        self._dropped_count = 0

        self._sniffer_thread = threading.Thread(
            target=self._capture_loop,
            name="PacketSnifferThread",
            daemon=True,
        )
        self._sniffer_thread.start()
        self._is_running = True
        logger.info(
            "Sniffer started on interface='%s' filter='%s'",
            self._interface or "<default>",
            self._bpf_filter or "<none>",
        )

    def stop(self) -> None:
        """Gracefully stop the capture thread.

        Signals the thread to exit and waits up to 3 seconds for it to join.
        Safe to call even if the sniffer is not running.
        """
        if not self._is_running:
            logger.debug("stop() called but sniffer is not running — no-op.")
            return

        self._stop_event.set()
        if self._sniffer_thread and self._sniffer_thread.is_alive():
            self._sniffer_thread.join(timeout=3.0)
        self._is_running = False
        logger.info(
            "Sniffer stopped. captured=%d dropped=%d",
            self._packet_count,
            self._dropped_count,
        )

    def get_queue(self) -> queue.Queue:
        """Return the shared raw-packet queue.

        Returns:
            A :class:`queue.Queue` of raw scapy ``Packet`` objects.
        """
        return self._raw_queue

    @property
    def is_running(self) -> bool:
        """``True`` if the capture thread is active."""
        return self._is_running

    @property
    def stats(self) -> dict:
        """Return a snapshot of basic capture counters.

        Returns:
            Dict with keys ``captured``, ``dropped``, ``queue_size``.
        """
        return {
            "captured": self._packet_count,
            "dropped": self._dropped_count,
            "queue_size": self._raw_queue.qsize(),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _capture_loop(self) -> None:
        """Main capture loop — runs in the sniffer thread.

        Uses scapy's ``sniff()`` with a ``stop_filter`` so it yields
        control back and respects the stop event.
        """
        try:
            from scapy.all import sniff  # type: ignore

            kwargs: dict = {
                "prn": self._enqueue_packet,
                "store": False,
                "stop_filter": lambda _: self._stop_event.is_set(),
            }
            if self._interface:
                kwargs["iface"] = self._interface
            if self._bpf_filter:
                kwargs["filter"] = self._bpf_filter

            logger.debug("Entering scapy sniff() loop.")
            sniff(**kwargs)

        except PermissionError:
            logger.error(
                "Permission denied — run with administrator/root privileges."
            )
            self._is_running = False
        except OSError as exc:
            logger.error("OS error during capture (bad interface?): %s", exc)
            self._is_running = False
        except Exception as exc:  # pragma: no cover
            logger.exception("Unexpected error in capture loop: %s", exc)
            self._is_running = False

    def _enqueue_packet(self, packet: object) -> None:
        """Callback invoked by scapy for each captured packet.

        Args:
            packet: A raw scapy ``Packet`` object.
        """
        self._packet_count += 1
        try:
            self._raw_queue.put_nowait(packet)
        except queue.Full:
            self._dropped_count += 1
            if self._dropped_count % 100 == 0:
                logger.warning(
                    "Raw queue full — dropped %d packets total.",
                    self._dropped_count,
                )
