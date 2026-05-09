"""
capture/simulator.py — Traffic simulation for demo/hosted environments.

Generates fake network traffic (TCP, UDP, DNS, HTTP) to allow the
dashboard to function on platforms where raw sniffing is restricted (Vercel).
"""

import time
import random
import threading
import queue
from typing import Optional

from utils.logger import get_logger
from utils.config import CaptureConfig, DEFAULT_CONFIG

logger = get_logger(__name__)

class TrafficSimulator:
    """Mock replacement for PacketSniffer that generates fake traffic."""

    def __init__(self, config: Optional[CaptureConfig] = None) -> None:
        self._config = config or DEFAULT_CONFIG.capture
        self._raw_queue = queue.Queue(maxsize=self._config.raw_queue_maxsize)
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._is_running = False
        self._packet_count = 0

    def start(self, interface: str = "", bpf_filter: str = "") -> None:
        if self._is_running: return
        self._stop_event.clear()
        self._packet_count = 0
        self._thread = threading.Thread(target=self._sim_loop, daemon=True)
        self._thread.start()
        self._is_running = True
        logger.info("Traffic simulator started (Demo Mode)")

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread: self._thread.join(timeout=1.0)
        self._is_running = False

    def get_queue(self) -> queue.Queue:
        return self._raw_queue

    @property
    def is_running(self) -> bool:
        return self._is_running

    def _sim_loop(self):
        """Generate random scapy-like packets or mock objects."""
        # Note: We import scapy inside the loop to avoid top-level import issues
        try:
            from scapy.layers.inet import IP, TCP, UDP, ICMP
            from scapy.layers.dns import DNS, DNSQR
            from scapy.packet import Raw
        except ImportError:
            logger.error("Scapy not found - simulator cannot generate realistic packets.")
            return

        ips = ["192.168.1.10", "10.0.0.5", "172.16.0.20", "8.8.8.8", "1.1.1.1", "142.250.190.46"]
        domains = ["google.com", "github.com", "vercel.app", "openai.com", "amazon.aws"]
        
        while not self._stop_event.is_set():
            # Random protocol
            p = random.random()
            src = random.choice(ips)
            dst = random.choice(ips)
            while dst == src: dst = random.choice(ips)
            
            pkt = IP(src=src, dst=dst)
            
            if p < 0.6: # TCP / HTTP
                sport = random.randint(1024, 65535)
                dport = random.choice([80, 443, 8080, 22])
                flags = random.choice(["S", "A", "PA", "FA"])
                pkt /= TCP(sport=sport, dport=dport, flags=flags)
                if dport == 80:
                    pkt /= Raw(load=f"GET /index.html HTTP/1.1\r\nHost: {random.choice(domains)}\r\n\r\n")
            elif p < 0.85: # UDP / DNS
                sport = random.randint(1024, 65535)
                dport = random.choice([53, 123, 443]) # QUIC on 443
                if dport == 53:
                    pkt /= UDP(sport=sport, dport=53)/DNS(rd=1, qd=DNSQR(qname=random.choice(domains)))
                else:
                    pkt /= UDP(sport=sport, dport=dport)
            else: # ICMP
                pkt /= ICMP(type=8) # Echo Request
            
            self._packet_count += 1
            try:
                self._raw_queue.put_nowait(pkt)
            except queue.Full:
                pass
            
            # Control rate: 10-50 packets per second
            time.sleep(random.uniform(0.02, 0.1))

    @property
    def stats(self) -> dict:
        return {"captured": self._packet_count, "dropped": 0, "queue_size": self._raw_queue.qsize()}
