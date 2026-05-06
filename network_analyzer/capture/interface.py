"""
capture/interface.py — Network interface discovery and validation.

Provides OS-aware utilities to enumerate available network interfaces
so the UI can present a dropdown and the sniffer can validate input.
"""

from __future__ import annotations

import socket
from typing import List, Optional

from utils.logger import get_logger

logger = get_logger(__name__)


def get_interfaces() -> List[str]:
    """Return a sorted list of available network interface names.

    Attempts to use scapy first (most reliable); falls back to psutil,
    then to a minimal socket probe. Never raises — returns [] on failure.

    Returns:
        List of interface name strings (e.g. ``["eth0", "lo", "wlan0"]``).
    """
    try:
        from scapy.arch import get_if_list  # type: ignore
        interfaces = sorted(get_if_list())
        logger.debug("Discovered %d interfaces via scapy: %s", len(interfaces), interfaces)
        return interfaces
    except Exception as exc:  # pragma: no cover
        logger.warning("scapy interface discovery failed: %s", exc)

    try:
        import psutil  # type: ignore
        interfaces = sorted(psutil.net_if_addrs().keys())
        logger.debug("Discovered %d interfaces via psutil: %s", len(interfaces), interfaces)
        return interfaces
    except Exception as exc:  # pragma: no cover
        logger.warning("psutil interface discovery failed: %s", exc)

    # Last resort — just return the hostname
    try:
        return [socket.gethostname()]
    except Exception:
        return []


def get_default_interface() -> Optional[str]:
    """Return the best default interface for sniffing.

    Prefers non-loopback interfaces. Returns ``None`` if nothing found.

    Returns:
        Interface name string or ``None``.
    """
    try:
        from scapy.arch import conf  # type: ignore
        iface = conf.iface
        if iface:
            logger.debug("Default interface from scapy conf: %s", iface)
            return str(iface)
    except Exception:
        pass

    for iface in get_interfaces():
        if "lo" not in iface.lower() and "loopback" not in iface.lower():
            return iface
    return None


def validate_interface(name: str) -> bool:
    """Check whether *name* is a currently available interface.

    Args:
        name: Interface name to validate.

    Returns:
        ``True`` if the interface exists, ``False`` otherwise.
    """
    available = get_interfaces()
    valid = name in available
    if not valid:
        logger.warning("Interface '%s' not in available list: %s", name, available)
    return valid
