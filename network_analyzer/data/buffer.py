"""
data/buffer.py — Thread-safe circular packet buffer.

The buffer is the single shared in-memory store that the UI reads from.
It never blocks writers — if capacity is exceeded, the oldest entry is
silently evicted (circular semantics via collections.deque maxlen).
"""

from __future__ import annotations

import threading
from collections import deque
from typing import Callable, List, Optional

from utils.config import BufferConfig, DEFAULT_CONFIG
from utils.logger import get_logger

logger = get_logger(__name__)


class PacketBuffer:
    """Thread-safe circular buffer for :class:`~processing.models.PacketRecord` objects.

    Backed by :class:`collections.deque` with a fixed ``maxlen`` — appending
    beyond capacity automatically drops the oldest entry, so writes never
    block or raise.

    Example::

        buf = PacketBuffer()
        buf.append(record)
        recent = buf.get_recent(50)
        filtered = buf.filter(lambda r: r.protocol == "TCP")
    """

    def __init__(self, config: Optional[BufferConfig] = None) -> None:
        """Initialise the buffer.

        Args:
            config: :class:`BufferConfig`; defaults to the global config.
        """
        self._cfg = config or DEFAULT_CONFIG.buffer
        self._buf: deque = deque(maxlen=self._cfg.max_capacity)
        self._lock = threading.RLock()
        self._total_appended: int = 0

    # ------------------------------------------------------------------
    # Write API
    # ------------------------------------------------------------------

    def append(self, record: object) -> None:
        """Add a packet record to the buffer.

        If the buffer is at capacity, the oldest entry is evicted
        automatically (circular behaviour).

        Args:
            record: A :class:`~processing.models.PacketRecord` instance.
        """
        with self._lock:
            self._buf.append(record)
            self._total_appended += 1

    # ------------------------------------------------------------------
    # Read API
    # ------------------------------------------------------------------

    def get_all(self) -> List[object]:
        """Return a snapshot of all records currently in the buffer.

        Returns:
            List of :class:`~processing.models.PacketRecord` objects,
            oldest first.
        """
        with self._lock:
            return list(self._buf)

    def get_recent(self, n: int) -> List[object]:
        """Return the *n* most recent records.

        Args:
            n: Number of records to retrieve.

        Returns:
            List of up to *n* :class:`~processing.models.PacketRecord` objects,
            most recent last.
        """
        with self._lock:
            items = list(self._buf)
        return items[-n:] if n < len(items) else items

    def filter(self, predicate: Callable[[object], bool]) -> List[object]:
        """Return all records matching *predicate*.

        Args:
            predicate: A callable that accepts a PacketRecord and returns bool.

        Returns:
            Filtered list of matching records.
        """
        with self._lock:
            return [r for r in self._buf if predicate(r)]

    def clear(self) -> None:
        """Discard all buffered records."""
        with self._lock:
            self._buf.clear()
        logger.info("PacketBuffer cleared.")

    # ------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------

    @property
    def size(self) -> int:
        """Current number of records in the buffer."""
        with self._lock:
            return len(self._buf)

    @property
    def capacity(self) -> int:
        """Maximum capacity of the buffer."""
        return self._cfg.max_capacity

    @property
    def total_appended(self) -> int:
        """All-time append count (including evicted entries)."""
        with self._lock:
            return self._total_appended
