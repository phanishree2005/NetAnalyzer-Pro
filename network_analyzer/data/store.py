"""
data/store.py — Optional SQLite persistence and CSV/JSON export.

DataStore batches writes to avoid per-packet SQLite overhead.
Reads and exports can be filtered by IP, protocol, or time range.
SQLite is disabled by default (config.store.enabled = False).
"""

from __future__ import annotations

import csv
import json
import sqlite3
import threading
import time
from typing import Callable, List, Optional

from utils.config import StoreConfig, DEFAULT_CONFIG
from utils.logger import get_logger

logger = get_logger(__name__)

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS packets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       REAL    NOT NULL,
    src_ip          TEXT,
    dst_ip          TEXT,
    src_port        INTEGER,
    dst_port        INTEGER,
    protocol        TEXT,
    size            INTEGER,
    ttl             INTEGER,
    flags           TEXT,
    payload_summary TEXT,
    raw_summary     TEXT
);
"""

_INSERT_ROW = """
INSERT INTO packets
    (timestamp, src_ip, dst_ip, src_port, dst_port,
     protocol, size, ttl, flags, payload_summary, raw_summary)
VALUES (?,?,?,?,?,?,?,?,?,?,?);
"""


class DataStore:
    """Batched SQLite persistence layer with CSV/JSON export.

    When ``config.store.enabled`` is ``False`` the instance is a no-op
    stub — all methods succeed but do nothing except export from the
    provided buffer.

    Example::

        store = DataStore()
        store.start()
        store.ingest(record)       # buffered — not written immediately
        store.export_csv("out.csv")
        store.stop()
    """

    def __init__(
        self,
        config: Optional[StoreConfig] = None,
        buffer: Optional[object] = None,
    ) -> None:
        """Initialise the data store.

        Args:
            config: :class:`StoreConfig`; defaults to global config.
            buffer: Optional :class:`~data.buffer.PacketBuffer` reference
                    used for export operations when SQLite is disabled.
        """
        self._cfg = config or DEFAULT_CONFIG.store
        self._buffer = buffer  # fallback for exports
        self._conn: Optional[sqlite3.Connection] = None
        self._pending: List[object] = []
        self._lock = threading.RLock()
        self._flush_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._last_flush: float = time.time()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Open the SQLite connection and start the flush thread."""
        if not self._cfg.enabled:
            logger.info("DataStore: SQLite disabled — running in export-only mode.")
            return

        try:
            self._conn = sqlite3.connect(
                self._cfg.db_path, check_same_thread=False
            )
            self._conn.execute(_CREATE_TABLE)
            self._conn.commit()
            logger.info("DataStore: SQLite opened at '%s'.", self._cfg.db_path)
        except sqlite3.Error as exc:
            logger.error("DataStore: Failed to open SQLite: %s", exc)
            self._conn = None
            return

        self._stop_event.clear()
        self._flush_thread = threading.Thread(
            target=self._flush_loop,
            name="DataStoreFlushThread",
            daemon=True,
        )
        self._flush_thread.start()

    def stop(self) -> None:
        """Flush remaining records and close the SQLite connection."""
        self._stop_event.set()
        if self._flush_thread and self._flush_thread.is_alive():
            self._flush_thread.join(timeout=5.0)
        self._flush_pending()
        if self._conn:
            self._conn.close()
            self._conn = None
        logger.info("DataStore stopped.")

    # ------------------------------------------------------------------
    # Write API
    # ------------------------------------------------------------------

    def ingest(self, record: object) -> None:
        """Accept a parsed record for eventual persistence.

        If SQLite is disabled this is a no-op.

        Args:
            record: A :class:`~processing.models.PacketRecord`.
        """
        if not self._cfg.enabled or self._conn is None:
            return
        with self._lock:
            self._pending.append(record)
            if len(self._pending) >= self._cfg.batch_size:
                self._flush_pending()

    # ------------------------------------------------------------------
    # Export API
    # ------------------------------------------------------------------

    def export_csv(
        self,
        path: str,
        filter_fn: Optional[Callable[[object], bool]] = None,
    ) -> int:
        """Write matching records to a CSV file.

        Args:
            path:      Destination file path.
            filter_fn: Optional predicate to filter records.

        Returns:
            Number of rows written.
        """
        records = self._get_exportable(filter_fn)
        if not records:
            logger.warning("export_csv: no records to export.")
            return 0
        try:
            rows = [r.to_dict() for r in records]  # type: ignore[attr-defined]
            with open(path, "w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=rows[0].keys())
                writer.writeheader()
                writer.writerows(rows)
            logger.info("export_csv: wrote %d rows to '%s'.", len(rows), path)
            return len(rows)
        except OSError as exc:
            logger.error("export_csv failed: %s", exc)
            return 0

    def export_json(
        self,
        path: str,
        filter_fn: Optional[Callable[[object], bool]] = None,
    ) -> int:
        """Write matching records to a JSON file.

        Args:
            path:      Destination file path.
            filter_fn: Optional predicate to filter records.

        Returns:
            Number of records written.
        """
        records = self._get_exportable(filter_fn)
        if not records:
            logger.warning("export_json: no records to export.")
            return 0
        try:
            rows = [r.to_dict() for r in records]  # type: ignore[attr-defined]
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(rows, fh, indent=2, default=str)
            logger.info("export_json: wrote %d records to '%s'.", len(rows), path)
            return len(rows)
        except OSError as exc:
            logger.error("export_json failed: %s", exc)
            return 0

    def query(
        self,
        src_ip: Optional[str] = None,
        protocol: Optional[str] = None,
        since: Optional[float] = None,
    ) -> List[object]:
        """Query persisted records from SQLite.

        Falls back to buffer if SQLite is disabled.

        Args:
            src_ip:   Filter by source IP (exact match).
            protocol: Filter by protocol name.
            since:    Only return records after this Unix timestamp.

        Returns:
            List of matching :class:`~processing.models.PacketRecord` objects
            (reconstructed as plain dicts when reading from SQLite).
        """
        if self._conn is None or not self._cfg.enabled:
            return self._query_buffer(src_ip, protocol, since)

        clauses, params = [], []
        if src_ip:
            clauses.append("src_ip = ?")
            params.append(src_ip)
        if protocol:
            clauses.append("protocol = ?")
            params.append(protocol)
        if since:
            clauses.append("timestamp >= ?")
            params.append(since)

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT * FROM packets {where} ORDER BY timestamp DESC LIMIT 5000;"
        try:
            cur = self._conn.execute(sql, params)
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]
        except sqlite3.Error as exc:
            logger.error("DataStore.query failed: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _flush_loop(self) -> None:
        """Periodically flush pending records to SQLite."""
        while not self._stop_event.is_set():
            time.sleep(self._cfg.batch_interval_seconds)
            self._flush_pending()

    def _flush_pending(self) -> None:
        """Write buffered records to SQLite in one transaction."""
        if not self._conn:
            return
        with self._lock:
            if not self._pending:
                return
            batch = self._pending[:]
            self._pending.clear()

        try:
            rows = [
                (
                    r.timestamp, r.src_ip, r.dst_ip, r.src_port, r.dst_port,  # type: ignore[attr-defined]
                    r.protocol, r.size, r.ttl, r.flags,                        # type: ignore[attr-defined]
                    r.payload_summary, r.raw_summary,                          # type: ignore[attr-defined]
                )
                for r in batch
            ]
            self._conn.executemany(_INSERT_ROW, rows)
            self._conn.commit()
            logger.debug("DataStore: flushed %d records to SQLite.", len(rows))
        except sqlite3.Error as exc:
            logger.error("DataStore flush failed: %s", exc)

    def _get_exportable(
        self, filter_fn: Optional[Callable[[object], bool]]
    ) -> List[object]:
        """Retrieve records for export from buffer or SQLite."""
        if self._buffer is not None:
            records = self._buffer.get_all()  # type: ignore[attr-defined]
        elif self._cfg.enabled and self._conn:
            records = self.query()  # type: ignore[assignment]
        else:
            return []
        if filter_fn:
            records = [r for r in records if filter_fn(r)]
        return records

    def _query_buffer(
        self,
        src_ip: Optional[str],
        protocol: Optional[str],
        since: Optional[float],
    ) -> List[object]:
        """Filter buffer when SQLite is unavailable."""
        if self._buffer is None:
            return []

        def pred(r: object) -> bool:
            if src_ip and getattr(r, "src_ip", "") != src_ip:
                return False
            if protocol and getattr(r, "protocol", "") != protocol:
                return False
            if since and getattr(r, "timestamp", 0.0) < since:
                return False
            return True

        return self._buffer.filter(pred)  # type: ignore[attr-defined]
