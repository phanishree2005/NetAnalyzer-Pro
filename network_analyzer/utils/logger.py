"""
utils/logger.py — Structured logging setup for the Network Protocol Analyzer.

Provides a factory function that returns a consistently configured logger.
All modules obtain their logger via get_logger(__name__).
"""

import logging
import sys
from logging.handlers import RotatingFileHandler
from typing import Optional


_LOG_FORMAT = (
    "%(asctime)s | %(levelname)-8s | %(name)-35s | %(message)s"
)
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
_LOG_FILE = "network_analyzer.log"
_MAX_BYTES = 10 * 1024 * 1024   # 10 MB
_BACKUP_COUNT = 3


def _build_handler(stream: bool = True) -> logging.Handler:
    """Create a stream or rotating-file handler with consistent formatting."""
    if stream:
        handler: logging.Handler = logging.StreamHandler(sys.stdout)
    else:
        handler = RotatingFileHandler(
            _LOG_FILE, maxBytes=_MAX_BYTES, backupCount=_BACKUP_COUNT,
            encoding="utf-8"
        )
    formatter = logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT)
    handler.setFormatter(formatter)
    return handler


def configure_root_logger(level: int = logging.INFO) -> None:
    """Call once at application startup to configure the root logger.

    Args:
        level: Minimum log level for all loggers (e.g., logging.DEBUG).
    """
    root = logging.getLogger()
    if root.handlers:
        return  # already configured — idempotent
    root.setLevel(level)
    root.addHandler(_build_handler(stream=True))
    root.addHandler(_build_handler(stream=False))


def get_logger(name: str, level: Optional[int] = None) -> logging.Logger:
    """Return a named logger, inheriting the root configuration.

    Args:
        name:  Typically ``__name__`` of the calling module.
        level: Optional override for this specific logger's level.

    Returns:
        A configured :class:`logging.Logger` instance.
    """
    logger = logging.getLogger(name)
    if level is not None:
        logger.setLevel(level)
    return logger
