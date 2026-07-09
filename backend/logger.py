"""Unified logging configuration for OpenDeepHole."""

import logging
import logging.handlers
import sys
from pathlib import Path

from backend.config import get_config

_initialized = False
_NOISY_HTTP_LOGGERS = ("httpx", "httpcore", "openai")


def _suppress_third_party_http_logging() -> None:
    """Keep SDK request summaries out of the Agent console by default."""
    for logger_name in _NOISY_HTTP_LOGGERS:
        logging.getLogger(logger_name).setLevel(logging.WARNING)


def setup_logging() -> None:
    """Initialize logging based on config.yaml settings.

    Sets up both console and file handlers. Call once at application startup.
    """
    global _initialized
    _suppress_third_party_http_logging()
    if _initialized:
        return
    _initialized = True

    config = get_config()
    level = getattr(logging, config.logging.level.upper(), logging.INFO)

    root_logger = logging.getLogger("opendeephole")
    root_logger.setLevel(level)

    formatter = logging.Formatter(
        "[%(asctime)s] %(levelname)-8s %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(level)
    console.setFormatter(formatter)
    root_logger.addHandler(console)

    # File handler with rotation
    log_path = Path(config.logging.file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    max_bytes = config.logging.max_size_mb * 1024 * 1024
    file_handler = logging.handlers.RotatingFileHandler(
        log_path,
        maxBytes=max_bytes,
        backupCount=config.logging.backup_count,
    )
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)


def get_logger(name: str) -> logging.Logger:
    """Get a logger under the opendeephole namespace.

    Usage:
        logger = get_logger(__name__)
        logger.info("Scan started")
    """
    setup_logging()
    return logging.getLogger(f"opendeephole.{name}")
