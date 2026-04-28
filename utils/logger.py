"""
utils/logger.py — Centralised logging: rotating file + JSON Lines + coloured console.
"""

import logging
import json
import os
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone

LOG_DIR = "logs"
_loggers = {}

RESET  = "\033[0m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
GREY   = "\033[90m"


class ColouredFormatter(logging.Formatter):
    COLOURS = {
        logging.DEBUG:    GREY,
        logging.INFO:     CYAN,
        logging.WARNING:  YELLOW,
        logging.ERROR:    RED,
        logging.CRITICAL: RED,
    }

    def format(self, record):
        colour = self.COLOURS.get(record.levelno, RESET)
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        return f"{GREY}[{ts}]{RESET} {colour}{record.levelname:<8}{RESET} {GREY}{record.name:<18}{RESET} {record.getMessage()}"


class JsonlHandler(logging.Handler):
    """Writes one JSON object per log record to a .jsonl file."""

    def __init__(self, filepath):
        super().__init__()
        os.makedirs(os.path.dirname(filepath), exist_ok=True) if os.path.dirname(filepath) else None
        self.filepath = filepath

    def emit(self, record):
        try:
            entry = {
                "ts":      datetime.now(timezone.utc).isoformat(),
                "level":   record.levelname,
                "logger":  record.name,
                "message": record.getMessage(),
            }
            if hasattr(record, "extra"):
                entry.update(record.extra)
            with open(self.filepath, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            pass


def get_logger(name: str) -> logging.Logger:
    if name in _loggers:
        return _loggers[name]

    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    os.makedirs(LOG_DIR, exist_ok=True)

    # Rotating plain-text log
    fh = RotatingFileHandler(
        f"{LOG_DIR}/honeypot.log",
        maxBytes=5 * 1024 * 1024,
        backupCount=10,
        encoding="utf-8",
    )
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s — %(message)s"))
    fh.setLevel(logging.DEBUG)
    logger.addHandler(fh)

    # JSON Lines (SIEM-ready)
    logger.addHandler(JsonlHandler(f"{LOG_DIR}/honeypot.jsonl"))

    # Coloured console
    ch = logging.StreamHandler()
    ch.setFormatter(ColouredFormatter())
    ch.setLevel(logging.INFO)
    logger.addHandler(ch)

    _loggers[name] = logger
    return logger


def log_event(logger: logging.Logger, level: str, msg: str, **extra):
    """Log a structured event with arbitrary extra fields."""
    record = logging.LogRecord(
        name=logger.name, level=getattr(logging, level.upper(), logging.INFO),
        pathname="", lineno=0, msg=msg, args=(), exc_info=None,
    )
    record.extra = extra
    for handler in logger.handlers:
        if handler.level <= record.levelno:
            handler.emit(record)
