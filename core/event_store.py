"""
core/event_store.py
Thread-safe in-memory event store with JSON Lines persistence.
Holds all connection events, provides querying, and streams
live events to the dashboard via a queue.
"""

import json
import threading
import os
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import List, Dict, Optional
import queue


@dataclass
class ConnectionEvent:
    ip:            str
    port:          int
    service:       str        # e.g. "HTTP Shop", "SSH Server"
    protocol:      str        # http | ftp | ssh | mysql
    timestamp:     str        # ISO 8601 UTC
    session_id:    str
    method:        str = ""   # HTTP method if applicable
    path:          str = ""   # Requested path
    user_agent:    str = ""
    body_snippet:  str = ""   # First 200 chars of body
    threat_score:  int = 0
    severity:      str = "LOW"
    tags:          List[str] = field(default_factory=list)
    response_sent: bool = False
    country:       str = "Unknown"
    honeypot_port: int = 0

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


class EventStore:
    """
    Central repository for all honeypot events.
    - Thread-safe reads/writes
    - Persists events to logs/events.jsonl
    - Provides live event queue for SSE dashboard streaming
    - Computes aggregated stats for dashboard API
    """

    def __init__(self, log_dir: str = "logs"):
        self._events: deque = deque(maxlen=10_000)   # keep last 10k in memory
        self._lock = threading.RLock()
        self._log_dir = log_dir
        self._live_queue: queue.Queue = queue.Queue(maxsize=500)
        os.makedirs(log_dir, exist_ok=True)
        self._jsonl_path = os.path.join(log_dir, "events.jsonl")

    # ── Write ──────────────────────────────────────────────────────────────

    def add(self, event: ConnectionEvent):
        with self._lock:
            self._events.append(event)
        self._persist(event)
        try:
            self._live_queue.put_nowait(event)
        except queue.Full:
            pass  # drop oldest if queue full

    def _persist(self, event: ConnectionEvent):
        try:
            with open(self._jsonl_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event.to_dict()) + "\n")
        except Exception:
            pass

    # ── Read ───────────────────────────────────────────────────────────────

    def recent(self, n: int = 100) -> List[ConnectionEvent]:
        with self._lock:
            return list(self._events)[-n:]

    def all(self) -> List[ConnectionEvent]:
        with self._lock:
            return list(self._events)

    def get_live_event(self, timeout: float = 1.0) -> Optional[ConnectionEvent]:
        try:
            return self._live_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    # ── Aggregations ────────────────────────────────────────────────────────

    def stats(self) -> dict:
        with self._lock:
            events = list(self._events)

        total = len(events)
        if total == 0:
            return self._empty_stats()

        unique_ips   = len({e.ip for e in events})
        by_severity  = defaultdict(int)
        by_service   = defaultdict(int)
        by_protocol  = defaultdict(int)
        by_tag       = defaultdict(int)
        by_ip        = defaultdict(int)
        scores       = []
        timeline     = defaultdict(int)   # hour → count

        for e in events:
            by_severity[e.severity] += 1
            by_service[e.service]   += 1
            by_protocol[e.protocol] += 1
            by_ip[e.ip]             += 1
            scores.append(e.threat_score)
            for tag in e.tags:
                by_tag[tag] += 1
            hour = e.timestamp[:13]   # "2026-04-26T10"
            timeline[hour] += 1

        top_ips = sorted(by_ip.items(), key=lambda x: x[1], reverse=True)[:10]

        return {
            "total_events":   total,
            "unique_ips":     unique_ips,
            "by_severity":    dict(by_severity),
            "by_service":     dict(by_service),
            "by_protocol":    dict(by_protocol),
            "by_tag":         dict(by_tag),
            "top_attacker_ips": [{"ip": ip, "count": c} for ip, c in top_ips],
            "avg_threat_score": round(sum(scores) / len(scores), 1),
            "max_threat_score": max(scores),
            "timeline":        [{"hour": h, "count": c}
                                for h, c in sorted(timeline.items())[-24:]],
            "critical_count":  by_severity.get("CRITICAL", 0),
            "high_count":      by_severity.get("HIGH", 0),
        }

    def _empty_stats(self) -> dict:
        return {
            "total_events": 0, "unique_ips": 0,
            "by_severity": {}, "by_service": {}, "by_protocol": {},
            "by_tag": {}, "top_attacker_ips": [], "avg_threat_score": 0,
            "max_threat_score": 0, "timeline": [],
            "critical_count": 0, "high_count": 0,
        }
