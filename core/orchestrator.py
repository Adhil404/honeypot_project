"""
core/orchestrator.py — Starts and manages all honeypot services.
"""

import threading
from utils.logger import get_logger
from core.event_store import EventStore
from core.threat_analyser import ThreatAnalyser
from services.http_honeypot import start_http_service
from services.tcp_honeypot import start_tcp_service
from dashboard.app import start_dashboard

log = get_logger("orchestrator")


class HoneypotOrchestrator:
    def __init__(self, config: dict):
        self.config   = config
        self.store    = EventStore(log_dir=config["logging"]["log_dir"])
        self.analyser = ThreatAnalyser(config)
        self._threads = []

    def start(self):
        host = "0.0.0.0"

        for svc in self.config["services"]:
            if not svc.get("enabled", True):
                continue
            proto = svc["protocol"]
            try:
                if proto == "http":
                    t = start_http_service(
                        host, svc["port"], svc["name"],
                        self.store, self.analyser, self.config
                    )
                else:
                    t = start_tcp_service(host, svc, self.store, self.analyser)
                self._threads.append(t)
            except OSError as e:
                log.error(f"Could not start '{svc['name']}' on port {svc['port']}: {e}")

        # Start web dashboard
        if self.config["dashboard"].get("enabled", True):
            t = start_dashboard(
                self.config["dashboard"]["host"],
                self.config["dashboard"]["port"],
                self.store,
                self.config,
            )
            self._threads.append(t)

        log.info(f"All services started. {len(self._threads)} threads running.")

    def stop(self):
        log.info("Stopping orchestrator (daemon threads will exit with process).")
