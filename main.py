"""
HoneyShield — Advanced E-commerce Threat Intelligence Honeypot
Entry point: starts all honeypot services and the web dashboard.
"""

import sys
import os
import signal
import threading
import argparse
import time

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(__file__))

from core.orchestrator import HoneypotOrchestrator
from config.settings   import load_config
from utils.logger       import get_logger

log = get_logger("main")


def parse_args():
    p = argparse.ArgumentParser(description="HoneyShield — E-commerce Threat Intel Honeypot")
    p.add_argument("--config", default="config/config.json", help="Path to config file")
    p.add_argument("--no-dashboard", action="store_true", help="Disable web dashboard")
    p.add_argument("--ports", nargs="+", type=int, help="Override honeypot ports")
    return p.parse_args()


def print_banner():
    banner = r"""
 ██╗  ██╗ ██████╗ ███╗   ██╗███████╗██╗   ██╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗
 ██║  ██║██╔═══██╗████╗  ██║██╔════╝╚██╗ ██╔╝██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗
 ███████║██║   ██║██╔██╗ ██║█████╗   ╚████╔╝ ███████╗███████║██║█████╗  ██║     ██║  ██║
 ██╔══██║██║   ██║██║╚██╗██║██╔══╝    ╚██╔╝  ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║
 ██║  ██║╚██████╔╝██║ ╚████║███████╗   ██║   ███████║██║  ██║██║███████╗███████╗██████╔╝
 ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝

       E-commerce Threat Intelligence Honeypot  |  v2.0  |  Academic Project
    """
    print("\033[36m" + banner + "\033[0m")


def main():
    print_banner()
    args   = parse_args()
    config = load_config(args.config)

    if args.ports:
        for i, svc in enumerate(config["services"]):
            if i < len(args.ports):
                svc["port"] = args.ports[i]

    orchestrator = HoneypotOrchestrator(config)

    def shutdown(sig, frame):
        log.info("Shutdown signal received. Stopping all services...")
        orchestrator.stop()
        log.info("HoneyShield stopped cleanly.")
        sys.exit(0)

    signal.signal(signal.SIGINT,  shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    orchestrator.start()

    if not args.no_dashboard:
        log.info(f"Web dashboard → http://127.0.0.1:{config['dashboard']['port']}")

    log.info("HoneyShield is running. Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        shutdown(None, None)


if __name__ == "__main__":
    main()
