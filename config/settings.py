"""
config/settings.py — Configuration loader with defaults.
"""

import json
import os


DEFAULTS = {
    "services": [
        {"name": "HTTP Shop",       "port": 8080, "protocol": "http",  "enabled": True},
        {"name": "Admin Panel",     "port": 8888, "protocol": "http",  "enabled": True},
        {"name": "FTP Server",      "port": 2121, "protocol": "ftp",   "enabled": True},
        {"name": "SSH Server",      "port": 2222, "protocol": "ssh",   "enabled": True},
        {"name": "MySQL DB",        "port": 3307, "protocol": "mysql", "enabled": True},
        {"name": "Payment API",     "port": 9090, "protocol": "http",  "enabled": True},
    ],
    "dashboard": {
        "port": 5000,
        "host": "127.0.0.1",
        "enabled": True,
    },
    "logging": {
        "log_dir":      "logs",
        "max_bytes":    5242880,   # 5 MB
        "backup_count": 10,
        "geo_lookup":   False,     # set True if geoip2 installed
    },
    "threat_intel": {
        "rate_limit_window": 60,   # seconds
        "rate_limit_max":    10,   # connections per IP per window → flagged
        "blacklist_file":    "config/blacklist.txt",
        "threat_score_weights": {
            "repeat_visit":    10,
            "rapid_requests":  25,
            "sql_injection":   40,
            "xss_attempt":     35,
            "path_traversal":  40,
            "credential_dump": 50,
            "scanner_ua":      20,
        }
    },
    "fake_credentials": {
        "admin_user": "admin",
        "admin_pass": "admin123",   # intentionally weak — part of the trap
    },
    "responses": {
        "http_delay_ms": 500,       # add fake latency so attacker thinks it's real
        "ftp_banner": "220 ProFTPD 1.3.5e Server (ShopFTP) [::ffff:192.168.1.10]",
        "ssh_banner": "SSH-2.0-OpenSSH_7.4p1 Ubuntu-10+deb9u7",
        "mysql_banner": "5.7.34-log MySQL Community Server",
    }
}


def load_config(path: str) -> dict:
    if os.path.exists(path):
        with open(path, "r") as f:
            user_cfg = json.load(f)
        # Deep merge user config over defaults
        merged = deep_merge(DEFAULTS, user_cfg)
        return merged
    return DEFAULTS.copy()


def deep_merge(base: dict, override: dict) -> dict:
    result = base.copy()
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = deep_merge(result[k], v)
        else:
            result[k] = v
    return result
