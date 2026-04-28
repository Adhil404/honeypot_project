"""
core/threat_analyser.py
Detects attack patterns in HTTP requests and assigns a threat score.
Patterns: SQL injection, XSS, path traversal, credential stuffing,
          scanner User-Agents, rapid-request rate abuse.
"""

import re
import time
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Dict

# ── Attack signature patterns ──────────────────────────────────────────────

SQL_PATTERNS = [
    r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|CREATE|ALTER|EXEC|EXECUTE)\b)",
    r"(--|#|/\*|\*/)",
    r"(\bOR\b\s+\d+=\d+)",
    r"(\bAND\b\s+\d+=\d+)",
    r"('.*?--)",
    r"(1\s*=\s*1)",
    r"(SLEEP\s*\()",
    r"(BENCHMARK\s*\()",
    r"(LOAD_FILE\s*\()",
    r"(INTO\s+OUTFILE)",
]

XSS_PATTERNS = [
    r"(<\s*script.*?>)",
    r"(javascript\s*:)",
    r"(onerror\s*=)",
    r"(onload\s*=)",
    r"(<\s*iframe)",
    r"(document\.cookie)",
    r"(window\.location)",
    r"(eval\s*\()",
    r"(alert\s*\()",
]

PATH_TRAVERSAL_PATTERNS = [
    r"(\.\./)",
    r"(\.\.\\)",
    r"(%2e%2e%2f)",
    r"(%252e%252e%252f)",
    r"(/etc/passwd)",
    r"(/etc/shadow)",
    r"(/proc/self)",
    r"(boot\.ini)",
    r"(win\.ini)",
]

SCANNER_USER_AGENTS = [
    "sqlmap", "nikto", "nmap", "masscan", "zgrab", "nuclei",
    "dirbuster", "gobuster", "wfuzz", "burpsuite", "havij",
    "acunetix", "nessus", "openvas", "metasploit", "hydra",
    "medusa", "python-requests", "go-http-client", "curl/",
    "libwww-perl", "scrapy", "wget/",
]

SENSITIVE_PATHS = [
    "/admin", "/wp-admin", "/phpmyadmin", "/.env", "/config",
    "/backup", "/.git", "/api/keys", "/api/tokens", "/checkout/admin",
    "/payment/debug", "/cart/dump", "/.htaccess", "/robots.txt",
    "/sitemap.xml", "/swagger", "/graphql", "/actuator",
]

CREDENTIAL_PATHS = [
    "/admin/login", "/login", "/signin", "/auth",
    "/api/login", "/api/auth", "/admin",
]

# ── Compiled regexes ───────────────────────────────────────────────────────

_SQL_RE  = [re.compile(p, re.IGNORECASE) for p in SQL_PATTERNS]
_XSS_RE  = [re.compile(p, re.IGNORECASE) for p in XSS_PATTERNS]
_PATH_RE = [re.compile(p, re.IGNORECASE) for p in PATH_TRAVERSAL_PATTERNS]


@dataclass
class ThreatResult:
    ip: str
    score: int = 0
    tags: List[str] = field(default_factory=list)
    severity: str = "LOW"   # LOW | MEDIUM | HIGH | CRITICAL

    def finalise(self):
        if self.score >= 80:
            self.severity = "CRITICAL"
        elif self.score >= 50:
            self.severity = "HIGH"
        elif self.score >= 25:
            self.severity = "MEDIUM"
        else:
            self.severity = "LOW"
        return self


class RateLimiter:
    """Sliding-window rate limiter — flags IPs exceeding max_requests/window_sec."""

    def __init__(self, window_sec: int = 60, max_requests: int = 10):
        self.window  = window_sec
        self.max_req = max_requests
        self._store: Dict[str, List[float]] = defaultdict(list)
        self._lock   = threading.Lock()

    def check(self, ip: str) -> bool:
        """Returns True if IP has exceeded the rate limit."""
        now = time.time()
        with self._lock:
            timestamps = self._store[ip]
            # Drop old timestamps outside window
            self._store[ip] = [t for t in timestamps if now - t < self.window]
            self._store[ip].append(now)
            return len(self._store[ip]) > self.max_req

    def count(self, ip: str) -> int:
        with self._lock:
            return len(self._store.get(ip, []))


class ThreatAnalyser:
    """
    Main threat analysis engine.
    Scores each request against all attack patterns and returns a ThreatResult.
    """

    def __init__(self, config: dict):
        w = config["threat_intel"]["threat_score_weights"]
        self.weights    = w
        self.rate_limiter = RateLimiter(
            window_sec   = config["threat_intel"]["rate_limit_window"],
            max_requests = config["threat_intel"]["rate_limit_max"],
        )
        self._ip_visit_count: Dict[str, int] = defaultdict(int)
        self._lock = threading.Lock()

    def analyse(self, ip: str, method: str, path: str,
                headers: dict, body: str = "") -> ThreatResult:
        result = ThreatResult(ip=ip)
        ua = headers.get("User-Agent", "")
        payload = f"{path} {body}"

        # 1. Repeat visitor
        with self._lock:
            self._ip_visit_count[ip] += 1
            visits = self._ip_visit_count[ip]
        if visits > 1:
            result.score += self.weights["repeat_visit"]
            result.tags.append(f"repeat_visitor({visits}x)")

        # 2. Rate limit
        if self.rate_limiter.check(ip):
            result.score += self.weights["rapid_requests"]
            result.tags.append(f"rate_limit_exceeded({self.rate_limiter.count(ip)}/min)")

        # 3. SQL injection
        if any(r.search(payload) for r in _SQL_RE):
            result.score += self.weights["sql_injection"]
            result.tags.append("sql_injection")

        # 4. XSS
        if any(r.search(payload) for r in _XSS_RE):
            result.score += self.weights["xss_attempt"]
            result.tags.append("xss_attempt")

        # 5. Path traversal
        if any(r.search(payload) for r in _PATH_RE):
            result.score += self.weights["path_traversal"]
            result.tags.append("path_traversal")

        # 6. Credential endpoint
        if any(path.lower().startswith(cp) for cp in CREDENTIAL_PATHS):
            if method == "POST":
                result.score += self.weights["credential_dump"]
                result.tags.append("credential_stuffing_attempt")

        # 7. Scanner User-Agent
        ua_lower = ua.lower()
        matched_ua = [s for s in SCANNER_USER_AGENTS if s in ua_lower]
        if matched_ua:
            result.score += self.weights["scanner_ua"]
            result.tags.append(f"scanner_ua({matched_ua[0]})")

        # 8. Sensitive path probe
        if any(path.lower().startswith(sp) for sp in SENSITIVE_PATHS):
            result.score += 15
            result.tags.append("sensitive_path_probe")

        return result.finalise()

    def get_ip_stats(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._ip_visit_count)
