"""
services/http_honeypot.py
Multi-endpoint HTTP honeypot simulating a realistic e-commerce platform.
Serves fake product pages, login forms, admin panels, payment APIs, and cart endpoints.
All requests are analysed and logged.
"""

import threading
import uuid
import json
import time
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

from core.event_store    import EventStore, ConnectionEvent
from core.threat_analyser import ThreatAnalyser
from utils.logger         import get_logger

log = get_logger("http_honeypot")

# ── Fake e-commerce HTML pages ─────────────────────────────────────────────

SHOP_HOME = """<!DOCTYPE html>
<html><head><title>ShopZone — Best Deals Online</title>
<style>body{font-family:Arial;margin:0;background:#f5f5f5}
.header{background:#e74c3c;color:white;padding:20px;font-size:24px}
.nav a{color:white;margin:0 10px;text-decoration:none}
.products{display:flex;flex-wrap:wrap;padding:20px;gap:20px}
.card{background:white;padding:15px;border-radius:8px;width:200px;box-shadow:0 2px 5px rgba(0,0,0,.1)}
.price{color:#e74c3c;font-size:20px;font-weight:bold}
.btn{background:#e74c3c;color:white;border:none;padding:8px 15px;cursor:pointer;border-radius:4px}
.footer{background:#333;color:#aaa;padding:20px;text-align:center;margin-top:40px}
</style></head>
<body>
<div class="header"> ShopZone
  <span class="nav"><a href="/login">Login</a><a href="/cart">Cart (0)</a><a href="/products">Products</a></span>
</div>
<div class="products">
  <div class="card"><img src="//placehold.it/200x150" width="100%"><h3>Wireless Headphones</h3><div class="price">$49.99</div><button class="btn">Add to Cart</button></div>
  <div class="card"><img src="//placehold.it/200x150" width="100%"><h3>Smart Watch</h3><div class="price">$129.99</div><button class="btn">Add to Cart</button></div>
  <div class="card"><img src="//placehold.it/200x150" width="100%"><h3>Laptop Stand</h3><div class="price">$29.99</div><button class="btn">Add to Cart</button></div>
  <div class="card"><img src="//placehold.it/200x150" width="100%"><h3>USB-C Hub</h3><div class="price">$39.99</div><button class="btn">Add to Cart</button></div>
</div>
<div class="footer">© 2026 ShopZone Inc. | All rights reserved | <a href="/sitemap.xml" style="color:#aaa">Sitemap</a></div>
</body></html>"""

LOGIN_PAGE = """<!DOCTYPE html>
<html><head><title>ShopZone — Login</title>
<style>body{font-family:Arial;background:#f5f5f5;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
.box{background:white;padding:40px;border-radius:10px;box-shadow:0 4px 20px rgba(0,0,0,.1);width:320px}
h2{color:#e74c3c;margin-top:0}input{width:100%;padding:10px;margin:8px 0;box-sizing:border-box;border:1px solid #ddd;border-radius:4px}
button{width:100%;background:#e74c3c;color:white;border:none;padding:12px;cursor:pointer;border-radius:4px;font-size:16px}
.msg{color:red;font-size:12px;margin-top:10px}
</style></head>
<body><div class="box">
<h2>🛍️ ShopZone Login</h2>
<form method="POST" action="/login">
  <input type="text"     name="username" placeholder="Email or Username" required>
  <input type="password" name="password" placeholder="Password" required>
  <button type="submit">Sign In</button>
</form>
<p class="msg">⚠️ Invalid credentials. Please try again.</p>
<p style="margin-top:15px;font-size:12px;color:#999">Forgot password? <a href="/reset">Reset here</a></p>
</div></body></html>"""

ADMIN_PAGE = """<!DOCTYPE html>
<html><head><title>ShopZone Admin Panel</title>
<style>body{font-family:Arial;background:#1a1a2e;color:#eee;margin:0}
.sidebar{width:220px;background:#16213e;height:100vh;position:fixed;padding:20px;box-sizing:border-box}
.sidebar h2{color:#e74c3c;border-bottom:1px solid #333;padding-bottom:10px}
.sidebar a{display:block;color:#aaa;text-decoration:none;padding:8px 0}
.sidebar a:hover{color:white}
.main{margin-left:260px;padding:30px}
.stat{background:#16213e;border-radius:8px;padding:20px;display:inline-block;margin:10px;min-width:160px}
.stat .num{font-size:32px;font-weight:bold;color:#e74c3c}
table{width:100%;border-collapse:collapse;background:#16213e;border-radius:8px}
th{background:#e74c3c;padding:10px;text-align:left}td{padding:10px;border-bottom:1px solid #333}
</style></head>
<body>
<div class="sidebar">
  <h2>⚙️ Admin</h2>
  <a href="/admin">Dashboard</a><a href="/admin/users">👤 Users</a>
  <a href="/admin/orders">📦 Orders</a><a href="/admin/products">🛍️ Products</a>
  <a href="/admin/payments">💳 Payments</a><a href="/admin/logs">📋 Logs</a>
  <a href="/api/config"  >🔧 Config API</a><a href="/api/keys">🔑 API Keys</a>
</div>
<div class="main">
  <h1>Admin Dashboard</h1>
  <div class="stat"><div>Total Orders</div><div class="num">1,248</div></div>
  <div class="stat"><div>Revenue Today</div><div class="num">$8,432</div></div>
  <div class="stat"><div>Active Users</div><div class="num">342</div></div>
  <div class="stat"><div>Pending</div><div class="num">17</div></div>
  <h2 style="margin-top:30px">Recent Orders</h2>
  <table>
    <tr><th>Order ID</th><th>Customer</th><th>Amount</th><th>Status</th><th>Card</th></tr>
    <tr><td>#10492</td><td>john.doe@email.com</td><td>$129.99</td><td>Shipped</td><td>****4521</td></tr>
    <tr><td>#10491</td><td>jane.smith@email.com</td><td>$49.99</td><td>Processing</td><td>****7823</td></tr>
    <tr><td>#10490</td><td>bob.jones@email.com</td><td>$299.99</td><td>Delivered</td><td>****1234</td></tr>
  </table>
  <h2 style="margin-top:30px">⚠️ This session is monitored and logged.</h2>
</div></body></html>"""

PAYMENT_API_RESPONSE = {
    "status": "ok",
    "gateway": "StripeV3",
    "merchant_id": "SHOP_ZONE_MERCHANT_001",
    "api_version": "2026-01-15",
    "test_card": "4242424242424242",
    "webhook_secret": "whsec_FAKE_SECRET_DO_NOT_USE_ab12cd34ef56",
    "keys": {
        "publishable": "pk_live_FAKE_KEY_honeypot_1234567890",
        "secret":      "sk_live_FAKE_SECRET_honeypot_abcdefghij"
    },
    "note": "WARNING: This is a honeypot. Your access has been logged."
}

ENV_FILE_RESPONSE = """DB_HOST=db.internal.shopzone.com
DB_USER=shopzone_prod
DB_PASS=FAKE_PASSWORD_HONEYPOT_1234
DB_NAME=shopzone_production
STRIPE_SECRET=sk_live_FAKE_honeypot_key_logged
STRIPE_WEBHOOK=whsec_FAKE_honeypot_logged
JWT_SECRET=FAKE_JWT_SECRET_your_ip_is_logged
ADMIN_EMAIL=admin@shopzone.com
ADMIN_PASS=FAKE_ADMIN_PASS_honeypot
REDIS_URL=redis://:FAKE_PASS@redis.internal:6379
# WARNING: This is a honeypot. All access is logged and reported."""

FAKE_CONFIG = {
    "database": {
        "host": "db.internal.shopzone.com",
        "port": 5432,
        "name": "shopzone_production",
        "user": "shopzone_prod",
        "password": "FAKE_DB_PASS_HONEYPOT"
    },
    "aws": {
        "access_key": "AKIAFAKE_HONEYPOT_KEY_1234",
        "secret_key": "FAKE/SECRET/KEY/your+ip+has+been+logged+honeypot",
        "region": "us-east-1",
        "s3_bucket": "shopzone-prod-assets"
    },
    "note": "Honeypot — your IP and all requests are logged."
}


def make_response_body(path: str, method: str, params: dict) -> tuple:
    """Returns (body_bytes, content_type, status_code)"""
    p = path.lower().rstrip("/") or "/"

    if p in ("", "/", "/index.html", "/home"):
        return SHOP_HOME.encode(), "text/html", 200

    if p in ("/login", "/signin", "/auth"):
        if method == "POST":
            time.sleep(0.3)   # fake auth delay
            return LOGIN_PAGE.encode(), "text/html", 200
        return LOGIN_PAGE.encode(), "text/html", 200

    if p.startswith("/admin"):
        return ADMIN_PAGE.encode(), "text/html", 200

    if p in ("/api/payment", "/payment/api", "/checkout/payment", "/api/stripe"):
        return json.dumps(PAYMENT_API_RESPONSE, indent=2).encode(), "application/json", 200

    if p in ("/.env", "/env", "/.env.local", "/.env.production"):
        return ENV_FILE_RESPONSE.encode(), "text/plain", 200

    if p in ("/api/config", "/config", "/api/keys", "/api/tokens"):
        return json.dumps(FAKE_CONFIG, indent=2).encode(), "application/json", 200

    if p == "/robots.txt":
        return b"User-agent: *\nDisallow: /admin\nDisallow: /api\nDisallow: /.env\n", "text/plain", 200

    if p == "/sitemap.xml":
        return b"""<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
<url><loc>http://shopzone.com/</loc></url>
<url><loc>http://shopzone.com/products</loc></url>
<url><loc>http://shopzone.com/admin</loc></url>
</urlset>""", "application/xml", 200

    if p.startswith("/api/"):
        return json.dumps({"error": "Unauthorized", "code": 401, "honeypot": True}).encode(), "application/json", 401

    # Default 404 that looks real
    body = f"""<!DOCTYPE html><html><head><title>404 — ShopZone</title></head>
<body style="font-family:Arial;text-align:center;padding:60px">
<h1 style="color:#e74c3c">404</h1><p>Page not found: {path}</p>
<a href="/">← Back to Shop</a></body></html>"""
    return body.encode(), "text/html", 404


# ── HTTP Request Handler ───────────────────────────────────────────────────

class HoneypotRequestHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        pass   # suppress default access log; we do our own

    def _get_body(self) -> str:
        length = int(self.headers.get("Content-Length", 0))
        if length:
            return self.rfile.read(min(length, 4096)).decode("utf-8", errors="replace")
        return ""

    def _headers_dict(self) -> dict:
        return {k: v for k, v in self.headers.items()}

    def _handle(self, method: str):
        ip   = self.client_address[0]
        port = self.server.server_address[1]
        path = self.path
        headers = self._headers_dict()
        body = self._get_body() if method in ("POST", "PUT", "PATCH") else ""

        parsed  = urlparse(path)
        params  = parse_qs(parsed.query)

        # Threat analysis
        result = self.server.analyser.analyse(ip, method, path, headers, body)

        # Build event
        event = ConnectionEvent(
            ip            = ip,
            port          = self.client_address[1],
            service       = self.server.service_name,
            protocol      = "http",
            timestamp     = datetime.now(timezone.utc).isoformat(),
            session_id    = str(uuid.uuid4()),
            method        = method,
            path          = path,
            user_agent    = headers.get("User-Agent", ""),
            body_snippet  = body[:200],
            threat_score  = result.score,
            severity      = result.severity,
            tags          = result.tags,
            honeypot_port = port,
        )

        self.server.store.add(event)

        log.warning(
            f"[{result.severity}] {ip} {method} {path} "
            f"score={result.score} tags={result.tags}"
        )

        # Build and send response
        body_bytes, ctype, status = make_response_body(parsed.path, method, params)
        delay = self.server.config["responses"].get("http_delay_ms", 0) / 1000
        if delay:
            time.sleep(delay)

        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body_bytes)))
        self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
        self.send_header("X-Powered-By", "PHP/7.4.3")
        self.end_headers()
        self.wfile.write(body_bytes)
        event.response_sent = True

    def do_GET(self):    self._handle("GET")
    def do_POST(self):   self._handle("POST")
    def do_PUT(self):    self._handle("PUT")
    def do_DELETE(self): self._handle("DELETE")
    def do_HEAD(self):   self._handle("HEAD")
    def do_OPTIONS(self):self._handle("OPTIONS")


class HoneypotHTTPServer(HTTPServer):
    def __init__(self, host, port, service_name, store, analyser, config):
        super().__init__((host, port), HoneypotRequestHandler)
        self.service_name = service_name
        self.store        = store
        self.analyser     = analyser
        self.config       = config
        self.timeout      = 5


def start_http_service(host: str, port: int, service_name: str,
                       store: EventStore, analyser: ThreatAnalyser,
                       config: dict) -> threading.Thread:
    server = HoneypotHTTPServer(host, port, service_name, store, analyser, config)
    t = threading.Thread(
        target=server.serve_forever,
        name=f"http-{port}",
        daemon=True,
    )
    t.start()
    log.info(f"HTTP honeypot '{service_name}' listening on {host}:{port}")
    return t
