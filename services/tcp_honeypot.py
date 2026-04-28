"""
services/tcp_honeypot.py
Raw TCP honeypot services for FTP, SSH, and MySQL protocols.
"""

import socket
import threading
import uuid
from datetime import datetime, timezone

from core.event_store     import EventStore, ConnectionEvent
from core.threat_analyser import ThreatAnalyser
from utils.logger          import get_logger

log = get_logger("tcp_honeypot")


def _make_event(ip, port, service, protocol, honeypot_port,
                tags=None, score=0, severity="LOW") -> ConnectionEvent:
    return ConnectionEvent(
        ip            = ip,
        port          = port,
        service       = service,
        protocol      = protocol,
        timestamp     = datetime.now(timezone.utc).isoformat(),
        session_id    = str(uuid.uuid4()),
        threat_score  = score,
        severity      = severity,
        tags          = tags or [],
        honeypot_port = honeypot_port,
    )


def safe_recv(conn, bufsize=1024, timeout=5.0):
    conn.settimeout(timeout)
    try:
        return conn.recv(bufsize)
    except (socket.timeout, ConnectionResetError, OSError):
        return b""


def safe_send(conn, data):
    try:
        conn.sendall(data)
        return True
    except (BrokenPipeError, ConnectionResetError, OSError):
        return False


# ── FTP ────────────────────────────────────────────────────────────────────

FTP_BANNER    = b"220 ProFTPD 1.3.5e Server (ShopZone FTP) [::ffff:192.168.1.10]\r\n"
FTP_AUTH_FAIL = b"530 Login incorrect.\r\n"
FTP_PASV      = b"227 Entering Passive Mode (192,168,1,10,200,80).\r\n"
FTP_LIST      = b"150 Opening ASCII mode data connection for file list\r\n"


def handle_ftp(conn, addr, store, analyser, service_cfg):
    ip, port = addr
    event = _make_event(ip, port, service_cfg["name"], "ftp", service_cfg["port"])
    captured = {"user": "", "pass": ""}
    try:
        safe_send(conn, FTP_BANNER)
        event.tags.append("ftp_probe")
        while True:
            data = safe_recv(conn)
            if not data:
                break
            line = data.decode("utf-8", errors="replace").strip()
            cmd  = line.upper()
            if cmd.startswith("USER"):
                user = line[5:].strip()
                captured["user"] = user
                safe_send(conn, ("331 Password required for " + user + "\r\n").encode())
            elif cmd.startswith("PASS"):
                pw = line[5:].strip()
                captured["pass"] = pw
                event.body_snippet = "USER=" + captured["user"] + " PASS=" + pw
                event.tags.append("ftp_credentials(user=" + captured["user"] + ")")
                event.threat_score += 40
                event.severity = "HIGH"
                log.warning("[FTP] " + ip + " credential attempt: user=" + captured["user"] + " pass=" + pw)
                safe_send(conn, FTP_AUTH_FAIL)
            elif cmd.startswith("PASV"):
                safe_send(conn, FTP_PASV)
            elif cmd.startswith("LIST") or cmd.startswith("NLST"):
                safe_send(conn, FTP_LIST)
                event.tags.append("ftp_directory_listing")
                event.threat_score += 15
            elif cmd.startswith("RETR"):
                filename = line[5:].strip()
                event.tags.append("ftp_file_download_attempt(" + filename + ")")
                event.threat_score += 30
                safe_send(conn, b"550 Permission denied.\r\n")
            elif cmd.startswith("QUIT"):
                safe_send(conn, b"221 Goodbye.\r\n")
                break
            else:
                safe_send(conn, b"500 Unknown command.\r\n")
        event.response_sent = True
    except Exception as e:
        log.debug("[FTP] " + ip + " error: " + str(e))
    finally:
        event.tags = list(set(event.tags))
        store.add(event)
        conn.close()


# ── SSH ────────────────────────────────────────────────────────────────────

SSH_BANNER = b"SSH-2.0-OpenSSH_7.4p1 Ubuntu-10+deb9u7\r\n"


def handle_ssh(conn, addr, store, analyser, service_cfg):
    ip, port = addr
    event = _make_event(ip, port, service_cfg["name"], "ssh", service_cfg["port"],
                        tags=["ssh_probe"], score=20, severity="MEDIUM")
    try:
        safe_send(conn, SSH_BANNER)
        data = safe_recv(conn, bufsize=512, timeout=8)
        if data:
            client_banner = data.decode("utf-8", errors="replace").strip()
            event.body_snippet = client_banner[:200]
            for sc in ["masscan", "libssh", "paramiko", "putty", "ncrack"]:
                if sc.lower() in client_banner.lower():
                    event.tags.append("ssh_scanner(" + sc + ")")
                    event.threat_score += 30
                    event.severity = "HIGH"
            log.warning("[SSH] " + ip + " client banner: " + client_banner[:80])
        event.response_sent = True
    except Exception as e:
        log.debug("[SSH] " + ip + " error: " + str(e))
    finally:
        store.add(event)
        conn.close()


# ── MySQL ──────────────────────────────────────────────────────────────────

MYSQL_GREETING = (
    b"\x4a\x00\x00\x00"
    b"\x0a"
    b"5.7.34-log\x00"
    b"\x01\x00\x00\x00"
    b"\x52\x42\x33\x4a\x48\x57\x72\x33\x00"
    b"\xff\xf7"
    b"\x21"
    b"\x02\x00"
    b"\xff\x81"
    b"\x15"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x7a\x51\x67\x61\x44\x69\x49\x55\x34\x37\x4c\x6c\x00"
    b"mysql_native_password\x00"
)

MYSQL_AUTH_FAIL = (
    b"\x23\x00\x00\x02"
    b"\xff"
    b"\x15\x04"
    b"#28000"
    b"Access denied for user 'root'@'client' (using password: YES)"
)


def handle_mysql(conn, addr, store, analyser, service_cfg):
    ip, port = addr
    event = _make_event(ip, port, service_cfg["name"], "mysql", service_cfg["port"],
                        tags=["mysql_probe"], score=35, severity="HIGH")
    try:
        safe_send(conn, MYSQL_GREETING)
        data = safe_recv(conn, bufsize=256, timeout=8)
        if data:
            event.body_snippet = data.hex()[:200]
            try:
                ascii_parts = [c for c in data[36:] if 32 <= c < 127]
                username = "".join(chr(c) for c in ascii_parts).split("\x00")[0]
                if username:
                    event.tags.append("mysql_auth_attempt(user=" + username + ")")
                    event.threat_score += 25
                    log.warning("[MySQL] " + ip + " auth attempt user: " + username)
            except Exception:
                pass
        safe_send(conn, MYSQL_AUTH_FAIL)
        event.response_sent = True
        event.severity = "HIGH"
    except Exception as e:
        log.debug("[MySQL] " + ip + " error: " + str(e))
    finally:
        store.add(event)
        conn.close()


# ── Generic TCP listener ───────────────────────────────────────────────────

PROTOCOL_HANDLERS = {
    "ftp":   handle_ftp,
    "ssh":   handle_ssh,
    "mysql": handle_mysql,
}


def tcp_listener(host, service_cfg, store, analyser):
    port     = service_cfg["port"]
    protocol = service_cfg["protocol"]
    handler  = PROTOCOL_HANDLERS.get(protocol)
    if not handler:
        return

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((host, port))
    server_sock.listen(50)
    server_sock.settimeout(1.0)
    log.info("TCP honeypot '" + service_cfg["name"] + "' (" + protocol.upper() + ") listening on " + host + ":" + str(port))

    while True:
        try:
            conn, addr = server_sock.accept()
            t = threading.Thread(
                target=handler,
                args=(conn, addr, store, analyser, service_cfg),
                daemon=True,
            )
            t.start()
        except socket.timeout:
            continue
        except OSError:
            break


def start_tcp_service(host, service_cfg, store, analyser):
    t = threading.Thread(
        target=tcp_listener,
        args=(host, service_cfg, store, analyser),
        name="tcp-" + str(service_cfg["port"]),
        daemon=True,
    )
    t.start()
    return t
