#!/usr/bin/env python3
"""
victim_sink.py  --  controlled "patient zero" responder for the IoT testbed
============================================================================

A passive, inert stand-in for an attackable IoT device. It opens the ports the
family generators aim application-layer traffic at and gives PLAUSIBLE responses,
so the actual payloads cross a completed handshake and land in the capture:

  * TCP 23   -- a BusyBox-style telnet login (banner + `login:` / `Password:`
               prompts), so the Mirai/Gafgyt default-credential bytes AND the
               read-only BusyBox loader strings are transmitted and logged.
  * TCP 80 / 37215 / 52869 / 60001 -- minimal HTTP/SOAP responders, so the
               neutralised CVE exploit-probe bodies (Huawei/Realtek/GPON/JAWS/
               D-Link) are fully sent; known probe paths are tagged in the log.
  * UDP 6881 -- a minimal BitTorrent-DHT responder (answers ping/find_node), so
               the Mozi P2P mesh exchange is bidirectional, not one-way.

Why this exists (methodology)
-----------------------------
TCP carries no payload until the handshake completes, so firing at a CLOSED port
captures only a SYN and a refusal -- none of the credential / BusyBox / SOAP
bytes that are the whole point of a *behavioural* dataset. This sink makes those
bytes appear on the wire, reproducibly and under version control.

It is NOT a vulnerable service and NOT a honeypot: it parses nothing it is told
to execute, runs no command, and returns only fixed, inert responses. Every
connection is logged (console + JSONL, UTC) as a THIRD ground-truth source
alongside the generator's labels and the sim-C2 log.

Run it on a CONTROLLED stand-in host at an attack-target IP -- NOT on a real
Tapo/ESP32 device (those stay untouched, contributing only benign traffic). One
host can present several victim IPs via `ip addr add`, then run one sink per IP
(use --bind), or bind 0.0.0.0 to answer for all of them.

Usage
-----
  sudo python3 victim_sink.py                      # all ports, bind 0.0.0.0
  sudo python3 victim_sink.py --bind 192.168.25.50 # answer as patient zero only
  python3 victim_sink.py --no-privileged           # skip ports <1024 (no root)

  stdlib only -- no pip install required. Ctrl-C to stop.
"""
from __future__ import annotations

import argparse
import json
import random
import socket
import socketserver
import sys
import threading
from datetime import datetime, timezone

# ---- defaults ---------------------------------------------------------------
BIND = "0.0.0.0"
TELNET_PORT = 23
HTTP_PORTS = [80, 37215, 52869, 60001]   # exploit-probe endpoints are HTTP/SOAP
DHT_PORT = 6881
LOG_FILE = "victim_sink_log.jsonl"

# A BusyBox-style embedded-device login, so the telnet exchange looks genuine.
TELNET_BANNER = b"\r\n(none) login: "
TELNET_PWPROMPT = b"Password: "
TELNET_FAIL = b"\r\nLogin incorrect\r\n"

# Known exploit-probe paths -> tag, so the victim log cross-checks the generator.
EXPLOIT_PATHS = {
    "/ctrlt/DeviceUpgrade_1": "huawei-hg532-cve-2017-17215",
    "/picsdesc.xml": "realtek-sdk-cve-2014-8361",
    "/GponForm/diag_Form": "gpon-home-gateway-cve-2018-10561",
    "/shell": "jaws-dvr-webserver-rce",
    "/HNAP1/": "dlink-hnap-soapaction-rce",
    "/bins/": "loader-marker-pull",
}

_lock = threading.Lock()
_log_path = LOG_FILE


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def log_event(proto: str, peer: str, port: int, detail: str, tag: str = "") -> None:
    rec = {"ts": _now(), "proto": proto, "peer": peer, "port": port, "detail": detail}
    if tag:
        rec["tag"] = tag
    line = json.dumps(rec)
    with _lock:
        print(line, flush=True)
        try:
            with open(_log_path, "a") as fh:
                fh.write(line + "\n")
        except Exception:
            pass


def _tag_for(path: str) -> str:
    for prefix, tag in EXPLOIT_PATHS.items():
        if path.startswith(prefix) or path.split("?")[0].startswith(prefix):
            return tag
    return ""


# ---- TCP 23: BusyBox-style telnet login ------------------------------------
class _TelnetHandler(socketserver.BaseRequestHandler):
    def handle(self):
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        port = self.server.server_address[1]
        try:
            self.request.settimeout(6)
            self.request.sendall(TELNET_BANNER)
            lines = []
            # read up to a handful of lines (user, pass, then any BusyBox strings)
            for i in range(10):
                data = self.request.recv(256)
                if not data:
                    break
                text = data.decode(errors="replace").strip()
                if text:
                    lines.append(text)
                if i == 0:
                    self.request.sendall(TELNET_PWPROMPT)
                elif i == 1:
                    self.request.sendall(TELNET_FAIL)   # never grant access
            log_event("telnet", peer, port, " | ".join(lines))
        except Exception:
            log_event("telnet", peer, port, "(no data / closed)")


# ---- TCP 80 / 37215 / 52869 / 60001: HTTP + SOAP responder ------------------
class _HTTPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        port = self.server.server_address[1]
        try:
            self.request.settimeout(6)
            raw = self.request.recv(8192)
            if not raw:
                log_event("http", peer, port, "(empty)")
                return
            head, _, body = raw.partition(b"\r\n\r\n")
            # honour Content-Length so SOAP bodies are fully read
            try:
                hdrs = head.decode(errors="replace")
                clen = next((int(h.split(":", 1)[1]) for h in hdrs.split("\r\n")
                             if h.lower().startswith("content-length:")), 0)
                while len(body) < clen:
                    chunk = self.request.recv(min(8192, clen - len(body)))
                    if not chunk:
                        break
                    body += chunk
            except Exception:
                hdrs = head.decode(errors="replace")
            req_line = hdrs.split("\r\n", 1)[0]
            path = req_line.split(" ")[1] if len(req_line.split(" ")) > 1 else "/"
            tag = _tag_for(path)
            detail = req_line + (f"  body[{len(body)}]={body[:120].decode(errors='replace')}"
                                 if body else "")
            log_event("http", peer, port, detail, tag)
            resp_body = (b"testbed marker -- harmless placeholder\n"
                         if path.startswith("/bins/") else b"OK\n")
            self.request.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                b"Content-Length: " + str(len(resp_body)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n" + resp_body)
        except Exception:
            log_event("http", peer, port, "(error)")


# ---- UDP 6881: minimal BitTorrent-DHT responder -----------------------------
class _DHTHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        port = self.server.server_address[1]
        q = "find_node" if b"find_node" in data else ("ping" if b"ping" in data else "?")
        log_event("dht", peer, port, f"query={q} len={len(data)}")
        # answer so the mesh exchange is bidirectional (inert: a fixed reply)
        try:
            tid = data.split(b"1:t2:")[1][:2] if b"1:t2:" in data else b"aa"
            nid = b"TB" + bytes(random.getrandbits(8) for _ in range(18))
            resp = b"d1:rd2:id20:" + nid + b"e1:t2:" + tid + b"1:y1:re"
            sock.sendto(resp, self.client_address)
        except Exception:
            pass


# ---- threading servers ------------------------------------------------------
class _TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _UDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


def _serve(server, name):
    try:
        server.serve_forever()
    except Exception as e:
        print(f"[{name}] stopped: {e}", file=sys.stderr)


def main():
    global _log_path
    ap = argparse.ArgumentParser(description="Controlled victim responder for the IoT testbed.")
    ap.add_argument("--bind", default=BIND, help="IP to bind (default 0.0.0.0)")
    ap.add_argument("--telnet-port", type=int, default=TELNET_PORT)
    ap.add_argument("--http-ports", default=",".join(map(str, HTTP_PORTS)),
                    help="comma list of HTTP/SOAP ports")
    ap.add_argument("--dht-port", type=int, default=DHT_PORT)
    ap.add_argument("--no-privileged", action="store_true",
                    help="skip ports <1024 (run without root)")
    ap.add_argument("--log", default=LOG_FILE)
    a = ap.parse_args()
    _log_path = a.log

    http_ports = [int(p) for p in a.http_ports.split(",") if p.strip()]
    servers, skipped = [], []

    def _bind_tcp(port, handler, name):
        if a.no_privileged and port < 1024:
            skipped.append(f"{name}:{port}")
            return
        try:
            servers.append((name, _TCPServer((a.bind, port), handler)))
        except PermissionError:
            skipped.append(f"{name}:{port} (needs root)")
        except OSError as e:
            skipped.append(f"{name}:{port} ({e})")

    _bind_tcp(a.telnet_port, _TelnetHandler, "telnet")
    for p in http_ports:
        _bind_tcp(p, _HTTPHandler, "http")
    try:
        servers.append(("dht", _UDPServer((a.bind, a.dht_port), _DHTHandler)))
    except OSError as e:
        skipped.append(f"dht:{a.dht_port} ({e})")

    if not servers:
        sys.exit("No ports could be bound. Re-run with sudo, or use --no-privileged.")

    listening = ", ".join(f"{n}:{s.server_address[1]}" for n, s in servers)
    print(f"victim-sink listening on {a.bind}  [{listening}]")
    if skipped:
        print(f"  skipped: {', '.join(skipped)}")
    print(f"logging to {a.log}  (Ctrl-C to stop)")
    print("NOTE: inert responder -- plausible banners only; runs no command.\n")

    for name, srv in servers:
        threading.Thread(target=_serve, args=(srv, name), daemon=True).start()
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\nshutting down.")
        for _, srv in servers:
            try:
                srv.shutdown()
            except Exception:
                pass


if __name__ == "__main__":
    main()
