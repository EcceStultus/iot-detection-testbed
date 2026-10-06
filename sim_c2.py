#!/usr/bin/env python3
"""
sim_c2.py  --  passive C2 sink for the IoT botnet emulator testbed
==================================================================

This is NOT command-and-control infrastructure. It is a passive listener that
stands in for the "C2" endpoint the emulator (iot_botnet_emulator.py) beacons
to, so that:

  * the emulated HTTP register / gate.php callbacks get a 200 response,
  * the raw TCP and UDP heartbeats have something that accepts them,
  * the loader's "payload pull" of /bins/marker.txt returns a harmless file,

...which makes the beacon/registration/loader signatures complete and realistic
on the wire. It issues NO real commands and controls NOTHING -- the emulator
ignores the responses anyway. Every connection is logged (console + JSONL) with
a UTC timestamp, so this log is a handy second ground-truth source alongside the
emulator's own labels.

Run it on the host you set as SIM_C2 in the emulator config -- a SEPARATE box
from the gateway (ideally on the WAN side of the Pi, so the beacon crosses the
egress boundary).

Usage
-----
  # defaults: HTTP :80, TCP :4444, UDP :4445  (port 80 needs root)
  sudo python3 sim_c2.py

  # no root? use a high HTTP port and set C2_HTTP_PORT to match in the emulator
  python3 sim_c2.py --http-port 8080

  stdlib only -- no pip install required. Ctrl-C to stop.
"""
from __future__ import annotations

import argparse
import http.server
import json
import socketserver
import sys
import threading
from datetime import datetime, timezone

# ---- defaults (override on the command line) --------------------------------
HTTP_PORT = 80
TCP_PORT = 4444
UDP_PORT = 4445
BIND = "0.0.0.0"
LOG_FILE = "sim_c2_log.jsonl"
MARKER_BODY = b"testbed marker file -- harmless placeholder, not a payload\n"
# Inert placeholder returned on gate.php callbacks, purely to put some bytes on
# the response leg so it resembles C2 tasking. It is never a real instruction;
# the emulator does not read or act on it.
GATE_BODY = b"NOP\n"

_lock = threading.Lock()
_log_path = LOG_FILE


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def log_event(proto: str, peer: str, detail: str) -> None:
    rec = {"ts": _now(), "proto": proto, "peer": peer, "detail": detail}
    line = json.dumps(rec)
    with _lock:
        print(line, flush=True)
        try:
            with open(_log_path, "a") as fh:
                fh.write(line + "\n")
        except Exception:
            pass


# ---- HTTP: register / gate.php / marker -------------------------------------
class _HTTPHandler(http.server.BaseHTTPRequestHandler):
    def _handle(self):
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        log_event("http", peer, f"{self.command} {self.path}")
        if self.path.startswith("/bins/"):
            body = MARKER_BODY
        elif self.path.startswith("/gate"):
            body = GATE_BODY
        else:
            body = b"OK\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    do_GET = _handle
    do_POST = _handle

    def log_message(self, *a):   # silence the default stderr spew; we log our own
        pass


class _ThreadingHTTP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


# ---- raw TCP heartbeat sink -------------------------------------------------
class _TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        try:
            data = self.request.recv(4096)
        except Exception:
            data = b""
        log_event("tcp", peer, data.decode(errors="replace").strip())


class _ThreadingTCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


# ---- raw UDP heartbeat sink -------------------------------------------------
class _UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0]
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        log_event("udp", peer, data.decode(errors="replace").strip())


class _ThreadingUDP(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


def _serve(server, name: str):
    try:
        server.serve_forever()
    except Exception as e:
        print(f"[{name}] stopped: {e}", file=sys.stderr)


def main():
    global _log_path
    ap = argparse.ArgumentParser(description="Passive C2 sink for the IoT emulator testbed.")
    ap.add_argument("--bind", default=BIND)
    ap.add_argument("--http-port", type=int, default=HTTP_PORT)
    ap.add_argument("--tcp-port", type=int, default=TCP_PORT)
    ap.add_argument("--udp-port", type=int, default=UDP_PORT)
    ap.add_argument("--log", default=LOG_FILE)
    a = ap.parse_args()
    _log_path = a.log

    servers = []
    try:
        http_srv = _ThreadingHTTP((a.bind, a.http_port), _HTTPHandler)
        servers.append(("http", http_srv))
    except PermissionError:
        sys.exit(f"Cannot bind HTTP port {a.http_port} (needs root). "
                 f"Re-run with sudo, or use --http-port 8080 and set C2_HTTP_PORT "
                 f"to match in the emulator config.")
    except OSError as e:
        sys.exit(f"Cannot bind HTTP port {a.http_port}: {e}")

    try:
        servers.append(("tcp", _ThreadingTCP((a.bind, a.tcp_port), _TCPHandler)))
        servers.append(("udp", _ThreadingUDP((a.bind, a.udp_port), _UDPHandler)))
    except OSError as e:
        sys.exit(f"Cannot bind TCP/UDP port: {e}")

    print(f"sim-C2 sink listening on {a.bind}  "
          f"HTTP:{a.http_port}  TCP:{a.tcp_port}  UDP:{a.udp_port}")
    print(f"logging to {a.log}  (Ctrl-C to stop)")
    print("NOTE: passive sink -- accepts and logs beacons; issues no commands.\n")

    for name, srv in servers:
        threading.Thread(target=_serve, args=(srv, name), daemon=True).start()

    try:
        threading.Event().wait()          # block until Ctrl-C
    except KeyboardInterrupt:
        print("\nshutting down.")
        for _, srv in servers:
            try:
                srv.shutdown()
            except Exception:
                pass


if __name__ == "__main__":
    main()
