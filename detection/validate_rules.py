#!/usr/bin/env python3
"""
validate_rules.py -- replay pcaps through the SAME logic the Zeek rules use.

This is a verification harness, not the detector. It mirrors, packet-for-packet,
the content signatures in signatures/iot-botnet.sig and the behavioural
thresholds in scripts/main.zeek, so we can confirm every rule fires on the real
captures and produce the detection table for the report. The authoritative run
is `zeek -C -r <pcap> scripts/main.zeek` on a host with Zeek installed.
"""
import sys, re
from scapy.all import PcapReader, IP, TCP, UDP, Raw, ARP

LAB_NET = "192.168.25."
C2_HOSTS = {"10.10.10.60"}
KNOWN_C2_PORTS = {4444}
RECON_DISTINCT = 20
TELNET_THRESH = 8
BEACON_THRESH = 5
DDOS_THRESH = 200
DDOS_EPOCH = 10.0

# content signatures (mirror of the .sig file)
HTTP_SIGS = {
    "gpon_cve_2018_10561": re.compile(rb"/GponForm/diag_Form"),
    "hnap_soap_exploit":   re.compile(rb"/HNAP1/"),
    "loader_bins_pull":    re.compile(rb"GET\s+/bins/"),
    "bot_registration":    re.compile(rb"/register\?id=.*fam="),
    "mirai_c2_beacon":     re.compile(rb"/app/(handshake|request)"),
}
PAYLOAD_SIGS = {
    "gafgyt_c2_ping":   re.compile(rb"^(PING|PONG)\x0a"),
    "mozi_dht_announce":re.compile(rb"^d1:ad2:id20:"),
}

def is_lab(ip): return ip.startswith(LAB_NET)

def analyse(fam, pcap):
    sig_hits = {k: 0 for k in list(HTTP_SIGS) + list(PAYLOAD_SIGS)}
    scan_targets = {}            # orig -> set(resp)   (SYN no-ACK)
    arp_targets = {}             # spa -> set(tpa)
    tel_syn = {}                 # dst -> telnet SYN count
    tot_syn = {}                 # dst -> all SYN count
    c2port = set()               # (orig,resp) flagged known-port
    c2host = set()               # (orig,resp) known C2 host
    ddos_events = []             # (time, victim)
    syn_seen = set()             # dedupe scan per (o,r)
    TELNET_PORTS = {23, 2323}
    TELNET_DOMINANCE = 0.8

    for pk in PcapReader(pcap):
        if ARP in pk and pk[ARP].op == 1:
            spa, tpa = pk[ARP].psrc, pk[ARP].pdst
            arp_targets.setdefault(spa, set()).add(tpa)
        if IP not in pk:
            continue
        src, dst, t = pk[IP].src, pk[IP].dst, float(pk.time)

        # content signatures
        if Raw in pk:
            pl = bytes(pk[Raw].load)
            for name, rx in PAYLOAD_SIGS.items():
                if rx.search(pl): sig_hits[name] += 1
            # http-request: match the request line
            if pl[:8].split(b" ")[0] in (b"GET", b"POST", b"HEAD", b"PUT"):
                line = pl.split(b"\r\n", 1)[0]
                for name, rx in HTTP_SIGS.items():
                    if rx.search(line): sig_hits[name] += 1

        if TCP in pk:
            fl = int(pk[TCP].flags)
            sport, dport = int(pk[TCP].sport), int(pk[TCP].dport)
            syn, ack = bool(fl & 0x02), bool(fl & 0x10)
            # ddos: count every new connection (first SYN) keyed by victim
            if syn and not ack:
                key = (src, sport, dst, dport)
                if key not in syn_seen:
                    syn_seen.add(key)
                    ddos_events.append((t, dst))
                    scan_targets.setdefault(src, set()).add(dst)
                    # telnet: telnet-SYN vs total-SYN per dst
                    tot_syn[dst] = tot_syn.get(dst, 0) + 1
                    if dport in TELNET_PORTS:
                        tel_syn[dst] = tel_syn.get(dst, 0) + 1
            # c2: internal->external, known-indicator match
            if is_lab(src) and not is_lab(dst):
                if dport in KNOWN_C2_PORTS:
                    c2port.add((src, dst))
                if dst in C2_HOSTS:
                    c2host.add((src, dst))

    # ddos: max connections to a single victim in any DDOS_EPOCH window
    ddos_events.sort()
    worst = {}
    from collections import deque, defaultdict
    byv = defaultdict(list)
    for t, v in ddos_events: byv[v].append(t)
    ddos_fire = {}
    for v, ts in byv.items():
        ts.sort(); dq = deque(); mx = 0
        for t in ts:
            dq.append(t)
            while dq and t - dq[0] > DDOS_EPOCH: dq.popleft()
            mx = max(mx, len(dq))
        if mx >= DDOS_THRESH:
            ddos_fire[v] = mx

    # ---- report ----
    print(f"\n################  {fam}  ################")
    print("CONTENT SIGNATURES (packets matched):")
    for k, v in sig_hits.items():
        mark = "FIRES" if v else "  -  "
        print(f"   [{mark}] {k:22s} {v}")
    print("BEHAVIOURAL:")
    # recon
    rc = {o: len(s) for o, s in scan_targets.items() if len(s) >= RECON_DISTINCT}
    ar = {o: len(s) for o, s in arp_targets.items() if len(s) >= RECON_DISTINCT}
    print(f"   [{'FIRES' if rc else '  -  '}] recon SYN-scan   "
          + (", ".join(f"{o}->{n} hosts" for o, n in rc.items()) or "below threshold"))
    print(f"   [{'FIRES' if ar else '  -  '}] recon ARP-sweep  "
          + (", ".join(f"{o}->{n} addrs" for o, n in ar.items()) or "no ARP / below threshold"))
    tf = {d: tel_syn[d] for d in tel_syn
          if tel_syn[d] >= TELNET_THRESH
          and tot_syn.get(d, 0) > 0
          and tel_syn[d] / tot_syn[d] >= TELNET_DOMINANCE}
    print(f"   [{'FIRES' if tf else '  -  '}] telnet access    "
          + (", ".join(f"victim {d}: {n} telnet SYNs ({100*n/tot_syn[d]:.0f}% of inbound)"
                       for d, n in tf.items()) or "below threshold / no dominant-telnet host"))
    c2 = (", ".join(f"{o}->{d} (port4444)" for o, d in c2port)
          + ("  " if c2port and c2host else "")
          + ", ".join(f"{o}->{d} (intel host)" for o, d in c2host))
    print(f"   [{'FIRES' if (c2port or c2host) else '  -  '}] c2 indicator     "
          + (c2 or "no indicator match"))
    print(f"   [{'FIRES' if ddos_fire else '  -  '}] ddos flood       "
          + (", ".join(f"victim {v}: {n} conns/10s" for v, n in ddos_fire.items()) or "below threshold"))

if __name__ == "__main__":
    fams = dict(zip(["Mirai", "Gafgyt", "Mozi"], sys.argv[1:4]))
    for fam, p in fams.items():
        analyse(fam, p)
