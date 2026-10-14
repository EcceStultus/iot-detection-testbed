##! main.zeek -- entry point for the IoT botnet detector.
##!
##! Load this one file and you get the whole detection suite:
##!   - content signatures  (signatures/iot-botnet.sig  -> scripts/signatures.zeek)
##!   - behavioural scripts  (recon, telnet access, C2 beacon, DDoS)
##!
##! Run over a capture:
##!   zeek -C -r capture.pcap detection/scripts/main.zeek
##!
##! (-C disables checksum verification; capture hosts often offload checksums,
##!  which otherwise makes Zeek ignore the packets.)
##!
##! All detections emit entries into notice.log with a kill-chain phase and a
##! MITRE ATT&CK technique in the message, so results map straight back onto the
##! project proposal's threat model.

@load base/frameworks/notice
@load base/frameworks/sumstats
@load base/frameworks/signatures

# Our signatures.zeek raises clean, deduplicated notices from signature_match;
# silence Zeek's built-in per-match signature notices so notice.log stays tidy.
redef Notice::ignored_types += {
    Signatures::Sensitive_Signature,
    Signatures::Multiple_Sig_Responders,
};

module IoTBotnet;

export {
    redef enum Notice::Type += {
        Recon_Sweep,        ## horizontal scan / ARP sweep of the subnet
        Telnet_Access,      ## repeated telnet (default-credential) sessions
        Exploit_Attempt,    ## GPON / HNAP exploit (from signature)
        Loader_Pull,        ## stage-2 binary download (from signature)
        Bot_Registration,   ## enrolment to C2 (from signature)
        C2_Beacon,          ## periodic check-ins to an external C2 host
        C2_KnownPort,       ## connection to a known botnet C2 port
        DHT_P2P_C2,         ## Mozi BitTorrent-DHT P2P C2 (from signature)
        DDoS_Flood,         ## high-rate flood toward a single victim
    };

    # ---- testbed scope ------------------------------------------------------
    # The lab subnet (where the IoT devices live) and the external C2 host.
    const lab_net: subnet = 192.168.25.0/24 &redef;
    const c2_hosts: set[addr] = { 10.10.10.60 } &redef;

    # Ports known to be used by the emulated C2 channels.
    const known_c2_ports: set[port] = { 4444/tcp } &redef;

    # ---- detection thresholds (all tunable with redef) ----------------------
    # Recon: a single host touching this many distinct peers = a sweep.
    const recon_distinct_hosts: count = 20 &redef;

    # Telnet: this many telnet sessions from one host = default-cred sweep.
    const telnet_conn_threshold: count = 8 &redef;

    # C2 beacon: this many connections from one internal host to one external
    # host = beaconing (real beacons repeat; one-off egress does not).
    const beacon_conn_threshold: count = 5 &redef;

    # DDoS: this many new connections toward a single victim inside one epoch.
    const ddos_conn_threshold: double = 200.0 &redef;
    const ddos_epoch: interval = 10sec &redef;
}

# ---- load the detection modules (order after the export block above) --------
@load-sigs ../signatures/iot-botnet.sig
@load ./signatures.zeek
@load ./recon.zeek
@load ./telnet-access.zeek
@load ./c2-beacon.zeek
@load ./ddos.zeek
