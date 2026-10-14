# =============================================================================
# iot-botnet.sig  --  content / payload signatures for IoT botnet traffic
# =============================================================================
# Zeek signature-framework rules. Each one matches a distinctive byte-string
# that one of the three emulated families (Mirai / Gafgyt / Mozi) actually puts
# on the wire in our testbed captures. Every regex below was confirmed present
# in the Oct-08 pcaps before being written -- none are speculative.
#
# A match raises a `signature_match` event; scripts/signatures.zeek turns that
# into a Notice tagged with the kill-chain phase and the MITRE ATT&CK technique.
#
# Load with:  @load-sigs ./signatures/iot-botnet.sig   (done in scripts/main.zeek)
# or on the CLI:  zeek -r capture.pcap -s signatures/iot-botnet.sig
# =============================================================================


# --- EXPLOIT -----------------------------------------------------------------
# GPON home-router RCE, CVE-2018-10561/10562. A staple IoT-botnet spreader
# vector. Gafgyt and Mozi both POST this exact form path.
# Kill-chain: exploit | MITRE: T1190 Exploit Public-Facing Application
signature gpon_cve_2018_10561 {
    ip-proto == tcp
    http-request /.*\/GponForm\/diag_Form/
    event "EXPLOIT GPON CVE-2018-10561 diag_Form RCE attempt"
}

# D-Link HNAP1 SOAPAction abuse -- another common botnet propagation vector.
# Kill-chain: exploit | MITRE: T1190
signature hnap_soap_exploit {
    ip-proto == tcp
    http-request /.*\/HNAP1\//
    event "EXPLOIT D-Link HNAP1 SOAP endpoint access"
}


# --- LOADER ------------------------------------------------------------------
# After access, the loader pulls an architecture-specific binary from a
# "bins" server. Real Mirai does GET /bins/<arch>; our Mirai pulls
# /bins/marker.txt and Mozi pulls /bins/config.bin.
# Kill-chain: loader | MITRE: T1105 Ingress Tool Transfer
signature loader_bins_pull {
    ip-proto == tcp
    http-request /.*\/bins\//
    event "LOADER HTTP binary pull from /bins/ (stage-2 download)"
}


# --- REGISTER ----------------------------------------------------------------
# Bot announces itself to the C2 with id/arch/version/family. Mirai does
# GET /register?id=...&arch=...&fam=mirai.
# Kill-chain: register | MITRE: T1071.001 Application Layer Protocol: Web
signature bot_registration {
    ip-proto == tcp
    http-request /.*\/register\?id=.*fam=/
    event "REGISTER bot check-in / enrolment to C2"
}


# --- C2 ----------------------------------------------------------------------
# Mirai periodic beacon: repeated POSTs to /app/handshake* and /app/request?seq=
# on a fixed cadence -- the heartbeat that keeps the bot enrolled.
# Kill-chain: c2 | MITRE: T1071.001
signature mirai_c2_beacon {
    ip-proto == tcp
    http-request /.*\/app\/(handshake|request)/
    event "C2 Mirai periodic /app/ beacon (heartbeat)"
}

# Gafgyt plaintext keep-alive. The bot sends the literal token PING to the C2
# on tcp/4444 and the C2 replies PONG. Distinctive and plaintext.
# Kill-chain: c2 | MITRE: T1071 Application Layer Protocol
signature gafgyt_c2_ping {
    ip-proto == tcp
    payload /^(PING|PONG)\x0a/
    event "C2 Gafgyt plaintext PING/PONG keep-alive"
}

# Mozi uses the public BitTorrent DHT as its P2P C2. DHT query packets are
# bencoded and start with d1:ad2:id20: (dict -> 'a' args -> 20-byte node id).
# Seen on udp/6881.
# Kill-chain: c2 (dht_beacon) | MITRE: T1090 Proxy / P2P
signature mozi_dht_announce {
    ip-proto == udp
    payload /^d1:ad2:id20:/
    event "C2 Mozi BitTorrent-DHT bencode query (P2P botnet node)"
}
