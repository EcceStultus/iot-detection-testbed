##! signatures.zeek -- turn content-signature hits into tagged Notices.
##!
##! The .sig file raises a `signature_match` event when a payload matches. Here
##! we map each signature id onto a kill-chain phase + MITRE technique and raise
##! a Notice. Notices are de-duplicated per (signature, source) so a chatty
##! match (e.g. Mirai's repeated /app/request beacons) logs once, not hundreds
##! of times.

@load base/frameworks/notice
@load ./main.zeek

module IoTBotnet;

# signature id -> (Notice::Type, human label with kill-chain + MITRE)
global sig_map: table[string] of record {
    note: Notice::Type;
    phase: string;
} = {
    ["gpon_cve_2018_10561"] = [$note=Exploit_Attempt,   $phase="exploit  (T1190 Exploit Public-Facing App)"],
    ["hnap_soap_exploit"]   = [$note=Exploit_Attempt,   $phase="exploit  (T1190 Exploit Public-Facing App)"],
    ["loader_bins_pull"]    = [$note=Loader_Pull,       $phase="loader   (T1105 Ingress Tool Transfer)"],
    ["bot_registration"]    = [$note=Bot_Registration,  $phase="register (T1071.001 Web C2)"],
    ["mirai_c2_beacon"]     = [$note=C2_Beacon,         $phase="c2       (T1071.001 Web C2)"],
    ["gafgyt_c2_ping"]      = [$note=C2_Beacon,         $phase="c2       (T1071 App-Layer C2)"],
    ["mozi_dht_announce"]   = [$note=DHT_P2P_C2,        $phase="c2       (T1090 P2P/Proxy C2)"],
};

event signature_match(state: signature_state, msg: string, data: string)
    {
    local sid = state$sig_id;
    if ( sid !in sig_map )
        return;

    local m = sig_map[sid];
    local c = state$conn;
    local src = c$id$orig_h;

    NOTICE([$note=m$note,
            $conn=c,
            $msg=fmt("[%s] %s", m$phase, msg),
            $sub=sid,
            # one notice per signature+source; default suppression handles repeats
            $identifier=fmt("%s-%s", sid, src)]);
    }
