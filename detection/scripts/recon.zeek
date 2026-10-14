##! recon.zeek -- detect the reconnaissance phase (network sweep).
##!
##! The loader's first move is to map the subnet. In our captures this shows up
##! two ways, and we catch both:
##!
##!   1. ARP sweep -- the host ARP-who-has's the entire /24 (observed: 256
##!      distinct targets for Mirai & Gafgyt). Caught via arp_request. Note that
##!      ARP events only fire if the capture retained L2 frames; the SYN-scan
##!      detector below is the reliable fallback.
##!
##!   2. Horizontal SYN scan -- SYNs to many distinct hosts that mostly don't
##!      answer. Caught via connection_attempt (a SYN with no completed
##!      handshake), counting distinct responders per originator.
##!
##! Kill-chain: recon | MITRE: T1046 Network Service Discovery

@load ./main.zeek

module IoTBotnet;

# ---- SYN horizontal scan ----------------------------------------------------
global scan_targets: table[addr] of set[addr];
global scan_fired: set[addr];

event connection_attempt(c: connection)
    {
    local o = c$id$orig_h;
    local r = c$id$resp_h;

    if ( o in scan_fired )
        return;
    if ( o !in scan_targets )
        scan_targets[o] = set();
    add scan_targets[o][r];

    if ( |scan_targets[o]| >= recon_distinct_hosts )
        {
        add scan_fired[o];
        NOTICE([$note=Recon_Sweep, $src=o,
                $msg=fmt("[recon (T1046 Network Service Discovery)] horizontal scan: %s sent SYNs to %d distinct hosts",
                         o, |scan_targets[o]|),
                $identifier=fmt("recon-syn-%s", o)]);
        }
    }

# ---- ARP sweep (best-effort; depends on L2 being present in the pcap) --------
global arp_targets: table[addr] of set[addr];
global arp_fired: set[addr];

event arp_request(mac_src: string, mac_dst: string, SPA: addr, SHA: string,
                  TPA: addr, THA: string)
    {
    if ( SPA in arp_fired )
        return;
    if ( SPA !in arp_targets )
        arp_targets[SPA] = set();
    add arp_targets[SPA][TPA];

    if ( |arp_targets[SPA]| >= recon_distinct_hosts )
        {
        add arp_fired[SPA];
        NOTICE([$note=Recon_Sweep, $src=SPA,
                $msg=fmt("[recon (T1046 Network Service Discovery)] ARP sweep: %s probed %d distinct addresses (full-subnet enumeration)",
                         SPA, |arp_targets[SPA]|),
                $identifier=fmt("recon-arp-%s", SPA)]);
        }
    }
