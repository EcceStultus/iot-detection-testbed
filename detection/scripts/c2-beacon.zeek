##! c2-beacon.zeek -- detect command-and-control channels (indicator-based).
##!
##! C2 *discovery* in this suite is done by the content signatures
##! (Mirai /app/ beacon, Gafgyt PING, Mozi DHT) -- they identify the channel
##! from its payload, for every family, with no prior knowledge of the C2 host.
##!
##! This script is the indicator/behavioural confirmation layer, in the spirit
##! of Zeek's Intel framework: it flags egress that matches a known C2 indicator
##! without needing to parse the payload. Two indicators:
##!
##!   1. Known C2 port -- a connection to a port strongly associated with bot
##!      C2/backdoors (tcp/4444). Generalisable: doesn't depend on the host.
##!   2. Known C2 host -- egress to an address on the lab's C2 indicator list
##!      (10.10.10.60). Stands in for a real threat-intel feed.
##!
##! We deliberately do NOT flag "repeated egress to any external host": in this
##! testbed the DDoS phase sends to public IPs (DNS resolvers on :53/:443) at
##! volumes indistinguishable from a beacon by count alone, so a generic
##! heuristic there only adds false positives. The content signatures already
##! give precise, host-independent C2 detection.
##!
##! Kill-chain: c2 | MITRE: T1571 Non-Standard Port + T1071 App-Layer C2

@load ./main.zeek

module IoTBotnet;

global c2port_fired: set[addr, addr];
global c2host_fired: set[addr, addr];

event connection_established(c: connection)
    {
    local o = c$id$orig_h;
    local r = c$id$resp_h;

    # internal device reaching out
    if ( o !in lab_net || r in lab_net )
        return;

    # 1) known C2 port (host-independent indicator)
    if ( c$id$resp_p in known_c2_ports && [o, r] !in c2port_fired )
        {
        add c2port_fired[o, r];
        NOTICE([$note=C2_KnownPort, $conn=c,
                $msg=fmt("[c2 (T1571 Non-Standard Port)] %s connected to known botnet C2 port %s on %s",
                         o, c$id$resp_p, r),
                $identifier=fmt("c2port-%s-%s", o, r)]);
        }

    # 2) known C2 host (threat-intel indicator list)
    if ( r in c2_hosts && [o, r] !in c2host_fired )
        {
        add c2host_fired[o, r];
        NOTICE([$note=C2_Beacon, $conn=c,
                $msg=fmt("[c2 (T1071 App-Layer C2)] %s contacted known C2 host %s (intel indicator)",
                         o, r),
                $identifier=fmt("c2host-%s-%s", o, r)]);
        }
    }
