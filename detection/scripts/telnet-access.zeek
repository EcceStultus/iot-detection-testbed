##! telnet-access.zeek -- detect the default-credential access phase.
##!
##! Mirai/Gafgyt gain a foothold by hammering telnet (tcp/23) with a built-in
##! default-credential list. The credential *payloads* are not in our captures
##! (the emulator opens the sessions but doesn't transmit the word list in
##! cleartext), and nothing completes a handshake (the ESP victims RST), so this
##! is a behavioural detector.
##!
##! The subtlety: the DDoS phase is multi-vector and also sends SYNs to tcp/23
##! on the flood victim -- so a naive "count telnet SYNs" fires on the flood.
##! The discriminator is the port *mix* per destination:
##!   - a brute-force victim receives SYNs almost entirely on telnet ports
##!     (observed: 0.9-1.0 of inbound SYNs), while
##!   - a flood victim receives SYNs spread across many ports (observed ~0.33 on
##!     telnet, the rest on 80/1883/...).
##! So we flag a destination only when telnet is the dominant port AND the count
##! clears the threshold. This cleanly separates access from the DDoS and
##! correctly stays silent on Mozi, which has no telnet phase.
##!
##! Kill-chain: access | MITRE: T1110.001 Brute Force: Password Guessing
##!                            + T1078.001 Valid Accounts: Default Accounts

@load ./main.zeek

module IoTBotnet;

# telnet/alt-telnet ports the botnets brute
const telnet_ports: set[port] = { 23/tcp, 2323/tcp } &redef;
# fraction of a destination's inbound SYNs that must be telnet to count as brute
const telnet_dominance: double = 0.8 &redef;

global tel_syn:   table[addr] of count &default=0;   # telnet SYNs per dst
global tot_syn:   table[addr] of count &default=0;   # all SYNs per dst
global tel_fired: set[addr];

event new_connection(c: connection)
    {
    local d = c$id$resp_h;
    tot_syn[d] += 1;
    if ( c$id$resp_p in telnet_ports )
        tel_syn[d] += 1;

    if ( d in tel_fired )
        return;
    if ( tel_syn[d] < telnet_conn_threshold )
        return;
    if ( tot_syn[d] > 0 && (tel_syn[d] + 0.0) / tot_syn[d] >= telnet_dominance )
        {
        add tel_fired[d];
        NOTICE([$note=Telnet_Access, $src=c$id$orig_h, $dst=d,
                $msg=fmt("[access (T1110.001 Password Guessing / T1078.001 Default Accounts)] telnet default-credential sweep: %s hit %s with %d telnet connection attempts (%.0f%% of its inbound SYNs)",
                         c$id$orig_h, d, tel_syn[d], 100.0 * tel_syn[d] / tot_syn[d]),
                $identifier=fmt("telnet-%s", d)]);
        }
    }
