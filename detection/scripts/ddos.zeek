##! ddos.zeek -- detect the DDoS phase (high-rate flood to a single victim).
##!
##! The final kill-chain phase is the attack itself: the bot floods a victim
##! (in our testbed, the ESP32 sensor at 192.168.25.15) with thousands of
##! SYN/UDP packets. We count new connections per victim inside a short time
##! window with the SumStats framework; crossing the threshold raises a Notice.
##!
##! Keying on the *victim* (resp_h) means a distributed flood from many sources
##! still trips the same victim key -- which is the point of a DDoS detector.
##! SumStats gives us the real metric for the report: flows-per-window, i.e. the
##! attack rate.
##!
##! Kill-chain: ddos | MITRE: T1498 Network DoS / T1499 Endpoint DoS

@load base/frameworks/sumstats
@load ./main.zeek

module IoTBotnet;

event zeek_init()
    {
    local r = SumStats::Reducer($stream="iot.ddos",
                                $apply=set(SumStats::SUM));

    SumStats::create([$name="iot-ddos-detect",
        $epoch=ddos_epoch,
        $reducers=set(r),
        $threshold=ddos_conn_threshold,
        $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
            {
            return result["iot.ddos"]$sum;
            },
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local victim = to_addr(key$str);
            local n = result["iot.ddos"]$sum;
            NOTICE([$note=DDoS_Flood, $dst=victim,
                    $msg=fmt("[ddos (T1498/T1499 Network/Endpoint DoS)] flood: %.0f connections to victim %s within a %s window (rate ~%.0f conn/s)",
                             n, victim, ddos_epoch, n / interval_to_double(ddos_epoch)),
                    $identifier=fmt("ddos-%s", victim)]);
            }]);
    }

# count every new connection, keyed by the destination (victim)
event new_connection(c: connection)
    {
    SumStats::observe("iot.ddos",
                      SumStats::Key($str=cat(c$id$resp_h)),
                      SumStats::Observation($num=1));
    }
