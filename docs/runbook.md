# Runbook — generating a labelled capture

> The operational procedure for a live run: prerequisites, the exact run order
> across the three machines, where the artifacts land, how to inspect them, and
> every gotcha we hit (with the fix). Pair with [`network-setup.md`](network-setup.md)
> for the topology/addressing.

## Roles

| Machine | Role | Runs |
|---|---|---|
| **MacBook** | attacker | the generators (`iot_family_profiles.py`) |
| **Lab PC** (Ubuntu) | sim-C2, on the isolated WAN segment | `sim_c2.py` |
| **Raspberry Pi** "edge" | gateway / AP / capture | `capture.sh` |

The lab is **isolated from the internet**, which drives several of the steps
below (offline dependency handling, manual clock sync).

## One-time setup

**MacBook** (needs internet once; the venv then works offline):
```bash
python3 -m venv ~/iot-venv
~/iot-venv/bin/pip install scapy paho-mqtt dnspython
brew install nmap            # recon uses nmap; the scapy fallback is far slower
```

**Transfer the scripts** (the lab has no internet, so copy over the local links):
```bash
# sim_c2.py -> PC (over the 10.10.10.x link; scp if the PC runs sshd, else nc/USB)
scp sim_c2.py <pcuser>@10.10.10.60:~/
# capture.sh -> Pi (over the hotspot)
scp capture.sh group@192.168.25.1:~/
```
If the PC has no SSH server (can't `apt install` offline), use netcat:
`nc -l -p 9000 > sim_c2.py` on the PC, `nc 10.10.10.60 9000 < sim_c2.py` on the Mac.

**Pi network** (WAN link + routing + NAT): see [`network-setup.md`](network-setup.md) §3.

## Before every run

1. **Mac on the lab hotspot** (not normal Wi-Fi — the venv/nmap are already cached).
2. **Sync the Pi clock.** The Pi has no RTC and no internet NTP, so it boots with
   the wrong time — which breaks the label↔PCAP join. On the Mac:
   ```bash
   date -u "+%Y-%m-%d %H:%M:%S"
   ```
   On the Pi:
   ```bash
   sudo timedatectl set-ntp false
   sudo date -u -s "PASTE-THE-MAC-UTC-VALUE"
   ```
3. **Confirm isolation.** On the Pi, `ip route` should show **no `default` line**.
4. **Pick a live DDoS target.** On the Pi:
   ```bash
   ip neigh show dev wlan0
   ```
   Choose a REACHABLE/STALE device that is **not** the Pi (`.1`) or the Mac, and
   make sure `DDOS_TARGET` in `iot_family_profiles.py` points at it (currently the
   ESP32 at `.15`). A flood at an offline host produces almost no packets.

## Run order

```bash
# ── Pi ── start capture FIRST
sudo ./capture.sh wlan0 10.10.10.60            # leave running

# ── PC ── start the C2 sink (bind to the lab IP only)
sudo python3 sim_c2.py --bind 10.10.10.60

# ── Mac ── fire a family (sudo for the scapy recon/ddos phases)
sudo ~/iot-venv/bin/python3 iot_family_profiles.py run mirai --fire
#   dry-run first (no sudo) to preview:  ~/iot-venv/bin/python3 iot_family_profiles.py run mirai

# ── Pi ── once the Mac prints "done.", Ctrl-C the capture
```

Timing: `recon` is seconds (nmap), the `c2` beacon phase runs ~5 min, so a full
chain is ~6–8 min. A clean Ctrl-C of the generator still writes its labels but
skips remaining phases.

Phase subsets are handy for targeted captures:
```bash
... run gafgyt --phases access,exploit,register,c2 --fire   # no scapy needed
... run mozi   --phases config_pull,dht_join,dht_beacon --fire
```

## Artifacts (three ground-truth sources, joined on UTC time)

| Host | Path | Contents |
|---|---|---|
| Pi | `captures/cap_<ts>/lab_*.pcap` | the capture (+ `capture_meta.json`, `SHA256SUMS`, `capture_end.json`) |
| Mac | `runs/<run_id>/run_*_labels.csv` / `.jsonl` / `_manifest.json` | per-phase ground-truth labels (family, technique, ATT&CK, src/dst, UTC + monotonic times) |
| PC | `sim_c2_log.jsonl` | every C2 connection received (secondary cross-check) |

## Inspecting a capture

`tcpdump -r` reads **one** file — don't glob multiple pcaps into it. Pick the newest:
```bash
f=$(ls -t captures/cap_*/lab_*.pcap | head -1); echo "$f"
sudo tcpdump -nr "$f" | wc -l
sudo tcpdump -nr "$f" | head -40
# e.g. just the C2 traffic:
sudo tcpdump -nr "$f" host 10.10.10.60
```

## Gotchas we hit (and the fix)

| Symptom | Cause | Fix |
|---|---|---|
| `uv run` hangs on "resolving dependencies" | lab has no internet; uv can't reach PyPI | use the pre-built `~/iot-venv`; for stdlib-only phases, plain `python3` works |
| `recon` runs ~14 min, floods "Using broadcast" | scapy SYN-sweeping 254 mostly-dead IPs | install `nmap` (script prefers it); warnings now silenced anyway |
| `ddos` dns vector: `KeyError: 'ANY'` | scapy ≥2.8 dropped the `"ANY"` qtype string | fixed in code — uses numeric `255` |
| `ddos` sends ~4 packets/8s | the DDoS target is offline (ARP fails) | point `DDOS_TARGET` at a live host; code now warns up front |
| capture folders dated a day off | Pi clock wrong (no RTC/NTP) | manual clock sync before each run (see above) |
| `tcpdump: can't parse filter expression` | glob matched >1 pcap; extra file parsed as filter | read one file at a time (see inspect section) |
| `zsh: no matches found: ...?test=1` | zsh globs the `?` in a URL | quote the URL |
| `sudo` slow + `unable to resolve host edge.home.arpa` | Pi hostname not locally resolvable | `echo "127.0.1.1 edge edge.home.arpa" | sudo tee -a /etc/hosts` |

## Validation status (as of first live bring-up)

- ✅ **C2 path validated end-to-end**: `mirai register,c2` beacons reached the PC
  sim-C2 at `10.10.10.60` via the Pi's NAT (sink logged `peer: 10.10.10.1`),
  confirming the beacon genuinely crosses the gateway.
- ✅ **First full `mirai --fire` ran** recon→access→loader→register→c2 cleanly;
  `ddos` surfaced the DNS-vector bug (now fixed) and the live-target requirement.
- ⚠️ **Patient-zero victim host intentionally omitted** for now — `access`/`loader`
  produce connection-attempt signatures only (no application-layer payloads).
- ⚠️ **Clock sync is manual** pending a local NTP server / RTC (see TODO below).

## TODO / hardening

- Durable clock: run a local NTP server on a lab host (or fit a Pi RTC) so the
  capture clock survives reboots without manual setting.
- Reconcile `DEVICES` in `iot_family_profiles.py` with the real testbed addresses
  (currently `.10` and `.76` are unidentified live clients; `.20/.25/.50` are not
  present).
- Persist the Pi's `ip_forward` + NAT rule (see `network-setup.md` §8).
