# Testbed network setup

> The physical/network configuration the generators and capture assume. This is
> a reproducibility artefact: anyone rebuilding the testbed should be able to
> recreate the exact topology from this document. Keep it in step with the
> `CONFIG` blocks in `iot_family_profiles.py` (and `iot_botnet_emulator.py`).
> For the step-by-step run procedure, see [`runbook.md`](runbook.md).

## 1. Topology

```
            university network  (PC's built-in NIC -- for our own use only,
                   │             NOT part of the lab, never carries lab traffic)
                   │
         ┌─────────┴─────────┐
         │   Lab PC (Ubuntu) │   sim-C2  (sim_c2.py)  +  can host victim_sink
         │  USB-Eth NIC      │   10.10.10.60/24   (no gateway on this NIC)
         └─────────┬─────────┘
                   │  isolated WAN link (direct cable, 10.10.10.0/24)
                   │  ── the C2 beacon crosses the gateway here ──
         ┌─────────┴─────────┐
         │ Raspberry Pi      │  eth0 = 10.10.10.1/24  (never-default; no uni route)
         │  "edge" (gateway) │  router + DNS + MQTT broker + Wi-Fi AP + capture
         │                   │  wlan0 = 192.168.25.1/24  (hotspot = the lab LAN)
         └─────────┬─────────┘
                   │  Wi-Fi hotspot  (all lab traffic transits the Pi by design)
     ┌─────────────┼───────────────┬───────────────┬──────────────┐
   PIR sensor     DHT22 sensor     smart bulb        Attacker
  192.168.25.15   192.168.25.20    192.168.25.30     (MacBook)
  (CoAP; DDoS      (MQTT; temp/      (benign)          DHCP from Pi
```

Because the Pi is the devices' **Wi-Fi access point**, every packet a device
sends — including device-to-device — passes through the Pi. That is what makes a
single capture **on the Pi** see the whole kill chain, and it matches the
research claim of detecting **at the gateway**.

## 2. Address plan

| Host / role | Interface | Address | Notes |
|---|---|---|---|
| Pi gateway "edge" — LAN/AP | `wlan0` | `192.168.25.1/24` | DHCP, DNS, MQTT broker; **capture interface** |
| Pi gateway — WAN link | `eth0` | `10.10.10.1/24` | isolated link to C2; `never-default` (no internet route) |
| C2 host — sim-C2 (ThinkPad) | USB-Eth | `10.10.10.60/24` | **no gateway** on this NIC; its normal uplink stays on a separate NIC |
| PIR sensor (ESP32) | Wi-Fi | `192.168.25.15` | CoAP/UDP 5683; MAC `c8:c9:a3:69:6d:ad`; **DDoS target** (confirmed live) |
| DHT22 sensor (ESP32) | Wi-Fi | `192.168.25.20` | MQTT temp/humidity; MAC `c8:c9:a3:69:6d:02` |
| Smart bulb | Wi-Fi | `192.168.25.30` | MAC `ac:a7:f1:4a:3c:a2`; benign (DNS/NTP chatter) |
| Ultrasonic sensor (ESP32) | Wi-Fi | — | CoAP; **currently UNPLUGGED** — not on the testbed |
| Patient zero | Wi-Fi | `192.168.25.50` | `victim_sink.py` host — **not deployed**; VICTIM unused, victim phases skipped |
| Attacker | Wi-Fi | DHCP | MacBook running the generators |

The C2 (`SIM_C2 = 10.10.10.60`) is the single host outside `LAB_NET` that the
generators are permitted to reach — enforced by `EGRESS_ALLOW` in
`iot_family_profiles.py`. Everything else stays inside `192.168.25.0/24`.

**Confirmed live state (2026-10-08).** `ip neigh show dev wlan0` shows: Mac
(`.12`), PIR (`.15`, confirmed by its CoAP `{"detected":...}` traffic), DHT22
(`.20`), and the smart bulb (`.30`). The ultrasonic sensor is unplugged and the
`.50` patient-zero host is not deployed, so the `access`/`loader` victim phases
are skipped. `DDOS_TARGET` is the confirmed-live PIR at `.15`; `DEVICES` in both
`iot_family_profiles.py` and `iot_botnet_emulator.py` matches this.

## 3. Pi configuration

```bash
# --- isolated WAN link on eth0 (NetworkManager-managed) ---
sudo nmcli con mod "Wired connection 1" \
    ipv4.method manual ipv4.addresses 10.10.10.1/24 \
    ipv4.gateway "" ipv4.dns "" ipv4.never-default yes
sudo nmcli con up "Wired connection 1"

# --- routing + NAT so lab devices reach the C2 and replies return ---
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -o eth0 -s 192.168.25.0/24 -j MASQUERADE
```

We capture on `wlan0` (the LAN/pre-NAT side), so packets keep their **real device
source IPs** for joining to the per-device ground-truth labels.

## 4. C2 host (Lenovo ThinkPad, Ubuntu) configuration

> The sim-C2 role moved from the original lab PC to a Lenovo ThinkPad running
> Ubuntu — same role, same addressing. "uni connection" below means whatever
> normal uplink that machine uses; keep it on a separate NIC from the lab link.

- USB-Eth NIC: static `10.10.10.60/24`, **gateway and DNS left blank** (so the
  built-in NIC remains the PC's default route and the uni connection is
  untouched). If the PC's firewall is active, allow the lab:
  ```bash
  sudo ufw allow from 192.168.25.0/24
  sudo ufw allow from 10.10.10.1
  ```
- Run sim-C2 bound to the lab IP only (not exposed on the uni side):
  ```bash
  sudo python3 sim_c2.py --bind 10.10.10.60
  ```

## 5. Containment

- The `10.10.10.0/24` link is a **direct cable** between the Pi and the PC's USB
  NIC — it is **not** connected to the university network. The PC's uni
  connection lives on a separate NIC and never carries lab traffic.
- `eth0` is `never-default`, so the Pi has **no default route / no internet**.
  Confirm before any capture run:
  ```bash
  ip route        # expect NO 'default' line
  ```
  (A stray `default via 10.10.10.60` or a uni route means the link is bridging
  the lab to the outside — remove it before firing.)
- The generators are additionally software-contained: the `EGRESS_ALLOW` guard
  refuses any target that is neither in `192.168.25.0/24` nor the one C2 IP.

## 6. Capture

```bash
# on the Pi, LAN/AP side:
sudo ./capture.sh wlan0 10.10.10.60
```
Writes hourly-rotated PCAPs + a metadata sidecar + SHA-256 sums into a per-run
directory. `wlan0` is the AP interface; `10.10.10.60` adds the C2 host to the
BPF filter.

## 7. Gotchas we hit (so they don't cost time again)

- **Both link ends must be on the same subnet.** We briefly had the Pi `eth0` on
  `192.168.55.x` (a stale auto-DHCP lease from PC connection-sharing) while the
  PC was on `10.10.10.x`. Symptom: `ping` shows `Destination Host Unreachable`
  **from your own IP** = ARP failed = nothing at that address on the cable.
  Fix: put both ends on `10.10.10.0/24` statically, no DHCP/sharing.
- **Never set a default gateway on the isolated-link NICs.** Use
  `ipv4.never-default yes` on the Pi and leave the PC USB NIC's gateway blank —
  otherwise the link hijacks the default route and/or bridges the lab to uni.
- **`sudo` slow + `unable to resolve host edge.home.arpa`:** the Pi's hostname
  isn't resolvable locally. Fix: `echo "127.0.1.1 edge edge.home.arpa" | sudo tee -a /etc/hosts`.
- **PC firewall (ufw) can drop ICMP/connections** even when ARP works — if ping
  fails but `ip neigh` shows the peer `REACHABLE`, open the lab subnets (s4).
- **Runtime `ip`/`iptables`/`sysctl` changes do not survive reboot.** See below.

## 8. Clock sync (critical for label joins)

Labels (Mac) and PCAP (Pi) are joined on UTC timestamps, so the two clocks must
agree. The Pi has **no battery-backed RTC and no internet NTP**, so it boots with
the wrong time (we saw captures stamped a day off). Until a durable fix is in,
**sync the Pi to the Mac before every capture** (see [`runbook.md`](runbook.md)
"Before every run"):
```bash
# Mac:
date -u "+%Y-%m-%d %H:%M:%S"
# Pi:
sudo timedatectl set-ntp false
sudo date -u -s "PASTE-THE-MAC-UTC-VALUE"
```
Durable options: run a local NTP server on a lab host (e.g. chrony on the Pi or
PC) and sync the others to it, or fit a hardware RTC to the Pi.

## 9. Persistence (make it survive a reboot) — TODO

Currently the `eth0` static (via nmcli) persists, but the NAT rule and
`ip_forward` are runtime-only. To persist:
```bash
# ip_forward
echo "net.ipv4.ip_forward=1" | sudo tee /etc/sysctl.d/99-lab.conf
# iptables NAT
sudo apt install -y iptables-persistent   # saves current rules, restores on boot
sudo netfilter-persistent save
```
(A single `lab-netup.sh` bring-up script is a planned convenience.)
