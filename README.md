# IoT Botnet Behaviour Emulator — Documentation

`iot_botnet_emulator.py`

> **Current generator:** the testbed now runs on `iot_family_profiles.py` (Mirai /
> Gafgyt / Mozi family profiles, built on `testbed_lib.py`) — that is what the
> runbook, captures and `datasets/` use. The `iot_botnet_emulator.py` documented
> here is the original single-profile reference; the inert-emulation rationale
> applies to both. See `PROJECT.md` for status and `pipeline/README.md` for turning
> captures into datasets.

A reproducible, labelled generator of the **network behaviour** of IoT botnets
(Mirai / Gafgyt / Mozi family) for a smart-home intrusion-detection testbed. It
replays the on-the-wire *signatures* of a botnet infection — scanning, credential
attempts, loader fingerprinting, C2 registration and beaconing, propagation, DDoS
participation, exfiltration, MQTT abuse — so a gateway-based detector (Zeek,
Wireshark/tshark, IoT Inspector, MQTT Explorer) can be trained and evaluated
against traffic with exact ground-truth labels.

It is an **emulator**, not malware. See *Safety & Scope* below.

---

## 1. Why the tool works this way

The research question is network-level: *can a gateway detector recognise
malware-like traffic in a smart home?* That framing drives every design choice.

**Detection is on the wire, so the source of the traffic doesn't matter.**
Mirai's Telnet scan, its C2 beacon rhythm, and a flood burst look the same to a
gateway sensor whether they come from a real infected camera or from a script
imitating one. Because the detector only ever sees packets at the gateway, a
faithful *traffic* reproduction yields data that is methodologically equivalent
to running the real malware — for the purpose of building and testing signatures.

**Running live malware is avoided on purpose.** Self-propagating IoT malware can
escape even a "contained" lab and attack other hosts, and possessing/executing it
carries legal and ethical risk. The literature that builds IoT detection datasets
takes the same position — emulate the observable behaviours rather than detonate a
binary (e.g. the EDIMA project rules out live malware on testbed devices;
Antonakakis et al. 2017 documents Mirai's behaviour from source; TON_IoT and
REAL-IoT generate labelled attack traffic with tooling, not infections).

**Everything is grounded in documented behaviour.** The default-credential list,
the BusyBox `MIRAI`/`ECCHI` fingerprint strings, the scan ports, the beacon
cadence and the attack classes are taken from public Mirai source analysis and
the IoT-security literature, so each emulated phase corresponds to a real,
citable behaviour rather than an invented one.

---

## 2. Safety & scope (what it deliberately does NOT do)

These constraints are design decisions, not accidents, and they are what keep the
tool inside the scope an ethics / methods review would expect.

| It does **not** | Why |
|---|---|
| carry a real botnet binary or drop any payload | no malware on the testbed |
| install persistence or self-replicate | no uncontrolled spread |
| exploit any vulnerability | it imitates traffic, it does not break in |
| evaluate a login response for success, or escalate | the credential phases **emit attempt traffic only** — they are signature generators, not credential crackers |
| report which credential (if any) a broker accepts | it reports only aggregate CONNACK counts, never a working pair |
| execute remote commands on a device | the loader phase sends benign, read-only strings; nothing is run |
| run an unbounded / line-rate flood | every flood is time-boxed (short bursts) and packet-rate-capped |
| touch anything outside the lab | every target is asserted inside `LAB_NET`; a non-private or out-of-range target aborts the run |

**Dry-run is the default.** Nothing is transmitted without `--fire`; a plain run
prints the exact plan (useful for a methods section). A live run also asks for
confirmation unless `--yes` is passed.

---

## 3. What each phase does

Every phase emits the traffic signature of one stage of an infection, records a
ground-truth label (see §5), and is bracketed by benign-idle baseline windows so
the detector has clean comparison periods.

| Phase | Emulates | Traffic produced | MITRE ATT&CK | Kept inert by |
|---|---|---|---|---|
| `recon` | Botnet scanning for victims | TCP SYN sweep of the subnet across IoT ports (22/23/2323/80/443/554/1883/5683/8080/8883), via `nmap` or a scapy fallback | T1595, T1046 | non-destructive SYN probes; scapy path sends a polite RST to avoid half-open sockets |
| `access` | Mirai default-credential login attempts | Telnet connections to the victim that send the documented default `user`/`pass` pairs | T1110.001, T1078.001 | **never reads the response for success, never escalates** — emits the attempt bytes only |
| `loader` | A loader's device fingerprint + payload pull | Benign BusyBox strings (`busybox MIRAI`, `ps`, `cat /proc/*`, `ECCHI`) on the Telnet channel, then an HTTP GET of a harmless marker file **from the attacker box** | T1059, T1105 | read-only strings only; no `wget`-to-device, no file write, no execution follow-up |
| `c2_register` | First check-in of a newly "infected" device | HTTP GET `/register?id=…&arch=arm` to the sim-C2 | T1071.001 | plain HTTP to a host you control |
| `beacon` | C2 heartbeat (the detectable rhythm) | Low-jitter HTTP + raw TCP + raw UDP callbacks, plus an anomalous MQTT publish to an *unexpected* broker, for a fixed window | T1071, T1571, T1008 | benign payloads; destination is a host the devices never normally contact |
| `propagate` | Worm-style outward spread | Outward SYN scan + default-credential attempt traffic to the *other* lab devices | T1210, T1046 | same inert credential-attempt mechanism as `access`; no real spread |
| `ddos` | Bot participating in a flood | Three short, rate-capped bursts — SYN, UDP, ICMP — at one lab target | T1498, T1499 | each burst is time-boxed and capped in packets/sec; aimed at a device, **not** the gateway |
| `exfil` | Data exfiltration shapes | One oversized MQTT publish (authenticated if broker creds are supplied) + a run of high-entropy DNS TXT lookups (DNS-tunnel shape) | T1048, T1071.004 | fixed-size blob to a topic you own; lookups go to your own resolver |
| `mqtt_misuse` | MQTT-specific abuse | `#` wildcard subscription, a bounded publish flood, credential-stuffing attempt traffic, and malformed payloads — all against the lab broker | T1499, T1110 | flood is count/rate-capped; brute reports aggregate CONNACK codes only; malformed payloads test parser robustness |

### Scenarios (ordered chains of phases)

| Scenario | Phases |
|---|---|
| `mirai_full` | recon → access → loader → c2_register → beacon → propagate → ddos → exfil |
| `infection_only` | recon → access → loader → c2_register |
| `botnet_ops` | beacon → ddos → exfil |
| `worm` | recon → access → loader → propagate |
| `mqtt_suite` | mqtt_misuse → exfil |

Run any single phase or any scenario. `python3 iot_botnet_emulator.py describe`
prints this catalogue with the ATT&CK IDs.

---

## 4. Credentials — two different kinds, handled oppositely

The word "credentials" appears in two unrelated roles, and they are treated
differently on purpose.

**(a) The attacker's guess-list** (`MIRAI_CREDS` for Telnet; `MQTT_BRUTE_DEFAULTS`
for MQTT). These *are* the signature — a botnet throws a known wordlist at a login,
and the burst of failed attempts is exactly what an IDS flags. They are emitted as
attempt traffic. The tool **does not discover or report a working pair**: the MQTT
brute phase records the broker's CONNACK return codes *in aggregate* (e.g. nine
"not authorised", one "accepted") and, if any attempt is accepted, flags only the
*count* so you can harden the broker — never the credential itself. This keeps it a
signature generator rather than a credential cracker, and it loses nothing for the
research, because a gateway sensor cannot see whether a guess succeeded anyway.
Point `MQTT_BRUTE_WORDLIST_FILE` at a `user:pass`-per-line file to use your own list.

**(b) The legitimate broker login** (`MQTT_USER` / `MQTT_PASS`, used by `exfil` to
authenticate a real publish). This is a genuine secret, so it is **not** hardcoded.
`broker_creds()` resolves it at run time, in precedence order:

1. `MQTT_USER` / `MQTT_PASS` environment variables
2. a `KEY=VALUE` file at `BROKER_CREDS_FILE` (default `~/.config/iot-sim/broker.env`; keep it out of version control)
3. the macOS Keychain item named in `BROKER_KEYCHAIN_ITEM` (password)
4. an interactive prompt on a live, interactive run
5. nothing found → anonymous connect

The manifest records only *whether* authentication was used (`broker_auth: true/false`),
never the value.

---

## 5. Outputs — ground truth for labelling

Each run writes a timestamped directory `runs/<RUN_ID>/` containing:

| File | Contents |
|---|---|
| `run_<id>_manifest.json` | full nested record: a config snapshot plus every phase |
| `run_<id>_labels.jsonl` | one JSON line per action, streamed as it happens (survives a crash) |
| `run_<id>_labels.csv` | flat table for pandas / joining to Zeek logs |
| `run_<id>_capture.md` | the recommended `tcpdump` command, the attacker IP, and the capture filter |

Every record carries: phase, technique, MITRE ATT&CK ID, source, target, wall-clock
start/end (UTC, ISO-8601) **and** monotonic offsets, the parameters used, and counts
where measurable. Because each phase has precise start/end timestamps, you can slice
a continuously captured PCAP by time and attach the correct label to every window.

**Reproducibility:** a fixed, recorded RNG seed (`--seed`, default 718) makes runs
repeatable, and the config snapshot in the manifest captures exactly what was run.

---

## 6. Configuration

Edit the `CONFIG` block at the top of the script to match your testbed.

| Setting | Meaning |
|---|---|
| `LAB_NET` | the only network the tool may touch; everything else is asserted against it |
| `GATEWAY` | the Raspberry Pi acting as router / DNS resolver / MQTT broker |
| `BROKER_HOST`, `BROKER_PORT` | the MQTT broker (usually the gateway) |
| `SIM_C2`, `C2_HTTP_PORT`, `C2_TCP_PORT`, `C2_UDP_PORT` | the stand-in command-and-control host and its listeners |
| `ROGUE_BROKER_HOST/PORT` | an *unexpected* MQTT broker, for the C2-in-MQTT beacon |
| `DEVICES`, `VICTIM` | the lab devices and the "patient zero" |
| `DDOS_TARGET` | the single device the flood aims at (not the gateway) |
| `SCAN_PORTS` | ports probed during recon/propagation |
| timing (`BASELINE_GAP`, `BEACON_*`, `MQTT_FLOOD_*`, `DOS_BURST_*`, …) | window lengths, cadence, and the flood caps |
| `SPOOF_SRC` | optional: make scan/DoS appear to come from a chosen lab device (SunBlock-style) |

**Why the C2 is a separate host, not the gateway.** Real C2 is traffic that leaves
*through* the router to an unexpected destination. If the beacon pointed *at* the
gateway it would model "a device talking to its own router" — something every device
does constantly, and useless as a signature. The sim-C2 must be a host the IoT
devices never normally contact (ideally on the WAN side of the Pi, so the beacon
genuinely crosses the egress boundary). Before a live run, stand up listeners on it,
e.g. `nc -lk 4444`, a second mosquitto instance, and something on port 80.

**Why the DoS target is a device, not the gateway.** Flooding the gateway would also
disrupt your capture path and the C2 host mid-run, corrupting the dataset.

---

## 7. Installation & usage

Dependencies are declared inline in the script (PEP 723), so **`uv`** installs them
automatically with nothing to manage:

```bash
brew install uv                                   # one-time
uv run iot_botnet_emulator.py deps                # resolves scapy/paho-mqtt/dnspython, shows tool status
uv run iot_botnet_emulator.py describe            # phase + scenario catalogue
uv run iot_botnet_emulator.py run mirai_full      # DRY-RUN: prints the plan, sends nothing
sudo uv run iot_botnet_emulator.py run mirai_full --fire   # LIVE (raw-socket phases need sudo)
```

Only the three Python libraries are required. The system tools (`nmap`, `curl`,
`dig`) are optional — each has a built-in fallback. `sudo` is needed only for the
raw-socket phases (the scapy scan fallback and the DoS bursts).

Alternative without `uv` — a classic virtualenv (call the venv's Python directly
under `sudo` so the packages are visible; plain `sudo python3` would use the system
interpreter and miss them):

```bash
python3 -m venv iot-venv && ./iot-venv/bin/pip install scapy paho-mqtt dnspython
sudo ./iot-venv/bin/python3 iot_botnet_emulator.py run mirai_full --fire
```

### Command reference

| Command | Effect |
|---|---|
| `describe` | print the phase/scenario catalogue |
| `deps` | check library and tool availability |
| `run <phase\|scenario>` | run it (dry-run unless `--fire`) |
| `--fire` | actually transmit |
| `--seed N` | set the RNG seed (default 718) |
| `--out DIR` | output directory (default `runs/`) |
| `--spoof-src IP` | spoof the source IP (must be in `LAB_NET`) |
| `--yes` | skip the live confirmation prompt |

---

## 8. Suggested experiment procedure

1. On the monitoring host (mirror / SPAN port), start a continuous capture —
   `run_<id>_capture.md` prints the exact command.
2. Keep the attacker (MacBook) and the monitoring host on NTP so timestamps align.
3. Run a scenario with `--fire`. Baseline windows are recorded before and after each
   phase automatically.
4. After the run, join the PCAP to `run_<id>_labels.csv` on the UTC start/end times
   to label each window, then develop/evaluate detection rules against the result.
