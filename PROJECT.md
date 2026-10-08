# IoT Malware Detection Testbed — Project Charter & Technical Plan

> Master context document. Read this first. It defines the goal, the quality bar,
> the architecture, every design decision made so far (and why), and the roadmap.
> Rationale for the emulator specifically also lives in `README.md`.

---

## 1. Vision & quality bar

**Goal:** a practical, gateway-based network-threat detection system for smart
homes, developed and evaluated on a minimal physical testbed, using traffic that
faithfully reproduces the *network behaviour* of IoT botnets (Mirai / Gafgyt /
Mozi) without running live malware.

**This is research-grade work, not a demo.** The standard we are holding to:

- **Reproducible.** Every experiment is scripted, seeded, config-driven, and
  produces machine-readable ground truth. Anyone with the repo and the testbed
  can regenerate our results. No manual, un-recorded steps.
- **Scientifically honest.** Claims are backed by evidence; scope limits are
  stated plainly, not hidden. We never overstate what emulated traffic proves.
- **Externally validated.** Our emulated signatures are checked against real,
  public malware captures — we don't rely on our own data to validate itself.
- **Rigorously evaluated.** Proper train/test discipline, per-class metrics, and
  the false-positive rate on benign treated as a first-class result.
- **Well-documented.** Code, data, and decisions are documented to a standard a
  marker, a reviewer, or a new teammate could pick up and follow.
- **The dataset is a deliverable in its own right**, published with a datasheet.

The litmus test for any addition: *would it survive peer review, and could
someone else reproduce it from the repo?*

---

## 2. Research question, objective, deliverables

**Research question.** What impacts do IoT malware behaviours and communication
protocols have on the network performance and security of a minimal smart-home
testbed?

**Primary objective.** Develop a practical IoT network-threat detection system
for smart homes by analysing behavioural traffic patterns and packet anomalies,
in a testbed-based observational study — detecting threats at the gateway without
placing additional load on constrained IoT devices.

**Deliverables.**
1. A functional minimal smart-home testbed evaluated under both normal and
   suspicious traffic conditions.
2. A labelled traffic **dataset** (PCAP + extracted flow features + ground-truth
   labels) with a datasheet.
3. A **detection system** — signature rules plus an ML/anomaly comparison — with
   a full evaluation (accuracy, per-class P/R/F1, false-positive rate, detection
   latency, and resource cost measured on the gateway).
4. A **reproducibility package** (scripts, configs, environment, orchestration).
5. The written report, grounded in the above.

---

## 3. Testbed (FIXED — do not change)

The physical testbed is settled. The project builds software *around* it.

| Element | Role |
|---|---|
| ESP32 / ESP8266 sensors | controllable devices; MQTT telemetry; reproducible baseline |
| Tapo smart bulbs & plugs | real consumer firmware + cloud traffic (realism) |
| Raspberry Pi gateway | router / DNS resolver / MQTT broker — the single point all IoT traffic passes through, and where the detector runs |
| Monitoring host | continuous packet capture via a mirror / SPAN port |
| Network | static IPs, isolated from the wider internet during attack phases |

Scope limits (stated, not flaws): no IP cameras; no live malware. Detection is
purely network-level at the gateway, so the *source* of traffic does not affect
signature validity — which is what makes behavioural emulation a valid substitute
for detonating real malware.

---

## 4. System architecture

Four software components sit around the fixed testbed:

```
                         ┌──────────────────────────┐
   (attacker: MacBook)   │   1. Traffic generators  │
   iot_botnet_emulator ──┤   - adversary emulator   │
   benign_generator   ───┤   - benign traffic       │
                         └────────────┬─────────────┘
                                      │ traffic on the wire
            ┌─────────────────────────┼─────────────────────────┐
            │                         │                         │
   ESP32 / bulbs / plugs      Raspberry Pi gateway        2. C2 sink (sim_c2.py)
   (testbed devices)      (router / DNS / MQTT broker)   on a separate host / VPS
            │                         │                         │
            └──────────── mirror / SPAN port ──────────┐        │
                                                        ▼        ▼
                                            Monitoring host: continuous PCAP
                                                        │
                                                        ▼
                                   3. Labelling + feature pipeline
                            (PCAP + labels.csv → Zeek/nfstream → labelled features)
                                                        │
                                                        ▼
                                   4. Detection + evaluation
                         (signature rules + ML; metrics; resource cost on the Pi)
```

**Ground truth** flows from the generators: the emulator writes per-phase labels
with UTC + monotonic timestamps; the C2 sink logs every beacon; the capture host
records PCAP. All three share an NTP clock, so the pipeline can join them exactly.

---

## 5. Design decisions already made (and why)

These are settled; keep them unless there is a strong reason to revisit.

- **Inert emulation, never live malware.** The generator reproduces traffic
  signatures only: no binary, no persistence, no self-replication, no exploit, no
  login escalation, no remote execution, and floods are short and rate-capped.
  Justification: detection is network-level, so emulation is methodologically
  equivalent and far safer (cf. EDIMA; Antonakakis et al. 2017; TON_IoT; REAL-IoT).
- **C2 lives on a separate host, reached *through* the gateway — not *at* it.**
  Beaconing to the gateway models "device talks to its router," which every
  device does constantly and is useless as a signature. The C2 must be a
  destination the devices never normally contact.
- **Real public egress is allowed only via an endpoint we own.** For maximum
  realism the C2 may be a self-owned public VPS (or a domain we control), so the
  beacon genuinely crosses the internet to a real public IP — but never an IP we
  don't own (that is unsolicited third-party traffic and breaks containment). An
  **egress allowlist** in the emulator permits one named C2 endpoint outside
  `LAB_NET`; everything else stays locked to the lab. RFC 5737 TEST-NET addresses
  are the contained alternative for the "outbound to public" shape.
- **DoS targets a device, never the gateway** — flooding the gateway would also
  kill the capture/C2 path and corrupt the run.
- **Exploit-probe spreading is emitted as *structure only*, payload neutralised.**
  The family profiles (Gafgyt/Mozi) reproduce the known router/DVR
  command-injection CVE requests (Huawei HG532, Realtek SDK, GPON, JAWS DVR,
  D-Link HNAP). The real request *structure* — method, URI, SOAPAction, the
  injection parameter — is what a NIDS signature matches, so we emit exactly
  that, but the command payload is replaced by an inert shell no-op marker.
  Result: faithful signature, zero working exploit, fired at lab devices that
  are not vulnerable anyway. Same logic as the inert credential phase.
- **Mozi's P2P mesh stays inside the lab.** Mozi has no central C2; its signature
  is BitTorrent-DHT (bencoded UDP `ping`/`find_node`) chatter among peers. We
  reproduce that DHT traffic with lab hosts as the peer set, and emit a
  recognisable lab marker (`TB…`) as the node-ID prefix rather than a real Mozi
  config hash — so the family is identifiable in capture without impersonating
  live infrastructure. The real public DHT bootstrap nodes are contacted only if
  explicitly egress-allowlisted.
- **Two kinds of credentials, handled oppositely.** The attacker guess-list is
  emitted as attempt traffic to *produce the brute-force signature* and never
  surfaces a valid pair (signature generator, not a credential cracker). The
  legitimate broker login is a real secret, resolved at runtime (env / file /
  Keychain / prompt) and never hardcoded or logged.
- **Everything is labelled and seeded.** Per-run manifest (JSON/JSONL/CSV),
  fixed RNG seed, config snapshot — so runs are reproducible and the capture is
  exactly labellable.

---

## 6. Components — current state and target

| Component | Now | Target |
|---|---|---|
| **Adversary emulator** (`iot_botnet_emulator.py`) | ✅ 9 kill-chain phases, 5 scenarios, ATT&CK-tagged, labelled output, dry-run default, private-IP guard, paho 1.x/2.x safe | migrate onto `testbed_lib`; YAML-driven config |
| **Family profiles** (`iot_family_profiles.py`) | ✅ Mirai/Gafgyt/Mozi distinct profiles — per-family creds, C2 shape (Mirai fixed heartbeat / Gafgyt plaintext tokens / Mozi BitTorrent-DHT P2P), neutralised CVE exploit-probe spreading, bounded family-specific DDoS vectors; `family`-labelled output; dry-run default; egress allowlist | validate feature distributions vs real per-family captures (M2) |
| **Shared plumbing** (`testbed_lib.py`) | ✅ LAB_NET guard + egress allowlist, RunContext + ground-truth recording, manifest/CSV/JSONL/capture writers, collision-free run ids, shared CLI | emulator to adopt it |
| **C2 sink** (`sim_c2.py`) | ✅ HTTP/TCP/UDP listeners + JSONL log; mosquitto for the rogue broker | optional deploy on a self-owned VPS for real public egress |
| **Benign traffic generator** | ✗ | realistic baseline: MQTT telemetry, cloud check-ins, NTP/DNS, mDNS/SSDP, firmware polls — a first-class component, not idle silence |
| **Capture** | tcpdump command documented | wrap as a service on the gateway/mirror; rotate + checksum PCAPs |
| **Labelling + feature pipeline** | ✗ (**highest priority**) | PCAP + `labels.csv` → Zeek `conn.log` / nfstream flows → per-flow features → one labelled CSV ready for ML |
| **Detector** | ✗ | signature layer (Suricata/Snort + Zeek scripts) **and** ML layer (RF/XGBoost, autoencoder on benign) as a comparison |
| **Evaluation harness** | ✗ | metrics, plots, resource-cost profiling, external-dataset validation |
| **Orchestrator** | ✗ | one command runs baseline→attacks→baseline across scenarios, N repetitions, emits dataset + metrics |

---

## 7. Roadmap (priority order)

- **M1 — Labelled dataset pipeline.** The single biggest force-multiplier. Turn
  raw PCAP + labels into a documented, feature-extracted, labelled dataset. This
  makes the dataset a citable deliverable.
- **M2 — External validation.** Compare our emulated Mirai/Gafgyt/Mozi traffic to
  real public captures (IoT-23/Aposemat, Bot-IoT, TON_IoT, N-BaIoT, MedBIoT);
  train-on-ours/test-on-theirs and vice versa to show transferability.
- **M3 — Realistic benign generator.** So "normal" is genuinely normal and the
  detection task is meaningful.
- **M4 — Detector + rigorous evaluation.** Signature + ML; time-based split;
  per-class P/R/F1; PR/ROC; confusion matrix; false-positive rate; detection
  latency and CPU/memory cost measured on the Pi gateway.
- **M5 — Family profiles + multi-class.** Distinct Mirai / Gafgyt / Mozi
  behaviour modules; label and detect by family, not just benign/malicious.
- **M6 — Engineering polish.** YAML-driven experiments, one-command orchestrator,
  controlled public-VPS C2 with egress allowlist, dataset datasheet, repro package.

---

## 8. Evaluation methodology (the standard to hold)

- **Train/test split by time**, never random — random split leaks near-duplicate
  flows and inflates scores.
- **Report per class**: precision, recall, F1; PR and ROC curves; confusion
  matrix — not a single accuracy number.
- **False-positive rate on benign is a headline result.** An IoT IDS that flags
  normal traffic is undeployable; this number decides practical value.
- **Measure cost on the gateway**: detection latency and CPU/memory of running
  the detector on the Pi — directly answers the "no device burden" objective.
- **Validate emulation realism statistically**: compare feature distributions of
  our emulated attacks to the real public captures (e.g. KS tests), so "we didn't
  run real malware" has a quantitative answer.
- **Repeat runs** for variance; report means with spread, not single runs.

---

## 9. External datasets (for validation & comparison)

IoT-23 / Aposemat · Bot-IoT · TON_IoT · N-BaIoT · MedBIoT. Used to (a) validate
that our emulated signatures match real ones, and (b) test cross-dataset
generalisation of the detector.

---

## 10. Reproducibility & engineering standards

- **Config over code**: experiments declared in a YAML file, not by editing
  Python constants. Config snapshot saved into every run's manifest.
- **Seeded** RNG; recorded in the manifest.
- **Environment**: `uv` with inline (PEP 723) dependencies — no venv juggling.
- **One-command runs** via the orchestrator; no un-recorded manual steps.
- **Data hygiene**: PCAPs and `runs/` outputs are git-ignored (large/machine-
  specific); secrets (`config/broker.env`) never committed; a committed
  `broker.env.example` documents the shape.
- **Git discipline**: small, described commits; the repo is the shared memory
  between Claude chat (design/writing) and Claude Code (building).
- **Tests** for the pipeline (label-join correctness, feature extraction) once it
  exists — the dataset's validity depends on them.

---

## 11. Ethics & scope statement

Run only on the isolated lab we own and are authorised to test. The generator is
adversary **emulation**, not malware (see §5). It performs no real intrusion,
exfiltrates no real data, and never targets hosts outside the lab (the one
exception being a self-owned public C2 endpoint via an explicit egress
allowlist). The project's scope is network-level detection at the gateway; on-host
malware effects and IP cameras are out of scope by design, not omission.

---

## 12. Repository layout

```
iot-detection-testbed/
├── PROJECT.md                 ← this document (master plan)
├── README.md                  ← emulator documentation & rationale
├── iot_botnet_emulator.py     ← generic adversary emulator (done)
├── iot_family_profiles.py     ← Mirai/Gafgyt/Mozi family profiles (done)
├── testbed_lib.py             ← shared plumbing: guard, recording, outputs (done)
├── sim_c2.py                  ← C2 sink (done)
├── config/
│   └── broker.env.example     ← template; real broker.env is git-ignored
├── victim_sink.py             ← controlled patient-zero responder (done)
├── capture.sh                 ← Pi-side PCAP capture w/ rotation+checksums (done)
├── docs/
│   ├── roadmap.md             ← short roadmap pointer
│   ├── network-setup.md       ← testbed topology, addressing, setup, gotchas (done)
│   └── runbook.md             ← run procedure, artifacts, inspection, gotchas (done)
├── runs/                      ← experiment outputs (git-ignored)
└── (planned) benign/ pipeline/ detector/ eval/ configs/ datasets/
```

---

## 13. Status & changelog

- **Done:** three-family adversary generator — Mirai/Gafgyt/Mozi
  (`iot_family_profiles.py` + `testbed_lib.py`); C2 sink (`sim_c2.py`); victim
  sink; capture wrapper; **M1 feature pipeline** (`pipeline/extract_features.py`,
  nfstream flows + grace-margin labelling); **three complete labelled datasets** —
  every phase of every family's chain lands (`datasets/`, 2026-10-08);
  **publication figures** (`figures/`); testbed + network docs.
- **Validated end-to-end (2026-10-08).** Pi AP/gateway on `192.168.25.0/24`;
  isolated `10.10.10.0/24` WAN link to the sim-C2 host; capture on the Pi's
  `wlan0`. The C2 beacon crosses the gateway's NAT, and all three families ran
  their full chains to labelled datasets. recon (ARP-sweep + SYN) and exploit both
  land now; the pipeline's grace margin absorbs the tool-launch skew.
- **Next:** **signature-based detection (core deliverable)** — Zeek signatures +
  scripts evaluated against the labelled captures (detection rate + false-positive
  rate, per family/phase). Then M2 external validation (real IoT-23 / Bot-IoT) and
  M3 benign generator; ML (M4b) is the stretch goal.
- **Known limitations:** recon/loader/register/exploit are small flow classes —
  an isolated subnet reaches only ~3 live hosts and several phases are single-shot.
  Fine for signature detection (the packet-level pattern is clear); a constraint
  for flow-level ML. Pi clock sync is still manual (no RTC/NTP).

---

## 14. References

- Antonakakis et al., *Understanding the Mirai Botnet*, USENIX Security 2017.
- EDIMA — contained IoT malware traffic generation.
- TON_IoT, REAL-IoT, Bot-IoT, IoT-23/Aposemat, N-BaIoT, MedBIoT — IoT attack
  datasets.
- Zeek, Suricata — network analysis / IDS.
- MITRE ATT&CK — technique taxonomy used throughout the emulator.
