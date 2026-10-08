# Roadmap

Components: generator (`iot_family_profiles.py` — Mirai/Gafgyt/Mozi, built on
`testbed_lib.py`) · C2 sink (`sim_c2.py`) · victim sink (`victim_sink.py`) ·
feature pipeline (`pipeline/extract_features.py`) · detector (next).
Design rationale lives in `README.md` and `PROJECT.md` (inert emulation, C2
placement, bounded DoS).

**Status (2026-10-08):** all three families captured and labelled end-to-end;
every phase lands; three labelled datasets in `datasets/`; publication figures
in `figures/`.

Priority order:
1. ✅ **DONE** — PCAP + labels.csv → labelled feature dataset (nfstream flows +
   time-join labelling, grace-margin for tool-launch skew).
2. **NEXT (core deliverable)** — signature-based detection: Zeek signatures +
   scripts, evaluated against the labelled captures (detection rate +
   false-positive rate, per family/phase).
3. Validate emulated traffic against real captures (IoT-23, Bot-IoT, TON_IoT).
4. Realistic benign-traffic generator (MQTT telemetry, NTP/DNS, mDNS/SSDP).
5. ✅ **DONE** — family profiles (Mirai / Gafgyt / Mozi).
6. ML comparison (RF/XGBoost), time-split eval, resource cost on the Pi gateway
   — stretch goal ("extra if time").
7. Egress allowlist for a self-owned public VPS C2 — optional.
