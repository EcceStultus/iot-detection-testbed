# Roadmap

Components: generator (iot_botnet_emulator.py) · C2 sink (sim_c2.py) · detector (todo).
Design rationale lives in README.md (inert emulation, C2 placement, bounded DoS).

Next, in priority order:
1. PCAP + labels.csv -> labelled feature dataset (Zeek/nfstream + label join).
2. Validate emulated traffic against real captures (IoT-23, Bot-IoT, TON_IoT).
3. Realistic benign-traffic generator (MQTT telemetry, NTP/DNS, mDNS/SSDP).
4. Detector: signature (Suricata/Zeek) + ML (RF/XGBoost), proper time-split eval,
   false-positive rate, resource cost measured on the Pi gateway.
5. Family profiles (Mirai / Gafgyt / Mozi); YAML-driven experiments; one-command orchestrator.
6. Egress allowlist for a self-owned public VPS C2.
