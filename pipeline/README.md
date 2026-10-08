# Feature pipeline (M1)

Turns one capture run into a labelled, per-flow feature dataset for detection work.

```
pcap + run_<id>_labels.csv + run_<id>_manifest.json
   └─ extract_features.py ─→ labelled_flows.csv  (+ .cols.json)
```

## Usage
```bash
pip install nfstream scapy pandas          # nfstream pulls the flow features
python3 extract_features.py \
    --pcap   captures/cap_<ts>/lab_<ts>.pcap \
    --labels runs/<run_id>/run_<run_id>_labels.csv \
    --manifest runs/<run_id>/run_<run_id>_manifest.json \
    --out    datasets/labelled_flows.csv \
    --grace  8          # seconds; widen phase windows for tool-launch skew (default 8)
```

## What it produces
- **`labelled_flows.csv`** — one row per bidirectional flow: ~69 nfstream statistical
  features (packet/byte counts, durations, inter-arrival and packet-size stats,
  TCP-flag counts, per-direction splits) + identifier columns + labels.
- **`labelled_flows.cols.json`** — which columns are identifiers (drop for training,
  or a model trivially learns the attacker's IP), which are features, which are labels.
- **Labels:** `label_binary` (0 benign / 1 malicious), `label_class`
  (benign / recon / access / loader / exploit / register / c2 /
  dht_join / config_pull / dht_beacon / ddos), plus `family`, `technique`, `mitre_attack`.

## Labelling rule (why it's valid)
A flow is tagged with an attack phase only if **all** hold:
1. its first packet falls inside that phase's `[start,end]` window, **widened by a
   `--grace` margin** (default 8 s),
2. it involves an attacker-side IP (generator host or C2), **and**
3. its other endpoint is in-scope (lab subnet, or the C2/gateway).

Condition 3 keeps the attacker host's background internet traffic (e.g. DNS to
1.1.1.1) out of the attack classes, and the attacker-involvement condition keeps
real device traffic that runs *concurrently* with an attack window labelled benign.
Labelling purely by time window would mislabel both.

**Why the grace margin:** the scan tools launch slightly *before* the generator
stamps the phase start — the recon ARP-sweep and SYNs were observed firing ~2–6 s
ahead of the logged `recon` window, so a tight window missed them entirely
(recon showed 0 flows). The margin is safe because the attacker-involvement +
in-scope conditions still filter out background traffic, and attack phases are
>30 s apart so widened windows never overlap each other.

## Results — three-family labelled datasets (2026-10-08)
Every phase of every family's kill chain now lands as labelled flows:

| phase | Mirai | Gafgyt | Mozi |
|---|---|---|---|
| recon | 8 | 25 | — |
| access | 38 | 19 | — |
| loader | 2 | — | — |
| exploit | — | 10 | 10 |
| register | 1 | 1 | — |
| c2 | 12 | 10 | — |
| dht_join / config_pull / dht_beacon | — | — | 8 / 2 / 56 |
| ddos | 15,674 | 7,938 | 8,437 |
| benign | 914 | 739 | 599 |

Notes for the write-up:
- **Heavy class imbalance** (ddos dominates): expected — a flood is thousands of
  1-packet flows. Flow-level ML would need resampling/weighting.
- **recon / loader / register / exploit are small classes.** This is inherent to
  the testbed: a scan on an isolated subnet only reaches ~3 live hosts (ARP gates
  the rest), and several phases are single-shot. **For signature-based detection
  this is fine** — the recon *pattern* (a full ARP sweep + SYNs to live hosts) is
  plainly visible at the packet level, which is what a Zeek signature keys on. It
  is only flow-level ML that is constrained by the small counts.
- The in-scope rule correctly keeps concurrent benign device traffic (and the
  attacker host's background DNS) out of the attack classes.
