#!/usr/bin/env python3
"""
extract_features.py -- PCAP + ground-truth labels -> labelled flow-feature dataset
==================================================================================

Turns one capture run into a per-flow, labelled CSV ready for detection work:

    pcap  +  run_<id>_labels.csv  +  run_<id>_manifest.json
        -> bidirectional flows (nfstream, ~80 statistical features)
        -> each flow labelled by WHEN it occurred AND WHO it involved
        -> labelled_flows.csv  (+ a printed class summary)

Labelling rule (important for validity)
---------------------------------------
A flow is tagged with an attack phase only if BOTH hold:
  1. its first packet falls inside that phase's [start,end] window, AND
  2. it involves an attacker-side IP (the generator host, or the C2).
Everything else -- including real device traffic that runs *concurrently* with an
attack window -- is labelled "benign". This stops the detector from learning
"any flow during the recon window = attack", which would be an artefact of the
capture rather than a real signature.

Identifier columns (IPs, ports, times) are kept for traceability but flagged so
they can be dropped at training time (otherwise a model trivially learns the
attacker's IP). See ID_COLS below.

Usage
-----
  python3 extract_features.py --pcap cap.pcap --labels run_*_labels.csv \
          --manifest run_*_manifest.json --out labelled_flows.csv
"""
from __future__ import annotations
import argparse, ipaddress, json, sys
from datetime import datetime, timezone
import pandas as pd
from nfstream import NFStreamer

# flow-table columns that identify the endpoints/timing -- keep for traceability,
# drop for training (listed in the output's companion .cols.json too).
ID_COLS = ["id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
           "bidirectional_first_seen_ms", "bidirectional_last_seen_ms",
           "src_mac", "dst_mac", "application_name", "application_category_name",
           "requested_server_name", "client_fingerprint", "server_fingerprint",
           "user_agent", "content_type", "flow_start_utc"]

ATTACK_PHASES = {"recon", "access", "loader", "register", "c2", "ddos",
                 "propagate", "exfil", "mqtt_misuse", "exploit",
                 "config_pull", "dht_join", "dht_beacon"}


def parse_iso(s: str) -> float:
    """ISO-8601 (UTC) -> epoch seconds."""
    return datetime.fromisoformat(s).timestamp()


def load_windows(labels_csv: str):
    """Attack-phase windows only: [(start_s, end_s, meta_dict), ...]."""
    df = pd.read_csv(labels_csv)
    wins = []
    for _, r in df.iterrows():
        phase = str(r["phase"]).split(":")[0]
        if phase not in ATTACK_PHASES:
            continue
        wins.append((parse_iso(r["start"]), parse_iso(r["end"]), {
            "label": r["phase"],
            "family": r.get("family", "n/a"),
            "technique": r.get("technique", ""),
            "mitre_attack": r.get("mitre_attack", ""),
        }))
    return wins, df


def attacker_ips(labels_df: pd.DataFrame, manifest: dict) -> set:
    ips = set(str(s) for s in labels_df["src"].unique() if str(s) not in ("n/a", "nan"))
    cfg = manifest.get("config", {})
    for k in ("sim_c2",):
        if cfg.get(k):
            ips.add(str(cfg[k]))
    sp = cfg.get("spoof_src")
    if sp:
        ips.add(str(sp))
    return ips


def in_scope(ip: str, lab_net, extra: set) -> bool:
    """True if ip is inside the lab subnet or is a known in-scope host (C2/gateway)."""
    if ip in extra:
        return True
    try:
        return ipaddress.ip_address(ip) in lab_net
    except ValueError:
        return False


def label_flow(first_seen_s, src, dst, windows, atk_ips, lab_net, scope_extra, grace=8.0):
    """A flow is an attack only if, in an attack window, it involves an attacker
    IP AND its other endpoint is in-scope (lab subnet or C2/gateway). This keeps
    the attacker host's background internet traffic (e.g. DNS to 1.1.1.1) benign.

    `grace` widens each phase window by a few seconds on both edges. The scan
    tools launch slightly before the generator stamps the phase start (observed:
    recon ARP-sweep + SYNs fire ~2-6s *before* the logged 'recon' window), so a
    tight window misses them. The attacker-involvement + in-scope constraints make
    the margin safe: it catches the scan's own packets, not background traffic, and
    attack phases are >30s apart so widened windows never overlap each other."""
    src_atk, dst_atk = src in atk_ips, dst in atk_ips
    if not (src_atk or dst_atk):
        return 0, "benign", "n/a", "", ""
    peer = dst if src_atk else src                      # the non-attacker endpoint
    if not in_scope(peer, lab_net, scope_extra):
        return 0, "benign", "n/a", "", ""               # attacker's out-of-scope bg traffic
    for a, b, meta in windows:
        if (a - grace) <= first_seen_s <= (b + grace):
            return 1, meta["label"].split(":")[0], meta["family"], meta["technique"], meta["mitre_attack"]
    return 0, "benign", "n/a", "", ""


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--labels", required=True)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--out", default="labelled_flows.csv")
    ap.add_argument("--grace", type=float, default=8.0,
                    help="seconds to widen each phase window (tool-launch skew; default 8)")
    a = ap.parse_args()

    manifest = json.load(open(a.manifest))
    cfg = manifest.get("config", {})
    windows, labels_df = load_windows(a.labels)
    atk = attacker_ips(labels_df, manifest)
    lab_net = ipaddress.ip_network(cfg.get("lab_net", "192.168.25.0/24"), strict=False)
    scope_extra = {str(cfg[k]) for k in ("sim_c2", "gateway") if cfg.get(k)}
    print(f"[+] {len(windows)} attack-phase windows | attacker/C2 IPs: {sorted(atk)}")
    print(f"[+] in-scope: {lab_net} + {sorted(scope_extra)}")

    print(f"[+] extracting flows from {a.pcap} ...")
    flows = NFStreamer(source=a.pcap, statistical_analysis=True,
                       idle_timeout=120, active_timeout=1800).to_pandas()
    print(f"[+] {len(flows)} bidirectional flows, {len(flows.columns)} raw columns")

    flows["flow_start_utc"] = pd.to_datetime(
        flows["bidirectional_first_seen_ms"], unit="ms", utc=True)

    labs = flows.apply(lambda r: label_flow(
        r["bidirectional_first_seen_ms"] / 1000.0,
        str(r["src_ip"]), str(r["dst_ip"]), windows, atk, lab_net, scope_extra, a.grace),
        axis=1, result_type="expand")
    labs.columns = ["label_binary", "label_class", "family", "technique", "mitre_attack"]
    out = pd.concat([flows, labs], axis=1)

    out.to_csv(a.out, index=False)
    cols_meta = {"id_columns": [c for c in ID_COLS if c in out.columns],
                 "label_columns": list(labs.columns),
                 "feature_columns": [c for c in out.columns
                                     if c not in ID_COLS and c not in labs.columns]}
    json.dump(cols_meta, open(a.out.replace(".csv", ".cols.json"), "w"), indent=2)

    print(f"\n[+] wrote {a.out}  ({len(out)} flows x {len(out.columns)} cols)")
    print(f"[+] feature columns: {len(cols_meta['feature_columns'])} "
          f"(ID cols flagged in {a.out.replace('.csv', '.cols.json')})\n")
    print("=== class distribution (flows) ===")
    print(out["label_class"].value_counts().to_string())
    print(f"\nbinary: benign={int((out.label_binary==0).sum())}  "
          f"malicious={int((out.label_binary==1).sum())}")


if __name__ == "__main__":
    main()
