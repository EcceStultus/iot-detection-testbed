#!/usr/bin/env python3
"""Publication figures for the IoT botnet detection testbed.
Okabe-Ito colourblind-safe palette; 300 DPI; PNG + PDF."""
import json, numpy as np, pandas as pd
from datetime import datetime
import matplotlib as mpl, matplotlib.pyplot as plt
from matplotlib.patches import Patch
from scapy.all import PcapReader, IP

B="/mnt/user-data/uploads/iot-detection-testbed"; OUT="/home/claude/figs"
CAPS={"Mirai":f"{B}/captures/lab_20261008-114108.pcap",
      "Gafgyt":f"{B}/captures/cap_20261008-003301/lab_20261008-133301.pcap",
      "Mozi":f"{B}/captures/cap_20261008-004834/lab_20261008-134834.pcap"}
LABS={"Mirai":f"{B}/runs/20261008-114203-de9e/run_20261008-114203-de9e_labels.csv",
      "Gafgyt":f"{B}/runs/20261008-133339-f3e4/run_20261008-133339-f3e4_labels.csv",
      "Mozi":f"{B}/runs/20261008-134910-d12a/run_20261008-134910-d12a_labels.csv"}
CSVS={"Mirai":"/home/claude/labelled_flows.csv",
      "Gafgyt":"/mnt/user-data/outputs/labelled_flows_gafgyt.csv",
      "Mozi":"/mnt/user-data/outputs/labelled_flows_mozi.csv"}

# Okabe-Ito
OI={"black":"#000000","orange":"#E69F00","sky":"#56B4E9","green":"#009E73",
    "yellow":"#F0E442","blue":"#0072B2","vermillion":"#D55E00","purple":"#CC79A7","grey":"#999999"}
CLASS_COLOR={"benign":OI["grey"],"ddos":OI["vermillion"],"c2":OI["blue"],
             "access":OI["orange"],"dht_beacon":OI["green"],"recon":OI["purple"],
             "exploit":OI["sky"],"register":OI["yellow"],"loader":OI["black"],
             "dht_join":OI["green"],"config_pull":OI["sky"]}
ATTACK={"recon","access","loader","exploit","register","c2","ddos",
        "dht_join","config_pull","dht_beacon"}

mpl.rcParams.update({
    "font.family":"DejaVu Sans","font.size":11,"axes.titlesize":12,
    "axes.labelsize":11,"axes.spines.top":False,"axes.spines.right":False,
    "axes.grid":True,"grid.color":"#E6E6E6","grid.linewidth":0.8,
    "axes.axisbelow":True,"figure.dpi":120,"savefig.dpi":300,"savefig.bbox":"tight",
    "legend.frameon":False,"xtick.color":"#444","ytick.color":"#444",
    "axes.edgecolor":"#888","axes.labelcolor":"#222","text.color":"#222"})

def iso(s): return datetime.fromisoformat(s).timestamp()
def save(fig,name):
    fig.savefig(f"{OUT}/{name}.png"); fig.savefig(f"{OUT}/{name}.pdf"); plt.close(fig)
    print("wrote",name)

def packet_times(p):
    return np.array([float(pk.time) for pk in PcapReader(p) if IP in pk])

def phase_windows(labcsv,t0):
    df=pd.read_csv(labcsv)
    w=[]
    for _,r in df.iterrows():
        ph=str(r["phase"]).split(":")[0]
        if ph in ATTACK:
            try: w.append((ph,iso(r["start"])-t0,iso(r["end"])-t0))
            except: pass
    return w

# ---------- FIG 1: traffic-rate timeline, 3 panels ----------
fig,axes=plt.subplots(3,1,figsize=(7.2,7.4),sharex=False)
for ax,(fam,p) in zip(axes,CAPS.items()):
    t=packet_times(p); t0=t.min(); rel=t-t0
    sec=np.arange(0,int(rel.max())+2)
    rate=np.bincount(rel.astype(int),minlength=len(sec))[:len(sec)]
    ax.fill_between(sec,rate,color=OI["blue"],alpha=0.18,linewidth=0)
    ax.plot(sec,rate,color=OI["blue"],lw=0.9)
    # shade attack windows; label ddos + c2
    for ph,a,b in phase_windows(LABS[fam],t0):
        col=OI["vermillion"] if ph=="ddos" else OI["grey"]
        ax.axvspan(a,b,color=col,alpha=0.12 if ph!="ddos" else 0.22,linewidth=0)
    ax.set_title(f"{fam}",loc="left",fontweight="bold")
    ax.set_ylabel("packets / s")
    ax.margins(x=0.01)
    base=int(np.median(rate[rate>0])) if (rate>0).any() else 0
    ax.text(0.014,0.93,f"peak {int(rate.max())} pkt/s   •   baseline median {base} pkt/s",
            transform=ax.transAxes,ha="left",va="top",fontsize=8.5,color="#555",
            bbox=dict(boxstyle="round,pad=0.3",fc="white",ec="none",alpha=0.8))
axes[-1].set_xlabel("time since capture start (s)")
fig.suptitle("Network traffic rate across the botnet attack lifecycle",
             fontweight="bold",x=0.02,ha="left",y=0.999)
leg=[Patch(facecolor=OI["vermillion"],alpha=0.45,label="DDoS phase"),
     Patch(facecolor=OI["grey"],alpha=0.35,label="other attack phases")]
fig.legend(handles=leg,loc="upper right",bbox_to_anchor=(0.995,0.992),fontsize=9,ncol=2)
fig.tight_layout(rect=[0,0,1,0.96]); save(fig,"fig1_traffic_timeline")

# ---------- FIG 2: flow composition per family ----------
order=["benign","ddos","c2","access","dht_beacon"]
counts={fam:pd.read_csv(c,low_memory=False).label_class.value_counts().to_dict() for fam,c in CSVS.items()}
fams=list(CSVS); x=np.arange(len(order)); w=0.25
fig,ax=plt.subplots(figsize=(7.2,4.2))
for i,fam in enumerate(fams):
    vals=[counts[fam].get(k,0) for k in order]
    bars=ax.bar(x+(i-1)*w, np.maximum(vals,0.4), w,
                label=fam, color=[OI["blue"],OI["vermillion"],OI["orange"]][i],
                edgecolor="white",linewidth=0.6)
    for b,v in zip(bars,vals):
        if v>0: ax.text(b.get_x()+b.get_width()/2,v*1.08,str(v),ha="center",va="bottom",fontsize=7,color="#555")
ax.set_yscale("log"); ax.set_ylim(0.4,2e4)
ax.set_xticks(x); ax.set_xticklabels([k.replace("_","\n") for k in order])
ax.set_ylabel("labelled flows (log scale)")
ax.set_title("Labelled flow composition by malware family",loc="left",fontweight="bold")
ax.legend(title=None,loc="upper right",ncol=3,fontsize=9)
ax.grid(axis="x",visible=False)
fig.tight_layout(); save(fig,"fig2_flow_composition")

# ---------- FIG 3: Mirai C2 beacon rhythm ----------
t=[]
for pk in PcapReader(CAPS["Mirai"]):
    if IP in pk and ("10.10.10.60" in (pk[IP].src,pk[IP].dst)):
        t.append(float(pk.time))
t=np.array(sorted(t)); t0=t.min(); rel=t-t0
fig,ax=plt.subplots(figsize=(7.2,2.8))
ax.vlines(rel,0,1,color=OI["blue"],lw=1.1)
ax.set_yticks([]); ax.set_ylim(0,1.3)
ax.set_xlabel("time since first C2 contact (s)")
ax.set_title("Mirai C2 beaconing: periodic check-ins to the command-and-control host",
             loc="left",fontweight="bold")
ax.text(0.99,0.9,"each line = a packet to/from the C2\nclustered bursts recur on a regular interval",
        transform=ax.transAxes,ha="right",va="top",fontsize=8,color="#666")
for s in ("left","right","top"): ax.spines[s].set_visible(False)
ax.grid(axis="y",visible=False)
fig.tight_layout(); save(fig,"fig3_c2_beacon")
print("done")
