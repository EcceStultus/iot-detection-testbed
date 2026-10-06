#!/usr/bin/env python3
"""
testbed_lib.py  --  shared plumbing for the IoT detection testbed generators
=============================================================================

Common, dependency-light machinery used by the traffic generators in this
repo (currently `iot_family_profiles.py`; the original `iot_botnet_emulator.py`
will migrate onto it). Keeping this in one place means every generator writes
*identical* ground-truth, so their outputs join cleanly against the same PCAP
and feed one labelling pipeline.

It provides, and nothing more:
  * the LAB_NET containment guard, with an explicit egress allowlist (PROJECT.md
    section 5: exactly one named C2 endpoint may sit outside the lab),
  * a RunContext that holds run id / seed / mode / output dir / records,
  * ground-truth recording (streamed to JSONL immediately, so a crash still
    leaves labels) and the manifest / CSV / capture-note writers,
  * a cooperative Ctrl-C stop flag and a stop-aware sleep,
  * small CLI helpers (shared arguments + the live-fire confirmation).

Design notes
------------
* No network or attack logic lives here -- this is pure bookkeeping and safety,
  so it can be read and trusted on its own.
* The label schema is a strict SUPERSET of the emulator's: it adds a `family`
  column (mirai / gafgyt / mozi / n/a). Older emulator CSVs without that column
  still join on the timestamp fields.
* stdlib only.
"""
from __future__ import annotations

import csv
import ipaddress
import json
import os
import signal
import socket
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Iterable, Optional

# =============================================================================
# Terminal colours (disabled when not a TTY, so logs/pipes stay clean)
# =============================================================================
class C:
    _on = sys.stdout.isatty()
    R = "\033[31m" if _on else ""
    G = "\033[32m" if _on else ""
    Y = "\033[33m" if _on else ""
    B = "\033[34m" if _on else ""
    DIM = "\033[2m" if _on else ""
    BOLD = "\033[1m" if _on else ""
    END = "\033[0m" if _on else ""


# =============================================================================
# Clock helpers -- every record carries BOTH wall-clock (UTC ISO-8601, for
# joining to PCAP across NTP-synced hosts) and a monotonic offset (immune to
# clock steps, for ordering within a run).
# =============================================================================
_T_MONO0 = time.monotonic()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def mono() -> float:
    return round(time.monotonic() - _T_MONO0, 3)


# =============================================================================
# Cooperative interrupt: Ctrl-C sets a flag; long loops check stopped() and the
# current action finishes cleanly so no half-labelled phase is left behind.
# =============================================================================
_STOP = False


def _handle_sigint(signum, frame):
    global _STOP
    _STOP = True
    info("Interrupt -- finishing current action and stopping.", C.Y)


def install_sigint() -> None:
    signal.signal(signal.SIGINT, _handle_sigint)


def stopped() -> bool:
    return _STOP


def sleep(seconds: float) -> None:
    """Sleep that wakes promptly on Ctrl-C."""
    end = time.time() + seconds
    while time.time() < end and not _STOP:
        time.sleep(min(0.2, max(0, end - time.time())))


# =============================================================================
# Logging
# =============================================================================
def info(m: str, colour: str = "") -> None:
    print(f"{C.DIM}{datetime.now():%H:%M:%S}{C.END} {colour}{m}{C.END}")


def banner(title: str) -> None:
    print(f"\n{C.BOLD}{C.G}-- {title}{C.END}")


def die(m: str) -> None:
    print(f"{C.R}x {m}{C.END}", file=sys.stderr)
    sys.exit(1)


def have(tool: str) -> bool:
    import shutil
    return shutil.which(tool) is not None


def local_ip(peer: str) -> str:
    """Our source IP on the route toward `peer` (no packet is sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((peer, 9))
        return s.getsockname()[0]
    except Exception:
        return "0.0.0.0"
    finally:
        s.close()


# =============================================================================
# Containment guard
# =============================================================================
def in_net(ip: str, net: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(net, strict=False)
    except ValueError:
        return False


@dataclass
class Boundary:
    """The only networks/hosts a generator is permitted to touch.

    lab_net        -- the isolated lab CIDR (must be RFC1918 unless the operator
                      deliberately flips allow_nonprivate).
    egress_allow   -- zero or more hostnames/IPs OUTSIDE the lab that are
                      explicitly permitted (PROJECT.md s5: a single self-owned
                      public C2 endpoint). Empty by default -- locked to the lab.
    allow_nonprivate -- lets lab_net be non-RFC1918 (kept False; a safety fuse).
    """
    lab_net: str
    egress_allow: tuple[str, ...] = ()
    allow_nonprivate: bool = False

    def _allowlisted(self, host: str, ip: str) -> bool:
        return host in self.egress_allow or ip in self.egress_allow

    def assert_targets(self, *targets: str) -> None:
        """Abort the run unless every target is inside lab_net or explicitly
        egress-allowlisted. A single CIDR target must be a subnet of lab_net."""
        net = ipaddress.ip_network(self.lab_net, strict=False)
        if not (net.is_private or self.allow_nonprivate):
            die(f"LAB_NET {self.lab_net} is not private and allow_nonprivate is False.")
        for t in targets:
            host = t.split("/")[0]
            if "/" in t:  # a CIDR (e.g. a scan sweep) -- must be within the lab
                try:
                    n = ipaddress.ip_network(t, strict=False)
                except ValueError:
                    die(f"target subnet '{t}' is not a valid network -- refusing.")
                if not (n.subnet_of(net) or n == net):
                    die(f"target subnet {t} is outside {self.lab_net} -- refusing.")
                continue
            try:
                ip = socket.gethostbyname(host)
            except Exception as e:
                die(f"cannot resolve target '{t}': {e}")
            if in_net(ip, self.lab_net):
                continue
            if self._allowlisted(host, ip):
                info(f"  egress-allowlisted target {t} ({ip}) -- permitted by config.", C.Y)
                continue
            die(f"target {t} ({ip}) is outside {self.lab_net} and not egress-allowlisted "
                f"-- refusing. Lab-only.")


# =============================================================================
# Run context + ground-truth recording
# =============================================================================
@dataclass
class RunContext:
    tool: str                      # basename of the generating script
    scenario: str                  # what was asked for on the CLI
    fire: bool                     # False = dry-run (nothing sent)
    seed: int
    out_dir: str                   # parent dir; a per-run subdir is created
    src: str                       # our source IP (or spoofed src)
    boundary: Boundary
    config_snapshot: dict          # saved verbatim into the manifest
    family: str = "n/a"            # default family label for records
    # timestamp (sortable) + short random suffix, so back-to-back runs within the
    # same second (e.g. an orchestrated N-repetition sweep) never collide/overwrite
    # timestamp (sortable) + short suffix from OS entropy (NOT the seeded RNG, so
    # repeated runs with the same --seed still get distinct ids), so back-to-back
    # runs within the same second (an orchestrated N-repetition sweep) never collide
    run_id: str = field(default_factory=lambda: datetime.now().strftime("%Y%m%d-%H%M%S")
                        + "-" + os.urandom(2).hex())
    records: list[dict] = field(default_factory=list)
    _started: str = ""

    # ---- paths -------------------------------------------------------------
    def run_dir(self) -> str:
        d = os.path.join(self.out_dir, self.run_id)
        os.makedirs(d, exist_ok=True)
        return d

    def _jsonl_path(self) -> str:
        return os.path.join(self.run_dir(), f"run_{self.run_id}_labels.jsonl")

    # ---- recording ---------------------------------------------------------
    def record(self, phase, technique, attck, target, t0_iso, t0_mono,
               extra: Optional[dict] = None, family: Optional[str] = None) -> dict:
        rec = {
            "run_id": self.run_id,
            "family": family or self.family,
            "phase": phase,
            "technique": technique,
            "mitre_attack": attck,
            "src": self.src,
            "target": target,
            "start": t0_iso,
            "end": now_iso(),
            "start_mono_s": t0_mono,
            "end_mono_s": mono(),
            "mode": "live" if self.fire else "dry-run",
            **(extra or {}),
        }
        self.records.append(rec)
        # stream immediately so a crash/kill still leaves labels on disk
        try:
            with open(self._jsonl_path(), "a") as fh:
                fh.write(json.dumps(rec) + "\n")
        except Exception:
            pass
        return rec

    @contextmanager
    def phase(self, phase, technique, attck, target, family: Optional[str] = None):
        t0_iso, t0_mono = now_iso(), mono()
        info(f"{C.DIM}[{attck}] {family or self.family}: src={self.src} -> {target}{C.END}")
        extra: dict = {}
        try:
            yield extra
        finally:
            self.record(phase, technique, attck, target, t0_iso, t0_mono, extra, family)

    # ---- lifecycle ---------------------------------------------------------
    def start(self) -> None:
        self._started = now_iso()
        self.record("run_start", "meta", "N/A", self.boundary.lab_net,
                    self._started, mono(), {"scenario": self.scenario})

    def finish(self) -> None:
        self.record("run_end", "meta", "N/A", self.boundary.lab_net, now_iso(), mono())
        self._write_outputs()

    # ---- output writers ----------------------------------------------------
    def _write_outputs(self) -> None:
        d = self.run_dir()
        manifest = {
            "run_id": self.run_id,
            "tool": self.tool,
            "scenario": self.scenario,
            "family": self.family,
            "mode": "live" if self.fire else "dry-run",
            "started": self._started,
            "finished": now_iso(),
            "config": self.config_snapshot,
            "phases": self.records,
        }
        with open(os.path.join(d, f"run_{self.run_id}_manifest.json"), "w") as f:
            json.dump(manifest, f, indent=2)

        cols = ["run_id", "family", "phase", "technique", "mitre_attack", "src",
                "target", "start", "end", "start_mono_s", "end_mono_s", "mode"]
        with open(os.path.join(d, f"run_{self.run_id}_labels.csv"), "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            for r in self.records:
                w.writerow(r)

        self._write_capture_note(d)

        print(f"\n{C.G}+ outputs written to {d}/{C.END}")
        for suffix in ("manifest.json", "labels.jsonl", "labels.csv", "capture.md"):
            print(f"    run_{self.run_id}_{suffix}")

    def _write_capture_note(self, d: str) -> None:
        lab = self.boundary.lab_net
        with open(os.path.join(d, f"run_{self.run_id}_capture.md"), "w") as f:
            f.write(f"""# Capture notes - run {self.run_id}

- Generator: `{self.tool}`   Family: `{self.family}`   Scenario: `{self.scenario}`
- Attacker (this box): `{self.src}`
- Lab net: `{lab}`   Mode: `{'live' if self.fire else 'dry-run'}`

On the monitoring host (mirror/SPAN port), capture continuously:

    sudo tcpdump -i <mirror_iface> -s 0 -w capture_{self.run_id}.pcap net {lab}

Label by joining the PCAP against `run_{self.run_id}_labels.csv` on the
start/end timestamps (UTC). Keep both machines on NTP. The `family` column
carries the per-family label for multi-class detection.
""")


# =============================================================================
# CLI helpers -- shared across generators so their interfaces match
# =============================================================================
def add_common_run_args(parser) -> None:
    parser.add_argument("--fire", action="store_true",
                        help="execute (default: dry-run, prints the plan only)")
    parser.add_argument("--seed", type=int, default=0, help="RNG seed (recorded)")
    parser.add_argument("--out", default="runs", help="output directory")
    parser.add_argument("--spoof-src", default=None,
                        help="source IP to spoof for raw-socket phases (must be in LAB_NET)")
    parser.add_argument("--yes", action="store_true",
                        help="skip the interactive live-fire confirmation")


def confirm_fire(lab_net: str, assume_yes: bool) -> None:
    if assume_yes:
        return
    ans = input(f"\n{C.BOLD}Run LIVE against {lab_net}? [y/N] {C.END}").strip().lower()
    if ans != "y":
        die("aborted.")


def run_phases(ctx: RunContext, order: Iterable[str],
               phase_funcs: dict[str, Callable[[RunContext], None]],
               baseline_gap: int, phase_spacing: tuple[float, float]) -> None:
    """Run phases in order, bracketing each with a benign-idle baseline window
    (clean comparison periods for the detector) and a random inter-phase gap."""
    import random
    order = list(order)
    for i, ph in enumerate(order):
        if stopped():
            break
        _baseline(ctx, f"before:{ph}", baseline_gap)
        phase_funcs[ph](ctx)
        _baseline(ctx, f"after:{ph}", baseline_gap)
        if ctx.fire and i < len(order) - 1:
            sleep(random.uniform(*phase_spacing))


def _baseline(ctx: RunContext, label: str, gap: int) -> None:
    banner(f"baseline:{label} (benign-idle {gap}s)")
    with ctx.phase(f"baseline:{label}", "benign-idle", "N/A", "n/a", family="n/a") as x:
        x["note"] = "clean comparison window; allow normal device traffic"
        info(f"  quiet window {gap}s")
        if ctx.fire:
            sleep(gap)
