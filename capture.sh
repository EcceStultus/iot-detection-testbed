#!/usr/bin/env bash
# =============================================================================
# capture.sh  --  gateway-side PCAP capture for the IoT detection testbed
# =============================================================================
# Runs on the Raspberry Pi (the gateway/AP). Captures all lab traffic on the AP
# interface -- because the Pi is the devices' access point, every packet
# (including device-to-device) transits it, so this single vantage point sees
# the whole kill chain AND matches the "detect at the gateway" research claim.
#
# Capture hygiene (so the PCAP is a citable artefact, PROJECT.md s10):
#   * per-invocation run directory with a timestamped id,
#   * full-frame capture (snaplen 0),
#   * hourly file rotation so no single file grows unbounded,
#   * a metadata sidecar recording interface, BPF filter, host, clock/NTP state,
#     tcpdump + kernel versions, and start/end times,
#   * SHA-256 of every PCAP on exit, so integrity is verifiable later.
#
# The capture is taken on the LAN/AP side (pre-NAT), so packets keep their real
# device source IPs -- essential for joining to the generators' per-device
# ground-truth labels.
#
# Usage:
#   sudo ./capture.sh <ap_iface> [sim_c2_wan_ip] [out_dir]
# Examples:
#   sudo ./capture.sh wlan0
#   sudo ./capture.sh wlan0 192.168.1.60 captures
#
# Stop with Ctrl-C; checksums and the end time are written on exit.
# =============================================================================
set -euo pipefail

LAB_NET="192.168.25.0/24"

IFACE="${1:?usage: sudo ./capture.sh <ap_iface> [sim_c2_wan_ip] [out_dir]}"
C2_WAN="${2:-}"
OUT_ROOT="${3:-captures}"

# BPF filter: every lab packet has an endpoint in LAB_NET (device->C2 included,
# since its source is a lab device). If the sim-C2's WAN IP is given, add it so
# the post-NAT egress leg is captured too when running on a bridged interface.
FILTER="net ${LAB_NET}"
if [[ -n "${C2_WAN}" ]]; then
  FILTER="(net ${LAB_NET}) or (host ${C2_WAN})"
fi

if ! command -v tcpdump >/dev/null 2>&1; then
  echo "tcpdump not found -- install it: sudo apt install -y tcpdump" >&2
  exit 1
fi

TS="$(date -u +%Y%m%d-%H%M%S)"
RUN_DIR="${OUT_ROOT}/cap_${TS}"
mkdir -p "${RUN_DIR}"
META="${RUN_DIR}/capture_meta.json"

ntp_sync="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo unknown)"
tcpdump_ver="$(tcpdump --version 2>&1 | head -1 | tr -d '\n' || true)"

cat > "${META}" <<EOF
{
  "capture_id": "cap_${TS}",
  "host": "$(hostname)",
  "interface": "${IFACE}",
  "bpf_filter": "${FILTER}",
  "lab_net": "${LAB_NET}",
  "sim_c2_wan": "${C2_WAN}",
  "snaplen": 0,
  "rotate_seconds": 3600,
  "start_utc": "$(date -u +%Y-%m-%dT%H:%M:%S%z)",
  "ntp_synchronized": "${ntp_sync}",
  "tcpdump_version": "${tcpdump_ver}",
  "kernel": "$(uname -srm)"
}
EOF

finish() {
  echo
  echo "finalising capture ${RUN_DIR} ..."
  ( cd "${RUN_DIR}" && sha256sum ./*.pcap > SHA256SUMS 2>/dev/null || true )
  # record end time (append a small sidecar rather than rewrite the JSON)
  echo "{\"end_utc\": \"$(date -u +%Y-%m-%dT%H:%M:%S%z)\"}" > "${RUN_DIR}/capture_end.json"
  echo "wrote: ${RUN_DIR}/SHA256SUMS and capture_end.json"
  ls -la "${RUN_DIR}"
}
trap finish EXIT            # runs once, on any exit
trap 'exit 130' INT TERM    # Ctrl-C/term -> exit -> the EXIT trap finalises

if [[ "${ntp_sync}" != "yes" ]]; then
  echo "WARNING: clock is not NTP-synchronised (NTPSynchronized=${ntp_sync})."
  echo "         Label<->PCAP joins depend on a shared clock -- fix with:"
  echo "             sudo timedatectl set-ntp true"
  echo
fi

echo "capturing on ${IFACE}   filter: ${FILTER}"
echo "writing hourly-rotated PCAPs to ${RUN_DIR}/   (Ctrl-C to stop)"
echo

# -s 0 full frames; -n no name resolution (keeps capture quiet and fast);
# -G 3600 + strftime pattern = one file per hour. Run in the FOREGROUND (not
# exec) so the EXIT trap still fires to checksum the files when you Ctrl-C.
# ${FILTER} is intentionally unquoted: tcpdump takes the trailing words as the
# BPF expression.
tcpdump -i "${IFACE}" -s 0 -n \
  -G 3600 -w "${RUN_DIR}/lab_%Y%m%d-%H%M%S.pcap" \
  ${FILTER}
