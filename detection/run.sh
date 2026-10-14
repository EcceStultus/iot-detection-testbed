#!/usr/bin/env bash
# run.sh -- run the IoT botnet detector over one capture and show the notices.
#
#   ./run.sh <capture.pcap> [outdir]
#
# Produces Zeek's logs (notice.log, conn.log, http.log, signatures.log, ...)
# in outdir (default: ./zeek-out/<pcap-name>/) and prints a notice summary.
set -euo pipefail

PCAP="${1:?usage: ./run.sh <capture.pcap> [outdir]}"
# resolve to an absolute path BEFORE we cd into the output dir
PCAP="$(cd "$(dirname "$PCAP")" && pwd)/$(basename "$PCAP")"
[[ -f "$PCAP" ]] || { echo "error: no such pcap: $PCAP" >&2; exit 1; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${2:-$HERE/zeek-out/$(basename "${PCAP%.*}")}"

mkdir -p "$OUT"
cd "$OUT"

# -C : skip checksum validation (capture NICs often offload checksums)
# -r : read from pcap
zeek -C -r "$PCAP" "$HERE/scripts/main.zeek"

echo
echo "=================  NOTICES  ================="
if [[ -f notice.log ]]; then
    zeek-cut -d note msg < notice.log 2>/dev/null || cat notice.log
else
    echo "(no notice.log produced -- nothing fired)"
fi
echo "============================================="
echo "logs written to: $OUT"
