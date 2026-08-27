#!/bin/sh
# Turn the newest qobuzconnect2mpd core into a readable report.
#
# The daemon runs under daemon(8) with cwd "/", which the service account
# cannot write, so cores only land anywhere useful because kern.corefile is
# set to an absolute path (see /etc/sysctl.conf). The installed binary is
# built debugoptimized and installed unstripped, so the backtrace has real
# symbols and line numbers.

set -u
BIN="${QCONNECT_BIN:-/usr/local/bin/qobuzconnect2mpd}"
CORE=$(ls -t /var/tmp/qobuzconnect2mpd-*.core 2>/dev/null | head -1)
OUT="${1:-/tmp/qconnect-crash-report.txt}"

[ -n "$CORE" ] || { echo "no core in /var/tmp"; exit 1; }
command -v gdb >/dev/null || { echo "gdb not installed"; exit 1; }

{
    echo "=== qobuzconnect2mpd crash report ==="
    echo "core:   $CORE"
    echo "binary: $BIN"
    ls -l "$CORE"
    echo
    echo "--- faulting thread ---"
    gdb -batch -q -ex "bt full" "$BIN" "$CORE" 2>/dev/null
    echo
    echo "--- all threads ---"
    gdb -batch -q -ex "thread apply all bt" "$BIN" "$CORE" 2>/dev/null
} > "$OUT" 2>&1

echo "wrote $OUT"
grep -m1 "Program terminated" "$OUT" || true
