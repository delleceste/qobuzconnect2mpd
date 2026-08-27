#!/bin/sh
# Watch upstream QBZ for changes that affect how it talks to Qobuz.
#
# QBZ (github.com/vicrodh/qbz) is an actively developed Qobuz client that
# reverse-engineers the same private API we do, at roughly 11 commits a day.
# When Qobuz changes an endpoint, a signature, or the CMAF crypto, upstream
# usually notices before we do. This reports only the commits that touch the
# Qobuz-facing code, so the noise from UI and packaging work stays out.
#
# Writes a digest to $REPORT when something relevant landed, and stays silent
# otherwise. Run from cron; read the report at your leisure.

set -u

REPO="${QBZ_REPO:-/home/giacomo/qbz}"
STATE="${QBZ_WATCH_STATE:-/home/giacomo/.local/state/qbz-watch}"
REPORT="${QBZ_WATCH_REPORT:-/tmp/qbz-upstream-changes.txt}"
BRANCH="${QBZ_WATCH_BRANCH:-origin/main}"

# Only these paths matter to us. Everything else upstream does (Slint UI,
# packaging, translations, kiosk mode) cannot affect our compatibility.
PATHS="crates/qbz-qobuz/src crates/qbz-cmaf crates/qconnect-protocol \
crates/qconnect-core crates/qconnect-transport-ws crates/qconnect-app"

[ -d "$REPO/.git" ] || { echo "watch-qbz: no git repo at $REPO" >&2; exit 1; }
mkdir -p "$(dirname "$STATE")" || exit 1

cd "$REPO" || exit 1
git fetch --quiet origin 2>/dev/null || {
    echo "watch-qbz: fetch failed (offline?)" >&2; exit 0; }

NEW=$(git rev-parse "$BRANCH" 2>/dev/null) || {
    echo "watch-qbz: no $BRANCH" >&2; exit 1; }

if [ -f "$STATE" ]; then
    OLD=$(cat "$STATE")
else
    # First run: establish a baseline, report nothing.
    echo "$NEW" > "$STATE"
    exit 0
fi

[ "$OLD" = "$NEW" ] && exit 0

# shellcheck disable=SC2086
RELEVANT=$(git log --no-merges --format='%h %ad %s' --date=short \
           "$OLD..$NEW" -- $PATHS 2>/dev/null)

if [ -n "$RELEVANT" ]; then
    {
        echo "=== QBZ upstream: Qobuz-facing changes as of $(date '+%Y-%m-%d %H:%M') ==="
        echo "range $(echo "$OLD" | cut -c1-9)..$(echo "$NEW" | cut -c1-9)"
        echo
        echo "$RELEVANT"
        echo
        echo "--- files touched ---"
        # shellcheck disable=SC2086
        git diff --stat "$OLD..$NEW" -- $PATHS 2>/dev/null | tail -25
        echo
        echo "Review with:"
        echo "  cd $REPO && git diff $OLD..$NEW -- $PATHS"
    } > "$REPORT"
    echo "watch-qbz: $(echo "$RELEVANT" | wc -l | tr -d ' ') relevant commit(s) -> $REPORT"
fi

echo "$NEW" > "$STATE"
