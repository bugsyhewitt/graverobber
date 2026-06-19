#!/usr/bin/env bash
# graverobber/scripts/fpdb-sync.sh
#
# Refresh graverobber's fingerprint database from EdOverflow/can-i-take-over-xyz
# (Packet 07 §4 / Appendix A, D1), then verify the claim-adapter augmentations
# still resolve.
#
# graverobber's claim_adapter / nxdomain augmentations live in a SIDE-FILE
# (pkg/fingerprints/augment.json) that is applied at LOAD time, NOT written into
# the synced fingerprints cache. That is the whole point of D1: a sync re-pulls
# the upstream fingerprints (which carry no claim_adapter) and can never clobber
# graverobber's additions, because the additions are not in the synced file.
# So the sync is simply:
#
#   1. graverobber update            — fetch upstream fingerprints into the cache
#                                      (~/.config/graverobber/fingerprints.json)
#   2. list-fingerprints --claimable — confirm the augmentations still bind to the
#                                      (possibly renamed) upstream service names
#
# If a sync ever renames a service upstream such that an augmentation no longer
# binds, step 2 surfaces the drop so augment.json can be updated.
#
# Weekly is plenty — upstream moves slowly (see the systemd timer below). The DB
# is a PRIOR, never the sole signal: detection still requires live multi-signal
# corroboration (pkg/engine, D2/A5).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${GRAVEROBBER_BIN:-graverobber}"

# Prefer a freshly-built binary from the repo if the CLI is not on PATH.
if ! command -v "$BIN" >/dev/null 2>&1; then
  echo "fpdb-sync: building graverobber from $REPO_ROOT ..."
  ( cd "$REPO_ROOT" && go build -o bin/graverobber ./cmd/graverobber )
  BIN="$REPO_ROOT/bin/graverobber"
fi

echo "fpdb-sync: refreshing fingerprints from can-i-take-over-xyz ..."
"$BIN" update

echo "fpdb-sync: claim-adapter coverage after sync:"
"$BIN" list-fingerprints --claimable || {
  echo "fpdb-sync: WARNING — no claimable services resolved; check augment.json service names against upstream" >&2
  exit 1
}

echo "fpdb-sync: done."
