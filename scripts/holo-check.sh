#!/usr/bin/env bash
# Guard for the embedded branch: the holo fork checked out at ../holo must be
# at the rev cfab pins in holo.rev, and holo's "testing" feature (stub sockets,
# empty state) must not be unified into cfab's build graph.
set -euo pipefail
cd "$(dirname "$0")/.."

want=$(cat holo.rev)
have=$(git -C ../holo rev-parse HEAD)
if [ "$want" != "$have" ]; then
    echo "holo-check: ../holo is at $have but holo.rev pins $want" >&2
    echo "remedy: git -C ../holo checkout $want  # or: echo $have > holo.rev" >&2
    exit 1
fi

# cargo runs on its own line so a cargo failure aborts (set -e) instead of
# reading as "no match"; real `cargo tree` lines look like
# `holo-protocol feature "testing"` (name, one space, feature).
tree=$(cargo tree -e features --prefix none)
if grep -E '^holo-(protocol|bfd|ospf|utils|northbound) feature "testing"' <<<"$tree"; then
    echo "holo-check: holo testing feature enabled in cfab's build graph (stub sockets, empty state) — fix the feature unification" >&2
    exit 1
fi

echo "holo-check OK $want"
