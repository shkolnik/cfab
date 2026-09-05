#!/bin/bash
# cfab-entrypoint.sh — container PID 1: up, verify once (informational — a member that cannot
# converge stays up for inspection rather than restart-looping), then wait; SIGTERM = cfab down
# (rollback is `docker stop` / `docker compose down`). No systemd in a container, so the engine
# and any watchdog/shape units cfab starts are its own detached children; `cfab down` stops them
# by pidfile, the same as on a native host.
set -uo pipefail

[ -n "${CFAB_HOST:-}" ] || unset CFAB_HOST   # empty env (e.g. from compose defaulting) = use hostname

# An overriding command (e.g. `docker run cfab cfab check`, `docker run cfab cfab --version`)
# runs as given and exits — only a bare `docker run`/compose invocation (no command) enters the
# up/verify/wait member lifecycle below.
if [ $# -gt 0 ]; then
	exec "$@"
fi

term() {
	echo "cfab: stop requested — tearing down"
	cfab down
	exit 0
}
trap term TERM INT

cfab up || echo "cfab: up FAILED (rc=$?) — run 'docker exec <container> cfab down'; staying up for inspection" >&2
cfab verify --timeout "${CFAB_VERIFY_TIMEOUT:-90}" || echo "cfab: verify did not pass — inspect with: docker exec <container> cat /run/cfab/engine.log" >&2
echo "cfab: running (docker exec <container> cfab verify --timeout 5 to re-check)"

while :; do
	sleep 3600 &
	wait $! || true
done
