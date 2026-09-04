#!/usr/bin/env bash
# Gate-0 live oracle: the embedded engine (`cfab engine`) against FRR, in two netnses.
#
# Runs as root INSIDE a throwaway privileged container (no host network) that has iproute2,
# frr (10.x: zebra/bfdd/ospfd/mgmtd + vtysh), jq, socat, and the cfab binary at
# $ORACLE_BIN. Nothing here touches the container's own netns beyond creating and deleting
# the two netnses H and F; every interface, route, daemon, and file it creates is torn down
# on exit (trap), and the last line is `netns after: 0`.
#
# Topology (the interop spike's B2 shape, reduced to cfab's own naming):
#   netns H = cfab engine, member `h` (node 1)      netns F = FRR, the oracle peer (node 2)
#   cfab-st    10.99.1.1/24  <-veth->  f-st    10.99.1.2/24   zone storage (99), seg 1
#   cfab-st-bk 10.99.2.1/24  <-veth->  f-st-bk 10.99.2.2/24   zone storage (99), seg 2
#   cfab-cl    10.199.1.1/24 <-veth->  f-cl    10.199.1.2/24  zone cluster (199), seg 1
#   identities: H cfab-id99 10.99.0.1/32, cfab-id199 10.199.0.1/32 (veth pairs, as `up`
#   makes them); F f-id99 10.99.0.2/32, f-id199 10.199.0.2/32 (same shape: an address on
#   `lo` would be advertised by BOTH FRR instances and dissolve the zone separation the
#   route asserts depend on).
# Both storage segments carry cost 10 so 10.99.0.2 is an ECMP route (assert A3).
#
# Asserts: A0 the engine writes no forwarding sysctl (holo patch P1, watched not read);
# A1 OSPF full on every wire, both instances; A2 BFD up (engine state doc and
# FRR agree); A3 ECMP 10.99.0.2 proto 201 src 10.99.0.1; A4 10.199.0.2 proto 201 src
# 10.199.0.1; A5 SIGTERM withdraws routes + socket within 5 s; A6 crash (SIGKILL) leaves
# routes, restart purges them (log line, count >= 1) and reinstalls within CONVERGE_S; A7 teeth:
# --unsafe-no-prefsrc makes A3 go RED; A8 a configured interface absent from the kernel is
# not silent. Every assert prints OK/RED with its evidence; any RED => exit 1.
set -euo pipefail
# Job control OFF, explicitly: a background job then stays in this shell's process group, so
# `setsid` is not a process-group leader and execs the engine in place — $! IS the engine.
# With job control on (`set -m`) setsid forks and the run loses the engine's pid (measured).
set +m

ORACLE_BIN=${ORACLE_BIN:-/oracle/cfab}
# Writable state (fabric.conf, run dir, logs). /oracle is mounted read-only by the gate-0
# container, so the working files live on the container's own tmpfs.
WORK=${ORACLE_WORK:-/run/cfab-oracle}
RUN=$WORK/run
CONF=$WORK/fabric.conf
SOCK=$RUN/engine.sock
PIDFILE=$RUN/engine.pid
LOG=$RUN/engine.log
FRR_PS=oracle                      # FRR pathspace (-N): /etc/frr/$FRR_PS, /var/run/frr/$FRR_PS
FRR_BIN=/usr/lib/frr
FRR_ETC=/etc/frr/$FRR_PS
FRR_RUN=/var/run/frr/$FRR_PS
FRR_LOG=/var/log/frr
PROTO_OSPF=201                     # engine's private route protocol; = emit::engine::PROTO_BASE
                                   # (src/emit/engine.rs) + 0 = ospf. Change both together.
# How long any assert waits for the FIB to catch up with a converged adjacency. MEASURED on
# pve3 (gate 0, 2026-09-04, 29 immediate restarts of the engine against a live FRR peer):
# both identity routes are back in 10.6-18.1 s in 23 runs and in 40.2-40.3 s in 6 — a
# bimodal distribution with nothing in between and no run that failed to converge. A window
# under ~40 s therefore makes these asserts flaky rather than strict (it produced three
# false REDs before this was measured); the OK lines print the time, which is the evidence.
CONVERGE_S=60

RED_COUNT=0
ENGINE_PID=""
T_SPAWN=0

ts() { date -u +%H:%M:%S.%N | cut -c1-12; }
say() { printf '%s %s\n' "$(ts)" "$*"; }
ok() { say "OK  $*"; }
red() { say "RED $*"; RED_COUNT=$((RED_COUNT + 1)); }
die() { say "FATAL $*"; exit 1; }

# ---------------------------------------------------------------------------------------
# preflight: every tool this script needs, named before anything is created
# ---------------------------------------------------------------------------------------
preflight() {
    [ "$(id -u)" = 0 ] || die "must run as root (netns, veth, FRR)"
    for t in ip jq socat vtysh setsid; do
        command -v "$t" >/dev/null 2>&1 || die "missing tool: $t"
    done
    for d in mgmtd zebra bfdd ospfd; do
        [ -x "$FRR_BIN/$d" ] || die "missing FRR daemon: $FRR_BIN/$d"
    done
    id frr >/dev/null 2>&1 || die "no 'frr' user (frr package not installed?)"
    [ -x "$ORACLE_BIN" ] || die "cfab binary not executable: $ORACLE_BIN (set ORACLE_BIN)"
    for ns in H F; do
        ip netns list | grep -qE "^$ns( |$)" && die "netns $ns already exists: not ours to reuse"
    done
    say "preflight: $(ip -V) | $(vtysh --version 2>/dev/null | head -1) | cfab $("$ORACLE_BIN" --version 2>&1 | head -1)"
}

# ---------------------------------------------------------------------------------------
# fabric.conf: two hosts, two zones, three segments; no gw row, no VRRP, no forwarding.
# Wire names are placeholders: the oracle creates the segment interfaces itself and never
# runs `up`, so FABRIC_MODE=tagged only has to parse.
# ---------------------------------------------------------------------------------------
write_conf() {
    local extra_row=${1:-}
    mkdir -p "$WORK" "$RUN"
    cat > "$CONF" <<EOF
FABRIC_MODE=tagged
MEMBER_TABLE="
h 1 host h-st:1000 h-cl:1000 -
f 2 host f-st-w:1000 f-cl-w:1000 -
"
FABRIC_DOMAIN=oracle.example
ZONE_TABLE="
storage  99 0 cs0 2000 2 4 -
cluster 199 6 cs6  200 0 1 -
"
CLASS_TABLE="
cfab-st     st storage 1 100 primary 10
cfab-st-bk  cl storage 2 101 backup  10
cfab-cl     cl cluster 1 200 primary 10
${extra_row}
"
LEAF_COST_OFFSET=30000
HOST_FORWARD=0
ADMIN_FLOOR=100
ADMIN_BAND=1
FORWARD_ALLOW=""
VRRP_GW=0
VRRP_VRID=99
VRRP_IF=cfab-st-vr
VRRP_ADVERT_MS=100
PCP_CTRL=6
DSCP_MARK=1
DSCP_CTRL=cs6
BFD_RX_MS=300
BFD_TX_MS=300
BFD_MULT=3
OSPF_HELLO=1
OSPF_DEAD=3
BGP_AS=65000
BGP_KEEPALIVE_S=1
BGP_HOLD_S=3
BGP_CONNECT_S=3
USB_NICS=""
CFAB_RUN=$RUN
EOF
}

# ---------------------------------------------------------------------------------------
# topology
# ---------------------------------------------------------------------------------------
# A /32 on an always-up veth pair, both ends in the netns — the shape `up`'s mk_identity
# makes (dummy is absent on some target kernels).
mk_identity() {                    # ns name cidr
    local ns=$1 name=$2 cidr=$3
    ip -n "$ns" link add "$name" type veth peer name "$name-peer"
    ip -n "$ns" addr add "$cidr" dev "$name"
    ip -n "$ns" link set "$name-peer" up
    ip -n "$ns" link set "$name" up
}

mk_wire() {                        # h-if h-cidr f-if f-cidr
    local hif=$1 hcidr=$2 fif=$3 fcidr=$4
    ip link add "$hif" type veth peer name "$fif"
    ip link set "$hif" netns H
    ip link set "$fif" netns F
    ip -n H addr add "$hcidr" dev "$hif"
    ip -n F addr add "$fcidr" dev "$fif"
    ip -n H link set "$hif" up
    ip -n F link set "$fif" up
}

build_topology() {
    ip netns add H
    ip netns add F
    ip -n H link set lo up
    ip -n F link set lo up
    mk_wire cfab-st 10.99.1.1/24 f-st 10.99.1.2/24
    mk_wire cfab-st-bk 10.99.2.1/24 f-st-bk 10.99.2.2/24
    mk_wire cfab-cl 10.199.1.1/24 f-cl 10.199.1.2/24
    mk_identity H cfab-id99 10.99.0.1/32
    mk_identity H cfab-id199 10.199.0.1/32
    mk_identity F f-id99 10.99.0.2/32
    mk_identity F f-id199 10.199.0.2/32
    say "topology: H=[$(ip -n H -br link | awk '{print $1}' | grep -v peer | tr '\n' ' ')] F=[$(ip -n F -br link | awk '{print $1}' | grep -v peer | tr '\n' ' ')]"
}

# ---------------------------------------------------------------------------------------
# FRR in netns F: pathspace-isolated daemons (proven shape on FRR 10.3: no -f, config via
# `vtysh -b`; mgmtd must run or vtysh -b rejects config). Blocks mirror what cfab's FRR
# build generates (main:src/emit/frr.rs) minus the src route-map: one ospfd instance per
# zone id, broadcast, hello 1 / dead 3, BFD profile 300/300/3, passive identity.
# ---------------------------------------------------------------------------------------
frr_conf() {
    cat <<EOF
frr defaults traditional
hostname oracle-f
log file $FRR_LOG/oracle-frr.log
bfd
 profile cfab-fast
  receive-interval 300
  transmit-interval 300
  detect-multiplier 3
 exit
exit
EOF
    local spec ifn inst
    for spec in "f-st 99" "f-st-bk 99" "f-cl 199"; do
        read -r ifn inst <<< "$spec"
        cat <<EOF
interface $ifn
 ip ospf $inst area 0
 ip ospf network broadcast
 ip ospf hello-interval 1
 ip ospf dead-interval 3
 ip ospf cost 10
 ip ospf bfd
 ip ospf bfd profile cfab-fast
exit
EOF
    done
    cat <<EOF
interface f-id99
 ip ospf 99 area 0
 ip ospf passive
exit
interface f-id199
 ip ospf 199 area 0
 ip ospf passive
exit
router ospf 99
 ospf router-id 10.99.0.2
exit
router ospf 199
 ospf router-id 10.199.0.2
exit
EOF
}

start_frr() {
    mkdir -p "$FRR_ETC" "$FRR_RUN" "$FRR_LOG"
    frr_conf > "$FRR_ETC/frr.conf"
    echo "service integrated-vtysh-config" > "$FRR_ETC/vtysh.conf"
    chown -R frr:frr "$FRR_ETC" "$FRR_RUN" "$FRR_LOG"
    local d
    # -d daemonizes; stdout must not be a pipe (the daemon inherits it and the reader hangs).
    for d in mgmtd zebra bfdd; do
        ip netns exec F "$FRR_BIN/$d" -d -N "$FRR_PS" > "$FRR_LOG/$d-$FRR_PS.out" 2>&1 < /dev/null
    done
    for d in 99 199; do
        ip netns exec F "$FRR_BIN/ospfd" -d -N "$FRR_PS" -n "$d" > "$FRR_LOG/ospfd-$d-$FRR_PS.out" 2>&1 < /dev/null
    done
    local i
    for i in $(seq 1 20); do
        [ -e "$FRR_RUN/mgmtd.pid" ] && [ -e "$FRR_RUN/zebra.pid" ] && [ -e "$FRR_RUN/bfdd.pid" ] \
            && [ -e "$FRR_RUN/ospfd-99.pid" ] && [ -e "$FRR_RUN/ospfd-199.pid" ] && break
        sleep 0.5
    done
    [ -e "$FRR_RUN/ospfd-199.pid" ] || die "FRR daemons did not write their pidfiles in $FRR_RUN (see $FRR_LOG)"
    sleep 0.5
    local out
    out=$(ip netns exec F vtysh -N "$FRR_PS" -b 2>&1 || true)
    if printf '%s\n' "$out" | grep -qE '^%|has not been set|is not running'; then
        die "vtysh -b rejected config lines: $out"
    fi
    # vtysh drops whole blocks for a daemon that is not there; read the result back.
    local rc
    # `|| true`: a vtysh failure must reach the `die` below, not exit with vtysh's status.
    rc=$(ip netns exec F vtysh -N "$FRR_PS" -c "show running-config" 2>&1 || true)
    local want
    for want in "router ospf 99" "router ospf 199" " ip ospf bfd profile cfab-fast"; do
        printf '%s\n' "$rc" | grep -qF -- "$want" || die "FRR did not load '$want' (vtysh -b said: $out)"
    done
    say "FRR up in F: $(ls "$FRR_RUN"/*.pid | xargs -n1 basename | tr '\n' ' ')"
}

vtysh_f() { ip netns exec F vtysh -N "$FRR_PS" -c "$1"; }

stop_frr() {
    [ -d "$FRR_RUN" ] || return 0
    local f pid
    for f in "$FRR_RUN"/*.pid; do          # custody: only pids from our pathspace's pidfiles
        [ -e "$f" ] || continue
        pid=$(cat "$f" 2>/dev/null || true)
        [ -n "$pid" ] && kill -TERM "$pid" 2>/dev/null || true
    done
    local i alive
    for i in $(seq 1 20); do
        alive=0
        for f in "$FRR_RUN"/*.pid; do
            [ -e "$f" ] || continue
            pid=$(cat "$f" 2>/dev/null || true)
            # -d daemons reparent to pid 1, which may not reap: a zombie counts as gone.
            if [ -n "$pid" ] && [ -e "/proc/$pid/stat" ] \
                && [ "$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null)" != Z ]; then
                alive=1
            fi
        done
        [ "$alive" = 0 ] && break
        sleep 0.5
    done
    rm -rf "$FRR_RUN" "$FRR_ETC"
}

# ---------------------------------------------------------------------------------------
# engine lifecycle
# ---------------------------------------------------------------------------------------
state_doc() {                      # one request; empty output when nothing answers
    [ -S "$SOCK" ] || return 1
    # -t 5: socat's default lingers only 0.5 s after stdin EOF before closing the socket;
    # a state reply slower than that would be dropped (empty doc → spurious RED).
    printf 'state\n' | socat -t 5 -T 5 - UNIX-CONNECT:"$SOCK" 2>/dev/null
}

# start_engine <log> [engine args…]; sets ENGINE_PID. `ip netns exec` execs the command in
# place (no fork), so $! is the engine's own pid; the pidfile is cross-checked at ready.
# NO_COLOR=1: tracing-subscriber's fmt layer colors stderr even when it is a file (measured:
# `count=2` arrives as `ESC[3mcount ESC[0m ESC[2m= ESC[0m2`), which defeats every grep below;
# it honors NO_COLOR. elog() strips escapes anyway, in case a build stops honoring it.
start_engine() {
    local log=$1; shift
    NO_COLOR=1 ip netns exec H setsid "$ORACLE_BIN" --config "$CONF" --host h engine "$@" > "$log" 2>&1 < /dev/null &
    ENGINE_PID=$!
    T_SPAWN=$(date +%s.%N)
    say "engine started pid $ENGINE_PID log $log args [$*]"
}

elog() { sed -e $'s/\x1b\[[0-9;]*m//g' "$1"; }   # engine log with ANSI escapes stripped

engine_alive() { [ -n "$ENGINE_PID" ] && [ -e "/proc/$ENGINE_PID/stat" ] && [ "$(awk '{print $3}' "/proc/$ENGINE_PID/stat")" != Z ]; }

# Wait ≤30 s for the socket to answer "ready": true; prints the latency. Returns 1 (no
# die) so callers that expect failure can decide.
#
# Custody: $ENGINE_PID is the engine itself because `set +m` (top of the script) keeps the
# background job in this shell's process group, so `setsid` is not a group leader and execs
# in place — measured both ways: with job control ON setsid forks and $! is already gone one
# iteration later. No pid can be recovered in that case (the engine writes engine.pid only
# after its commit, engine/mod.rs), so the mismatch is fatal rather than adopted.
wait_ready() {
    local i doc pidfile
    for i in $(seq 1 60); do
        if ! engine_alive; then
            say "engine pid $ENGINE_PID exited before ready; log tail: $(tail -3 "$1" 2>/dev/null | tr '\n' ';')"
            return 1
        fi
        doc=$(state_doc || true)
        if [ -n "$doc" ] && [ "$(printf '%s' "$doc" | jq -r '.ready' 2>/dev/null)" = true ]; then
            pidfile=$(cat "$PIDFILE" 2>/dev/null || echo none)
            say "engine ready after $(awk -v a="$(date +%s.%N)" -v b="$T_SPAWN" 'BEGIN{printf "%.2f", a - b}') s; pidfile=$pidfile spawn=$ENGINE_PID"
            [ "$pidfile" = "$ENGINE_PID" ] || die "engine.pid ($pidfile) is not the spawned pid ($ENGINE_PID): setsid forked (job control on?) and this run cannot stop the engine it started"
            return 0
        fi
        sleep 0.5
    done
    say "engine not ready within 30 s; last log lines:"; tail -5 "$1" 2>/dev/null || true
    return 1
}

stop_engine() {                    # SIGTERM, wait ≤10 s, SIGKILL after
    engine_alive || { ENGINE_PID=""; return 0; }
    kill -TERM "$ENGINE_PID" 2>/dev/null || true
    local i
    for i in $(seq 1 20); do
        engine_alive || break
        sleep 0.5
    done
    if engine_alive; then
        say "engine pid $ENGINE_PID ignored SIGTERM for 10 s: SIGKILL"
        kill -KILL "$ENGINE_PID" 2>/dev/null || true
    fi
    wait "$ENGINE_PID" 2>/dev/null || true
    ENGINE_PID=""
}

# Wait ≤$1 s until every configured wire has a full neighbor in its instance (the state doc).
wait_full() {                      # timeout-s
    local i doc
    for i in $(seq 1 $(( $1 * 2 ))); do
        doc=$(state_doc || true)
        if [ -n "$doc" ] && [ "$(printf '%s' "$doc" | jq -r '
            [ (.ospf.storage.interfaces["cfab-st"], .ospf.storage.interfaces["cfab-st-bk"], .ospf.cluster.interfaces["cfab-cl"])
              | any(.neighbors[]?; .state == "full") ] | all' 2>/dev/null)" = true ]; then
            return 0
        fi
        sleep 0.5
    done
    return 1
}

proto_routes() { ip -n H -4 route show table all proto "$PROTO_OSPF"; }

# ---------------------------------------------------------------------------------------
# asserts
# ---------------------------------------------------------------------------------------
# A0: the engine must never write a forwarding sysctl (holo patch P1 deletes holo-routing's
# startup `ipv4_forwarding("1")` / `ipv6_forwarding("1")`; forwarding is cfab's scoped policy).
# This is the only place that watches it happen instead of reading that the code is gone: the
# container is privileged, so an unpatched build's write WOULD succeed.
# The baseline is SET to 0, not assumed: a new netns copies init_net's all-devconf, and on any
# host running dockerd that is `ip_forward=1` (measured on pve3: a fresh `ip netns add` starts
# at 1). Without the write the assert could never see 0 -> 1, which is precisely the pre-P1
# behavior it exists to catch.
FWD4_BEFORE=""
FWD6_BEFORE=""

read_fwd() {                       # 4|6 -> the sysctl's value in H, or ERR when unreadable
    local v
    case $1 in
        4) v=$(ip netns exec H cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || true) ;;
        *) v=$(ip netns exec H cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || true) ;;
    esac
    printf '%s' "${v:-ERR}"
}

write_fwd() {                      # 4|6 value -> write the sysctl in H (netns H is ours)
    case $1 in
        4) ip netns exec H sh -c "echo $2 > /proc/sys/net/ipv4/ip_forward" 2>/dev/null || true ;;
        *) ip netns exec H sh -c "echo $2 > /proc/sys/net/ipv6/conf/all/forwarding" 2>/dev/null || true ;;
    esac
}

sample_forwarding() {              # call immediately before the first start_engine
    local i4 i6
    i4=$(read_fwd 4)
    i6=$(read_fwd 6)
    write_fwd 4 0
    write_fwd 6 0
    FWD4_BEFORE=$(read_fwd 4)
    FWD6_BEFORE=$(read_fwd 6)
    say "A0 baseline in H: inherited ipv4.ip_forward=$i4 ipv6.conf.all.forwarding=$i6; set to ipv4.ip_forward=$FWD4_BEFORE ipv6.conf.all.forwarding=$FWD6_BEFORE"
}

a0_forwarding_untouched() {
    local a4 a6 ev
    a4=$(read_fwd 4)
    a6=$(read_fwd 6)
    ev="ipv4.ip_forward $FWD4_BEFORE->$a4, ipv6.conf.all.forwarding $FWD6_BEFORE->$a6"
    if [ "$FWD4_BEFORE" != 0 ] || [ "$FWD6_BEFORE" != 0 ]; then
        red "A0 cannot judge: the baseline in H would not go to 0 before the engine started ($ev)"
    elif [ "$a4" = 0 ] && [ "$a6" = 0 ]; then
        ok "A0 engine wrote no forwarding sysctl: $ev"
    else
        red "A0 forwarding sysctl written by the engine (want 0->0 for both; holo patch P1): $ev"
    fi
}

a1_ospf_full() {
    local doc summary
    doc=$(state_doc || true)
    summary=$(printf '%s' "$doc" | jq -c '[.ospf | to_entries[] | {zone: .key, rid: .value.router_id,
        ifs: [.value.interfaces | to_entries[] | {if: .key, state: .value.state, nbrs: [.value.neighbors[] | .state]}]}]' 2>/dev/null || echo "$doc")
    if [ "$(printf '%s' "$doc" | jq -r '
            [ (.ospf.storage.interfaces["cfab-st"], .ospf.storage.interfaces["cfab-st-bk"], .ospf.cluster.interfaces["cfab-cl"])
              | any(.neighbors[]?; .state == "full") ] | all' 2>/dev/null)" = true ]; then
        ok "A1 both instances full on every wire: $summary"
    else
        red "A1 not full on every wire: $summary"
    fi
    say "A1 FRR view: $(vtysh_f 'show ip ospf neighbor' | grep -E 'Full|Instance' | tr -s ' ' | tr '\n' ';')"
}

a2_bfd_up() {
    local doc n_up n_all frr_up
    doc=$(state_doc || true)
    # `|| echo ERR`: a truncated/malformed state doc must go RED here, not abort the run
    # (jq exits 5 on a parse error, and `set -e` + pipefail would kill every later assert).
    n_all=$(printf '%s' "$doc" | jq -r '.bfd | length' 2>/dev/null || echo ERR)
    n_up=$(printf '%s' "$doc" | jq -r '[.bfd[] | select(.state == "up")] | length' 2>/dev/null || echo ERR)
    frr_up=$(vtysh_f 'show bfd peers brief' | grep -cE '[[:space:]]up[[:space:]]*$' || true)
    if [ "$n_all" = 3 ] && [ "$n_up" = 3 ] && [ "$frr_up" = 3 ]; then
        ok "A2 BFD up: engine $n_up/$n_all, FRR brief $frr_up up: $(printf '%s' "$doc" | jq -c '[.bfd[] | {if, peer, state, rx_us, tx_us, mult}]')"
    else
        red "A2 BFD: engine $n_up/$n_all up, FRR brief $frr_up up (want 3/3/3): $(printf '%s' "$doc" | jq -c '.bfd')"
        say "A2 FRR: $(vtysh_f 'show bfd peers brief' | tr -s ' ' | tr '\n' ';')"
    fi
}

# Two independent predicates on the 10.99.0.2 route, so a caller can tell "src missing"
# from "second nexthop not there yet" (the second link's inclusion in the router-LSA is
# held by MinLSInterval after the first adjacency, ~5 s in the spike). Both print nothing.
# check_ecmp: our proto and BOTH storage nexthops. check_src: prefsrc 10.99.0.1.
check_ecmp() {
    local r
    r=$(ip -n H route show 10.99.0.2 2>/dev/null || true)
    [ -n "$r" ] || return 1
    printf '%s\n' "$r" | head -1 | grep -qE "proto $PROTO_OSPF( |$)" || return 1
    printf '%s\n' "$r" | grep -qE 'nexthop via 10\.99\.1\.2 dev cfab-st( |$)' || return 1
    printf '%s\n' "$r" | grep -qE 'nexthop via 10\.99\.2\.2 dev cfab-st-bk( |$)' || return 1
    return 0
}

check_src() {
    ip -n H route show 10.99.0.2 2>/dev/null | head -1 | grep -qE 'src 10\.99\.0\.1( |$)'
}

# Wait ≤$1 s for the two identity routes to be installed (any src), so route asserts read
# a converged FIB rather than a race.
wait_routes() {
    local i
    for i in $(seq 1 $(( $1 * 2 ))); do
        if ip -n H route show 10.99.0.2 | grep -q "proto $PROTO_OSPF" \
            && ip -n H route show 10.199.0.2 | grep -q "proto $PROTO_OSPF"; then
            return 0
        fi
        sleep 0.5
    done
    return 1
}

# Wait ≤$1 s for 10.99.0.2 to be ECMP over both storage wires (check_ecmp), i.e. past the
# MinLSInterval hold; without this a single-nexthop route is the likely state the instant
# the first nexthop lands, and any src assertion made then is evidence for nothing.
wait_ecmp() {
    local i
    for i in $(seq 1 $(( $1 * 2 ))); do
        check_ecmp && return 0
        sleep 0.5
    done
    return 1
}

a3_ecmp_prefsrc() {
    local r
    r=$(ip -n H route show 10.99.0.2 2>/dev/null | tr '\n' ';' | tr -s ' \t' ' ' || true)
    if check_ecmp && check_src; then
        ok "A3 10.99.0.2 ECMP proto $PROTO_OSPF src 10.99.0.1: $r"
    else
        red "A3 10.99.0.2 (want 2 nexthops cfab-st + cfab-st-bk, proto $PROTO_OSPF, src 10.99.0.1; ecmp=$(check_ecmp && echo yes || echo no) src=$(check_src && echo yes || echo no)): [$r]"
    fi
}

a4_cluster_prefsrc() {
    local r
    r=$(ip -n H route show 10.199.0.2 2>/dev/null | tr '\n' ';' | tr -s ' \t' ' ' || true)
    if printf '%s' "$r" | grep -qE "proto $PROTO_OSPF( |;|$)" && printf '%s' "$r" | grep -qE 'src 10\.199\.0\.1( |;|$)' \
        && printf '%s' "$r" | grep -qE 'dev cfab-cl( |;|$)'; then
        ok "A4 10.199.0.2 proto $PROTO_OSPF src 10.199.0.1 via cfab-cl: $r"
    else
        red "A4 10.199.0.2 (want dev cfab-cl proto $PROTO_OSPF src 10.199.0.1): [$r]"
    fi
}

a5_sigterm_withdraws() {
    local t0 i left before
    # Withdrawal proves nothing unless something was installed: count the routes (route
    # headers only — `grep -c .` also counts each `\tnexthop via …` continuation line, so an
    # ECMP route would report as 3) immediately before the signal.
    before=$(proto_routes | grep -c '^[^[:space:]]' || true)
    if [ "${before:-0}" -lt 1 ]; then
        red "A5 no routes proto $PROTO_OSPF were installed before the SIGTERM: withdrawal proves nothing"
        stop_engine
        return 0
    fi
    t0=$(date +%s.%N)
    kill -TERM "$ENGINE_PID" || true
    for i in $(seq 1 10); do
        left=$(proto_routes | grep -c '^[^[:space:]]' || true)
        if [ "$left" = 0 ] && [ ! -e "$SOCK" ]; then
            ok "A5 SIGTERM: all $before route(s) proto $PROTO_OSPF withdrawn and socket gone after $(echo "$(date +%s.%N) $t0" | awk '{printf "%.2f", $1 - $2}') s"
            stop_engine
            return 0
        fi
        sleep 0.5
    done
    red "A5 SIGTERM: after 5 s $left route(s) proto $PROTO_OSPF remain, socket $([ -e "$SOCK" ] && echo present || echo gone): $(proto_routes | tr '\n' ';')"
    stop_engine
}

a6_crash_window() {
    local before purge count t0 i
    start_engine "$RUN/engine-a6a.log"
    wait_ready "$RUN/engine-a6a.log" || { red "A6 engine not ready before the crash"; stop_engine; return 0; }
    wait_routes "$CONVERGE_S" || { red "A6 routes not installed before the crash: $(proto_routes | tr '\n' ';')"; stop_engine; return 0; }
    kill -KILL "$ENGINE_PID" 2>/dev/null || true
    wait "$ENGINE_PID" 2>/dev/null || true
    ENGINE_PID=""
    sleep 0.5
    before=$(proto_routes | grep -c '^[^[:space:]]' || true)
    if [ "$before" -ge 1 ]; then
        ok "A6a SIGKILL left $before route(s) proto $PROTO_OSPF in the kernel (the crash window): $(proto_routes | grep -v '^[[:space:]]' | tr '\n' ';')"
    else
        red "A6a SIGKILL left no routes proto $PROTO_OSPF; nothing for the restart to purge"
    fi
    t0=$(date +%s.%N)
    start_engine "$RUN/engine-a6b.log"
    wait_ready "$RUN/engine-a6b.log" || { red "A6 engine did not restart after the crash"; stop_engine; return 0; }
    purge=$(elog "$RUN/engine-a6b.log" | grep -m1 'purged stale routes' || true)
    count=$(printf '%s' "$purge" | grep -oE 'count=[0-9]+' | cut -d= -f2 || true)
    if [ -n "$purge" ] && [ "${count:-0}" -ge 1 ]; then
        ok "A6b restart purged stale routes (count=$count): $purge"
    else
        red "A6b restart did not log a purge with count >= 1 (log: $(elog "$RUN/engine-a6b.log" | grep -iE 'purg|stale' | tr '\n' ';'))"
    fi
    # The plan said 10 s; the spike measured ~5 s of ECMP restore from MinLSInterval alone,
    # on top of adjacency re-formation, and gate 0 then measured a 40 s second mode (see
    # CONVERGE_S). The measured time on the OK line is the evidence (spec §8).
    for i in $(seq 1 $((CONVERGE_S * 2))); do
        if check_ecmp && check_src && ip -n H route show 10.199.0.2 | grep -q "proto $PROTO_OSPF"; then
            ok "A6c routes reinstalled (ECMP + src) $(echo "$(date +%s.%N) $t0" | awk '{printf "%.2f", $1 - $2}') s after the restart: $(ip -n H route show 10.99.0.2 | tr '\n' ';' | tr -s ' \t' ' ')"
            stop_engine
            return 0
        fi
        sleep 0.5
    done
    red "A6c routes not reinstalled within $CONVERGE_S s of the restart (ecmp=$(check_ecmp && echo yes || echo no) src=$(check_src && echo yes || echo no)): [$(proto_routes | tr '\n' ';')]"
    say "A6c engine state doc: $(state_doc | jq -c '.ospf | to_entries | map({zone: .key, ifs: (.value.interfaces | to_entries | map({(.key): [.value.neighbors[]?.state]}))})' 2>/dev/null || echo UNREADABLE)"
    say "A6c engine log: $(elog "$RUN/engine-a6b.log" | tail -12 | tr '\n' ';')"
    say "A6c FRR neighbors: $(vtysh_f 'show ip ospf neighbor' | tr -s ' ' | tr '\n' ';')"
    say "A6c FRR bfd: $(vtysh_f 'show bfd peers brief' | tr -s ' ' | tr '\n' ';')"
    say "A6c FRR db 99: $(vtysh_f 'show ip ospf 99 database router' | tr -s ' ' | tr '\n' ';')"
    stop_engine
}

a7_teeth_no_prefsrc() {
    start_engine "$RUN/engine-a7.log" --unsafe-no-prefsrc
    wait_ready "$RUN/engine-a7.log" || { red "A7 engine not ready with --unsafe-no-prefsrc"; stop_engine; return 0; }
    wait_routes "$CONVERGE_S" || { red "A7 routes not installed with --unsafe-no-prefsrc: $(proto_routes | tr '\n' ';')"; stop_engine; return 0; }
    # The route must be fully converged (both nexthops) before the src check means anything:
    # a single-nexthop route fails A3 too, for a reason that has nothing to do with prefsrc.
    wait_ecmp "$CONVERGE_S" || { red "A7 10.99.0.2 not ECMP within $CONVERGE_S s with --unsafe-no-prefsrc (cannot judge the src check): [$(ip -n H route show 10.99.0.2 | tr '\n' ';' | tr -s ' \t' ' ')]"; stop_engine; return 0; }
    local r
    r=$(ip -n H route show 10.99.0.2 2>/dev/null | tr '\n' ';' | tr -s ' \t' ' ' || true)
    if check_src; then
        red "A7 teeth: ECMP route carries src 10.99.0.1 without prefsrc rules — the src check has no teeth: $r"
    else
        ok "A7 teeth: ECMP route (both nexthops, proto $PROTO_OSPF) has NO src 10.99.0.1 without prefsrc rules, so A3's src check goes RED for the src alone: $r"
    fi
    elog "$RUN/engine-a7.log" | grep -q 'unsafe-no-prefsrc' && say "A7 engine warned: $(elog "$RUN/engine-a7.log" | grep -m1 'unsafe-no-prefsrc')"
    stop_engine
}

# A configured segment interface that does not exist in the kernel. The leafref is
# config->config (the interfaces tree is emitted from fabric.conf), so libyang validates;
# what must NOT happen is silence. Accepted outcomes, each recorded: the engine exits
# nonzero naming the interface; or it comes up and the state document / log shows the
# interface as `down` by name (ietf-ospf interface states: down loopback waiting
# point-to-point dr-other backup dr). NOTE on `up`-style readback: engine_ctl::readback
# only checks that each configured interface is LISTED under its instance (null check),
# so a ghost listed with state "down" passes readback silently — the OK line says so.
# A refusal to start counts only when the log NAMES cfab-ghost: any other startup error
# (busy run dir, bind failure) is a failure for an unrelated reason, so it goes RED.
a8_missing_interface() {
    write_conf "cfab-ghost  st cluster 2 201 backup  10"
    start_engine "$RUN/engine-a8.log"
    local doc ghost_state logline
    if wait_ready "$RUN/engine-a8.log"; then
        doc=$(state_doc || true)
        logline=$(elog "$RUN/engine-a8.log" | grep -m1 -i 'cfab-ghost' || true)
        if [ -z "$doc" ]; then
            red "A8 engine ready but the state socket returned an EMPTY document (cannot judge cfab-ghost) log:[${logline:-none}]"
            stop_engine
            write_conf
            return 0
        fi
        ghost_state=$(printf '%s' "$doc" | jq -r '.ospf.cluster.interfaces["cfab-ghost"].state // "ABSENT"' 2>/dev/null || echo ERR)
        if [ "$ghost_state" = "down" ]; then
            ok "A8 engine ready; state doc lists cfab-ghost state=\"down\" (not silent in the state doc; engine_ctl::readback is a listed-only null check and would NOT catch it) log:[${logline:-none}]"
        elif [ -n "$logline" ]; then
            ok "A8 engine ready; state doc cfab-ghost=$ghost_state; log names it: $logline"
        else
            red "A8 SILENT: engine ready, cfab-ghost state=$ghost_state (want \"down\" or a log line), no log line names it"
        fi
    else
        # `|| true` on every one of these: a grep that matches nothing exits 1, and under
        # `set -e` + pipefail a bare assignment would abort the run — precisely in the case
        # (a silent failure) this assert exists to report.
        local errline
        logline=$(elog "$RUN/engine-a8.log" | grep -m1 -i 'cfab-ghost' || true)
        errline=$(elog "$RUN/engine-a8.log" | grep -iE 'error|fatal' | head -3 | tr '\n' ';' || true)
        if [ -n "$logline" ]; then
            ok "A8 engine refused to come up and named cfab-ghost: $logline"
        else
            # An error that never names the ghost (a busy run dir, a bind failure) is a
            # failure for some other reason: it is not evidence about the missing interface.
            red "A8 engine did not come up and no log line names cfab-ghost, so the refusal says nothing about the ghost: errors:[${errline:-none}] tail:[$(elog "$RUN/engine-a8.log" | tail -3 | tr '\n' ';')]"
        fi
    fi
    stop_engine
    write_conf
}

# ---------------------------------------------------------------------------------------
# teardown (always)
# ---------------------------------------------------------------------------------------
teardown() {
    local rc=$?
    trap - EXIT
    set +e
    say "teardown"
    stop_engine
    stop_frr
    local ns
    for ns in H F; do
        ip netns list | grep -qE "^$ns( |$)" && ip netns del "$ns"
    done
    say "netns after: $(ip netns list | grep -cE '^(H|F)( |$)')"
    if [ "$rc" != 0 ]; then say "exit $rc (script error)"; exit "$rc"; fi
    if [ "$RED_COUNT" != 0 ]; then say "RESULT: $RED_COUNT RED"; exit 1; fi
    say "RESULT: all OK"
}

main() {
    preflight
    trap teardown EXIT
    write_conf
    build_topology
    start_frr
    sample_forwarding
    start_engine "$LOG"
    wait_ready "$LOG" || die "engine never became ready (see $LOG)"
    a0_forwarding_untouched
    wait_full 60 || say "note: not every wire reached full within 60 s"
    wait_routes "$CONVERGE_S" || say "note: identity routes not installed within $CONVERGE_S s"
    wait_ecmp "$CONVERGE_S" || say "note: 10.99.0.2 not ECMP over both storage wires within $CONVERGE_S s"
    say "state doc: $(state_doc | jq -c . 2>/dev/null || echo UNREADABLE)"
    say "F (FRR) route to H's identities: $(ip -n F route show 10.99.0.1 | tr '\n' ';' | tr -s ' \t' ' ')|$(ip -n F route show 10.199.0.1 | tr '\n' ';' | tr -s ' \t' ' ')"
    a1_ospf_full
    a2_bfd_up
    a3_ecmp_prefsrc
    a4_cluster_prefsrc
    a5_sigterm_withdraws
    a6_crash_window
    a7_teeth_no_prefsrc
    a8_missing_interface
    say "engine log ($LOG) tail: $(tail -3 "$LOG" | tr '\n' ';')"
}

main "$@"
