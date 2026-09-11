#!/bin/bash
# probe-pve.sh — READ-ONLY inventory of a host before the fabric is installed on it: what is
# already on the wires, which services own the network, what the firewall and sysctls say.
# Prints, changes nothing; every command is optional (absent on a non-PVE box is an answer too).
# Env: CFAB_CONF (default /etc/cfab/fabric.toml), CFAB_NICS (space-separated wires; default:
# the nics named in CFAB_CONF, else every non-virtual link), CFAB_KEYRING (apt signing keyring).
set -u
CONF=${CFAB_CONF:-/etc/cfab/fabric.toml}
NICS=${CFAB_NICS:-}
[ -z "$NICS" ] && [ -f "$CONF" ] && NICS=$(grep -o 'nic *= *"[^"]*"' "$CONF" | sed 's/.*"\(.*\)"/\1/' | sort -u | tr '\n' ' ')
[ -z "$NICS" ] && NICS=$(find /sys/class/net -mindepth 1 -maxdepth 1 -lname '*/devices/pci*' -o -lname '*/devices/platform*' -o -lname '*/usb*' 2>/dev/null | xargs -rn1 basename | tr '\n' ' ')
KEYRING=${CFAB_KEYRING:-/usr/share/keyrings/jshkol-archive-keyring.gpg}
s() { printf '\n== %s\n' "$*"; }
try() { "$@" 2>&1 || echo "  (rc=$?: $*)"; }
have() { command -v "$1" >/dev/null 2>&1; }

s identity
hostname; try getent hosts "$(hostname)"; . /etc/os-release && echo "$PRETTY_NAME"; uname -r
have pveversion && try pveversion || echo "pveversion: absent (not a PVE host)"
cat /proc/1/comm

s packages
dpkg-query -W -f='${Package} ${Version} ${db:Status-Status}\n' cfab frr frr-pythontools nftables ethtool \
  iproute2 procps bsdutils ifupdown2 ifupdown pve-firewall proxmox-firewall corosync 2>&1
have apt-cache && apt-cache policy cfab 2>/dev/null | sed -n '1,6p'

s services
for u in frr networking systemd-networkd NetworkManager dhcpcd corosync pve-cluster pve-firewall \
         proxmox-firewall cfab cfab-revert.timer; do
  printf '  %-24s %s / %s\n' "$u" "$(systemctl is-enabled "$u" 2>&1 | head -1)" "$(systemctl is-active "$u" 2>&1 | head -1)"
done

s /etc/network/interfaces
cat /etc/network/interfaces 2>/dev/null || echo "  absent"
ls /etc/network/interfaces.d/ 2>/dev/null

s links "(wires: $NICS)"
ip -c=never -br link; ip -c=never -br -4 addr; bridge -c=never link 2>/dev/null | sed 's/^/  port /'
ls /etc/systemd/network/*.link 2>/dev/null
for d in $NICS; do
  ip link show "$d" >/dev/null 2>&1 || { echo "  $d: MISSING"; continue; }
  printf '  %s: driver=%s master=%s ' "$d" "$(ethtool -i "$d" 2>/dev/null | awk '/^driver:/{print $2}')" "$(ip -o link show "$d" | grep -o 'master [^ ]*' | cut -d" " -f2)"
  ethtool "$d" 2>/dev/null | awk '/Speed|Link detected/{printf "%s ", $NF}'; echo
done

s sysctls
for k in net.ipv4.ip_forward net.ipv4.conf.all.forwarding net.ipv4.conf.default.forwarding \
         net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter \
         net.bridge.bridge-nf-call-iptables net.bridge.bridge-nf-call-ip6tables; do
  printf '  %s = %s\n' "$k" "$(sysctl -n "$k" 2>/dev/null || echo 'absent')"
done
grep -rH 'bridge-nf\|forward' /etc/sysctl.conf /etc/sysctl.d /usr/lib/sysctl.d 2>/dev/null | sed 's/^/  /'
lsmod | awk '/^br_netfilter|^nf_tables|^8021q|^veth/{print "  module " $1}'

s netfilter
nft list tables 2>&1 | sed 's/^/  /'
have iptables-save && echo "  iptables-save rules: $(iptables-save 2>/dev/null | grep -c '^-')"
[ -f /etc/pve/firewall/cluster.fw ] && grep -H '^enable' /etc/pve/firewall/cluster.fw
[ -f "/etc/pve/nodes/$(hostname)/host.fw" ] && grep -H '^enable' "/etc/pve/nodes/$(hostname)/host.fw"

s frr
# The routing engine is embedded in cfab now; a RUNNING frr is a conflict, not a dependency —
# its bfdd binds the BFD control port (3784) and cfab's engine loses it.
[ -d /etc/frr ] || echo "  /etc/frr absent"
grep -E '^[a-z0-9_]+=yes|^ospfd_instances' /etc/frr/daemons 2>/dev/null | sed 's/^/  /'
[ -f /etc/frr/frr.conf ] && echo "  frr.conf: $(wc -l < /etc/frr/frr.conf) lines; $(grep -c '^router ' /etc/frr/frr.conf) 'router' stanzas"
[ -f /etc/frr/frr.conf.pre-cfab ] && echo "  frr.conf.pre-cfab: PRESENT (fabric applied, or a stale backup)"

s corosync
for f in /etc/pve/corosync.conf /etc/corosync/corosync.conf; do
  [ -f "$f" ] && { echo "  $f:"; grep -E 'name:|ring[0-9]_addr|link_mode|bindnetaddr' "$f" | sed 's/^/    /'; }
done
have pvecm && try pvecm status | grep -E 'Quorate|Nodes|Expected' | sed 's/^/  /'

s storage
[ -f /etc/pve/storage.cfg ] && sed 's/^/  /' /etc/pve/storage.cfg || echo "  /etc/pve/storage.cfg absent"
mount | awk '$1 ~ /:\// || $5 ~ /nfs|cifs/ {print "  mounted " $1 " on " $3 " (" $5 ")"}'

s qdisc
for d in $NICS; do ip link show "$d" >/dev/null 2>&1 && echo "  $d: $(tc qdisc show dev "$d" | head -1)"; done

s dhcp-clients
pgrep -a 'dhclient|dhcpcd|udhcpc' 2>/dev/null | sed 's/^/  /' || echo "  none"

s cfab
have cfab && try cfab --version || echo "  cfab: not installed"
[ -f "$CONF" ] && echo "  $CONF: $(wc -l < "$CONF") lines" || echo "  $CONF absent"
for f in /etc/apt/sources.list.d/jshkol.sources "$KEYRING"; do
  [ -f "$f" ] && echo "  $f: present" || echo "  $f: absent"
done
[ -d /run/cfab ] && echo "  /run/cfab present (fabric applied since boot)" || echo "  /run/cfab absent"
ip -c=never -br link | awk '$1 ~ /^cfab-/ {print "  netdev " $1}'

s workload "(declaration: $CONF)"
if [ ! -f "$CONF" ]; then
  echo "  $CONF absent"
  WLIFS=""
else
  # 0.6.0 [[workload]] rows carry `uplink = "<bridge>"` and `vid = <tag>` (the retired
  # `ifname = "primary.3"` sub-interface key is gone). The cfab leg `cfab-work-<name>` does not
  # exist until apply; what MUST pre-exist is the host-provided uplink bridge, carrying `vid`.
  # Match keys by regex, not field count: `uplink="primary"` with no spaces is legal TOML that a
  # `$1==` field match would miss (the M5 whole-branch-review lesson, kept). Flush on the next
  # `[[workload]]` too, so a second row is not swallowed by the first.
  WL=$(awk '
    /^\[\[workload\]\]/{ if(w && up!=""){print up" "vid}; w=1; up=""; vid=""; next }
    /^\[/{ if(w && up!=""){print up" "vid}; w=0 }
    w && /^uplink[ \t]*=/{ line=$0; sub(/^uplink[ \t]*=[ \t]*"/, "", line); sub(/".*/, "", line); up=line }
    w && /^vid[ \t]*=/{ line=$0; sub(/^vid[ \t]*=[ \t]*/, "", line); sub(/[^0-9].*/, "", line); vid=line }
    END{ if(w && up!=""){print up" "vid} }
  ' "$CONF")
  [ -z "$WL" ] && echo "  no [[workload]] rows in $CONF"
fi
printf '%s\n' "$WL" | while read -r br vid; do
  [ -n "$br" ] || continue
  echo "  -- workload uplink $br (vid $vid)"
  if ! ip link show "$br" >/dev/null 2>&1; then
    echo "    MISSING (precondition unmet: the uplink bridge must exist before apply)"
    continue
  fi
  if [ ! -d /sys/class/net/"$br"/bridge ]; then
    echo "    $br is not a bridge (the workload uplink must be a vlan-aware bridge)"
    continue
  fi
  # stp_state: 0=off, 1=kernel STP, 2=user-space STP (e.g. mstpd). vlan_filtering must be 1.
  echo "    bridge $br: vlan_filtering=$(cat /sys/class/net/"$br"/bridge/vlan_filtering 2>/dev/null) (1 = vlan-aware, required for the vid $vid leg) stp=$(cat /sys/class/net/"$br"/bridge/stp_state 2>/dev/null) forward_delay=$(cat /sys/class/net/"$br"/bridge/forward_delay 2>/dev/null)"
  ip -d -br link show dev "$br" 2>&1 | sed 's/^/    /'
  ip -4 -br addr show dev "$br" 2>&1 | sed 's/^/    /'
  for p in /sys/class/net/"$br"/brif/*; do
    [ -e "$p" ] || continue
    p=${p##*/}
    sfile=/sys/class/net/"$br"/brif/"$p"/state
    if [ -f "$sfile" ]; then pstate=$(cat "$sfile" 2>/dev/null); else pstate=MISSING; fi
    # state 3 = forwarding (the port passes traffic); anything else blocks it.
    echo "    port $p state=$pstate"
  done
  if have bridge; then
    # The uplink's vlan set: `vid` must appear for the VM leg to pass. `dev $br` scopes it to this
    # bridge and its ports, so the port tagging that proves vid actually reaches it shows too.
    bridge -c=never vlan show dev "$br" 2>&1 | sed 's/^/    /'
  else
    echo "    bridge: command absent"
  fi
done
echo "  net.ipv4.conf.all.arp_ignore = $(sysctl -n net.ipv4.conf.all.arp_ignore 2>/dev/null || echo absent)"
if have nft; then
  NFTOUT=$(nft list tables 2>&1)
  NFTRC=$?
  if [ "$NFTRC" -ne 0 ]; then
    echo "  nft: cannot list bridge tables ($NFTOUT)"
  else
    BRTABLES=$(printf '%s\n' "$NFTOUT" | grep -E '^table bridge')
    if [ -n "$BRTABLES" ]; then echo "$BRTABLES" | sed 's/^/  /'; else echo "  no bridge nft tables"; fi
  fi
else
  echo "  nft: command absent"
fi
