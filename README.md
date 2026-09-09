# cfab — Cluster Network Fabric

A resilient converged network fabric for small, heterogeneous clusters and home labs
(Proxmox, Kubernetes, storage), borrowing principles — not complexity — from modern
scale-out data-center fabrics.

The core idea: **decouple logical traffic class from physical network path.** Physical NICs
(`eno1`, `usb0`, `sfp0`…) are transport resources with differing capacity, preference, and
failure characteristics; storage, cluster-control, management, and public networks are
*policies* layered above them — routing, multipath, failure detection, segmentation, QoS.
Connectivity is additive (plug in a spare NIC → more resilience, no redesign), failover is
automatic and measured in milliseconds-to-seconds, application-facing identities stay stable,
and critical control traffic (Corosync, etcd) stays protected under line-rate load. Hosts are
the policy layer; the physical network is asked for as little as possible — dumb, cheap
switches are a design assumption, not a limitation.

`cfab` is the per-host runtime, a single static binary: `fabric.toml` declares the fabric,
and the binary validates it, generates every artifact from it (nftables forward policy and
traffic-class marking, HTB shaping trees, FRR configuration), applies and verifies the fabric
on the host, and tears it down.

**Status: early, working prototype.** The mechanisms are live-proven on a three-node physical
testbed (cable pulls, switch power loss, driver resets, saturation, poison-config recovery),
but interfaces and the `fabric.toml` format are still moving. Not yet ready for machines you
depend on.

## Commands

```
cfab check                      # parse + validate fabric.toml, print this member's resolved view
cfab schema                     # the fabric.toml declaration schema as JSON Schema
cfab gen policy|mark|engine     # pure generators: print the derived artifacts
cfab gen shape <dev> [--tc|--expect]
cfab run                        # apply the fabric and supervise its daemons (systemd notify, root)
cfab down                       # remove everything cfab applied, restore pre-fabric FRR
cfab status [--wait N] [--permissive]
                                # UP 0 / UP-DEGRADED 1 / FAILED 2 / DOWN 3
cfab measure-cap <dev> <peer>   # measure a wire's real capacity; feeds the shape derivation
cfab policy-teeth               # prove the forward policy in throwaway netnses — and prove the proof bites
cfab cluster status             # Proxmox (pmxcfs) coordination state; clean "not clustered" when absent
cfab conf publish               # validate the local fabric.toml, publish it cluster-wide
cfab shape-daemon | conf-sync | fwd-watchdog   # service-mode subcommands started by `run`; not for hands
```

`--config` defaults to `fabric.toml` beside the binary; `--host` to `$CFAB_HOST`, else the
kernel hostname.

## Runtime requirements

Both member kinds need `ip` (iproute2). A **host** needs `nft` (nftables): it installs
`table inet cfab`, the per-zone bulk DSCP clamp plus one derived control-egress ceiling per
fallback bond, and a kernel without nf_tables is a hard refusal for that kind. A **leaf**
takes `nft` too where the kernel has it; where it does not (a Synology NAS on Linux 4.4, say)
it falls back to `iptables-legacy`, `iptables-legacy-save` and `iptables-legacy-restore` and
installs the **ceiling only** — that kernel has no DSCP target, so the per-zone bulk clamp is
skipped and `cfab status` names the backend and says so. The choice is made at `up` on the
kernel's own refusal, never on a knob, and recorded in the run dir. A leaf gets the ceiling
either way because it sources a fallback-segment control storm exactly as a host does, so a
containment it escaped would be half a containment. (This member's OWN control marking is not
in that table: the engine sets DSCP CS6 and skb-priority `[marking] pcp_ctrl` on its OSPF and BFD
sockets, and the segment sub-interface's egress-qos-map carries that priority onto the wire.
The table's `return` guards keep the bulk clamp off those packets.) A **host** additionally needs `tc`
for its shaping trees; a **leaf** shapes nothing, its wires' qdiscs being its own OS's business.
Every kind needs `ethtool`: link speed is cross-checked with it, and a wire may declare
`driver_features` — a string of `<feature> on|off` pairs handed to `ethtool -K <nic>` as written
(the case that motivates it: USB adapters that lock up under load with scatter-gather on).
cfab names no adapter and no driver; it validates the string at `check`, records the value each
named feature had, and `down` puts those values back. Anything missing is refused by name before
`up` applies a thing. The Debian package's `Depends` covers all of it.

## Running it as a service

The Debian package ships `cfab.service`, **installed disabled and not started** —
installing cfab never changes the network. Write `/etc/cfab/fabric.toml`, then:

```
systemctl enable --now cfab
```

The unit is `Type=notify`; `ExecStart` is `cfab run`, the long-lived supervisor that applies the
fabric and keeps the engine, shape daemon, and conf-sync alive. `ExecReload` is
`kill -HUP $MAINPID`, which re-reads `/etc/cfab/fabric.toml` and acts on what it finds (below).
`ConditionPathExists=/etc/cfab/fabric.toml` means a host with the package but no declaration is
skipped at boot rather than failed. Set `CFAB_HOST` in `/etc/default/cfab` only when this
member's row is not named by the kernel hostname.

A package upgrade restarts the unit once the new files are in place (teardown and re-apply:
every identity on the host is down for the restart). It is not left running on the old binary:
the supervisor respawns its children from `/usr/bin/cfab`, so an un-restarted upgrade would run
the next engine under the previous supervisor.

`systemctl reload cfab` re-reads the declaration:

- **Unchanged** (comments and whitespace do not count — the comparison is of the derived fabric):
  re-applied in place, no teardown, no netdev churn, but the engine and the shape daemon restart.
  Measured 2026-09-06 on the testbed: 6–10 s of loss on every zone while OSPF re-converges.
- **Changed and valid**: the fabric is torn down and the unit restarted onto the new declaration.
  An in-place apply cannot do this — it creates and repairs, it never removes what the previous
  declaration had — so the whole fabric is down for the restart, as on a package upgrade.
- Reloads never overlap: a second SIGHUP or `reapply` that arrives during a reload queues and
  runs after it, never concurrently and never lost.
- **Invalid, unreadable, or no longer declaring this host**: refused. The running fabric is kept
  exactly as it was and `cfab status` names the refusal on its `components:` line.

`apt remove` stops the
unit (correct: the binary is going away) and disables it; `apt purge` also removes
`/etc/default/cfab`.

The package also ships `/etc/iproute2/rt_protos.d/cfab.conf`, naming the engine's private
kernel route-protocol ids (`cfab-ospf` 201, `cfab-static` 202, `cfab-bgp` 203, `cfab-other`
204) so `ip route` prints them instead of bare numbers — cosmetic only; cfab's own sweep
matches the numeric ids.

## Metrics

The supervisor serves the member's state as metrics at

```
http://<any address of the member>:23232/metrics
```

The body is OpenMetrics text, which every Prometheus-compatible scraper also reads as
Prometheus text. The supervisor refreshes it from its own status gather every 15 s, so a scrape
costs no host reads and never blocks the fabric; the reader sees the same numbers `cfab status`
prints.

The endpoint is plaintext and unauthenticated, like `node_exporter`. LAN-trust: put it behind a
proxy or firewall if that is not your posture.

What a scrape shows in each fabric state:

| supervisor | fabric | scrape |
|---|---|---|
| not running | — | connection refused (the scraper's `up == 0` is the signal; standard) |
| running, before first apply | DOWN | `cfab_fabric_state{state="DOWN"} 1`, build/member info, components; no adjacency families |
| running | UP / UP-DEGRADED / FAILED | full schema |
| running, port not bound | any | nothing to scrape; `cfab status` shows the standing reason line |

If the port cannot be bound, the supervisor logs one `WARN` naming the port and the errno, adds
a standing `cfab status` line `metrics endpoint not listening on :23232 (...)` for as long as
the bind keeps failing, and retries every 60 s. The fabric is unaffected: a bind failure is
never fatal and never delays the apply.

A member carrying at least one `[[workload]]` row also serves `cfab_workload_up{name}` (1 when
the row's table is present, its addresses and sibling return-path rule are installed, the
route-get proof succeeds, and its announcer is running); a member with no row carries no series
at all.

```
curl -s http://10.249.0.1:23232/metrics | grep -E 'cfab_fabric_state|cfab_links_up'
```

## Cluster coordination (optional, never required)

On a Proxmox cluster, `cfab` additionally coordinates through pmxcfs (`/etc/pve`) — probed at
the point of use, with identical single-host behavior when absent:

- `conf publish` distributes one validated `fabric.toml` cluster-wide (atomic rename publish,
  generation counter, stale-lock reclaim).
- `conf-sync` applies published configurations under a **peer-witness protocol**: validate →
  apply → status → ack, then commit only once at least one fresh peer ack proves the new
  fabric actually carries traffic — otherwise revert to the previous configuration. A
  cluster-wide bad config (one the switches cannot forward) self-heals: every member reverts.
- `measure-cap` serializes floods behind a cluster lease and publishes measured capacities so
  they survive reboots.

## VM workloads

A `[[workload]]` row declares a VM VLAN cfab reaches into the fabric — an anycast gateway every
member answers, a passive OSPF advertisement into the zones it may reach, and a symmetric
forward policy. The VLAN interface itself is baseline-owned (Proxmox/systemd-networkd/whatever
already brought it up); cfab only points at it.

```toml
[[workload]]
name   = "vms"
ifname = "primary.3"          # host-side interface on the workload VLAN; preconfigured, required
prefix = "192.168.20.0/24"
gw     = "192.168.20.254"     # the anycast gateway every host answers
router = "192.168.20.1"       # the VLAN's existing default router, printed inside DHCP option 121
allow  = ["storage"]          # zones this workload may reach; default deny, counted

[[member]]
name = "pve1"
workloads = [ { name = "vms", address = "192.168.20.2/24" } ]   # this host's own address on ifname
```

`cfab check` refuses a `gw`, `router`, or member address outside `prefix`; any of them landing on
`prefix`'s network or broadcast address; a member address without the prefix's mask or equal to
`gw`; an empty `allow`; an `allow` naming an unknown zone; an `ifname` colliding with a declared
wire, a declared segment, or a cfab-generated bond/identity interface; two `[[workload]]` rows
sharing a name; a workload name that is also a zone name (workload and zone names share one
vocabulary); a workload row no member carries; a member declaring the same workload row twice; a
member workload naming an unknown row; and a leaf carrying one (a leaf never transits). Names
share the zone vocabulary, so `vms>storage` reads like `storage>storage`. A fabric with `[forward]
enabled = false` cannot declare a `[[workload]]` row at all — a workload with nothing to reach is
refused, and reaching a zone requires forwarding, so there is no valid `allow` once forwarding is
off.

`cfab up` refuses if `ifname` does not exist, lacks the member's declared address, or is
administratively down (or in an unparsable state) — a stanza problem needing a fix and a
re-apply. A lower-layer carrier fault (`LOWERLAYERDOWN`) is not a declaration fault, and neither
is an uplink that cannot yet be identified or is not yet STP-forwarding: each defers that one row
to the watchdog (a warning names the reason, no gw address goes live) and applies everything
else, and the watchdog installs the row once the condition clears.

- **`up` adds:** IPv4 forwarding on `ifname`; a passive OSPF entry for `ifname` in every allowed
  zone's instance, so every member and leaf learns the prefix; a pref-2000 sibling return-path
  rule per (zone, workload prefix) on every member and leaf, ahead of the general egress rule, so
  a reply that ECMPs to a host that never saw the flow still finds its way back; a symmetric
  stateless accept pair in the forward policy (`vms>storage` emits both directions, because the
  reply may arrive on a different host than the request left from); a forward-hook DSCP
  overwrite (a workload's own marking is never trusted); the anycast `gw` as a second address on
  `ifname`, answered with the host's own MAC, with `net.ipv4.conf.all.arp_ignore=1` so a host
  answers `gw` only on the interface that holds it; an nft bridge rule that drops ARP for `gw`
  arriving on the bridge's uplink port, so hosts never contend over who answers it; and a
  gratuitous-ARP announcer, a beacon every few seconds plus a burst when the bridge learns a new
  MAC, so a migrated VM's fabric-side neighbor entries converge onto its new host.
- **`down` removes** everything `up` added on this member: the OSPF entry, the return-path
  rules, the forward accepts, the DSCP hook, the second address, the bridge guard, and stops the
  announcer. It never touches `ifname` itself.
- **The watchdog restores** anything of the above it finds missing or wrong, the same way it
  restores every other cfab-owned interface, rule, or sysctl.
- A VM's DHCP lease should carry option 121 (RFC 3442) with the fabric aggregate routed via `gw`,
  plus the default route via the declared `router` inside the *same* option: a client that
  receives option 121 ignores option 3 (VERIFIED: isc-dhclient and systemd-networkd both do,
  so a 121 lease with no default route inside it leaves the VM with none at all). A VM without
  option 121 still reaches fabric identities via the declared `router`, degraded, not broken.

## Design

- **Pure core, thin exec.** Parse → typed model + validation → derivation → pure generators
  are all side-effect free. Everything that touches the system goes through a `Sys` trait:
  argv vectors, no shell, fully mockable — every imperative branch is unit-tested.
- **A leaf is reached from outside at its own addresses.** Only hosts carry a zone's ingress
  leg, so fabric members reach a leaf at its identities while the general network reaches it
  at the leaf's own IPs. Ingress to a leaf's fabric identity is unsupported by design (the
  leaf answers such a packet with a local unreachable, never a leak), not a gap. So leaf
  identities are never advertised to the router: every gw zone's iBGP policy rejects them,
  and the router is never given a route to an address the fabric cannot answer. The shipped
  example declares that leg on `gw = { domain = "any" }`, which makes it MIGRATE — an
  active-backup bond with one tagged sub-interface per wire, so ingress survives losing a whole
  switch — and asks of the rack what a universal segment does: the ingress vid must be carried
  on every island's uplink, or the leg is dark on the wires whose switch does not trunk it.
- **Fail loud, never degrade silently.** A missing capability, absent interface, or unmet
  precondition is a clear, actionable error, never a partial apply.
- **Detectors actuate, `status` reports.** A condition that makes a link unsafe is brought down
  by the watchdog, and the state follows from the adjacency counts; everything else is a reason
  line that never moves the state. `status` itself is read-only, with a test that proves it —
  a false FAILED costs an exit code, a false actuation costs packets.
- **`status` is a first-class citizen.** It reads the fabric end to end (BFD sessions, fallback
  neighbors, identities, source pinning, forward posture) and reports one of four states with
  three counts, `(<peers> | <links> | <fallbacks>)`. Its exit code — 0 UP, 1 UP-DEGRADED,
  2 FAILED, 3 DOWN — is the contract every other mechanism builds on.
- **`--wait <s>` waits for a *settled* fabric, not for the headline.** The counts go UP as soon
  as the sessions are up, seconds before the engine has installed the routes, addresses and
  source pins the identities answer on, so the wait ends early only when the state is UP and no
  reason line is still settling (a route not installed, an adjacency still forming, a child the
  supervisor is restarting, a sysctl or rule `up` and the watchdog own). Reason lines a settled
  fabric prints by design — the mark backend, a leg carrying on a backup wire, drift against
  generated state, a counter, a hardware fact — never hold the wait. At the deadline `status`
  reports what it reached, whatever that is. `--wait 0` is one instant read.
- **`status` describes the fabric that is *running*, not the file.** `cfab run` keeps the
  declaration it applied at `<run_dir>/fabric.toml.applied` (written before the initial apply,
  removed with the run dir by `cfab down`), and `status` prefers that copy — so an operator
  editing `fabric.toml`, or one whose bad edit the reload has just refused, still gets the state
  of the fabric instead of a parse error. The one gap: a member that moved `run_dir` off the
  default *and* whose file will not parse has nothing on disk that says where the copy is, so
  `status` fails on the parse error as before. Every other subcommand keeps reading the file: they act
  on what is *declared*. A disagreement is one reason line and never a state:
  `declaration /etc/cfab/fabric.toml: <error> (status describes the running fabric; a reload of
  this file will be refused)`, with the parser's own line and column, or
  `declaration /etc/cfab/fabric.toml changed since apply (systemctl reload cfab to apply; the
  fabric will restart)`. Equality is semantic, so a comment or whitespace edit is not a change.

## Building

Rust stable; the pinned toolchain is in `rust-toolchain.toml`.

```
cargo test                                        # unit tests, no root, no network
cargo build --release --target x86_64-unknown-linux-musl   # one static binary for any x86_64 host
cargo deb --target x86_64-unknown-linux-musl      # Debian package (needs cargo-deb)
```

The man page is `doc/cfab.8` (`man ./doc/cfab.8`).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion
in this work by you, as defined in the Apache-2.0 license, shall be dual licensed as above,
without any additional terms or conditions.
