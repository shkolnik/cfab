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

`cfab` is the per-host runtime, a single static binary: `fabric.conf` declares the fabric,
and the binary validates it, generates every artifact from it (nftables forward policy and
traffic-class marking, HTB shaping trees, FRR configuration), applies and verifies the fabric
on the host, and tears it down.

**Status: early, working prototype.** The mechanisms are live-proven on a three-node physical
testbed (cable pulls, switch power loss, driver resets, saturation, poison-config recovery),
but interfaces and the `fabric.conf` format are still moving. Not yet ready for machines you
depend on.

## Commands

```
cfab check                      # parse + validate fabric.conf, print this member's resolved view
cfab schema                     # the fabric.conf data model as JSON Schema
cfab gen policy|mark|engine     # pure generators: print the derived artifacts
cfab gen shape <dev> [--tc|--expect]
cfab run                        # apply the fabric and supervise its daemons (systemd notify, root)
cfab down                       # remove everything cfab applied, restore pre-fabric FRR
cfab status [--wait N] [--permissive]
                                # UP 0 / UP-DEGRADED 1 / FAILED 2 / DOWN 3
cfab measure-cap <dev> <peer>   # measure a wire's real capacity; feeds the shape derivation
cfab policy-teeth               # prove the forward policy in throwaway netnses — and prove the proof bites
cfab cluster status             # Proxmox (pmxcfs) coordination state; clean "not clustered" when absent
cfab conf publish               # validate the local fabric.conf, publish it cluster-wide
cfab shape-daemon | conf-sync | fwd-watchdog   # service-mode subcommands started by `run`; not for hands
```

`--config` defaults to `fabric.conf` beside the binary; `--host` to `$CFAB_HOST`, else the
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
in that table: the engine sets DSCP CS6 and skb-priority PCP_CTRL on its OSPF and BFD
sockets, and the segment sub-interface's egress-qos-map carries that priority onto the wire.
The table's `return` guards keep the bulk clamp off those packets.) A **host** additionally needs `tc` and
`ethtool` for its shaping trees and per-NIC offload posture; a **leaf** shapes nothing, its
wires' qdiscs being its own OS's business. Anything missing is refused by name before `up`
applies a thing. The Debian package's `Depends` covers all of it.

## Running it as a service

The Debian package ships `cfab.service`, **installed disabled and not started** —
installing cfab never changes the network. Write `/etc/cfab/fabric.conf`, then:

```
systemctl enable --now cfab
```

The unit is `Type=notify`; `ExecStart` is `cfab run`, the long-lived supervisor that applies the
fabric and keeps the engine, shape daemon, and conf-sync alive. `ExecReload` is
`kill -HUP $MAINPID`, which re-applies the declaration in place — no teardown, no netdev churn.
`ConditionPathExists=/etc/cfab/fabric.conf` means a host with the package but no declaration is
skipped at boot rather than failed. Set `CFAB_HOST` in `/etc/default/cfab` only when this
member's row is not named by the kernel hostname.

A package upgrade neither stops nor restarts the unit: stopping it tears the fabric down, an
outage for every identity on the host. The supervisor already running keeps the old binary's
inode, so the new binary takes effect at the next `systemctl restart cfab`. `systemctl reload
cfab` re-applies the declaration in place (no teardown, no netdev churn) but restarts the engine and
the shape daemon: measured 2026-09-06 on the testbed, 6–10 s of loss on every zone while OSPF re-converges. `apt remove` stops the
unit (correct: the binary is going away) and disables it; `apt purge` also removes
`/etc/default/cfab`.

The package also ships `/etc/iproute2/rt_protos.d/cfab.conf`, naming the engine's private
kernel route-protocol ids (`cfab-ospf` 201, `cfab-static` 202, `cfab-bgp` 203, `cfab-other`
204) so `ip route` prints them instead of bare numbers — cosmetic only; cfab's own sweep
matches the numeric ids.

## Cluster coordination (optional, never required)

On a Proxmox cluster, `cfab` additionally coordinates through pmxcfs (`/etc/pve`) — probed at
the point of use, with identical single-host behavior when absent:

- `conf publish` distributes one validated `fabric.conf` cluster-wide (atomic rename publish,
  generation counter, stale-lock reclaim).
- `conf-sync` applies published configurations under a **peer-witness protocol**: validate →
  apply → status → ack, then commit only once at least one fresh peer ack proves the new
  fabric actually carries traffic — otherwise revert to the previous configuration. A
  cluster-wide bad config (one the switches cannot forward) self-heals: every member reverts.
- `measure-cap` serializes floods behind a cluster lease and publishes measured capacities so
  they survive reboots.

## Design

- **Pure core, thin exec.** Parse → typed model + validation → derivation → pure generators
  are all side-effect free. Everything that touches the system goes through a `Sys` trait:
  argv vectors, no shell, fully mockable — every imperative branch is unit-tested.
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
