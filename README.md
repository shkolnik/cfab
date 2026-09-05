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
cfab up                         # apply the fabric on this member (idempotent, root)
cfab down                       # remove everything `up` created, restore pre-fabric FRR
cfab status [--wait N] [--permissive]
                                # UP 0 / UP-DEGRADED 1 / FAILED 2 / DOWN 3
cfab measure-cap <dev> <peer>   # measure a wire's real capacity; feeds the shape derivation
cfab policy-teeth               # prove the forward policy in throwaway netnses — and prove the proof bites
cfab cluster status             # Proxmox (pmxcfs) coordination state; clean "not clustered" when absent
cfab conf publish               # validate the local fabric.conf, publish it cluster-wide
cfab shape-daemon | conf-sync | fwd-watchdog   # service-mode subcommands started by `up`; not for hands
```

`--config` defaults to `fabric.conf` beside the binary; `--host` to `$CFAB_HOST`, else the
kernel hostname.

## Running it as a service

The Debian package ships `cfab-fabric.service`, **installed disabled and not started** —
installing cfab never changes the network. Write `/etc/cfab/fabric.conf`, then:

```
systemctl enable --now cfab-fabric
```

The unit is `Type=oneshot` + `RemainAfterExit=yes`; `ExecStart`/`ExecReload` are `cfab up`,
`ExecStop` is `cfab down`. `ConditionPathExists=/etc/cfab/fabric.conf` means a host with the
package but no declaration is skipped at boot rather than failed. Set `CFAB_HOST` in
`/etc/default/cfab` only when this member's row is not named by the kernel hostname.

A package upgrade neither stops nor restarts the unit: stopping it runs `cfab down`, an outage
for every identity on the host. The engine already running keeps the old binary's inode, so the
new binary takes effect at the next `systemctl reload cfab-fabric` — which is `cfab up` again,
and `up` always stops and restarts the routing engine, so this member's adjacencies drop and
re-form. `apt remove` stops the unit (`cfab down`, correct: the binary is going away) and
disables it; `apt purge` also removes `/etc/default/cfab`.

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
