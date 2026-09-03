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

**Status: early, working prototype — under construction.** Not yet ready for machines you
depend on.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion
in this work by you, as defined in the Apache-2.0 license, shall be dual licensed as above,
without any additional terms or conditions.
