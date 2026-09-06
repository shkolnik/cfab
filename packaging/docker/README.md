# cfab generic container image

A generic runtime image for hosts whose OS cannot run cfab natively (e.g. a NAS), or for
`cfab check`-only validation of a declaration. It bakes nothing member-specific: no
`fabric.toml`, no hostname, no fixture files. Everything a specific deployment needs — the
declaration and, when it differs from the container's own hostname, which row in
``[[member]]`` this container is — is supplied at `docker run`/compose time.

## Build

```
cp /path/to/cfab_0.2.0-1_amd64.deb packaging/docker/cfab.deb
docker build --build-arg CFAB_DEB=cfab.deb -t cfab packaging/docker
```

or, with BuildKit, point at a deb that lives elsewhere without copying it into the tree first:

```
docker buildx build --build-context debdir=/path/to/out \
    --build-arg CFAB_DEB=debdir/cfab_0.2.0-1_amd64.deb -t cfab packaging/docker
```

## Run — validate only (`cfab check`)

No network privilege is needed to lint a declaration:

```
docker run --rm --network none \
    -v /path/to/fabric.toml:/etc/cfab/fabric.toml:ro \
    -e CFAB_HOST=pve1-tb \
    cfab cfab check
```

`CFAB_HOST` selects which ``[[member]]`` row this container is; leave it unset to fall back to
the container's own hostname (`docker run --hostname`).

## Run — as a fabric member (leaf or transiting host)

Applying the fabric creates real interfaces, routes, and nftables state, so it needs the host's
network namespace and elevated capabilities — measured on the testbed (see
`docs/research/2026-09-02-nas-leaf-docker-live-evidence.md` in the research repo):
`--cap-add NET_ADMIN` alone leaves `/proc/sys` read-only, so per-interface sysctls fail;
`--privileged` is what actually works. A Docker **user-defined** bridge network also drops OSPF
multicast, so this is `network_mode: host`, not a published-ports bridge:

```yaml
services:
  cfab:
    image: cfab
    network_mode: host
    privileged: true
    restart: unless-stopped
    stop_grace_period: 60s
    volumes:
      - /etc/cfab/fabric.toml:/etc/cfab/fabric.toml:ro
    environment:
      CFAB_HOST: ${CFAB_HOST:-}
```

PID 1 is `cfab run`; the restart policy is the runtime's (`restart: unless-stopped`);
`stop_grace_period: 60s` is required or the teardown is SIGKILLed halfway. `docker compose
up -d` starts the supervisor, which applies the fabric and keeps its children alive;
`docker compose down` (SIGTERM) runs the stop sequence, tearing down everything cfab created.

The declaration's fallback segment (active-backup bond leg over every wire's fallback VLAN,
role `fallback`, no BFD, cost 5000) reaches this container the same way any other segment
does — through the mounted `fabric.toml` and the host network namespace; nothing about the
fallback segment is container-specific.

## What was left out, and why

Studied on pve3 before writing this: `/root/fallback-rename/ctx/` (a test **fixture** image —
bakes a fixture `fabric.toml`, `systemctl`/`systemd-run` shims so SDD tests can run without a
real systemd, and diagnostic tools `python3-minimal jq bsdextrautils netbase tcpdump
iputils-ping`) and `/root/leaf-cfab/` (the **reference deployment** for the NAS: same deb, but
bakes its own `fabric.toml` and a leaf-specific entrypoint, and is the thing actually running as
`cfab-leaf`).

- **No baked `fabric.toml` or hostname** — the whole point of "generic": one image, any member,
  by bind-mount + `CFAB_HOST`, per the backlog decision that the image stays generic.
- **No systemd shims** — those exist only so a *test fixture* can assert `systemctl is-active`
  without a real init system; they are not part of running cfab and would be actively
  misleading baked into a real deployment image.
- **No diagnostic tools** (`tcpdump`, `python3`, `jq`, ...) baked in — they are fixture/test
  conveniences, not part of the runtime contract; add them in a derived `FROM cfab` image if a
  deployment wants them.
- **No shell entrypoint** — the entrypoint is the binary itself (`ENTRYPOINT ["/usr/bin/cfab"]`,
  `CMD ["run"]`), so `cfab run` is PID 1: it applies the fabric, supervises its children, reaps
  orphans, and on SIGTERM runs the stop sequence. An argv override (`docker run <img> status`)
  still works. `cfab-leaf`'s compose project (`/root/leaf-cfab` on pve3) stays the reference for
  the one member actually running this way.

## Caveats

- A container leaf never transits (`forwarding=0`, no forward table; the cfab declaration marks
  it `kind=leaf`) — this image does not change that; it is a packaging convenience, not a new
  engine capability.
- A host with Docker installed drops all forwarded traffic through the FORWARD chain's Docker
  base policy unless cfab's `DOCKER-USER` accept is in place (`cfab run`/the watchdog install it
  automatically) — irrelevant to a container that only ever runs *as* a leaf, but relevant if
  this image is later run on a Docker host that also transits for other fabric members.
