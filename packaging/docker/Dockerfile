# cfab generic runtime image. Bakes NOTHING member-specific: no fabric.toml, no hostname, no
# fixture. Bind-mount /etc/cfab/fabric.toml and give the container the member's name with
# `--hostname` (compose: `hostname:`) at run time — cfab indexes the declaration by hostname and
# takes no override. See README.md. Embedded-engine build: the routing engine is inside /usr/bin/cfab, so there is
# no FRR in this image.
FROM debian:trixie-slim

# Path to the cfab .deb, relative to the build context. The default expects the deb copied
# beside this Dockerfile, which is also what CI does:
#   cp /path/to/cfab_0.4.1-1_amd64.deb packaging/docker/cfab.deb
#   docker build -t cfab packaging/docker
# A differently named deb in the same context works with a build-arg:
#   docker build --build-arg CFAB_DEB=cfab_0.4.1-1_amd64.deb -t cfab packaging/docker
ARG CFAB_DEB=cfab.deb
COPY ${CFAB_DEB} /tmp/cfab.deb

# apt pulls the deb's own Depends (nftables, iproute2). iptables and ethtool are only
# Recommends of the deb and this install is --no-install-recommends, so both are named
# explicitly: without iptables the leaf's ceiling-only fallback (iptables-legacy, for a kernel
# without nf_tables — a real Synology, DSM 7.3.2 / 4.4) would silently be missing from the
# image; without ethtool the image would run in the degraded no-ethtool mode by design (no
# driver record, no link-speed cross-check) rather than by an accident of this install line.
# Which backend is used is decided at apply time against the host's kernel, not at build time.
# Add diagnostic tools (tcpdump, iputils-ping, ...) in a derived image if a deployment wants
# them — they are not part of the generic contract.
RUN apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      /tmp/cfab.deb iptables ethtool \
 && rm -rf /var/lib/apt/lists/* /tmp/cfab.deb

ENTRYPOINT ["/usr/bin/cfab"]
CMD ["run"]
