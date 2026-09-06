# cfab generic runtime image. Bakes NOTHING member-specific: no fabric.toml, no hostname, no
# fixture. Bind-mount /etc/cfab/fabric.toml and set CFAB_HOST at `docker run`/compose time —
# see README.md. Embedded-engine build: the routing engine is inside /usr/bin/cfab, so there is
# no FRR in this image.
FROM debian:trixie-slim

# Path to the cfab .deb, relative to the build context. The default expects the deb copied
# beside this Dockerfile, which is also what CI does:
#   cp /path/to/cfab_0.4.0-1_amd64.deb packaging/docker/cfab.deb
#   docker build -t cfab packaging/docker
# A differently named deb in the same context works with a build-arg:
#   docker build --build-arg CFAB_DEB=cfab_0.4.0-1_amd64.deb -t cfab packaging/docker
ARG CFAB_DEB=cfab.deb
COPY ${CFAB_DEB} /tmp/cfab.deb

# apt pulls the deb's own Depends (nftables, iproute2, ethtool). iptables is only a Recommends
# of the deb and this install is --no-install-recommends, so it is named explicitly: without it
# the leaf's ceiling-only fallback (iptables-legacy, for a kernel without nf_tables — a real
# Synology, DSM 7.3.2 / 4.4) would silently be missing from the image. Which backend is used is
# decided at `cfab up` against the host's kernel, not at build time. Add diagnostic tools
# (tcpdump, iputils-ping, ...) in a derived image if a deployment wants them — they are not part
# of the generic contract.
RUN apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      /tmp/cfab.deb iptables \
 && rm -rf /var/lib/apt/lists/* /tmp/cfab.deb

ENTRYPOINT ["/usr/bin/cfab"]
CMD ["run"]
