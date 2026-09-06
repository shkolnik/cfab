# cfab generic runtime image. Bakes NOTHING member-specific: no fabric.toml, no hostname, no
# fixture. Bind-mount /etc/cfab/fabric.toml and set CFAB_HOST at `docker run`/compose time —
# see README.md. Embedded-engine build: the routing engine is inside /usr/bin/cfab, so there is
# no FRR in this image.
FROM debian:trixie-slim

# Path to the cfab .deb, relative to the build context (default: alongside this Dockerfile).
# Plain build-arg form:
#   docker build --build-arg CFAB_DEB=cfab_0.2.0-1_amd64.deb .
# BuildKit --build-context form (deb lives outside this directory, e.g. a CI output dir):
#   docker buildx build --build-context debdir=/path/to/out \
#       --build-arg CFAB_DEB=debdir/cfab_0.2.0-1_amd64.deb .
ARG CFAB_DEB=cfab.deb
COPY ${CFAB_DEB} /tmp/cfab.deb

# apt pulls the deb's own Depends (nftables, iptables, iproute2, ethtool) — that is the whole
# runtime chain; nothing extra is baked in. iptables is there for the ceiling-only fallback a
# leaf takes on a kernel without nf_tables (the -legacy binaries; the image's own kernel is the
# host's, so which one is used is decided at `cfab up`, not at build time). Add diagnostic
# tools (tcpdump, iputils-ping, ...) in a derived image if a deployment wants them — they are
# not part of the generic contract.
RUN apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends /tmp/cfab.deb \
 && rm -rf /var/lib/apt/lists/* /tmp/cfab.deb

ENTRYPOINT ["/usr/bin/cfab"]
CMD ["run"]
