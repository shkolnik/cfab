#!/usr/bin/env bash
# Builds the one C dependency the static musl build needs and no distro ships
# for musl: PCRE2.
#
# yang5's `bundled` feature vendors libyang's own source (libyang5-sys/libyang)
# but not PCRE2 — libyang's CMakeLists does find_package(PCRE2 10.21 REQUIRED),
# and Debian's libpcre2-dev is a glibc build, so the musl cmake configure fails
# with "Could NOT find PCRE2 (missing: PCRE2_LIBRARY)".
#
# Installs a static PCRE2 into $PREFIX and prints the environment the cargo
# build then needs:
#   CMAKE_PREFIX_PATH_<target>          libyang's find_package finds our PCRE2
#   CARGO_TARGET_<TARGET>_RUSTFLAGS     -L for the final link, target-scoped, so
#                                       a glibc build in the same job is unaffected
#   LIBPCRE2_8_NO_PKG_CONFIG            skip libyang5-sys's pkg-config probe
#
# <target> is the underscored spelling (x86_64_unknown_linux_musl): the
# hyphenated one is not a shell identifier, so it cannot be exported.
#
# Why the probe is skipped rather than pointed at our .pc: the probe emits the
# .pc's libdir as a rustc -L path, and with a musl target it was measured
# (2026-09-05, rust:1-trixie) to return the *system* glibc libpcre2-8.pc even
# with PKG_CONFIG_PATH_<target> and PKG_CONFIG_LIBDIR_<target> exported. The
# resulting -L/usr/lib/x86_64-linux-gnu makes the linker resolve -lc to glibc's
# libc.a inside a static musl link, which fails on __gcc_personality_v0, pow,
# fmodl and __fpclassifyl. Skipping the probe leaves libyang5-sys emitting a
# bare -lpcre2-8 (plus two cargo warnings), which our -L resolves.
#
# Usage:
#   scripts/musl-deps.sh              # build, then print an `export` block
#   eval "$(scripts/musl-deps.sh)"    # ... and apply it to this shell
# Under GitHub Actions the block is also appended to $GITHUB_ENV.
#
# Requires: musl-tools (musl-gcc), cmake, build-essential, curl.
set -euo pipefail

TARGET=${TARGET:-x86_64-unknown-linux-musl}
PREFIX=${MUSL_PREFIX:-/opt/musl-deps}
PCRE2_VERSION=${PCRE2_VERSION:-10.45}
# Recorded from the release asset on 2026-09-05; upstream publishes no
# checksum file next to it, so this pin is the integrity check.
PCRE2_SHA256=21547f3516120c75597e5b30a992e27a592a31950b5140e7b8bfde3f192033c4
CC_MUSL=${CC_MUSL:-x86_64-linux-musl-gcc}

log() { echo "musl-deps: $*" >&2; }

if [ ! -f "$PREFIX/lib/pkgconfig/libpcre2-8.pc" ]; then
    command -v "$CC_MUSL" >/dev/null || {
        echo "musl-deps: $CC_MUSL not found — install musl-tools" >&2
        exit 1
    }
    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT
    tarball="pcre2-$PCRE2_VERSION.tar.bz2"
    log "fetching $tarball"
    curl -fsSL -o "$work/$tarball" \
        "https://github.com/PCRE2Project/pcre2/releases/download/pcre2-$PCRE2_VERSION/$tarball"
    echo "$PCRE2_SHA256  $work/$tarball" | sha256sum -c - >&2
    tar -xf "$work/$tarball" -C "$work"
    log "building PCRE2 $PCRE2_VERSION for $TARGET into $PREFIX"
    (
        cd "$work/pcre2-$PCRE2_VERSION"
        # No JIT: it is not needed by libyang's use of PCRE2 and its assembly
        # backend is the part most likely to differ under musl.
        ./configure --host=x86_64-linux-musl --prefix="$PREFIX" \
            --enable-static --disable-shared --disable-jit \
            CC="$CC_MUSL" CFLAGS="-O2 -fPIC" >"$work/configure.log" 2>&1 ||
            { tail -30 "$work/configure.log" >&2; exit 1; }
        make -j"$(nproc)" >"$work/make.log" 2>&1 || { tail -30 "$work/make.log" >&2; exit 1; }
        make install >>"$work/make.log" 2>&1 || { tail -30 "$work/make.log" >&2; exit 1; }
    )
else
    log "PCRE2 already installed in $PREFIX"
fi

env_block() {
    local t=${TARGET//-/_}
    local T=${t^^}
    cat <<EOF
CMAKE_PREFIX_PATH_$t=$PREFIX
CARGO_TARGET_${T}_RUSTFLAGS=-L native=$PREFIX/lib
LIBPCRE2_8_NO_PKG_CONFIG=1
EOF
}

if [ -n "${GITHUB_ENV:-}" ]; then
    env_block >>"$GITHUB_ENV"
fi
# Values contain spaces, so the shell form quotes them; $GITHUB_ENV must not be
# quoted (Actions takes the raw value).
env_block | sed 's/^\([^=]*\)=\(.*\)$/export \1="\2"/'
