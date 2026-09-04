# Bake-off shared fixes

Fixes made on `embedded` that `main` (FRR) also needs; James applies them after the bake-off decision.

| commit | what | main needs |
|---|---|---|
| (none yet) | `.github/workflows/release.yml` still builds `--target x86_64-unknown-linux-musl` with no holo clone/apt/`holo-check` step; breaks if `embedded` is merged or tagged | rework release.yml for whichever engine wins (musl static size is a post-decision measurement, spec §11) |
| (none yet) | `src/derive.rs:299/:307` fail `cargo fmt --check` (CI Format step red on both branches) | `cargo fmt` — same bytes on main |
