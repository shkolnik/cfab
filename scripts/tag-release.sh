#!/usr/bin/env bash
# Cut a formal release: tag the pushed tip of main as v<Cargo.toml version>.
#
# Flow: bump `version` in Cargo.toml, run any cargo command (e.g. `cargo
# check`) so Cargo.lock follows, commit, push main, wait for CI, then run
# this script. It verifies everything is in sync, creates the annotated tag,
# and pushes it; the release workflow (test-gated) builds and publishes.
#
# The workflow independently rejects a tag that does not equal v<Cargo.toml
# version>; this script exists so that mistake fails here, before a bad tag
# is public.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

remote="origin"
branch="main"
dry_run=false

if [[ "${1:-}" == "--dry-run" && $# -eq 1 ]]; then
  dry_run=true
elif (( $# != 0 )); then
  echo "usage: scripts/tag-release.sh [--dry-run]" >&2
  exit 2
fi

current_branch="$(git symbolic-ref --quiet --short HEAD)" || {
  echo "releases must be tagged from a branch, not detached HEAD" >&2
  exit 1
}
if [[ "$current_branch" != "$branch" ]]; then
  echo "releases must be tagged from $branch (currently on $current_branch)" >&2
  exit 1
fi
if [[ -n "$(git status --short)" ]]; then
  echo "the worktree must be clean before tagging a release:" >&2
  git status --short >&2
  exit 1
fi

echo "Fetching $remote/$branch..."
git fetch --prune "$remote" "+refs/heads/$branch:refs/remotes/$remote/$branch"
if [[ "$(git rev-parse HEAD)" != "$(git rev-parse "refs/remotes/$remote/$branch")" ]]; then
  echo "HEAD ($(git rev-parse --short HEAD)) is not $remote/$branch" \
    "($(git rev-parse --short "refs/remotes/$remote/$branch"))." >&2
  echo "The tag must point at the pushed, CI-checked tip of $branch;" \
    "push or pull first." >&2
  exit 1
fi

ver="$(sed -nE 's/^version = "([0-9]+\.[0-9]+\.[0-9]+[^"]*)"$/\1/p' Cargo.toml)"
if [[ -z "$ver" || "$ver" == *$'\n'* ]]; then
  echo "could not read exactly one package version from Cargo.toml (got: ${ver:-nothing})" >&2
  exit 1
fi

lock_ver="$(awk -F '"' '$0 == "name = \"cfab\"" { getline; if ($0 ~ /^version = /) print $2 }' Cargo.lock)"
if [[ "$lock_ver" != "$ver" ]]; then
  echo "Cargo.lock records cfab $lock_ver but Cargo.toml says $ver." >&2
  echo "Run \`cargo check\`, commit the Cargo.lock change, and push;" \
    "otherwise the release workflow's \`cargo test --locked\` fails after the tag is public." >&2
  exit 1
fi

tag="v$ver"

if git rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
  echo "tag $tag already exists locally" \
    "(at $(git rev-parse --short "$tag^{commit}"))." >&2
  echo "Formal releases are never re-tagged: bump version in Cargo.toml," \
    "commit, push, and rerun." >&2
  exit 1
fi
# Checked substitution: with `if [[ -n "$(git ls-remote ...)" ]]` a transient
# network failure would be indistinguishable from "tag does not exist".
if ! remote_tag="$(git ls-remote --refs --tags "$remote" "refs/tags/$tag")"; then
  echo "failed to read tags from $remote" >&2
  exit 1
fi
if [[ -n "$remote_tag" ]]; then
  echo "tag $tag already exists on $remote:" >&2
  printf '%s\n' "$remote_tag" >&2
  echo "Formal releases are never re-tagged: bump version in Cargo.toml," \
    "commit, push, and rerun." >&2
  exit 1
fi

printf '\nRelease preview\n'
printf '  Tag:     %s (annotated)\n' "$tag"
printf '  Commit:  %s %s\n' "$(git rev-parse --short HEAD)" "$(git log -1 --format=%s)"
printf '  Push to: %s (%s)\n\n' "$remote" "$(git remote get-url "$remote")"

if $dry_run; then
  echo "Dry run complete; no tags were created or pushed."
  exit 0
fi

if [[ -t 0 && -t 1 ]]; then
  read -r -p "Create and push this tag? [y/N] " answer
  case "$answer" in
    [Yy]|[Yy][Ee][Ss]) ;;
    *) echo "Release cancelled."; exit 0 ;;
  esac
else
  echo "No TTY detected; proceeding without confirmation."
fi

git tag -a "$tag" -m "cfab $ver"
git push "$remote" "refs/tags/$tag"

echo
echo "Tag $tag pushed. The release workflow is now building:"
echo "  https://github.com/shkolnik/cfab/actions/workflows/release.yml"
