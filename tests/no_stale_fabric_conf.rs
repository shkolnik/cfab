//! The declaration file is `fabric.toml` everywhere (spec §11.2 rule 5). One stale
//! `fabric.conf` in a message, a path, a doc or a packaging asset is enough to send an
//! operator to a file that does not exist, so the whole tree is grepped here.
//!
//! Four exclusions, each deliberate:
//!   * `docs/bakeoff-shared-fixes.md` — frozen history of a bake-off that ran against the
//!     shell format; renaming the file it actually used would falsify the record.
//!   * `tests/fixtures/model-v0/` and `tests/fixtures/model-v1-2eaf191/` — outputs CAPTURED
//!     from binaries that printed `fabric.conf OK`. They are evidence, not source; the
//!     equivalence test applies that one rename as its single enumerated transform.
//!   * `src/lib.rs` — home of `retired_format_error`, the one place that must still SAY
//!     `fabric.conf`, to tell an operator holding the old file what happened to it.
//!   * this file — it names what it forbids.

use std::path::{Path, PathBuf};

const ALLOWED: [&str; 5] = [
    "docs/bakeoff-shared-fixes.md",
    "tests/fixtures/model-v0",
    "tests/fixtures/model-v1-2eaf191",
    "src/lib.rs",
    "tests/no_stale_fabric_conf.rs",
];

const SKIP_DIRS: [&str; 4] = [".git", "target", ".worktrees", "node_modules"];

fn walk(dir: &Path, root: &Path, out: &mut Vec<(PathBuf, usize, String)>) {
    for entry in std::fs::read_dir(dir).expect("readable directory") {
        let path = entry.expect("dir entry").path();
        let rel = path.strip_prefix(root).expect("under the root");
        let rel_s = rel.to_string_lossy().replace('\\', "/");
        if ALLOWED.iter().any(|a| rel_s.starts_with(a)) {
            continue;
        }
        if path.is_dir() {
            if SKIP_DIRS.contains(&path.file_name().unwrap().to_string_lossy().as_ref()) {
                continue;
            }
            walk(&path, root, out);
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue; // not UTF-8: not a place a declaration name hides
        };
        for (i, line) in text.lines().enumerate() {
            if line.contains("fabric.conf") {
                out.push((rel.to_path_buf(), i + 1, line.trim().to_string()));
            }
        }
    }
}

#[test]
fn no_stale_fabric_conf_anywhere_in_the_tree() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut hits = Vec::new();
    walk(&root, &root, &mut hits);
    assert!(
        hits.is_empty(),
        "the declaration is fabric.toml; stale references:\n{}",
        hits.iter()
            .map(|(p, n, l)| format!("  {}:{n}: {l}", p.display()))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// The guard has teeth: the same walk over a directory that DOES contain the old name finds
/// it (proving the walker reads files, rather than passing because it read nothing).
#[test]
fn the_guard_finds_a_planted_reference() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("sub")).unwrap();
    std::fs::write(dir.path().join("sub/x.rs"), "// /etc/cfab/fabric.conf\n").unwrap();
    let mut hits = Vec::new();
    walk(dir.path(), dir.path(), &mut hits);
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert_eq!(hits[0].1, 1);
}
