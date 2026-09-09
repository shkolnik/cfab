//! Shared file-walking and `#[cfg(test)]` stripping for the negative "no such call/mechanism
//! survives in production" guards (`tests/no_ethtool_dash_k.rs`, `tests/no_second_path.rs`).
//! Not a top-level `tests/*.rs` file itself (cargo only auto-discovers those as integration
//! test binaries), so this module compiles into whichever test binary does `#[path =
//! "support/mod.rs"] mod support;` and is never its own crate.
//!
//! Production code only: each source has every `#[cfg(test)]`-gated `mod { ... }` block
//! removed before the grep, so a test naming a forbidden mechanism to prove the production side
//! never emits it is not itself a false positive. A plain "truncate at the first `#[cfg(test)]`
//! line" is not enough: `src/emit/workload.rs` has `pub fn bridge_table` after its tests module
//! and `src/decl.rs` has `pub mod fixtures` after its tests module (neither `#[cfg(test)]`), so
//! truncating there would blind the guard to anything either one contains. This walks brace
//! depth to find each gated module's real end and skips only that span, so code after it (and
//! code before/between other such blocks) stays in the scanned text.

use std::path::Path;

/// Every `.rs` under `src/`, as `(display path, production-only text)`.
pub fn rust_sources() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path).unwrap();
                out.push((display(&path), strip_cfg_test_mods(&text)));
            }
        }
    }
    out
}

fn display(path: &Path) -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

/// Removes every `#[cfg(test)]`-gated `[vis] mod name { ... }` block from `text` (this codebase
/// gates modules named `tests`, `mock`, `interp` and `workload_lifecycle` this way, never just
/// `tests`), leaving everything else — including production code that follows such a block —
/// byte-for-byte intact. A `#[cfg(test)]` on something other than a `mod` (this codebase has
/// exactly one: `commands/status.rs`'s `is_read_only`, a test-only helper) is left alone: it is
/// inert for these grep-based guards and out of scope for this stripper.
///
/// Finds each block's matching close brace by depth, but only counting braces the sanitize pass
/// below marks as real code — this codebase's test modules embed raw-string fixtures whose
/// braces span lines unevenly (`src/cluster.rs`'s `CLUSTERED` JSON) and char literals that are
/// themselves braces (`src/emit/workload.rs`'s `.ends_with('}')`), either of which would desync
/// a naive per-line or per-char counter.
pub fn strip_cfg_test_mods(text: &str) -> String {
    const ATTR: &[u8] = b"#[cfg(test)]";
    let sanitized = sanitize(text);
    let s = sanitized.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut copy_from = 0usize;
    let mut i = 0usize;
    while i + ATTR.len() <= s.len() {
        if &s[i..i + ATTR.len()] != ATTR {
            i += 1;
            continue;
        }
        let after_attr = skip_ws(s, i + ATTR.len());
        let Some(after_mod_kw) = match_mod_after_attr(s, after_attr) else {
            i += 1;
            continue;
        };
        let brace_start = s[after_mod_kw..]
            .iter()
            .position(|&c| c == b'{')
            .map(|off| after_mod_kw + off)
            .expect("a `mod` item is always followed by a `{ ... }` block");
        let block_end = matching_brace_end(s, brace_start);
        out.push_str(&text[copy_from..i]);
        copy_from = block_end;
        i = block_end;
    }
    out.push_str(&text[copy_from..]);
    out
}

/// `s[open]` is `{`; returns the index just past its matching `}` (depth-counted over `s`,
/// which the caller has already sanitized so only real code braces are seen).
fn matching_brace_end(s: &[u8], open: usize) -> usize {
    let mut depth = 0i32;
    let mut j = open;
    while j < s.len() {
        match s[j] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return j + 1;
                }
            }
            _ => {}
        }
        j += 1;
    }
    s.len()
}

fn skip_ws(s: &[u8], mut i: usize) -> usize {
    while i < s.len() && s[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

/// `i` is the sanitized-text position right after a `#[cfg(test)]` attribute (and its trailing
/// whitespace/blanked comments). If an optional visibility (`pub`, `pub(crate)`, `pub(in ...)`,
/// ...) followed by `mod` starts here, returns the position right after the `mod` keyword.
fn match_mod_after_attr(s: &[u8], mut i: usize) -> Option<usize> {
    if s[i..].starts_with(b"pub") {
        i += 3;
        i = skip_ws(s, i);
        if s.get(i) == Some(&b'(') {
            let mut depth = 0i32;
            while i < s.len() {
                match s[i] {
                    b'(' => depth += 1,
                    b')' => depth -= 1,
                    _ => {}
                }
                i += 1;
                if depth == 0 {
                    break;
                }
            }
            i = skip_ws(s, i);
        }
    }
    if s[i..].starts_with(b"mod") && s.get(i + 3).is_some_and(u8::is_ascii_whitespace) {
        Some(i + 3)
    } else {
        None
    }
}

/// A same-length copy of `text` with every string literal, char literal, and comment replaced
/// by spaces (newlines kept), so downstream brace-counting and attribute search only see real
/// code structure. Byte-for-byte, so indices into `sanitized` line up with `text`.
fn sanitize(text: &str) -> String {
    let b = text.as_bytes();
    let n = b.len();
    let mut out = b.to_vec();
    let mut i = 0usize;
    while i < n {
        match b[i] {
            b'/' if i + 1 < n && b[i + 1] == b'/' => {
                let start = i;
                while i < n && b[i] != b'\n' {
                    i += 1;
                }
                blank(&mut out, start, i);
            }
            b'/' if i + 1 < n && b[i + 1] == b'*' => {
                let start = i;
                i += 2;
                let mut depth = 1i32;
                while i < n && depth > 0 {
                    if i + 1 < n && b[i] == b'/' && b[i + 1] == b'*' {
                        depth += 1;
                        i += 2;
                    } else if i + 1 < n && b[i] == b'*' && b[i + 1] == b'/' {
                        depth -= 1;
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                blank(&mut out, start, i);
            }
            b'r' if is_raw_string_start(b, i) => {
                let start = i;
                i = raw_string_end(b, i);
                blank(&mut out, start, i);
            }
            b'"' => {
                let start = i;
                i += 1;
                while i < n {
                    if b[i] == b'\\' && i + 1 < n {
                        i += 2;
                        continue;
                    }
                    let hit_close = b[i] == b'"';
                    i += 1;
                    if hit_close {
                        break;
                    }
                }
                blank(&mut out, start, i);
            }
            b'\'' => {
                // Could be a char literal (`'{'`, `'\''`, ...) or a lifetime (`'a`); only the
                // former closes with a bare `'` right after one (possibly escaped) char.
                if let Some(end) = char_literal_end(b, i) {
                    blank(&mut out, i, end);
                    i = end;
                } else {
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }
    String::from_utf8(out).expect("byte-for-byte ASCII blanking of valid UTF-8 stays valid UTF-8")
}

fn blank(out: &mut [u8], start: usize, end: usize) {
    for byte in &mut out[start..end] {
        if *byte != b'\n' {
            *byte = b' ';
        }
    }
}

/// `b[i]` is `'r'`: is this the start of a raw string (`r"..."`, `r#"..."#`, `r##"..."##`, ...)
/// rather than an identifier or keyword that merely starts with `r`?
fn is_raw_string_start(b: &[u8], i: usize) -> bool {
    let mut j = i + 1;
    while j < b.len() && b[j] == b'#' {
        j += 1;
    }
    j < b.len() && b[j] == b'"'
}

/// `b[i]` is the `r` of a raw string (as confirmed by `is_raw_string_start`); returns the index
/// just past its closing delimiter.
fn raw_string_end(b: &[u8], i: usize) -> usize {
    let n = b.len();
    let mut j = i + 1;
    let mut hashes = 0usize;
    while j < n && b[j] == b'#' {
        hashes += 1;
        j += 1;
    }
    j += 1; // past the opening `"`
    while j < n {
        if b[j] == b'"' {
            let mut k = j + 1;
            let mut matched = 0usize;
            while matched < hashes && k < n && b[k] == b'#' {
                matched += 1;
                k += 1;
            }
            if matched == hashes {
                return k;
            }
        }
        j += 1;
    }
    n
}

/// `b[start]` is `'`. Returns the index just past the closing `'` if this is a genuine char
/// literal, or `None` if it is a lifetime/generic tick (no matching close right after one char).
fn char_literal_end(b: &[u8], start: usize) -> Option<usize> {
    let n = b.len();
    let mut i = start + 1;
    if i >= n {
        return None;
    }
    if b[i] == b'\\' {
        i += 1;
        if i >= n {
            return None;
        }
        match b[i] {
            b'u' => {
                i += 1;
                if i < n && b[i] == b'{' {
                    while i < n && b[i] != b'}' {
                        i += 1;
                    }
                    if i < n {
                        i += 1;
                    }
                }
            }
            b'x' => {
                i += 1;
                for _ in 0..2 {
                    if i < n && b[i].is_ascii_hexdigit() {
                        i += 1;
                    }
                }
            }
            _ => i += 1,
        }
    } else {
        i += 1;
        while i < n && (b[i] & 0xC0) == 0x80 {
            i += 1; // UTF-8 continuation byte of one multi-byte char
        }
    }
    if i < n && b[i] == b'\'' {
        Some(i + 1)
    } else {
        None
    }
}
