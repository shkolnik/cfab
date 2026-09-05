//! `cfab run`'s supervisor. Only the single-instance lock lands in this gate (Task 9); the
//! rest — `run()`'s lifecycle, `child.rs`, `report.rs`, `sock.rs` — is a later task, built by
//! another lane against this module.

pub mod lock;
