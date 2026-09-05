//! `cfab run`: one supervising process that applies the fabric and then keeps the fabric's
//! child processes (`cfab engine`, `cfab shape-daemon`, `cfab conf-sync`) running.

pub mod child;
pub mod lock;
pub mod report;
pub mod sock;
