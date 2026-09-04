//! Imperative subcommands. All host access goes through the `Sys` trait so the imperative
//! branches are testable against `MockSys`.

pub mod cluster;
pub mod common;
pub mod conf_sync;
pub mod down;
pub mod engine_ctl;
pub mod fwd_watchdog;
pub mod measure_cap;
pub mod policy_teeth;
pub mod shape_daemon;
pub mod up;
pub mod verify;
