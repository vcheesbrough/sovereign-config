//! The Connect-protocol side of the contract: buffa messages and
//! `connectrpc` service traits for the operations served over Connect — the
//! unversioned handshake and protocol `v6` (#582).
//!
//! Generated from the same `.proto` files as `sovereign-config-proto`, so the
//! two describe one wire. The server bridges these messages onto its prost
//! shims by re-encoding them; nothing else depends on this crate.

pub mod proto {
    connectrpc::include_generated!();
}
