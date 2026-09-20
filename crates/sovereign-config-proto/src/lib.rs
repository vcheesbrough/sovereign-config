//! Versioned protobuf contract shared by every Sovereign Config component.
//!
//! One module per protocol version, plus the unversioned `sovereign.config`
//! package at the root of [`sovereign::config`], which holds the handshake and
//! nothing else.

pub mod sovereign {
    pub mod config {
        // The unversioned handshake. It sits at the root of the namespace
        // rather than in a `vN` module because it is the one operation that is
        // never routed by version; see `proto/sovereign/config/handshake.proto`.
        tonic::include_proto!("sovereign.config");

        pub mod v3 {
            tonic::include_proto!("sovereign.config.v3");
        }
    }
}
