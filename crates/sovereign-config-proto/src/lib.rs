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

        pub mod v4 {
            tonic::include_proto!("sovereign.config.v4");
        }

        pub mod v5 {
            tonic::include_proto!("sovereign.config.v5");
        }

        /// Served over the Connect protocol only (#582). The tonic stubs are
        /// generated like every other version's, but no gRPC router ever
        /// registers them: the server reaches its `v6` shims through the
        /// Connect bridge, and the clients dial `v6` with hand-written
        /// Connect unary calls over these messages.
        pub mod v6 {
            tonic::include_proto!("sovereign.config.v6");
        }
    }
}
