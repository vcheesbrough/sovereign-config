//! Versioned protobuf contract shared by every Sovereign Config component.

pub mod sovereign {
    pub mod config {
        pub mod v2 {
            tonic::include_proto!("sovereign.config.v2");
        }
    }
}
