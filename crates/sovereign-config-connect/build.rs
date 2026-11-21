fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Build scripts run single-threaded before connectrpc-build invokes protoc.
    unsafe {
        std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
    }
    // Only what is served over Connect: the unversioned handshake and `v6`.
    // `v3`–`v5` are gRPC and gRPC-Web only, so they are never generated here.
    connectrpc_build::Config::new()
        .files(&[
            "../../proto/sovereign/config/handshake.proto",
            "../../proto/sovereign/config/v6/service.proto",
        ])
        .includes(&["../../proto"])
        .include_file("_connectrpc.rs")
        .compile()?;
    Ok(())
}
