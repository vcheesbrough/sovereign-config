fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Build scripts run single-threaded before tonic invokes protoc.
    unsafe {
        std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
    }
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .build_transport(false)
        .compile_protos(
            &[
                // The unversioned handshake, and then one file per protocol
                // version. The handshake is listed first because it is the
                // operation every version's clients call before any of them.
                "../../proto/sovereign/config/handshake.proto",
                "../../proto/sovereign/config/v3/service.proto",
            ],
            &["../../proto"],
        )?;
    Ok(())
}
