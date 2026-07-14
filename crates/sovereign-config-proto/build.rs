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
            &["../../proto/sovereign/config/v1/service.proto"],
            &["../../proto"],
        )?;
    Ok(())
}
