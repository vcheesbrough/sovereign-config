//! First-party Sovereign Config local stdio MCP server (binary entry point).
//!
//! The binary speaks the Model Context Protocol over stdin/stdout so an MCP
//! host (e.g. Codex) can drive the full implemented administration surface
//! using the authenticated user's permissions. It reuses the public client
//! library and native transport/credential layer exclusively — it never shells
//! out to the CLI and never bypasses server authorization.

#![forbid(unsafe_code)]

use tokio::io::BufReader;

use sovereign_config_mcp::SERVER_VERSION;
use sovereign_config_mcp::native::NativeBackend;
use sovereign_config_mcp::server::Server;

/// Environment variable selecting the connection profile, mirroring the CLI's
/// `--profile`. Absent means the default profile.
const PROFILE_ENV: &str = "SOVEREIGN_CONFIG_PROFILE";

fn main() -> anyhow::Result<()> {
    let mut arguments = std::env::args().skip(1);
    let mut profile = std::env::var(PROFILE_ENV)
        .ok()
        .filter(|value| !value.is_empty());
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--version" | "-V" => {
                println!("sovereign-config-mcp {SERVER_VERSION}");
                return Ok(());
            }
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            "--profile" => {
                profile = arguments
                    .next()
                    .filter(|value| !value.is_empty())
                    .or(profile);
            }
            other => {
                anyhow::bail!("unknown argument: {other}");
            }
        }
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(serve(profile))
}

async fn serve(profile: Option<String>) -> anyhow::Result<()> {
    let backend = NativeBackend::new(profile);
    let server = Server::new(backend, SERVER_VERSION);
    let stdin = BufReader::new(tokio::io::stdin());
    let stdout = tokio::io::stdout();
    server.run(stdin, stdout).await?;
    Ok(())
}

fn print_help() {
    println!(
        "sovereign-config-mcp {SERVER_VERSION}\n\
         Local stdio Model Context Protocol server for Sovereign Config.\n\n\
         USAGE:\n    sovereign-config-mcp [--profile <name>]\n\n\
         The server communicates over stdin/stdout using the MCP JSON-RPC\n\
         framing; launch it from an MCP host rather than interactively.\n\n\
         OPTIONS:\n    \
         --profile <name>  Connection profile to use (env: {PROFILE_ENV})\n    \
         --version         Print the version and exit\n    \
         --help            Print this help and exit",
    );
}
