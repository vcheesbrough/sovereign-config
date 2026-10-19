# MCP server

Each running server also publishes a prebuilt local **Model Context Protocol** server, `sovereign-config-mcp`, matched to its own release. It exposes the full implemented administration surface as MCP tools to any local stdio MCP host (for example Codex), using the authenticated user's permissions. It is local software — not a container or a remote HTTP service — and it talks to Sovereign Config only through the same public Rust client library the CLI uses; it never shells out to the CLI and never bypasses server authorization. Browse `https://<server>/downloads` for the link and command, or install directly into a self-cleaning temporary directory:

```sh
sh -c 'd=$(mktemp -d); trap "rm -rf \"$d\"" EXIT; curl -fsSL "https://<server>/dist/install-sovereign-config-mcp-<version>-x86_64-linux.sh" -o "$d/installer.sh" && sh "$d/installer.sh"'
```

The installer verifies its embedded checksum, installs `sovereign-config-mcp` into `~/.local/bin` (override with `SOVEREIGN_CONFIG_BIN`), and prints the installed version. Re-run it to upgrade. Because the binary is built from the server's own release tag, the installed MCP server is protocol-matched to that server by construction. Like the CLI installer, it extracts itself from its own file, so download it and run it — it cannot be piped straight into a shell. A Rust-toolchain source fallback is also available:

```sh
cargo install --locked --git https://github.com/vcheesbrough/sovereign-config --tag <version> --bin sovereign-config-mcp
```

Configure the MCP host to launch the installed binary directly as a local stdio process — no container, no wrapper. It reuses the CLI's profiles and stored credentials, selecting a profile with `--profile <name>` or the `SOVEREIGN_CONFIG_PROFILE` environment variable (the default profile otherwise). A minimal host entry:

```toml
[mcp_servers.sovereign-config]
command = "sovereign-config-mcp"
# args = ["--profile", "prod"]   # optional; omit to use the default profile
```

After installing or upgrading the binary, or changing its configuration, restart or reload the MCP host once so it relaunches the stdio process — that is the single reload boundary. Credentials stay in the established credential store; profiles are managed with the CLI (`sovereign-config profile …`).

The server exposes tools for authentication status and explicit device-flow `login`/`logout`; exact and subtree reads (`get`, `list`); plain and secret writes (`put_value`, `put_secret`); JSON-merge subtree replacement (`replace_subtree`); exact/recursive deletion (`delete`); explicit secret reveal (`reveal_secret`); multi-path value aliasing (`alias_add`, `alias_list`); and managed application connection lifecycle with their permission grants (`list_connections`, `create_connection`, `rotate_connection`, `revoke_connection`). The `login` tool surfaces the device verification URL and user code as a log notification, then polls the provider to completion. Secrets and authentication material never appear in tool arguments, diagnostics, or logs; plaintext is returned only by an explicit authorized reveal, and a managed connection's one-time URL only as the result of creating or rotating it. Every request is authorized by the server: a caller cannot reveal an unreadable secret, expand a delegated prefix, grant an unheld permission, or otherwise widen a request through the adapter.
