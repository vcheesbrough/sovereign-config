//! MCP method dispatch and tool execution over a JSON-RPC stdio stream.
//!
//! [`Server`] is generic over a [`Backend`] and over the byte streams it reads
//! and writes, so the exact same dispatch runs against real stdio in
//! production and against in-memory buffers in tests. Only protocol messages
//! are ever written to the output stream; diagnostics go to stderr, redacted.

use std::io;

use serde_json::{Value, json};
use sovereign_config_core::{
    ManagedConnectionMetadata, PlainValue, ProvisionedManagedConnection, SubTreeValue, Timestamp,
    ValueContent, ValueListing, ValuePaths, ValueSubTree, render_subtree_json,
};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc::unbounded_channel;

use crate::backend::{Backend, LoginPrompt};
use crate::errors::ToolFailure;
use crate::protocol::{
    INVALID_PARAMS, Incoming, METHOD_NOT_FOUND, error, notification, parse_incoming, success,
};
use crate::tools::{ToolCall, catalogue, parse_call};

/// The newest MCP protocol revision this server implements. When a client
/// requests a different revision the server still advertises this one.
const DEFAULT_PROTOCOL_VERSION: &str = "2025-06-18";

/// A buffered writer that emits one JSON-RPC message per line and flushes each,
/// keeping the output stream pure protocol.
struct Outbound<W> {
    writer: W,
}

impl<W: AsyncWrite + Unpin> Outbound<W> {
    async fn send(&mut self, message: &Value) -> io::Result<()> {
        let mut line = serde_json::to_vec(message).expect("protocol messages always serialize");
        line.push(b'\n');
        self.writer.write_all(&line).await?;
        self.writer.flush().await
    }
}

/// An MCP server bound to one administration backend.
pub struct Server<B> {
    backend: B,
    server_version: &'static str,
}

impl<B: Backend> Server<B> {
    #[must_use]
    pub const fn new(backend: B, server_version: &'static str) -> Self {
        Self {
            backend,
            server_version,
        }
    }

    /// Runs the read/dispatch/write loop until the input stream reaches EOF,
    /// which is treated as a graceful shutdown.
    ///
    /// # Errors
    ///
    /// Returns an I/O error only if reading or writing the streams fails;
    /// protocol and tool errors are reported in-band and never abort the loop.
    pub async fn run<R, W>(mut self, reader: R, writer: W) -> io::Result<()>
    where
        R: AsyncBufRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut lines = reader.lines();
        let mut out = Outbound { writer };
        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }
            self.handle_line(&line, &mut out).await?;
        }
        Ok(())
    }

    async fn handle_line<W: AsyncWrite + Unpin>(
        &mut self,
        line: &str,
        out: &mut Outbound<W>,
    ) -> io::Result<()> {
        match parse_incoming(line) {
            Incoming::Request { id, method, params } => {
                self.handle_request(id, &method, &params, out).await
            }
            Incoming::Notification { method } => {
                // Notifications are informational; `initialized` completes the
                // handshake and the rest are ignored. None produce a response.
                if method != "notifications/initialized" {
                    eprintln!("sovereign-config-mcp: ignoring notification {method}");
                }
                Ok(())
            }
            Incoming::Invalid { id: Some(id), code } => {
                out.send(&error(id, code, "invalid request")).await
            }
            Incoming::Invalid { id: None, .. } => {
                // No id to address a response to; a malformed frame is dropped.
                eprintln!("sovereign-config-mcp: discarded a malformed message");
                Ok(())
            }
        }
    }

    async fn handle_request<W: AsyncWrite + Unpin>(
        &mut self,
        id: Value,
        method: &str,
        params: &Value,
        out: &mut Outbound<W>,
    ) -> io::Result<()> {
        match method {
            "initialize" => {
                let result = self.initialize_result(params);
                out.send(&success(id, result)).await
            }
            "tools/list" => {
                out.send(&success(id, json!({ "tools": catalogue() })))
                    .await
            }
            "ping" => out.send(&success(id, json!({}))).await,
            "tools/call" => self.handle_tools_call(id, params, out).await,
            _ => {
                out.send(&error(id, METHOD_NOT_FOUND, "method not found"))
                    .await
            }
        }
    }

    fn initialize_result(&self, params: &Value) -> Value {
        let protocol_version = params
            .get("protocolVersion")
            .and_then(Value::as_str)
            .filter(|version| !version.is_empty())
            .unwrap_or(DEFAULT_PROTOCOL_VERSION)
            .to_owned();
        json!({
            "protocolVersion": protocol_version,
            "capabilities": { "tools": {}, "logging": {} },
            "serverInfo": {
                "name": "sovereign-config-mcp",
                "version": self.server_version,
            },
        })
    }

    async fn handle_tools_call<W: AsyncWrite + Unpin>(
        &mut self,
        id: Value,
        params: &Value,
        out: &mut Outbound<W>,
    ) -> io::Result<()> {
        let Some(name) = params.get("name").and_then(Value::as_str) else {
            return out
                .send(&error(
                    id,
                    INVALID_PARAMS,
                    "tools/call requires a string name",
                ))
                .await;
        };
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let result = match parse_call(name, &arguments) {
            Ok(call) => self.execute(call, out).await,
            Err(failure) => Err(failure),
        };
        let payload = match result {
            Ok(text) => tool_ok(&text),
            Err(failure) => tool_error(&failure),
        };
        out.send(&success(id, payload)).await
    }

    /// Executes a validated call, emitting any interim notifications through
    /// `out`, and returns the human-readable result text or a bounded failure.
    async fn execute<W: AsyncWrite + Unpin>(
        &mut self,
        call: ToolCall,
        out: &mut Outbound<W>,
    ) -> Result<String, ToolFailure> {
        match call {
            ToolCall::Status => self.status().await,
            ToolCall::Login => self.login(out).await,
            ToolCall::Logout => {
                self.backend.logout().await?;
                Ok("Logged out".to_owned())
            }
            ToolCall::Get { path, reveal } => {
                let subtree = self.backend.get_subtree(&path).await?;
                self.render_get(&path, subtree, reveal).await
            }
            ToolCall::List { path } => {
                let listing = self.backend.list_values(&path).await?;
                Ok(render_listing(&listing))
            }
            ToolCall::PutValue { path, value } => {
                self.backend.put_value(&path, &value).await?;
                Ok("Value stored".to_owned())
            }
            ToolCall::PutSecret { path, value } => {
                self.backend.put_secret(&path, &value).await?;
                Ok("Secret stored".to_owned())
            }
            ToolCall::ReplaceSubtree { path, values } => {
                let metadata = self.backend.replace_subtree(&path, &values).await?;
                Ok(format!(
                    "Subtree replaced ({} values)",
                    metadata.value_count
                ))
            }
            ToolCall::Delete { path, recurse } => {
                let metadata = self.backend.delete_values(&path, recurse).await?;
                Ok(if recurse {
                    format!("Subtree deleted ({} values)", metadata.deleted_count)
                } else {
                    "Value deleted".to_owned()
                })
            }
            ToolCall::RevealSecret { path } => {
                let revealed = self.backend.reveal_secret(&path).await?;
                Ok(revealed.expose().to_owned())
            }
            ToolCall::AliasAdd {
                source_path,
                new_path,
            } => {
                self.backend.add_value_path(&source_path, &new_path).await?;
                Ok(format!("Alias created at {}", new_path.as_str()))
            }
            ToolCall::AliasList { path } => {
                let paths = self.backend.list_value_paths(&path).await?;
                Ok(render_value_paths(&paths))
            }
            ToolCall::ListConnections => {
                let connections = self.backend.list_connections().await?;
                let rendered: Vec<Value> = connections.iter().map(connection_json).collect();
                Ok(to_pretty(&json!(rendered)))
            }
            ToolCall::CreateConnection {
                display_name,
                root,
                permissions,
            } => {
                let provisioned = self
                    .backend
                    .create_connection(&display_name, &root, &permissions)
                    .await?;
                Ok(provisioned_text("Connection created", &provisioned))
            }
            ToolCall::RotateConnection { connection_id } => {
                let provisioned = self.backend.rotate_connection(&connection_id).await?;
                Ok(provisioned_text("Connection rotated", &provisioned))
            }
            ToolCall::RevokeConnection { connection_id } => {
                self.backend.revoke_connection(&connection_id).await?;
                Ok("Connection revoked".to_owned())
            }
        }
    }

    async fn status(&self) -> Result<String, ToolFailure> {
        let service = self.backend.service_status().await?;
        let authentication = self.backend.authentication_status().await?;
        Ok(format!(
            "Service {} (protocol {}; compatible={})\nAuthentication: {}",
            service.application_version,
            service.protocol_version,
            service.compatible,
            if authentication.authenticated {
                "logged in"
            } else {
                "logged out"
            },
        ))
    }

    async fn login<W: AsyncWrite + Unpin>(
        &self,
        out: &mut Outbound<W>,
    ) -> Result<String, ToolFailure> {
        let (prompts, mut inbox) = unbounded_channel::<LoginPrompt>();
        let login = self.backend.login(prompts);
        tokio::pin!(login);
        let mut prompt: Option<LoginPrompt> = None;
        loop {
            tokio::select! {
                biased;
                delivery = inbox.recv() => {
                    if let Some(incoming) = delivery {
                        out.send(&login_notification(&incoming)).await.ok();
                        prompt = Some(incoming);
                    }
                }
                result = &mut login => {
                    result?;
                    // Drain a prompt that arrived in the same wake as completion.
                    while let Ok(incoming) = inbox.try_recv() {
                        out.send(&login_notification(&incoming)).await.ok();
                        prompt = Some(incoming);
                    }
                    return Ok(match prompt {
                        Some(prompt) => format!(
                            "Logged in. If prompted, visit {} and enter code {}.",
                            prompt.verification_uri, prompt.user_code,
                        ),
                        None => "Logged in".to_owned(),
                    });
                }
            }
        }
    }

    async fn render_get(
        &self,
        path: &sovereign_config_core::ConfigPath,
        mut subtree: ValueSubTree,
        reveal: bool,
    ) -> Result<String, ToolFailure> {
        if reveal {
            self.reveal_subtree(&mut subtree.values).await?;
        }
        render_subtree_json(path, &subtree.values).map_err(ToolFailure::from)
    }

    /// Replaces each masked secret with its revealed plaintext through an
    /// explicit per-path authorized reveal. Any reveal the server refuses
    /// aborts the whole render, so an unreadable secret is never disclosed.
    async fn reveal_subtree(&self, values: &mut [SubTreeValue]) -> Result<(), ToolFailure> {
        for value in values {
            if matches!(value.value, ValueContent::Secret(_)) {
                let revealed = self.backend.reveal_secret(&value.path).await?;
                value.value = ValueContent::Plain(PlainValue::new(revealed.expose()));
            }
        }
        Ok(())
    }
}

fn tool_ok(text: &str) -> Value {
    json!({ "content": [ { "type": "text", "text": text } ], "isError": false })
}

fn tool_error(failure: &ToolFailure) -> Value {
    json!({
        "content": [ { "type": "text", "text": format!("{}: {}", failure.code, failure.message) } ],
        "isError": true,
        "structuredContent": { "error": { "code": failure.code, "message": failure.message } },
    })
}

fn login_notification(prompt: &LoginPrompt) -> Value {
    notification(
        "notifications/message",
        json!({
            "level": "info",
            "logger": "sovereign-config-mcp",
            "data": {
                "message": "Complete the device login to continue.",
                "verification_uri": prompt.verification_uri,
                "user_code": prompt.user_code,
                "verification_uri_complete": prompt.verification_uri_complete,
            },
        }),
    )
}

fn render_listing(listing: &ValueListing) -> String {
    let values: Vec<Value> = listing
        .values
        .iter()
        .map(|value| {
            json!({
                "path": value.path.as_str(),
                "classification": classification(&value.value),
                "value": value.value.display_text(),
            })
        })
        .collect();
    let paths: Vec<&str> = listing
        .paths
        .iter()
        .map(sovereign_config_core::ConfigPath::as_str)
        .collect();
    to_pretty(&json!({ "values": values, "paths": paths }))
}

fn render_value_paths(paths: &ValuePaths) -> String {
    let paths: Vec<&str> = paths
        .paths
        .iter()
        .map(sovereign_config_core::ConfigPath::as_str)
        .collect();
    to_pretty(&json!({ "paths": paths }))
}

fn classification(content: &ValueContent) -> &'static str {
    match content {
        ValueContent::Plain(_) => "plain",
        ValueContent::Secret(_) => "secret",
    }
}

fn connection_json(metadata: &ManagedConnectionMetadata) -> Value {
    json!({
        "connection_id": metadata.connection_id.as_str(),
        "display_name": metadata.display_name.as_str(),
        "root": metadata.root.as_str(),
        "state": metadata.state.as_str(),
        "permissions": metadata.permissions.grant_tokens(),
        "created_at": epoch_seconds(&metadata.created_at),
        "updated_at": epoch_seconds(&metadata.updated_at),
    })
}

/// Renders a provisioned connection, including its one-time connection URL. The
/// URL is the authorized product of create/rotate — the only place a credential
/// leaves the server — and appears nowhere else, including diagnostics.
fn provisioned_text(action: &str, provisioned: &ProvisionedManagedConnection) -> String {
    let metadata = connection_json(&provisioned.metadata);
    let url = provisioned.connection_url.connection().canonical().expose();
    format!("{action}\n{}\nconnection_url: {url}", to_pretty(&metadata))
}

const fn epoch_seconds(timestamp: &Timestamp) -> i64 {
    timestamp.seconds
}

fn to_pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}
