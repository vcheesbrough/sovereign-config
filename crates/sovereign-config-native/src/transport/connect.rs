//! Connect unary, by hand, over the HTTP client this crate already has.
//!
//! `v6` and the handshake are served over the Connect protocol (#582): a
//! `POST` of the encoded message with `Content-Type: application/proto`,
//! answered `200` with the encoded reply, or with an error status and a JSON
//! body naming the code. That is small enough to write here over `reqwest` and
//! prost — no `connectrpc` client, no second HTTP stack, and no second major
//! of anything — and it works over HTTP/1.1, so a proxy needs no h2c for it.
//!
//! [`ConnectChannel::unary`] answers in tonic's terms (`tonic::Response`,
//! `tonic::Status` carrying the `sovereign-config-*` headers as metadata), so
//! the dialer macro and the status mapping every gRPC version uses serve `v6`
//! unchanged.

use std::{sync::Arc, time::Duration};

use prost::Message;
use serde::Deserialize;
use tonic::{
    Code, Status,
    metadata::{MetadataMap, MetadataValue},
};

/// The content type of a Connect unary call in the binary encoding.
const PROTO: &str = "application/proto";

/// A connection to one service, over which Connect unary calls are made.
#[derive(Clone)]
pub(crate) struct ConnectChannel {
    http: reqwest::Client,
    base: Arc<str>,
    timeout: Duration,
}

/// Why a Connect call produced no reply.
#[derive(Debug)]
pub(crate) enum ConnectFailure {
    /// The service answered, but not in Connect's shape — it predates `v6`,
    /// or something between it and this client does not pass Connect — or
    /// the request never reached an answer at all.
    NotConnect,
    /// A Connect answer refusing the call, or no answer at all.
    Status(Status),
}

impl From<ConnectFailure> for Status {
    fn from(failure: ConnectFailure) -> Self {
        match failure {
            // After negotiation, a service that stops answering in Connect's
            // shape is a service that is not there.
            ConnectFailure::NotConnect => Self::unavailable("the service did not answer"),
            ConnectFailure::Status(status) => status,
        }
    }
}

#[derive(Deserialize)]
struct ConnectErrorBody {
    code: String,
    #[serde(default)]
    message: String,
}

impl ConnectChannel {
    /// A channel to `base` (`https://host[:port]`, already validated).
    ///
    /// # Errors
    ///
    /// Returns the client builder's failure when no TLS backend can be set up.
    pub(crate) fn new(
        base: &str,
        connect_timeout: Duration,
        timeout: Duration,
    ) -> Result<Self, reqwest::Error> {
        let http = reqwest::Client::builder()
            .connect_timeout(connect_timeout)
            .timeout(timeout)
            // A redirect would replay a bearer to wherever it pointed.
            .redirect(reqwest::redirect::Policy::none())
            // Straight to the endpoint, as the gRPC transport goes: an
            // `HTTP_PROXY` in the environment must not take the bearer on an
            // undeclared route, in clear text for a loopback endpoint.
            .no_proxy()
            .build()?;
        Ok(Self {
            http,
            base: Arc::from(base.trim_end_matches('/')),
            timeout,
        })
    }

    /// One Connect unary call on `route`.
    pub(crate) async fn unary<Req, Res>(
        &self,
        route: &str,
        request: tonic::Request<Req>,
    ) -> Result<tonic::Response<Res>, ConnectFailure>
    where
        Req: Message,
        Res: Message + Default,
    {
        let (metadata, _, message) = request.into_parts();
        let mut call = self
            .http
            .post(format!("{}{route}", self.base))
            .header(reqwest::header::CONTENT_TYPE, PROTO)
            .header("connect-protocol-version", "1")
            .header("connect-timeout-ms", self.timeout.as_millis().to_string())
            .body(message.encode_to_vec());
        if let Some(authorization) = metadata.get("authorization")
            && let Ok(value) = authorization.to_str()
        {
            call = call.header(reqwest::header::AUTHORIZATION, value);
        }
        // A request that never got an answer — refused, reset, or spoken to
        // by a server that only accepts HTTP/2 with prior knowledge — says
        // nothing about Connect either way, so it reads as "not Connect" and
        // the handshake asks again over gRPC, which reports the failure if it
        // is real. A timeout does not: asking again would only double it.
        let response = call.send().await.map_err(|error| {
            if error.is_timeout() {
                ConnectFailure::Status(Status::deadline_exceeded(
                    "the service did not answer in time",
                ))
            } else {
                ConnectFailure::NotConnect
            }
        })?;
        let status = response.status();
        let headers = response.headers().clone();
        let content_type = headers
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.split(';').next().unwrap_or(value).trim().to_owned())
            .unwrap_or_default();
        let body = response.bytes().await.map_err(|error| {
            ConnectFailure::Status(if error.is_timeout() {
                Status::deadline_exceeded("the service did not answer in time")
            } else {
                Status::unavailable("the answer was cut short")
            })
        })?;
        if status.is_success() {
            if content_type != PROTO {
                return Err(ConnectFailure::NotConnect);
            }
            return Res::decode(body)
                .map(tonic::Response::new)
                .map_err(|_| ConnectFailure::Status(Status::internal("the answer is malformed")));
        }
        if content_type != "application/json" {
            return Err(ConnectFailure::NotConnect);
        }
        let error: ConnectErrorBody =
            serde_json::from_slice(&body).map_err(|_| ConnectFailure::NotConnect)?;
        let Some(code) = code_named(&error.code) else {
            return Err(ConnectFailure::NotConnect);
        };
        Err(ConnectFailure::Status(Status::with_metadata(
            code,
            error.message,
            marker_metadata(&headers),
        )))
    }
}

/// The `sovereign-config-*` headers a Connect error carries — the
/// version-not-served marker among them — as the metadata a gRPC error
/// would carry them in.
fn marker_metadata(headers: &reqwest::header::HeaderMap) -> MetadataMap {
    let mut metadata = MetadataMap::new();
    for (name, value) in headers {
        if !name.as_str().starts_with("sovereign-config-") {
            continue;
        }
        if let (Ok(key), Ok(text)) = (
            tonic::metadata::AsciiMetadataKey::from_bytes(name.as_str().as_bytes()),
            value.to_str(),
        ) && let Ok(value) = MetadataValue::try_from(text)
        {
            metadata.insert(key, value);
        }
    }
    metadata
}

/// A Connect error code, as the gRPC code it stands for.
fn code_named(code: &str) -> Option<Code> {
    Some(match code {
        "canceled" => Code::Cancelled,
        "unknown" => Code::Unknown,
        "invalid_argument" => Code::InvalidArgument,
        "deadline_exceeded" => Code::DeadlineExceeded,
        "not_found" => Code::NotFound,
        "already_exists" => Code::AlreadyExists,
        "permission_denied" => Code::PermissionDenied,
        "resource_exhausted" => Code::ResourceExhausted,
        "failed_precondition" => Code::FailedPrecondition,
        "aborted" => Code::Aborted,
        "out_of_range" => Code::OutOfRange,
        "unimplemented" => Code::Unimplemented,
        "internal" => Code::Internal,
        "unavailable" => Code::Unavailable,
        "data_loss" => Code::DataLoss,
        "unauthenticated" => Code::Unauthenticated,
        _ => return None,
    })
}

/// Clients for one `v6` service, shaped like tonic's generated clients so the
/// dialer macro calls them the same way: `Client::new(channel)`, then one
/// method per RPC taking anything that is a `tonic::IntoRequest`.
macro_rules! connect_client {
    ($module:ident, $client:ident, $service:literal, { $($method:ident => $rpc:literal ($request:ident) -> $response:ident),+ $(,)? }) => {
        pub(crate) mod $module {
            use super::*;
            use crate::transport::connect::ConnectChannel;

            pub(crate) struct $client<T>(T);

            impl $client<ConnectChannel> {
                pub(crate) const fn new(channel: ConnectChannel) -> Self {
                    Self(channel)
                }

                $(
                    pub(crate) async fn $method(
                        &mut self,
                        request: impl tonic::IntoRequest<$request>,
                    ) -> Result<tonic::Response<$response>, tonic::Status> {
                        self.0
                            .unary(
                                concat!("/sovereign.config.v6.", $service, "/", $rpc),
                                request.into_request(),
                            )
                            .await
                            .map_err(tonic::Status::from)
                    }
                )+
            }
        }
    };
}

pub(crate) use connect_client;

#[cfg(test)]
mod tests {
    use super::code_named;

    #[test]
    fn every_connect_code_names_its_grpc_code_and_nothing_else_does() {
        for (name, code) in [
            ("canceled", 1),
            ("unknown", 2),
            ("invalid_argument", 3),
            ("deadline_exceeded", 4),
            ("not_found", 5),
            ("already_exists", 6),
            ("permission_denied", 7),
            ("resource_exhausted", 8),
            ("failed_precondition", 9),
            ("aborted", 10),
            ("out_of_range", 11),
            ("unimplemented", 12),
            ("internal", 13),
            ("unavailable", 14),
            ("data_loss", 15),
            ("unauthenticated", 16),
        ] {
            assert_eq!(
                code_named(name).map(|code| code as i32),
                Some(code),
                "{name}"
            );
        }
        assert_eq!(code_named("ok"), None);
        assert_eq!(code_named("INVALID_ARGUMENT"), None);
    }
}
