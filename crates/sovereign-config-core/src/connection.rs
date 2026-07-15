use core::fmt;
use std::net::IpAddr;

use base64::{Engine, engine::general_purpose};
use url::{Url, form_urlencoded};

use crate::{ConfigPath, Secret};

const FORMAT_VERSION: &str = "1";

#[derive(Clone)]
pub struct ConnectionUrl {
    canonical: Secret,
    endpoint: String,
    root: ConfigPath,
    issuer: String,
    client_id: String,
    client_authentication: Option<Secret>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionUrlError;

impl ConnectionUrl {
    /// Parses the canonical version-1 connection URL.
    ///
    /// # Errors
    ///
    /// Returns a redacted error when the URL, root, identity-provider fields, or
    /// optional client credential is malformed or non-canonical.
    pub fn parse(value: &str) -> Result<Self, ConnectionUrlError> {
        let url = Url::parse(value).map_err(|_| ConnectionUrlError)?;
        validate_endpoint(&url)?;
        let root = parse_root(url.path())?;
        let fragment = url.fragment().ok_or(ConnectionUrlError)?;
        let mut version = None;
        let mut issuer = None;
        let mut client_id = None;
        let mut client_secret = None;
        for (key, value) in form_urlencoded::parse(fragment.as_bytes()) {
            let target = match key.as_ref() {
                "v" => &mut version,
                "issuer" => &mut issuer,
                "client_id" => &mut client_id,
                "client_secret" => &mut client_secret,
                _ => return Err(ConnectionUrlError),
            };
            if target.replace(value.into_owned()).is_some() {
                return Err(ConnectionUrlError);
            }
        }
        if version.as_deref() != Some(FORMAT_VERSION) {
            return Err(ConnectionUrlError);
        }
        let issuer = canonical_issuer(&issuer.ok_or(ConnectionUrlError)?)?;
        let client_id = client_id.ok_or(ConnectionUrlError)?;
        if client_id.is_empty()
            || !client_id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
            })
        {
            return Err(ConnectionUrlError);
        }
        let client_authentication = client_secret
            .as_deref()
            .map(parse_client_authentication)
            .transpose()?;
        let endpoint = url.origin().ascii_serialization();
        let canonical = serialize(
            &endpoint,
            &root,
            &issuer,
            &client_id,
            client_secret.as_deref(),
        );
        if canonical != value {
            return Err(ConnectionUrlError);
        }
        Ok(Self {
            canonical: Secret::new(canonical),
            endpoint,
            root,
            issuer,
            client_id,
            client_authentication,
        })
    }

    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    #[must_use]
    pub const fn root(&self) -> &ConfigPath {
        &self.root
    }

    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    #[must_use]
    pub const fn client_authentication(&self) -> Option<&Secret> {
        self.client_authentication.as_ref()
    }

    #[must_use]
    pub const fn canonical(&self) -> &Secret {
        &self.canonical
    }

    #[must_use]
    pub fn redacted(&self) -> String {
        serialize(
            &self.endpoint,
            &self.root,
            &self.issuer,
            &self.client_id,
            self.client_authentication.as_ref().map(|_| "*"),
        )
    }
}

impl fmt::Debug for ConnectionUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ConnectionUrl")
            .field(&self.redacted())
            .finish()
    }
}

impl fmt::Display for ConnectionUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.redacted())
    }
}

impl fmt::Display for ConnectionUrlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("connection URL is invalid")
    }
}

impl std::error::Error for ConnectionUrlError {}

fn validate_endpoint(url: &Url) -> Result<(), ConnectionUrlError> {
    if !valid_secure_origin(url)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
    {
        return Err(ConnectionUrlError);
    }
    Ok(())
}

fn canonical_issuer(value: &str) -> Result<String, ConnectionUrlError> {
    let issuer = Url::parse(value).map_err(|_| ConnectionUrlError)?;
    if !valid_secure_origin(&issuer)
        || !issuer.username().is_empty()
        || issuer.password().is_some()
        || issuer.query().is_some()
        || issuer.fragment().is_some()
        || !issuer.path().ends_with('/')
    {
        return Err(ConnectionUrlError);
    }
    let canonical = issuer.as_str().to_owned();
    if canonical == value {
        Ok(canonical)
    } else {
        Err(ConnectionUrlError)
    }
}

fn valid_secure_origin(url: &Url) -> bool {
    url.host_str().is_some()
        && (url.scheme() == "https"
            || (url.scheme() == "http"
                && url
                    .host_str()
                    .and_then(|host| host.parse::<IpAddr>().ok())
                    .is_some_and(|address| address.is_loopback())))
}

fn parse_root(path: &str) -> Result<ConfigPath, ConnectionUrlError> {
    ConfigPath::parse(path).map_err(|_| ConnectionUrlError)
}

fn parse_client_authentication(value: &str) -> Result<Secret, ConnectionUrlError> {
    if value.is_empty() || value.contains('=') {
        return Err(ConnectionUrlError);
    }
    let decoded = general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ConnectionUrlError)?;
    if general_purpose::URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(ConnectionUrlError);
    }
    let decoded_text = std::str::from_utf8(&decoded).map_err(|_| ConnectionUrlError)?;
    let (username, password) = decoded_text.split_once(':').ok_or(ConnectionUrlError)?;
    if username.is_empty()
        || password.is_empty()
        || decoded_text.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(ConnectionUrlError);
    }
    Ok(Secret::new(general_purpose::STANDARD.encode(decoded)))
}

fn serialize(
    endpoint: &str,
    root: &ConfigPath,
    issuer: &str,
    client_id: &str,
    client_secret: Option<&str>,
) -> String {
    let mut fragment = form_urlencoded::Serializer::new(String::new());
    fragment
        .append_pair("v", FORMAT_VERSION)
        .append_pair("issuer", issuer)
        .append_pair("client_id", client_id);
    let redacted = client_secret == Some("*");
    if let Some(client_secret) = client_secret.filter(|_| !redacted) {
        fragment.append_pair("client_secret", client_secret);
    }
    let mut serialized = format!("{endpoint}{}#{}", root.as_str(), fragment.finish());
    if redacted {
        serialized.push_str("&client_secret=*");
    }
    serialized
}

#[cfg(test)]
mod tests {
    use base64::{Engine, engine::general_purpose};

    use super::ConnectionUrl;

    fn device_url() -> &'static str {
        "https://config.example.test/apps/api#v=1&issuer=https%3A%2F%2Fauth.example.test%2Fapplication%2Fo%2Fconfig%2F&client_id=sovereign-config"
    }

    #[test]
    fn parses_canonical_device_connection() {
        let connection = ConnectionUrl::parse(device_url()).unwrap();
        assert_eq!(connection.endpoint(), "https://config.example.test");
        assert_eq!(connection.root().as_str(), "/apps/api");
        assert_eq!(
            connection.issuer(),
            "https://auth.example.test/application/o/config/"
        );
        assert_eq!(connection.client_id(), "sovereign-config");
        assert!(connection.client_authentication().is_none());
        assert_eq!(connection.canonical().expose(), device_url());
    }

    #[test]
    fn decodes_and_redacts_managed_credentials() {
        let credential = general_purpose::URL_SAFE_NO_PAD.encode("pipeline:app-password-sentinel");
        let value = format!("{}&client_secret={credential}", device_url());
        let connection = ConnectionUrl::parse(&value).unwrap();
        assert_eq!(
            connection.client_authentication().unwrap().expose(),
            general_purpose::STANDARD.encode("pipeline:app-password-sentinel")
        );
        assert_eq!(
            connection.to_string(),
            format!("{}&client_secret=*", device_url())
        );
        assert!(!format!("{connection:?}").contains("app-password-sentinel"));
    }

    #[test]
    fn rejects_noncanonical_and_ambiguous_connections() {
        for invalid in [
            "http://config.example.test/#v=1&issuer=https%3A%2F%2Fauth.example.test%2F&client_id=client",
            "https://user:password@config.example.test/#v=1&issuer=https%3A%2F%2Fauth.example.test%2F&client_id=client",
            "https://config.example.test/?query=value#v=1&issuer=https%3A%2F%2Fauth.example.test%2F&client_id=client",
            "https://config.example.test/Apps#v=1&issuer=https%3A%2F%2Fauth.example.test%2F&client_id=client",
            "https://config.example.test/#v=2&issuer=https%3A%2F%2Fauth.example.test%2F&client_id=client",
            "https://config.example.test/#v=1&issuer=http%3A%2F%2Fauth.example.test%2F&client_id=client",
            "https://config.example.test/#v=1&issuer=https%3A%2F%2FAUTH.example.test%2F&client_id=client",
            "https://config.example.test/#v=1&issuer=https%3A%2F%2Fauth.example.test%2F&client_id=bad+client",
            "https://config.example.test/#v=1&issuer=https%3A%2F%2Fauth.example.test%2F&client_id=client&unknown=value",
            "https://config.example.test/#v=1&v=1&issuer=https%3A%2F%2Fauth.example.test%2F&client_id=client",
            "https://config.example.test/#v=1&issuer=https%3A%2F%2Fauth.example.test%2F&client_id=client&client_secret=",
            "https://config.example.test/#v=1&issuer=https%3A%2F%2Fauth.example.test%2F&client_id=client&client_secret=cGlwZWxpbmU6cGFzcw==",
            "https://config.example.test/#v=1&issuer=https%3A%2F%2Fauth.example.test%2F&client_id=client&client_secret=YWJj",
        ] {
            assert!(ConnectionUrl::parse(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn permits_plaintext_only_for_numeric_loopback_tests() {
        let value = "http://127.0.0.1:50051/#v=1&issuer=http%3A%2F%2F127.0.0.1%3A50052%2F&client_id=test-client";
        assert!(ConnectionUrl::parse(value).is_ok());
        assert!(ConnectionUrl::parse(&value.replace("127.0.0.1", "localhost")).is_err());
    }
}
