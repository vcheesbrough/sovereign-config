//! `migrate`'s Authentik step: what the release configures in Authentik
//! itself, applied from the image rather than from a CI step (#615).
//!
//! 1. Authentik must be at least [`MINIMUM_VERSION`] and expose every API
//!    surface the connection manager calls; otherwise nothing is applied.
//! 2. The environment's blueprint, compiled into the binary, is rendered with
//!    its variables and applied as its managed instance — created the first
//!    time, its content replaced after that — and `migrate` waits for
//!    Authentik's verdict.
//!
//! Re-applying an unchanged blueprint changes nothing, so the step is
//! idempotent; an older release's blueprint resets the fields it sets and
//! deletes nothing it does not name.
//!
//! Its variables:
//!
//! - `SOVEREIGN_CONFIG_AUTHENTIK_BLUEPRINT` — `production` or `development`.
//!   Unset or blank, the step is skipped: the operator configures Authentik.
//! - `SOVEREIGN_CONFIG_AUTHENTIK_ADMIN_TOKEN` (or `…_FILE`) — an Authentik
//!   API token allowed to manage blueprints. Only `migrate` is given it.
//! - `SOVEREIGN_CONFIG_OIDC_ISSUER` — names the Authentik instance, whose
//!   host is also the brand the device-code flow is set on, and the
//!   application, which must be the blueprint's.
//! - `SOVEREIGN_CONFIG_PUBLIC_ORIGIN` — the web UI's redirect URI is
//!   `<origin>/auth/callback`.
//! - `SOVEREIGN_CONFIG_MANAGER_API_TOKEN` (or `…_FILE`) — the connection
//!   manager's token, which the blueprint sets as the manager's key.
//!
//! No error message quotes a value.

use std::{net::IpAddr, time::Duration};

use anyhow::{Context, Result, bail};
use reqwest::Url;
use sovereign_config_core::Secret;
use sovereign_config_identity::{ProviderError, Variables};
use sovereign_config_telemetry::error::Classified;
use tracing::info;

use crate::client::{AuthentikAdminClient, BlueprintState};
use crate::settings::validate_issuer_url;

const BLUEPRINT: &str = "SOVEREIGN_CONFIG_AUTHENTIK_BLUEPRINT";
const ADMIN_TOKEN: &str = "SOVEREIGN_CONFIG_AUTHENTIK_ADMIN_TOKEN";
const ISSUER: &str = "SOVEREIGN_CONFIG_OIDC_ISSUER";
const PUBLIC_ORIGIN: &str = "SOVEREIGN_CONFIG_PUBLIC_ORIGIN";
const MANAGER_API_TOKEN: &str = "SOVEREIGN_CONFIG_MANAGER_API_TOKEN";

/// The oldest Authentik the server's calls are known to work against.
pub(crate) const MINIMUM_VERSION: (u32, u32, u32) = (2026, 5, 2);

/// API surfaces the connection manager calls, as they appear in Authentik's
/// schema: the version check alone would not notice a build without them.
const REQUIRED_SURFACES: [&str; 4] = [
    "grant_types",
    "/core/users/service_account/",
    "/core/tokens/{identifier}/set_key/",
    "initial_permissions",
];

/// One call may take this long: applying a blueprint runs inside the request.
const CALL_TIMEOUT: Duration = Duration::from_secs(120);
/// How long Authentik may take to report the apply finished.
const APPLY_DEADLINE: Duration = Duration::from_secs(300);
const POLL_INTERVAL: Duration = if cfg!(test) {
    Duration::from_millis(10)
} else {
    Duration::from_secs(2)
};

/// The blueprint each environment applies, compiled into the binary so the
/// one an image applies is the one it was built with.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Blueprint {
    Production,
    Development,
}

impl Blueprint {
    const ALL: [Self; 2] = [Self::Production, Self::Development];

    const fn name(self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::Development => "development",
        }
    }

    fn content(self) -> &'static str {
        match self {
            Self::Production => include_str!("../../../authentik/blueprint.yaml"),
            Self::Development => include_str!("../../../authentik/blueprint-dev.yaml"),
        }
    }

    /// The managed instance Authentik keeps it under: the names the CI steps
    /// this replaces used, so the same instance goes on owning its objects.
    const fn instance_name(self) -> &'static str {
        match self {
            Self::Production => "sovereign-config",
            Self::Development => "sovereign-config-dev",
        }
    }

    /// The application the blueprint creates, which the issuer must name.
    const fn application_slug(self) -> &'static str {
        match self {
            Self::Production => "sovereign-config",
            Self::Development => "sovereign-config-dev",
        }
    }

    /// Its placeholders: the redirect URI, the manager's token, the brand.
    const fn placeholders(self) -> [&'static str; 3] {
        match self {
            Self::Production => [
                "SOVEREIGN_CONFIG_BROWSER_REDIRECT_URI",
                "AUTHENTIK_SOVEREIGN_CONFIG_MANAGER_API_TOKEN",
                "AUTHENTIK_BRAND_DOMAIN",
            ],
            Self::Development => [
                "SOVEREIGN_CONFIG_DEV_BROWSER_REDIRECT_URI",
                "AUTHENTIK_SOVEREIGN_CONFIG_DEV_MANAGER_API_TOKEN",
                "AUTHENTIK_DEV_BRAND_DOMAIN",
            ],
        }
    }

    fn named(value: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|blueprint| blueprint.name() == value)
            .with_context(|| {
                format!(
                    "{BLUEPRINT} names no blueprint; it is one of: {}",
                    Self::ALL.map(Self::name).join(", ")
                )
            })
    }
}

/// The Authentik step, configured.
pub struct Setup {
    client: AuthentikAdminClient,
    blueprint: Blueprint,
    /// The blueprint with its variables substituted: it carries the
    /// manager's token, so it is held as a secret.
    rendered: Secret,
}

impl Setup {
    /// The step the variables select, or `None` when they select no
    /// blueprint.
    ///
    /// # Errors
    ///
    /// A blueprint is selected and a variable it needs is missing or not
    /// permitted. The message names the variable and quotes no value.
    pub fn from_variables(variables: &dyn Variables) -> Result<Option<Self>> {
        let Some(selected) = variables.optional(BLUEPRINT) else {
            return Ok(None);
        };
        let blueprint = Blueprint::named(selected.trim())?;
        let issuer = variables.required(ISSUER)?;
        let issuer_url = issuer
            .parse::<Url>()
            .with_context(|| format!("{ISSUER} must be a valid URL"))?;
        validate_issuer_url(&issuer, &issuer_url)?;
        if issuer_url.path() != format!("/application/o/{}/", blueprint.application_slug()) {
            bail!(
                "{ISSUER} does not name the application the {} blueprint creates",
                blueprint.name()
            );
        }
        let brand_domain = issuer_url
            .host_str()
            .context("SOVEREIGN_CONFIG_OIDC_ISSUER names no host")?
            .to_owned();
        let api_origin = issuer_url
            .origin()
            .ascii_serialization()
            .parse::<Url>()
            .with_context(|| format!("{ISSUER} has no usable origin"))?;
        let redirect_uri = format!(
            "{}/auth/callback",
            validated_public_origin(&variables.required(PUBLIC_ORIGIN)?)?
        );
        let manager_token = variables.secret(MANAGER_API_TOKEN)?;
        if manager_token
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
        {
            bail!("{MANAGER_API_TOKEN} must not contain whitespace");
        }
        let [redirect, token, brand] = blueprint.placeholders();
        let rendered = render(
            blueprint.content(),
            &[
                (redirect, &redirect_uri),
                (token, &manager_token),
                (brand, &brand_domain),
            ],
        )?;
        let client = AuthentikAdminClient::new(
            api_origin,
            Secret::new(variables.secret(ADMIN_TOKEN)?),
            CALL_TIMEOUT,
        )?;
        Ok(Some(Self {
            client,
            blueprint,
            rendered: Secret::new(rendered),
        }))
    }

    /// Checks Authentik, then applies the blueprint and waits for the
    /// verdict.
    ///
    /// # Errors
    ///
    /// Authentik is unreachable, older than [`MINIMUM_VERSION`] or missing a
    /// surface, or the blueprint does not apply. Nothing is applied unless
    /// the checks pass.
    pub async fn apply(&self) -> Result<()> {
        let version = self
            .client
            .version()
            .await
            .map_err(|error| failure("unable to read Authentik's version", error))?;
        // Authentik's own text, so it is shown only when it looks like a
        // version: no response text reaches a message otherwise.
        let version = displayable(&version);
        if !at_least(version, MINIMUM_VERSION) {
            let (major, minor, patch) = MINIMUM_VERSION;
            return Err(Classified::new(
                "authentik_too_old",
                format!(
                    "Authentik {version} is older than {major}.{minor}.{patch}, the oldest this \
                     release supports; nothing was applied"
                ),
            )
            .into());
        }
        let schema = self
            .client
            .schema()
            .await
            .map_err(|error| failure("unable to read Authentik's API schema", error))?;
        if let Some(missing) = REQUIRED_SURFACES
            .into_iter()
            .find(|surface| !contains(&schema, surface.as_bytes()))
        {
            return Err(Classified::new(
                "authentik_incompatible",
                format!(
                    "Authentik {version} does not expose {missing}, which managed connections \
                     need; nothing was applied"
                ),
            )
            .into());
        }
        info!(version = %version, "Authentik is compatible");

        let name = self.blueprint.instance_name();
        let found = self
            .client
            .blueprint_instance(name)
            .await
            .map_err(|error| failure("unable to look up the blueprint instance", error))?;
        let pk = if let Some(pk) = found {
            self.client
                .update_blueprint_instance(&pk, name, &self.rendered)
                .await
                .map_err(|error| failure("unable to update the blueprint instance", error))?;
            info!(blueprint = name, "updated the blueprint instance");
            pk
        } else {
            let pk = self
                .client
                .create_blueprint_instance(name, &self.rendered)
                .await
                .map_err(|error| failure("unable to create the blueprint instance", error))?;
            info!(blueprint = name, "created the blueprint instance");
            pk
        };
        // What the instance said before this apply: Authentik may apply in
        // the background, so a status read straight after asking can still
        // be the last apply's.
        let before = self.state(&pk).await?;
        self.client
            .apply_blueprint_instance(&pk)
            .await
            .map_err(|error| failure("unable to apply the blueprint", error))?;
        self.wait_for_verdict(&pk, &before).await
    }

    async fn state(&self, pk: &str) -> Result<BlueprintState> {
        self.client
            .blueprint_status(pk)
            .await
            .map_err(|error| failure("unable to read the blueprint's status", error))
    }

    async fn wait_for_verdict(&self, pk: &str, before: &BlueprintState) -> Result<()> {
        let name = self.blueprint.instance_name();
        let deadline = tokio::time::Instant::now() + APPLY_DEADLINE;
        loop {
            let now = self.state(pk).await?;
            let status = now.status.clone();
            match Verdict::after(before, &now) {
                Verdict::Applied => {
                    info!(blueprint = name, status = %displayable(&status), "applied the blueprint");
                    return Ok(());
                }
                Verdict::Failed => {
                    // `status` is one of the two words `Verdict` matched.
                    return Err(Classified::new(
                        "blueprint_failed",
                        format!(
                            "Authentik reports the {name} blueprint {status}; its worker's log \
                             says why"
                        ),
                    )
                    .into());
                }
                Verdict::Pending if tokio::time::Instant::now() >= deadline => {
                    return Err(Classified::new(
                        "blueprint_timeout",
                        format!(
                            "Authentik had not finished applying the {name} blueprint after {}s",
                            APPLY_DEADLINE.as_secs()
                        ),
                    )
                    .into());
                }
                Verdict::Pending => tokio::time::sleep(POLL_INTERVAL).await,
            }
        }
    }
}

/// What an apply status means.
#[derive(Debug, Eq, PartialEq)]
enum Verdict {
    Applied,
    Failed,
    Pending,
}

impl Verdict {
    /// The verdict on this apply, from the state before it and now.
    ///
    /// It applied only once `last_applied` has moved, which Authentik does on
    /// every successful apply; an unchanged one is the previous apply still
    /// showing. It failed when a failure status shows that was not already
    /// there. A failure that repeats the previous one cannot be told from an
    /// apply not yet run, so it is waited out to the deadline, and fails
    /// then.
    fn after(before: &BlueprintState, now: &BlueprintState) -> Self {
        match Self::of(&now.status) {
            Self::Applied
                if now.last_applied.is_some() && now.last_applied != before.last_applied =>
            {
                Self::Applied
            }
            Self::Failed if now.status != before.status => Self::Failed,
            _ => Self::Pending,
        }
    }

    /// `warning` is a non-fatal issue Authentik applied past, as the CI plugin
    /// treated it; an unrecognised status is waited out.
    fn of(status: &str) -> Self {
        match status {
            "successful" | "warning" => Self::Applied,
            "error" | "orphaned" => Self::Failed,
            _ => Self::Pending,
        }
    }
}

fn failure(what: &str, error: ProviderError) -> anyhow::Error {
    Classified::new(error.label(), format!("{what} ({})", error.label())).into()
}

/// Substitutes each `${NAME}` placeholder. Every placeholder in the content
/// must be one of `values`, and every one of `values` must appear, so a
/// blueprint and its variables cannot drift apart unnoticed.
fn render(content: &str, values: &[(&str, &str)]) -> Result<String> {
    let mut rendered = content.to_owned();
    for (name, value) in values {
        let placeholder = format!("${{{name}}}");
        if !rendered.contains(&placeholder) {
            bail!("the blueprint has no {placeholder} placeholder");
        }
        rendered = rendered.replace(&placeholder, value);
    }
    if let Some(start) = rendered.find("${") {
        let name: String = rendered[start + 2..]
            .chars()
            .take_while(|character| character.is_ascii_alphanumeric() || *character == '_')
            .collect();
        bail!("the blueprint's ${{{name}}} placeholder has no value");
    }
    Ok(rendered)
}

/// Whether `version` (`2026.5.2`, or with a suffix such as `-rc1`) is at
/// least `minimum`. An unreadable version is not.
fn at_least(version: &str, minimum: (u32, u32, u32)) -> bool {
    let mut parts = version.split('.').map(|part| {
        part.chars()
            .take_while(char::is_ascii_digit)
            .collect::<String>()
            .parse::<u32>()
            .ok()
    });
    let (Some(Some(major)), Some(Some(minor)), Some(Some(patch))) =
        (parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    (major, minor, patch) >= minimum
}

fn displayable(version: &str) -> &str {
    if !version.is_empty()
        && version.len() <= 32
        && version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
    {
        version
    } else {
        "(an unreadable version)"
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// The web UI's origin, as the server itself requires it: HTTPS (or
/// numeric-loopback HTTP, for tests), canonical, with nothing after it.
fn validated_public_origin(value: &str) -> Result<String> {
    let refused = || anyhow::anyhow!("{PUBLIC_ORIGIN} is not a permitted canonical origin");
    let url = value.parse::<Url>().map_err(|_| refused())?;
    let loopback_http = url.scheme() == "http"
        && url
            .host_str()
            .and_then(|host| host.trim_matches(['[', ']']).parse::<IpAddr>().ok())
            .is_some_and(|address| address.is_loopback());
    let canonical = url.origin().ascii_serialization();
    if !(url.scheme() == "https" || loopback_http)
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || value.trim_end_matches('/') != canonical
    {
        return Err(refused());
    }
    Ok(canonical)
}

#[cfg(test)]
mod tests;
