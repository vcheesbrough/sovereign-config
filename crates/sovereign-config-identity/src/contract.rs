//! The terms of the realm contract the server itself relies on, whichever
//! identity provider is behind it (`docs/authentication.md`, "The realm
//! contract"). A provider's setup must meet them; a provider's tests hold its
//! setup file to these values.

use std::time::Duration;

/// The scope every access token must carry, which every deployed client
/// requests by this name.
pub const REQUIRED_SCOPE: &str = "sovereign-config";

/// The longest an access token may live. What waits for "every token minted
/// before now has expired" waits this long, plus its own margin.
pub const ACCESS_TOKEN_LIFETIME: Duration = Duration::from_mins(5);

/// How long a refresh token lives, which the web UI assumes when it decides
/// whether a stored session can still be resumed.
pub const REFRESH_TOKEN_LIFETIME: Duration = Duration::from_hours(8);

/// What the identity provider appends to a managed account's name in the
/// display-name claim of its tokens, so an access URL can never read as a
/// person in the audit trail.
pub const ACCESS_URL_NAME_MARKER: &str = " (access URL)";
