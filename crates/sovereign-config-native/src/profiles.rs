use std::{collections::BTreeMap, env, path::PathBuf};

use serde::{Deserialize, Serialize};
use sovereign_config_core::{ClientError, ConnectionUrl, ErrorKind};

use crate::storage::{read_private, write_private};

const CONFIG_FORMAT_VERSION: u8 = 1;
const MAX_CONFIG_BYTES: usize = 1024 * 1024;

pub struct ProfileStore {
    path: PathBuf,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredConfig {
    format_version: u8,
    default_profile: String,
    profiles: BTreeMap<String, StoredProfile>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredProfile {
    url: String,
}

impl ProfileStore {
    #[must_use]
    pub const fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Adds a named profile, making the first profile the default.
    ///
    /// # Errors
    ///
    /// Returns a bounded error for invalid names, duplicates, or unsafe storage.
    pub fn add(&self, name: &str, connection: &ConnectionUrl) -> Result<(), ClientError> {
        validate_name(name)?;
        let mut config = self.load()?.unwrap_or_else(|| StoredConfig {
            format_version: CONFIG_FORMAT_VERSION,
            default_profile: name.to_owned(),
            profiles: BTreeMap::new(),
        });
        if config.profiles.contains_key(name) {
            return Err(ClientError::new(
                ErrorKind::InvalidRequest,
                "profile already exists",
            ));
        }
        config.profiles.insert(
            name.to_owned(),
            StoredProfile {
                url: connection.canonical().expose().to_owned(),
            },
        );
        self.store(&config)
    }

    /// Replaces an existing profile URL.
    ///
    /// # Errors
    ///
    /// Returns a bounded error for invalid names, missing profiles, or unsafe storage.
    pub fn update(&self, name: &str, connection: &ConnectionUrl) -> Result<(), ClientError> {
        validate_name(name)?;
        let mut config = self.required()?;
        let profile = config.profiles.get_mut(name).ok_or_else(not_found)?;
        connection.canonical().expose().clone_into(&mut profile.url);
        self.store(&config)
    }

    /// Selects an existing profile as the default.
    ///
    /// # Errors
    ///
    /// Returns a bounded error for invalid names, missing profiles, or unsafe storage.
    pub fn set_default(&self, name: &str) -> Result<(), ClientError> {
        validate_name(name)?;
        let mut config = self.required()?;
        if !config.profiles.contains_key(name) {
            return Err(not_found());
        }
        name.clone_into(&mut config.default_profile);
        self.store(&config)
    }

    /// Loads the selected profile, falling back to the configured default.
    ///
    /// # Errors
    ///
    /// Returns a bounded error for invalid names, missing profiles, malformed URLs, or unsafe storage.
    pub fn connection(&self, name: Option<&str>) -> Result<ConnectionUrl, ClientError> {
        if let Some(name) = name {
            validate_name(name)?;
        }
        let config = self.required()?;
        let name = name.unwrap_or(&config.default_profile);
        let profile = config.profiles.get(name).ok_or_else(not_found)?;
        ConnectionUrl::parse(&profile.url).map_err(|_| unavailable())
    }

    /// Returns the redacted URL for an existing profile.
    ///
    /// # Errors
    ///
    /// Returns a bounded error for invalid names, missing profiles, malformed URLs, or unsafe storage.
    pub fn redacted(&self, name: &str) -> Result<String, ClientError> {
        Ok(self.connection(Some(name))?.redacted())
    }

    /// Reports whether another stored human profile uses the same authentication identity.
    ///
    /// # Errors
    ///
    /// Returns a bounded error for malformed profiles or unsafe storage.
    pub fn contains_other_human_identity(
        &self,
        excluded_name: &str,
        connection: &ConnectionUrl,
    ) -> Result<bool, ClientError> {
        let config = self.required()?;
        for (name, profile) in &config.profiles {
            if name == excluded_name {
                continue;
            }
            let candidate = ConnectionUrl::parse(&profile.url).map_err(|_| unavailable())?;
            if candidate.client_authentication().is_none()
                && candidate.endpoint() == connection.endpoint()
                && candidate.issuer() == connection.issuer()
                && candidate.client_id() == connection.client_id()
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn required(&self) -> Result<StoredConfig, ClientError> {
        self.load()?.ok_or_else(not_found)
    }

    fn load(&self) -> Result<Option<StoredConfig>, ClientError> {
        let Some(bytes) = read_private(&self.path, MAX_CONFIG_BYTES).map_err(|()| unavailable())?
        else {
            return Ok(None);
        };
        let text = std::str::from_utf8(&bytes).map_err(|_| unavailable())?;
        let config: StoredConfig = toml::from_str(text).map_err(|_| unavailable())?;
        if config.format_version != CONFIG_FORMAT_VERSION
            || config.profiles.is_empty()
            || !config.profiles.contains_key(&config.default_profile)
            || config
                .profiles
                .keys()
                .any(|name| validate_name(name).is_err())
        {
            return Err(unavailable());
        }
        Ok(Some(config))
    }

    fn store(&self, config: &StoredConfig) -> Result<(), ClientError> {
        let encoded = toml::to_string(config).map_err(|_| unavailable())?;
        write_private(&self.path, encoded.as_bytes()).map_err(|()| unavailable())
    }
}

/// Resolves the protected profile configuration path.
///
/// # Errors
///
/// Returns an unavailable error when neither `XDG_CONFIG_HOME` nor `HOME` is set.
pub fn default_profile_path() -> Result<PathBuf, ClientError> {
    if let Some(path) = env::var_os("XDG_CONFIG_HOME").filter(|path| !path.is_empty()) {
        let path = PathBuf::from(path);
        if !path.is_absolute() {
            return Err(unavailable());
        }
        return Ok(path.join("sovereign-config").join("config.toml"));
    }
    env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|home| home.is_absolute())
        .map(|home| home.join(".config/sovereign-config/config.toml"))
        .ok_or_else(unavailable)
}

fn validate_name(name: &str) -> Result<(), ClientError> {
    let valid = (1..=63).contains(&name.len())
        && name
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    if valid {
        Ok(())
    } else {
        Err(ClientError::new(
            ErrorKind::InvalidRequest,
            "profile name is invalid",
        ))
    }
}

fn not_found() -> ClientError {
    ClientError::new(ErrorKind::InvalidRequest, "profile was not found")
}

fn unavailable() -> ClientError {
    ClientError::new(
        ErrorKind::Unavailable,
        "profile configuration is unavailable",
    )
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use sovereign_config_core::ConnectionUrl;

    use super::ProfileStore;

    fn connection(host: &str, credential: Option<&str>) -> ConnectionUrl {
        let credential = credential
            .map(|value| format!("&client_secret={value}"))
            .unwrap_or_default();
        ConnectionUrl::parse(&format!(
            "https://{host}/#v=1&issuer=https%3A%2F%2Fauth.example.test%2Fissuer%2F&client_id=client{credential}"
        ))
        .unwrap()
    }

    fn temporary_path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("sovereign-config-profiles-{}", std::process::id()))
    }

    #[test]
    fn add_update_and_default_persist_private_profiles() {
        let root = temporary_path();
        let _ = fs::remove_dir_all(&root);
        let path = root.join("config.toml");
        let profiles = ProfileStore::new(path.clone());
        profiles
            .add("dev", &connection("dev.example.test", None))
            .unwrap();
        profiles
            .add("prod", &connection("prod.example.test", None))
            .unwrap();
        profiles
            .add(
                "managed",
                &connection("managed.example.test", Some("cGlwZWxpbmU6YXBwLXBhc3N3b3Jk")),
            )
            .unwrap();
        assert!(
            profiles
                .redacted("managed")
                .unwrap()
                .ends_with("client_secret=*")
        );
        assert!(
            !profiles
                .redacted("managed")
                .unwrap()
                .contains("YXBwLXBhc3N3b3Jk")
        );
        assert_eq!(
            profiles.connection(None).unwrap().endpoint(),
            "https://dev.example.test"
        );
        profiles.set_default("prod").unwrap();
        assert_eq!(
            profiles.connection(None).unwrap().endpoint(),
            "https://prod.example.test"
        );
        profiles
            .update("prod", &connection("new.example.test", None))
            .unwrap();
        assert_eq!(
            profiles.connection(Some("prod")).unwrap().endpoint(),
            "https://new.example.test"
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn profiles_reject_duplicates_missing_names_and_permissive_storage() {
        let root = temporary_path().with_extension("invalid");
        let _ = fs::remove_dir_all(&root);
        let path = root.join("config.toml");
        let profiles = ProfileStore::new(path.clone());
        let connection = connection("dev.example.test", None);
        assert!(profiles.add("Bad", &connection).is_err());
        profiles.add("dev", &connection).unwrap();
        assert!(profiles.add("dev", &connection).is_err());
        assert!(profiles.update("missing", &connection).is_err());
        assert!(profiles.set_default("missing").is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(profiles.connection(None).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(profiles.connection(None).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn profiles_reject_symlinks_and_permissive_directories() {
        use std::os::unix::fs::symlink;

        let root = temporary_path().with_extension("unsafe");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        let profiles = ProfileStore::new(root.join("config.toml"));
        let connection = connection("dev.example.test", None);
        assert!(profiles.add("dev", &connection).is_err());

        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let target = root.join("target");
        fs::write(&target, "sentinel").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, root.join("config.toml")).unwrap();
        assert!(profiles.add("dev", &connection).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
