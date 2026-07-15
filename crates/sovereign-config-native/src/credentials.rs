use std::{
    env,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};
use sovereign_config_core::{ClientError, ConnectionUrl, ErrorKind, Secret};

use crate::storage::{read_private, remove_private, write_private};

const MAX_CREDENTIAL_BYTES: usize = 16 * 1024;

pub struct CredentialStore {
    path: PathBuf,
}

impl CredentialStore {
    #[must_use]
    pub fn new(directory: &Path, connection: &ConnectionUrl) -> Self {
        let mut digest = Sha256::new();
        digest.update(b"v1\0");
        digest.update(connection.endpoint().as_bytes());
        digest.update([0]);
        digest.update(connection.issuer().as_bytes());
        digest.update([0]);
        digest.update(connection.client_id().as_bytes());
        let scope = format!("{:x}", digest.finalize());
        Self {
            path: directory.join(scope),
        }
    }

    /// Loads a refresh credential from its private state file.
    ///
    /// # Errors
    ///
    /// Returns an unavailable error when ownership, mode, type, size, or contents are invalid.
    pub fn load(&self) -> Result<Option<Secret>, ClientError> {
        let Some(value) =
            read_private(&self.path, MAX_CREDENTIAL_BYTES).map_err(|()| unavailable())?
        else {
            return Ok(None);
        };
        let value = String::from_utf8(value).map_err(|_| unavailable())?;
        if value.is_empty() || value.bytes().any(|byte| matches!(byte, b'\n' | b'\r')) {
            return Err(unavailable());
        }
        Ok(Some(Secret::new(value)))
    }

    /// Atomically stores a refresh credential in a private state file.
    ///
    /// # Errors
    ///
    /// Returns an unavailable error when the credential cannot be persisted securely.
    pub fn store(&self, credential: &Secret) -> Result<(), ClientError> {
        write_private(&self.path, credential.expose().as_bytes()).map_err(|()| unavailable())
    }

    /// Deletes the selected refresh credential when present.
    ///
    /// # Errors
    ///
    /// Returns an unavailable error when a stored credential cannot be removed securely.
    pub fn delete(&self) -> Result<(), ClientError> {
        remove_private(&self.path).map_err(|()| unavailable())
    }
}

/// Resolves the user-scoped refresh-credential state directory.
///
/// # Errors
///
/// Returns an unavailable error when neither `XDG_STATE_HOME` nor `HOME` is set.
pub fn default_credential_directory() -> Result<PathBuf, ClientError> {
    if let Some(path) = env::var_os("XDG_STATE_HOME").filter(|path| !path.is_empty()) {
        let path = PathBuf::from(path);
        if !path.is_absolute() {
            return Err(unavailable());
        }
        return Ok(path.join("sovereign-config").join("credentials"));
    }
    env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|home| home.is_absolute())
        .map(|home| home.join(".local/state/sovereign-config/credentials"))
        .ok_or_else(unavailable)
}

fn unavailable() -> ClientError {
    ClientError::new(ErrorKind::Unavailable, "credential storage is unavailable")
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use sovereign_config_core::{ConnectionUrl, Secret};

    use super::CredentialStore;

    fn connection(endpoint: &str, root: &str) -> ConnectionUrl {
        ConnectionUrl::parse(&format!(
            "{endpoint}/{root}#v=1&issuer=https%3A%2F%2Fauth.example.test%2Fissuer%2F&client_id=client"
        ))
        .unwrap()
    }

    fn temporary_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("sovereign-config-{name}-{}", std::process::id()))
    }

    #[test]
    fn credentials_are_private_and_bound_to_the_connection_identity() {
        let root = temporary_path("credential-state");
        let _ = fs::remove_dir_all(&root);
        let first = CredentialStore::new(&root, &connection("https://one.example.test", "a"));
        let same_identity =
            CredentialStore::new(&root, &connection("https://one.example.test", "b"));
        let other_endpoint =
            CredentialStore::new(&root, &connection("https://two.example.test", "a"));

        first.store(&Secret::new("refresh-sentinel")).unwrap();
        assert_eq!(
            same_identity.load().unwrap().unwrap().expose(),
            "refresh-sentinel"
        );
        assert!(other_endpoint.load().unwrap().is_none());

        let [path] = fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        same_identity.delete().unwrap();
        assert!(first.load().unwrap().is_none());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn credentials_reject_permissive_files() {
        let root = temporary_path("credential-permissions");
        let _ = fs::remove_dir_all(&root);
        let store = CredentialStore::new(&root, &connection("https://one.example.test", ""));
        store.store(&Secret::new("refresh-sentinel")).unwrap();
        let path = fs::read_dir(&root).unwrap().next().unwrap().unwrap().path();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(store.load().is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(store.load().is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
