use std::{
    env, fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use sovereign_config_core::{ClientError, ErrorKind, Secret};

const SERVICE: &str = "sovereign-config";
const ACCOUNT: &str = "refresh-token";

pub struct CredentialStore {
    entry: keyring::Entry,
    fallback: PathBuf,
}

impl CredentialStore {
    /// Creates an OS credential-store handle with the supplied file fallback.
    ///
    /// # Errors
    ///
    /// Returns an unavailable error when no credential entry can be constructed.
    pub fn new(fallback: PathBuf) -> Result<Self, ClientError> {
        let entry = keyring::Entry::new(SERVICE, ACCOUNT).map_err(|_| unavailable())?;
        Ok(Self { entry, fallback })
    }

    /// Loads a refresh credential from the OS store or private fallback file.
    ///
    /// # Errors
    ///
    /// Returns an unavailable error when fallback ownership, mode, or contents are invalid.
    pub fn load(&self) -> Result<Option<Secret>, ClientError> {
        match self.entry.get_password() {
            Ok(value) => Ok(Some(Secret::new(value))),
            Err(_) => read_fallback(&self.fallback),
        }
    }

    /// Stores a refresh credential in the OS store or private fallback file.
    ///
    /// # Errors
    ///
    /// Returns an unavailable error when neither storage mechanism can persist it.
    pub fn store(&self, credential: &Secret) -> Result<(), ClientError> {
        if self.entry.set_password(credential.expose()).is_ok() {
            if self.fallback.exists() {
                remove_fallback(&self.fallback)?;
            }
            return Ok(());
        }
        write_fallback(&self.fallback, credential)
    }

    /// Deletes the refresh credential from every configured storage mechanism.
    ///
    /// # Errors
    ///
    /// Returns an unavailable error when a stored credential cannot be removed.
    pub fn delete(&self) -> Result<(), ClientError> {
        match self.entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => {}
            Err(_) if !self.fallback.exists() => return Err(unavailable()),
            Err(_) => {}
        }
        if self.fallback.exists() {
            remove_fallback(&self.fallback)?;
        }
        Ok(())
    }
}

/// Resolves the user-scoped refresh credential fallback path.
///
/// # Errors
///
/// Returns an unavailable error when neither `XDG_CONFIG_HOME` nor `HOME` is set.
pub fn default_credential_path() -> Result<PathBuf, ClientError> {
    if let Some(path) = env::var_os("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(path)
            .join("sovereign-config")
            .join("refresh-token"));
    }
    env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".config/sovereign-config/refresh-token"))
        .ok_or_else(unavailable)
}

fn read_fallback(path: &Path) -> Result<Option<Secret>, ClientError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_metadata(&metadata)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(unavailable()),
    }
    let value = fs::read_to_string(path).map_err(|_| unavailable())?;
    if value.is_empty() || value.bytes().any(|byte| byte == b'\n' || byte == b'\r') {
        return Err(unavailable());
    }
    Ok(Some(Secret::new(value)))
}

#[cfg(unix)]
fn validate_metadata(metadata: &fs::Metadata) -> Result<(), ClientError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let owned = metadata.uid() == rustix::process::geteuid().as_raw();
    let private = metadata.permissions().mode() & 0o777 == 0o600;
    if !metadata.file_type().is_file() || !owned || !private {
        return Err(unavailable());
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_metadata(metadata: &fs::Metadata) -> Result<(), ClientError> {
    if !metadata.file_type().is_file() {
        return Err(unavailable());
    }
    Ok(())
}

fn write_fallback(path: &Path, credential: &Secret) -> Result<(), ClientError> {
    let parent = path.parent().ok_or_else(unavailable)?;
    fs::create_dir_all(parent).map_err(|_| unavailable())?;
    secure_directory(parent)?;
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary).map_err(|_| unavailable())?;
    if file
        .write_all(credential.expose().as_bytes())
        .and_then(|()| file.sync_all())
        .is_err()
    {
        let _ = fs::remove_file(&temporary);
        return Err(unavailable());
    }
    if fs::rename(&temporary, path).is_err() {
        let _ = fs::remove_file(&temporary);
        return Err(unavailable());
    }
    Ok(())
}

#[cfg(unix)]
fn secure_directory(path: &Path) -> Result<(), ClientError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = fs::symlink_metadata(path).map_err(|_| unavailable())?;
    if !metadata.file_type().is_dir() || metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(unavailable());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|_| unavailable())
}

#[cfg(not(unix))]
fn secure_directory(_: &Path) -> Result<(), ClientError> {
    Ok(())
}

fn remove_fallback(path: &Path) -> Result<(), ClientError> {
    fs::remove_file(path).map_err(|_| unavailable())
}

fn unavailable() -> ClientError {
    ClientError::new(ErrorKind::Unavailable, "credential storage is unavailable")
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use sovereign_config_core::Secret;

    use super::{read_fallback, write_fallback};

    fn temporary_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("sovereign-config-{name}-{}", std::process::id()))
    }

    #[test]
    fn fallback_is_written_with_private_mode_and_read_without_formatting() {
        let root = temporary_path("credentials");
        let path = root.join("refresh-token");
        let _ = fs::remove_dir_all(&root);
        write_fallback(&path, &Secret::new("refresh-sentinel")).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            read_fallback(&path).unwrap().unwrap().expose(),
            "refresh-sentinel"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn fallback_rejects_permissive_files() {
        let root = temporary_path("permissions");
        let path = root.join("refresh-token");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(&path, "refresh-sentinel").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_fallback(&path).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
