use std::{
    fs,
    io::{self, Read, Write},
    path::Path,
};

pub(crate) fn read_private(path: &Path, maximum_bytes: usize) -> Result<Option<Vec<u8>>, ()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(()),
    };
    validate_parent(path)?;
    validate_private_file(&metadata)?;
    if metadata.len() > maximum_bytes as u64 {
        return Err(());
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_| ())?;
    let mut value = Vec::with_capacity(capacity);
    fs::File::open(path)
        .map_err(|_| ())?
        .take(maximum_bytes as u64 + 1)
        .read_to_end(&mut value)
        .map_err(|_| ())?;
    if value.len() > maximum_bytes {
        return Err(());
    }
    Ok(Some(value))
}

pub(crate) fn write_private(path: &Path, value: &[u8]) -> Result<(), ()> {
    let directory = path.parent().ok_or(())?;
    ensure_private_directory(directory)?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        validate_private_file(&metadata)?;
    }
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary).map_err(|_| ())?;
    if file
        .write_all(value)
        .and_then(|()| file.sync_all())
        .is_err()
    {
        let _ = fs::remove_file(&temporary);
        return Err(());
    }
    if fs::rename(&temporary, path).is_err() {
        let _ = fs::remove_file(&temporary);
        return Err(());
    }
    fs::File::open(directory)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| ())
}

pub(crate) fn remove_private(path: &Path) -> Result<(), ()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(()),
    };
    validate_parent(path)?;
    validate_private_file(&metadata)?;
    fs::remove_file(path).map_err(|_| ())?;
    fs::File::open(path.parent().ok_or(())?)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| ())
}

fn ensure_private_directory(path: &Path) -> Result<(), ()> {
    if !path.exists() {
        fs::create_dir_all(path).map_err(|_| ())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|_| ())?;
        }
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    validate_private_directory(&metadata)
}

fn validate_parent(path: &Path) -> Result<(), ()> {
    let parent = path.parent().ok_or(())?;
    let metadata = fs::symlink_metadata(parent).map_err(|_| ())?;
    validate_private_directory(&metadata)
}

#[cfg(unix)]
fn validate_private_file(metadata: &fs::Metadata) -> Result<(), ()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if metadata.file_type().is_file()
        && metadata.uid() == rustix::process::geteuid().as_raw()
        && metadata.permissions().mode() & 0o777 == 0o600
    {
        Ok(())
    } else {
        Err(())
    }
}

#[cfg(not(unix))]
fn validate_private_file(metadata: &fs::Metadata) -> Result<(), ()> {
    metadata.file_type().is_file().then_some(()).ok_or(())
}

#[cfg(unix)]
fn validate_private_directory(metadata: &fs::Metadata) -> Result<(), ()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if metadata.file_type().is_dir()
        && metadata.uid() == rustix::process::geteuid().as_raw()
        && metadata.permissions().mode() & 0o777 == 0o700
    {
        Ok(())
    } else {
        Err(())
    }
}

#[cfg(not(unix))]
fn validate_private_directory(metadata: &fs::Metadata) -> Result<(), ()> {
    metadata.file_type().is_dir().then_some(()).ok_or(())
}
