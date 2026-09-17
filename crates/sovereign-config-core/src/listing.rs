//! Timestamps and the listing, subtree and mutation-metadata shapes every
//! client exchanges with the service.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::{ClientError, ConfigPath, ErrorKind, PlainValue, ValueContent};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Timestamp {
    pub seconds: i64,
    pub nanos: i32,
}

impl Timestamp {
    /// Converts a system timestamp into the protocol-neutral representation.
    ///
    /// # Errors
    ///
    /// Returns an error for times before the Unix epoch or values outside the
    /// representable range.
    pub fn from_system_time(value: SystemTime) -> Result<Self, ClientError> {
        let duration = value.duration_since(UNIX_EPOCH).map_err(|_| {
            ClientError::new(ErrorKind::Internal, "service returned an invalid timestamp")
        })?;
        Ok(Self {
            seconds: i64::try_from(duration.as_secs()).map_err(|_| {
                ClientError::new(ErrorKind::Internal, "service returned an invalid timestamp")
            })?,
            nanos: i32::try_from(duration.subsec_nanos()).map_err(|_| invalid_timestamp())?,
        })
    }

    /// Converts this timestamp to [`SystemTime`].
    ///
    /// # Errors
    ///
    /// Returns an error when seconds or nanoseconds are negative or overflow.
    pub fn to_system_time(self) -> Result<SystemTime, ClientError> {
        let seconds = u64::try_from(self.seconds).map_err(|_| invalid_timestamp())?;
        let nanos = u32::try_from(self.nanos).map_err(|_| invalid_timestamp())?;
        if nanos >= 1_000_000_000 {
            return Err(invalid_timestamp());
        }
        UNIX_EPOCH
            .checked_add(Duration::new(seconds, nanos))
            .ok_or_else(invalid_timestamp)
    }
}

fn invalid_timestamp() -> ClientError {
    ClientError::new(ErrorKind::Internal, "service returned an invalid timestamp")
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListedValue {
    pub path: ConfigPath,
    pub value: ValueContent,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    /// Other canonical paths resolving to the same value that the caller may
    /// read. Excludes this value's own `path`.
    pub alias_paths: Vec<ConfigPath>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValueListing {
    pub values: Vec<ListedValue>,
    pub paths: Vec<ConfigPath>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubTreeValue {
    pub path: ConfigPath,
    pub value: ValueContent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubTreeMutationContent {
    Plain(PlainValue),
    PreserveSecret,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubTreeMutationValue {
    pub path: ConfigPath,
    pub value: SubTreeMutationContent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValueSubTree {
    pub values: Vec<SubTreeValue>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PutMetadata {
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeleteMetadata {
    pub deleted_at: Timestamp,
    pub deleted_count: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplaceMetadata {
    pub updated_at: Timestamp,
    pub value_count: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddPathMetadata {
    pub created_at: Timestamp,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValuePaths {
    pub paths: Vec<ConfigPath>,
}
