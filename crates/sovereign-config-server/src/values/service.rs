//! The `Configuration` service, in no protocol version's terms. Each operation
//! authorizes, then composes named validation (`authz`, `subtree`, `paths`),
//! storage (`store`) and masking (`content`) steps; no SQL is written here.
//!
//! Inputs arrive unvalidated — a raw path string, an absent content as `None`
//! — because validating them is this layer's job, in an order that is part of
//! the behaviour every protocol version promises. Nothing here may import the
//! proto crate: a version is a shim over this file (`v3`), never a branch in it.

use std::{collections::BTreeMap, sync::Arc, time::SystemTime};

use sovereign_config_core::{
    AddPathMetadata, ConfigPath, DeleteMetadata, ListedValue, PutMetadata, ReplaceMetadata,
    RevealedSecret, SubTreeValue, ValueListing, ValuePaths, ValueSubTree,
};
use sqlx::{PgPool, Postgres, Transaction};
use time::OffsetDateTime;
use tonic::Status;
use tracing::error;

use super::authz::authorize;
use super::content::masked_content;
use super::paths::{add_parent_paths, parent_path};
use super::store::{
    self, MutationRow, content_ids, insert_content, insert_path, lock_mutation_path, path_collides,
    prune_orphan_contents, reserve_content_id,
};
use super::subtree::{self, NormalizedSubtree, SubTreeEntry, SubTreeEntryContent};
use super::{PLAIN, SECRET};
use crate::auth::Permission;
use crate::encryption::{DecryptError, ValueCipher};
use crate::rpc::{CallContext, storage_unavailable, to_timestamp};

#[derive(Clone)]
pub(crate) struct ConfigurationService {
    database: PgPool,
    cipher: Arc<ValueCipher>,
}

/// What a caller asked `put_value` to store, before any of it is validated.
pub(super) enum PutContent<'a> {
    Plain(&'a str),
    Secret(&'a str),
}

/// A subtree's plain writes resolved against what is stored: content ids that
/// already exist mapped to their single new value, and paths with no stored
/// value yet.
///
/// `shared` must stay ordered by content id: iterating it ascending is what
/// gives concurrent replacements a common row-lock order. Values
/// cross-aliased between disjoint subtrees (X at /a/1 and /b/2, Y at /a/2 and
/// /b/1) would otherwise lock X-then-Y in one transaction and Y-then-X in the
/// other and deadlock, since their path locks are disjoint. Do not swap this
/// for a `HashMap`.
struct ResolvedWrites<'a> {
    shared: BTreeMap<i64, &'a String>,
    fresh: Vec<(&'a String, &'a String)>,
}

impl ConfigurationService {
    pub(crate) fn new(database: PgPool, cipher: Arc<ValueCipher>) -> Self {
        Self { database, cipher }
    }

    /// Produces the representation to store for a value of `classification`.
    ///
    /// Secrets become an AEAD envelope bound to the content row that will hold
    /// them; plain values are stored verbatim, because masking them would only
    /// obstruct the operators and tooling that are meant to read them.
    #[expect(
        clippy::result_large_err,
        reason = "tonic::Status is the crate's RPC error type and is returned by value"
    )]
    fn stored_representation(
        &self,
        content_id: i64,
        classification: &str,
        value: &str,
    ) -> Result<String, Status> {
        if classification == SECRET {
            self.cipher
                .encrypt(content_id, classification, value)
                .map_err(|_| encryption_failed())
        } else {
            Ok(value.to_owned())
        }
    }

    /// Writes `value` at an existing content row, refusing a reclassification
    /// that would change how the value is exposed at its other paths.
    async fn overwrite_existing(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        existing: store::PathContentClassRow,
        value: &str,
        classification: &str,
        now: OffsetDateTime,
    ) -> Result<MutationRow, Status> {
        // Classification belongs to the stored value, so it cannot differ
        // between aliases. Rather than let a write through one path silently
        // change how the value is exposed at every other path — including
        // paths the caller may not be able to see — refuse the change while
        // more than one path resolves to it. Rotating a value in place, and
        // changing classification while a single path remains, both still
        // work.
        if existing.path_count > 1 && existing.classification != classification {
            return Err(Status::invalid_argument(
                "configuration value has multiple paths and cannot change classification",
            ));
        }
        let content_id = existing.content_id;
        // Reclassification needs no conversion of what is already stored:
        // every classification change arrives with a fresh value from the
        // caller, so `plain -> secret` seals the new value and
        // `secret -> plain` writes the new plaintext.
        let stored = self.stored_representation(content_id, classification, value)?;
        // Writing through any path updates the shared content, so every
        // other path aliasing it observes the new value.
        store::update_content(transaction, content_id, &stored, classification, now).await
    }

    /// Creates a new value at `path`, which must not nest with any stored path.
    async fn create_value(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        path: &ConfigPath,
        value: &str,
        classification: &str,
        now: OffsetDateTime,
    ) -> Result<MutationRow, Status> {
        if path_collides(transaction, &path.fold()).await? {
            return Err(Status::invalid_argument(
                "configuration value collides with an existing value",
            ));
        }
        let content_id = reserve_content_id(transaction).await?;
        let stored = self.stored_representation(content_id, classification, value)?;
        let content = insert_content(transaction, content_id, &stored, classification, now).await?;
        // The path exactly as written establishes its display case.
        insert_path(transaction, path.as_str(), content.id, now).await?;
        Ok(MutationRow {
            created_at: content.created_at,
            updated_at: content.updated_at,
        })
    }
}

impl ConfigurationService {
    pub(super) async fn list_values(
        &self,
        context: &CallContext<'_>,
        path: &str,
    ) -> Result<ValueListing, Status> {
        let selected = ConfigPath::parse_selection(path)
            .map_err(|_| Status::invalid_argument("configuration path is invalid"))?;
        let principal = context.principal()?;
        let candidates = store::path_candidates(&self.database).await?;

        // Group every readable path by the content it resolves to so a listed
        // value can advertise its other authorized aliases, even ones outside
        // the selected namespace. Candidates arrive sorted, so each group stays
        // sorted too. Each pair is (fold key, display form): the fold key is
        // what excludes a listing's own path from its alias list, the display
        // form is what the alias is actually reported as.
        let mut content_paths: BTreeMap<i64, Vec<(String, String)>> = BTreeMap::new();
        // Ancestor namespace paths, keyed by fold: each maps to the earliest
        // `created_at` among candidates sharing that ancestor and the display
        // form that row established it with — the "first-created row's case"
        // decision recorded on card #294.
        let mut paths: BTreeMap<String, (OffsetDateTime, String)> = BTreeMap::new();
        let mut direct = Vec::new();
        for row in candidates {
            let path = ConfigPath::parse(&row.lowercase_path).map_err(|_| storage_unavailable())?;
            if !principal.allows(&path, Permission::Read) {
                continue;
            }
            content_paths
                .entry(row.content_id)
                .or_default()
                .push((row.lowercase_path.clone(), row.path.clone()));
            add_parent_paths(&mut paths, &row.lowercase_path, &row.path, row.created_at);
            if parent_path(&row.lowercase_path) == selected.fold() {
                direct.push(row.lowercase_path);
            }
        }

        let mut values = Vec::new();
        if !direct.is_empty() {
            for row in store::listed_values(&self.database, &direct).await? {
                let value = masked_content(row.value, &row.classification)
                    .ok_or_else(storage_unavailable)?;
                let mut alias_paths = Vec::new();
                for (fold, display) in content_paths.get(&row.content_id).into_iter().flatten() {
                    if fold != &row.lowercase_path {
                        alias_paths.push(stored_path(display)?);
                    }
                }
                values.push(ListedValue {
                    path: stored_path(&row.path)?,
                    value,
                    created_at: to_timestamp(row.created_at)?,
                    updated_at: to_timestamp(row.updated_at)?,
                    alias_paths,
                });
            }
        }

        let mut namespaces = Vec::with_capacity(paths.len());
        for (_, display) in paths.into_values() {
            // Ancestors include the tree root, which is a selection rather
            // than an operation path.
            namespaces
                .push(ConfigPath::parse_selection(display).map_err(|_| storage_unavailable())?);
        }
        Ok(ValueListing {
            values,
            paths: namespaces,
        })
    }

    pub(super) async fn get_sub_tree(
        &self,
        context: &CallContext<'_>,
        path: &str,
    ) -> Result<ValueSubTree, Status> {
        let path = authorize(context, path, &[Permission::Read], true)?;
        let rows = store::sub_tree_rows(&self.database, &path.fold()).await?;
        let mut values = Vec::with_capacity(rows.len());
        for row in rows {
            let value =
                masked_content(row.value, &row.classification).ok_or_else(storage_unavailable)?;
            values.push(SubTreeValue {
                path: stored_path(&row.path)?,
                value,
            });
        }
        Ok(ValueSubTree { values })
    }

    pub(super) async fn put_value(
        &self,
        context: &CallContext<'_>,
        path: &str,
        written: Option<PutContent<'_>>,
    ) -> Result<PutMetadata, Status> {
        let path = authorize(context, path, &[Permission::Write], false)?;
        let (value, classification) = match written {
            Some(PutContent::Plain(value)) => (value, PLAIN),
            Some(PutContent::Secret(value)) => (value, SECRET),
            None => return Err(Status::invalid_argument("configuration value is invalid")),
        };
        if value.contains('\0') {
            return Err(Status::invalid_argument(
                "configuration value contains an invalid character",
            ));
        }
        let mut transaction = store::begin(&self.database).await?;
        lock_mutation_path(&mut transaction, &path).await?;
        let now = OffsetDateTime::from(SystemTime::now());
        let row = match store::path_content_class(&mut transaction, &path.fold()).await? {
            Some(existing) => {
                self.overwrite_existing(&mut transaction, existing, value, classification, now)
                    .await?
            }
            None => {
                self.create_value(&mut transaction, &path, value, classification, now)
                    .await?
            }
        };
        store::commit(transaction).await?;

        Ok(PutMetadata {
            created_at: to_timestamp(row.created_at)?,
            updated_at: to_timestamp(row.updated_at)?,
        })
    }

    pub(super) async fn replace_sub_tree(
        &self,
        context: &CallContext<'_>,
        path: &str,
        values: Vec<SubTreeEntry>,
    ) -> Result<ReplaceMetadata, Status> {
        let path = authorize(
            context,
            path,
            &[Permission::Write, Permission::Manage],
            true,
        )?;
        let NormalizedSubtree {
            mut values,
            displays,
        } = subtree::normalize(&path, values)?;

        let mut transaction = store::begin(&self.database).await?;
        lock_mutation_path(&mut transaction, &path).await?;
        let secret_paths = store::secret_paths_touching(&mut transaction, &path.fold()).await?;
        subtree::resolve_preserve_markers(&mut values, &secret_paths);
        let plain_paths = subtree::plain_paths(&values, &secret_paths)?;
        let now = OffsetDateTime::from(SystemTime::now());
        let cleared =
            store::delete_plain_paths_except(&mut transaction, &path.fold(), &plain_paths).await?;
        prune_orphan_contents(&mut transaction, &content_ids(&cleared)).await?;
        let writes = resolve_plain_writes(&mut transaction, &values).await?;
        // Nothing below encrypts, because subtree replacement can neither read
        // nor create a secret: it only ever writes `plain`, only ever deletes
        // `plain`, and the validation above rejects a plain value colliding
        // with a secret path. Every content row reached here is therefore
        // already plaintext and stays that way.
        for (content_id, content) in &writes.shared {
            store::update_plain_content(&mut transaction, *content_id, content, now).await?;
        }
        for (path, content) in writes.fresh {
            let content_id = reserve_content_id(&mut transaction).await?;
            let inserted =
                insert_content(&mut transaction, content_id, content, PLAIN, now).await?;
            let display = displays.get(path).map_or(path.as_str(), String::as_str);
            insert_path(&mut transaction, display, inserted.id, now).await?;
        }
        store::commit(transaction).await?;
        Ok(ReplaceMetadata {
            updated_at: to_timestamp(now)?,
            value_count: u64::try_from(values.len()).map_err(|_| storage_unavailable())?,
        })
    }

    pub(super) async fn delete_values(
        &self,
        context: &CallContext<'_>,
        path: &str,
        recurse: bool,
    ) -> Result<DeleteMetadata, Status> {
        let path = authorize(context, path, &[Permission::Write], recurse)?;
        let mut transaction = store::begin(&self.database).await?;
        lock_mutation_path(&mut transaction, &path).await?;
        let deleted = store::delete_paths(&mut transaction, &path.fold(), recurse).await?;
        if deleted.is_empty() {
            return Err(Status::not_found("configuration value not found"));
        }
        // A path may have been the sole alias of its value; drop any content
        // left with no remaining paths so deleting the last path removes the
        // value for good, while shared values survive.
        prune_orphan_contents(&mut transaction, &content_ids(&deleted)).await?;
        store::commit(transaction).await?;
        let deleted_at = OffsetDateTime::from(SystemTime::now());
        Ok(DeleteMetadata {
            deleted_at: to_timestamp(deleted_at)?,
            deleted_count: u64::try_from(deleted.len()).map_err(|_| storage_unavailable())?,
        })
    }

    pub(super) async fn reveal_secret(
        &self,
        context: &CallContext<'_>,
        path: &str,
    ) -> Result<RevealedSecret, Status> {
        let path = authorize(context, path, &[Permission::Read], false)?;
        let row = store::revealed_row(&self.database, &path.fold())
            .await?
            .ok_or_else(|| Status::not_found("configuration value not found"))?;
        if row.classification != SECRET {
            return Err(Status::invalid_argument(
                "configuration value is not a secret",
            ));
        }
        // This is the only RPC that returns a secret in the clear, so it is the
        // only one that decrypts. A failure here means the key is wrong or the
        // stored envelope was tampered with; returning what is stored would
        // hand the caller ciphertext labelled as their secret.
        let value = self
            .cipher
            .decrypt(row.content_id, &row.classification, &row.value)
            .map_err(|error| decryption_failed(row.content_id, &error))?;
        Ok(RevealedSecret::new(value))
    }

    pub(super) async fn add_value_path(
        &self,
        context: &CallContext<'_>,
        source_path: &str,
        new_path: &str,
    ) -> Result<AddPathMetadata, Status> {
        let principal = context.principal()?;
        let source = ConfigPath::parse_operation(source_path)
            .map_err(|_| Status::invalid_argument("configuration path is invalid"))?;
        let new_path = ConfigPath::parse_operation(new_path)
            .map_err(|_| Status::invalid_argument("configuration path is invalid"))?;
        // Resolving the value and exposing it elsewhere is a write on both
        // paths; reading the source is required to name the value at all.
        if !principal.allows(&source, Permission::Read)
            || !principal.allows(&source, Permission::Write)
            || !principal.allows(&new_path, Permission::Write)
        {
            return Err(Status::permission_denied(
                "configuration operation is not permitted",
            ));
        }
        // `==`/`<=` on `ConfigPath` compare the fold, so this rejects a
        // fold-equal alias (however it's cased) and picks a lock order that
        // agrees with what `lock_mutation_path` actually locks.
        if source == new_path {
            return Err(Status::invalid_argument(
                "configuration value already has that path",
            ));
        }

        let mut transaction = store::begin(&self.database).await?;
        // Lock both mutation hierarchies in a canonical order so concurrent
        // aliasing in either direction cannot deadlock.
        let (first, second) = if source <= new_path {
            (&source, &new_path)
        } else {
            (&new_path, &source)
        };
        lock_mutation_path(&mut transaction, first).await?;
        lock_mutation_path(&mut transaction, second).await?;

        let content_id = store::content_id_at(&mut *transaction, &source.fold())
            .await?
            .ok_or_else(|| Status::not_found("configuration value not found"))?;
        if store::path_is_occupied(&mut transaction, &new_path.fold()).await? {
            return Err(Status::already_exists("configuration path already exists"));
        }
        if path_collides(&mut transaction, &new_path.fold()).await? {
            return Err(Status::invalid_argument(
                "configuration value collides with an existing value",
            ));
        }
        let now = OffsetDateTime::from(SystemTime::now());
        // The path exactly as written establishes this alias's display case.
        insert_path(&mut transaction, new_path.as_str(), content_id, now).await?;
        store::commit(transaction).await?;
        Ok(AddPathMetadata {
            created_at: to_timestamp(now)?,
        })
    }

    pub(super) async fn list_value_paths(
        &self,
        context: &CallContext<'_>,
        path: &str,
    ) -> Result<ValuePaths, Status> {
        let path = authorize(context, path, &[Permission::Read], false)?;
        let principal = context.principal()?;
        let content_id = store::content_id_at(&self.database, &path.fold())
            .await?
            .ok_or_else(|| Status::not_found("configuration value not found"))?;
        // Hide paths the caller cannot read: one value may be reachable through
        // paths outside the caller's grants.
        let mut paths = Vec::new();
        for row in store::paths_of_content(&self.database, content_id).await? {
            let candidate =
                ConfigPath::parse(&row.lowercase_path).map_err(|_| storage_unavailable())?;
            if principal.allows(&candidate, Permission::Read) {
                paths.push(stored_path(&row.path)?);
            }
        }
        Ok(ValuePaths { paths })
    }
}

/// A stored display path as the version-free type every response carries.
///
/// The `configuration_paths_path_check` constraint admits exactly the grammar
/// [`ConfigPath::parse_operation`] accepts, so this cannot fail for a row the
/// database holds: it satisfies the type, it does not validate. `as_str()`
/// gives back the stored bytes unchanged, which is what a shim emits.
#[expect(
    clippy::result_large_err,
    reason = "tonic::Status is the crate's RPC error type and is returned by value"
)]
fn stored_path(path: &str) -> Result<ConfigPath, Status> {
    ConfigPath::parse_operation(path).map_err(|_| storage_unavailable())
}

/// Resolves each plain write to the content it lands on, so a value shared by
/// several paths in the subtree is written exactly once: applying one update
/// per path would let the last path in sort order overwrite the others,
/// silently discarding an edit while still reporting success.
async fn resolve_plain_writes<'a>(
    transaction: &mut Transaction<'_, Postgres>,
    values: &'a [SubTreeEntry],
) -> Result<ResolvedWrites<'a>, Status> {
    let mut writes = ResolvedWrites {
        shared: BTreeMap::new(),
        fresh: Vec::new(),
    };
    for value in values {
        let Some(SubTreeEntryContent::PlainValue(content)) = value.content.as_ref() else {
            continue;
        };
        match store::content_id_at(&mut **transaction, &value.path).await? {
            Some(content_id) => match writes.shared.get(&content_id) {
                // Aliases of one value must agree; a genuine conflict is
                // ambiguous, so reject it rather than pick a winner.
                Some(assigned) if *assigned != content => {
                    return Err(Status::invalid_argument(
                        "configuration subtree assigns conflicting values to one stored value",
                    ));
                }
                Some(_) => {}
                None => {
                    writes.shared.insert(content_id, content);
                }
            },
            None => writes.fresh.push((&value.path, content)),
        }
    }
    Ok(writes)
}

fn encryption_failed() -> Status {
    Status::internal("configuration value could not be encrypted")
}

/// Reports a value that could not be decrypted.
///
/// The log records which row failed and why, but never the stored bytes: an
/// envelope that fails to authenticate may still be somebody's ciphertext, and
/// one that turns out to be legacy plaintext is a secret in the clear.
fn decryption_failed(content_id: i64, error: &DecryptError) -> Status {
    error!(content_id, reason = %error, "configuration value could not be decrypted");
    Status::internal("configuration value could not be decrypted")
}
