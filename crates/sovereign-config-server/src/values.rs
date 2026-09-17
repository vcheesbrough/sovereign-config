use std::{collections::BTreeSet, sync::Arc, time::SystemTime};

use std::collections::BTreeMap;

use anyhow::Context as _;
use sovereign_config_core::{ConfigPath, MASKED_SECRET_TEXT};
use sovereign_config_proto::sovereign::config::v3::{
    AddValuePathRequest, AddValuePathResponse, DeleteValuesRequest, DeleteValuesResponse,
    GetSubTreeRequest, GetSubTreeResponse, ListValuePathsRequest, ListValuePathsResponse,
    ListValuesRequest, ListValuesResponse, ListedValue, MaskedSecret, PutValueRequest,
    PutValueResponse, ReplaceSubTreeRequest, ReplaceSubTreeResponse, RevealSecretRequest,
    RevealSecretResponse, SubTreeValue, ValueClassification, configuration_server::Configuration,
    listed_value, put_value_request, sub_tree_mutation_value, sub_tree_value,
};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use time::OffsetDateTime;
use tonic::{Request, Response, Status};
use tracing::{error, info};

use crate::auth::Permission;
use crate::encryption::{DecryptError, ValueCipher, is_envelope};
use crate::rpc::{principal, storage_unavailable, to_proto_timestamp};

/// Classification of a value the caller may read back in the clear.
const PLAIN: &str = "plain";
/// Classification of a value stored as ciphertext and masked on read.
const SECRET: &str = "secret";

#[derive(Clone)]
pub(crate) struct ConfigurationService {
    database: PgPool,
    cipher: Arc<ValueCipher>,
}

#[derive(FromRow)]
struct ListedValueRow {
    path: String,
    lowercase_path: String,
    content_id: i64,
    value: String,
    classification: String,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

#[derive(FromRow)]
struct SubTreeRow {
    path: String,
    value: String,
    classification: String,
}

/// A row's fold key, selected under the name `path` — the caller already
/// treats the result as an opaque fold-key string (a collision probe, a
/// secret-path set), never as anything meant for display.
#[derive(FromRow)]
struct PathRow {
    path: String,
}

#[derive(FromRow)]
struct PathWithFoldRow {
    path: String,
    lowercase_path: String,
}

#[derive(FromRow)]
struct RevealedRow {
    content_id: i64,
    value: String,
    classification: String,
}

#[derive(FromRow)]
struct StoredSecretRow {
    id: i64,
    value: String,
}

#[derive(FromRow)]
struct PathContentRow {
    path: String,
    lowercase_path: String,
    content_id: i64,
    created_at: OffsetDateTime,
}

#[derive(FromRow)]
struct PathContentClassRow {
    content_id: i64,
    classification: String,
    path_count: i64,
}

#[derive(FromRow)]
struct DeletedPathRow {
    content_id: i64,
}

#[derive(FromRow)]
struct MutationRow {
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

#[derive(FromRow)]
struct ContentRow {
    id: i64,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
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
}

#[tonic::async_trait]
impl Configuration for ConfigurationService {
    async fn list_values(
        &self,
        request: Request<ListValuesRequest>,
    ) -> Result<Response<ListValuesResponse>, Status> {
        let selected = ConfigPath::parse_selection(&request.get_ref().path)
            .map_err(|_| Status::invalid_argument("configuration path is invalid"))?;
        let principal = principal(&request)?;
        let candidates = sqlx::query_as::<_, PathContentRow>(
            "SELECT path, lowercase_path, content_id, created_at FROM configuration_paths ORDER BY lowercase_path",
        )
        .fetch_all(&self.database)
        .await
        .map_err(|_| storage_unavailable())?;

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
            let rows = sqlx::query_as::<_, ListedValueRow>(
                r"
                SELECT p.path, p.lowercase_path, p.content_id, c.value, c.classification, c.created_at, c.updated_at
                FROM configuration_paths p
                JOIN configuration_value_contents c ON c.id = p.content_id
                WHERE p.lowercase_path = ANY($1::TEXT[])
                ORDER BY p.lowercase_path
                ",
            )
            .bind(&direct)
            .fetch_all(&self.database)
            .await
            .map_err(|_| storage_unavailable())?;
            for row in rows {
                let (classification, content) = listed_content(row.value, &row.classification)
                    .ok_or_else(storage_unavailable)?;
                let alias_paths = content_paths
                    .get(&row.content_id)
                    .map(|siblings| {
                        siblings
                            .iter()
                            .filter(|(fold, _)| fold != &row.lowercase_path)
                            .map(|(_, display)| display.clone())
                            .collect()
                    })
                    .unwrap_or_default();
                values.push(ListedValue {
                    path: row.path,
                    created_at: Some(to_proto_timestamp(row.created_at)?),
                    updated_at: Some(to_proto_timestamp(row.updated_at)?),
                    classification,
                    content: Some(content),
                    alias_paths,
                });
            }
        }

        Ok(Response::new(ListValuesResponse {
            values,
            paths: paths.into_values().map(|(_, display)| display).collect(),
        }))
    }

    async fn get_sub_tree(
        &self,
        request: Request<GetSubTreeRequest>,
    ) -> Result<Response<GetSubTreeResponse>, Status> {
        let path = authorize(&request, &[Permission::Read], true)?;
        // Subtree matching uses starts_with, never LIKE: `_` is a legal path
        // segment character (since 2.15.0) and a single-character LIKE
        // wildcard, so `LIKE '/a/b_c/%'` would also match the sibling subtree
        // `/a/bXc/` that authorize() never checked. This applies to every
        // prefix match in this file. Do not "optimize" it back to LIKE for the
        // btree prefix scan.
        let rows = sqlx::query_as::<_, SubTreeRow>(
            r"
            SELECT p.path, c.value, c.classification
            FROM configuration_paths p
            JOIN configuration_value_contents c ON c.id = p.content_id
            WHERE $1 = '/' OR p.lowercase_path = $1 OR starts_with(p.lowercase_path, $1 || '/')
            ORDER BY p.lowercase_path
            ",
        )
        .bind(path.fold())
        .fetch_all(&self.database)
        .await
        .map_err(|_| storage_unavailable())?;

        let mut values = Vec::with_capacity(rows.len());
        for row in rows {
            let (classification, content) =
                subtree_content(row.value, &row.classification).ok_or_else(storage_unavailable)?;
            values.push(SubTreeValue {
                path: row.path,
                classification,
                content: Some(content),
            });
        }
        Ok(Response::new(GetSubTreeResponse { values }))
    }

    async fn put_value(
        &self,
        request: Request<PutValueRequest>,
    ) -> Result<Response<PutValueResponse>, Status> {
        let path = authorize(&request, &[Permission::Write], false)?;
        let (value, classification) = match request.get_ref().content.as_ref() {
            Some(put_value_request::Content::PlainValue(value)) => (value, PLAIN),
            Some(put_value_request::Content::SecretValue(value)) => (value, SECRET),
            None => return Err(Status::invalid_argument("configuration value is invalid")),
        };
        if value.contains('\0') {
            return Err(Status::invalid_argument(
                "configuration value contains an invalid character",
            ));
        }
        let mut transaction = self
            .database
            .begin()
            .await
            .map_err(|_| storage_unavailable())?;
        lock_mutation_path(&mut transaction, &path).await?;
        let now = OffsetDateTime::from(SystemTime::now());
        let existing = sqlx::query_as::<_, PathContentClassRow>(
            r"
            SELECT
                p.content_id,
                c.classification,
                (
                    SELECT COUNT(*)
                    FROM configuration_paths siblings
                    WHERE siblings.content_id = p.content_id
                ) AS path_count
            FROM configuration_paths p
            JOIN configuration_value_contents c ON c.id = p.content_id
            WHERE p.lowercase_path = $1
            ",
        )
        .bind(path.fold())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| storage_unavailable())?;
        let row = if let Some(existing) = existing {
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
            sqlx::query_as::<_, MutationRow>(
                r"
                UPDATE configuration_value_contents
                SET value = $2, classification = $3, updated_at = $4
                WHERE id = $1
                RETURNING created_at, updated_at
                ",
            )
            .bind(content_id)
            .bind(&stored)
            .bind(classification)
            .bind(now)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| storage_unavailable())?
        } else {
            if path_collides(&mut transaction, &path.fold()).await? {
                return Err(Status::invalid_argument(
                    "configuration value collides with an existing value",
                ));
            }
            let content_id = reserve_content_id(&mut transaction).await?;
            let stored = self.stored_representation(content_id, classification, value)?;
            let content =
                insert_content(&mut transaction, content_id, &stored, classification, now).await?;
            // The path exactly as written establishes its display case.
            insert_path(&mut transaction, path.as_str(), content.id, now).await?;
            MutationRow {
                created_at: content.created_at,
                updated_at: content.updated_at,
            }
        };
        transaction
            .commit()
            .await
            .map_err(|_| storage_unavailable())?;

        Ok(Response::new(PutValueResponse {
            created_at: Some(to_proto_timestamp(row.created_at)?),
            updated_at: Some(to_proto_timestamp(row.updated_at)?),
        }))
    }

    async fn replace_sub_tree(
        &self,
        request: Request<ReplaceSubTreeRequest>,
    ) -> Result<Response<ReplaceSubTreeResponse>, Status> {
        let path = authorize(&request, &[Permission::Write, Permission::Manage], true)?;
        let mut values = request.get_ref().values.clone();
        // Parse and fold every path up front, before sorting or the
        // ancestor-collision walk below: both depend on paths comparing and
        // ordering by fold key, not by raw (possibly mixed-case) bytes. Each
        // value's `path` field is normalized in place to its fold form here,
        // so every line below this loop keeps the same fold-only invariant it
        // always has; `displays` is consulted only where a path is written.
        let mut displays: BTreeMap<String, String> = BTreeMap::new();
        for value in &mut values {
            let value_path = ConfigPath::parse_operation(&value.path)
                .map_err(|_| Status::invalid_argument("configuration subtree is invalid"))?;
            if !value_path.is_at_or_below(&path) {
                return Err(Status::invalid_argument("configuration subtree is invalid"));
            }
            match value.content.as_ref() {
                Some(sub_tree_mutation_value::Content::PlainValue(content))
                    if !content.contains('\0') => {}
                Some(sub_tree_mutation_value::Content::PreserveSecret(_)) => {}
                _ => return Err(Status::invalid_argument("configuration subtree is invalid")),
            }
            let fold = value_path.fold();
            if fold != value_path.as_str() {
                displays.insert(fold.clone(), value_path.as_str().to_owned());
            }
            value.path = fold;
        }
        values.sort_by(|first, second| first.path.cmp(&second.path));
        let mut accepted_paths = BTreeSet::new();
        for value in &values {
            let mut ancestor = value.path.as_str();
            let mut has_stored_ancestor = false;
            while let Some((parent, _)) = ancestor.rsplit_once('/') {
                if parent.is_empty() {
                    break;
                }
                if accepted_paths.contains(parent) {
                    has_stored_ancestor = true;
                    break;
                }
                ancestor = parent;
            }
            if has_stored_ancestor || !accepted_paths.insert(value.path.as_str()) {
                return Err(Status::invalid_argument("configuration subtree is invalid"));
            }
        }

        let mut transaction = self
            .database
            .begin()
            .await
            .map_err(|_| storage_unavailable())?;
        lock_mutation_path(&mut transaction, &path).await?;
        let secret_rows = sqlx::query_as::<_, PathRow>(
            r"
            SELECT p.lowercase_path AS path
            FROM configuration_paths p
            JOIN configuration_value_contents c ON c.id = p.content_id
            WHERE c.classification = 'secret'
              AND (
                    $1 = '/'
                    OR p.lowercase_path = $1
                    OR starts_with(p.lowercase_path, $1 || '/')
                    OR starts_with($1, p.lowercase_path || '/')
                  )
            ORDER BY p.lowercase_path
            ",
        )
        .bind(path.fold())
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| storage_unavailable())?;
        let secret_paths = secret_rows
            .into_iter()
            .map(|row| row.path)
            .collect::<BTreeSet<_>>();
        // The JSON representation uses the masked token for both a preserved
        // secret and a legitimate plain value with the same text. Resolve
        // that ambiguity against the stored classification while the
        // mutation path is locked. Unknown markers are therefore stored as a
        // plain masked token; markers colliding with an existing secret still
        // fail the subtree validation below.
        for value in &mut values {
            let Some(sub_tree_mutation_value::Content::PreserveSecret(_)) = value.content.as_ref()
            else {
                continue;
            };
            if !secret_paths.contains(&value.path) {
                value.content = Some(sub_tree_mutation_value::Content::PlainValue(
                    MASKED_SECRET_TEXT.into(),
                ));
            }
        }
        let plain_paths: Vec<String> = values
            .iter()
            .filter_map(|value| match value.content.as_ref() {
                Some(sub_tree_mutation_value::Content::PlainValue(_)) => Some(value.path.clone()),
                _ => None,
            })
            .collect();
        let preserve_paths = values
            .iter()
            .filter_map(|value| match value.content.as_ref() {
                Some(sub_tree_mutation_value::Content::PreserveSecret(_)) => {
                    Some(value.path.as_str())
                }
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        if plain_paths.iter().any(|plain| {
            secret_paths
                .iter()
                .any(|secret| paths_collide(plain, secret))
        }) || !preserve_paths
            .iter()
            .all(|preserve| secret_paths.contains(*preserve))
        {
            return Err(Status::invalid_argument("configuration subtree is invalid"));
        }
        let now = OffsetDateTime::from(SystemTime::now());
        let cleared = sqlx::query_as::<_, DeletedPathRow>(
            r"
            DELETE FROM configuration_paths p
            USING configuration_value_contents c
            WHERE p.content_id = c.id
              AND ($1 = '/' OR p.lowercase_path = $1 OR starts_with(p.lowercase_path, $1 || '/'))
              AND c.classification = 'plain'
              AND NOT (p.lowercase_path = ANY($2::TEXT[]))
            RETURNING p.content_id
            ",
        )
        .bind(path.fold())
        .bind(&plain_paths)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| storage_unavailable())?;
        prune_orphan_contents(&mut transaction, &content_ids(&cleared)).await?;
        // Several paths in the subtree can alias one stored value, and the
        // subtree representation exposes every one of them. Resolve each
        // mutation to its content before writing so a shared value is written
        // exactly once: applying one update per path would let the last path in
        // sort order overwrite the others, silently discarding an edit while
        // still reporting success. Ascending content id also gives concurrent
        // replacements a common write order.
        // The map must stay ordered by content id: iterating it ascending is
        // what gives concurrent replacements a common row-lock order. Values
        // cross-aliased between disjoint subtrees (X at /a/1 and /b/2, Y at /a/2
        // and /b/1) would otherwise lock X-then-Y in one transaction and
        // Y-then-X in the other and deadlock, since their path locks are
        // disjoint. Do not swap this for a HashMap.
        let mut shared: BTreeMap<i64, &String> = BTreeMap::new();
        let mut fresh: Vec<(&String, &String)> = Vec::new();
        for value in &values {
            let Some(sub_tree_mutation_value::Content::PlainValue(content)) =
                value.content.as_ref()
            else {
                continue;
            };
            let existing = sqlx::query_scalar::<_, i64>(
                "SELECT content_id FROM configuration_paths WHERE lowercase_path = $1",
            )
            .bind(&value.path)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| storage_unavailable())?;
            match existing {
                Some(content_id) => match shared.get(&content_id) {
                    // Aliases of one value must agree; a genuine conflict is
                    // ambiguous, so reject it rather than pick a winner.
                    Some(assigned) if *assigned != content => {
                        return Err(Status::invalid_argument(
                            "configuration subtree assigns conflicting values to one stored value",
                        ));
                    }
                    Some(_) => {}
                    None => {
                        shared.insert(content_id, content);
                    }
                },
                None => fresh.push((&value.path, content)),
            }
        }
        // Nothing below encrypts, because subtree replacement can neither read
        // nor create a secret: it only ever writes `plain`, only ever deletes
        // `plain`, and the validation above rejects a plain value colliding
        // with a secret path. Every content row reached here is therefore
        // already plaintext and stays that way.
        for (content_id, content) in &shared {
            sqlx::query(
                r"
                UPDATE configuration_value_contents
                SET value = $2, classification = 'plain', updated_at = $3
                WHERE id = $1
                ",
            )
            .bind(content_id)
            .bind(content)
            .bind(now)
            .execute(&mut *transaction)
            .await
            .map_err(|_| storage_unavailable())?;
        }
        for (path, content) in fresh {
            let content_id = reserve_content_id(&mut transaction).await?;
            let inserted =
                insert_content(&mut transaction, content_id, content, PLAIN, now).await?;
            let display = displays.get(path).map_or(path.as_str(), String::as_str);
            insert_path(&mut transaction, display, inserted.id, now).await?;
        }
        transaction
            .commit()
            .await
            .map_err(|_| storage_unavailable())?;
        Ok(Response::new(ReplaceSubTreeResponse {
            updated_at: Some(to_proto_timestamp(now)?),
            value_count: u64::try_from(values.len()).map_err(|_| storage_unavailable())?,
        }))
    }

    async fn delete_values(
        &self,
        request: Request<DeleteValuesRequest>,
    ) -> Result<Response<DeleteValuesResponse>, Status> {
        let recurse = request.get_ref().recurse;
        let path = authorize(&request, &[Permission::Write], recurse)?;
        let mut transaction = self
            .database
            .begin()
            .await
            .map_err(|_| storage_unavailable())?;
        lock_mutation_path(&mut transaction, &path).await?;
        let deleted = if recurse {
            sqlx::query_as::<_, DeletedPathRow>(
                "DELETE FROM configuration_paths WHERE $1 = '/' OR lowercase_path = $1 OR starts_with(lowercase_path, $1 || '/') RETURNING content_id",
            )
            .bind(path.fold())
            .fetch_all(&mut *transaction)
            .await
            .map_err(|_| storage_unavailable())?
        } else {
            sqlx::query_as::<_, DeletedPathRow>(
                "DELETE FROM configuration_paths WHERE lowercase_path = $1 RETURNING content_id",
            )
            .bind(path.fold())
            .fetch_all(&mut *transaction)
            .await
            .map_err(|_| storage_unavailable())?
        };
        if deleted.is_empty() {
            return Err(Status::not_found("configuration value not found"));
        }
        // A path may have been the sole alias of its value; drop any content
        // left with no remaining paths so deleting the last path removes the
        // value for good, while shared values survive.
        prune_orphan_contents(&mut transaction, &content_ids(&deleted)).await?;
        transaction
            .commit()
            .await
            .map_err(|_| storage_unavailable())?;
        let deleted_at = OffsetDateTime::from(SystemTime::now());
        Ok(Response::new(DeleteValuesResponse {
            deleted_at: Some(to_proto_timestamp(deleted_at)?),
            deleted_count: u64::try_from(deleted.len()).map_err(|_| storage_unavailable())?,
        }))
    }

    async fn reveal_secret(
        &self,
        request: Request<RevealSecretRequest>,
    ) -> Result<Response<RevealSecretResponse>, Status> {
        let path = authorize(&request, &[Permission::Read], false)?;
        let row = sqlx::query_as::<_, RevealedRow>(
            r"
            SELECT p.content_id, c.value, c.classification
            FROM configuration_paths p
            JOIN configuration_value_contents c ON c.id = p.content_id
            WHERE p.lowercase_path = $1
            ",
        )
        .bind(path.fold())
        .fetch_optional(&self.database)
        .await
        .map_err(|_| storage_unavailable())?
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
        Ok(Response::new(RevealSecretResponse { value }))
    }

    async fn add_value_path(
        &self,
        request: Request<AddValuePathRequest>,
    ) -> Result<Response<AddValuePathResponse>, Status> {
        let principal = principal(&request)?;
        let source = ConfigPath::parse_operation(&request.get_ref().source_path)
            .map_err(|_| Status::invalid_argument("configuration path is invalid"))?;
        let new_path = ConfigPath::parse_operation(&request.get_ref().new_path)
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

        let mut transaction = self
            .database
            .begin()
            .await
            .map_err(|_| storage_unavailable())?;
        // Lock both mutation hierarchies in a canonical order so concurrent
        // aliasing in either direction cannot deadlock.
        let (first, second) = if source <= new_path {
            (&source, &new_path)
        } else {
            (&new_path, &source)
        };
        lock_mutation_path(&mut transaction, first).await?;
        lock_mutation_path(&mut transaction, second).await?;

        let content_id = sqlx::query_scalar::<_, i64>(
            "SELECT content_id FROM configuration_paths WHERE lowercase_path = $1",
        )
        .bind(source.fold())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| storage_unavailable())?
        .ok_or_else(|| Status::not_found("configuration value not found"))?;
        let occupied = sqlx::query_scalar::<_, String>(
            "SELECT path FROM configuration_paths WHERE lowercase_path = $1",
        )
        .bind(new_path.fold())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| storage_unavailable())?
        .is_some();
        if occupied {
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
        transaction
            .commit()
            .await
            .map_err(|_| storage_unavailable())?;
        Ok(Response::new(AddValuePathResponse {
            created_at: Some(to_proto_timestamp(now)?),
        }))
    }

    async fn list_value_paths(
        &self,
        request: Request<ListValuePathsRequest>,
    ) -> Result<Response<ListValuePathsResponse>, Status> {
        let path = authorize(&request, &[Permission::Read], false)?;
        let principal = principal(&request)?;
        let content_id = sqlx::query_scalar::<_, i64>(
            "SELECT content_id FROM configuration_paths WHERE lowercase_path = $1",
        )
        .bind(path.fold())
        .fetch_optional(&self.database)
        .await
        .map_err(|_| storage_unavailable())?
        .ok_or_else(|| Status::not_found("configuration value not found"))?;
        let rows = sqlx::query_as::<_, PathWithFoldRow>(
            "SELECT path, lowercase_path FROM configuration_paths WHERE content_id = $1 ORDER BY lowercase_path",
        )
        .bind(content_id)
        .fetch_all(&self.database)
        .await
        .map_err(|_| storage_unavailable())?;
        // Hide paths the caller cannot read: one value may be reachable through
        // paths outside the caller's grants.
        let mut paths = Vec::new();
        for row in rows {
            let candidate =
                ConfigPath::parse(&row.lowercase_path).map_err(|_| storage_unavailable())?;
            if principal.allows(&candidate, Permission::Read) {
                paths.push(row.path);
            }
        }
        Ok(Response::new(ListValuePathsResponse { paths }))
    }
}

fn paths_collide(first: &str, second: &str) -> bool {
    first == second
        || first
            .strip_prefix(second)
            .is_some_and(|suffix| suffix.starts_with('/'))
        || second
            .strip_prefix(first)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

// True if `path` is an ancestor or descendant of an existing path; values form
// a tree of leaves, so nesting is never allowed.
async fn path_collides(
    transaction: &mut Transaction<'_, Postgres>,
    path: &str,
) -> Result<bool, Status> {
    let collision = sqlx::query_scalar::<_, String>(
        r"
        SELECT path
        FROM configuration_paths
        WHERE lowercase_path <> $1
          AND (starts_with(lowercase_path, $1 || '/') OR starts_with($1, lowercase_path || '/'))
        LIMIT 1
        ",
    )
    .bind(path)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| storage_unavailable())?;
    Ok(collision.is_some())
}

/// Claims the identity a new content row will be inserted under.
///
/// A secret's ciphertext is bound to the row that stores it, so the identity
/// has to be known before the value is encrypted — which rules out letting the
/// INSERT generate it. Taking it from the sequence up front means the row is
/// written once, already sealed: no plaintext is ever handed to `PostgreSQL`,
/// not even briefly inside the transaction, where it would still reach the
/// write-ahead log.
async fn reserve_content_id(transaction: &mut Transaction<'_, Postgres>) -> Result<i64, Status> {
    sqlx::query_scalar::<_, i64>(
        "SELECT nextval(pg_get_serial_sequence('configuration_value_contents', 'id'))",
    )
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| storage_unavailable())
}

/// Inserts a content row under a previously reserved identity.
///
/// `value` is the stored representation, already encrypted when the
/// classification calls for it — this function does no encoding of its own.
async fn insert_content(
    transaction: &mut Transaction<'_, Postgres>,
    content_id: i64,
    value: &str,
    classification: &str,
    now: OffsetDateTime,
) -> Result<ContentRow, Status> {
    sqlx::query_as::<_, ContentRow>(
        r"
        INSERT INTO configuration_value_contents (id, value, classification, created_at, updated_at)
        OVERRIDING SYSTEM VALUE
        VALUES ($1, $2, $3, $4, $4)
        RETURNING id, created_at, updated_at
        ",
    )
    .bind(content_id)
    .bind(value)
    .bind(classification)
    .bind(now)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| storage_unavailable())
}

/// Inserts a path row. `path` is the exact case it was written with;
/// `lowercase_path` is computed by Postgres and must never appear here — the
/// generated column rejects any attempt to write it directly.
async fn insert_path(
    transaction: &mut Transaction<'_, Postgres>,
    path: &str,
    content_id: i64,
    now: OffsetDateTime,
) -> Result<(), Status> {
    sqlx::query(
        r"
        INSERT INTO configuration_paths (path, content_id, created_at, updated_at)
        VALUES ($1, $2, $3, $3)
        ",
    )
    .bind(path)
    .bind(content_id)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(|_| storage_unavailable())?;
    Ok(())
}

fn content_ids(rows: &[DeletedPathRow]) -> Vec<i64> {
    let mut ids = rows.iter().map(|row| row.content_id).collect::<Vec<_>>();
    ids.sort_unstable();
    ids.dedup();
    ids
}

// Delete any of the given contents that no longer have a path referencing them.
// Runs inline in the mutation transaction so the last path removal is what
// deletes the value — no background reconciliation.
async fn prune_orphan_contents(
    transaction: &mut Transaction<'_, Postgres>,
    content_ids: &[i64],
) -> Result<(), Status> {
    if content_ids.is_empty() {
        return Ok(());
    }
    // Path locks do not serialize deletions of aliases under unrelated
    // hierarchies, so two transactions each removing one of a value's last two
    // paths would both still see the other's uncommitted path row and skip
    // pruning, orphaning the content permanently. Lock each affected content
    // first. `content_ids` arrives sorted and deduplicated, so concurrent
    // pruners take these in a common order and cannot deadlock; every path lock
    // in a transaction is already held before any content lock.
    for content_id in content_ids {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('content:' || $1::TEXT, 0))")
            .bind(content_id)
            .execute(&mut **transaction)
            .await
            .map_err(|_| storage_unavailable())?;
    }
    sqlx::query(
        r"
        DELETE FROM configuration_value_contents c
        WHERE c.id = ANY($1::BIGINT[])
          AND NOT EXISTS (
                SELECT 1 FROM configuration_paths p WHERE p.content_id = c.id
              )
        ",
    )
    .bind(content_ids)
    .execute(&mut **transaction)
    .await
    .map_err(|_| storage_unavailable())?;
    Ok(())
}

// Shared ancestor locks and an exclusive target lock form a hierarchy: sibling
// subtrees can proceed together, while identical or parent/descendant mutations
// serialize. A hash collision can only add serialization, never remove it.
async fn lock_mutation_path(
    transaction: &mut Transaction<'_, Postgres>,
    path: &ConfigPath,
) -> Result<(), Status> {
    // Locks are hashed by this string, so two concurrent writes to the same
    // fold key — spelled differently — must hash to the same lock or they
    // would never serialize against each other. Always the fold, never
    // `path.as_str()` (display).
    let fold = path.fold();
    if fold != "/" {
        lock_path(transaction, "/", false).await?;
        let parent = parent_path(&fold);
        if parent != "/" {
            let mut prefix = String::new();
            for segment in parent.trim_start_matches('/').split('/') {
                prefix.push('/');
                prefix.push_str(segment);
                lock_path(transaction, &prefix, false).await?;
            }
        }
    }
    lock_path(transaction, &fold, true).await
}

async fn lock_path(
    transaction: &mut Transaction<'_, Postgres>,
    path: &str,
    exclusive: bool,
) -> Result<(), Status> {
    let query = if exclusive {
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))"
    } else {
        "SELECT pg_advisory_xact_lock_shared(hashtextextended($1, 0))"
    };
    sqlx::query(query)
        .bind(path)
        .execute(&mut **transaction)
        .await
        .map_err(|_| storage_unavailable())?;
    Ok(())
}

#[expect(
    clippy::result_large_err,
    reason = "tonic::Status is the crate's RPC error type and is returned by value"
)]
fn authorize<T>(
    request: &Request<T>,
    permissions: &[Permission],
    allow_root: bool,
) -> Result<ConfigPath, Status>
where
    T: ValueRequest,
{
    let path = if allow_root {
        ConfigPath::parse_selection(request.get_ref().path())
    } else {
        ConfigPath::parse_operation(request.get_ref().path())
    }
    .map_err(|_| Status::invalid_argument("configuration path is invalid"))?;
    let principal = principal(request)?;
    if permissions
        .iter()
        .any(|permission| !principal.allows(&path, *permission))
    {
        return Err(Status::permission_denied(
            "configuration operation is not permitted",
        ));
    }
    Ok(path)
}

trait ValueRequest {
    fn path(&self) -> &str;
}

impl ValueRequest for GetSubTreeRequest {
    fn path(&self) -> &str {
        &self.path
    }
}

impl ValueRequest for PutValueRequest {
    fn path(&self) -> &str {
        &self.path
    }
}

impl ValueRequest for ReplaceSubTreeRequest {
    fn path(&self) -> &str {
        &self.path
    }
}

impl ValueRequest for DeleteValuesRequest {
    fn path(&self) -> &str {
        &self.path
    }
}

impl ValueRequest for RevealSecretRequest {
    fn path(&self) -> &str {
        &self.path
    }
}

impl ValueRequest for ListValuePathsRequest {
    fn path(&self) -> &str {
        &self.path
    }
}

/// Renders a stored value for a listing.
///
/// A secret's stored representation is dropped here rather than decrypted:
/// listings mask secrets, so the ciphertext must not travel any further.
fn listed_content(value: String, classification: &str) -> Option<(i32, listed_value::Content)> {
    match classification {
        PLAIN => Some((
            ValueClassification::Plain as i32,
            listed_value::Content::PlainValue(value),
        )),
        SECRET => Some((
            ValueClassification::Secret as i32,
            listed_value::Content::MaskedSecret(MaskedSecret {}),
        )),
        _ => None,
    }
}

/// Renders a stored value for a subtree read. Masks secrets exactly as
/// [`listed_content`] does, so ciphertext never leaves the server here either.
fn subtree_content(value: String, classification: &str) -> Option<(i32, sub_tree_value::Content)> {
    match classification {
        PLAIN => Some((
            ValueClassification::Plain as i32,
            sub_tree_value::Content::PlainValue(value),
        )),
        SECRET => Some((
            ValueClassification::Secret as i32,
            sub_tree_value::Content::MaskedSecret(MaskedSecret {}),
        )),
        _ => None,
    }
}

/// The parent of a fold path. Takes `&str`, not `&ConfigPath`, so a caller
/// must explicitly hand in a fold key (e.g. `path.fold()` or a
/// `lowercase_path` column) rather than one that might carry display case.
fn parent_path(fold_path: &str) -> &str {
    fold_path.rsplit_once('/').map_or(
        "/",
        |(parent, _)| if parent.is_empty() { "/" } else { parent },
    )
}

/// Records every ancestor namespace of `fold_path` (a stored row's fold key),
/// keyed by fold, mapped to the earliest `created_at` among rows sharing that
/// ancestor and the matching prefix of `display_path`.
///
/// `fold_path` and `display_path` always have the same segment count and byte
/// length per segment — display case never adds, removes, or resizes a
/// segment — so their segments can be walked in lockstep by index.
fn add_parent_paths(
    paths: &mut BTreeMap<String, (OffsetDateTime, String)>,
    fold_path: &str,
    display_path: &str,
    created_at: OffsetDateTime,
) {
    upsert_ancestor(paths, "/".to_owned(), created_at, "/".to_owned());
    let fold_parent =
        fold_path.rsplit_once('/').map_or(
            "/",
            |(parent, _)| if parent.is_empty() { "/" } else { parent },
        );
    if fold_parent == "/" {
        return;
    }
    let fold_segments: Vec<&str> = fold_parent.trim_start_matches('/').split('/').collect();
    let display_segments: Vec<&str> = display_path.trim_start_matches('/').split('/').collect();
    let mut fold_prefix = String::new();
    let mut display_prefix = String::new();
    for index in 0..fold_segments.len() {
        fold_prefix.push('/');
        fold_prefix.push_str(fold_segments[index]);
        display_prefix.push('/');
        display_prefix.push_str(display_segments[index]);
        upsert_ancestor(
            paths,
            fold_prefix.clone(),
            created_at,
            display_prefix.clone(),
        );
    }
}

/// Keeps the display form from whichever row established this ancestor
/// first — ties break on the display string itself, so the choice stays
/// deterministic without depending on row iteration order.
fn upsert_ancestor(
    paths: &mut BTreeMap<String, (OffsetDateTime, String)>,
    fold: String,
    created_at: OffsetDateTime,
    display: String,
) {
    use std::collections::btree_map::Entry;
    match paths.entry(fold) {
        Entry::Vacant(entry) => {
            entry.insert((created_at, display));
        }
        Entry::Occupied(mut entry) => {
            if (created_at, display.as_str()) < (entry.get().0, entry.get().1.as_str()) {
                entry.insert((created_at, display));
            }
        }
    }
}

fn encryption_failed() -> Status {
    Status::internal("configuration value could not be encrypted")
}

/// Brings every stored secret up to the current encrypted representation.
///
/// Runs at startup, after migrations, because encrypting is something only the
/// server can do — a SQL migration has no access to the key. Rows already
/// sealed are verified and left alone, so a second run changes nothing; rows
/// still in plaintext, written before this server encrypted anything, are
/// sealed in place. Running on every start rather than once behind a marker
/// also repairs a deployment that was rolled back, wrote plaintext, and rolled
/// forward again.
///
/// Rows that will not open are judged together rather than one at a time,
/// because the same symptom has two very different causes. If *every* sealed
/// row fails, the key does not match this database: startup aborts, since
/// running on would mean serving errors for secrets that are perfectly intact
/// under the right key — or, worse, sealing a second layer over them. If only
/// some fail among healthy ones, that is damage to those rows — a torn write, a
/// partial restore — and taking the whole service down with them would deny
/// every `plain` value too, none of which needs a key at all. Those rows are
/// logged and left exactly as found, and [`ConfigurationService::reveal_secret`]
/// still fails closed for their paths.
pub(crate) async fn encrypt_stored_secrets(
    database: &PgPool,
    cipher: &ValueCipher,
) -> anyhow::Result<()> {
    let mut transaction = database
        .begin()
        .await
        .context("unable to begin the configuration secret encryption pass")?;
    // Replicas start concurrently, and two of them rewriting the same row would
    // race. The lock is held for the transaction, so it is released either way.
    //
    // It excludes other encryption passes, not live traffic: this assumes no
    // other instance is already serving. The deployment runs one container, so
    // the pass completes before anything can write. Anyone adding a replica or
    // a rolling deploy must revisit this — a `put_value` landing between the
    // SELECT below and its UPDATE would be overwritten by the sealed older
    // value. Locking the rows (`FOR UPDATE`) is the fix at that point.
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended('sovereign-config:encrypt-stored-secrets', 0))",
    )
    .execute(&mut *transaction)
    .await
    .context("unable to lock configuration secrets for encryption")?;

    let stored = sqlx::query_as::<_, StoredSecretRow>(
        r"
        SELECT id, value
        FROM configuration_value_contents
        WHERE classification = 'secret'
        ORDER BY id
        ",
    )
    .fetch_all(&mut *transaction)
    .await
    .context("unable to read configuration secrets for encryption")?;

    let mut encrypted = 0usize;
    let mut sealed_on_entry = 0usize;
    let mut unreadable = Vec::new();
    for row in stored {
        if is_envelope(&row.value) {
            sealed_on_entry += 1;
            if let Err(error) = cipher.decrypt(row.id, SECRET, &row.value) {
                error!(
                    content_id = row.id,
                    reason = %error,
                    "stored configuration secret is unreadable"
                );
                unreadable.push(row.id);
            }
            continue;
        }
        let sealed = cipher
            .encrypt(row.id, SECRET, &row.value)
            .map_err(|error| anyhow::anyhow!("configuration secret {}: {error}", row.id))?;
        // `updated_at` deliberately stays put: how a value is stored changed,
        // the value itself did not, and moving the timestamp would misreport a
        // rotation to every client watching it.
        sqlx::query("UPDATE configuration_value_contents SET value = $2 WHERE id = $1")
            .bind(row.id)
            .bind(&sealed)
            .execute(&mut *transaction)
            .await
            .context("unable to encrypt a stored configuration secret")?;
        encrypted += 1;
    }

    if wrong_key(unreadable.len(), sealed_on_entry) {
        // Nothing is committed: the rows encrypted above roll back with the
        // transaction, so a mistaken key cannot half-convert the database.
        anyhow::bail!(
            "every stored configuration secret is unreadable ({sealed_on_entry} rows); \
             the configured value encryption key does not match this database"
        );
    }

    transaction
        .commit()
        .await
        .context("unable to commit encrypted configuration secrets")?;
    if encrypted > 0 {
        info!(count = encrypted, "encrypted stored configuration secrets");
    }
    if !unreadable.is_empty() {
        error!(
            count = unreadable.len(),
            content_ids = ?unreadable,
            "some stored configuration secrets are unreadable and will fail when revealed; \
             every other value is unaffected"
        );
    }
    Ok(())
}

/// Decides whether unreadable secrets mean the key is wrong or the rows are.
///
/// Every sealed row failing points at the key, because one key opens all of
/// them. A mix means the key is right and those particular rows are damaged.
///
/// The two are genuinely indistinguishable when the database holds exactly one
/// sealed secret and it fails, so that case is treated as the wrong key: a
/// server that refuses to start is easier to diagnose and safer than one
/// quietly serving a secret it cannot read.
fn wrong_key(unreadable: usize, sealed_on_entry: usize) -> bool {
    unreadable > 0 && unreadable == sealed_on_entry
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

#[cfg(test)]
mod tests;
