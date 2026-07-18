use std::{collections::BTreeSet, time::SystemTime};

use sovereign_config_core::{ConfigPath, MASKED_SECRET_TEXT};
use sovereign_config_proto::sovereign::config::v3::{
    DeleteValuesRequest, DeleteValuesResponse, GetSubTreeRequest, GetSubTreeResponse,
    ListValuesRequest, ListValuesResponse, ListedValue, MaskedSecret, PutValueRequest,
    PutValueResponse, ReplaceSubTreeRequest, ReplaceSubTreeResponse, RevealSecretRequest,
    RevealSecretResponse, SubTreeValue, ValueClassification, configuration_server::Configuration,
    listed_value, put_value_request, sub_tree_mutation_value, sub_tree_value,
};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use time::OffsetDateTime;
use tonic::{Request, Response, Status};

use crate::auth::{AuthenticatedPrincipal, Permission};

#[derive(Clone)]
pub(crate) struct ConfigurationService {
    database: PgPool,
}

#[derive(FromRow)]
struct ListedValueRow {
    path: String,
    value: String,
    classification: String,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

#[derive(FromRow)]
struct PathRow {
    path: String,
}

#[derive(FromRow)]
struct MutationRow {
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl ConfigurationService {
    pub(crate) fn new(database: PgPool) -> Self {
        Self { database }
    }
}

#[allow(clippy::too_many_lines)]
#[tonic::async_trait]
impl Configuration for ConfigurationService {
    async fn list_values(
        &self,
        request: Request<ListValuesRequest>,
    ) -> Result<Response<ListValuesResponse>, Status> {
        let selected = ConfigPath::parse(&request.get_ref().path)
            .map_err(|_| Status::invalid_argument("configuration path is invalid"))?;
        let principal = request
            .extensions()
            .get::<AuthenticatedPrincipal>()
            .ok_or_else(|| Status::unauthenticated("authentication required"))?;
        let candidates =
            sqlx::query_as::<_, PathRow>("SELECT path FROM configuration_values ORDER BY path")
                .fetch_all(&self.database)
                .await
                .map_err(|_| storage_unavailable())?;

        let mut readable_values = Vec::new();
        let mut paths = BTreeSet::new();
        for row in candidates {
            let path = ConfigPath::parse(&row.path).map_err(|_| storage_unavailable())?;
            if !principal.allows(&path, Permission::Read) {
                continue;
            }
            add_parent_paths(&mut paths, &path);
            if parent_path(&path) == selected.as_str() {
                readable_values.push(row.path);
            }
        }

        let mut values = Vec::new();
        if !readable_values.is_empty() {
            let rows = sqlx::query_as::<_, ListedValueRow>(
                r"
                SELECT path, value, classification, created_at, updated_at
                FROM configuration_values
                WHERE path = ANY($1::TEXT[])
                ORDER BY path
                ",
            )
            .bind(&readable_values)
            .fetch_all(&self.database)
            .await
            .map_err(|_| storage_unavailable())?;
            for row in rows {
                let (classification, content) = listed_content(row.value, &row.classification)
                    .ok_or_else(storage_unavailable)?;
                values.push(ListedValue {
                    path: row.path,
                    created_at: Some(to_proto_timestamp(row.created_at)?),
                    updated_at: Some(to_proto_timestamp(row.updated_at)?),
                    classification,
                    content: Some(content),
                });
            }
        }

        Ok(Response::new(ListValuesResponse {
            values,
            paths: paths.into_iter().collect(),
        }))
    }

    async fn get_sub_tree(
        &self,
        request: Request<GetSubTreeRequest>,
    ) -> Result<Response<GetSubTreeResponse>, Status> {
        let path = authorize(&request, &[Permission::Read], true)?;
        let rows = sqlx::query_as::<_, ListedValueRow>(
            r"
            SELECT path, value, classification, created_at, updated_at
            FROM configuration_values
            WHERE $1 = '/' OR path = $1 OR path LIKE $1 || '/%'
            ORDER BY path
            ",
        )
        .bind(path.as_str())
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
            Some(put_value_request::Content::PlainValue(value)) => (value, "plain"),
            Some(put_value_request::Content::SecretValue(value)) => (value, "secret"),
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
        let collides = sqlx::query_scalar::<_, String>(
            r"
            SELECT path
            FROM configuration_values
            WHERE path <> $1
              AND (path LIKE $1 || '/%' OR $1 LIKE path || '/%')
            LIMIT 1
            ",
        )
        .bind(path.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| storage_unavailable())?
        .is_some();
        if collides {
            return Err(Status::invalid_argument(
                "configuration value collides with an existing value",
            ));
        }
        let now = OffsetDateTime::from(SystemTime::now());
        let row = sqlx::query_as::<_, MutationRow>(
            r"
            INSERT INTO configuration_values (path, value, classification, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $4)
            ON CONFLICT (path) DO UPDATE
            SET value = EXCLUDED.value,
                classification = EXCLUDED.classification,
                updated_at = EXCLUDED.updated_at
            RETURNING created_at, updated_at
            ",
        )
        .bind(path.as_str())
        .bind(value)
        .bind(classification)
        .bind(now)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| storage_unavailable())?;
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
        values.sort_by(|first, second| first.path.cmp(&second.path));
        let mut accepted_paths = BTreeSet::new();
        for value in &values {
            let value_path = ConfigPath::parse(&value.path)
                .map_err(|_| Status::invalid_argument("configuration subtree is invalid"))?;
            if value_path.as_str() == "/" || !value_path.is_at_or_below(&path) {
                return Err(Status::invalid_argument("configuration subtree is invalid"));
            }
            match value.content.as_ref() {
                Some(sub_tree_mutation_value::Content::PlainValue(content))
                    if !content.contains('\0') => {}
                Some(sub_tree_mutation_value::Content::PreserveSecret(_)) => {}
                _ => return Err(Status::invalid_argument("configuration subtree is invalid")),
            }
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
            SELECT path
            FROM configuration_values
            WHERE classification = 'secret'
              AND ($1 = '/' OR path = $1 OR path LIKE $1 || '/%')
            ORDER BY path
            ",
        )
        .bind(path.as_str())
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
        sqlx::query(
            r"
            DELETE FROM configuration_values
            WHERE ($1 = '/' OR path = $1 OR path LIKE $1 || '/%')
              AND classification = 'plain'
              AND NOT (path = ANY($2::TEXT[]))
            ",
        )
        .bind(path.as_str())
        .bind(&plain_paths)
        .execute(&mut *transaction)
        .await
        .map_err(|_| storage_unavailable())?;
        for value in &values {
            let Some(sub_tree_mutation_value::Content::PlainValue(content)) =
                value.content.as_ref()
            else {
                continue;
            };
            sqlx::query(
                r"
                INSERT INTO configuration_values
                    (path, value, classification, created_at, updated_at)
                VALUES ($1, $2, 'plain', $3, $3)
                ON CONFLICT (path) DO UPDATE
                SET value = EXCLUDED.value,
                    classification = 'plain',
                    updated_at = EXCLUDED.updated_at
                ",
            )
            .bind(&value.path)
            .bind(content)
            .bind(now)
            .execute(&mut *transaction)
            .await
            .map_err(|_| storage_unavailable())?;
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
        let path = authorize(&request, &[Permission::Manage], recurse)?;
        let mut transaction = self
            .database
            .begin()
            .await
            .map_err(|_| storage_unavailable())?;
        lock_mutation_path(&mut transaction, &path).await?;
        let deleted = if recurse {
            sqlx::query(
                "DELETE FROM configuration_values WHERE $1 = '/' OR path = $1 OR path LIKE $1 || '/%' RETURNING path",
            )
            .bind(path.as_str())
            .fetch_all(&mut *transaction)
            .await
            .map_err(|_| storage_unavailable())?
        } else {
            sqlx::query("DELETE FROM configuration_values WHERE path = $1 RETURNING path")
                .bind(path.as_str())
                .fetch_all(&mut *transaction)
                .await
                .map_err(|_| storage_unavailable())?
        };
        if deleted.is_empty() {
            return Err(Status::not_found("configuration value not found"));
        }
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
        let row = sqlx::query_as::<_, ListedValueRow>(
            r"
            SELECT path, value, classification, created_at, updated_at
            FROM configuration_values
            WHERE path = $1
            ",
        )
        .bind(path.as_str())
        .fetch_optional(&self.database)
        .await
        .map_err(|_| storage_unavailable())?
        .ok_or_else(|| Status::not_found("configuration value not found"))?;
        if row.classification != "secret" {
            return Err(Status::invalid_argument(
                "configuration value is not a secret",
            ));
        }
        Ok(Response::new(RevealSecretResponse { value: row.value }))
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

// Shared ancestor locks and an exclusive target lock form a hierarchy: sibling
// subtrees can proceed together, while identical or parent/descendant mutations
// serialize. A hash collision can only add serialization, never remove it.
async fn lock_mutation_path(
    transaction: &mut Transaction<'_, Postgres>,
    path: &ConfigPath,
) -> Result<(), Status> {
    if path.as_str() != "/" {
        lock_path(transaction, "/", false).await?;
        let parent = parent_path(path);
        if parent != "/" {
            let mut prefix = String::new();
            for segment in parent.trim_start_matches('/').split('/') {
                prefix.push('/');
                prefix.push_str(segment);
                lock_path(transaction, &prefix, false).await?;
            }
        }
    }
    lock_path(transaction, path.as_str(), true).await
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

#[allow(clippy::result_large_err)]
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
    let principal = request
        .extensions()
        .get::<AuthenticatedPrincipal>()
        .ok_or_else(|| Status::unauthenticated("authentication required"))?;
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

fn listed_content(value: String, classification: &str) -> Option<(i32, listed_value::Content)> {
    match classification {
        "plain" => Some((
            ValueClassification::Plain as i32,
            listed_value::Content::PlainValue(value),
        )),
        "secret" => Some((
            ValueClassification::Secret as i32,
            listed_value::Content::MaskedSecret(MaskedSecret {}),
        )),
        _ => None,
    }
}

fn subtree_content(value: String, classification: &str) -> Option<(i32, sub_tree_value::Content)> {
    match classification {
        "plain" => Some((
            ValueClassification::Plain as i32,
            sub_tree_value::Content::PlainValue(value),
        )),
        "secret" => Some((
            ValueClassification::Secret as i32,
            sub_tree_value::Content::MaskedSecret(MaskedSecret {}),
        )),
        _ => None,
    }
}

fn parent_path(path: &ConfigPath) -> &str {
    path.as_str().rsplit_once('/').map_or(
        "/",
        |(parent, _)| if parent.is_empty() { "/" } else { parent },
    )
}

fn add_parent_paths(paths: &mut BTreeSet<String>, path: &ConfigPath) {
    let parent = parent_path(path);
    paths.insert("/".into());
    if parent == "/" {
        return;
    }
    let mut prefix = String::new();
    for segment in parent.trim_start_matches('/').split('/') {
        prefix.push('/');
        prefix.push_str(segment);
        paths.insert(prefix.clone());
    }
}

#[allow(clippy::result_large_err)]
fn to_proto_timestamp(value: OffsetDateTime) -> Result<prost_types::Timestamp, Status> {
    let nanos = value.nanosecond();
    Ok(prost_types::Timestamp {
        seconds: value.unix_timestamp(),
        nanos: i32::try_from(nanos).map_err(|_| invalid_timestamp())?,
    })
}

fn storage_unavailable() -> Status {
    Status::unavailable("configuration storage is unavailable")
}

fn invalid_timestamp() -> Status {
    Status::internal("configuration timestamp is invalid")
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, env, time::Duration};

    use sovereign_config_proto::sovereign::config::v3::{
        PreserveSecret, RevealSecretRequest, SubTreeMutationValue, ValueClassification,
        configuration_server::Configuration, listed_value, put_value_request,
        sub_tree_mutation_value, sub_tree_value,
    };
    use sqlx::postgres::PgPoolOptions;
    use tokio::time::{sleep, timeout};
    use tonic::{Code, Request};

    use super::{
        ConfigurationService, DeleteValuesRequest, GetSubTreeRequest, ListValuesRequest,
        MASKED_SECRET_TEXT, PutValueRequest, ReplaceSubTreeRequest,
    };
    use crate::auth::{AuthenticatedPrincipal, Grant, Permission};

    fn request<T>(message: T, permissions: &[Permission]) -> Request<T> {
        request_for_prefix(message, "/tests/exact", permissions)
    }

    fn request_for_prefix<T>(message: T, prefix: &str, permissions: &[Permission]) -> Request<T> {
        let mut request = Request::new(message);
        request.extensions_mut().insert(AuthenticatedPrincipal {
            subject: "integration-principal".into(),
            grants: vec![Grant {
                prefix: prefix.into(),
                permissions: permissions.iter().copied().collect::<BTreeSet<_>>(),
            }],
        });
        request
    }

    fn plain_put(path: &str, value: &str) -> PutValueRequest {
        PutValueRequest {
            path: path.into(),
            content: Some(put_value_request::Content::PlainValue(value.into())),
        }
    }

    fn secret_put(path: &str, value: &str) -> PutValueRequest {
        PutValueRequest {
            path: path.into(),
            content: Some(put_value_request::Content::SecretValue(value.into())),
        }
    }

    fn plain_mutation(path: &str, value: &str) -> SubTreeMutationValue {
        SubTreeMutationValue {
            path: path.into(),
            content: Some(sub_tree_mutation_value::Content::PlainValue(value.into())),
        }
    }

    fn preserve_secret(path: &str) -> SubTreeMutationValue {
        SubTreeMutationValue {
            path: path.into(),
            content: Some(sub_tree_mutation_value::Content::PreserveSecret(
                PreserveSecret {},
            )),
        }
    }

    #[tokio::test]
    #[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
    #[allow(clippy::too_many_lines)]
    async fn postgres_service_enforces_atomic_v3_value_lifecycle() {
        let database_url = env::var("SOVEREIGN_CONFIG_TEST_DATABASE_URL")
            .expect("SOVEREIGN_CONFIG_TEST_DATABASE_URL must be configured");
        let pool = PgPoolOptions::new().connect(&database_url).await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        sqlx::query(
            "DELETE FROM configuration_values WHERE path = '/tests/exact' OR path LIKE '/tests/exact/%' OR path LIKE '/tests/exactly/%'",
        )
            .execute(&pool)
            .await
            .unwrap();
        let service = ConfigurationService::new(pool.clone());

        let invalid_list = service
            .list_values(request(
                ListValuesRequest {
                    path: "/tests//exact".into(),
                },
                &[Permission::Read],
            ))
            .await
            .unwrap_err();
        assert_eq!(invalid_list.code(), Code::InvalidArgument);
        let unrooted_value = service
            .get_sub_tree(request(
                GetSubTreeRequest {
                    path: "tests/exact/key".into(),
                },
                &[Permission::Read],
            ))
            .await
            .unwrap_err();
        assert_eq!(unrooted_value.code(), Code::InvalidArgument);
        let invalid_value = service
            .put_value(request(
                plain_put("/tests/exact/invalid", "invalid\0value"),
                &[Permission::Write],
            ))
            .await
            .unwrap_err();
        assert_eq!(invalid_value.code(), Code::InvalidArgument);

        service
            .put_value(request(
                plain_put("/Tests/Exact/Key", "value-sentinel-one"),
                &[Permission::Write],
            ))
            .await
            .unwrap();
        service
            .put_value(request_for_prefix(
                plain_put("/tests/exactly/outside", "boundary-value-sentinel"),
                "/",
                &[Permission::Write],
            ))
            .await
            .unwrap();
        service
            .put_value(request(
                plain_put("/tests/exact/nested/child", "nested-value-sentinel"),
                &[Permission::Write],
            ))
            .await
            .unwrap();
        let listing = service
            .list_values(request(
                ListValuesRequest {
                    path: "/tests/exact".into(),
                },
                &[Permission::Read],
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listing.values.len(), 1);
        assert_eq!(listing.values[0].path, "/tests/exact/key");
        assert_eq!(
            listing.paths,
            ["/", "/tests", "/tests/exact", "/tests/exact/nested"]
        );
        let nested_only = service
            .list_values(request_for_prefix(
                ListValuesRequest {
                    path: "/tests/exact".into(),
                },
                "/tests/exact/nested",
                &[Permission::Read],
            ))
            .await
            .unwrap()
            .into_inner();
        assert!(nested_only.values.is_empty());
        assert_eq!(
            nested_only.paths,
            ["/", "/tests", "/tests/exact", "/tests/exact/nested"]
        );
        let write_only = service
            .list_values(request(
                ListValuesRequest {
                    path: "/tests/exact".into(),
                },
                &[Permission::Write],
            ))
            .await
            .unwrap()
            .into_inner();
        assert!(write_only.values.is_empty());
        assert!(write_only.paths.is_empty());
        let denied = service
            .get_sub_tree(request(
                GetSubTreeRequest {
                    path: "/tests/exact".into(),
                },
                &[Permission::Write],
            ))
            .await
            .unwrap_err();
        assert_eq!(denied.code(), Code::PermissionDenied);
        assert!(!denied.message().contains("value-sentinel"));

        let stored = service
            .get_sub_tree(request(
                GetSubTreeRequest {
                    path: "/TESTS/EXACT".into(),
                },
                &[Permission::Read],
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(stored.values.len(), 2);
        assert_eq!(stored.values[0].path, "/tests/exact/key");
        assert!(matches!(
            stored.values[0].content.as_ref(),
            Some(sub_tree_value::Content::PlainValue(value)) if value == "value-sentinel-one"
        ));
        assert_eq!(stored.values[1].path, "/tests/exact/nested/child");

        let narrower_read = service
            .get_sub_tree(request_for_prefix(
                GetSubTreeRequest {
                    path: "/tests/exact".into(),
                },
                "/tests/exact/nested",
                &[Permission::Read],
            ))
            .await
            .unwrap_err();
        assert_eq!(narrower_read.code(), Code::PermissionDenied);

        let boundary = service
            .get_sub_tree(request(
                GetSubTreeRequest {
                    path: "/tests/exactly".into(),
                },
                &[Permission::Read],
            ))
            .await
            .unwrap_err();
        assert_eq!(boundary.code(), Code::PermissionDenied);

        let write_only_replace = service
            .replace_sub_tree(request(
                ReplaceSubTreeRequest {
                    path: "/tests/exact".into(),
                    values: vec![],
                },
                &[Permission::Write],
            ))
            .await
            .unwrap_err();
        assert_eq!(write_only_replace.code(), Code::PermissionDenied);

        let invalid_replace = service
            .replace_sub_tree(request(
                ReplaceSubTreeRequest {
                    path: "/tests/exact".into(),
                    values: vec![
                        plain_mutation("/tests/exact/collision/child", "child"),
                        plain_mutation("/tests/exact/collision-sibling", "sibling"),
                        plain_mutation("/tests/exact/collision", "parent"),
                    ],
                },
                &[Permission::Write, Permission::Manage],
            ))
            .await
            .unwrap_err();
        assert_eq!(invalid_replace.code(), Code::InvalidArgument);
        let invalid_root_value = service
            .replace_sub_tree(request_for_prefix(
                ReplaceSubTreeRequest {
                    path: "/".into(),
                    values: vec![plain_mutation("/", "invalid-root-value")],
                },
                "/",
                &[Permission::Write, Permission::Manage],
            ))
            .await
            .unwrap_err();
        assert_eq!(invalid_root_value.code(), Code::InvalidArgument);
        assert_eq!(
            service
                .get_sub_tree(request(
                    GetSubTreeRequest {
                        path: "/tests/exact".into()
                    },
                    &[Permission::Read]
                ))
                .await
                .unwrap()
                .into_inner()
                .values
                .len(),
            2
        );

        let replacement = service
            .replace_sub_tree(request(
                ReplaceSubTreeRequest {
                    path: "/tests/exact".into(),
                    values: vec![
                        plain_mutation("/tests/exact/alpha", "one"),
                        plain_mutation("/tests/exact/nested/beta", "two"),
                    ],
                },
                &[Permission::Write, Permission::Manage],
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(replacement.value_count, 2);
        let replaced = service
            .get_sub_tree(request(
                GetSubTreeRequest {
                    path: "/tests/exact".into(),
                },
                &[Permission::Read],
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            replaced
                .values
                .iter()
                .map(|value| value.path.as_str())
                .collect::<Vec<_>>(),
            ["/tests/exact/alpha", "/tests/exact/nested/beta"]
        );

        let exact_delete = service
            .delete_values(request(
                DeleteValuesRequest {
                    path: "/tests/exact/alpha".into(),
                    recurse: false,
                },
                &[Permission::Manage],
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(exact_delete.deleted_count, 1);
        let recursive_delete = service
            .delete_values(request(
                DeleteValuesRequest {
                    path: "/tests/exact".into(),
                    recurse: true,
                },
                &[Permission::Manage],
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(recursive_delete.deleted_count, 1);
        let preserved_boundary = service
            .get_sub_tree(request_for_prefix(
                GetSubTreeRequest {
                    path: "/tests/exactly".into(),
                },
                "/",
                &[Permission::Read],
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(preserved_boundary.values.len(), 1);
        assert_eq!(preserved_boundary.values[0].path, "/tests/exactly/outside");
        let missing_delete = service
            .delete_values(request(
                DeleteValuesRequest {
                    path: "/tests/exact".into(),
                    recurse: true,
                },
                &[Permission::Manage],
            ))
            .await
            .unwrap_err();
        assert_eq!(missing_delete.code(), Code::NotFound);
        assert!(
            service
                .get_sub_tree(request(
                    GetSubTreeRequest {
                        path: "/tests/exact".into()
                    },
                    &[Permission::Read]
                ))
                .await
                .unwrap()
                .into_inner()
                .values
                .is_empty()
        );

        pool.close().await;
        let unavailable = service
            .get_sub_tree(request(
                GetSubTreeRequest {
                    path: "/tests/exact".into(),
                },
                &[Permission::Read],
            ))
            .await
            .unwrap_err();
        assert_eq!(unavailable.code(), Code::Unavailable);
    }

    #[tokio::test]
    #[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
    #[allow(clippy::too_many_lines)]
    async fn postgres_masks_rotates_reveals_and_preserves_secrets() {
        let database_url = env::var("SOVEREIGN_CONFIG_TEST_DATABASE_URL")
            .expect("SOVEREIGN_CONFIG_TEST_DATABASE_URL must be configured");
        let pool = PgPoolOptions::new().connect(&database_url).await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        sqlx::query(
            "DELETE FROM configuration_values WHERE path = '/tests/secrets' OR path LIKE '/tests/secrets/%'",
        )
        .execute(&pool)
        .await
        .unwrap();
        let service = ConfigurationService::new(pool.clone());

        for sentinel in ["secret-sentinel-one", "secret-sentinel-two"] {
            service
                .put_value(request_for_prefix(
                    secret_put("/tests/secrets/credential", sentinel),
                    "/tests/secrets",
                    &[Permission::Write],
                ))
                .await
                .unwrap();
        }

        let listing = service
            .list_values(request_for_prefix(
                ListValuesRequest {
                    path: "/tests/secrets".into(),
                },
                "/tests/secrets",
                &[Permission::Read],
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            listing.values[0].classification,
            ValueClassification::Secret as i32
        );
        assert!(matches!(
            listing.values[0].content,
            Some(listed_value::Content::MaskedSecret(_))
        ));

        // A plain value that happens to equal the JSON mask token must still
        // round-trip as plain when the marker is resolved against stored
        // classifications.
        service
            .replace_sub_tree(request_for_prefix(
                ReplaceSubTreeRequest {
                    path: "/tests/secrets".into(),
                    values: vec![
                        preserve_secret("/tests/secrets/credential"),
                        preserve_secret("/tests/secrets/plain-mask"),
                    ],
                },
                "/tests/secrets",
                &[Permission::Write, Permission::Manage],
            ))
            .await
            .unwrap();
        let round_tripped = service
            .get_sub_tree(request_for_prefix(
                GetSubTreeRequest {
                    path: "/tests/secrets".into(),
                },
                "/tests/secrets",
                &[Permission::Read],
            ))
            .await
            .unwrap()
            .into_inner();
        assert!(round_tripped.values.iter().any(|value| {
            value.path == "/tests/secrets/plain-mask"
                && value.classification == ValueClassification::Plain as i32
                && matches!(
                    value.content.as_ref(),
                    Some(sub_tree_value::Content::PlainValue(content))
                        if content == MASKED_SECRET_TEXT
                )
        }));

        service
            .put_value(request_for_prefix(
                secret_put(
                    "/tests/secrets/collision-parent",
                    "collision-parent-sentinel",
                ),
                "/tests/secrets",
                &[Permission::Write],
            ))
            .await
            .unwrap();
        let rejected_child = service
            .put_value(request_for_prefix(
                plain_put(
                    "/tests/secrets/collision-parent/child",
                    "collision-child-sentinel",
                ),
                "/tests/secrets",
                &[Permission::Write],
            ))
            .await
            .unwrap_err();
        assert_eq!(rejected_child.code(), Code::InvalidArgument);
        assert!(
            !rejected_child
                .message()
                .contains("collision-child-sentinel")
        );

        service
            .put_value(request_for_prefix(
                secret_put(
                    "/tests/secrets/collision-child/leaf",
                    "collision-leaf-sentinel",
                ),
                "/tests/secrets",
                &[Permission::Write],
            ))
            .await
            .unwrap();
        let rejected_parent = service
            .put_value(request_for_prefix(
                plain_put(
                    "/tests/secrets/collision-child",
                    "collision-parent-sentinel",
                ),
                "/tests/secrets",
                &[Permission::Write],
            ))
            .await
            .unwrap_err();
        assert_eq!(rejected_parent.code(), Code::InvalidArgument);
        assert!(
            !rejected_parent
                .message()
                .contains("collision-parent-sentinel")
        );

        let revealed = service
            .reveal_secret(request_for_prefix(
                RevealSecretRequest {
                    path: "/tests/secrets/credential".into(),
                },
                "/tests/secrets",
                &[Permission::Read],
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(revealed.value, "secret-sentinel-two");
        let denied = service
            .reveal_secret(request_for_prefix(
                RevealSecretRequest {
                    path: "/tests/secrets/credential".into(),
                },
                "/tests/secrets",
                &[Permission::Write],
            ))
            .await
            .unwrap_err();
        assert_eq!(denied.code(), Code::PermissionDenied);
        assert!(!denied.message().contains("secret-sentinel"));

        service
            .replace_sub_tree(request_for_prefix(
                ReplaceSubTreeRequest {
                    path: "/tests/secrets".into(),
                    values: vec![
                        preserve_secret("/tests/secrets/credential"),
                        plain_mutation("/tests/secrets/enabled", "true"),
                    ],
                },
                "/tests/secrets",
                &[Permission::Write, Permission::Manage],
            ))
            .await
            .unwrap();
        service
            .replace_sub_tree(request_for_prefix(
                ReplaceSubTreeRequest {
                    path: "/tests/secrets".into(),
                    values: vec![plain_mutation("/tests/secrets/enabled", "false")],
                },
                "/tests/secrets",
                &[Permission::Write, Permission::Manage],
            ))
            .await
            .unwrap();
        let rejected = service
            .replace_sub_tree(request_for_prefix(
                ReplaceSubTreeRequest {
                    path: "/tests/secrets".into(),
                    values: vec![plain_mutation(
                        "/tests/secrets/credential",
                        "attempted-overwrite-sentinel",
                    )],
                },
                "/tests/secrets",
                &[Permission::Write, Permission::Manage],
            ))
            .await
            .unwrap_err();
        assert_eq!(rejected.code(), Code::InvalidArgument);
        assert!(!rejected.message().contains("attempted-overwrite-sentinel"));
        let rejected_child = service
            .replace_sub_tree(request_for_prefix(
                ReplaceSubTreeRequest {
                    path: "/tests/secrets".into(),
                    values: vec![plain_mutation(
                        "/tests/secrets/credential/child",
                        "attempted-child-sentinel",
                    )],
                },
                "/tests/secrets",
                &[Permission::Write, Permission::Manage],
            ))
            .await
            .unwrap_err();
        assert_eq!(rejected_child.code(), Code::InvalidArgument);
        assert!(
            !rejected_child
                .message()
                .contains("attempted-child-sentinel")
        );
        assert_eq!(
            service
                .reveal_secret(request_for_prefix(
                    RevealSecretRequest {
                        path: "/tests/secrets/credential".into(),
                    },
                    "/tests/secrets",
                    &[Permission::Read],
                ))
                .await
                .unwrap()
                .into_inner()
                .value,
            "secret-sentinel-two"
        );

        service
            .put_value(request_for_prefix(
                plain_put("/tests/secrets/credential", "now-plain"),
                "/tests/secrets",
                &[Permission::Write],
            ))
            .await
            .unwrap();
        let not_secret = service
            .reveal_secret(request_for_prefix(
                RevealSecretRequest {
                    path: "/tests/secrets/credential".into(),
                },
                "/tests/secrets",
                &[Permission::Read],
            ))
            .await
            .unwrap_err();
        assert_eq!(not_secret.code(), Code::InvalidArgument);

        service
            .put_value(request_for_prefix(
                secret_put("/tests/secrets/credential", "secret-sentinel-three"),
                "/tests/secrets",
                &[Permission::Write],
            ))
            .await
            .unwrap();
        service
            .delete_values(request_for_prefix(
                DeleteValuesRequest {
                    path: "/tests/secrets/credential".into(),
                    recurse: false,
                },
                "/tests/secrets",
                &[Permission::Manage],
            ))
            .await
            .unwrap();
        let retained: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM configuration_values WHERE path = '/tests/secrets/credential'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(retained, 0);
    }

    #[tokio::test]
    #[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
    #[allow(clippy::too_many_lines)]
    async fn postgres_serializes_overlapping_subtree_replacements() {
        let database_url = env::var("SOVEREIGN_CONFIG_TEST_DATABASE_URL")
            .expect("SOVEREIGN_CONFIG_TEST_DATABASE_URL must be configured");
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(&database_url)
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        sqlx::query(
            "DELETE FROM configuration_values WHERE path = '/tests/concurrent' OR path LIKE '/tests/concurrent/%'",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO configuration_values (path, value, classification, created_at, updated_at) VALUES ('/tests/concurrent/existing', 'seed', 'plain', NOW(), NOW())",
        )
        .execute(&pool)
        .await
        .unwrap();

        let mut blocker = pool.begin().await.unwrap();
        sqlx::query(
            "SELECT path FROM configuration_values WHERE path = '/tests/concurrent/existing' FOR UPDATE",
        )
        .fetch_one(&mut *blocker)
        .await
        .unwrap();

        let service = ConfigurationService::new(pool.clone());
        let first_service = service.clone();
        let first = tokio::spawn(async move {
            first_service
                .replace_sub_tree(request_for_prefix(
                    ReplaceSubTreeRequest {
                        path: "/tests/concurrent".into(),
                        values: vec![
                            plain_mutation("/tests/concurrent/alpha-one", "one"),
                            plain_mutation("/tests/concurrent/alpha-two", "two"),
                        ],
                    },
                    "/tests/concurrent",
                    &[Permission::Write, Permission::Manage],
                ))
                .await
        });
        let second = tokio::spawn(async move {
            service
                .replace_sub_tree(request_for_prefix(
                    ReplaceSubTreeRequest {
                        path: "/tests/concurrent".into(),
                        values: vec![
                            plain_mutation("/tests/concurrent/beta-one", "one"),
                            plain_mutation("/tests/concurrent/beta-two", "two"),
                        ],
                    },
                    "/tests/concurrent",
                    &[Permission::Write, Permission::Manage],
                ))
                .await
        });

        let both_waiting = timeout(Duration::from_secs(5), async {
            loop {
                let waiting: i64 = sqlx::query_scalar(
                    r"
                    SELECT COUNT(*)
                    FROM pg_stat_activity
                    WHERE datname = current_database()
                      AND pid <> pg_backend_pid()
                      AND wait_event_type = 'Lock'
                      AND (
                        query LIKE '%DELETE FROM configuration_values%'
                        OR query LIKE '%pg_advisory_xact_lock%'
                      )
                    ",
                )
                .fetch_one(&pool)
                .await
                .unwrap();
                if waiting >= 2 {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        blocker.commit().await.unwrap();
        assert!(
            both_waiting.is_ok(),
            "concurrent replacements did not both reach their lock waits"
        );
        for replacement in [first, second] {
            timeout(Duration::from_secs(5), replacement)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        }

        let paths = sqlx::query_scalar::<_, String>(
            "SELECT path FROM configuration_values WHERE path LIKE '/tests/concurrent/%' ORDER BY path",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert!(
            paths == ["/tests/concurrent/alpha-one", "/tests/concurrent/alpha-two",]
                || paths == ["/tests/concurrent/beta-one", "/tests/concurrent/beta-two",],
            "final subtree was not one complete replacement: {paths:?}"
        );

        sqlx::query(
            "DELETE FROM configuration_values WHERE path = '/tests/concurrent' OR path LIKE '/tests/concurrent/%'",
        )
        .execute(&pool)
        .await
        .unwrap();
        pool.close().await;
    }
}
