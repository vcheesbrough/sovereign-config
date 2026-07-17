use std::{collections::BTreeSet, time::SystemTime};

use sovereign_config_core::ConfigPath;
use sovereign_config_proto::sovereign::config::v2::{
    DeleteValuesRequest, DeleteValuesResponse, GetSubTreeRequest, GetSubTreeResponse,
    ListValuesRequest, ListValuesResponse, ListedValue, PutValueRequest, PutValueResponse,
    ReplaceSubTreeRequest, ReplaceSubTreeResponse, SubTreeValue,
    configuration_server::Configuration,
};
use sqlx::{FromRow, PgPool};
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
                SELECT path, value, created_at, updated_at
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
                values.push(ListedValue {
                    path: row.path,
                    value: row.value,
                    created_at: Some(to_proto_timestamp(row.created_at)?),
                    updated_at: Some(to_proto_timestamp(row.updated_at)?),
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
            SELECT path, value, created_at, updated_at
            FROM configuration_values
            WHERE $1 = '/' OR path = $1 OR path LIKE $1 || '/%'
            ORDER BY path
            ",
        )
        .bind(path.as_str())
        .fetch_all(&self.database)
        .await
        .map_err(|_| storage_unavailable())?;

        Ok(Response::new(GetSubTreeResponse {
            values: rows
                .into_iter()
                .map(|row| SubTreeValue {
                    path: row.path,
                    value: row.value,
                })
                .collect(),
        }))
    }

    async fn put_value(
        &self,
        request: Request<PutValueRequest>,
    ) -> Result<Response<PutValueResponse>, Status> {
        let path = authorize(&request, &[Permission::Write], false)?;
        let value = &request.get_ref().value;
        if value.contains('\0') {
            return Err(Status::invalid_argument(
                "configuration value contains an invalid character",
            ));
        }
        let now = OffsetDateTime::from(SystemTime::now());
        let row = sqlx::query_as::<_, MutationRow>(
            r"
            INSERT INTO configuration_values (path, value, created_at, updated_at)
            VALUES ($1, $2, $3, $3)
            ON CONFLICT (path) DO UPDATE
            SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at
            RETURNING created_at, updated_at
            ",
        )
        .bind(path.as_str())
        .bind(value)
        .bind(now)
        .fetch_one(&self.database)
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
        let mut previous: Option<&str> = None;
        for value in &values {
            let value_path = ConfigPath::parse(&value.path)
                .map_err(|_| Status::invalid_argument("configuration subtree is invalid"))?;
            if value_path.as_str() == "/"
                || !value_path.is_at_or_below(&path)
                || value.value.contains('\0')
            {
                return Err(Status::invalid_argument("configuration subtree is invalid"));
            }
            if previous.is_some_and(|previous| {
                value.path == previous
                    || value
                        .path
                        .strip_prefix(previous)
                        .is_some_and(|suffix| suffix.starts_with('/'))
            }) {
                return Err(Status::invalid_argument("configuration subtree is invalid"));
            }
            previous = Some(&value.path);
        }

        let now = OffsetDateTime::from(SystemTime::now());
        let paths = values
            .iter()
            .map(|value| value.path.clone())
            .collect::<Vec<_>>();
        let mut transaction = self
            .database
            .begin()
            .await
            .map_err(|_| storage_unavailable())?;
        sqlx::query(
            r"
            DELETE FROM configuration_values
            WHERE ($1 = '/' OR path = $1 OR path LIKE $1 || '/%')
              AND NOT (path = ANY($2::TEXT[]))
            ",
        )
        .bind(path.as_str())
        .bind(&paths)
        .execute(&mut *transaction)
        .await
        .map_err(|_| storage_unavailable())?;
        for value in &values {
            sqlx::query(
                r"
                INSERT INTO configuration_values (path, value, created_at, updated_at)
                VALUES ($1, $2, $3, $3)
                ON CONFLICT (path) DO UPDATE
                SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at
                ",
            )
            .bind(&value.path)
            .bind(&value.value)
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
    use std::{collections::BTreeSet, env};

    use sovereign_config_proto::sovereign::config::v2::configuration_server::Configuration;
    use sqlx::postgres::PgPoolOptions;
    use tonic::{Code, Request};

    use super::{
        ConfigurationService, DeleteValuesRequest, GetSubTreeRequest, ListValuesRequest,
        PutValueRequest, ReplaceSubTreeRequest, SubTreeValue,
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

    #[tokio::test]
    #[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
    #[allow(clippy::too_many_lines)]
    async fn postgres_service_enforces_atomic_v2_value_lifecycle() {
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
                PutValueRequest {
                    path: "/tests/exact/invalid".into(),
                    value: "invalid\0value".into(),
                },
                &[Permission::Write],
            ))
            .await
            .unwrap_err();
        assert_eq!(invalid_value.code(), Code::InvalidArgument);

        service
            .put_value(request(
                PutValueRequest {
                    path: "/Tests/Exact/Key".into(),
                    value: "value-sentinel-one".into(),
                },
                &[Permission::Write],
            ))
            .await
            .unwrap();
        service
            .put_value(request_for_prefix(
                PutValueRequest {
                    path: "/tests/exactly/outside".into(),
                    value: "boundary-value-sentinel".into(),
                },
                "/",
                &[Permission::Write],
            ))
            .await
            .unwrap();
        service
            .put_value(request(
                PutValueRequest {
                    path: "/tests/exact/nested/child".into(),
                    value: "nested-value-sentinel".into(),
                },
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
        assert_eq!(stored.values[0].value, "value-sentinel-one");
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
                        SubTreeValue {
                            path: "/tests/exact/collision".into(),
                            value: "parent".into(),
                        },
                        SubTreeValue {
                            path: "/tests/exact/collision/child".into(),
                            value: "child".into(),
                        },
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
                    values: vec![SubTreeValue {
                        path: "/".into(),
                        value: "invalid-root-value".into(),
                    }],
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
                        SubTreeValue {
                            path: "/tests/exact/alpha".into(),
                            value: "one".into(),
                        },
                        SubTreeValue {
                            path: "/tests/exact/nested/beta".into(),
                            value: "two".into(),
                        },
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
}
