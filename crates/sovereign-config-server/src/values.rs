use std::{collections::BTreeSet, time::SystemTime};

use sovereign_config_core::ConfigPath;
use sovereign_config_proto::sovereign::config::v1::{
    DeleteValueRequest, DeleteValueResponse, GetValueRequest, GetValueResponse, ListValuesRequest,
    ListValuesResponse, ListedValue, PutValueRequest, PutValueResponse,
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
struct ValueRow {
    value: String,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
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

    async fn get_value(
        &self,
        request: Request<GetValueRequest>,
    ) -> Result<Response<GetValueResponse>, Status> {
        let path = authorize(&request, Permission::Read)?;
        let row = sqlx::query_as::<_, ValueRow>(
            "SELECT value, created_at, updated_at FROM configuration_values WHERE path = $1",
        )
        .bind(path.as_str())
        .fetch_optional(&self.database)
        .await
        .map_err(|_| storage_unavailable())?
        .ok_or_else(|| Status::not_found("configuration value not found"))?;

        Ok(Response::new(GetValueResponse {
            value: row.value,
            created_at: Some(to_proto_timestamp(row.created_at)?),
            updated_at: Some(to_proto_timestamp(row.updated_at)?),
        }))
    }

    async fn put_value(
        &self,
        request: Request<PutValueRequest>,
    ) -> Result<Response<PutValueResponse>, Status> {
        let path = authorize(&request, Permission::Write)?;
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

    async fn delete_value(
        &self,
        request: Request<DeleteValueRequest>,
    ) -> Result<Response<DeleteValueResponse>, Status> {
        let path = authorize(&request, Permission::Manage)?;
        let deleted =
            sqlx::query("DELETE FROM configuration_values WHERE path = $1 RETURNING path")
                .bind(path.as_str())
                .fetch_optional(&self.database)
                .await
                .map_err(|_| storage_unavailable())?;
        if deleted.is_none() {
            return Err(Status::not_found("configuration value not found"));
        }
        let deleted_at = OffsetDateTime::from(SystemTime::now());
        Ok(Response::new(DeleteValueResponse {
            deleted_at: Some(to_proto_timestamp(deleted_at)?),
        }))
    }
}

#[allow(clippy::result_large_err)]
fn authorize<T>(request: &Request<T>, permission: Permission) -> Result<ConfigPath, Status>
where
    T: ValueRequest,
{
    let path = ConfigPath::parse_operation(request.get_ref().path())
        .map_err(|_| Status::invalid_argument("configuration path is invalid"))?;
    let principal = request
        .extensions()
        .get::<AuthenticatedPrincipal>()
        .ok_or_else(|| Status::unauthenticated("authentication required"))?;
    if !principal.allows(&path, permission) {
        return Err(Status::permission_denied(
            "configuration operation is not permitted",
        ));
    }
    Ok(path)
}

trait ValueRequest {
    fn path(&self) -> &str;
}

impl ValueRequest for GetValueRequest {
    fn path(&self) -> &str {
        &self.path
    }
}

impl ValueRequest for PutValueRequest {
    fn path(&self) -> &str {
        &self.path
    }
}

impl ValueRequest for DeleteValueRequest {
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

    use sovereign_config_proto::sovereign::config::v1::configuration_server::Configuration;
    use sqlx::postgres::PgPoolOptions;
    use tonic::{Code, Request};

    use super::{
        ConfigurationService, DeleteValueRequest, GetValueRequest, ListValuesRequest,
        PutValueRequest,
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
    async fn postgres_service_enforces_permissions_and_exact_value_lifecycle() {
        let database_url = env::var("SOVEREIGN_CONFIG_TEST_DATABASE_URL")
            .expect("SOVEREIGN_CONFIG_TEST_DATABASE_URL must be configured");
        let pool = PgPoolOptions::new().connect(&database_url).await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        sqlx::query("DELETE FROM configuration_values WHERE path LIKE '/tests/exact/%'")
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
            .get_value(request(
                GetValueRequest {
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

        let first = service
            .put_value(request(
                PutValueRequest {
                    path: "/Tests/Exact/Key".into(),
                    value: "value-sentinel-one".into(),
                },
                &[Permission::Write],
            ))
            .await
            .unwrap()
            .into_inner();
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
            .get_value(request(
                GetValueRequest {
                    path: "/tests/exact/key".into(),
                },
                &[Permission::Write],
            ))
            .await
            .unwrap_err();
        assert_eq!(denied.code(), Code::PermissionDenied);
        assert!(!denied.message().contains("value-sentinel"));

        let stored = service
            .get_value(request(
                GetValueRequest {
                    path: "/TESTS/EXACT/KEY".into(),
                },
                &[Permission::Read],
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(stored.value, "value-sentinel-one");
        assert_eq!(stored.created_at, first.created_at);

        let second = service
            .put_value(request(
                PutValueRequest {
                    path: "/tests/exact/key".into(),
                    value: "value-sentinel-two".into(),
                },
                &[Permission::Write],
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(second.created_at, first.created_at);
        let first_updated = first.updated_at.unwrap();
        let second_updated = second.updated_at.unwrap();
        assert!(
            (second_updated.seconds, second_updated.nanos)
                >= (first_updated.seconds, first_updated.nanos)
        );

        let boundary = service
            .get_value(request(
                GetValueRequest {
                    path: "/tests/exactly/key".into(),
                },
                &[Permission::Read],
            ))
            .await
            .unwrap_err();
        assert_eq!(boundary.code(), Code::PermissionDenied);

        service
            .delete_value(request(
                DeleteValueRequest {
                    path: "/tests/exact/key".into(),
                },
                &[Permission::Manage],
            ))
            .await
            .unwrap();
        let missing = service
            .get_value(request(
                GetValueRequest {
                    path: "/tests/exact/key".into(),
                },
                &[Permission::Read],
            ))
            .await
            .unwrap_err();
        assert_eq!(missing.code(), Code::NotFound);

        pool.close().await;
        let unavailable = service
            .get_value(request(
                GetValueRequest {
                    path: "/tests/exact/key".into(),
                },
                &[Permission::Read],
            ))
            .await
            .unwrap_err();
        assert_eq!(unavailable.code(), Code::Unavailable);
    }
}
