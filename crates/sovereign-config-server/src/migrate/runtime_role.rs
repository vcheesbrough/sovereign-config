//! The `runtime_role` step: the login the server connects with (#616).
//!
//! `migrate` connects as the schema owner, which owns every table and is the
//! image's superuser. The server connects as [`RUNTIME_ROLE`], which this
//! step creates, or brings back to exactly this shape:
//!
//! - it can log in with the password `migrate` was given, and nothing more:
//!   not a superuser, no `CREATEDB`, `CREATEROLE`, replication or RLS
//!   bypass, and a member of no other role;
//! - `SELECT, INSERT, UPDATE, DELETE` on every table in the schema, and
//!   `USAGE, SELECT` on every sequence, but only `SELECT` on
//!   `_sqlx_migrations`, which the server reads to verify the schema;
//! - the same on every table and sequence the owner creates there later,
//!   through `ALTER DEFAULT PRIVILEGES`, so a new migration needs no grant
//!   of its own.
//!
//! It owns nothing and may create nothing in the schema (`CREATE` is taken
//! back from `PUBLIC` there too), so it can create, alter, drop or truncate
//! nothing.
//!
//! The step is idempotent: a second run on current state changes nothing,
//! not even the password's salt. The password is sent as a SCRAM-SHA-256
//! verifier, never as text, so it cannot reach the database's log. It is set
//! whenever it no longer matches, which is how it is rotated: change the
//! secret and redeploy.
//!
//! Release N-1 serves on the owner login while this runs, and is unaffected
//! by it; a rollback to it simply goes on using the owner login.

use std::num::NonZeroU32;

use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ring::{digest, hmac, pbkdf2};
use sqlx::{PgPool, Postgres, Transaction};
use tracing::{field::Empty, info, instrument};
use zeroize::Zeroizing;

use crate::spans::{self, classified};

/// The role the server logs in as. A deployment's server URL names it.
pub(crate) const RUNTIME_ROLE: &str = "sovereign_config_runtime";

/// PostgreSQL's own default (`scram_iterations`).
const ITERATIONS: NonZeroU32 = NonZeroU32::new(4096).unwrap();

/// The variable `migrate` reads the runtime password from (or its `_FILE`).
pub(crate) const PASSWORD_VARIABLE: &str = "SOVEREIGN_CONFIG_RUNTIME_DATABASE_PASSWORD";

/// The server's login, as `migrate` is to create it.
pub(crate) struct RuntimeLogin {
    role: String,
    password: Zeroizing<String>,
}

impl RuntimeLogin {
    /// The deployment's runtime login: [`RUNTIME_ROLE`] with `password`.
    pub(crate) fn new(password: String) -> Result<Self> {
        Self::named(RUNTIME_ROLE, password)
    }

    /// A login under another name, so tests sharing one cluster (roles are
    /// cluster-wide) need not share one.
    ///
    /// # Errors
    ///
    /// The password is empty or not printable ASCII. Anything else would be
    /// normalised (`SASLprep`) differently by different clients, and the
    /// message never quotes it.
    pub(crate) fn named(role: &str, password: String) -> Result<Self> {
        let password = Zeroizing::new(password);
        debug_assert!(
            role.bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'),
            "a role name is a plain identifier"
        );
        if password.is_empty() || !password.bytes().all(|byte| byte.is_ascii_graphic()) {
            anyhow::bail!("{PASSWORD_VARIABLE} must be printable ASCII, with no spaces");
        }
        Ok(Self {
            role: role.to_owned(),
            password,
        })
    }
}

/// What the step found and did to the role itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RoleChange {
    Created,
    PasswordSet,
    Unchanged,
}

impl RoleChange {
    fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::PasswordSet => "password_set",
            Self::Unchanged => "unchanged",
        }
    }
}

/// Creates or updates the runtime role and its grants, in one transaction.
///
/// # Errors
///
/// The database cannot be reached or refuses a statement (the owner is not a
/// superuser), the runtime role is the owner itself, or the role is left able
/// to create anything or to act as another role.
#[instrument(
    name = "ensure_runtime_role",
    skip_all,
    fields(otel.kind = "client", otel.status_code = Empty, error.type = Empty, db.system.name = "postgresql", db.operation.name = "ensure_runtime_role")
)]
pub(crate) async fn ensure(database: &PgPool, login: &RuntimeLogin) -> Result<RoleChange> {
    let mut transaction = database.begin().await.map_err(unavailable)?;
    // Two `migrate`s at once would otherwise race on `CREATE ROLE`.
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended('sovereign-config:runtime-role', 0))",
    )
    .execute(&mut *transaction)
    .await
    .map_err(unavailable)?;
    let (owner, schema, database_name): (String, Option<String>, String) = sqlx::query_as(
        "SELECT current_user::TEXT, current_schema()::TEXT, current_database()::TEXT",
    )
    .fetch_one(&mut *transaction)
    .await
    .map_err(unavailable)?;
    let Some(schema) = schema else {
        return Err(refused(
            "no_schema",
            "the owner login's search path names no existing schema",
        ));
    };
    if owner == login.role {
        return Err(refused(
            "runtime_role_is_owner",
            "the runtime role must not be the login `migrate` connects as",
        ));
    }
    let change = role(&mut transaction, login).await?;
    grant(
        &mut transaction,
        &login.role,
        &owner,
        &schema,
        &database_name,
    )
    .await?;
    confine(&mut transaction, &login.role, &schema).await?;
    transaction.commit().await.map_err(unavailable)?;
    info!(
        runtime_role = login.role.as_str(),
        change = change.as_str(),
        "runtime role is current"
    );
    Ok(change)
}

/// The role, its attributes and its password.
async fn role(
    transaction: &mut Transaction<'_, Postgres>,
    login: &RuntimeLogin,
) -> Result<RoleChange> {
    // Readable by a superuser only, which the owner is.
    let stored: Option<Option<String>> =
        sqlx::query_scalar("SELECT rolpassword FROM pg_catalog.pg_authid WHERE rolname = $1")
            .bind(&login.role)
            .fetch_optional(&mut **transaction)
            .await
            .map_err(unavailable)?;
    let role = quote_identifier(&login.role);
    let attributes =
        "LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS";
    let change = match &stored {
        None => {
            let verifier = scram_verifier(&login.password)?;
            execute(
                transaction,
                &format!(
                    "CREATE ROLE {role} WITH {attributes} PASSWORD {}",
                    quote_literal(&verifier)
                ),
            )
            .await?;
            RoleChange::Created
        }
        Some(verifier) => {
            // Resetting them is a no-op unless someone changed them.
            execute(transaction, &format!("ALTER ROLE {role} WITH {attributes}")).await?;
            if verifier
                .as_deref()
                .is_some_and(|verifier| verifier_matches(verifier, &login.password))
            {
                RoleChange::Unchanged
            } else {
                let verifier = scram_verifier(&login.password)?;
                execute(
                    transaction,
                    &format!(
                        "ALTER ROLE {role} WITH PASSWORD {}",
                        quote_literal(&verifier)
                    ),
                )
                .await?;
                RoleChange::PasswordSet
            }
        }
    };
    Ok(change)
}

/// Exactly the grants the server needs, on what exists now and on what the
/// owner creates later. Revoking first makes them exact, and inside the
/// transaction nobody sees the gap.
async fn grant(
    transaction: &mut Transaction<'_, Postgres>,
    role: &str,
    owner: &str,
    schema: &str,
    database_name: &str,
) -> Result<()> {
    let role = quote_identifier(role);
    let owner = quote_identifier(owner);
    let schema = quote_identifier(schema);
    let database_name = quote_identifier(database_name);
    let tracked: bool = sqlx::query_scalar(
        "SELECT to_regclass(format('%I._sqlx_migrations', current_schema())) IS NOT NULL",
    )
    .fetch_one(&mut **transaction)
    .await
    .map_err(unavailable)?;
    let mut statements = vec![
        format!("GRANT CONNECT ON DATABASE {database_name} TO {role}"),
        format!("REVOKE CREATE ON DATABASE {database_name} FROM {role}"),
        // PostgreSQL 15 and later create `public` without it, but a cluster
        // first initialised by an older one keeps it through an upgrade. The
        // owner is a superuser, so nothing else relied on it.
        format!("REVOKE CREATE ON SCHEMA {schema} FROM PUBLIC"),
        format!("REVOKE CREATE ON SCHEMA {schema} FROM {role}"),
        format!("GRANT USAGE ON SCHEMA {schema} TO {role}"),
        format!("REVOKE ALL ON ALL TABLES IN SCHEMA {schema} FROM {role}"),
        format!("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {schema} TO {role}"),
        format!("REVOKE ALL ON ALL SEQUENCES IN SCHEMA {schema} FROM {role}"),
        format!("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA {schema} TO {role}"),
        format!(
            "ALTER DEFAULT PRIVILEGES FOR ROLE {owner} IN SCHEMA {schema} \
             GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {role}"
        ),
        format!(
            "ALTER DEFAULT PRIVILEGES FOR ROLE {owner} IN SCHEMA {schema} \
             GRANT USAGE, SELECT ON SEQUENCES TO {role}"
        ),
    ];
    if tracked {
        // Read to verify the schema; only `migrate` records a migration.
        statements.push(format!(
            "REVOKE INSERT, UPDATE, DELETE ON {schema}._sqlx_migrations FROM {role}"
        ));
    }
    for statement in statements {
        execute(transaction, &statement).await?;
    }
    Ok(())
}

/// Refuses a runtime role that could still change the schema once the grants
/// are in place: one that can create in the database (through `PUBLIC`,
/// which this step leaves alone at the database level) or in the schema, or
/// that belongs to another role it could act as.
async fn confine(
    transaction: &mut Transaction<'_, Postgres>,
    role: &str,
    schema: &str,
) -> Result<()> {
    let (creates, member): (bool, bool) = sqlx::query_as(
        "SELECT has_schema_privilege($1, $2, 'CREATE') \
                OR has_database_privilege($1, current_database(), 'CREATE'), \
                EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members \
                        WHERE member = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = $1))",
    )
    .bind(role)
    .bind(schema)
    .fetch_one(&mut **transaction)
    .await
    .map_err(unavailable)?;
    if creates {
        return Err(refused(
            "runtime_role_can_create",
            "the runtime role can create objects in the database; \
             revoke CREATE on it from PUBLIC",
        ));
    }
    if member {
        return Err(refused(
            "runtime_role_is_member",
            "the runtime role is a member of another role; revoke that membership",
        ));
    }
    Ok(())
}

async fn execute(transaction: &mut Transaction<'_, Postgres>, statement: &str) -> Result<()> {
    sqlx::raw_sql(statement)
        .execute(&mut **transaction)
        .await
        .map(|_| ())
        .map_err(|_| {
            refused(
                "statement_refused",
                "the database refused a runtime role statement",
            )
        })
}

/// A SCRAM-SHA-256 verifier for `password` under a fresh salt, in the form
/// PostgreSQL stores (`SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey>`).
/// Handed to `PASSWORD`, it is stored as it is, so the password itself never
/// reaches the server.
fn scram_verifier(password: &str) -> Result<String> {
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt)
        .map_err(|_| classified("entropy_unavailable", "no randomness for the password salt"))?;
    Ok(verifier(password, &salt, ITERATIONS))
}

fn verifier(password: &str, salt: &[u8], iterations: NonZeroU32) -> String {
    let (stored_key, server_key) = keys(password, salt, iterations);
    format!(
        "SCRAM-SHA-256${iterations}:{}${}:{}",
        STANDARD.encode(salt),
        STANDARD.encode(stored_key),
        STANDARD.encode(server_key)
    )
}

/// RFC 5802's `StoredKey` and `ServerKey`.
fn keys(password: &str, salt: &[u8], iterations: NonZeroU32) -> (Vec<u8>, Vec<u8>) {
    let mut salted = Zeroizing::new([0u8; digest::SHA256_OUTPUT_LEN]);
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        salt,
        password.as_bytes(),
        &mut *salted,
    );
    let key = hmac::Key::new(hmac::HMAC_SHA256, &*salted);
    let client_key = hmac::sign(&key, b"Client Key");
    let stored_key = digest::digest(&digest::SHA256, client_key.as_ref());
    let server_key = hmac::sign(&key, b"Server Key");
    (stored_key.as_ref().to_vec(), server_key.as_ref().to_vec())
}

/// Whether `stored`, a verifier PostgreSQL holds, is one for `password`.
/// Anything not a SCRAM-SHA-256 verifier (an MD5 hash, say) is not.
fn verifier_matches(stored: &str, password: &str) -> bool {
    let parse = || {
        let rest = stored.strip_prefix("SCRAM-SHA-256$")?;
        let (parameters, keys) = rest.split_once('$')?;
        let (iterations, salt) = parameters.split_once(':')?;
        let (stored_key, server_key) = keys.split_once(':')?;
        Some((
            iterations.parse::<NonZeroU32>().ok()?,
            STANDARD.decode(salt).ok()?,
            STANDARD.decode(stored_key).ok()?,
            STANDARD.decode(server_key).ok()?,
        ))
    };
    let Some((iterations, salt, stored_key, server_key)) = parse() else {
        return false;
    };
    // Compared in `migrate` against what it read itself: no one is timing it.
    keys(password, &salt, iterations) == (stored_key, server_key)
}

fn quote_identifier(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

fn quote_literal(literal: &str) -> String {
    format!("'{}'", literal.replace('\'', "''"))
}

fn unavailable(_: sqlx::Error) -> anyhow::Error {
    refused("unavailable", "unable to bring the runtime role up to date")
}

/// Never carries the database's own text: it can quote a statement.
fn refused(error_type: &'static str, message: &str) -> anyhow::Error {
    spans::record_error(error_type);
    classified(error_type, message.to_owned())
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use super::{RuntimeLogin, verifier, verifier_matches};

    /// A verifier made here is one this module recognises for the same
    /// password only; PostgreSQL's own are checked against the database in
    /// `migrate/tests.rs`.
    #[test]
    fn a_verifier_matches_its_own_password_only() {
        let iterations = NonZeroU32::new(4096).unwrap();
        let made = verifier("correct-horse", b"0123456789abcdef", iterations);
        assert!(
            made.starts_with("SCRAM-SHA-256$4096:MDEyMzQ1Njc4OWFiY2RlZg==$"),
            "{made}"
        );
        assert!(verifier_matches(&made, "correct-horse"));
        assert!(!verifier_matches(&made, "correct-horsf"));
        assert!(!verifier_matches(
            "md5a3556571e93b0d20722ba62be61e8c2d",
            "correct-horse"
        ));
        assert!(!verifier_matches("SCRAM-SHA-256$garbage", "correct-horse"));
        // The same password under another salt is another verifier.
        assert_ne!(
            made,
            verifier("correct-horse", b"fedcba9876543210", iterations)
        );
    }

    /// RFC 7677's test vector: user `user`, password `pencil`, salt
    /// `W22ZaJ0SNY7soEsUEjb6gQ==`, 4096 iterations, whose `ServerKey` signs
    /// the RFC's auth message into its `ServerSignature`.
    #[test]
    fn the_server_key_is_rfc_7677s() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let salt = STANDARD.decode("W22ZaJ0SNY7soEsUEjb6gQ==").unwrap();
        let (_, server_key) = super::keys("pencil", &salt, NonZeroU32::new(4096).unwrap());
        let auth_message = "n=user,r=rOprNGfwEbeRWgbNEkqO,\
                            r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,\
                            s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,\
                            c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &server_key);
        let signature = ring::hmac::sign(&key, auth_message.as_bytes());
        assert_eq!(
            STANDARD.encode(signature.as_ref()),
            "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="
        );
    }

    /// The server's URL is built by the deploy, not here, so it must name the
    /// role this step creates, and `compose.yaml` must say which that is.
    #[test]
    fn the_deploy_logs_the_server_in_as_this_role() {
        let deploy = include_str!("../../../../.woodpecker/deploy-dev.yml");
        assert!(
            deploy.contains(&format!(
                "RUNTIME_DATABASE_URL=\"postgresql://{}:",
                super::RUNTIME_ROLE
            )),
            "deploy-dev's server URL names another role"
        );
        let compose = include_str!("../../../../compose.yaml");
        assert!(compose.contains(&format!("`{}`", super::RUNTIME_ROLE)));
    }

    #[test]
    fn a_password_is_printable_ascii_and_never_quoted() {
        for refused in ["", "has space", "tab\there", "naïve", "line\nbreak"] {
            let error = RuntimeLogin::new(refused.to_owned())
                .err()
                .unwrap_or_else(|| panic!("{refused:?} is refused"))
                .to_string();
            assert_eq!(
                error,
                "SOVEREIGN_CONFIG_RUNTIME_DATABASE_PASSWORD must be printable ASCII, with no spaces"
            );
        }
        let login = RuntimeLogin::new("p%40ss'w\"rd".to_owned()).unwrap();
        assert_eq!(login.role, "sovereign_config_runtime");
    }
}
