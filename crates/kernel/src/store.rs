//! Storage: connection management, schema, and SQL error mapping.
//!
//! SQLite is the default engine for local/on-prem and tests. The whole platform
//! talks to it only through kernel services, and the SQL here is deliberately
//! ANSI-ish so a Postgres `Store` can implement the same surface later
//! (documented but not exercised in this build).

use latentdb_contracts::{ApiError, ErrorCode};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::SqlitePool;
use std::path::PathBuf;
use std::str::FromStr;

/// Where the kernel keeps its data.
#[derive(Clone, Debug)]
pub enum StoreConfig {
    /// A private in-memory database (one per pool). Used by tests and ephemeral
    /// dev runs.
    Memory,
    /// A SQLite file on disk (local/on-prem default).
    File(PathBuf),
}

impl StoreConfig {
    pub fn memory() -> Self {
        StoreConfig::Memory
    }
    pub fn file(path: impl Into<PathBuf>) -> Self {
        StoreConfig::File(path.into())
    }
    /// Build from the `LATENTDB_DATABASE_URL` env var, defaulting to a local file.
    pub fn from_env() -> Self {
        match std::env::var("LATENTDB_DATABASE_URL") {
            Ok(v) if v == ":memory:" || v == "sqlite::memory:" => StoreConfig::Memory,
            Ok(v) => {
                let path = v.strip_prefix("sqlite://").unwrap_or(&v);
                StoreConfig::File(PathBuf::from(path))
            }
            Err(_) => StoreConfig::File(PathBuf::from("latentdb.db")),
        }
    }
}

/// A thin handle exported for documentation/typing purposes. The actual pool is
/// held privately inside [`crate::Kernel`].
pub type Store = SqlitePool;

pub(crate) async fn connect(config: &StoreConfig) -> latentdb_contracts::Result<SqlitePool> {
    let (opts, max_conns) = match config {
        StoreConfig::Memory => (
            SqliteConnectOptions::from_str("sqlite::memory:")
                .map_err(map_db_err)?
                .foreign_keys(true),
            // A single long-lived connection keeps the in-memory DB alive.
            1,
        ),
        StoreConfig::File(path) => (
            SqliteConnectOptions::new()
                .filename(path)
                .create_if_missing(true)
                .foreign_keys(true)
                .journal_mode(SqliteJournalMode::Wal)
                .busy_timeout(std::time::Duration::from_secs(5)),
            8,
        ),
    };

    SqlitePoolOptions::new()
        .max_connections(max_conns)
        .min_connections(1)
        .idle_timeout(None)
        .max_lifetime(None)
        .connect_with(opts)
        .await
        .map_err(map_db_err)
}

/// Map an sqlx error to an [`ApiError`]. Unique-constraint violations become
/// `Conflict`; everything else is an internal error (we never leak SQL text to
/// clients).
pub(crate) fn map_db_err(e: sqlx::Error) -> ApiError {
    let msg = e.to_string();
    if msg.contains("UNIQUE constraint failed") {
        ApiError::new(ErrorCode::Conflict, "a record with these values already exists")
    } else if msg.contains("FOREIGN KEY constraint failed") {
        ApiError::new(ErrorCode::Validation, "referenced entity does not exist")
    } else {
        tracing::error!(error = %msg, "database error");
        ApiError::internal("internal storage error")
    }
}

/// The complete schema, applied idempotently on startup. One file keeps the alpha
/// simple; a Postgres adapter would translate these statements.
pub(crate) async fn migrate(pool: &SqlitePool) -> latentdb_contracts::Result<()> {
    for stmt in SCHEMA.split("-- >>") {
        let stmt = stmt.trim();
        if stmt.is_empty() {
            continue;
        }
        sqlx::query(stmt).execute(pool).await.map_err(map_db_err)?;
    }
    Ok(())
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS tenants (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    plan TEXT NOT NULL DEFAULT 'standard',
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL
);
-- >>
CREATE TABLE IF NOT EXISTS organizations (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    name TEXT NOT NULL,
    slug TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(tenant_id, slug)
);
-- >>
CREATE TABLE IF NOT EXISTS workspaces (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    org_id TEXT NOT NULL REFERENCES organizations(id),
    name TEXT NOT NULL,
    created_at TEXT NOT NULL
);
-- >>
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    email TEXT NOT NULL,
    name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    is_platform_admin INTEGER NOT NULL DEFAULT 0,
    default_org_id TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(tenant_id, email)
);
-- >>
CREATE TABLE IF NOT EXISTS service_accounts (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    org_id TEXT NOT NULL REFERENCES organizations(id),
    name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL
);
-- >>
CREATE TABLE IF NOT EXISTS roles (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    key TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    system INTEGER NOT NULL DEFAULT 0,
    grants_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    UNIQUE(tenant_id, key)
);
-- >>
CREATE TABLE IF NOT EXISTS role_assignments (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    principal_type TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    role_key TEXT NOT NULL,
    org_id TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(tenant_id, principal_id, role_key)
);
-- >>
CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    org_id TEXT NOT NULL,
    principal_type TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    name TEXT NOT NULL,
    prefix TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL,
    last_used_at TEXT
);
-- >>
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    user_id TEXT NOT NULL REFERENCES users(id),
    org_id TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0
);
-- >>
CREATE TABLE IF NOT EXISTS object_types (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    key TEXT NOT NULL,
    label TEXT NOT NULL,
    label_plural TEXT,
    description TEXT,
    system INTEGER NOT NULL DEFAULT 0,
    workflow_key TEXT,
    display_field TEXT,
    module TEXT,
    fields_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    UNIQUE(tenant_id, key)
);
-- >>
CREATE TABLE IF NOT EXISTS records (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    org_id TEXT NOT NULL,
    workspace_id TEXT,
    object_type TEXT NOT NULL,
    data_json TEXT NOT NULL DEFAULT '{}',
    lifecycle TEXT NOT NULL DEFAULT 'active',
    workflow_state TEXT,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    archived_at TEXT
);
-- >>
CREATE INDEX IF NOT EXISTS idx_records_tenant_type
    ON records(tenant_id, object_type, lifecycle);
-- >>
CREATE INDEX IF NOT EXISTS idx_records_org
    ON records(tenant_id, org_id, object_type);
-- >>
CREATE TABLE IF NOT EXISTS relations (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    from_record TEXT NOT NULL,
    to_record TEXT NOT NULL,
    relation_type TEXT NOT NULL,
    data_json TEXT NOT NULL DEFAULT '{}',
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(tenant_id, from_record, to_record, relation_type)
);
-- >>
CREATE INDEX IF NOT EXISTS idx_relations_from ON relations(tenant_id, from_record);
-- >>
CREATE INDEX IF NOT EXISTS idx_relations_to ON relations(tenant_id, to_record);
-- >>
CREATE TABLE IF NOT EXISTS documents (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    org_id TEXT NOT NULL,
    name TEXT NOT NULL,
    mime TEXT,
    size INTEGER NOT NULL DEFAULT 0,
    storage_ref TEXT,
    extracted_text TEXT,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
-- >>
CREATE TABLE IF NOT EXISTS workflows (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    key TEXT NOT NULL,
    object_type TEXT NOT NULL,
    name TEXT NOT NULL,
    definition_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(tenant_id, key)
);
-- >>
CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    org_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    assignee_id TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    due_at TEXT,
    related_object_type TEXT,
    related_record_id TEXT,
    data_json TEXT NOT NULL DEFAULT '{}',
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
-- >>
CREATE INDEX IF NOT EXISTS idx_tasks_assignee ON tasks(tenant_id, assignee_id, status);
-- >>
CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    org_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    policy TEXT,
    requested_by TEXT NOT NULL,
    decided_by TEXT,
    decision_reason TEXT,
    related_object_type TEXT,
    related_record_id TEXT,
    transition_key TEXT,
    target_state TEXT,
    risk_score REAL,
    data_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    decided_at TEXT
);
-- >>
CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(tenant_id, status);
-- >>
CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    org_id TEXT,
    actor_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    target_object_type TEXT,
    target_record_id TEXT,
    before_json TEXT,
    after_json TEXT,
    request_id TEXT NOT NULL,
    reason TEXT,
    source TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    client_meta_json TEXT,
    ai_meta_json TEXT,
    retrieved_source_ids_json TEXT,
    risk_score REAL,
    approval_id TEXT
);
-- >>
CREATE INDEX IF NOT EXISTS idx_audit_tenant_time ON audit_logs(tenant_id, timestamp);
-- >>
CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_logs(tenant_id, target_object_type, target_record_id);
-- >>
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_logs(tenant_id, actor_id);
-- >>
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    org_id TEXT,
    kind TEXT NOT NULL,
    payload_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    processed INTEGER NOT NULL DEFAULT 0
);
-- >>
CREATE INDEX IF NOT EXISTS idx_events_unprocessed ON events(tenant_id, processed);
-- >>
CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    key TEXT NOT NULL,
    name TEXT NOT NULL,
    definition_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(tenant_id, key)
);
-- >>
CREATE TABLE IF NOT EXISTS dashboards (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    key TEXT NOT NULL,
    name TEXT NOT NULL,
    cards_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    UNIQUE(tenant_id, key)
);
-- >>
CREATE TABLE IF NOT EXISTS ai_providers (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    base_url TEXT,
    model TEXT,
    api_key_ref TEXT,
    config_json TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL
);
-- >>
CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    key TEXT NOT NULL,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    safety_level INTEGER NOT NULL DEFAULT 0,
    role_key TEXT,
    config_json TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL,
    UNIQUE(tenant_id, key)
);
-- >>
CREATE TABLE IF NOT EXISTS usage_meters (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    metric TEXT NOT NULL,
    period TEXT NOT NULL,
    value INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL,
    UNIQUE(tenant_id, metric, period)
);
-- >>
CREATE TABLE IF NOT EXISTS settings (
    tenant_id TEXT NOT NULL,
    key TEXT NOT NULL,
    value_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(tenant_id, key)
);
"#;
