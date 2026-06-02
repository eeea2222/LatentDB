//! The record service — generic CRUD over metadata-defined object types.
//!
//! This is where the object database's guarantees come together: every method
//! authorizes via the RBAC service, validates against the object type's fields,
//! enforces field-level permissions on reads and writes, scopes every query to
//! the tenant, and writes an audit event (and domain event) in the same
//! transaction as the mutation.

use crate::audit::{event_from, insert_audit};
use crate::event::emit_on;
use crate::store::map_db_err;
use crate::Kernel;
use latentdb_contracts::record::Lifecycle;
use latentdb_contracts::{
    ids, Action, ApiError, AuthContext, ListResponse, NewRecord, ObjectTypeDef, PermissionGrant,
    Record, RecordFilter, RecordPatch,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sqlx::Row;

/// One edge in the relationship graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationEdge {
    pub id: String,
    pub relation_type: String,
    /// `out` = this record -> other; `in` = other -> this record.
    pub direction: String,
    pub record_id: String,
    pub created_at: String,
}

fn resource_for(object_type: &str) -> String {
    format!("object:{object_type}")
}

const MAX_SCAN: i64 = 5000;

impl Kernel {
    /// Create a record. Validates against the object type, enforces create-time
    /// field permissions, sets the workflow initial state, and audits.
    pub async fn create_record(
        &self,
        ctx: &AuthContext,
        new: &NewRecord,
    ) -> latentdb_contracts::Result<Record> {
        let resource = resource_for(&new.object_type);
        self.authorize(ctx, Action::Create, &resource, None).await?;
        let otype = self.load_object_type(&ctx.tenant_id, &new.object_type).await?;

        // Build the data map: defaults first, then provided values.
        let mut data = Map::new();
        for f in &otype.fields {
            if let Some(def) = &f.default {
                data.insert(f.key.clone(), def.clone());
            }
        }
        let create_grants = self.grants_for(ctx, Action::Create, &resource, None).await?;
        let grant_refs: Vec<&PermissionGrant> = create_grants.iter().collect();
        for (key, value) in &new.data {
            let field = otype
                .field(key)
                .ok_or_else(|| ApiError::validation(format!("unknown field '{key}'")))?;
            if field.system {
                return Err(ApiError::validation(format!("field '{key}' is system-managed")));
            }
            if field.restricted && !crate::rbac::field_permitted(&grant_refs, &otype, key) {
                self.audit_denial(ctx, "write_field", &resource, None).await;
                return Err(ApiError::forbidden(format!("not permitted to set field '{key}'")));
            }
            data.insert(key.clone(), value.clone());
        }
        validate_against_type(&otype, &data)?;

        // Workflow initial state.
        let workflow_state = match &otype.workflow_key {
            Some(wf) => self.workflow_initial_state(&ctx.tenant_id, wf).await?,
            None => None,
        };

        let id = ids::new_id();
        let now = ids::now_rfc3339();
        let data_json = Value::Object(data.clone()).to_string();
        let workspace_id: Option<String> =
            new.workspace_id.clone().or_else(|| ctx.workspace_id.clone());

        let mut tx = self.pool().begin().await.map_err(map_db_err)?;
        sqlx::query("INSERT INTO records (id, tenant_id, org_id, workspace_id, object_type, data_json, lifecycle, workflow_state, created_by, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)")
            .bind(&id).bind(&ctx.tenant_id).bind(&ctx.org_id)
            .bind(workspace_id.as_deref())
            .bind(&new.object_type).bind(&data_json).bind("active")
            .bind(workflow_state.as_deref()).bind(&ctx.actor_id).bind(&now).bind(&now)
            .execute(&mut *tx).await.map_err(map_db_err)?;

        let ev = event_from(ctx, "record.create", Some(&new.object_type), Some(&id),
            None, Some(Value::Object(data.clone())));
        insert_audit(&mut tx, &ev).await?;
        emit_on(&mut tx, ctx, "record.created",
            serde_json::json!({"object_type": new.object_type, "id": id})).await?;
        tx.commit().await.map_err(map_db_err)?;

        Ok(Record {
            id,
            object_type: new.object_type.clone(),
            tenant_id: ctx.tenant_id.clone(),
            org_id: ctx.org_id.clone(),
            workspace_id: new.workspace_id.clone().or_else(|| ctx.workspace_id.clone()),
            data,
            lifecycle: Lifecycle::Active,
            workflow_state,
            created_by: ctx.actor_id.clone(),
            created_at: now.clone(),
            updated_at: now,
            archived_at: None,
        })
    }

    /// Fetch a single record, enforcing record-level read permission and
    /// projecting out fields the actor cannot see.
    pub async fn get_record(
        &self,
        ctx: &AuthContext,
        id: &str,
    ) -> latentdb_contracts::Result<Record> {
        let record = self
            .load_record(&ctx.tenant_id, id)
            .await?
            .ok_or_else(|| ApiError::not_found("record not found"))?;
        let resource = resource_for(&record.object_type);
        self.authorize(ctx, Action::Read, &resource, Some(&record)).await?;
        let otype = self.load_object_type(&ctx.tenant_id, &record.object_type).await?;
        Ok(self.project_for_read(ctx, &record, &otype).await?)
    }

    /// Update a record's fields. Enforces update-time field permissions and
    /// audits the before/after diff.
    pub async fn update_record(
        &self,
        ctx: &AuthContext,
        id: &str,
        patch: &RecordPatch,
    ) -> latentdb_contracts::Result<Record> {
        let mut record = self
            .load_record(&ctx.tenant_id, id)
            .await?
            .ok_or_else(|| ApiError::not_found("record not found"))?;
        let resource = resource_for(&record.object_type);
        self.authorize(ctx, Action::Update, &resource, Some(&record)).await?;
        let otype = self.load_object_type(&ctx.tenant_id, &record.object_type).await?;

        let before = Value::Object(record.data.clone());
        let update_grants = self
            .grants_for(ctx, Action::Update, &resource, Some(&record))
            .await?;
        let grant_refs: Vec<&PermissionGrant> = update_grants.iter().collect();

        for (key, value) in &patch.data {
            let field = otype
                .field(key)
                .ok_or_else(|| ApiError::validation(format!("unknown field '{key}'")))?;
            if field.system {
                return Err(ApiError::validation(format!("field '{key}' is system-managed")));
            }
            if field.restricted && !crate::rbac::field_permitted(&grant_refs, &otype, key) {
                self.audit_denial(ctx, "write_field", &resource, Some(id)).await;
                return Err(ApiError::forbidden(format!("not permitted to set field '{key}'")));
            }
            if value.is_null() {
                record.data.remove(key);
            } else {
                record.data.insert(key.clone(), value.clone());
            }
        }
        validate_against_type(&otype, &record.data)?;

        let now = ids::now_rfc3339();
        let data_json = Value::Object(record.data.clone()).to_string();
        let mut tx = self.pool().begin().await.map_err(map_db_err)?;
        sqlx::query("UPDATE records SET data_json = ?, updated_at = ? WHERE tenant_id = ? AND id = ?")
            .bind(&data_json).bind(&now).bind(&ctx.tenant_id).bind(id)
            .execute(&mut *tx).await.map_err(map_db_err)?;
        let ev = event_from(ctx, "record.update", Some(&record.object_type), Some(id),
            Some(before), Some(Value::Object(record.data.clone())));
        insert_audit(&mut tx, &ev).await?;
        emit_on(&mut tx, ctx, "record.updated",
            serde_json::json!({"object_type": record.object_type, "id": id})).await?;
        tx.commit().await.map_err(map_db_err)?;

        record.updated_at = now;
        Ok(self.project_for_read(ctx, &record, &otype).await?)
    }

    /// Archive (soft-delete) a record.
    pub async fn archive_record(
        &self,
        ctx: &AuthContext,
        id: &str,
    ) -> latentdb_contracts::Result<()> {
        self.set_lifecycle(ctx, id, Lifecycle::Archived).await
    }

    /// Restore an archived record.
    pub async fn restore_record(
        &self,
        ctx: &AuthContext,
        id: &str,
    ) -> latentdb_contracts::Result<()> {
        self.set_lifecycle(ctx, id, Lifecycle::Active).await
    }

    async fn set_lifecycle(
        &self,
        ctx: &AuthContext,
        id: &str,
        lifecycle: Lifecycle,
    ) -> latentdb_contracts::Result<()> {
        let record = self
            .load_record(&ctx.tenant_id, id)
            .await?
            .ok_or_else(|| ApiError::not_found("record not found"))?;
        let resource = resource_for(&record.object_type);
        let action = match lifecycle {
            Lifecycle::Archived => Action::Archive,
            Lifecycle::Active => Action::Restore,
        };
        self.authorize(ctx, action, &resource, Some(&record)).await?;
        let now = ids::now_rfc3339();
        let archived_at = match lifecycle {
            Lifecycle::Archived => Some(now.clone()),
            Lifecycle::Active => None,
        };
        let mut tx = self.pool().begin().await.map_err(map_db_err)?;
        sqlx::query("UPDATE records SET lifecycle = ?, archived_at = ?, updated_at = ? WHERE tenant_id = ? AND id = ?")
            .bind(lifecycle.as_str()).bind(&archived_at).bind(&now).bind(&ctx.tenant_id).bind(id)
            .execute(&mut *tx).await.map_err(map_db_err)?;
        let verb = if matches!(lifecycle, Lifecycle::Archived) { "record.archive" } else { "record.restore" };
        let ev = event_from(ctx, verb, Some(&record.object_type), Some(id), None, None);
        insert_audit(&mut tx, &ev).await?;
        tx.commit().await.map_err(map_db_err)?;
        Ok(())
    }

    /// List records of a type with filtering, search, sorting, and pagination —
    /// permission-aware: rows the actor cannot read are excluded, and visible
    /// rows have restricted fields projected out.
    pub async fn list_records(
        &self,
        ctx: &AuthContext,
        object_type: &str,
        filter: &RecordFilter,
    ) -> latentdb_contracts::Result<ListResponse<Record>> {
        let resource = resource_for(object_type);
        self.authorize(ctx, Action::Search, &resource, None).await?;
        let otype = self.load_object_type(&ctx.tenant_id, object_type).await?;
        let grants = self.effective_grants(ctx).await?;

        // Fetch the candidate set (tenant + type + lifecycle), bounded.
        let mut sql = String::from(
            "SELECT * FROM records WHERE tenant_id = ? AND object_type = ?",
        );
        if !filter.include_archived {
            sql.push_str(" AND lifecycle = 'active'");
        }
        sql.push_str(" ORDER BY created_at DESC LIMIT ?");
        let rows = sqlx::query(&sql)
            .bind(&ctx.tenant_id)
            .bind(object_type)
            .bind(MAX_SCAN)
            .fetch_all(self.pool())
            .await
            .map_err(map_db_err)?;

        let mut records: Vec<Record> = rows
            .iter()
            .map(row_to_record)
            .collect::<latentdb_contracts::Result<Vec<_>>>()?;

        // Permission filter (record-level scope), then field/keyword filters.
        records.retain(|r| self.grants_allow(&grants, ctx, Action::Read, &resource, Some(r)));
        if let Some(search) = filter.search.as_ref().filter(|s| !s.is_empty()) {
            let needle = search.to_lowercase();
            records.retain(|r| record_matches_search(r, &needle));
        }
        for fclause in &filter.filters {
            records.retain(|r| {
                r.data
                    .get(&fclause.field)
                    .map(|v| crate::rbac::value_matches(v, fclause.op, &fclause.value))
                    .unwrap_or(false)
            });
        }

        // Sort.
        if let Some(sort_field) = &filter.sort {
            records.sort_by(|a, b| compare_field(a, b, sort_field));
            if filter.desc {
                records.reverse();
            }
        }

        let total = records.len() as i64;
        let page = filter.page.clamped();
        let start = page.offset.min(total) as usize;
        let end = ((page.offset + page.limit).min(total)) as usize;
        let full_access = ctx.is_system() || ctx.is_platform_admin;
        let items = records[start..end]
            .iter()
            .map(|r| {
                if full_access {
                    r.clone()
                } else {
                    let read_grants =
                        self.applicable_read_grants(&grants, ctx, &resource, Some(r));
                    r.project_fields(|k| crate::rbac::field_permitted(&read_grants, &otype, k))
                }
            })
            .collect();

        Ok(ListResponse {
            items,
            total,
            limit: page.limit,
            offset: page.offset,
        })
    }

    /// Create a relation between two records (relationship graph edge).
    pub async fn relate(
        &self,
        ctx: &AuthContext,
        from_id: &str,
        to_id: &str,
        relation_type: &str,
    ) -> latentdb_contracts::Result<RelationEdge> {
        let from = self
            .load_record(&ctx.tenant_id, from_id)
            .await?
            .ok_or_else(|| ApiError::not_found("from record not found"))?;
        let to = self
            .load_record(&ctx.tenant_id, to_id)
            .await?
            .ok_or_else(|| ApiError::not_found("to record not found"))?;
        self.authorize(ctx, Action::Relate, &resource_for(&from.object_type), Some(&from)).await?;
        self.authorize(ctx, Action::Read, &resource_for(&to.object_type), Some(&to)).await?;

        let id = ids::new_id();
        let now = ids::now_rfc3339();
        let mut tx = self.pool().begin().await.map_err(map_db_err)?;
        sqlx::query("INSERT OR IGNORE INTO relations (id, tenant_id, from_record, to_record, relation_type, created_by, created_at) VALUES (?,?,?,?,?,?,?)")
            .bind(&id).bind(&ctx.tenant_id).bind(from_id).bind(to_id)
            .bind(relation_type).bind(&ctx.actor_id).bind(&now)
            .execute(&mut *tx).await.map_err(map_db_err)?;
        let ev = event_from(ctx, "relation.create", Some(&from.object_type), Some(from_id), None,
            Some(serde_json::json!({"to": to_id, "type": relation_type})));
        insert_audit(&mut tx, &ev).await?;
        tx.commit().await.map_err(map_db_err)?;

        Ok(RelationEdge {
            id,
            relation_type: relation_type.into(),
            direction: "out".into(),
            record_id: to_id.into(),
            created_at: now,
        })
    }

    /// All relation edges touching a record (both directions). The caller must be
    /// able to read the record.
    pub async fn get_relations(
        &self,
        ctx: &AuthContext,
        record_id: &str,
    ) -> latentdb_contracts::Result<Vec<RelationEdge>> {
        let record = self
            .load_record(&ctx.tenant_id, record_id)
            .await?
            .ok_or_else(|| ApiError::not_found("record not found"))?;
        self.authorize(ctx, Action::Read, &resource_for(&record.object_type), Some(&record)).await?;

        let rows = sqlx::query(
            "SELECT * FROM relations WHERE tenant_id = ? AND (from_record = ? OR to_record = ?)",
        )
        .bind(&ctx.tenant_id)
        .bind(record_id)
        .bind(record_id)
        .fetch_all(self.pool())
        .await
        .map_err(map_db_err)?;

        let mut edges = Vec::with_capacity(rows.len());
        for row in &rows {
            let from: String = row.try_get("from_record").map_err(map_db_err)?;
            let to: String = row.try_get("to_record").map_err(map_db_err)?;
            let (direction, other) = if from == record_id {
                ("out", to)
            } else {
                ("in", from)
            };
            edges.push(RelationEdge {
                id: row.try_get("id").map_err(map_db_err)?,
                relation_type: row.try_get("relation_type").map_err(map_db_err)?,
                direction: direction.into(),
                record_id: other,
                created_at: row.try_get("created_at").map_err(map_db_err)?,
            });
        }
        Ok(edges)
    }

    /// Internal: load a raw record (no auth). Callers must authorize.
    pub(crate) async fn load_record(
        &self,
        tenant_id: &str,
        id: &str,
    ) -> latentdb_contracts::Result<Option<Record>> {
        let row = sqlx::query("SELECT * FROM records WHERE tenant_id = ? AND id = ?")
            .bind(tenant_id)
            .bind(id)
            .fetch_optional(self.pool())
            .await
            .map_err(map_db_err)?;
        match row {
            None => Ok(None),
            Some(row) => Ok(Some(row_to_record(&row)?)),
        }
    }

    /// Project a record for reading, applying field-level visibility.
    async fn project_for_read(
        &self,
        ctx: &AuthContext,
        record: &Record,
        otype: &ObjectTypeDef,
    ) -> latentdb_contracts::Result<Record> {
        if ctx.is_system() || ctx.is_platform_admin {
            return Ok(record.clone());
        }
        let grants = self.effective_grants(ctx).await?;
        let read_grants =
            self.applicable_read_grants(&grants, ctx, &resource_for(&record.object_type), Some(record));
        Ok(record.project_fields(|k| crate::rbac::field_permitted(&read_grants, otype, k)))
    }
}

/// Validate a complete data map against an object type (required fields present,
/// each value well-typed).
fn validate_against_type(
    otype: &ObjectTypeDef,
    data: &Map<String, Value>,
) -> latentdb_contracts::Result<()> {
    for f in &otype.fields {
        let value = data.get(&f.key).cloned().unwrap_or(Value::Null);
        f.validate_value(&value)
            .map_err(ApiError::validation)?;
    }
    Ok(())
}

fn record_matches_search(record: &Record, needle: &str) -> bool {
    record.data.values().any(|v| match v {
        Value::String(s) => s.to_lowercase().contains(needle),
        _ => false,
    })
}

fn compare_field(a: &Record, b: &Record, field: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    if field == "created_at" {
        return a.created_at.cmp(&b.created_at);
    }
    match (a.data.get(field), b.data.get(field)) {
        (Some(Value::Number(x)), Some(Value::Number(y))) => x
            .as_f64()
            .partial_cmp(&y.as_f64())
            .unwrap_or(Ordering::Equal),
        (Some(Value::String(x)), Some(Value::String(y))) => x.cmp(y),
        (Some(_), None) => Ordering::Greater,
        (None, Some(_)) => Ordering::Less,
        _ => Ordering::Equal,
    }
}

pub(crate) fn row_to_record(row: &sqlx::sqlite::SqliteRow) -> latentdb_contracts::Result<Record> {
    let data_json: String = row.try_get("data_json").map_err(map_db_err)?;
    let data: Map<String, Value> = serde_json::from_str(&data_json).unwrap_or_default();
    let lifecycle = Lifecycle::from_str(&row.try_get::<String, _>("lifecycle").map_err(map_db_err)?);
    Ok(Record {
        id: row.try_get("id").map_err(map_db_err)?,
        object_type: row.try_get("object_type").map_err(map_db_err)?,
        tenant_id: row.try_get("tenant_id").map_err(map_db_err)?,
        org_id: row.try_get("org_id").map_err(map_db_err)?,
        workspace_id: row.try_get("workspace_id").map_err(map_db_err)?,
        data,
        lifecycle,
        workflow_state: row.try_get("workflow_state").map_err(map_db_err)?,
        created_by: row.try_get("created_by").map_err(map_db_err)?,
        created_at: row.try_get("created_at").map_err(map_db_err)?,
        updated_at: row.try_get("updated_at").map_err(map_db_err)?,
        archived_at: row.try_get("archived_at").map_err(map_db_err)?,
    })
}
