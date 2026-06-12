//! Object-type management — the schema layer of the metadata-driven database.
//!
//! Business "models" are object types with field definitions. The record service
//! loads them (via the internal `load_object_type`) to validate values, apply
//! defaults, and enforce field-level permissions.

use crate::audit::{event_from, insert_audit};
use crate::store::map_db_err;
use crate::Kernel;
use latentdb_contracts::{ids, Action, ApiError, AuthContext, FieldDefinition, ObjectTypeDef};
use sqlx::Row;

impl Kernel {
    /// Define a new object type. Requires `configure` on `object_types`.
    pub async fn create_object_type(
        &self,
        ctx: &AuthContext,
        def: &ObjectTypeDef,
    ) -> latentdb_contracts::Result<ObjectTypeDef> {
        self.authorize(ctx, Action::Configure, "object_types", None)
            .await?;
        validate_object_type(def)?;

        let id = if def.id.is_empty() {
            ids::new_id()
        } else {
            def.id.clone()
        };
        let now = ids::now_rfc3339();
        let fields_json = serde_json::to_string(&def.fields).unwrap_or_else(|_| "[]".into());

        let mut tx = self.pool().begin().await.map_err(map_db_err)?;
        sqlx::query("INSERT INTO object_types (id, tenant_id, key, label, label_plural, description, system, workflow_key, display_field, module, fields_json, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)")
            .bind(&id).bind(&ctx.tenant_id).bind(&def.key).bind(&def.label)
            .bind(&def.label_plural).bind(&def.description).bind(def.system as i64)
            .bind(&def.workflow_key).bind(&def.display_field).bind(&def.module)
            .bind(&fields_json).bind(&now)
            .execute(&mut *tx).await.map_err(map_db_err)?;
        let ev = event_from(
            ctx,
            "object_type.create",
            Some("object_type"),
            Some(&def.key),
            None,
            Some(serde_json::json!({"key": def.key, "fields": def.fields.len()})),
        );
        insert_audit(&mut tx, &ev).await?;
        tx.commit().await.map_err(map_db_err)?;

        let mut created = def.clone();
        created.id = id;
        Ok(created)
    }

    /// Replace an object type's metadata/fields. Requires `configure`.
    pub async fn update_object_type(
        &self,
        ctx: &AuthContext,
        key: &str,
        def: &ObjectTypeDef,
    ) -> latentdb_contracts::Result<ObjectTypeDef> {
        self.authorize(ctx, Action::Configure, "object_types", None)
            .await?;
        validate_object_type(def)?;
        let before = self.load_object_type(&ctx.tenant_id, key).await?;
        let fields_json = serde_json::to_string(&def.fields).unwrap_or_else(|_| "[]".into());

        let mut tx = self.pool().begin().await.map_err(map_db_err)?;
        let affected = sqlx::query("UPDATE object_types SET label = ?, label_plural = ?, description = ?, workflow_key = ?, display_field = ?, module = ?, fields_json = ? WHERE tenant_id = ? AND key = ?")
            .bind(&def.label).bind(&def.label_plural).bind(&def.description)
            .bind(&def.workflow_key).bind(&def.display_field).bind(&def.module)
            .bind(&fields_json).bind(&ctx.tenant_id).bind(key)
            .execute(&mut *tx).await.map_err(map_db_err)?.rows_affected();
        if affected == 0 {
            return Err(ApiError::not_found("object type not found"));
        }
        let ev = event_from(
            ctx,
            "object_type.update",
            Some("object_type"),
            Some(key),
            Some(serde_json::json!({"fields": before.fields.len()})),
            Some(serde_json::json!({"fields": def.fields.len()})),
        );
        insert_audit(&mut tx, &ev).await?;
        tx.commit().await.map_err(map_db_err)?;

        let mut updated = def.clone();
        updated.key = key.to_string();
        Ok(updated)
    }

    /// Fetch an object type (authorized read).
    pub async fn get_object_type(
        &self,
        ctx: &AuthContext,
        key: &str,
    ) -> latentdb_contracts::Result<ObjectTypeDef> {
        self.authorize(ctx, Action::Read, "object_types", None)
            .await?;
        self.load_object_type(&ctx.tenant_id, key).await
    }

    /// List all object types in the tenant.
    pub async fn list_object_types(
        &self,
        ctx: &AuthContext,
    ) -> latentdb_contracts::Result<Vec<ObjectTypeDef>> {
        self.authorize(ctx, Action::Read, "object_types", None)
            .await?;
        let rows = sqlx::query("SELECT * FROM object_types WHERE tenant_id = ? ORDER BY key")
            .bind(&ctx.tenant_id)
            .fetch_all(self.pool())
            .await
            .map_err(map_db_err)?;
        rows.iter().map(row_to_object_type).collect()
    }

    /// Internal: load an object type without an authorization check. Used by the
    /// record service which has already authorized the surrounding operation.
    pub(crate) async fn load_object_type(
        &self,
        tenant_id: &str,
        key: &str,
    ) -> latentdb_contracts::Result<ObjectTypeDef> {
        let row = sqlx::query("SELECT * FROM object_types WHERE tenant_id = ? AND key = ?")
            .bind(tenant_id)
            .bind(key)
            .fetch_optional(self.pool())
            .await
            .map_err(map_db_err)?
            .ok_or_else(|| ApiError::not_found(format!("object type '{key}' not found")))?;
        row_to_object_type(&row)
    }
}

/// Validate an object-type definition: keys present, field keys unique, enum
/// fields have options, references name a target type.
fn validate_object_type(def: &ObjectTypeDef) -> latentdb_contracts::Result<()> {
    if def.key.trim().is_empty() {
        return Err(ApiError::validation("object type key is required"));
    }
    let mut seen = std::collections::HashSet::new();
    for f in &def.fields {
        if f.key.trim().is_empty() {
            return Err(ApiError::validation("field key is required"));
        }
        if !seen.insert(f.key.as_str()) {
            return Err(ApiError::validation(format!(
                "duplicate field key '{}'",
                f.key
            )));
        }
        validate_field_def(f)?;
    }
    Ok(())
}

fn validate_field_def(f: &FieldDefinition) -> latentdb_contracts::Result<()> {
    use latentdb_contracts::FieldType;
    match f.field_type {
        FieldType::Enum | FieldType::MultiEnum if f.enum_options.is_empty() => Err(
            ApiError::validation(format!("field '{}' must define enum_options", f.key)),
        ),
        FieldType::RecordRef if f.ref_object_type.is_none() => Err(ApiError::validation(format!(
            "field '{}' must set ref_object_type",
            f.key
        ))),
        _ => Ok(()),
    }
}

fn row_to_object_type(row: &sqlx::sqlite::SqliteRow) -> latentdb_contracts::Result<ObjectTypeDef> {
    let fields_json: String = row.try_get("fields_json").map_err(map_db_err)?;
    let fields = serde_json::from_str(&fields_json).unwrap_or_default();
    Ok(ObjectTypeDef {
        id: row.try_get("id").map_err(map_db_err)?,
        key: row.try_get("key").map_err(map_db_err)?,
        label: row.try_get("label").map_err(map_db_err)?,
        label_plural: row.try_get("label_plural").map_err(map_db_err)?,
        description: row.try_get("description").map_err(map_db_err)?,
        system: row.try_get::<i64, _>("system").map_err(map_db_err)? != 0,
        workflow_key: row.try_get("workflow_key").map_err(map_db_err)?,
        display_field: row.try_get("display_field").map_err(map_db_err)?,
        module: row.try_get("module").map_err(map_db_err)?,
        fields,
    })
}
