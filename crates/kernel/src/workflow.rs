//! Workflow definitions storage and lookup.
//!
//! Phase 1 covers defining/loading workflows and resolving a type's initial state
//! (needed when creating records). Transition execution, tasks, and approvals are
//! layered on in Phase 2 (see `transition.rs`).

use crate::audit::{event_from, insert_audit};
use crate::store::map_db_err;
use crate::Kernel;
use latentdb_contracts::{ids, Action, ApiError, AuthContext, WorkflowDef};
use sqlx::Row;

impl Kernel {
    /// Register (or overwrite) a workflow definition. Requires `configure` on
    /// `workflows`.
    pub async fn create_workflow(
        &self,
        ctx: &AuthContext,
        def: &WorkflowDef,
    ) -> latentdb_contracts::Result<WorkflowDef> {
        self.authorize(ctx, Action::Configure, "workflows", None).await?;
        validate_workflow(def)?;
        let now = ids::now_rfc3339();
        let definition_json = serde_json::to_string(def)
            .map_err(|e| ApiError::internal(format!("serialize workflow: {e}")))?;

        let mut tx = self.pool().begin().await.map_err(map_db_err)?;
        sqlx::query(
            r#"INSERT INTO workflows (id, tenant_id, key, object_type, name, definition_json, created_at)
               VALUES (?,?,?,?,?,?,?)
               ON CONFLICT(tenant_id, key) DO UPDATE SET
                 object_type = excluded.object_type,
                 name = excluded.name,
                 definition_json = excluded.definition_json"#,
        )
        .bind(ids::new_id())
        .bind(&ctx.tenant_id)
        .bind(&def.key)
        .bind(&def.object_type)
        .bind(&def.name)
        .bind(&definition_json)
        .bind(&now)
        .execute(&mut *tx)
        .await
        .map_err(map_db_err)?;
        let ev = event_from(ctx, "workflow.create", Some("workflow"), Some(&def.key), None,
            Some(serde_json::json!({"object_type": def.object_type, "states": def.states.len()})));
        insert_audit(&mut tx, &ev).await?;
        tx.commit().await.map_err(map_db_err)?;
        Ok(def.clone())
    }

    pub async fn get_workflow(
        &self,
        ctx: &AuthContext,
        key: &str,
    ) -> latentdb_contracts::Result<WorkflowDef> {
        self.authorize(ctx, Action::Read, "workflows", None).await?;
        self.load_workflow(&ctx.tenant_id, key)
            .await?
            .ok_or_else(|| ApiError::not_found("workflow not found"))
    }

    pub async fn list_workflows(
        &self,
        ctx: &AuthContext,
    ) -> latentdb_contracts::Result<Vec<WorkflowDef>> {
        self.authorize(ctx, Action::Read, "workflows", None).await?;
        let rows = sqlx::query("SELECT definition_json FROM workflows WHERE tenant_id = ? ORDER BY key")
            .bind(&ctx.tenant_id)
            .fetch_all(self.pool())
            .await
            .map_err(map_db_err)?;
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            let json: String = row.try_get("definition_json").map_err(map_db_err)?;
            if let Ok(def) = serde_json::from_str::<WorkflowDef>(&json) {
                out.push(def);
            }
        }
        Ok(out)
    }

    /// Internal: load a workflow definition by key (no auth — callers have
    /// authorized the surrounding operation).
    pub(crate) async fn load_workflow(
        &self,
        tenant_id: &str,
        key: &str,
    ) -> latentdb_contracts::Result<Option<WorkflowDef>> {
        let row = sqlx::query("SELECT definition_json FROM workflows WHERE tenant_id = ? AND key = ?")
            .bind(tenant_id)
            .bind(key)
            .fetch_optional(self.pool())
            .await
            .map_err(map_db_err)?;
        match row {
            None => Ok(None),
            Some(row) => {
                let json: String = row.try_get("definition_json").map_err(map_db_err)?;
                Ok(serde_json::from_str(&json).ok())
            }
        }
    }

    /// Resolve the initial workflow state for an object type, if it has a
    /// workflow. Used when creating records.
    pub(crate) async fn workflow_initial_state(
        &self,
        tenant_id: &str,
        workflow_key: &str,
    ) -> latentdb_contracts::Result<Option<String>> {
        Ok(self
            .load_workflow(tenant_id, workflow_key)
            .await?
            .map(|w| w.initial_state))
    }
}

fn validate_workflow(def: &WorkflowDef) -> latentdb_contracts::Result<()> {
    if def.key.trim().is_empty() || def.object_type.trim().is_empty() {
        return Err(ApiError::validation("workflow key and object_type are required"));
    }
    if def.state(&def.initial_state).is_none() {
        return Err(ApiError::validation("initial_state must be one of the states"));
    }
    for t in &def.transitions {
        if def.state(&t.from).is_none() || def.state(&t.to).is_none() {
            return Err(ApiError::validation(format!(
                "transition '{}' references unknown state",
                t.key
            )));
        }
    }
    Ok(())
}
