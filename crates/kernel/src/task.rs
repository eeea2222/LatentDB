//! Tasks: assignable units of human work (approvals, follow-ups, onboarding steps).
//!
//! Workflow transitions that require approval create an approval-kind task; users
//! and modules can also create ad-hoc tasks. Like everything else, tasks are
//! tenant-scoped and audited.

use crate::audit::{event_from, insert_audit};
use crate::store::map_db_err;
use crate::Kernel;
use latentdb_contracts::{ids, Action, ApiError, AuthContext};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{Row, SqliteConnection};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    pub tenant_id: String,
    pub org_id: String,
    pub kind: String,
    pub title: String,
    pub assignee_id: Option<String>,
    pub status: String,
    pub due_at: Option<String>,
    pub related_object_type: Option<String>,
    pub related_record_id: Option<String>,
    pub data: Value,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Internal insert used by the workflow engine within an existing transaction.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn insert_task(
    conn: &mut SqliteConnection,
    ctx: &AuthContext,
    id: &str,
    kind: &str,
    title: &str,
    assignee_id: Option<&str>,
    related_object_type: Option<&str>,
    related_record_id: Option<&str>,
    data: &Value,
) -> latentdb_contracts::Result<()> {
    let now = ids::now_rfc3339();
    sqlx::query("INSERT INTO tasks (id, tenant_id, org_id, kind, title, assignee_id, status, due_at, related_object_type, related_record_id, data_json, created_by, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
        .bind(id).bind(&ctx.tenant_id).bind(&ctx.org_id).bind(kind).bind(title)
        .bind(assignee_id).bind("open").bind(Option::<String>::None)
        .bind(related_object_type).bind(related_record_id)
        .bind(data.to_string()).bind(&ctx.actor_id).bind(&now).bind(&now)
        .execute(conn).await.map_err(map_db_err)?;
    Ok(())
}

impl Kernel {
    /// Create a standalone task. Requires `create` on `task`.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_task(
        &self,
        ctx: &AuthContext,
        kind: &str,
        title: &str,
        assignee_id: Option<&str>,
        related_object_type: Option<&str>,
        related_record_id: Option<&str>,
        data: Value,
    ) -> latentdb_contracts::Result<Task> {
        self.authorize(ctx, Action::Create, "task", None).await?;
        let id = ids::new_id();
        let mut tx = self.pool().begin().await.map_err(map_db_err)?;
        insert_task(
            &mut tx,
            ctx,
            &id,
            kind,
            title,
            assignee_id,
            related_object_type,
            related_record_id,
            &data,
        )
        .await?;
        let ev = event_from(
            ctx,
            "task.create",
            Some("task"),
            Some(&id),
            None,
            Some(serde_json::json!({"kind": kind, "title": title})),
        );
        insert_audit(&mut tx, &ev).await?;
        tx.commit().await.map_err(map_db_err)?;
        self.get_task(ctx, &id).await
    }

    pub async fn get_task(&self, ctx: &AuthContext, id: &str) -> latentdb_contracts::Result<Task> {
        let row = sqlx::query("SELECT * FROM tasks WHERE tenant_id = ? AND id = ?")
            .bind(&ctx.tenant_id)
            .bind(id)
            .fetch_optional(self.pool())
            .await
            .map_err(map_db_err)?
            .ok_or_else(|| ApiError::not_found("task not found"))?;
        let task = row_to_task(&row)?;
        // Either you can read tasks broadly, or it is assigned to / created by
        // you. The broad check is non-auditing so an assignee viewing their own
        // task does not spam the audit log with permission denials.
        let grants = self.effective_grants(ctx).await?;
        let broad = self.grants_allow(&grants, ctx, Action::Read, "task", None);
        if !broad
            && task.assignee_id.as_deref() != Some(ctx.actor_id.as_str())
            && task.created_by != ctx.actor_id
        {
            self.audit_denial(ctx, "read", "task", Some(id)).await;
            return Err(ApiError::forbidden("not permitted to view this task"));
        }
        Ok(task)
    }

    /// List tasks. With `only_mine`, returns tasks assigned to the caller;
    /// otherwise requires `read` on `task` and returns all tenant tasks.
    pub async fn list_tasks(
        &self,
        ctx: &AuthContext,
        only_mine: bool,
        status: Option<&str>,
    ) -> latentdb_contracts::Result<Vec<Task>> {
        let rows = if only_mine {
            let mut sql =
                String::from("SELECT * FROM tasks WHERE tenant_id = ? AND assignee_id = ?");
            if status.is_some() {
                sql.push_str(" AND status = ?");
            }
            sql.push_str(" ORDER BY created_at DESC");
            let mut q = sqlx::query(&sql).bind(&ctx.tenant_id).bind(&ctx.actor_id);
            if let Some(s) = status {
                q = q.bind(s);
            }
            q.fetch_all(self.pool()).await.map_err(map_db_err)?
        } else {
            self.authorize(ctx, Action::Read, "task", None).await?;
            let mut sql = String::from("SELECT * FROM tasks WHERE tenant_id = ?");
            if status.is_some() {
                sql.push_str(" AND status = ?");
            }
            sql.push_str(" ORDER BY created_at DESC");
            let mut q = sqlx::query(&sql).bind(&ctx.tenant_id);
            if let Some(s) = status {
                q = q.bind(s);
            }
            q.fetch_all(self.pool()).await.map_err(map_db_err)?
        };
        rows.iter().map(row_to_task).collect()
    }

    /// Mark a task complete (or any terminal status). The caller must be the
    /// assignee or have broad task read/manage.
    pub async fn complete_task(
        &self,
        ctx: &AuthContext,
        id: &str,
        status: &str,
    ) -> latentdb_contracts::Result<Task> {
        if !matches!(status, "done" | "cancelled") {
            return Err(ApiError::validation(
                "status must be 'done' or 'cancelled'",
            ));
        }
        let task = self.get_task(ctx, id).await?; // enforces visibility
        if task.status != "open" && task.status != "in_progress" {
            return Err(ApiError::failed_precondition("task is already closed"));
        }
        let now = ids::now_rfc3339();
        let mut tx = self.pool().begin().await.map_err(map_db_err)?;
        sqlx::query("UPDATE tasks SET status = ?, updated_at = ? WHERE tenant_id = ? AND id = ?")
            .bind(status)
            .bind(&now)
            .bind(&ctx.tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(map_db_err)?;
        let ev = event_from(
            ctx,
            "task.update",
            Some("task"),
            Some(id),
            Some(serde_json::json!({"status": task.status})),
            Some(serde_json::json!({"status": status})),
        );
        insert_audit(&mut tx, &ev).await?;
        tx.commit().await.map_err(map_db_err)?;
        self.get_task(ctx, id).await
    }

    /// Internal: close the task(s) tied to an approval (called when an approval is
    /// decided) within an existing transaction.
    pub(crate) async fn close_tasks_for_approval(
        &self,
        conn: &mut SqliteConnection,
        tenant_id: &str,
        approval_id: &str,
        status: &str,
    ) -> latentdb_contracts::Result<()> {
        sqlx::query("UPDATE tasks SET status = ?, updated_at = ? WHERE tenant_id = ? AND json_extract(data_json, '$.approval_id') = ?")
            .bind(status).bind(ids::now_rfc3339()).bind(tenant_id).bind(approval_id)
            .execute(conn).await.map_err(map_db_err)?;
        Ok(())
    }
}

fn row_to_task(row: &sqlx::sqlite::SqliteRow) -> latentdb_contracts::Result<Task> {
    Ok(Task {
        id: row.try_get("id").map_err(map_db_err)?,
        tenant_id: row.try_get("tenant_id").map_err(map_db_err)?,
        org_id: row.try_get("org_id").map_err(map_db_err)?,
        kind: row.try_get("kind").map_err(map_db_err)?,
        title: row.try_get("title").map_err(map_db_err)?,
        assignee_id: row.try_get("assignee_id").map_err(map_db_err)?,
        status: row.try_get("status").map_err(map_db_err)?,
        due_at: row.try_get("due_at").map_err(map_db_err)?,
        related_object_type: row.try_get("related_object_type").map_err(map_db_err)?,
        related_record_id: row.try_get("related_record_id").map_err(map_db_err)?,
        data: row
            .try_get::<String, _>("data_json")
            .map_err(map_db_err)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or(Value::Null),
        created_by: row.try_get("created_by").map_err(map_db_err)?,
        created_at: row.try_get("created_at").map_err(map_db_err)?,
        updated_at: row.try_get("updated_at").map_err(map_db_err)?,
    })
}
