//! First-run migration service.
//!
//! A brand-new tenant usually already runs *some* model — a set of installed
//! object types with records inside them (their **old system**). Onboarding lets
//! them keep booting that old system while they evaluate a **selected system**
//! (one of the Builder templates) to migrate onto.
//!
//! Everything here is **non-destructive**. Selecting a target, planning, and even
//! the report emitted at logout never move, rewrite, or delete a single record.
//! The headline output is a [`MigrationReport`]: an inventory of the old system,
//! or — once a target is chosen — a field-level plan describing exactly how the
//! old data would land in the selected system, including every conflict a human
//! must resolve first.
//!
//! There is one session per tenant (the `migration_sessions` table), keyed by
//! `tenant_id`. Like every other kernel service, each public method authorizes
//! through [`Kernel::authorize`] and audits its mutations.

use crate::audit::event_from;
use crate::store::map_db_err;
use crate::{builder, Kernel};
use latentdb_contracts::{
    ids, Action, ApiError, AuthContext, BuilderDefinition, ConflictKind, FieldDefinition,
    FieldMapping, MappingStatus, MigrationConflict, MigrationPlan, MigrationReport,
    MigrationSession, MigrationStatus, MigrationSummary, ObjectMapping, ObjectTypeDef, SystemKind,
    SystemObject, SystemSnapshot,
};
// `FieldType` is reached transitively via `FieldDefinition::field_type`.
use sqlx::Row;
use std::collections::HashMap;

const RESOURCE: &str = "migration";
const OLD_SYSTEM_KEY: &str = "installed";
const OLD_SYSTEM_LABEL: &str = "Your current (old) system";

impl Kernel {
    /// Begin (or re-capture) a first-run migration session for the caller's
    /// tenant. Snapshots the old system as it stands and, optionally, records a
    /// selected target template. The tenant stays booted into the old system;
    /// nothing is migrated. Idempotent — re-running refreshes the snapshot.
    pub async fn start_migration(
        &self,
        ctx: &AuthContext,
        target_system_key: Option<&str>,
    ) -> latentdb_contracts::Result<MigrationSession> {
        self.authorize(ctx, Action::Configure, RESOURCE, None)
            .await?;

        if let Some(key) = target_system_key {
            ensure_template(key)?;
        }

        let (old_objects, counts) = self.old_objects_and_counts(ctx).await?;
        let snapshot = snapshot_from_objects(&old_objects, &counts);
        let snapshot_json = serde_json::to_string(&snapshot)
            .map_err(|e| ApiError::internal(format!("serialize snapshot: {e}")))?;

        let status = if target_system_key.is_some() {
            MigrationStatus::TargetSelected
        } else {
            MigrationStatus::BootedOld
        };
        let now = ids::now_rfc3339();

        sqlx::query(
            r#"INSERT INTO migration_sessions
                 (tenant_id, status, active_system, selected_system_key, snapshot_json, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?)
               ON CONFLICT(tenant_id) DO UPDATE SET
                 status = excluded.status,
                 selected_system_key = excluded.selected_system_key,
                 snapshot_json = excluded.snapshot_json,
                 updated_at = excluded.updated_at"#,
        )
        .bind(&ctx.tenant_id)
        .bind(status.as_str())
        // A first run always boots the old system.
        .bind(SystemKind::Old.as_str())
        .bind(target_system_key)
        .bind(&snapshot_json)
        .bind(&now)
        .bind(&now)
        .execute(self.pool())
        .await
        .map_err(map_db_err)?;

        let ev = event_from(
            ctx,
            "migration.start",
            Some(RESOURCE),
            None,
            None,
            Some(serde_json::json!({
                "objects": snapshot.objects.len(),
                "records": snapshot.total_records(),
                "target": target_system_key,
            })),
        );
        self.audit(&ev).await?;

        self.require_session(ctx).await
    }

    /// The current migration session for the tenant, or `None` if onboarding was
    /// never started.
    pub async fn get_migration(
        &self,
        ctx: &AuthContext,
    ) -> latentdb_contracts::Result<Option<MigrationSession>> {
        self.authorize(ctx, Action::Read, RESOURCE, None).await?;
        self.load_session(&ctx.tenant_id).await
    }

    /// Choose (or change) the selected target system. The old system is untouched.
    pub async fn select_target_system(
        &self,
        ctx: &AuthContext,
        target_system_key: &str,
    ) -> latentdb_contracts::Result<MigrationSession> {
        self.authorize(ctx, Action::Configure, RESOURCE, None)
            .await?;
        ensure_template(target_system_key)?;
        self.require_session(ctx).await?; // must have started

        let now = ids::now_rfc3339();
        sqlx::query(
            "UPDATE migration_sessions SET selected_system_key = ?, status = ?, updated_at = ? WHERE tenant_id = ?",
        )
        .bind(target_system_key)
        .bind(MigrationStatus::TargetSelected.as_str())
        .bind(&now)
        .bind(&ctx.tenant_id)
        .execute(self.pool())
        .await
        .map_err(map_db_err)?;

        let ev = event_from(
            ctx,
            "migration.select_target",
            Some(RESOURCE),
            None,
            None,
            Some(serde_json::json!({ "target": target_system_key })),
        );
        self.audit(&ev).await?;
        self.require_session(ctx).await
    }

    /// Switch which system the tenant is booted into. Choosing
    /// [`SystemKind::Selected`] requires a target to already be selected; it only
    /// re-points the session (so logout output is rendered for that system) and
    /// never migrates data.
    pub async fn set_active_system(
        &self,
        ctx: &AuthContext,
        active: SystemKind,
    ) -> latentdb_contracts::Result<MigrationSession> {
        self.authorize(ctx, Action::Configure, RESOURCE, None)
            .await?;
        let session = self.require_session(ctx).await?;

        if active == SystemKind::Selected && session.selected_system_key.is_none() {
            return Err(ApiError::failed_precondition(
                "select a target system before activating it",
            ));
        }

        // Booting the old system never downgrades a session that has reported.
        let status = match (active, session.status) {
            (SystemKind::Selected, MigrationStatus::BootedOld) => MigrationStatus::TargetSelected,
            (_, current) => current,
        };
        let now = ids::now_rfc3339();
        sqlx::query(
            "UPDATE migration_sessions SET active_system = ?, status = ?, updated_at = ? WHERE tenant_id = ?",
        )
        .bind(active.as_str())
        .bind(status.as_str())
        .bind(&now)
        .bind(&ctx.tenant_id)
        .execute(self.pool())
        .await
        .map_err(map_db_err)?;

        let ev = event_from(
            ctx,
            "migration.set_active_system",
            Some(RESOURCE),
            None,
            None,
            Some(serde_json::json!({ "active": active.as_str() })),
        );
        self.audit(&ev).await?;
        self.require_session(ctx).await
    }

    /// Compute the live old -> selected mapping. Requires a selected target.
    pub async fn plan_migration(
        &self,
        ctx: &AuthContext,
    ) -> latentdb_contracts::Result<MigrationPlan> {
        self.authorize(ctx, Action::Read, RESOURCE, None).await?;
        let session = self.require_session(ctx).await?;
        let target_key = session.selected_system_key.ok_or_else(|| {
            ApiError::failed_precondition("no target system selected to plan against")
        })?;
        let template_objects = ensure_template(&target_key)?;
        let (old_objects, counts) = self.old_objects_and_counts(ctx).await?;
        Ok(build_plan(
            &target_key,
            &old_objects,
            &counts,
            &template_objects,
        ))
    }

    /// Produce — and persist — the migration report for one system. This is the
    /// "output appropriate to either the old or the selected system": for
    /// [`SystemKind::Old`] an inventory of the current system; for
    /// [`SystemKind::Selected`] the full migration plan. Non-destructive.
    pub async fn migration_report(
        &self,
        ctx: &AuthContext,
        for_system: SystemKind,
    ) -> latentdb_contracts::Result<MigrationReport> {
        self.authorize(ctx, Action::Read, RESOURCE, None).await?;
        self.require_session(ctx).await?;
        self.generate_and_store_report(ctx, for_system).await
    }

    /// Called from the logout path with a tenant-scoped system context. If the
    /// tenant has a first-run migration session, emit the report for whichever
    /// system is currently active and return it; otherwise `None`. Errors here
    /// are swallowed by the caller so a report never blocks logout.
    pub(crate) async fn logout_migration_output(
        &self,
        ctx: &AuthContext,
    ) -> latentdb_contracts::Result<Option<MigrationReport>> {
        let Some(session) = self.load_session(&ctx.tenant_id).await? else {
            return Ok(None);
        };
        let report = self
            .generate_and_store_report(ctx, session.active_system)
            .await?;
        Ok(Some(report))
    }

    // ----- internals ---------------------------------------------------------

    /// Build the report, persist it on the session (status -> reported), audit and
    /// emit an event. Shared by the on-demand and logout paths.
    async fn generate_and_store_report(
        &self,
        ctx: &AuthContext,
        for_system: SystemKind,
    ) -> latentdb_contracts::Result<MigrationReport> {
        let session = self.require_session(ctx).await?;
        let (old_objects, counts) = self.old_objects_and_counts(ctx).await?;
        let report = build_report(
            &ctx.tenant_id,
            for_system,
            &old_objects,
            &counts,
            session.selected_system_key.as_deref(),
        );
        let report_json = serde_json::to_string(&report)
            .map_err(|e| ApiError::internal(format!("serialize report: {e}")))?;
        let now = ids::now_rfc3339();
        sqlx::query(
            "UPDATE migration_sessions SET last_report_json = ?, status = ?, updated_at = ? WHERE tenant_id = ?",
        )
        .bind(&report_json)
        .bind(MigrationStatus::Reported.as_str())
        .bind(&now)
        .bind(&ctx.tenant_id)
        .execute(self.pool())
        .await
        .map_err(map_db_err)?;

        let ev = event_from(
            ctx,
            "migration.report",
            Some(RESOURCE),
            None,
            None,
            Some(serde_json::json!({
                "for_system": for_system.as_str(),
                "source_records": report.summary.source_records,
                "records_mappable": report.summary.records_mappable,
                "conflicts": report.summary.conflicts,
            })),
        );
        self.audit(&ev).await?;
        self.emit_event(
            ctx,
            "migration.report_generated",
            serde_json::json!({ "for_system": for_system.as_str() }),
        )
        .await?;
        Ok(report)
    }

    /// Load the tenant's object types (live) plus a `type -> active record count`
    /// map. The pair is everything the snapshot and planner need.
    async fn old_objects_and_counts(
        &self,
        ctx: &AuthContext,
    ) -> latentdb_contracts::Result<(Vec<ObjectTypeDef>, HashMap<String, i64>)> {
        let objects = self.list_object_types(ctx).await?;
        let counts = self.active_record_counts(&ctx.tenant_id).await?;
        Ok((objects, counts))
    }

    /// One grouped query: active record counts per object type for a tenant.
    async fn active_record_counts(
        &self,
        tenant_id: &str,
    ) -> latentdb_contracts::Result<HashMap<String, i64>> {
        let rows = sqlx::query(
            "SELECT object_type, COUNT(*) AS c FROM records WHERE tenant_id = ? AND lifecycle = 'active' GROUP BY object_type",
        )
        .bind(tenant_id)
        .fetch_all(self.pool())
        .await
        .map_err(map_db_err)?;
        let mut map = HashMap::with_capacity(rows.len());
        for row in &rows {
            let key: String = row.try_get("object_type").map_err(map_db_err)?;
            let count: i64 = row.try_get("c").map_err(map_db_err)?;
            map.insert(key, count);
        }
        Ok(map)
    }

    async fn load_session(
        &self,
        tenant_id: &str,
    ) -> latentdb_contracts::Result<Option<MigrationSession>> {
        let row = sqlx::query("SELECT * FROM migration_sessions WHERE tenant_id = ?")
            .bind(tenant_id)
            .fetch_optional(self.pool())
            .await
            .map_err(map_db_err)?;
        match row {
            None => Ok(None),
            Some(row) => Ok(Some(row_to_session(&row)?)),
        }
    }

    async fn require_session(
        &self,
        ctx: &AuthContext,
    ) -> latentdb_contracts::Result<MigrationSession> {
        self.load_session(&ctx.tenant_id).await?.ok_or_else(|| {
            ApiError::failed_precondition("no migration session; call start_migration first")
        })
    }
}

/// Validate that a target template key names a built-in template, returning its
/// object definitions.
fn ensure_template(key: &str) -> latentdb_contracts::Result<Vec<BuilderDefinition>> {
    builder::template_by_key(key)
        .map(|t| t.objects)
        .ok_or_else(|| ApiError::not_found(format!("unknown target system '{key}'")))
}

fn snapshot_from_objects(
    objects: &[ObjectTypeDef],
    counts: &HashMap<String, i64>,
) -> SystemSnapshot {
    let objs = objects
        .iter()
        .map(|o| SystemObject {
            key: o.key.clone(),
            label: o.label.clone(),
            module: o.module.clone(),
            field_keys: o.fields.iter().map(|f| f.key.clone()).collect(),
            record_count: counts.get(&o.key).copied().unwrap_or(0),
        })
        .collect();
    SystemSnapshot {
        kind: SystemKind::Old,
        key: OLD_SYSTEM_KEY.into(),
        label: OLD_SYSTEM_LABEL.into(),
        objects: objs,
    }
}

/// Build the field-by-field mapping of one old object onto one target object.
/// Appends any conflicts it discovers to `conflicts`.
fn map_fields(
    target_key: &str,
    source: &ObjectTypeDef,
    target_fields: &[FieldDefinition],
    conflicts: &mut Vec<MigrationConflict>,
) -> Vec<FieldMapping> {
    let mut mappings = Vec::new();
    let target_keys: Vec<&str> = target_fields.iter().map(|f| f.key.as_str()).collect();

    for tf in target_fields {
        match source.field(&tf.key) {
            Some(sf) if sf.field_type == tf.field_type => mappings.push(FieldMapping {
                source_field: Some(sf.key.clone()),
                target_field: Some(tf.key.clone()),
                source_type: Some(sf.field_type),
                target_type: Some(tf.field_type),
                status: MappingStatus::Mapped,
            }),
            Some(sf) => {
                conflicts.push(MigrationConflict {
                    kind: ConflictKind::TypeMismatch,
                    object: target_key.to_string(),
                    field: Some(tf.key.clone()),
                    detail: format!(
                        "field '{}' is {:?} in the old system but {:?} in the selected system",
                        tf.key, sf.field_type, tf.field_type
                    ),
                });
                mappings.push(FieldMapping {
                    source_field: Some(sf.key.clone()),
                    target_field: Some(tf.key.clone()),
                    source_type: Some(sf.field_type),
                    target_type: Some(tf.field_type),
                    status: MappingStatus::TypeMismatch,
                });
            }
            None => {
                let status = if tf.required {
                    conflicts.push(MigrationConflict {
                        kind: ConflictKind::MissingRequiredTarget,
                        object: target_key.to_string(),
                        field: Some(tf.key.clone()),
                        detail: format!(
                            "required field '{}' has no source value; imported records need a default",
                            tf.key
                        ),
                    });
                    MappingStatus::MissingRequiredInTarget
                } else {
                    MappingStatus::AddedInTarget
                };
                mappings.push(FieldMapping {
                    source_field: None,
                    target_field: Some(tf.key.clone()),
                    source_type: None,
                    target_type: Some(tf.field_type),
                    status,
                });
            }
        }
    }

    // Source fields that have no home in the target — their data is dropped.
    for sf in &source.fields {
        if !target_keys.contains(&sf.key.as_str()) {
            conflicts.push(MigrationConflict {
                kind: ConflictKind::DroppedField,
                object: target_key.to_string(),
                field: Some(sf.key.clone()),
                detail: format!(
                    "old field '{}' has no counterpart in the selected system and would not be carried over",
                    sf.key
                ),
            });
            mappings.push(FieldMapping {
                source_field: Some(sf.key.clone()),
                target_field: None,
                source_type: Some(sf.field_type),
                target_type: None,
                status: MappingStatus::DroppedFromSource,
            });
        }
    }

    mappings
}

fn build_plan(
    target_key: &str,
    old_objects: &[ObjectTypeDef],
    counts: &HashMap<String, i64>,
    target_objects: &[BuilderDefinition],
) -> MigrationPlan {
    let old_by_key: HashMap<&str, &ObjectTypeDef> =
        old_objects.iter().map(|o| (o.key.as_str(), o)).collect();
    let target_by_key: HashMap<&str, &BuilderDefinition> =
        target_objects.iter().map(|o| (o.key.as_str(), o)).collect();

    let mut object_mappings = Vec::new();
    let mut conflicts = Vec::new();
    let mut mapped_objects = 0usize;
    let mut records_mappable = 0i64;

    // Target objects: matched to a source, or brand new.
    for def in target_objects {
        match old_by_key.get(def.key.as_str()) {
            Some(source) => {
                mapped_objects += 1;
                let record_count = counts.get(&def.key).copied().unwrap_or(0);
                records_mappable += record_count;
                let field_mappings = map_fields(&def.key, source, &def.fields, &mut conflicts);
                object_mappings.push(ObjectMapping {
                    source_object: Some(def.key.clone()),
                    target_object: Some(def.key.clone()),
                    label: def.label.clone(),
                    record_count,
                    field_mappings,
                    note: None,
                });
            }
            None => {
                let field_mappings = def
                    .fields
                    .iter()
                    .map(|tf| FieldMapping {
                        source_field: None,
                        target_field: Some(tf.key.clone()),
                        source_type: None,
                        target_type: Some(tf.field_type),
                        status: MappingStatus::AddedInTarget,
                    })
                    .collect();
                object_mappings.push(ObjectMapping {
                    source_object: None,
                    target_object: Some(def.key.clone()),
                    label: def.label.clone(),
                    record_count: 0,
                    field_mappings,
                    note: Some(
                        "New object type in the selected system; no existing data to import."
                            .into(),
                    ),
                });
            }
        }
    }

    // Old objects with no counterpart: data stays in the old system.
    for source in old_objects {
        if !target_by_key.contains_key(source.key.as_str()) {
            let record_count = counts.get(&source.key).copied().unwrap_or(0);
            conflicts.push(MigrationConflict {
                kind: ConflictKind::UnmappedSourceObject,
                object: source.key.clone(),
                field: None,
                detail: format!(
                    "'{}' ({} record(s)) has no counterpart in the selected system",
                    source.key, record_count
                ),
            });
            let field_mappings = source
                .fields
                .iter()
                .map(|sf| FieldMapping {
                    source_field: Some(sf.key.clone()),
                    target_field: None,
                    source_type: Some(sf.field_type),
                    target_type: None,
                    status: MappingStatus::DroppedFromSource,
                })
                .collect();
            object_mappings.push(ObjectMapping {
                source_object: Some(source.key.clone()),
                target_object: None,
                label: source.label.clone(),
                record_count,
                field_mappings,
                note: Some(
                    "No counterpart in the selected system; this data stays in the old system."
                        .into(),
                ),
            });
        }
    }

    let source_system = snapshot_from_objects(old_objects, counts);
    let source_records = source_system.total_records();
    let target_system = target_snapshot(target_key, target_objects, &old_by_key, counts);

    let summary = MigrationSummary {
        source_objects: old_objects.len(),
        target_objects: target_objects.len(),
        mapped_objects,
        source_records,
        records_mappable,
        records_unmapped: source_records - records_mappable,
        conflicts: conflicts.len(),
    };

    MigrationPlan {
        source_system,
        target_system,
        object_mappings,
        conflicts,
        summary,
    }
}

/// Build a snapshot for the selected system from its template, projecting the
/// record counts that would land in each object.
fn target_snapshot(
    target_key: &str,
    target_objects: &[BuilderDefinition],
    old_by_key: &HashMap<&str, &ObjectTypeDef>,
    counts: &HashMap<String, i64>,
) -> SystemSnapshot {
    let objs = target_objects
        .iter()
        .map(|def| SystemObject {
            key: def.key.clone(),
            label: def.label.clone(),
            module: def.module.clone(),
            field_keys: def.fields.iter().map(|f| f.key.clone()).collect(),
            record_count: if old_by_key.contains_key(def.key.as_str()) {
                counts.get(&def.key).copied().unwrap_or(0)
            } else {
                0
            },
        })
        .collect();
    SystemSnapshot {
        kind: SystemKind::Selected,
        key: target_key.to_string(),
        label: format!("Selected system: {target_key}"),
        objects: objs,
    }
}

fn build_report(
    tenant_id: &str,
    for_system: SystemKind,
    old_objects: &[ObjectTypeDef],
    counts: &HashMap<String, i64>,
    selected_key: Option<&str>,
) -> MigrationReport {
    let source_system = snapshot_from_objects(old_objects, counts);
    let source_records = source_system.total_records();

    // A plan exists only when a target is selected and we're reporting for it.
    let plan = match (for_system, selected_key) {
        (SystemKind::Selected, Some(key)) => {
            builder::template_by_key(key).map(|t| build_plan(key, old_objects, counts, &t.objects))
        }
        _ => None,
    };

    let (target_system, summary, mut notes) = match (&plan, for_system, selected_key) {
        (Some(plan), _, _) => (
            Some(plan.target_system.clone()),
            plan.summary.clone(),
            vec![
                "This is a plan only — no records were moved, rewritten, or deleted.".to_string(),
                format!(
                    "{} of {} record(s) map onto the selected system; {} stay in the old system.",
                    plan.summary.records_mappable,
                    plan.summary.source_records,
                    plan.summary.records_unmapped
                ),
            ],
        ),
        (None, SystemKind::Old, _) => (
            None,
            old_only_summary(&source_system),
            vec![
                "Inventory of your current (old) system. You can keep booting it; nothing here has changed.".to_string(),
            ],
        ),
        (None, SystemKind::Selected, _) => (
            None,
            old_only_summary(&source_system),
            vec![
                "No target system is selected, so there is nothing to migrate onto yet. Showing the old-system inventory.".to_string(),
            ],
        ),
    };

    if let Some(plan) = &plan {
        if plan.summary.conflicts > 0 {
            notes.push(format!(
                "{} conflict(s) need a decision before a clean import — see `plan.conflicts`.",
                plan.summary.conflicts
            ));
        } else {
            notes.push("No conflicts detected; the selected system is a clean fit.".to_string());
        }
    }
    notes.push(format!(
        "Old system: {} object type(s), {} active record(s).",
        source_system.objects.len(),
        source_records
    ));

    MigrationReport {
        id: ids::new_id(),
        tenant_id: tenant_id.to_string(),
        generated_at: ids::now_rfc3339(),
        for_system,
        source_system,
        target_system,
        plan,
        summary,
        notes,
    }
}

fn old_only_summary(source: &SystemSnapshot) -> MigrationSummary {
    let source_records = source.total_records();
    MigrationSummary {
        source_objects: source.objects.len(),
        target_objects: 0,
        mapped_objects: 0,
        source_records,
        records_mappable: 0,
        records_unmapped: source_records,
        conflicts: 0,
    }
}

fn row_to_session(row: &sqlx::sqlite::SqliteRow) -> latentdb_contracts::Result<MigrationSession> {
    let snapshot_json: String = row.try_get("snapshot_json").map_err(map_db_err)?;
    let old_system: SystemSnapshot =
        serde_json::from_str(&snapshot_json).unwrap_or_else(|_| SystemSnapshot {
            kind: SystemKind::Old,
            key: OLD_SYSTEM_KEY.into(),
            label: OLD_SYSTEM_LABEL.into(),
            objects: Vec::new(),
        });
    let last_report = row
        .try_get::<Option<String>, _>("last_report_json")
        .map_err(map_db_err)?
        .and_then(|s| serde_json::from_str(&s).ok());
    let active_system = SystemKind::parse(
        &row.try_get::<String, _>("active_system")
            .map_err(map_db_err)?,
    )
    .unwrap_or(SystemKind::Old);
    Ok(MigrationSession {
        tenant_id: row.try_get("tenant_id").map_err(map_db_err)?,
        status: MigrationStatus::parse(&row.try_get::<String, _>("status").map_err(map_db_err)?),
        active_system,
        selected_system_key: row.try_get("selected_system_key").map_err(map_db_err)?,
        old_system,
        last_report,
        created_at: row.try_get("created_at").map_err(map_db_err)?,
        updated_at: row.try_get("updated_at").map_err(map_db_err)?,
    })
}
