//! First-run migration tests.
//!
//! Exercise the onboarding flow end-to-end against an in-memory store: snapshot
//! the old system, select a target template, plan the old -> selected mapping
//! (counts + conflicts), and confirm logout emits the non-destructive report for
//! whichever system the user is booted into. Fully offline.

use latentdb_contracts::{
    AuthContext, ConflictKind, FieldDefinition, FieldType, MappingStatus, MigrationStatus,
    NewRecord, ObjectTypeDef, Source, SystemKind,
};
use latentdb_kernel::Kernel;
use serde_json::{json, Map, Value};

fn obj(v: Value) -> Map<String, Value> {
    v.as_object().cloned().unwrap_or_default()
}

/// Bootstrap a tenant; return the admin context and the live session token.
async fn bootstrap_admin(k: &Kernel, slug: &str) -> (AuthContext, String) {
    k.bootstrap_tenant(
        &format!("TestCo {slug}"),
        slug,
        "admin@example.test",
        "Admin",
        "pw-admin-123",
    )
    .await
    .expect("bootstrap");
    let login = k
        .login(
            slug,
            "admin@example.test",
            "pw-admin-123",
            "req-1",
            Source::Api,
        )
        .await
        .expect("login");
    let ctx = k
        .authenticate(&login.token, "req-2", Source::Api)
        .await
        .expect("authenticate");
    (ctx, login.token)
}

async fn create_type(
    k: &Kernel,
    ctx: &AuthContext,
    key: &str,
    display: &str,
    fields: Vec<FieldDefinition>,
) {
    let def = ObjectTypeDef {
        id: String::new(),
        key: key.into(),
        label: key.into(),
        label_plural: None,
        description: None,
        system: false,
        workflow_key: None,
        display_field: Some(display.into()),
        module: Some("legacy".into()),
        fields,
    };
    k.create_object_type(ctx, &def)
        .await
        .expect("create object type");
}

async fn create_record(k: &Kernel, ctx: &AuthContext, object_type: &str, data: Value) {
    k.create_record(
        ctx,
        &NewRecord {
            object_type: object_type.into(),
            data: obj(data),
            workspace_id: None,
        },
    )
    .await
    .expect("create record");
}

/// Build an "old system" that overlaps the `finance` template in interesting ways:
/// `account` (with a type-mismatched `tier`), `invoice` (with a `legacy_code`
/// field that has no target), and `widget` (no counterpart at all). Returns nothing
/// but leaves 2 accounts, 3 invoices, and 1 widget behind.
async fn seed_old_system(k: &Kernel, ctx: &AuthContext) {
    create_type(
        k,
        ctx,
        "account",
        "name",
        vec![
            FieldDefinition::new("name", "Name", FieldType::Text)
                .required()
                .display(),
            FieldDefinition::new("email", "Email", FieldType::Text),
            // Old `tier` is free text; the finance template models it as an enum.
            FieldDefinition::new("tier", "Tier", FieldType::Text),
        ],
    )
    .await;
    create_type(
        k,
        ctx,
        "invoice",
        "number",
        vec![
            FieldDefinition::new("number", "Number", FieldType::Text)
                .required()
                .display(),
            FieldDefinition::new("amount", "Amount", FieldType::Money)
                .required()
                .display(),
            FieldDefinition::new("status", "Status", FieldType::Enum).options(&["draft", "paid"]),
            // Has no home in the finance template -> dropped.
            FieldDefinition::new("legacy_code", "Legacy Code", FieldType::Text),
        ],
    )
    .await;
    create_type(
        k,
        ctx,
        "widget",
        "name",
        vec![
            FieldDefinition::new("name", "Name", FieldType::Text)
                .required()
                .display(),
            FieldDefinition::new("color", "Color", FieldType::Text),
        ],
    )
    .await;

    for i in 1..=2 {
        create_record(
            k,
            ctx,
            "account",
            json!({"name": format!("Acct {i}"), "email": format!("a{i}@old.test"), "tier": "gold"}),
        )
        .await;
    }
    for i in 1..=3 {
        create_record(
            k,
            ctx,
            "invoice",
            json!({"number": format!("INV-{i}"), "amount": i * 1000, "status": "draft", "legacy_code": "X"}),
        )
        .await;
    }
    create_record(k, ctx, "widget", json!({"name": "W1", "color": "red"})).await;
}

#[tokio::test]
async fn start_snapshots_old_system_and_boots_it() {
    let k = Kernel::in_memory().await.unwrap();
    let (ctx, _tok) = bootstrap_admin(&k, "co-start").await;
    seed_old_system(&k, &ctx).await;

    let session = k.start_migration(&ctx, None).await.unwrap();
    assert_eq!(session.status, MigrationStatus::BootedOld);
    assert_eq!(session.active_system, SystemKind::Old);
    assert!(session.selected_system_key.is_none());
    // Snapshot captured all three old object types with live counts.
    assert_eq!(session.old_system.objects.len(), 3);
    assert_eq!(session.old_system.total_records(), 6);

    // get_migration round-trips the session.
    let fetched = k.get_migration(&ctx).await.unwrap().expect("session");
    assert_eq!(fetched.old_system.total_records(), 6);
}

#[tokio::test]
async fn get_migration_is_none_before_start() {
    let k = Kernel::in_memory().await.unwrap();
    let (ctx, _tok) = bootstrap_admin(&k, "co-none").await;
    assert!(k.get_migration(&ctx).await.unwrap().is_none());
}

#[tokio::test]
async fn select_unknown_target_is_not_found() {
    let k = Kernel::in_memory().await.unwrap();
    let (ctx, _tok) = bootstrap_admin(&k, "co-bad").await;
    k.start_migration(&ctx, None).await.unwrap();
    let err = k
        .select_target_system(&ctx, "does-not-exist")
        .await
        .unwrap_err();
    assert_eq!(err.code, latentdb_contracts::ErrorCode::NotFound);
}

#[tokio::test]
async fn plan_maps_old_onto_selected_with_conflicts() {
    let k = Kernel::in_memory().await.unwrap();
    let (ctx, _tok) = bootstrap_admin(&k, "co-plan").await;
    seed_old_system(&k, &ctx).await;
    k.start_migration(&ctx, Some("finance")).await.unwrap();

    let plan = k.plan_migration(&ctx).await.unwrap();

    // Summary roll-up.
    assert_eq!(plan.summary.source_objects, 3);
    assert_eq!(plan.summary.target_objects, 4); // account, invoice, payment, budget
    assert_eq!(plan.summary.mapped_objects, 2); // account + invoice
    assert_eq!(plan.summary.source_records, 6);
    assert_eq!(plan.summary.records_mappable, 5); // 2 accounts + 3 invoices
    assert_eq!(plan.summary.records_unmapped, 1); // the widget
                                                  // tier type mismatch + dropped legacy_code + unmapped widget.
    assert_eq!(plan.summary.conflicts, 3);

    // The three distinct conflict kinds are all present.
    let has = |kind: ConflictKind| plan.conflicts.iter().any(|c| c.kind == kind);
    assert!(has(ConflictKind::TypeMismatch));
    assert!(has(ConflictKind::DroppedField));
    assert!(has(ConflictKind::UnmappedSourceObject));

    // The account.tier field mapping is flagged as a type mismatch.
    let account = plan
        .object_mappings
        .iter()
        .find(|m| m.target_object.as_deref() == Some("account"))
        .expect("account mapping");
    let tier = account
        .field_mappings
        .iter()
        .find(|f| f.target_field.as_deref() == Some("tier"))
        .expect("tier mapping");
    assert_eq!(tier.status, MappingStatus::TypeMismatch);

    // The widget has no target; its data stays in the old system.
    let widget = plan
        .object_mappings
        .iter()
        .find(|m| m.source_object.as_deref() == Some("widget"))
        .expect("widget mapping");
    assert!(widget.target_object.is_none());
    assert_eq!(widget.record_count, 1);
}

#[tokio::test]
async fn plan_requires_a_selected_target() {
    let k = Kernel::in_memory().await.unwrap();
    let (ctx, _tok) = bootstrap_admin(&k, "co-noplan").await;
    k.start_migration(&ctx, None).await.unwrap();
    let err = k.plan_migration(&ctx).await.unwrap_err();
    assert_eq!(err.code, latentdb_contracts::ErrorCode::FailedPrecondition);
}

#[tokio::test]
async fn report_for_old_is_an_inventory_with_no_plan() {
    let k = Kernel::in_memory().await.unwrap();
    let (ctx, _tok) = bootstrap_admin(&k, "co-oldrep").await;
    seed_old_system(&k, &ctx).await;
    k.start_migration(&ctx, Some("finance")).await.unwrap();

    let report = k.migration_report(&ctx, SystemKind::Old).await.unwrap();
    assert_eq!(report.for_system, SystemKind::Old);
    assert!(report.plan.is_none());
    assert!(report.target_system.is_none());
    assert_eq!(report.summary.source_records, 6);
    assert_eq!(report.summary.records_mappable, 0);
    assert!(!report.notes.is_empty());
}

#[tokio::test]
async fn activate_selected_requires_a_target_first() {
    let k = Kernel::in_memory().await.unwrap();
    let (ctx, _tok) = bootstrap_admin(&k, "co-act").await;
    k.start_migration(&ctx, None).await.unwrap();
    let err = k
        .set_active_system(&ctx, SystemKind::Selected)
        .await
        .unwrap_err();
    assert_eq!(err.code, latentdb_contracts::ErrorCode::FailedPrecondition);
}

#[tokio::test]
async fn logout_emits_report_for_active_system() {
    let k = Kernel::in_memory().await.unwrap();
    let (ctx, token) = bootstrap_admin(&k, "co-logout").await;
    seed_old_system(&k, &ctx).await;
    k.start_migration(&ctx, Some("finance")).await.unwrap();
    k.set_active_system(&ctx, SystemKind::Selected)
        .await
        .unwrap();

    let report = k
        .logout(&token)
        .await
        .unwrap()
        .expect("active session yields a report");
    assert_eq!(report.for_system, SystemKind::Selected);
    let plan = report.plan.expect("selected report carries a plan");
    assert_eq!(plan.summary.records_mappable, 5);

    // The session record was also persisted as reported.
    let session = k.get_migration(&ctx).await.unwrap().expect("session");
    assert_eq!(session.status, MigrationStatus::Reported);
    assert!(session.last_report.is_some());
}

#[tokio::test]
async fn logout_without_a_migration_session_returns_none() {
    let k = Kernel::in_memory().await.unwrap();
    let (_ctx, token) = bootstrap_admin(&k, "co-plain").await;
    // No start_migration call: a plain logout produces no report.
    assert!(k.logout(&token).await.unwrap().is_none());
}
