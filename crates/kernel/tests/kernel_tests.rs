//! Phase 1 kernel integration tests.
//!
//! These exercise the platform's non-negotiable guarantees end-to-end against a
//! real (in-memory) SQLite store: tenant isolation, RBAC, field-level and
//! record-level permissions, object CRUD + lifecycle, relations, and
//! audit-on-mutation. They run fully offline.

use latentdb_contracts::{
    AuditQuery, ErrorCode, FieldDefinition, FieldType, NewRecord, ObjectTypeDef, RecordFilter,
    RecordPatch, Source,
};
use latentdb_kernel::Kernel;
use serde_json::{json, Map, Value};

fn obj(json_data: Value) -> Map<String, Value> {
    json_data.as_object().cloned().unwrap_or_default()
}

/// Bootstrap a tenant and return an authenticated admin context.
async fn bootstrap_admin(
    k: &Kernel,
    slug: &str,
) -> latentdb_contracts::AuthContext {
    k.bootstrap_tenant(
        &format!("Acme {slug}"),
        slug,
        "admin@example.com",
        "Admin",
        "pw-admin-123",
    )
    .await
    .expect("bootstrap");
    let login = k
        .login(slug, "admin@example.com", "pw-admin-123", "req-1", Source::Api)
        .await
        .expect("login");
    k.authenticate(&login.token, "req-2", Source::Api)
        .await
        .expect("authenticate")
}

async fn define_invoice_type(k: &Kernel, ctx: &latentdb_contracts::AuthContext) {
    let def = ObjectTypeDef {
        id: String::new(),
        key: "invoice".into(),
        label: "Invoice".into(),
        label_plural: Some("Invoices".into()),
        description: None,
        system: false,
        workflow_key: None,
        display_field: Some("number".into()),
        module: Some("finance".into()),
        fields: vec![
            FieldDefinition::new("number", "Number", FieldType::Text).required().display(),
            FieldDefinition::new("amount", "Amount", FieldType::Money).required().display(),
            FieldDefinition::new("status", "Status", FieldType::Enum)
                .options(&["draft", "submitted", "paid"]),
        ],
    };
    k.create_object_type(ctx, &def).await.expect("create object type");
}

#[tokio::test]
async fn bootstrap_login_and_get_tenant() {
    let k = Kernel::in_memory().await.unwrap();
    let ctx = bootstrap_admin(&k, "acme").await;
    assert_eq!(ctx.role_keys, vec!["tenant_admin".to_string()]);
    assert!(!ctx.is_platform_admin);
    let tenant = k.get_tenant(&ctx).await.unwrap();
    assert_eq!(tenant.slug, "acme");
}

#[tokio::test]
async fn login_rejects_bad_password() {
    let k = Kernel::in_memory().await.unwrap();
    bootstrap_admin(&k, "acme").await;
    let err = k
        .login("acme", "admin@example.com", "wrong", "r", Source::Api)
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Unauthorized);
}

#[tokio::test]
async fn object_crud_emits_audit() {
    let k = Kernel::in_memory().await.unwrap();
    let ctx = bootstrap_admin(&k, "acme").await;
    define_invoice_type(&k, &ctx).await;

    let rec = k
        .create_record(
            &ctx,
            &NewRecord {
                object_type: "invoice".into(),
                data: obj(json!({"number": "INV-1", "amount": 50000, "status": "draft"})),
                workspace_id: None,
            },
        )
        .await
        .expect("create");
    assert_eq!(rec.data.get("number"), Some(&json!("INV-1")));

    // Update.
    let updated = k
        .update_record(&ctx, &rec.id, &RecordPatch { data: obj(json!({"status": "submitted"})) })
        .await
        .expect("update");
    assert_eq!(updated.data.get("status"), Some(&json!("submitted")));

    // List + get.
    let list = k
        .list_records(&ctx, "invoice", &RecordFilter::default())
        .await
        .unwrap();
    assert_eq!(list.total, 1);
    let got = k.get_record(&ctx, &rec.id).await.unwrap();
    assert_eq!(got.id, rec.id);

    // Archive then confirm it leaves active listing.
    k.archive_record(&ctx, &rec.id).await.unwrap();
    let active = k.list_records(&ctx, "invoice", &RecordFilter::default()).await.unwrap();
    assert_eq!(active.total, 0);

    // Audit trail must contain create + update + archive for this record.
    let audit = k
        .audit_query(
            &ctx,
            &AuditQuery {
                target_record_id: Some(rec.id.clone()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let actions: Vec<&str> = audit.iter().map(|e| e.action.as_str()).collect();
    assert!(actions.contains(&"record.create"), "missing create audit: {actions:?}");
    assert!(actions.contains(&"record.update"), "missing update audit");
    assert!(actions.contains(&"record.archive"), "missing archive audit");
}

#[tokio::test]
async fn tenant_isolation_blocks_cross_tenant_access() {
    let k = Kernel::in_memory().await.unwrap();
    let ctx_a = bootstrap_admin(&k, "tenant-a").await;
    define_invoice_type(&k, &ctx_a).await;
    let rec = k
        .create_record(
            &ctx_a,
            &NewRecord {
                object_type: "invoice".into(),
                data: obj(json!({"number": "A-1", "amount": 100, "status": "draft"})),
                workspace_id: None,
            },
        )
        .await
        .unwrap();

    // Second tenant, separate admin.
    let ctx_b = bootstrap_admin(&k, "tenant-b").await;
    define_invoice_type(&k, &ctx_b).await;

    // B cannot read A's record (it does not exist in B's tenant scope).
    let err = k.get_record(&ctx_b, &rec.id).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::NotFound);

    // B's invoice list is empty — A's data never leaks across the tenant boundary.
    let list_b = k.list_records(&ctx_b, "invoice", &RecordFilter::default()).await.unwrap();
    assert_eq!(list_b.total, 0);
}

#[tokio::test]
async fn member_cannot_configure_object_types() {
    let k = Kernel::in_memory().await.unwrap();
    let admin = bootstrap_admin(&k, "acme").await;
    // Admin creates a plain member user.
    let member = k
        .create_user(&admin, "m@example.com", "Member", "pw-member-1", &["member".into()])
        .await
        .unwrap();
    assert_eq!(member.role_keys, vec!["member".to_string()]);
    let login = k.login("acme", "m@example.com", "pw-member-1", "r", Source::Api).await.unwrap();
    let mctx = k.authenticate(&login.token, "r2", Source::Api).await.unwrap();

    let def = ObjectTypeDef {
        id: String::new(),
        key: "secret_type".into(),
        label: "Secret".into(),
        label_plural: None,
        description: None,
        system: false,
        workflow_key: None,
        display_field: None,
        module: None,
        fields: vec![],
    };
    let err = k.create_object_type(&mctx, &def).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::Forbidden);

    // The denial itself is audited (security-relevant).
    let denials = k
        .audit_query(&admin, &AuditQuery { action: Some("permission.denied".into()), ..Default::default() })
        .await
        .unwrap();
    assert!(!denials.is_empty(), "permission denial should be audited");
}

#[tokio::test]
async fn field_level_permission_hides_and_blocks_restricted_field() {
    let k = Kernel::in_memory().await.unwrap();
    let admin = bootstrap_admin(&k, "acme").await;

    // Employee type with a restricted `salary` field.
    let def = ObjectTypeDef {
        id: String::new(),
        key: "employee".into(),
        label: "Employee".into(),
        label_plural: Some("Employees".into()),
        description: None,
        system: false,
        workflow_key: None,
        display_field: Some("name".into()),
        module: Some("hcm".into()),
        fields: vec![
            FieldDefinition::new("name", "Name", FieldType::Text).required().display(),
            FieldDefinition::new("salary", "Salary", FieldType::Money).restricted(),
        ],
    };
    k.create_object_type(&admin, &def).await.unwrap();

    // Admin creates an employee WITH salary (admin's deny-nothing field rule allows it).
    let rec = k
        .create_record(
            &admin,
            &NewRecord {
                object_type: "employee".into(),
                data: obj(json!({"name": "Dana", "salary": 9000000})),
                workspace_id: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(rec.data.get("salary"), Some(&json!(9000000)));

    // A member reads the same record: salary must be projected out.
    k.create_user(&admin, "m@example.com", "M", "pw-member-1", &["member".into()]).await.unwrap();
    let login = k.login("acme", "m@example.com", "pw-member-1", "r", Source::Api).await.unwrap();
    let mctx = k.authenticate(&login.token, "r2", Source::Api).await.unwrap();

    let seen = k.get_record(&mctx, &rec.id).await.unwrap();
    assert_eq!(seen.data.get("name"), Some(&json!("Dana")));
    assert!(seen.data.get("salary").is_none(), "member must not see restricted salary");

    // Member cannot WRITE the restricted field either.
    let err = k
        .create_record(
            &mctx,
            &NewRecord {
                object_type: "employee".into(),
                data: obj(json!({"name": "Eve", "salary": 1})),
                workspace_id: None,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Forbidden);
}

#[tokio::test]
async fn record_level_own_scope_blocks_others() {
    let k = Kernel::in_memory().await.unwrap();
    let admin = bootstrap_admin(&k, "acme").await;
    define_invoice_type(&k, &admin).await;

    // Two members.
    for (email, _) in [("a@example.com", 0), ("b@example.com", 1)] {
        k.create_user(&admin, email, "U", "pw-member-1", &["member".into()]).await.unwrap();
    }
    let la = k.login("acme", "a@example.com", "pw-member-1", "r", Source::Api).await.unwrap();
    let actx = k.authenticate(&la.token, "r", Source::Api).await.unwrap();
    let lb = k.login("acme", "b@example.com", "pw-member-1", "r", Source::Api).await.unwrap();
    let bctx = k.authenticate(&lb.token, "r", Source::Api).await.unwrap();

    // A creates an invoice (A is the owner).
    let rec = k
        .create_record(
            &actx,
            &NewRecord {
                object_type: "invoice".into(),
                data: obj(json!({"number": "OWN-1", "amount": 10, "status": "draft"})),
                workspace_id: None,
            },
        )
        .await
        .unwrap();

    // B (member, Update is Own-scope) cannot update A's record.
    let err = k
        .update_record(&bctx, &rec.id, &RecordPatch { data: obj(json!({"status": "submitted"})) })
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Forbidden);

    // A can update their own.
    k.update_record(&actx, &rec.id, &RecordPatch { data: obj(json!({"status": "submitted"})) })
        .await
        .expect("owner update allowed");
}

#[tokio::test]
async fn relations_link_records() {
    let k = Kernel::in_memory().await.unwrap();
    let admin = bootstrap_admin(&k, "acme").await;
    define_invoice_type(&k, &admin).await;
    // A lightweight customer type.
    k.create_object_type(
        &admin,
        &ObjectTypeDef {
            id: String::new(),
            key: "customer".into(),
            label: "Customer".into(),
            label_plural: None,
            description: None,
            system: false,
            workflow_key: None,
            display_field: Some("name".into()),
            module: Some("crm".into()),
            fields: vec![FieldDefinition::new("name", "Name", FieldType::Text).required()],
        },
    )
    .await
    .unwrap();

    let cust = k
        .create_record(&admin, &NewRecord { object_type: "customer".into(), data: obj(json!({"name": "Globex"})), workspace_id: None })
        .await
        .unwrap();
    let inv = k
        .create_record(&admin, &NewRecord { object_type: "invoice".into(), data: obj(json!({"number": "R-1", "amount": 1, "status": "draft"})), workspace_id: None })
        .await
        .unwrap();

    let edge = k.relate(&admin, &inv.id, &cust.id, "billed_to").await.unwrap();
    assert_eq!(edge.record_id, cust.id);

    let edges = k.get_relations(&admin, &inv.id).await.unwrap();
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].relation_type, "billed_to");
    assert_eq!(edges[0].direction, "out");
}

#[tokio::test]
async fn validation_rejects_bad_values() {
    let k = Kernel::in_memory().await.unwrap();
    let admin = bootstrap_admin(&k, "acme").await;
    define_invoice_type(&k, &admin).await;

    // Missing required `number`.
    let err = k
        .create_record(&admin, &NewRecord { object_type: "invoice".into(), data: obj(json!({"amount": 1, "status": "draft"})), workspace_id: None })
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Validation);

    // Bad enum value.
    let err = k
        .create_record(&admin, &NewRecord { object_type: "invoice".into(), data: obj(json!({"number": "x", "amount": 1, "status": "nope"})), workspace_id: None })
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Validation);

    // Unknown field.
    let err = k
        .create_record(&admin, &NewRecord { object_type: "invoice".into(), data: obj(json!({"number": "x", "amount": 1, "status": "draft", "ghost": 1})), workspace_id: None })
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Validation);
}
