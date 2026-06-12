use latentdb_contracts::{
    AuditQuery, AuthContext, BuilderDefinition, FeatureFlags, FieldDefinition, FieldType,
    InstallTemplateRequest, NewRecord, SaveBuilderDraftRequest, Source,
};
use latentdb_kernel::{Kernel, StoreConfig};
use serde_json::{json, Map, Value};

fn obj(v: Value) -> Map<String, Value> {
    v.as_object().cloned().unwrap_or_default()
}

async fn kernel() -> Kernel {
    Kernel::open(StoreConfig::memory(), FeatureFlags::default())
        .await
        .unwrap()
}

async fn admin(k: &Kernel, slug: &str) -> AuthContext {
    k.bootstrap_tenant(
        &format!("Tenant {slug}"),
        slug,
        &format!("admin@{slug}.test"),
        "Admin",
        "pw-123456",
    )
    .await
    .unwrap();
    let l = k
        .login(
            slug,
            &format!("admin@{slug}.test"),
            "pw-123456",
            "r",
            Source::Api,
        )
        .await
        .unwrap();
    k.authenticate(&l.token, "r", Source::Api).await.unwrap()
}

fn invoice_builder() -> BuilderDefinition {
    BuilderDefinition {
        key: "custom_invoice".into(),
        label: "Custom Invoice".into(),
        label_plural: Some("Custom Invoices".into()),
        description: Some("Tenant invoice object".into()),
        icon: Some("CI".into()),
        module: Some("finance".into()),
        display_field: Some("number".into()),
        fields: vec![
            FieldDefinition::new("number", "Number", FieldType::Text)
                .required()
                .display()
                .ai_visible(),
            FieldDefinition::new("amount", "Amount", FieldType::Money)
                .required()
                .ai_visible(),
            FieldDefinition::new("internal_note", "Internal Note", FieldType::Text).restricted(),
        ],
        relations: vec![],
        workflow: None,
        permissions: vec![],
        approval_rules: vec![],
        sensitive_ai_visibility_confirmed: false,
    }
}

#[tokio::test]
async fn builder_drafts_are_tenant_isolated() {
    let k = kernel().await;
    let a = admin(&k, "tenant_a").await;
    let b = admin(&k, "tenant_b").await;
    k.save_builder_draft(
        &a,
        &SaveBuilderDraftRequest {
            id: None,
            definition: invoice_builder(),
        },
    )
    .await
    .unwrap();

    assert_eq!(k.list_builder_drafts(&a).await.unwrap().len(), 1);
    assert_eq!(k.list_builder_drafts(&b).await.unwrap().len(), 0);
}

#[tokio::test]
async fn duplicate_field_keys_are_rejected_before_publish() {
    let k = kernel().await;
    let a = admin(&k, "tenant_dup").await;
    let mut def = invoice_builder();
    def.fields
        .push(FieldDefinition::new("number", "Again", FieldType::Text));
    let res = k.validate_builder_definition(&a, &def).await.unwrap();
    assert!(!res.valid);
    assert!(res.issues.iter().any(|i| i.message.contains("unique")));
}

#[tokio::test]
async fn publish_creates_normal_object_type_and_audit() {
    let k = kernel().await;
    let a = admin(&k, "tenant_pub").await;
    let draft = k
        .save_builder_draft(
            &a,
            &SaveBuilderDraftRequest {
                id: None,
                definition: invoice_builder(),
            },
        )
        .await
        .unwrap();
    let published = k.publish_builder_draft(&a, &draft.id).await.unwrap();
    assert_eq!(published.object_type.key, "custom_invoice");

    let listed = k.list_object_types(&a).await.unwrap();
    assert!(listed.iter().any(|o| o.key == "custom_invoice"));

    let audits = k
        .audit_query(
            &a,
            &AuditQuery {
                action: Some("builder.publish".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(!audits.is_empty());
}

#[tokio::test]
async fn required_field_validation_works_after_publish() {
    let k = kernel().await;
    let a = admin(&k, "tenant_req").await;
    let draft = k
        .save_builder_draft(
            &a,
            &SaveBuilderDraftRequest {
                id: None,
                definition: invoice_builder(),
            },
        )
        .await
        .unwrap();
    k.publish_builder_draft(&a, &draft.id).await.unwrap();
    let err = k
        .create_record(
            &a,
            &NewRecord {
                object_type: "custom_invoice".into(),
                data: obj(json!({"number": "INV-1"})),
                workspace_id: None,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, latentdb_contracts::ErrorCode::Validation);
}

#[tokio::test]
async fn template_install_creates_normal_object_types_and_audit() {
    let k = kernel().await;
    let a = admin(&k, "tenant_tpl").await;
    let res = k
        .install_builder_template(
            &a,
            &InstallTemplateRequest {
                key: "finance".into(),
                include_sample_records: true,
            },
        )
        .await
        .unwrap();
    assert!(res.object_types.iter().any(|o| o.key == "invoice"));
    assert!(res.record_count >= 10);

    let records = k
        .list_records(&a, "invoice", &latentdb_contracts::RecordFilter::default())
        .await
        .unwrap();
    assert!(records.total >= 10);

    let audits = k
        .audit_query(
            &a,
            &AuditQuery {
                action: Some("builder.template.install".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(!audits.is_empty());
}
