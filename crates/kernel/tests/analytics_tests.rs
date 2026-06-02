//! Phase 4 tests: permission-aware metrics, reports, grouping, dashboards.

use latentdb_contracts::page::FieldFilter;
use latentdb_contracts::{
    AuthContext, ConditionOp, FieldDefinition, FieldType, NewRecord, ObjectTypeDef, Source,
};
use latentdb_kernel::analytics::{AggOp, Dashboard, ReportDef};
use latentdb_kernel::Kernel;
use serde_json::{json, Map, Value};

fn obj(v: Value) -> Map<String, Value> {
    v.as_object().cloned().unwrap_or_default()
}

async fn admin(k: &Kernel) -> AuthContext {
    k.bootstrap_tenant("Acme", "acme", "a@acme.com", "Admin", "pw-123456").await.unwrap();
    let l = k.login("acme", "a@acme.com", "pw-123456", "r", Source::Api).await.unwrap();
    k.authenticate(&l.token, "r", Source::Api).await.unwrap()
}

async fn setup_invoices(k: &Kernel, ctx: &AuthContext) {
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
            FieldDefinition::new("number", "Number", FieldType::Text).required(),
            FieldDefinition::new("amount", "Amount", FieldType::Money).required(),
            FieldDefinition::new("status", "Status", FieldType::Enum).options(&["draft", "paid"]),
            // A restricted profit margin that only privileged roles can see.
            FieldDefinition::new("margin", "Margin", FieldType::Money).restricted(),
        ],
    };
    k.create_object_type(ctx, &def).await.unwrap();

    let rows = [
        ("INV-1", 10000, "paid", 2000),
        ("INV-2", 20000, "paid", 5000),
        ("INV-3", 30000, "draft", 7000),
    ];
    for (num, amount, status, margin) in rows {
        k.create_record(ctx, &NewRecord {
            object_type: "invoice".into(),
            data: obj(json!({"number": num, "amount": amount, "status": status, "margin": margin})),
            workspace_id: None,
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn aggregate_sum_and_filter() {
    let k = Kernel::in_memory().await.unwrap();
    let ctx = admin(&k).await;
    setup_invoices(&k, &ctx).await;

    let total = k.aggregate(&ctx, "invoice", AggOp::Sum, Some("amount"), vec![]).await.unwrap();
    assert_eq!(total, 60000.0);

    // Only paid invoices.
    let paid = k
        .aggregate(
            &ctx,
            "invoice",
            AggOp::Sum,
            Some("amount"),
            vec![FieldFilter { field: "status".into(), op: ConditionOp::Eq, value: json!("paid") }],
        )
        .await
        .unwrap();
    assert_eq!(paid, 30000.0);

    let count = k.aggregate(&ctx, "invoice", AggOp::Count, None, vec![]).await.unwrap();
    assert_eq!(count, 3.0);
}

#[tokio::test]
async fn report_grouping_and_persistence() {
    let k = Kernel::in_memory().await.unwrap();
    let ctx = admin(&k).await;
    setup_invoices(&k, &ctx).await;

    let def = ReportDef {
        key: "invoices_by_status".into(),
        name: "Invoices by status".into(),
        object_type: "invoice".into(),
        op: AggOp::Sum,
        field: Some("amount".into()),
        filters: vec![],
        group_by: Some("status".into()),
    };
    k.save_report(&ctx, &def).await.unwrap();
    let res = k.run_report(&ctx, "invoices_by_status").await.unwrap();
    assert_eq!(res.sample_size, 3);
    let paid = res.groups.iter().find(|g| g.key == "paid").unwrap();
    assert_eq!(paid.value, 30000.0);
    assert_eq!(paid.count, 2);
    let draft = res.groups.iter().find(|g| g.key == "draft").unwrap();
    assert_eq!(draft.value, 30000.0);
    assert_eq!(draft.count, 1);
}

#[tokio::test]
async fn metrics_are_permission_aware_for_restricted_fields() {
    let k = Kernel::in_memory().await.unwrap();
    let adm = admin(&k).await;
    setup_invoices(&k, &adm).await;

    // Admin can aggregate the restricted margin.
    let admin_margin = k.aggregate(&adm, "invoice", AggOp::Sum, Some("margin"), vec![]).await.unwrap();
    assert_eq!(admin_margin, 14000.0);

    // A plain member cannot see `margin`; aggregating it yields 0 (projected out
    // before the numbers are computed) — the report cannot leak restricted data.
    k.create_user(&adm, "m@acme.com", "M", "pw-member-1", &["member".into()]).await.unwrap();
    let l = k.login("acme", "m@acme.com", "pw-member-1", "r", Source::Api).await.unwrap();
    let mctx = k.authenticate(&l.token, "r", Source::Api).await.unwrap();

    let member_margin = k.aggregate(&mctx, "invoice", AggOp::Sum, Some("margin"), vec![]).await.unwrap();
    assert_eq!(member_margin, 0.0, "member must not aggregate restricted margin");

    // But the member CAN aggregate the non-restricted amount.
    let member_amount = k.aggregate(&mctx, "invoice", AggOp::Sum, Some("amount"), vec![]).await.unwrap();
    assert_eq!(member_amount, 60000.0);
}

#[tokio::test]
async fn dashboards_persist() {
    let k = Kernel::in_memory().await.unwrap();
    let ctx = admin(&k).await;
    let dash = Dashboard {
        key: "ceo".into(),
        name: "CEO".into(),
        cards: vec![json!({"title": "Revenue", "report": "revenue"})],
    };
    k.save_dashboard(&ctx, &dash).await.unwrap();
    let got = k.get_dashboard(&ctx, "ceo").await.unwrap();
    assert_eq!(got.name, "CEO");
    assert_eq!(got.cards.len(), 1);
    assert_eq!(k.list_dashboards(&ctx).await.unwrap().len(), 1);
}
