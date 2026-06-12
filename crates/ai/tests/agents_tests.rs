//! Phase 5 tests: grounded agents, permission-aware retrieval, AI-off fallback,
//! and dry-run + approval-gated action execution. Fully offline (local provider).

use latentdb_ai::{action, AgentAction, AiEngine, OfflineProvider};
use latentdb_contracts::{
    AuditQuery, AuthContext, ErrorCode, FeatureFlags, FieldDefinition, FieldType, NewRecord,
    ObjectTypeDef, Source,
};
use latentdb_kernel::{Kernel, StoreConfig};
use serde_json::{json, Map, Value};
use std::sync::Arc;

fn obj(v: Value) -> Map<String, Value> {
    v.as_object().cloned().unwrap_or_default()
}

async fn kernel_with(flags: FeatureFlags) -> Kernel {
    Kernel::open(StoreConfig::memory(), flags).await.unwrap()
}

async fn admin(k: &Kernel) -> AuthContext {
    k.bootstrap_tenant("TestCo", "testco", "a@testco.test", "Admin", "pw-123456")
        .await
        .unwrap();
    let l = k
        .login("testco", "a@testco.test", "pw-123456", "r", Source::Api)
        .await
        .unwrap();
    k.authenticate(&l.token, "r", Source::Api).await.unwrap()
}

async fn member(k: &Kernel, admin: &AuthContext) -> AuthContext {
    k.create_user(
        admin,
        "m@testco.test",
        "M",
        "pw-member-1",
        &["member".into()],
    )
    .await
    .unwrap();
    let l = k
        .login("testco", "m@testco.test", "pw-member-1", "r", Source::Api)
        .await
        .unwrap();
    k.authenticate(&l.token, "r", Source::Api).await.unwrap()
}

fn test_ai() -> AiEngine {
    AiEngine::with_provider(Arc::new(OfflineProvider::default()))
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
            FieldDefinition::new("number", "Number", FieldType::Text)
                .required()
                .ai_visible(),
            FieldDefinition::new("amount", "Amount", FieldType::Money)
                .required()
                .ai_visible(),
            FieldDefinition::new("status", "Status", FieldType::Enum)
                .options(&["draft", "paid"])
                .ai_visible(),
            FieldDefinition::new("due_date", "Due", FieldType::Date).ai_visible(),
            FieldDefinition::new("secret_note", "Secret", FieldType::Text).restricted(),
        ],
    };
    k.create_object_type(ctx, &def).await.unwrap();

    // One overdue (draft, past due) and one paid.
    k.create_record(ctx, &NewRecord {
        object_type: "invoice".into(),
        data: obj(json!({"number":"INV-OVERDUE","amount":50000,"status":"draft","due_date":"2020-01-01","secret_note":"TOPSECRET"})),
        workspace_id: None,
    }).await.unwrap();
    k.create_record(
        ctx,
        &NewRecord {
            object_type: "invoice".into(),
            data: obj(
                json!({"number":"INV-PAID","amount":30000,"status":"paid","due_date":"2020-01-01"}),
            ),
            workspace_id: None,
        },
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn finance_agent_grounds_in_overdue_invoices() {
    let k = kernel_with(FeatureFlags::default()).await;
    let ctx = admin(&k).await;
    setup_invoices(&k, &ctx).await;
    let ai = test_ai();

    let ans = ai.agents().finance_cashflow_risk(&k, &ctx).await.unwrap();
    assert!(ans.used_ai);
    assert_eq!(ans.citations.len(), 1, "only the overdue invoice is cited");
    assert!(ans.text.contains("Overdue invoices: 1"));
    // The cited id is a real invoice the actor can see.
    let cited = k.get_record(&ctx, &ans.citations[0]).await.unwrap();
    assert_eq!(cited.data.get("number"), Some(&json!("INV-OVERDUE")));
}

#[tokio::test]
async fn bi_agent_answers_revenue_at_risk_with_citations() {
    let k = kernel_with(FeatureFlags::default()).await;
    let ctx = admin(&k).await;
    setup_invoices(&k, &ctx).await;
    let ai = test_ai();

    let ans = ai
        .agents()
        .bi_answer(&k, &ctx, "Why is revenue at risk this month?")
        .await
        .unwrap();
    assert!(!ans.citations.is_empty(), "answer must cite source records");
    assert!(ans.text.to_lowercase().contains("risk"));
}

#[tokio::test]
async fn retrieval_respects_field_level_permissions() {
    let k = kernel_with(FeatureFlags::default()).await;
    let adm = admin(&k).await;
    setup_invoices(&k, &adm).await;
    let mem = member(&k, &adm).await;
    let ai = test_ai();

    // Admin can read the record, but AI visibility excludes the restricted
    // secret from grounding snippets by default.
    let admin_ans = ai
        .agents()
        .ask(&k, &adm, "INV", &["invoice".into()])
        .await
        .unwrap();
    let admin_snippets: String = admin_ans
        .sources
        .iter()
        .map(|d| d.snippet.clone())
        .collect();
    assert!(!admin_snippets.contains("TOPSECRET"));

    // The member retrieves the same invoices but the restricted field is gone.
    let mem_ans = ai
        .agents()
        .ask(&k, &mem, "INV", &["invoice".into()])
        .await
        .unwrap();
    assert!(
        !mem_ans.sources.is_empty(),
        "member can still retrieve permitted records"
    );
    let mem_snippets: String = mem_ans.sources.iter().map(|d| d.snippet.clone()).collect();
    assert!(
        !mem_snippets.contains("TOPSECRET"),
        "AI retrieval must not leak restricted fields"
    );
}

#[tokio::test]
async fn ai_disabled_returns_feature_disabled() {
    let flags = FeatureFlags {
        enable_ai_agents: false,
        ..FeatureFlags::default()
    };
    let k = kernel_with(flags).await;
    let ctx = admin(&k).await;
    setup_invoices(&k, &ctx).await;
    let ai = test_ai();

    let err = ai
        .agents()
        .finance_cashflow_risk(&k, &ctx)
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::FeatureDisabled);
}

#[tokio::test]
async fn action_dry_run_does_not_mutate() {
    let k = kernel_with(FeatureFlags::default()).await;
    let ctx = admin(&k).await;
    setup_invoices(&k, &ctx).await;

    let action = AgentAction {
        kind: "draft_invoice".into(),
        description: "Draft a new invoice".into(),
        op: action::ActionOp::CreateRecord,
        object_type: Some("invoice".into()),
        record_id: None,
        payload: json!({"number":"INV-AI","amount":12345,"status":"draft"}),
        safety_level: 3,
        risk_score: 0.4,
    };

    let plan = latentdb_ai::dry_run(&k, &ctx, &action).await.unwrap();
    assert!(plan.requires_approval, "level-3 action requires approval");
    assert_eq!(plan.after.as_ref().unwrap()["number"], "INV-AI");

    // No record was created.
    let list = k
        .list_records(
            &ctx,
            "invoice",
            &latentdb_contracts::RecordFilter::default(),
        )
        .await
        .unwrap();
    assert_eq!(list.total, 2, "dry-run must not create records");
}

#[tokio::test]
async fn execution_is_approval_gated_and_audited() {
    let k = kernel_with(FeatureFlags::default()).await;
    let ctx = admin(&k).await;
    setup_invoices(&k, &ctx).await;

    let action = AgentAction {
        kind: "draft_invoice".into(),
        description: "Create invoice".into(),
        op: action::ActionOp::CreateRecord,
        object_type: Some("invoice".into()),
        record_id: None,
        payload: json!({"number":"INV-AI","amount":12345,"status":"draft"}),
        safety_level: 3,
        risk_score: 0.4,
    };

    // Without approval the level-3 action is refused.
    let err = latentdb_ai::execute(&k, &ctx, &action, false)
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::FailedPrecondition);

    // With approval it executes and creates the record.
    latentdb_ai::execute(&k, &ctx, &action, true).await.unwrap();
    let list = k
        .list_records(
            &ctx,
            "invoice",
            &latentdb_contracts::RecordFilter::default(),
        )
        .await
        .unwrap();
    assert_eq!(list.total, 3);

    // The execution is audited as an AI action.
    let audit = k
        .audit_query(
            &ctx,
            &AuditQuery {
                action: Some("ai.action.execute".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(!audit.is_empty(), "AI action execution must be audited");
}

#[tokio::test]
async fn execution_blocked_when_flag_disabled() {
    let flags = FeatureFlags {
        enable_agent_action_execution: false, // AI on, execution off
        ..FeatureFlags::default()
    };
    let k = kernel_with(flags).await;
    let ctx = admin(&k).await;
    setup_invoices(&k, &ctx).await;

    let action = AgentAction {
        kind: "draft_invoice".into(),
        description: "Create invoice".into(),
        op: action::ActionOp::CreateRecord,
        object_type: Some("invoice".into()),
        record_id: None,
        payload: json!({"number":"INV-AI","amount":1,"status":"draft"}),
        safety_level: 3,
        risk_score: 0.4,
    };
    let err = latentdb_ai::execute(&k, &ctx, &action, true)
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::FeatureDisabled);
}
