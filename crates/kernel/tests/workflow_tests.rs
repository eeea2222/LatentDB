//! Phase 2 tests: workflow transitions, approval-gated transitions, tasks.

use latentdb_contracts::{
    AuditQuery, AuthContext, ErrorCode, FieldDefinition, FieldType, NewRecord, ObjectTypeDef,
    Source, Transition, WorkflowDef, WorkflowState,
};
use latentdb_kernel::Kernel;
use serde_json::{json, Map, Value};

fn obj(v: Value) -> Map<String, Value> {
    v.as_object().cloned().unwrap_or_default()
}

async fn bootstrap_admin(k: &Kernel, slug: &str) -> AuthContext {
    k.bootstrap_tenant(&format!("Acme {slug}"), slug, "admin@example.com", "Admin", "pw-admin-123")
        .await
        .unwrap();
    let login = k.login(slug, "admin@example.com", "pw-admin-123", "r", Source::Api).await.unwrap();
    k.authenticate(&login.token, "r2", Source::Api).await.unwrap()
}

fn state(key: &str, terminal: bool) -> WorkflowState {
    WorkflowState { key: key.into(), label: key.into(), terminal }
}

fn transition(key: &str, from: &str, to: &str, requires_approval: bool) -> Transition {
    Transition {
        key: key.into(),
        from: from.into(),
        to: to.into(),
        label: key.into(),
        guard_permission: None,
        requires_approval,
        approval_policy: if requires_approval { Some("finance".into()) } else { None },
    }
}

async fn define_invoice_with_workflow(k: &Kernel, ctx: &AuthContext) {
    let wf = WorkflowDef {
        key: "invoice_wf".into(),
        object_type: "invoice".into(),
        name: "Invoice Approval".into(),
        initial_state: "draft".into(),
        states: vec![
            state("draft", false),
            state("submitted", false),
            state("approved", false),
            state("paid", true),
            state("cancelled", true),
        ],
        transitions: vec![
            transition("submit", "draft", "submitted", false),
            transition("approve", "submitted", "approved", true),
            transition("mark_paid", "approved", "paid", false),
            transition("cancel", "draft", "cancelled", false),
        ],
    };
    k.create_workflow(ctx, &wf).await.unwrap();

    let def = ObjectTypeDef {
        id: String::new(),
        key: "invoice".into(),
        label: "Invoice".into(),
        label_plural: Some("Invoices".into()),
        description: None,
        system: false,
        workflow_key: Some("invoice_wf".into()),
        display_field: Some("number".into()),
        module: Some("finance".into()),
        fields: vec![
            FieldDefinition::new("number", "Number", FieldType::Text).required(),
            FieldDefinition::new("amount", "Amount", FieldType::Money).required(),
        ],
    };
    k.create_object_type(ctx, &def).await.unwrap();
}

async fn new_invoice(k: &Kernel, ctx: &AuthContext, number: &str) -> String {
    k.create_record(ctx, &NewRecord {
        object_type: "invoice".into(),
        data: obj(json!({"number": number, "amount": 25000})),
        workspace_id: None,
    })
    .await
    .unwrap()
    .id
}

#[tokio::test]
async fn record_starts_in_initial_state() {
    let k = Kernel::in_memory().await.unwrap();
    let admin = bootstrap_admin(&k, "acme").await;
    define_invoice_with_workflow(&k, &admin).await;
    let id = new_invoice(&k, &admin, "INV-1").await;
    let rec = k.get_record(&admin, &id).await.unwrap();
    assert_eq!(rec.workflow_state.as_deref(), Some("draft"));
}

#[tokio::test]
async fn simple_transition_moves_state() {
    let k = Kernel::in_memory().await.unwrap();
    let admin = bootstrap_admin(&k, "acme").await;
    define_invoice_with_workflow(&k, &admin).await;
    let id = new_invoice(&k, &admin, "INV-1").await;

    let res = k.transition_record(&admin, &id, "submit", None).await.unwrap();
    assert_eq!(res.status, "transitioned");
    assert_eq!(res.to, "submitted");
    let rec = k.get_record(&admin, &id).await.unwrap();
    assert_eq!(rec.workflow_state.as_deref(), Some("submitted"));
}

#[tokio::test]
async fn invalid_transition_is_rejected() {
    let k = Kernel::in_memory().await.unwrap();
    let admin = bootstrap_admin(&k, "acme").await;
    define_invoice_with_workflow(&k, &admin).await;
    let id = new_invoice(&k, &admin, "INV-1").await;
    // `approve` is only valid from `submitted`, not the initial `draft`.
    let err = k.transition_record(&admin, &id, "approve", None).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::FailedPrecondition);
}

#[tokio::test]
async fn approval_gated_transition_waits_then_applies() {
    let k = Kernel::in_memory().await.unwrap();
    let admin = bootstrap_admin(&k, "acme").await;
    define_invoice_with_workflow(&k, &admin).await;
    let id = new_invoice(&k, &admin, "INV-1").await;
    k.transition_record(&admin, &id, "submit", None).await.unwrap();

    // `approve` requires approval: the record does NOT move yet.
    let res = k.transition_record(&admin, &id, "approve", None).await.unwrap();
    assert_eq!(res.status, "pending_approval");
    let approval_id = res.approval_id.clone().expect("approval id");
    let rec = k.get_record(&admin, &id).await.unwrap();
    assert_eq!(rec.workflow_state.as_deref(), Some("submitted"), "must not move before approval");

    // An approval task and a pending approval exist.
    let pending = k.list_pending_approvals(&admin).await.unwrap();
    assert_eq!(pending.len(), 1);
    let tasks = k.list_tasks(&admin, false, Some("open")).await.unwrap();
    assert!(tasks.iter().any(|t| t.kind == "approval"));

    // Deciding the approval applies the gated transition.
    k.decide_approval(&admin, &approval_id, true, Some("ok")).await.unwrap();
    let rec = k.get_record(&admin, &id).await.unwrap();
    assert_eq!(rec.workflow_state.as_deref(), Some("approved"));

    // The transition audit is linked to the approval id.
    let audit = k
        .audit_query(&admin, &AuditQuery { target_record_id: Some(id.clone()), ..Default::default() })
        .await
        .unwrap();
    let linked = audit.iter().find(|e| e.action == "workflow.transition" && e.approval_id.as_deref() == Some(approval_id.as_str()));
    assert!(linked.is_some(), "approved transition must be audited with approval id");

    // The approval task is now closed.
    let open = k.list_tasks(&admin, false, Some("open")).await.unwrap();
    assert!(!open.iter().any(|t| t.kind == "approval"));
}

#[tokio::test]
async fn rejected_approval_does_not_move_record() {
    let k = Kernel::in_memory().await.unwrap();
    let admin = bootstrap_admin(&k, "acme").await;
    define_invoice_with_workflow(&k, &admin).await;
    let id = new_invoice(&k, &admin, "INV-1").await;
    k.transition_record(&admin, &id, "submit", None).await.unwrap();
    let res = k.transition_record(&admin, &id, "approve", None).await.unwrap();
    let approval_id = res.approval_id.unwrap();

    k.decide_approval(&admin, &approval_id, false, Some("over budget")).await.unwrap();
    let rec = k.get_record(&admin, &id).await.unwrap();
    assert_eq!(rec.workflow_state.as_deref(), Some("submitted"), "rejection keeps prior state");
}

#[tokio::test]
async fn member_cannot_transition_without_grant() {
    let k = Kernel::in_memory().await.unwrap();
    let admin = bootstrap_admin(&k, "acme").await;
    define_invoice_with_workflow(&k, &admin).await;
    let id = new_invoice(&k, &admin, "INV-1").await;

    k.create_user(&admin, "m@example.com", "M", "pw-member-1", &["member".into()]).await.unwrap();
    let login = k.login("acme", "m@example.com", "pw-member-1", "r", Source::Api).await.unwrap();
    let mctx = k.authenticate(&login.token, "r2", Source::Api).await.unwrap();

    // `member` has no `transition` grant.
    let err = k.transition_record(&mctx, &id, "submit", None).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::Forbidden);
}
