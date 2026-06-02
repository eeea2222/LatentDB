//! Phase 3 product-API integration tests.
//!
//! These drive the real Axum router (no network) against an in-memory kernel,
//! proving the HTTP surface enforces auth and wires the full slice end-to-end:
//! login -> object type -> record -> workflow -> approval -> audit.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use http_body_util::BodyExt;
use latentdb_api::app::{router, AppState};
use latentdb_contracts::FeatureFlags;
use latentdb_kernel::{Kernel, StoreConfig};
use serde_json::{json, Value};
use tower::ServiceExt;

async fn test_state() -> AppState {
    let kernel = Kernel::open(StoreConfig::memory(), FeatureFlags::default())
        .await
        .unwrap();
    // Provision the demo tenant + admin directly (the HTTP bootstrap endpoint is
    // platform-admin only; first-tenant provisioning is a CLI/seed concern).
    kernel
        .bootstrap_tenant("Acme", "acme", "admin@acme.com", "Admin", "pw-123456")
        .await
        .unwrap();
    AppState { kernel, ai: latentdb_ai::AiEngine::default() }
}

async fn call(
    state: &AppState,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    let req = if let Some(b) = body {
        builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&b).unwrap()))
            .unwrap()
    } else {
        builder.body(Body::empty()).unwrap()
    };
    let resp = router(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let value: Value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, value)
}

async fn login(state: &AppState) -> String {
    let (status, body) = call(
        state,
        "POST",
        "/v1/auth/login",
        None,
        Some(json!({"tenant": "acme", "email": "admin@acme.com", "password": "pw-123456"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "login failed: {body}");
    body["token"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn health_endpoints_work() {
    let state = test_state().await;
    let (s, b) = call(&state, "GET", "/healthz", None, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["status"], "ok");
    let (s, b) = call(&state, "GET", "/readyz", None, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["status"], "ready");
}

#[tokio::test]
async fn unauthenticated_requests_are_rejected() {
    let state = test_state().await;
    let (s, b) = call(&state, "GET", "/v1/users", None, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(b["error"]["code"], "unauthorized");
}

#[tokio::test]
async fn login_me_and_consistent_error_envelope() {
    let state = test_state().await;
    let token = login(&state).await;
    let (s, b) = call(&state, "GET", "/v1/auth/me", Some(&token), None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["role_keys"][0], "tenant_admin");

    // Bad login returns the canonical error envelope.
    let (s, b) = call(
        &state,
        "POST",
        "/v1/auth/login",
        None,
        Some(json!({"tenant": "acme", "email": "admin@acme.com", "password": "nope"})),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(b["error"]["code"], "unauthorized");
}

#[tokio::test]
async fn full_slice_over_http() {
    let state = test_state().await;
    let token = login(&state).await;
    let t = Some(token.as_str());

    // Define the invoice workflow.
    let wf = json!({
        "key": "invoice_wf", "object_type": "invoice", "name": "Invoice Approval",
        "initial_state": "draft",
        "states": [
            {"key":"draft","label":"Draft"},
            {"key":"submitted","label":"Submitted"},
            {"key":"approved","label":"Approved"},
            {"key":"paid","label":"Paid","terminal":true}
        ],
        "transitions": [
            {"key":"submit","from":"draft","to":"submitted","label":"Submit","requires_approval":false},
            {"key":"approve","from":"submitted","to":"approved","label":"Approve","requires_approval":true,"approval_policy":"finance"},
            {"key":"mark_paid","from":"approved","to":"paid","label":"Mark Paid","requires_approval":false}
        ]
    });
    let (s, _) = call(&state, "POST", "/v1/workflows", t, Some(wf)).await;
    assert_eq!(s, StatusCode::OK);

    // Define the invoice object type bound to that workflow.
    let def = json!({
        "id": "", "key": "invoice", "label": "Invoice", "label_plural": "Invoices",
        "workflow_key": "invoice_wf", "display_field": "number", "module": "finance",
        "fields": [
            {"key":"number","label":"Number","type":"text","required":true},
            {"key":"amount","label":"Amount","type":"money","required":true},
            {"key":"status","label":"Status","type":"text"}
        ]
    });
    let (s, _) = call(&state, "POST", "/v1/object-types", t, Some(def)).await;
    assert_eq!(s, StatusCode::OK);

    // Create an invoice record.
    let (s, rec) = call(
        &state,
        "POST",
        "/v1/object-types/invoice/records",
        t,
        Some(json!({"data": {"number": "INV-1001", "amount": 250000}})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "create record: {rec}");
    let id = rec["id"].as_str().unwrap().to_string();
    assert_eq!(rec["workflow_state"], "draft");

    // List shows it.
    let (s, list) = call(&state, "GET", "/v1/object-types/invoice/records", t, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(list["total"], 1);

    // Submit (no approval) -> submitted.
    let (s, res) = call(
        &state,
        "POST",
        &format!("/v1/records/{id}/transitions"),
        t,
        Some(json!({"key": "submit"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(res["status"], "transitioned");
    assert_eq!(res["to"], "submitted");

    // Approve (requires approval) -> pending.
    let (s, res) = call(
        &state,
        "POST",
        &format!("/v1/records/{id}/transitions"),
        t,
        Some(json!({"key": "approve"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(res["status"], "pending_approval");
    let approval_id = res["approval_id"].as_str().unwrap().to_string();

    // Record hasn't moved yet.
    let (_, rec) = call(&state, "GET", &format!("/v1/records/{id}"), t, None).await;
    assert_eq!(rec["workflow_state"], "submitted");

    // Pending approvals list contains it.
    let (s, approvals) = call(&state, "GET", "/v1/approvals", t, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(approvals.as_array().unwrap().len(), 1);

    // Decide -> approved, record moves.
    let (s, _) = call(
        &state,
        "POST",
        &format!("/v1/approvals/{approval_id}/decide"),
        t,
        Some(json!({"approved": true, "reason": "ok"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (_, rec) = call(&state, "GET", &format!("/v1/records/{id}"), t, None).await;
    assert_eq!(rec["workflow_state"], "approved");

    // Audit trail for the invoice is queryable and includes the create.
    let (s, audit) = call(
        &state,
        "GET",
        &format!("/v1/audit?record_id={id}"),
        t,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let actions: Vec<&str> = audit
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    assert!(actions.contains(&"record.create"));
    assert!(actions.contains(&"workflow.transition"));
}

#[tokio::test]
async fn validation_error_maps_to_422() {
    let state = test_state().await;
    let token = login(&state).await;
    let t = Some(token.as_str());

    let def = json!({
        "id": "", "key": "widget", "label": "Widget",
        "fields": [{"key":"name","label":"Name","type":"text","required":true}]
    });
    call(&state, "POST", "/v1/object-types", t, Some(def)).await;

    // Missing required `name`.
    let (s, b) = call(
        &state,
        "POST",
        "/v1/object-types/widget/records",
        t,
        Some(json!({"data": {}})),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(b["error"]["code"], "validation");
}
