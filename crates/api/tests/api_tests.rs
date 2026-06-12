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
    // Provision the test tenant + admin directly (the HTTP bootstrap endpoint is
    // platform-admin only; first-tenant provisioning is a CLI/seed concern).
    kernel
        .bootstrap_tenant(
            "TestCo",
            "testco",
            "admin@testco.test",
            "Admin",
            "pw-123456",
        )
        .await
        .unwrap();
    AppState {
        kernel,
        ai: latentdb_ai::AiEngine::default(),
    }
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
        Some(json!({"tenant": "testco", "email": "admin@testco.test", "password": "pw-123456"})),
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
        Some(json!({"tenant": "testco", "email": "admin@testco.test", "password": "nope"})),
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
    let (s, audit) = call(&state, "GET", &format!("/v1/audit?record_id={id}"), t, None).await;
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

/// A fresh state with no tenant provisioned (first-run scenario).
async fn empty_state() -> AppState {
    let kernel = Kernel::open(StoreConfig::memory(), FeatureFlags::default())
        .await
        .unwrap();
    AppState {
        kernel,
        ai: latentdb_ai::AiEngine::default(),
    }
}

#[tokio::test]
async fn first_run_bootstrap_is_open_then_platform_admin_only() {
    let state = empty_state().await;

    // First run: no tenants exist, so bootstrap needs no credential.
    let (s, b) = call(
        &state,
        "POST",
        "/v1/bootstrap",
        None,
        Some(json!({
            "name": "FirstCo", "slug": "firstco",
            "admin_email": "admin@firstco.test", "admin_name": "Admin",
            "admin_password": "pw-123456"
        })),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "first-run bootstrap failed: {b}");
    assert_eq!(b["tenant"]["slug"], "firstco");

    // Second tenant without a token is rejected.
    let (s, b) = call(
        &state,
        "POST",
        "/v1/bootstrap",
        None,
        Some(json!({
            "name": "SecondCo", "slug": "secondco",
            "admin_email": "admin@secondco.test", "admin_name": "Admin",
            "admin_password": "pw-123456"
        })),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "expected 401: {b}");

    // A tenant admin (not platform admin) is also rejected.
    let (_, login) = call(
        &state,
        "POST",
        "/v1/auth/login",
        None,
        Some(json!({"tenant": "firstco", "email": "admin@firstco.test", "password": "pw-123456"})),
    )
    .await;
    let token = login["token"].as_str().unwrap();
    let (s, _) = call(
        &state,
        "POST",
        "/v1/bootstrap",
        Some(token),
        Some(json!({
            "name": "SecondCo", "slug": "secondco",
            "admin_email": "admin@secondco.test", "admin_name": "Admin",
            "admin_password": "pw-123456"
        })),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn responses_carry_security_headers_and_request_id() {
    let state = test_state().await;
    let req = Request::builder()
        .method("GET")
        .uri("/healthz")
        .header("x-request-id", "req-abc-123")
        .body(Body::empty())
        .unwrap();
    let resp = router(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let h = resp.headers();
    assert_eq!(h.get("x-request-id").unwrap(), "req-abc-123");
    assert_eq!(h.get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(h.get("x-frame-options").unwrap(), "DENY");
    assert_eq!(h.get("cache-control").unwrap(), "no-store");
}

#[tokio::test]
async fn usage_endpoint_reports_metered_api_calls() {
    let state = test_state().await;
    let token = login(&state).await;
    let t = Some(token.as_str());

    // Any authenticated call meters; then read the meters back.
    let (s, _) = call(&state, "GET", "/v1/auth/me", t, None).await;
    assert_eq!(s, StatusCode::OK);
    let (s, meters) = call(&state, "GET", "/v1/usage", t, None).await;
    assert_eq!(s, StatusCode::OK, "usage failed: {meters}");
    let arr = meters.as_array().unwrap();
    let api_calls = arr
        .iter()
        .find(|m| m["metric"] == "api_calls")
        .expect("api_calls meter present");
    assert!(api_calls["value"].as_i64().unwrap() >= 1);
}

#[tokio::test]
async fn weak_bootstrap_password_is_rejected() {
    let state = empty_state().await;
    let (s, b) = call(
        &state,
        "POST",
        "/v1/bootstrap",
        None,
        Some(json!({
            "name": "WeakCo", "slug": "weakco",
            "admin_email": "admin@weakco.test", "admin_name": "Admin",
            "admin_password": "short"
        })),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "expected 422: {b}");
    assert_eq!(b["error"]["code"], "validation");
}
