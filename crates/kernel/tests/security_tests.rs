//! Security hardening tests: login throttling, credential lifecycle (disabled
//! users, suspended tenants), API-key principal binding, password policy, and
//! approval separation of duties.

use latentdb_contracts::{
    AuthContext, ErrorCode, FeatureFlags, FieldDefinition, FieldType, NewRecord, ObjectTypeDef,
    Source, Transition, WorkflowDef, WorkflowState,
};
use latentdb_kernel::{Kernel, StoreConfig};
use serde_json::{json, Map, Value};

fn obj(v: Value) -> Map<String, Value> {
    v.as_object().cloned().unwrap_or_default()
}

async fn bootstrap_admin(k: &Kernel, slug: &str) -> AuthContext {
    k.bootstrap_tenant(
        &format!("TestCo {slug}"),
        slug,
        "admin@example.test",
        "Admin",
        "pw-admin-123",
    )
    .await
    .unwrap();
    let login = k
        .login(slug, "admin@example.test", "pw-admin-123", "r", Source::Api)
        .await
        .unwrap();
    k.authenticate(&login.token, "r2", Source::Api)
        .await
        .unwrap()
}

#[tokio::test]
async fn login_is_rate_limited_after_repeated_failures() {
    let k = Kernel::in_memory().await.unwrap();
    bootstrap_admin(&k, "ratelimit").await;

    for _ in 0..10 {
        let err = k
            .login("ratelimit", "admin@example.test", "wrong-pass", "r", Source::Api)
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::Unauthorized);
    }
    // The 11th attempt is locked out — even with the correct password.
    let err = k
        .login("ratelimit", "admin@example.test", "pw-admin-123", "r", Source::Api)
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::RateLimited);

    // Another user in the same tenant is unaffected (per-identity limiter).
    let err = k
        .login("ratelimit", "other@example.test", "wrong-pass", "r", Source::Api)
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Unauthorized);
}

#[tokio::test]
async fn failed_logins_are_audited() {
    let k = Kernel::in_memory().await.unwrap();
    let admin = bootstrap_admin(&k, "auditfail").await;
    let _ = k
        .login("auditfail", "admin@example.test", "nope-nope", "r", Source::Api)
        .await
        .unwrap_err();

    // Failure rows are recorded under the slug-scoped pseudo tenant so they
    // exist even when the tenant cannot be resolved.
    let sys = AuthContext::system("slug:auditfail", &admin.org_id);
    let events = k
        .audit_query(
            &sys,
            &latentdb_contracts::AuditQuery {
                actor_id: None,
                action: Some("auth.login.failed".into()),
                target_object_type: None,
                target_record_id: None,
                since: None,
                until: None,
                limit: None,
                offset: None,
            },
        )
        .await
        .unwrap();
    assert!(!events.is_empty(), "expected an auth.login.failed event");
    assert_eq!(events[0].reason.as_deref(), Some("bad_password"));
}

#[tokio::test]
async fn login_email_is_case_insensitive() {
    let k = Kernel::in_memory().await.unwrap();
    bootstrap_admin(&k, "caseco").await;
    let res = k
        .login("caseco", "  ADMIN@Example.Test ", "pw-admin-123", "r", Source::Api)
        .await
        .unwrap();
    assert_eq!(res.email, "admin@example.test");
}

#[tokio::test]
async fn disabling_a_user_revokes_sessions_and_api_keys() {
    let k = Kernel::in_memory().await.unwrap();
    let admin = bootstrap_admin(&k, "lifecycle").await;

    let user = k
        .create_user(
            &admin,
            "worker@example.test",
            "Worker",
            "pw-worker-123",
            &["member".to_string()],
        )
        .await
        .unwrap();
    let key = k
        .create_api_key(&admin, "worker key", Some(&user.id), "user")
        .await
        .unwrap();
    let session = k
        .login("lifecycle", "worker@example.test", "pw-worker-123", "r", Source::Api)
        .await
        .unwrap();

    // Both credentials work while the user is active.
    k.authenticate(&session.token, "r", Source::Api).await.unwrap();
    k.authenticate(&key.token, "r", Source::Api).await.unwrap();

    k.set_user_status(&admin, &user.id, "disabled").await.unwrap();

    let err = k
        .authenticate(&session.token, "r", Source::Api)
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Unauthorized);
    let err = k
        .authenticate(&key.token, "r", Source::Api)
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Unauthorized);

    // And the disabled user can no longer log in.
    let err = k
        .login("lifecycle", "worker@example.test", "pw-worker-123", "r", Source::Api)
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Unauthorized);
}

#[tokio::test]
async fn admins_cannot_disable_themselves() {
    let k = Kernel::in_memory().await.unwrap();
    let admin = bootstrap_admin(&k, "selfdisable").await;
    let err = k
        .set_user_status(&admin, &admin.actor_id, "disabled")
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::FailedPrecondition);
}

#[tokio::test]
async fn suspending_a_tenant_blocks_existing_credentials() {
    let k = Kernel::in_memory().await.unwrap();
    let admin = bootstrap_admin(&k, "suspendco").await;
    let session = k
        .login("suspendco", "admin@example.test", "pw-admin-123", "r", Source::Api)
        .await
        .unwrap();

    let platform = AuthContext::system(&admin.tenant_id, &admin.org_id);
    k.set_tenant_status(&platform, &admin.tenant_id, "suspended")
        .await
        .unwrap();

    let err = k
        .authenticate(&session.token, "r", Source::Api)
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Unauthorized);
    let err = k
        .login("suspendco", "admin@example.test", "pw-admin-123", "r", Source::Api)
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Unauthorized);

    // Re-activation restores access.
    k.set_tenant_status(&platform, &admin.tenant_id, "active")
        .await
        .unwrap();
    k.authenticate(&session.token, "r", Source::Api).await.unwrap();
}

#[tokio::test]
async fn tenant_status_change_requires_platform_admin() {
    let k = Kernel::in_memory().await.unwrap();
    let admin = bootstrap_admin(&k, "notplatform").await;
    let err = k
        .set_tenant_status(&admin, &admin.tenant_id, "suspended")
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Forbidden);
}

#[tokio::test]
async fn api_keys_cannot_be_minted_for_foreign_principals() {
    let k = Kernel::in_memory().await.unwrap();
    let admin_a = bootstrap_admin(&k, "keytenant-a").await;
    let admin_b = {
        k.bootstrap_tenant("TestCo B", "keytenant-b", "b@example.test", "B", "pw-admin-123")
            .await
            .unwrap();
        let l = k
            .login("keytenant-b", "b@example.test", "pw-admin-123", "r", Source::Api)
            .await
            .unwrap();
        k.authenticate(&l.token, "r", Source::Api).await.unwrap()
    };

    // Tenant A's admin cannot bind a key to tenant B's admin.
    let err = k
        .create_api_key(&admin_a, "stolen", Some(&admin_b.actor_id), "user")
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Validation);

    // Invalid principal types are rejected outright.
    let err = k
        .create_api_key(&admin_a, "bad type", None, "wizard")
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Validation);
}

#[tokio::test]
async fn password_policy_and_email_format_are_enforced() {
    let k = Kernel::in_memory().await.unwrap();
    let admin = bootstrap_admin(&k, "policyco").await;

    let err = k
        .create_user(&admin, "u@example.test", "U", "short", &[])
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Validation);

    let err = k
        .create_user(&admin, "not-an-email", "U", "long-enough-pass", &[])
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Validation);

    let err = k
        .bootstrap_tenant("X", "bad slug!", "x@example.test", "X", "pw-admin-123")
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Validation);
}

#[tokio::test]
async fn requester_cannot_decide_own_approval_when_sod_enabled() {
    let flags = FeatureFlags {
        enable_approval_separation_of_duties: true,
        ..FeatureFlags::default()
    };
    let k = Kernel::open(StoreConfig::memory(), flags).await.unwrap();
    let admin = bootstrap_admin(&k, "sodco").await;

    let wf = WorkflowDef {
        key: "invoice_wf".into(),
        object_type: "invoice".into(),
        name: "Invoice Approval".into(),
        initial_state: "draft".into(),
        states: vec![
            WorkflowState { key: "draft".into(), label: "Draft".into(), terminal: false },
            WorkflowState { key: "approved".into(), label: "Approved".into(), terminal: true },
        ],
        transitions: vec![Transition {
            key: "approve".into(),
            from: "draft".into(),
            to: "approved".into(),
            label: "Approve".into(),
            guard_permission: None,
            requires_approval: true,
            approval_policy: Some("finance".into()),
        }],
    };
    k.create_workflow(&admin, &wf).await.unwrap();
    k.create_object_type(
        &admin,
        &ObjectTypeDef {
            id: String::new(),
            key: "invoice".into(),
            label: "Invoice".into(),
            label_plural: None,
            description: None,
            system: false,
            workflow_key: Some("invoice_wf".into()),
            display_field: None,
            module: None,
            fields: vec![FieldDefinition::new("number", "Number", FieldType::Text).required()],
        },
    )
    .await
    .unwrap();

    let rec = k
        .create_record(
            &admin,
            &NewRecord {
                object_type: "invoice".into(),
                data: obj(json!({"number": "INV-1"})),
                workspace_id: None,
            },
        )
        .await
        .unwrap();
    let res = k
        .transition_record(&admin, &rec.id, "approve", None)
        .await
        .unwrap();
    let approval_id = res.approval_id.unwrap();

    // The requesting admin cannot approve their own request.
    let err = k
        .decide_approval(&admin, &approval_id, true, Some("self"))
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Forbidden);

    // A second admin can.
    k.create_user(
        &admin,
        "approver@example.test",
        "Approver",
        "pw-approver-1",
        &["tenant_admin".to_string()],
    )
    .await
    .unwrap();
    let login = k
        .login("sodco", "approver@example.test", "pw-approver-1", "r", Source::Api)
        .await
        .unwrap();
    let other_ctx = k.authenticate(&login.token, "r", Source::Api).await.unwrap();
    let decided = k
        .decide_approval(&other_ctx, &approval_id, true, Some("ok"))
        .await
        .unwrap();
    assert_eq!(decided.status, "approved");
}

#[tokio::test]
async fn session_cleanup_removes_revoked_sessions() {
    let k = Kernel::in_memory().await.unwrap();
    bootstrap_admin(&k, "cleanco").await;
    let session = k
        .login("cleanco", "admin@example.test", "pw-admin-123", "r", Source::Api)
        .await
        .unwrap();
    k.logout(&session.token).await.unwrap();
    let removed = k.cleanup_expired_sessions().await.unwrap();
    assert!(removed >= 1, "expected at least one session purged");
    // Housekeeping wrapper runs end-to-end too.
    k.run_housekeeping().await.unwrap();
}

#[tokio::test]
async fn usage_metering_counts_per_tenant() {
    let k = Kernel::in_memory().await.unwrap();
    let admin = bootstrap_admin(&k, "meterco").await;
    k.meter_api_call(&admin).await;
    k.meter_api_call(&admin).await;
    let meters = k.list_usage(&admin).await.unwrap();
    let api_calls = meters
        .iter()
        .find(|m| m.metric == "api_calls")
        .expect("api_calls meter present");
    assert!(api_calls.value >= 2);
}
