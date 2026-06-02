//! The product API: application state, router, and handlers.
//!
//! Handlers are deliberately thin — they validate/shape input and delegate to
//! kernel services, which own tenant isolation, permission checks, and audit.
//! The API never reaches around the kernel to the database. The same endpoints
//! back both developer/SDK usage and the admin/business UI.

use crate::auth::Auth;
use crate::error::ApiJson;
use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use latentdb_contracts::{
    AuditQuery, AuthContext, ListResponse, NewRecord, ObjectTypeDef, PermissionGrant, Record,
    RecordFilter, RecordPatch, Source, WorkflowDef,
};
use latentdb_kernel::analytics::{Dashboard, ReportDef, ReportResult};
use latentdb_kernel::approval::Approval;
use latentdb_kernel::identity::{NewApiKey, User};
use latentdb_kernel::record::RelationEdge;
use latentdb_kernel::task::Task;
use latentdb_kernel::tenant::{BootstrapResult, Organization, Tenant};
use latentdb_kernel::transition::TransitionResult;
use latentdb_kernel::Kernel;
use latentdb_ai::{action, AgentAction, AiAnswer, AiEngine};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Clone)]
pub struct AppState {
    pub kernel: Kernel,
    pub ai: AiEngine,
}

/// Build the full application router.
pub fn router(state: AppState) -> Router {
    Router::new()
        // --- public ---
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/v1/auth/login", post(login))
        // --- authenticated ---
        .route("/v1/auth/logout", post(logout))
        .route("/v1/auth/me", get(me))
        .route("/v1/bootstrap", post(bootstrap))
        .route("/v1/tenant", get(get_tenant))
        .route("/v1/tenants", get(list_tenants))
        .route("/v1/organizations", get(list_orgs))
        .route("/v1/users", get(list_users).post(create_user))
        .route("/v1/users/:id", get(get_user))
        .route("/v1/roles", get(list_roles).post(create_role))
        .route("/v1/api-keys", post(create_api_key))
        .route("/v1/object-types", get(list_object_types).post(create_object_type))
        .route("/v1/object-types/:key", get(get_object_type).put(update_object_type))
        .route(
            "/v1/object-types/:key/records",
            get(list_records).post(create_record),
        )
        .route("/v1/records/:id", get(get_record).patch(update_record).delete(archive_record))
        .route("/v1/records/:id/restore", post(restore_record))
        .route("/v1/records/:id/relations", get(get_relations).post(create_relation))
        .route("/v1/records/:id/transitions", get(list_transitions).post(do_transition))
        .route("/v1/workflows", get(list_workflows).post(create_workflow))
        .route("/v1/workflows/:key", get(get_workflow))
        .route("/v1/tasks", get(list_tasks).post(create_task))
        .route("/v1/tasks/:id/complete", post(complete_task))
        .route("/v1/approvals", get(list_approvals))
        .route("/v1/approvals/:id", get(get_approval))
        .route("/v1/approvals/:id/decide", post(decide_approval))
        .route("/v1/audit", get(query_audit))
        .route("/v1/reports", get(list_reports).post(save_report))
        .route("/v1/reports/run", post(run_report_adhoc))
        .route("/v1/reports/:key/run", get(run_report))
        .route("/v1/dashboards", get(list_dashboards).post(save_dashboard))
        .route("/v1/dashboards/:key", get(get_dashboard))
        // --- AI / agents ---
        .route("/v1/ai/ask", post(ai_ask))
        .route("/v1/ai/bi/ask", post(ai_bi_ask))
        .route("/v1/ai/records/:id/summary", post(ai_summarize))
        .route("/v1/ai/agents/finance/cashflow-risk", post(ai_finance))
        .route("/v1/ai/agents/procurement/low-stock", post(ai_procurement))
        .route("/v1/ai/agents/sales/deal-risk", post(ai_sales))
        .route("/v1/ai/actions/dry-run", post(ai_dry_run))
        .route("/v1/ai/actions/execute", post(ai_execute))
        .with_state(state)
}

// ----------------------------------------------------------------------------
// Health
// ----------------------------------------------------------------------------

#[derive(Serialize)]
struct Health {
    status: &'static str,
}

async fn healthz() -> Json<Health> {
    Json(Health { status: "ok" })
}

async fn readyz(State(s): State<AppState>) -> ApiJson<Health> {
    s.kernel.ping().await?;
    Ok(Json(Health { status: "ready" }))
}

// ----------------------------------------------------------------------------
// Auth
// ----------------------------------------------------------------------------

#[derive(Deserialize)]
struct LoginReq {
    tenant: String,
    email: String,
    password: String,
}

async fn login(
    State(s): State<AppState>,
    Json(req): Json<LoginReq>,
) -> ApiJson<latentdb_kernel::auth::LoginResult> {
    let res = s
        .kernel
        .login(&req.tenant, &req.email, &req.password, &latentdb_contracts::ids::new_id(), Source::Api)
        .await?;
    Ok(Json(res))
}

#[derive(Serialize)]
struct Ok2 {
    ok: bool,
}

async fn logout(State(s): State<AppState>, headers: axum::http::HeaderMap) -> ApiJson<Ok2> {
    if let Some(tok) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
    {
        s.kernel.logout(tok.trim()).await?;
    }
    Ok(Json(Ok2 { ok: true }))
}

#[derive(Serialize)]
struct Me {
    actor_type: latentdb_contracts::ActorType,
    actor_id: String,
    tenant_id: String,
    org_id: String,
    role_keys: Vec<String>,
    is_platform_admin: bool,
}

async fn me(Auth(ctx): Auth) -> Json<Me> {
    Json(Me {
        actor_type: ctx.actor_type,
        actor_id: ctx.actor_id,
        tenant_id: ctx.tenant_id,
        org_id: ctx.org_id,
        role_keys: ctx.role_keys,
        is_platform_admin: ctx.is_platform_admin,
    })
}

// ----------------------------------------------------------------------------
// Tenants / orgs / bootstrap
// ----------------------------------------------------------------------------

#[derive(Deserialize)]
struct BootstrapReq {
    name: String,
    slug: String,
    admin_email: String,
    admin_name: String,
    admin_password: String,
}

async fn bootstrap(
    State(s): State<AppState>,
    Auth(ctx): Auth,
    Json(req): Json<BootstrapReq>,
) -> ApiJson<BootstrapResult> {
    // Provisioning a new tenant is a platform-admin action.
    if !ctx.is_platform_admin {
        return Err(latentdb_contracts::ApiError::forbidden("platform admin required").into());
    }
    let res = s
        .kernel
        .bootstrap_tenant(&req.name, &req.slug, &req.admin_email, &req.admin_name, &req.admin_password)
        .await?;
    Ok(Json(res))
}

async fn get_tenant(State(s): State<AppState>, Auth(ctx): Auth) -> ApiJson<Tenant> {
    Ok(Json(s.kernel.get_tenant(&ctx).await?))
}

async fn list_tenants(State(s): State<AppState>, Auth(ctx): Auth) -> ApiJson<Vec<Tenant>> {
    Ok(Json(s.kernel.list_tenants(&ctx).await?))
}

async fn list_orgs(State(s): State<AppState>, Auth(ctx): Auth) -> ApiJson<Vec<Organization>> {
    Ok(Json(s.kernel.list_organizations(&ctx).await?))
}

// ----------------------------------------------------------------------------
// Identity
// ----------------------------------------------------------------------------

#[derive(Deserialize)]
struct CreateUserReq {
    email: String,
    name: String,
    password: String,
    #[serde(default)]
    roles: Vec<String>,
}

async fn create_user(
    State(s): State<AppState>,
    Auth(ctx): Auth,
    Json(req): Json<CreateUserReq>,
) -> ApiJson<User> {
    Ok(Json(
        s.kernel.create_user(&ctx, &req.email, &req.name, &req.password, &req.roles).await?,
    ))
}

async fn list_users(State(s): State<AppState>, Auth(ctx): Auth) -> ApiJson<Vec<User>> {
    Ok(Json(s.kernel.list_users(&ctx).await?))
}

async fn get_user(
    State(s): State<AppState>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
) -> ApiJson<User> {
    Ok(Json(s.kernel.get_user(&ctx, &id).await?))
}

#[derive(Deserialize)]
struct CreateRoleReq {
    key: String,
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    grants: Vec<PermissionGrant>,
}

async fn create_role(
    State(s): State<AppState>,
    Auth(ctx): Auth,
    Json(req): Json<CreateRoleReq>,
) -> ApiJson<latentdb_contracts::Role> {
    Ok(Json(
        s.kernel.create_role(&ctx, &req.key, &req.name, req.description.as_deref(), &req.grants).await?,
    ))
}

async fn list_roles(
    State(s): State<AppState>,
    Auth(ctx): Auth,
) -> ApiJson<Vec<latentdb_contracts::Role>> {
    Ok(Json(s.kernel.list_roles(&ctx).await?))
}

#[derive(Deserialize)]
struct CreateApiKeyReq {
    name: String,
    #[serde(default)]
    principal_id: Option<String>,
    #[serde(default = "default_principal_type")]
    principal_type: String,
}

fn default_principal_type() -> String {
    "user".into()
}

async fn create_api_key(
    State(s): State<AppState>,
    Auth(ctx): Auth,
    Json(req): Json<CreateApiKeyReq>,
) -> ApiJson<NewApiKey> {
    Ok(Json(
        s.kernel.create_api_key(&ctx, &req.name, req.principal_id.as_deref(), &req.principal_type).await?,
    ))
}

// ----------------------------------------------------------------------------
// Object types
// ----------------------------------------------------------------------------

async fn create_object_type(
    State(s): State<AppState>,
    Auth(ctx): Auth,
    Json(def): Json<ObjectTypeDef>,
) -> ApiJson<ObjectTypeDef> {
    Ok(Json(s.kernel.create_object_type(&ctx, &def).await?))
}

async fn update_object_type(
    State(s): State<AppState>,
    Auth(ctx): Auth,
    Path(key): Path<String>,
    Json(def): Json<ObjectTypeDef>,
) -> ApiJson<ObjectTypeDef> {
    Ok(Json(s.kernel.update_object_type(&ctx, &key, &def).await?))
}

async fn get_object_type(
    State(s): State<AppState>,
    Auth(ctx): Auth,
    Path(key): Path<String>,
) -> ApiJson<ObjectTypeDef> {
    Ok(Json(s.kernel.get_object_type(&ctx, &key).await?))
}

async fn list_object_types(
    State(s): State<AppState>,
    Auth(ctx): Auth,
) -> ApiJson<Vec<ObjectTypeDef>> {
    Ok(Json(s.kernel.list_object_types(&ctx).await?))
}

// ----------------------------------------------------------------------------
// Records
// ----------------------------------------------------------------------------

#[derive(Deserialize)]
struct ListParams {
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    offset: Option<i64>,
    #[serde(default)]
    search: Option<String>,
    #[serde(default)]
    sort: Option<String>,
    #[serde(default)]
    desc: bool,
    #[serde(default)]
    include_archived: bool,
}

impl ListParams {
    fn into_filter(self) -> RecordFilter {
        let mut f = RecordFilter {
            search: self.search,
            sort: self.sort,
            desc: self.desc,
            include_archived: self.include_archived,
            ..Default::default()
        };
        if let Some(l) = self.limit {
            f.page.limit = l;
        }
        if let Some(o) = self.offset {
            f.page.offset = o;
        }
        f
    }
}

async fn list_records(
    State(s): State<AppState>,
    Auth(ctx): Auth,
    Path(key): Path<String>,
    Query(p): Query<ListParams>,
) -> ApiJson<ListResponse<Record>> {
    Ok(Json(s.kernel.list_records(&ctx, &key, &p.into_filter()).await?))
}

#[derive(Deserialize)]
struct NewRecordBody {
    #[serde(default)]
    data: Map<String, Value>,
    #[serde(default)]
    workspace_id: Option<String>,
}

async fn create_record(
    State(s): State<AppState>,
    Auth(ctx): Auth,
    Path(key): Path<String>,
    Json(body): Json<NewRecordBody>,
) -> ApiJson<Record> {
    let new = NewRecord {
        object_type: key,
        data: body.data,
        workspace_id: body.workspace_id,
    };
    Ok(Json(s.kernel.create_record(&ctx, &new).await?))
}

async fn get_record(
    State(s): State<AppState>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
) -> ApiJson<Record> {
    Ok(Json(s.kernel.get_record(&ctx, &id).await?))
}

async fn update_record(
    State(s): State<AppState>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
    Json(patch): Json<RecordPatch>,
) -> ApiJson<Record> {
    Ok(Json(s.kernel.update_record(&ctx, &id, &patch).await?))
}

async fn archive_record(
    State(s): State<AppState>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
) -> ApiJson<Ok2> {
    s.kernel.archive_record(&ctx, &id).await?;
    Ok(Json(Ok2 { ok: true }))
}

async fn restore_record(
    State(s): State<AppState>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
) -> ApiJson<Ok2> {
    s.kernel.restore_record(&ctx, &id).await?;
    Ok(Json(Ok2 { ok: true }))
}

#[derive(Deserialize)]
struct RelateReq {
    to: String,
    relation_type: String,
}

async fn create_relation(
    State(s): State<AppState>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
    Json(req): Json<RelateReq>,
) -> ApiJson<RelationEdge> {
    Ok(Json(s.kernel.relate(&ctx, &id, &req.to, &req.relation_type).await?))
}

async fn get_relations(
    State(s): State<AppState>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
) -> ApiJson<Vec<RelationEdge>> {
    Ok(Json(s.kernel.get_relations(&ctx, &id).await?))
}

// ----------------------------------------------------------------------------
// Workflows + transitions
// ----------------------------------------------------------------------------

async fn create_workflow(
    State(s): State<AppState>,
    Auth(ctx): Auth,
    Json(def): Json<WorkflowDef>,
) -> ApiJson<WorkflowDef> {
    Ok(Json(s.kernel.create_workflow(&ctx, &def).await?))
}

async fn list_workflows(State(s): State<AppState>, Auth(ctx): Auth) -> ApiJson<Vec<WorkflowDef>> {
    Ok(Json(s.kernel.list_workflows(&ctx).await?))
}

async fn get_workflow(
    State(s): State<AppState>,
    Auth(ctx): Auth,
    Path(key): Path<String>,
) -> ApiJson<WorkflowDef> {
    Ok(Json(s.kernel.get_workflow(&ctx, &key).await?))
}

async fn list_transitions(
    State(s): State<AppState>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
) -> ApiJson<Vec<latentdb_contracts::Transition>> {
    Ok(Json(s.kernel.available_transitions(&ctx, &id).await?))
}

#[derive(Deserialize)]
struct TransitionReq {
    key: String,
    #[serde(default)]
    reason: Option<String>,
}

async fn do_transition(
    State(s): State<AppState>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
    Json(req): Json<TransitionReq>,
) -> ApiJson<TransitionResult> {
    Ok(Json(s.kernel.transition_record(&ctx, &id, &req.key, req.reason.as_deref()).await?))
}

// ----------------------------------------------------------------------------
// Tasks + approvals
// ----------------------------------------------------------------------------

#[derive(Deserialize)]
struct TaskParams {
    #[serde(default)]
    mine: bool,
    #[serde(default)]
    status: Option<String>,
}

async fn list_tasks(
    State(s): State<AppState>,
    Auth(ctx): Auth,
    Query(p): Query<TaskParams>,
) -> ApiJson<Vec<Task>> {
    Ok(Json(s.kernel.list_tasks(&ctx, p.mine, p.status.as_deref()).await?))
}

#[derive(Deserialize)]
struct CreateTaskReq {
    kind: String,
    title: String,
    #[serde(default)]
    assignee_id: Option<String>,
    #[serde(default)]
    related_object_type: Option<String>,
    #[serde(default)]
    related_record_id: Option<String>,
    #[serde(default)]
    data: Value,
}

async fn create_task(
    State(s): State<AppState>,
    Auth(ctx): Auth,
    Json(req): Json<CreateTaskReq>,
) -> ApiJson<Task> {
    Ok(Json(
        s.kernel
            .create_task(
                &ctx,
                &req.kind,
                &req.title,
                req.assignee_id.as_deref(),
                req.related_object_type.as_deref(),
                req.related_record_id.as_deref(),
                req.data,
            )
            .await?,
    ))
}

#[derive(Deserialize)]
struct CompleteTaskReq {
    #[serde(default = "default_done")]
    status: String,
}

fn default_done() -> String {
    "done".into()
}

async fn complete_task(
    State(s): State<AppState>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
    Json(req): Json<CompleteTaskReq>,
) -> ApiJson<Task> {
    Ok(Json(s.kernel.complete_task(&ctx, &id, &req.status).await?))
}

async fn list_approvals(State(s): State<AppState>, Auth(ctx): Auth) -> ApiJson<Vec<Approval>> {
    Ok(Json(s.kernel.list_pending_approvals(&ctx).await?))
}

async fn get_approval(
    State(s): State<AppState>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
) -> ApiJson<Approval> {
    Ok(Json(s.kernel.get_approval(&ctx, &id).await?))
}

#[derive(Deserialize)]
struct DecideReq {
    approved: bool,
    #[serde(default)]
    reason: Option<String>,
}

async fn decide_approval(
    State(s): State<AppState>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
    Json(req): Json<DecideReq>,
) -> ApiJson<Approval> {
    Ok(Json(s.kernel.decide_approval(&ctx, &id, req.approved, req.reason.as_deref()).await?))
}

// ----------------------------------------------------------------------------
// Audit
// ----------------------------------------------------------------------------

#[derive(Deserialize)]
struct AuditParams {
    #[serde(default)]
    actor_id: Option<String>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    object_type: Option<String>,
    #[serde(default)]
    record_id: Option<String>,
    #[serde(default)]
    since: Option<String>,
    #[serde(default)]
    until: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    offset: Option<i64>,
}

async fn query_audit(
    State(s): State<AppState>,
    Auth(ctx): Auth,
    Query(p): Query<AuditParams>,
) -> ApiJson<Vec<latentdb_contracts::AuditEvent>> {
    let q = AuditQuery {
        actor_id: p.actor_id,
        action: p.action,
        target_object_type: p.object_type,
        target_record_id: p.record_id,
        since: p.since,
        until: p.until,
        limit: p.limit,
        offset: p.offset,
    };
    Ok(Json(s.kernel.audit_query(&ctx, &q).await?))
}

// ----------------------------------------------------------------------------
// Reports, dashboards (BI)
// ----------------------------------------------------------------------------

async fn list_reports(State(s): State<AppState>, Auth(ctx): Auth) -> ApiJson<Vec<ReportDef>> {
    Ok(Json(s.kernel.list_reports(&ctx).await?))
}

async fn save_report(
    State(s): State<AppState>,
    Auth(ctx): Auth,
    Json(def): Json<ReportDef>,
) -> ApiJson<ReportDef> {
    Ok(Json(s.kernel.save_report(&ctx, &def).await?))
}

async fn run_report(
    State(s): State<AppState>,
    Auth(ctx): Auth,
    Path(key): Path<String>,
) -> ApiJson<ReportResult> {
    Ok(Json(s.kernel.run_report(&ctx, &key).await?))
}

async fn run_report_adhoc(
    State(s): State<AppState>,
    Auth(ctx): Auth,
    Json(def): Json<ReportDef>,
) -> ApiJson<ReportResult> {
    Ok(Json(s.kernel.run_report_def(&ctx, &def).await?))
}

async fn list_dashboards(State(s): State<AppState>, Auth(ctx): Auth) -> ApiJson<Vec<Dashboard>> {
    Ok(Json(s.kernel.list_dashboards(&ctx).await?))
}

async fn save_dashboard(
    State(s): State<AppState>,
    Auth(ctx): Auth,
    Json(dash): Json<Dashboard>,
) -> ApiJson<Dashboard> {
    Ok(Json(s.kernel.save_dashboard(&ctx, &dash).await?))
}

async fn get_dashboard(
    State(s): State<AppState>,
    Auth(ctx): Auth,
    Path(key): Path<String>,
) -> ApiJson<Dashboard> {
    Ok(Json(s.kernel.get_dashboard(&ctx, &key).await?))
}

// ----------------------------------------------------------------------------
// AI / agents
// ----------------------------------------------------------------------------

#[derive(Deserialize)]
struct AskReq {
    question: String,
    #[serde(default)]
    object_types: Vec<String>,
}

async fn ai_ask(
    State(s): State<AppState>,
    Auth(ctx): Auth,
    Json(req): Json<AskReq>,
) -> ApiJson<AiAnswer> {
    Ok(Json(s.ai.agents().ask(&s.kernel, &ctx, &req.question, &req.object_types).await?))
}

#[derive(Deserialize)]
struct BiAskReq {
    question: String,
}

async fn ai_bi_ask(
    State(s): State<AppState>,
    Auth(ctx): Auth,
    Json(req): Json<BiAskReq>,
) -> ApiJson<AiAnswer> {
    Ok(Json(s.ai.agents().bi_answer(&s.kernel, &ctx, &req.question).await?))
}

async fn ai_summarize(
    State(s): State<AppState>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
) -> ApiJson<AiAnswer> {
    Ok(Json(s.ai.agents().summarize_record(&s.kernel, &ctx, &id).await?))
}

async fn ai_finance(State(s): State<AppState>, Auth(ctx): Auth) -> ApiJson<AiAnswer> {
    Ok(Json(s.ai.agents().finance_cashflow_risk(&s.kernel, &ctx).await?))
}

async fn ai_procurement(State(s): State<AppState>, Auth(ctx): Auth) -> ApiJson<AiAnswer> {
    Ok(Json(s.ai.agents().procurement_low_stock(&s.kernel, &ctx).await?))
}

async fn ai_sales(State(s): State<AppState>, Auth(ctx): Auth) -> ApiJson<AiAnswer> {
    Ok(Json(s.ai.agents().sales_deal_risk(&s.kernel, &ctx).await?))
}

async fn ai_dry_run(
    State(s): State<AppState>,
    Auth(ctx): Auth,
    Json(act): Json<AgentAction>,
) -> ApiJson<action::ActionPlan> {
    Ok(Json(latentdb_ai::dry_run(&s.kernel, &ctx, &act).await?))
}

#[derive(Deserialize)]
struct ExecuteReq {
    action: AgentAction,
    #[serde(default)]
    approved: bool,
}

async fn ai_execute(
    State(s): State<AppState>,
    Auth(ctx): Auth,
    Json(req): Json<ExecuteReq>,
) -> ApiJson<Value> {
    Ok(Json(latentdb_ai::execute(&s.kernel, &ctx, &req.action, req.approved).await?))
}

// Keep `AuthContext` import meaningful for downstream phases.
#[allow(dead_code)]
fn _ctx_type(_c: &AuthContext) {}
