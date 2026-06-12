//! Governed dynamic object builder.

use crate::analytics::ReportDef;
use crate::audit::{event_from, insert_audit};
use crate::store::map_db_err;
use crate::Kernel;
use latentdb_contracts::builder::{workflow_state, workflow_transition};
use latentdb_contracts::{
    ids, Action, ApiError, AuthContext, BuilderDefinition, BuilderDraft, BuilderStatus,
    BuilderTemplate, BuilderValidationResult, FieldDefinition, FieldType, InstallTemplateRequest,
    InstallTemplateResult, NewRecord, PublishBuilderResult, SaveBuilderDraftRequest,
    ValidationIssue,
};
use serde_json::{json, Value};
use sqlx::Row;
use std::collections::HashSet;

impl Kernel {
    pub async fn list_builder_drafts(
        &self,
        ctx: &AuthContext,
    ) -> latentdb_contracts::Result<Vec<BuilderDraft>> {
        self.authorize(ctx, Action::Configure, "builder", None)
            .await?;
        let rows = sqlx::query(
            "SELECT * FROM builder_drafts WHERE tenant_id = ? ORDER BY updated_at DESC",
        )
        .bind(&ctx.tenant_id)
        .fetch_all(self.pool())
        .await
        .map_err(map_db_err)?;
        rows.iter().map(row_to_draft).collect()
    }

    pub async fn get_builder_draft(
        &self,
        ctx: &AuthContext,
        id: &str,
    ) -> latentdb_contracts::Result<BuilderDraft> {
        self.authorize(ctx, Action::Configure, "builder", None)
            .await?;
        let row = sqlx::query("SELECT * FROM builder_drafts WHERE tenant_id = ? AND id = ?")
            .bind(&ctx.tenant_id)
            .bind(id)
            .fetch_optional(self.pool())
            .await
            .map_err(map_db_err)?
            .ok_or_else(|| ApiError::not_found("builder draft not found"))?;
        row_to_draft(&row)
    }

    pub async fn save_builder_draft(
        &self,
        ctx: &AuthContext,
        req: &SaveBuilderDraftRequest,
    ) -> latentdb_contracts::Result<BuilderDraft> {
        self.authorize(ctx, Action::Configure, "builder", None)
            .await?;
        let id = req.id.clone().unwrap_or_else(ids::new_id);
        let now = ids::now_rfc3339();
        let status = if self
            .validate_builder_definition(ctx, &req.definition)
            .await?
            .valid
        {
            BuilderStatus::Validated
        } else {
            BuilderStatus::Draft
        };
        let definition_json = serde_json::to_string(&req.definition)
            .map_err(|e| ApiError::internal(format!("serialize builder draft: {e}")))?;
        let mut tx = self.pool().begin().await.map_err(map_db_err)?;
        sqlx::query(
            r#"INSERT INTO builder_drafts (id, tenant_id, status, key, definition_json, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?)
               ON CONFLICT(tenant_id, key) DO UPDATE SET
                 status = excluded.status,
                 definition_json = excluded.definition_json,
                 updated_at = excluded.updated_at"#,
        )
        .bind(&id)
        .bind(&ctx.tenant_id)
        .bind(status_str(&status))
        .bind(&req.definition.key)
        .bind(&definition_json)
        .bind(&now)
        .bind(&now)
        .execute(&mut *tx)
        .await
        .map_err(map_db_err)?;
        let ev = event_from(
            ctx,
            "builder.draft.save",
            Some("builder_draft"),
            Some(&req.definition.key),
            None,
            Some(json!({"status": status, "fields": req.definition.fields.len()})),
        );
        insert_audit(&mut tx, &ev).await?;
        tx.commit().await.map_err(map_db_err)?;
        match self.get_builder_draft(ctx, &id).await {
            Ok(draft) => Ok(draft),
            Err(_) => {
                // Upsert by key may have preserved an existing id.
                let key = req.definition.key.clone();
                let row =
                    sqlx::query("SELECT * FROM builder_drafts WHERE tenant_id = ? AND key = ?")
                        .bind(&ctx.tenant_id)
                        .bind(key)
                        .fetch_optional(self.pool())
                        .await
                        .map_err(map_db_err)?
                        .ok_or_else(|| ApiError::not_found("builder draft not found"))?;
                row_to_draft(&row)
            }
        }
    }

    pub async fn validate_builder_draft(
        &self,
        ctx: &AuthContext,
        id: &str,
    ) -> latentdb_contracts::Result<BuilderValidationResult> {
        let draft = self.get_builder_draft(ctx, id).await?;
        self.validate_builder_definition(ctx, &draft.definition)
            .await
    }

    pub async fn validate_builder_definition(
        &self,
        ctx: &AuthContext,
        def: &BuilderDefinition,
    ) -> latentdb_contracts::Result<BuilderValidationResult> {
        self.authorize(ctx, Action::Configure, "builder", None)
            .await?;
        let mut issues = Vec::new();
        validate_key("key", &def.key, &mut issues);
        if def.label.trim().is_empty() {
            issues.push(issue("label", "display name is required"));
        }
        if def.fields.is_empty() {
            issues.push(issue("fields", "at least one field is required"));
        }
        let mut seen = HashSet::new();
        let object_types = self.list_object_types(ctx).await.unwrap_or_default();
        let object_keys: HashSet<_> = object_types.iter().map(|o| o.key.as_str()).collect();
        for (idx, field) in def.fields.iter().enumerate() {
            let path = format!("fields[{idx}]");
            validate_key(&format!("{path}.key"), &field.key, &mut issues);
            if !seen.insert(field.key.as_str()) {
                issues.push(issue(&format!("{path}.key"), "field keys must be unique"));
            }
            if matches!(field.field_type, FieldType::Enum | FieldType::MultiEnum)
                && field.enum_options.is_empty()
            {
                issues.push(issue(&path, "enum fields require options"));
            }
            if field.field_type == FieldType::RecordRef {
                match field.ref_object_type.as_deref() {
                    Some(target) if object_keys.contains(target) || target == def.key => {}
                    _ => issues.push(issue(
                        &path,
                        "reference target must be an existing object type",
                    )),
                }
            }
            if field.restricted && field.ai_visible && !def.sensitive_ai_visibility_confirmed {
                issues.push(issue(
                    &path,
                    "sensitive AI visibility requires explicit confirmation",
                ));
            }
        }
        if let Some(display) = &def.display_field {
            if !def.fields.iter().any(|f| &f.key == display) {
                issues.push(issue(
                    "display_field",
                    "display field must be one of the fields",
                ));
            }
        }
        if let Some(workflow) = &def.workflow {
            let states: HashSet<_> = workflow.states.iter().map(|s| s.key.as_str()).collect();
            if !states.contains(workflow.initial_state.as_str()) {
                issues.push(issue("workflow.initial_state", "initial state must exist"));
            }
            for t in &workflow.transitions {
                if !states.contains(t.from.as_str()) || !states.contains(t.to.as_str()) {
                    issues.push(issue(
                        "workflow.transitions",
                        "transition references unknown state",
                    ));
                }
            }
        }
        for rel in &def.relations {
            if rel.to_object != def.key && !object_keys.contains(rel.to_object.as_str()) {
                issues.push(issue(
                    "relations",
                    "relation target must exist or be this draft object",
                ));
            }
            if matches!(rel.kind, latentdb_contracts::RelationKind::ManyToMany) {
                issues.push(issue(
                    "relations",
                    "many-to-many relations are not publishable in this build",
                ));
            }
        }
        let valid = issues.is_empty();
        Ok(BuilderValidationResult {
            valid,
            status: if valid {
                BuilderStatus::Validated
            } else {
                BuilderStatus::Draft
            },
            issues,
            preview: Some(json!({
                "object_type": def.to_object_type(),
                "workflow": def.workflow,
                "permissions": def.permissions,
                "approval_rules": def.approval_rules,
            })),
        })
    }

    pub async fn publish_builder_draft(
        &self,
        ctx: &AuthContext,
        id: &str,
    ) -> latentdb_contracts::Result<PublishBuilderResult> {
        let draft = self.get_builder_draft(ctx, id).await?;
        let validation = self
            .validate_builder_definition(ctx, &draft.definition)
            .await?;
        if !validation.valid {
            return Err(ApiError::validation("builder draft is not valid"));
        }
        if let Some(workflow) = &draft.definition.workflow {
            self.create_workflow(ctx, workflow).await?;
        }
        let object = draft.definition.to_object_type();
        let published = match self.create_object_type(ctx, &object).await {
            Ok(v) => v,
            Err(e) if e.code == latentdb_contracts::ErrorCode::Conflict => {
                self.update_object_type(ctx, &object.key, &object).await?
            }
            Err(e) => return Err(e),
        };
        let now = ids::now_rfc3339();
        let mut tx = self.pool().begin().await.map_err(map_db_err)?;
        sqlx::query(
            "UPDATE builder_drafts SET status = 'published', updated_at = ?, published_at = ? WHERE tenant_id = ? AND id = ?",
        )
        .bind(&now)
        .bind(&now)
        .bind(&ctx.tenant_id)
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(map_db_err)?;
        let ev = event_from(
            ctx,
            "builder.publish",
            Some("object_type"),
            Some(&published.key),
            None,
            Some(json!({"fields": published.fields.len()})),
        );
        insert_audit(&mut tx, &ev).await?;
        tx.commit().await.map_err(map_db_err)?;
        self.emit_event(
            ctx,
            "builder.object_published",
            json!({"object_type": published.key}),
        )
        .await?;
        let draft = self.get_builder_draft(ctx, id).await?;
        let workflow = draft.definition.workflow.clone();
        Ok(PublishBuilderResult {
            draft,
            object_type: published,
            workflow,
        })
    }

    pub async fn builder_templates(
        &self,
        ctx: &AuthContext,
    ) -> latentdb_contracts::Result<Vec<BuilderTemplate>> {
        self.authorize(ctx, Action::Configure, "builder", None)
            .await?;
        Ok(templates())
    }

    pub async fn install_builder_template(
        &self,
        ctx: &AuthContext,
        req: &InstallTemplateRequest,
    ) -> latentdb_contracts::Result<InstallTemplateResult> {
        self.authorize(ctx, Action::Configure, "builder", None)
            .await?;
        let template = templates()
            .into_iter()
            .find(|t| t.key == req.key)
            .ok_or_else(|| ApiError::not_found("builder template not found"))?;
        let mut object_types = Vec::new();
        for def in &template.objects {
            if let Some(wf) = &def.workflow {
                self.create_workflow(ctx, wf).await?;
            }
            let ot = def.to_object_type();
            let created = match self.create_object_type(ctx, &ot).await {
                Ok(v) => v,
                Err(e) if e.code == latentdb_contracts::ErrorCode::Conflict => {
                    self.update_object_type(ctx, &ot.key, &ot).await?
                }
                Err(e) => return Err(e),
            };
            object_types.push(created);
        }
        let mut record_count = 0;
        if req.include_sample_records {
            record_count = install_sample_records(self, ctx, &req.key).await?;
        }
        let (report_count, dashboard_count) = install_template_reports(self, ctx, &req.key).await?;
        let mut ev = event_from(
            ctx,
            "builder.template.install",
            Some("builder_template"),
            Some(&req.key),
            None,
            Some(json!({"objects": object_types.len(), "records": record_count})),
        );
        ev.client_meta = Some(json!({"template": req.key}));
        self.audit(&ev).await?;
        Ok(InstallTemplateResult {
            template_key: req.key.clone(),
            object_types,
            record_count,
            report_count,
            dashboard_count,
        })
    }
}

fn row_to_draft(row: &sqlx::sqlite::SqliteRow) -> latentdb_contracts::Result<BuilderDraft> {
    let definition_json: String = row.try_get("definition_json").map_err(map_db_err)?;
    let definition = serde_json::from_str(&definition_json)
        .map_err(|e| ApiError::internal(format!("parse builder draft: {e}")))?;
    Ok(BuilderDraft {
        id: row.try_get("id").map_err(map_db_err)?,
        tenant_id: row.try_get("tenant_id").map_err(map_db_err)?,
        status: parse_status(&row.try_get::<String, _>("status").map_err(map_db_err)?),
        definition,
        created_at: row.try_get("created_at").map_err(map_db_err)?,
        updated_at: row.try_get("updated_at").map_err(map_db_err)?,
        published_at: row.try_get("published_at").map_err(map_db_err)?,
    })
}

fn parse_status(value: &str) -> BuilderStatus {
    match value {
        "validated" => BuilderStatus::Validated,
        "published" => BuilderStatus::Published,
        _ => BuilderStatus::Draft,
    }
}

fn status_str(status: &BuilderStatus) -> &'static str {
    match status {
        BuilderStatus::Draft => "draft",
        BuilderStatus::Validated => "validated",
        BuilderStatus::Published => "published",
    }
}

fn issue(path: &str, message: &str) -> ValidationIssue {
    ValidationIssue {
        path: path.into(),
        message: message.into(),
    }
}

fn validate_key(path: &str, key: &str, issues: &mut Vec<ValidationIssue>) {
    if key.trim().is_empty() {
        issues.push(issue(path, "key is required"));
        return;
    }
    if !key
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        || key.starts_with('_')
        || key
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false)
    {
        issues.push(issue(
            path,
            "key must be snake_case and start with a letter",
        ));
    }
}

fn field(key: &str, label: &str, kind: FieldType) -> FieldDefinition {
    FieldDefinition::new(key, label, kind).ai_visible()
}

fn templates() -> Vec<BuilderTemplate> {
    vec![
        finance_template(),
        procurement_template(),
        inventory_template(),
        crm_template(),
        hr_template(),
    ]
}

/// Look up a single built-in template by key. Crate-internal so sibling services
/// (e.g. the migration service) can read template metadata without re-authorizing.
pub(crate) fn template_by_key(key: &str) -> Option<BuilderTemplate> {
    templates().into_iter().find(|t| t.key == key)
}

fn finance_template() -> BuilderTemplate {
    let invoice_wf = latentdb_contracts::WorkflowDef {
        key: "invoice_approval".into(),
        object_type: "invoice".into(),
        name: "Invoice Approval".into(),
        initial_state: "draft".into(),
        states: vec![
            workflow_state("draft", false),
            workflow_state("submitted", false),
            workflow_state("approved", false),
            workflow_state("paid", true),
            workflow_state("cancelled", true),
            workflow_state("rejected", true),
        ],
        transitions: vec![
            workflow_transition("submit", "draft", "submitted", "Submit", false),
            workflow_transition("approve", "submitted", "approved", "Approve", true),
            workflow_transition("reject", "submitted", "rejected", "Reject", true),
            workflow_transition("mark_paid", "approved", "paid", "Mark paid", false),
            workflow_transition("cancel", "draft", "cancelled", "Cancel", false),
        ],
    };
    BuilderTemplate {
        key: "finance".into(),
        name: "Finance".into(),
        description: "Accounts, invoices, payments, and budgets.".into(),
        objects: vec![
            BuilderDefinition {
                key: "account".into(),
                label: "Account".into(),
                label_plural: Some("Accounts".into()),
                description: Some("Customer or billing account.".into()),
                icon: Some("AC".into()),
                module: Some("finance".into()),
                display_field: Some("name".into()),
                fields: vec![
                    field("name", "Name", FieldType::Text).required().display(),
                    field("email", "Email", FieldType::Text),
                    field("tier", "Tier", FieldType::Enum).options(&[
                        "standard",
                        "premium",
                        "enterprise",
                    ]),
                ],
                relations: vec![],
                workflow: None,
                permissions: vec![],
                approval_rules: vec![],
                sensitive_ai_visibility_confirmed: false,
            },
            BuilderDefinition {
                key: "invoice".into(),
                label: "Invoice".into(),
                label_plural: Some("Invoices".into()),
                description: Some("Customer invoice with approval workflow.".into()),
                icon: Some("IN".into()),
                module: Some("finance".into()),
                display_field: Some("number".into()),
                fields: vec![
                    field("number", "Number", FieldType::Text)
                        .required()
                        .display(),
                    field("account_id", "Account", FieldType::RecordRef).references("account"),
                    field("amount", "Amount", FieldType::Money)
                        .required()
                        .display(),
                    field("status", "Status", FieldType::Enum).options(&[
                        "draft",
                        "submitted",
                        "approved",
                        "paid",
                        "cancelled",
                    ]),
                    field("due_date", "Due Date", FieldType::Date),
                    FieldDefinition::new("internal_note", "Internal Note", FieldType::LongText)
                        .restricted(),
                ],
                relations: vec![],
                workflow: Some(invoice_wf),
                permissions: vec![],
                approval_rules: vec![],
                sensitive_ai_visibility_confirmed: false,
            },
            simple_object(
                "payment",
                "Payment",
                "Payments",
                "finance",
                "reference",
                vec![
                    field("reference", "Reference", FieldType::Text)
                        .required()
                        .display(),
                    field("invoice_id", "Invoice", FieldType::RecordRef).references("invoice"),
                    field("amount", "Amount", FieldType::Money),
                    field("paid_date", "Paid Date", FieldType::Date),
                ],
            ),
            simple_object(
                "budget",
                "Budget",
                "Budgets",
                "finance",
                "name",
                vec![
                    field("name", "Name", FieldType::Text).required().display(),
                    field("period", "Period", FieldType::Text),
                    field("amount", "Amount", FieldType::Money),
                ],
            ),
        ],
    }
}

fn procurement_template() -> BuilderTemplate {
    BuilderTemplate {
        key: "procurement".into(),
        name: "Procurement".into(),
        description: "Vendors, requests, orders, and receipts.".into(),
        objects: vec![
            simple_object(
                "vendor",
                "Vendor",
                "Vendors",
                "procurement",
                "name",
                vec![
                    field("name", "Name", FieldType::Text).required().display(),
                    field("email", "Email", FieldType::Text),
                    field("risk", "Risk", FieldType::Enum).options(&["low", "medium", "high"]),
                ],
            ),
            simple_object(
                "purchase_request",
                "Purchase Request",
                "Purchase Requests",
                "procurement",
                "number",
                vec![
                    field("number", "Number", FieldType::Text)
                        .required()
                        .display(),
                    field("item", "Item", FieldType::Text),
                    field("estimated_cost", "Estimated Cost", FieldType::Money),
                    field("status", "Status", FieldType::Enum).options(&[
                        "requested",
                        "approved",
                        "ordered",
                        "rejected",
                    ]),
                ],
            ),
            simple_object(
                "purchase_order",
                "Purchase Order",
                "Purchase Orders",
                "procurement",
                "number",
                vec![
                    field("number", "Number", FieldType::Text)
                        .required()
                        .display(),
                    field("vendor_id", "Vendor", FieldType::RecordRef).references("vendor"),
                    field("amount", "Amount", FieldType::Money),
                ],
            ),
            simple_object(
                "receipt",
                "Receipt",
                "Receipts",
                "procurement",
                "number",
                vec![
                    field("number", "Number", FieldType::Text)
                        .required()
                        .display(),
                    field("quantity", "Quantity", FieldType::Number),
                ],
            ),
        ],
    }
}

fn inventory_template() -> BuilderTemplate {
    BuilderTemplate {
        key: "inventory".into(),
        name: "Inventory".into(),
        description: "Warehouses, products, and inventory movements.".into(),
        objects: vec![
            simple_object(
                "warehouse",
                "Warehouse",
                "Warehouses",
                "inventory",
                "name",
                vec![
                    field("name", "Name", FieldType::Text).required().display(),
                    field("location", "Location", FieldType::Text),
                ],
            ),
            simple_object(
                "product",
                "Product",
                "Products",
                "inventory",
                "name",
                vec![
                    field("sku", "SKU", FieldType::Text).required().display(),
                    field("name", "Name", FieldType::Text).required().display(),
                    field("price", "Price", FieldType::Money),
                    field("quantity", "Quantity", FieldType::Number),
                    field("reorder_point", "Reorder Point", FieldType::Number),
                ],
            ),
            simple_object(
                "inventory_movement",
                "Inventory Movement",
                "Inventory Movements",
                "inventory",
                "reference",
                vec![
                    field("reference", "Reference", FieldType::Text)
                        .required()
                        .display(),
                    field("quantity", "Quantity", FieldType::Number),
                ],
            ),
        ],
    }
}

fn crm_template() -> BuilderTemplate {
    BuilderTemplate {
        key: "crm".into(),
        name: "CRM".into(),
        description: "Accounts, contacts, leads, and deals.".into(),
        objects: vec![simple_object(
            "contact",
            "Contact",
            "Contacts",
            "crm",
            "name",
            vec![
                field("name", "Name", FieldType::Text).required().display(),
                field("email", "Email", FieldType::Text),
            ],
        )],
    }
}

fn hr_template() -> BuilderTemplate {
    BuilderTemplate {
        key: "hr".into(),
        name: "HR".into(),
        description: "Employees and leave requests.".into(),
        objects: vec![simple_object(
            "employee",
            "Employee",
            "Employees",
            "hr",
            "name",
            vec![
                field("name", "Name", FieldType::Text).required().display(),
                field("email", "Email", FieldType::Text),
                FieldDefinition::new("salary", "Salary", FieldType::Money).restricted(),
            ],
        )],
    }
}

fn simple_object(
    key: &str,
    label: &str,
    plural: &str,
    module: &str,
    display: &str,
    fields: Vec<FieldDefinition>,
) -> BuilderDefinition {
    BuilderDefinition {
        key: key.into(),
        label: label.into(),
        label_plural: Some(plural.into()),
        description: None,
        icon: None,
        module: Some(module.into()),
        display_field: Some(display.into()),
        fields,
        relations: vec![],
        workflow: None,
        permissions: vec![],
        approval_rules: vec![],
        sensitive_ai_visibility_confirmed: false,
    }
}

async fn install_sample_records(
    kernel: &Kernel,
    ctx: &AuthContext,
    key: &str,
) -> latentdb_contracts::Result<usize> {
    match key {
        "finance" => install_finance_records(kernel, ctx).await,
        "procurement" => install_procurement_records(kernel, ctx).await,
        "inventory" => install_inventory_records(kernel, ctx).await,
        _ => Ok(0),
    }
}

async fn create(
    kernel: &Kernel,
    ctx: &AuthContext,
    object_type: &str,
    data: Value,
) -> latentdb_contracts::Result<String> {
    let rec = kernel
        .create_record(
            ctx,
            &NewRecord {
                object_type: object_type.into(),
                data: data.as_object().cloned().unwrap_or_default(),
                workspace_id: None,
            },
        )
        .await?;
    Ok(rec.id)
}

async fn install_finance_records(
    kernel: &Kernel,
    ctx: &AuthContext,
) -> latentdb_contracts::Result<usize> {
    let mut account_ids = Vec::new();
    for i in 1..=10 {
        account_ids.push(create(kernel, ctx, "account", json!({"name": format!("Account {i:02}"), "email": format!("billing{i}@customer.test"), "tier": "standard"})).await?);
    }
    let mut invoice_ids = Vec::new();
    for i in 1..=10 {
        invoice_ids.push(create(kernel, ctx, "invoice", json!({"number": format!("INV-{i:04}"), "account_id": account_ids[(i - 1) % account_ids.len()], "amount": i as i64 * 125_000, "status": "draft", "due_date": "2026-07-01"})).await?);
    }
    for inv in invoice_ids.iter().take(3) {
        let _ = kernel
            .transition_record(ctx, inv, "submit", Some("builder-template"))
            .await;
        let _ = kernel
            .transition_record(ctx, inv, "approve", Some("builder-template"))
            .await;
    }
    for i in 1..=3 {
        create(kernel, ctx, "payment", json!({"reference": format!("PAY-{i:04}"), "amount": i as i64 * 100_000, "paid_date": "2026-06-15"})).await?;
    }
    Ok(23)
}

async fn install_procurement_records(
    kernel: &Kernel,
    ctx: &AuthContext,
) -> latentdb_contracts::Result<usize> {
    let mut vendor_ids = Vec::new();
    for i in 1..=5 {
        vendor_ids.push(create(kernel, ctx, "vendor", json!({"name": format!("Vendor {i:02}"), "email": format!("ap{i}@vendor.test"), "risk": if i == 5 { "high" } else { "low" }})).await?);
    }
    for i in 1..=5 {
        create(kernel, ctx, "purchase_request", json!({"number": format!("PR-{i:04}"), "item": format!("Item {i}"), "estimated_cost": i as i64 * 75_000, "status": "requested"})).await?;
    }
    for i in 1..=3 {
        create(kernel, ctx, "purchase_order", json!({"number": format!("PO-{i:04}"), "vendor_id": vendor_ids[(i - 1) % vendor_ids.len()], "amount": i as i64 * 150_000})).await?;
    }
    Ok(13)
}

async fn install_inventory_records(
    kernel: &Kernel,
    ctx: &AuthContext,
) -> latentdb_contracts::Result<usize> {
    for i in 1..=3 {
        create(
            kernel,
            ctx,
            "warehouse",
            json!({"name": format!("Warehouse {i}"), "location": "Primary"}),
        )
        .await?;
    }
    for i in 1..=10 {
        create(kernel, ctx, "product", json!({"sku": format!("SKU-{i:04}"), "name": format!("Product {i:02}"), "price": i as i64 * 10_000, "quantity": 100 + i, "reorder_point": 20})).await?;
    }
    Ok(13)
}

async fn install_template_reports(
    kernel: &Kernel,
    ctx: &AuthContext,
    key: &str,
) -> latentdb_contracts::Result<(usize, usize)> {
    let mut reports = Vec::new();
    if key == "finance" {
        reports.push(ReportDef {
            key: "revenue".into(),
            name: "Revenue".into(),
            object_type: "invoice".into(),
            op: crate::analytics::AggOp::Sum,
            field: Some("amount".into()),
            filters: vec![],
            group_by: None,
        });
        reports.push(ReportDef {
            key: "invoices_by_status".into(),
            name: "Invoices by Status".into(),
            object_type: "invoice".into(),
            op: crate::analytics::AggOp::Count,
            field: None,
            filters: vec![],
            group_by: Some("status".into()),
        });
        reports.push(ReportDef {
            key: "invoice_count".into(),
            name: "Invoice Count".into(),
            object_type: "invoice".into(),
            op: crate::analytics::AggOp::Count,
            field: None,
            filters: vec![],
            group_by: None,
        });
    }
    for report in &reports {
        let _ = kernel.save_report(ctx, report).await;
    }
    if key == "finance" {
        let _ = kernel
            .save_dashboard(
                ctx,
                &crate::analytics::Dashboard {
                    key: "finance".into(),
                    name: "Finance".into(),
                    cards: vec![
                        json!({"title": "Revenue", "report": "revenue"}),
                        json!({"title": "Invoices by Status", "report": "invoices_by_status"}),
                    ],
                },
            )
            .await;
        Ok((reports.len(), 1))
    } else {
        Ok((reports.len(), 0))
    }
}
