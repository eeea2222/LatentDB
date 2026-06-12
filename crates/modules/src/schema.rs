//! Business-module schemas: object types and workflows expressed as metadata.
//!
//! Every business "model" is a kernel object type — there are no bespoke module
//! tables. This is what lets CRM/Finance/Procurement/Inventory/HCM/Projects/
//! Contracts ride on one shared kernel (tenant, permission, workflow, audit)
//! instead of inventing parallel systems.

use latentdb_contracts::{
    FieldDefinition as F, FieldType as T, ObjectTypeDef, Transition, WorkflowDef, WorkflowState,
};

fn ot(
    key: &str,
    label: &str,
    plural: &str,
    module: &str,
    display: &str,
    workflow: Option<&str>,
    fields: Vec<F>,
) -> ObjectTypeDef {
    ObjectTypeDef {
        id: String::new(),
        key: key.into(),
        label: label.into(),
        label_plural: Some(plural.into()),
        description: None,
        system: true,
        workflow_key: workflow.map(|s| s.into()),
        display_field: Some(display.into()),
        module: Some(module.into()),
        fields,
    }
}

fn enum_f(key: &str, label: &str, opts: &[&str]) -> F {
    F::new(key, label, T::Enum).options(opts)
}

/// All object types installed by the business modules.
pub fn object_types() -> Vec<ObjectTypeDef> {
    let mut v = Vec::new();

    // ---------------- CRM ----------------
    v.push(ot(
        "account",
        "Account",
        "Accounts",
        "crm",
        "name",
        None,
        vec![
            F::new("name", "Name", T::Text).required().display(),
            F::new("industry", "Industry", T::Text),
            F::new("website", "Website", T::Text),
            enum_f("tier", "Tier", &["bronze", "silver", "gold", "platinum"]),
            F::new("email", "Email", T::Text),
            F::new("annual_revenue", "Annual Revenue", T::Money),
        ],
    ));
    v.push(ot(
        "contact",
        "Contact",
        "Contacts",
        "crm",
        "name",
        None,
        vec![
            F::new("name", "Name", T::Text).required().display(),
            F::new("email", "Email", T::Text),
            F::new("title", "Title", T::Text),
            F::new("account_id", "Account", T::RecordRef).references("account"),
        ],
    ));
    v.push(ot(
        "lead",
        "Lead",
        "Leads",
        "crm",
        "name",
        None,
        vec![
            F::new("name", "Name", T::Text).required().display(),
            F::new("email", "Email", T::Text),
            F::new("company", "Company", T::Text),
            enum_f(
                "status",
                "Status",
                &["new", "qualified", "converted", "disqualified"],
            ),
            F::new("score", "Score", T::Number),
        ],
    ));
    v.push(ot(
        "deal",
        "Deal",
        "Deals",
        "crm",
        "name",
        None,
        vec![
            F::new("name", "Name", T::Text).required().display(),
            F::new("account_id", "Account", T::RecordRef).references("account"),
            F::new("amount", "Amount", T::Money),
            enum_f(
                "stage",
                "Stage",
                &[
                    "prospecting",
                    "qualification",
                    "proposal",
                    "negotiation",
                    "at_risk",
                    "won",
                    "lost",
                ],
            ),
            F::new("close_date", "Close Date", T::Date),
            F::new("owner_id", "Owner", T::UserRef),
        ],
    ));
    v.push(ot(
        "activity",
        "Activity",
        "Activities",
        "crm",
        "subject",
        None,
        vec![
            F::new("subject", "Subject", T::Text).required().display(),
            enum_f("kind", "Kind", &["call", "email", "meeting", "note"]),
            F::new("account_id", "Account", T::RecordRef).references("account"),
            F::new("at", "When", T::DateTime),
        ],
    ));
    v.push(ot(
        "ticket",
        "Support Ticket",
        "Tickets",
        "crm",
        "subject",
        None,
        vec![
            F::new("subject", "Subject", T::Text).required().display(),
            F::new("account_id", "Account", T::RecordRef).references("account"),
            enum_f("priority", "Priority", &["low", "medium", "high", "urgent"]),
            enum_f("status", "Status", &["open", "pending", "closed"]),
        ],
    ));

    // ---------------- Finance / ERP ----------------
    v.push(ot(
        "vendor",
        "Vendor",
        "Vendors",
        "finance",
        "name",
        None,
        vec![
            F::new("name", "Name", T::Text).required().display(),
            F::new("email", "Email", T::Text),
            enum_f(
                "category",
                "Category",
                &["parts", "logistics", "services", "software"],
            ),
            enum_f("risk", "Risk", &["low", "medium", "high"]),
            F::new("lead_time_days", "Lead Time (days)", T::Number),
        ],
    ));
    v.push(ot(
        "invoice",
        "Invoice",
        "Invoices",
        "finance",
        "number",
        Some("invoice_approval"),
        vec![
            F::new("number", "Number", T::Text).required().display(),
            F::new("account_id", "Customer", T::RecordRef).references("account"),
            F::new("amount", "Amount", T::Money).required().display(),
            enum_f(
                "status",
                "Status",
                &["draft", "submitted", "approved", "paid", "cancelled"],
            ),
            F::new("issue_date", "Issue Date", T::Date),
            F::new("due_date", "Due Date", T::Date),
            F::new("notes", "Notes", T::LongText),
        ],
    ));
    v.push(ot(
        "bill",
        "Bill",
        "Bills",
        "finance",
        "number",
        None,
        vec![
            F::new("number", "Number", T::Text).required().display(),
            F::new("vendor_id", "Vendor", T::RecordRef).references("vendor"),
            F::new("amount", "Amount", T::Money).required(),
            enum_f("status", "Status", &["draft", "approved", "paid"]),
            F::new("due_date", "Due Date", T::Date),
        ],
    ));
    v.push(ot(
        "payment",
        "Payment",
        "Payments",
        "finance",
        "reference",
        None,
        vec![
            F::new("reference", "Reference", T::Text)
                .required()
                .display(),
            F::new("invoice_id", "Invoice", T::RecordRef).references("invoice"),
            F::new("amount", "Amount", T::Money),
            F::new("paid_date", "Paid Date", T::Date),
            enum_f("method", "Method", &["ach", "wire", "card", "check"]),
        ],
    ));
    v.push(ot(
        "budget",
        "Budget",
        "Budgets",
        "finance",
        "name",
        None,
        vec![
            F::new("name", "Name", T::Text).required().display(),
            F::new("period", "Period", T::Text),
            F::new("amount", "Amount", T::Money),
            F::new("spent", "Spent", T::Money),
        ],
    ));

    // ---------------- Procurement ----------------
    v.push(ot(
        "purchase_request",
        "Purchase Request",
        "Purchase Requests",
        "procurement",
        "number",
        Some("pr_approval"),
        vec![
            F::new("number", "Number", T::Text).required().display(),
            F::new("item", "Item", T::Text),
            F::new("quantity", "Quantity", T::Number),
            F::new("estimated_cost", "Estimated Cost", T::Money),
            F::new("vendor_id", "Vendor", T::RecordRef).references("vendor"),
            enum_f(
                "status",
                "Status",
                &[
                    "requested",
                    "manager_review",
                    "finance_review",
                    "ordered",
                    "received",
                    "closed",
                    "rejected",
                ],
            ),
        ],
    ));
    v.push(ot(
        "purchase_order",
        "Purchase Order",
        "Purchase Orders",
        "procurement",
        "number",
        None,
        vec![
            F::new("number", "Number", T::Text).required().display(),
            F::new("vendor_id", "Vendor", T::RecordRef).references("vendor"),
            F::new("amount", "Amount", T::Money),
            enum_f(
                "status",
                "Status",
                &["draft", "approved", "ordered", "received", "closed"],
            ),
            F::new("expected_date", "Expected Date", T::Date),
        ],
    ));
    v.push(ot(
        "receipt",
        "Goods Receipt",
        "Receipts",
        "procurement",
        "number",
        None,
        vec![
            F::new("number", "Number", T::Text).required().display(),
            F::new("po_id", "Purchase Order", T::RecordRef).references("purchase_order"),
            F::new("quantity", "Quantity", T::Number),
            F::new("received_date", "Received Date", T::Date),
        ],
    ));

    // ---------------- Inventory / SCM ----------------
    v.push(ot(
        "warehouse",
        "Warehouse",
        "Warehouses",
        "inventory",
        "name",
        None,
        vec![
            F::new("name", "Name", T::Text).required().display(),
            F::new("location", "Location", T::Text),
        ],
    ));
    v.push(ot(
        "product",
        "Product",
        "Products",
        "inventory",
        "name",
        None,
        vec![
            F::new("sku", "SKU", T::Text).required().display(),
            F::new("name", "Name", T::Text).required().display(),
            enum_f(
                "category",
                "Category",
                &["actuators", "sensors", "controllers", "frames", "batteries"],
            ),
            F::new("unit_cost", "Unit Cost", T::Money),
            F::new("price", "Price", T::Money),
            F::new("quantity", "On Hand", T::Number),
            F::new("reorder_point", "Reorder Point", T::Number),
            F::new("warehouse_id", "Warehouse", T::RecordRef).references("warehouse"),
        ],
    ));
    v.push(ot(
        "inventory_movement",
        "Inventory Movement",
        "Movements",
        "inventory",
        "reference",
        None,
        vec![
            F::new("reference", "Reference", T::Text)
                .required()
                .display(),
            F::new("product_id", "Product", T::RecordRef).references("product"),
            enum_f("kind", "Kind", &["in", "out", "adjust"]),
            F::new("quantity", "Quantity", T::Number),
            F::new("at", "When", T::DateTime),
        ],
    ));

    // ---------------- HCM ----------------
    v.push(ot(
        "department",
        "Department",
        "Departments",
        "hcm",
        "name",
        None,
        vec![
            F::new("name", "Name", T::Text).required().display(),
            F::new("head_id", "Head", T::UserRef),
        ],
    ));
    v.push(ot(
        "employee",
        "Employee",
        "Employees",
        "hcm",
        "name",
        None,
        vec![
            F::new("name", "Name", T::Text).required().display(),
            F::new("email", "Email", T::Text),
            F::new("department_id", "Department", T::RecordRef).references("department"),
            F::new("position", "Position", T::Text),
            // Compensation is field-level restricted; only HR roles can see it.
            F::new("salary", "Salary", T::Money).restricted(),
            F::new("hire_date", "Hire Date", T::Date),
        ],
    ));
    v.push(ot(
        "leave_request",
        "Leave Request",
        "Leave Requests",
        "hcm",
        "reference",
        Some("leave_approval"),
        vec![
            F::new("reference", "Reference", T::Text)
                .required()
                .display(),
            F::new("employee_id", "Employee", T::RecordRef).references("employee"),
            enum_f("kind", "Kind", &["vacation", "sick", "personal"]),
            F::new("start_date", "Start", T::Date),
            F::new("end_date", "End", T::Date),
            enum_f(
                "status",
                "Status",
                &[
                    "draft",
                    "submitted",
                    "manager_approved",
                    "hr_approved",
                    "rejected",
                ],
            ),
        ],
    ));
    v.push(ot(
        "candidate",
        "Candidate",
        "Candidates",
        "hcm",
        "name",
        None,
        vec![
            F::new("name", "Name", T::Text).required().display(),
            F::new("role", "Role", T::Text),
            enum_f(
                "stage",
                "Stage",
                &[
                    "applied",
                    "screening",
                    "interview",
                    "offer",
                    "hired",
                    "rejected",
                ],
            ),
        ],
    ));

    // ---------------- Projects ----------------
    v.push(ot(
        "project",
        "Project",
        "Projects",
        "projects",
        "name",
        None,
        vec![
            F::new("name", "Name", T::Text).required().display(),
            F::new("account_id", "Account", T::RecordRef).references("account"),
            enum_f(
                "status",
                "Status",
                &["planning", "active", "on_hold", "done"],
            ),
            F::new("start_date", "Start", T::Date),
            F::new("end_date", "End", T::Date),
        ],
    ));
    v.push(ot(
        "milestone",
        "Milestone",
        "Milestones",
        "projects",
        "name",
        None,
        vec![
            F::new("name", "Name", T::Text).required().display(),
            F::new("project_id", "Project", T::RecordRef).references("project"),
            F::new("due_date", "Due Date", T::Date),
            enum_f("status", "Status", &["pending", "in_progress", "done"]),
        ],
    ));

    // ---------------- Contracts / Documents ----------------
    v.push(ot(
        "contract",
        "Contract",
        "Contracts",
        "contracts",
        "title",
        None,
        vec![
            F::new("title", "Title", T::Text).required().display(),
            enum_f("party_type", "Party Type", &["customer", "vendor"]),
            F::new("party_id", "Party", T::Text),
            F::new("value", "Value", T::Money),
            F::new("start_date", "Start", T::Date),
            F::new("end_date", "End", T::Date),
            F::new("renewal_date", "Renewal Date", T::Date),
            enum_f(
                "status",
                "Status",
                &["active", "renewal_review", "renewed", "expired"],
            ),
        ],
    ));

    v
}

fn state(key: &str, terminal: bool) -> WorkflowState {
    WorkflowState {
        key: key.into(),
        label: title_case(key),
        terminal,
    }
}

fn tr(key: &str, from: &str, to: &str, label: &str, approval: bool) -> Transition {
    Transition {
        key: key.into(),
        from: from.into(),
        to: to.into(),
        label: label.into(),
        guard_permission: None,
        requires_approval: approval,
        approval_policy: if approval {
            Some("default".into())
        } else {
            None
        },
    }
}

/// All workflows installed by the business modules.
pub fn workflows() -> Vec<WorkflowDef> {
    vec![
        WorkflowDef {
            key: "invoice_approval".into(),
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
                tr("submit", "draft", "submitted", "Submit for approval", false),
                tr("approve", "submitted", "approved", "Approve", true),
                tr("mark_paid", "approved", "paid", "Mark paid", false),
                tr("cancel", "draft", "cancelled", "Cancel", false),
                tr(
                    "cancel_submitted",
                    "submitted",
                    "cancelled",
                    "Cancel",
                    false,
                ),
            ],
        },
        WorkflowDef {
            key: "pr_approval".into(),
            object_type: "purchase_request".into(),
            name: "Purchase Request Approval".into(),
            initial_state: "requested".into(),
            states: vec![
                state("requested", false),
                state("manager_review", false),
                state("finance_review", false),
                state("ordered", false),
                state("received", false),
                state("closed", true),
                state("rejected", true),
            ],
            transitions: vec![
                tr(
                    "to_manager",
                    "requested",
                    "manager_review",
                    "Send to manager",
                    false,
                ),
                tr(
                    "manager_approve",
                    "manager_review",
                    "finance_review",
                    "Manager approve",
                    true,
                ),
                tr(
                    "finance_approve",
                    "finance_review",
                    "ordered",
                    "Finance approve",
                    true,
                ),
                tr("receive", "ordered", "received", "Mark received", false),
                tr("close", "received", "closed", "Close", false),
                tr("reject", "manager_review", "rejected", "Reject", false),
            ],
        },
        WorkflowDef {
            key: "leave_approval".into(),
            object_type: "leave_request".into(),
            name: "Leave Request Approval".into(),
            initial_state: "draft".into(),
            states: vec![
                state("draft", false),
                state("submitted", false),
                state("manager_approved", false),
                state("hr_approved", true),
                state("rejected", true),
            ],
            transitions: vec![
                tr("submit", "draft", "submitted", "Submit", false),
                tr(
                    "manager_approve",
                    "submitted",
                    "manager_approved",
                    "Manager approve",
                    true,
                ),
                tr(
                    "hr_approve",
                    "manager_approved",
                    "hr_approved",
                    "HR approve",
                    true,
                ),
                tr("reject", "submitted", "rejected", "Reject", false),
            ],
        },
    ]
}

fn title_case(s: &str) -> String {
    s.split('_')
        .map(|w| {
            let mut c = w.chars();
            match c.next() {
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}
