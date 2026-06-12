//! Business roles, expressed as permission grants over the shared object system.
//!
//! These encode the spec's example boundaries: finance users can read invoices
//! but cannot approve them (only finance managers can); sales reps cannot see HR
//! salary; HR managers can; procurement agents can draft a PO but cannot approve
//! it; an exec sees read-only dashboards across modules.

use latentdb_contracts::{Action, FieldRule, FieldRuleMode, PermissionGrant, Scope};

pub struct RoleSpec {
    pub key: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub grants: Vec<PermissionGrant>,
}

fn g(action: Action, resource: &str) -> PermissionGrant {
    PermissionGrant::new(action, resource, Scope::Org)
}

/// Read/Create/Update/Search/Transition/Relate on a resource (but NOT Approve).
fn crud(resource: &str) -> Vec<PermissionGrant> {
    [
        Action::Read,
        Action::Create,
        Action::Update,
        Action::Search,
        Action::Transition,
        Action::Relate,
    ]
    .into_iter()
    .map(|a| g(a, resource))
    .collect()
}

/// Full management of a resource (includes Approve via `Manage`).
fn manage(resource: &str) -> PermissionGrant {
    g(Action::Manage, resource)
}

/// Management plus visibility of restricted fields (deny-nothing field rule).
fn manage_sensitive(resource: &str) -> PermissionGrant {
    let mut m = manage(resource);
    m.fields = Some(FieldRule {
        mode: FieldRuleMode::Deny,
        fields: vec![],
    });
    m
}

fn read_bi() -> Vec<PermissionGrant> {
    vec![
        g(Action::Read, "report"),
        g(Action::Read, "metric"),
        g(Action::Read, "dashboard"),
    ]
}

/// Concatenate grant groups.
fn join(groups: Vec<Vec<PermissionGrant>>) -> Vec<PermissionGrant> {
    groups.into_iter().flatten().collect()
}

pub fn business_roles() -> Vec<RoleSpec> {
    vec![
        RoleSpec {
            key: "finance_user",
            name: "Finance User",
            description: "Manage invoices/bills/payments; can submit but not approve",
            grants: join(vec![
                crud("object:invoice"),
                crud("object:bill"),
                crud("object:payment"),
                vec![
                    g(Action::Read, "object:account"),
                    g(Action::Read, "object:vendor"),
                    g(Action::Read, "object:budget"),
                ],
                read_bi(),
            ]),
        },
        RoleSpec {
            key: "finance_manager",
            name: "Finance Manager",
            description: "Full finance management including invoice approval",
            grants: join(vec![
                vec![
                    manage("object:invoice"),
                    manage("object:bill"),
                    manage("object:payment"),
                    manage("object:budget"),
                ],
                vec![
                    g(Action::Read, "object:account"),
                    g(Action::Read, "object:vendor"),
                ],
                read_bi(),
                vec![g(Action::Read, "approval"), g(Action::Read, "audit")],
            ]),
        },
        RoleSpec {
            key: "sales_rep",
            name: "Sales Rep",
            description: "CRM: accounts, contacts, leads, deals, activities, tickets",
            grants: join(vec![
                crud("object:account"),
                crud("object:contact"),
                crud("object:lead"),
                crud("object:deal"),
                crud("object:activity"),
                crud("object:ticket"),
                read_bi(),
            ]),
        },
        RoleSpec {
            key: "sales_manager",
            name: "Sales Manager",
            description: "Full CRM management",
            grants: join(vec![
                vec![
                    manage("object:account"),
                    manage("object:contact"),
                    manage("object:lead"),
                    manage("object:deal"),
                    manage("object:activity"),
                    manage("object:ticket"),
                ],
                read_bi(),
                vec![g(Action::Read, "approval")],
            ]),
        },
        RoleSpec {
            key: "procurement_agent",
            name: "Procurement Agent",
            description: "Draft purchase requests/orders; cannot approve",
            grants: join(vec![
                crud("object:purchase_request"),
                crud("object:purchase_order"),
                vec![
                    g(Action::Read, "object:vendor"),
                    g(Action::Read, "object:product"),
                    g(Action::Read, "object:receipt"),
                ],
                crud("object:receipt"),
                read_bi(),
            ]),
        },
        RoleSpec {
            key: "procurement_manager",
            name: "Procurement Manager",
            description: "Approve purchase requests and orders; manage vendors",
            grants: join(vec![
                vec![
                    manage("object:purchase_request"),
                    manage("object:purchase_order"),
                    manage("object:vendor"),
                    manage("object:receipt"),
                ],
                vec![g(Action::Read, "object:product")],
                read_bi(),
                vec![g(Action::Read, "approval")],
            ]),
        },
        RoleSpec {
            key: "inventory_user",
            name: "Inventory User",
            description: "Manage products, warehouses, and stock movements",
            grants: join(vec![
                crud("object:product"),
                crud("object:warehouse"),
                crud("object:inventory_movement"),
                read_bi(),
            ]),
        },
        RoleSpec {
            key: "hr_user",
            name: "HR User",
            description: "Read employees and departments WITHOUT compensation",
            grants: join(vec![
                vec![
                    g(Action::Read, "object:employee"),
                    g(Action::Search, "object:employee"),
                    g(Action::Read, "object:department"),
                    g(Action::Read, "object:leave_request"),
                    g(Action::Read, "object:candidate"),
                ],
                read_bi(),
            ]),
        },
        RoleSpec {
            key: "hr_manager",
            name: "HR Manager",
            description: "Full HR management including compensation and leave approval",
            grants: join(vec![
                vec![
                    manage_sensitive("object:employee"),
                    manage("object:department"),
                    manage("object:leave_request"),
                    manage("object:candidate"),
                ],
                read_bi(),
                vec![g(Action::Read, "approval")],
            ]),
        },
        RoleSpec {
            key: "project_manager",
            name: "Project Manager",
            description: "Manage projects and milestones",
            grants: join(vec![
                vec![manage("object:project"), manage("object:milestone")],
                vec![
                    g(Action::Read, "object:account"),
                    g(Action::Read, "object:deal"),
                ],
                read_bi(),
            ]),
        },
        RoleSpec {
            key: "contracts_manager",
            name: "Contracts Manager",
            description: "Manage contracts and documents",
            grants: join(vec![
                vec![manage("object:contract")],
                vec![
                    g(Action::Read, "object:account"),
                    g(Action::Read, "object:vendor"),
                ],
                read_bi(),
            ]),
        },
        RoleSpec {
            key: "exec",
            name: "Executive",
            description: "Read-only cross-module dashboards and audit",
            grants: join(vec![
                vec![g(Action::Read, "object:*"), g(Action::Search, "object:*")],
                read_bi(),
                vec![
                    g(Action::Read, "approval"),
                    PermissionGrant::new(Action::Read, "audit", Scope::Tenant),
                ],
            ]),
        },
    ]
}
